using System.Diagnostics.CodeAnalysis;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.WindowsRuntime;
using System.Security.Cryptography;
using Microsoft.UI;
using Microsoft.UI.Dispatching;
using Microsoft.UI.Windowing;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Controls.Primitives;
using Microsoft.UI.Xaml.Input;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Media.Imaging;
using PersonalAuthenticator.App.Dialogs;
using PersonalAuthenticator.App.ViewModels;
using PersonalAuthenticator.Core.Abstractions;
using PersonalAuthenticator.Core.Domain;
using PersonalAuthenticator.Core.Exceptions;
using Windows.Graphics;

namespace PersonalAuthenticator.App;

public sealed partial class MainWindow : Window, IDisposable
{
    private readonly IProvisioningUriParser _parser;
    private readonly IQrCodeDecoder _qrDecoder;
    private readonly IQrCodeGenerator _qrGenerator;
    private readonly IAutomaticLockMonitor _lockMonitor;
    private readonly IBackupService _backupService;
    private readonly DispatcherQueueTimer _timer;
    private readonly CancellationTokenSource _lifetime = new();
    private readonly nint _windowHandle;
    private readonly AppWindow _appWindow;
    private DateTimeOffset _lastActivity = DateTimeOffset.UtcNow;
    private ContentDialog? _sensitiveDialog;
    private bool _initialised;
    private bool _migrationPromptShowing;
    private bool _shutdownStarted;
    private bool _disposed;

    public MainWindow(
        MainViewModel viewModel,
        IProvisioningUriParser parser,
        IQrCodeDecoder qrDecoder,
        IQrCodeGenerator qrGenerator,
        IAutomaticLockMonitor lockMonitor,
        IBackupService backupService)
    {
        try
        {
            InitializeComponent();
        }
        catch (Exception exception)
        {
            WriteSafeStartupDiagnostic(exception);
            throw;
        }
        ViewModel = viewModel;
        _parser = parser;
        _qrDecoder = qrDecoder;
        _qrGenerator = qrGenerator;
        _lockMonitor = lockMonitor;
        _backupService = backupService;
        Root.DataContext = ViewModel;
        Root.AddHandler(
            UIElement.KeyDownEvent,
            new KeyEventHandler(Root_KeyDown),
            handledEventsToo: true);
        Root.AddHandler(
            UIElement.PointerPressedEvent,
            new PointerEventHandler(Root_PointerPressed),
            handledEventsToo: true);
        _windowHandle = WinRT.Interop.WindowNative.GetWindowHandle(this);
        WindowId windowId = Win32Interop.GetWindowIdFromWindow(_windowHandle);
        _appWindow = AppWindow.GetFromWindowId(windowId);
        _appWindow.Resize(new SizeInt32(1_000, 720));
        _appWindow.Changed += OnAppWindowChanged;

        ExtendsContentIntoTitleBar = true;
        SetTitleBar(AppTitleBar);
        TrySetMicaBackdrop();

        _timer = DispatcherQueue.CreateTimer();
        _timer.Interval = TimeSpan.FromSeconds(1);
        _timer.Tick += OnTimerTick;
        ViewModel.NotificationRequested += OnNotificationRequested;
        _lockMonitor.LockRequested += OnSystemLockRequested;
        _lockMonitor.Start();
        Activated += OnActivated;
        Closed += OnClosed;
    }

    public MainViewModel ViewModel { get; }

    private async void OnActivated(object sender, WindowActivatedEventArgs args)
    {
        if (args.WindowActivationState == WindowActivationState.Deactivated)
        {
            HideSensitiveDialog();
            return;
        }

        if (_initialised)
        {
            return;
        }

        _initialised = true;
        try
        {
            await ViewModel.InitialiseAsync(_lifetime.Token);
            ApplyTheme();
            bool migrationWasRequired = ViewModel.IsMigrationChoiceRequired;
            bool migrationResolved = await EnsureMigrationChoiceResolvedAsync();
            if (migrationWasRequired &&
                migrationResolved &&
                ViewModel.Settings.StartUnlocked &&
                ViewModel.IsLocked)
            {
                await ViewModel.UnlockAsync(_lifetime.Token);
            }

            _timer.Start();
        }
        catch (Exception exception)
        {
            ViewModel.NotifyError(exception);
        }
    }

    private void OnClosed(object sender, WindowEventArgs args)
    {
        Dispose();
    }

    internal void BeginShutdown()
    {
        if (_shutdownStarted)
        {
            return;
        }

        _shutdownStarted = true;
        Root.IsHitTestVisible = false;
        _timer.Stop();
        HideSensitiveDialog();
        _ = TrySetDisplayAffinity(NativeMethods.DisplayAffinityNone);
        _lifetime.Cancel();
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        BeginShutdown();
        Activated -= OnActivated;
        Closed -= OnClosed;
        _lockMonitor.LockRequested -= OnSystemLockRequested;
        _lockMonitor.Dispose();
        ViewModel.NotificationRequested -= OnNotificationRequested;
        _appWindow.Changed -= OnAppWindowChanged;
        _lifetime.Dispose();
    }

    private void OnTimerTick(DispatcherQueueTimer sender, object args)
    {
        ViewModel.RefreshCodes();
        if (ViewModel.IsUnlocked &&
            ViewModel.Settings.AutomaticLockMinutes > 0 &&
            DateTimeOffset.UtcNow - _lastActivity >=
            TimeSpan.FromMinutes(ViewModel.Settings.AutomaticLockMinutes))
        {
            _ = LockSafelyAsync();
        }
    }

    private void Root_KeyDown(object sender, KeyRoutedEventArgs args) =>
        _lastActivity = DateTimeOffset.UtcNow;

    private void Root_PointerPressed(object sender, PointerRoutedEventArgs args) =>
        _lastActivity = DateTimeOffset.UtcNow;

    private void SearchBox_TextChanged(AutoSuggestBox sender, AutoSuggestBoxTextChangedEventArgs args)
    {
        if (args.Reason == AutoSuggestionBoxTextChangeReason.UserInput)
        {
            ViewModel.SearchText = sender.Text;
        }
    }

    private void FavouritesButton_Click(object sender, RoutedEventArgs args) =>
        ViewModel.FavouritesOnly = ((ToggleButton)sender).IsChecked == true;

    private async void LockButton_Click(object sender, RoutedEventArgs args)
    {
        if (ViewModel.IsUnlocked)
        {
            await LockSafelyAsync();
        }
        else
        {
            await UnlockSafelyAsync();
        }
    }

    private async void UnlockButton_Click(object sender, RoutedEventArgs args) =>
        await UnlockSafelyAsync();

    private async Task UnlockSafelyAsync()
    {
        try
        {
            if (!await EnsureMigrationChoiceResolvedAsync())
            {
                return;
            }

            await ViewModel.UnlockAsync(_lifetime.Token);
            _lastActivity = DateTimeOffset.UtcNow;
        }
        catch (Exception exception)
        {
            ViewModel.NotifyError(exception);
        }
    }

    private async Task LockSafelyAsync()
    {
        try
        {
            await ViewModel.LockAsync(CancellationToken.None);
        }
        catch (Exception exception)
        {
            ViewModel.NotifyError(exception);
        }
    }

    private async void AddAccountButton_Click(object sender, RoutedEventArgs args)
    {
        if (!ViewModel.IsUnlocked &&
            (!await EnsureMigrationChoiceResolvedAsync() ||
             !await ViewModel.UnlockAsync(_lifetime.Token)))
        {
            return;
        }

        var dialog = new AddAccountDialog(_parser, _qrDecoder, _windowHandle)
        {
            XamlRoot = Root.XamlRoot,
        };
        ContentDialogResult result = await dialog.ShowAsync();
        using ParsedTotpProvisioning? parsed = dialog.TakeResult();
        if (result != ContentDialogResult.Primary || parsed is null)
        {
            return;
        }

        var preview = new ContentDialog
        {
            XamlRoot = Root.XamlRoot,
            Title = "Confirm account",
            Content = new TextBlock
            {
                Text =
                    $"{parsed.Issuer}\n{parsed.AccountName}\n\n" +
                    $"{parsed.Digits} digits · {parsed.Period} seconds · {FormatAlgorithm(parsed.Algorithm)}\n" +
                    $"Secret {parsed.MaskedSecretSuffix}",
                TextWrapping = TextWrapping.Wrap,
            },
            PrimaryButtonText = "Save account",
            CloseButtonText = "Cancel",
            DefaultButton = ContentDialogButton.Primary,
        };
        if (await preview.ShowAsync() != ContentDialogResult.Primary)
        {
            return;
        }

        TotpAccount account = parsed.CreateAccount();
        try
        {
            DuplicateResolution resolution = DuplicateResolution.Cancel;
            DuplicateAccountMatch? duplicate = ViewModel.FindDuplicateMatch(account);
            if (duplicate?.Kind == DuplicateMatchKind.SameAccountDifferentSecret)
            {
                TotpAccount existing = ViewModel.FindAccount(duplicate.ExistingAccountId)!;
                var duplicateDialog = new ContentDialog
                {
                    XamlRoot = Root.XamlRoot,
                    Title = "A different secret exists for this account",
                    Content = new TextBlock
                    {
                        Text =
                            $"Existing account: {existing.Issuer} — {existing.AccountName}\n\n" +
                            (ViewModel.CanUseV2Features
                                ? "Save the imported secret as a candidate without changing current codes, " +
                                  "or add it as a separate account."
                                : "The v1 vault cannot keep secret versions. You can add this as a separate account."),
                        TextWrapping = TextWrapping.Wrap,
                    },
                    PrimaryButtonText = ViewModel.CanUseV2Features
                        ? "Save as candidate"
                        : "Add separate",
                    SecondaryButtonText = ViewModel.CanUseV2Features
                        ? "Add separate"
                        : string.Empty,
                    CloseButtonText = "Cancel",
                    DefaultButton = ContentDialogButton.Close,
                };
                ContentDialogResult duplicateResult = await duplicateDialog.ShowAsync();
                if (ViewModel.CanUseV2Features &&
                    duplicateResult == ContentDialogResult.Primary)
                {
                    await ViewModel.AddSecretCandidateAsync(
                        duplicate.ExistingAccountId,
                        account,
                        _lifetime.Token);
                    return;
                }

                resolution =
                    duplicateResult == ContentDialogResult.Secondary ||
                    (!ViewModel.CanUseV2Features &&
                     duplicateResult == ContentDialogResult.Primary)
                        ? DuplicateResolution.AddSeparate
                        : DuplicateResolution.Cancel;
                if (resolution == DuplicateResolution.Cancel)
                {
                    account.Dispose();
                    return;
                }
            }
            else if (duplicate?.Kind == DuplicateMatchKind.Exact)
            {
                TotpAccount existing = ViewModel.FindAccount(duplicate.ExistingAccountId)!;
                var duplicateDialog = new ContentDialog
                {
                    XamlRoot = Root.XamlRoot,
                    Title = "This account already exists",
                    Content = new TextBlock
                    {
                        Text =
                            $"Existing account: {existing.Issuer} — {existing.AccountName}\n\n" +
                            "Replace its display entry, add a separate copy, or cancel.",
                        TextWrapping = TextWrapping.Wrap,
                    },
                    PrimaryButtonText = "Replace existing",
                    SecondaryButtonText = "Add separate",
                    CloseButtonText = "Cancel",
                    DefaultButton = ContentDialogButton.Close,
                };
                resolution = await duplicateDialog.ShowAsync() switch
                {
                    ContentDialogResult.Primary => DuplicateResolution.ReplaceExisting,
                    ContentDialogResult.Secondary => DuplicateResolution.AddSeparate,
                    _ => DuplicateResolution.Cancel,
                };
                if (resolution == DuplicateResolution.Cancel)
                {
                    account.Dispose();
                    return;
                }
            }

            if (resolution == DuplicateResolution.AddSeparate &&
                ViewModel.CanUseV2Features &&
                duplicate is not null)
            {
                await ViewModel.AddDuplicateAccountAsync(
                    duplicate.ExistingAccountId,
                    account,
                    _lifetime.Token);
                return;
            }

            await ViewModel.AddAsync(account, resolution, _lifetime.Token);
        }
        catch (Exception exception)
        {
            ViewModel.NotifyError(exception);
        }
    }

    private async void CopyButton_Click(object sender, RoutedEventArgs args)
    {
        if (TryGetCard(sender, out AccountCardViewModel? card))
        {
            try
            {
                await ViewModel.CopyAsync(card.Id, _lifetime.Token);
            }
            catch (Exception exception)
            {
                ViewModel.NotifyError(exception);
            }
        }
    }

    private async void RevealButton_Click(object sender, RoutedEventArgs args)
    {
        if (TryGetCard(sender, out AccountCardViewModel? card))
        {
            try
            {
                await ViewModel.RevealAsync(card.Id, _lifetime.Token);
            }
            catch (Exception exception)
            {
                ViewModel.NotifyError(exception);
            }
        }
    }

    private async void FavouriteMenuItem_Click(object sender, RoutedEventArgs args)
    {
        if (TryGetCard(sender, out AccountCardViewModel? card))
        {
            await RunSafelyAsync(() => ViewModel.ToggleFavouriteAsync(card.Id, _lifetime.Token));
        }
    }

    private async void MoveUpMenuItem_Click(object sender, RoutedEventArgs args)
    {
        if (TryGetCard(sender, out AccountCardViewModel? card))
        {
            await RunSafelyAsync(() => ViewModel.MoveAsync(card.Id, -1, _lifetime.Token));
        }
    }

    private async void MoveDownMenuItem_Click(object sender, RoutedEventArgs args)
    {
        if (TryGetCard(sender, out AccountCardViewModel? card))
        {
            await RunSafelyAsync(() => ViewModel.MoveAsync(card.Id, 1, _lifetime.Token));
        }
    }

    private async void EditMenuItem_Click(object sender, RoutedEventArgs args)
    {
        if (!TryGetCard(sender, out AccountCardViewModel? card))
        {
            return;
        }

        var issuerBox = new TextBox { Header = "Issuer", Text = card.Issuer };
        var nameBox = new TextBox { Header = "Account name", Text = card.AccountName };
        var content = new StackPanel { Spacing = 12 };
        content.Children.Add(issuerBox);
        content.Children.Add(nameBox);
        var dialog = new ContentDialog
        {
            XamlRoot = Root.XamlRoot,
            Title = "Edit account",
            Content = content,
            PrimaryButtonText = "Save",
            CloseButtonText = "Cancel",
            DefaultButton = ContentDialogButton.Primary,
        };
        if (await dialog.ShowAsync() == ContentDialogResult.Primary)
        {
            await RunSafelyAsync(
                () => ViewModel.EditAsync(card.Id, issuerBox.Text, nameBox.Text, _lifetime.Token));
        }
    }

    private async void DeleteMenuItem_Click(object sender, RoutedEventArgs args)
    {
        if (!TryGetCard(sender, out AccountCardViewModel? card))
        {
            return;
        }

        var dialog = new ContentDialog
        {
            XamlRoot = Root.XamlRoot,
            Title = ViewModel.CanUseV2Features
                ? $"Archive {card.Issuer} — {card.AccountName}?"
                : $"Delete {card.Issuer} — {card.AccountName}?",
            Content = new TextBlock
            {
                Text = ViewModel.CanUseV2Features
                    ? "The account will leave the main list but its encrypted secret versions and " +
                      "account history will remain available for restore."
                    : "The v1 format cannot archive accounts. Deleting this legacy entry cannot be " +
                      "undone without the original setup secret or an encrypted backup.",
                TextWrapping = TextWrapping.Wrap,
            },
            PrimaryButtonText = ViewModel.CanUseV2Features
                ? "Archive account"
                : "Delete v1 account",
            CloseButtonText = "Cancel",
            DefaultButton = ContentDialogButton.Close,
        };
        if (await dialog.ShowAsync() == ContentDialogResult.Primary)
        {
            await RunSafelyAsync(() => ViewModel.DeleteAsync(card.Id, _lifetime.Token));
        }
    }

    private void V2MenuItem_Loaded(object sender, RoutedEventArgs args)
    {
        if (sender is FrameworkElement item)
        {
            item.Visibility = ViewModel.CanUseV2Features
                ? Visibility.Visible
                : Visibility.Collapsed;
        }
    }

    private async void AddCandidateMenuItem_Click(object sender, RoutedEventArgs args)
    {
        if (TryGetCard(sender, out AccountCardViewModel? card))
        {
            await RunSafelyAsync(() => AddCandidateSecretAsync(card));
        }
    }

    private async Task AddCandidateSecretAsync(AccountCardViewModel card)
    {
        var dialog = new AddAccountDialog(_parser, _qrDecoder, _windowHandle)
        {
            XamlRoot = Root.XamlRoot,
            Title = $"Add a candidate secret for {card.Issuer} — {card.AccountName}",
        };
        ContentDialogResult result = await dialog.ShowAsync();
        using ParsedTotpProvisioning? parsed = dialog.TakeResult();
        if (result != ContentDialogResult.Primary || parsed is null)
        {
            return;
        }

        var confirmation = new ContentDialog
        {
            XamlRoot = Root.XamlRoot,
            Title = "Save candidate secret?",
            Content = new TextBlock
            {
                Text =
                    "The imported labels will not replace this account's display information. " +
                    "The current secret remains active until you explicitly activate the candidate.\n\n" +
                    $"{parsed.Digits} digits · {parsed.Period} seconds · {FormatAlgorithm(parsed.Algorithm)}\n" +
                    $"Secret {parsed.MaskedSecretSuffix}",
                TextWrapping = TextWrapping.Wrap,
            },
            PrimaryButtonText = "Save candidate",
            CloseButtonText = "Cancel",
            DefaultButton = ContentDialogButton.Close,
        };
        if (await confirmation.ShowAsync() != ContentDialogResult.Primary)
        {
            return;
        }

        TotpAccount candidate = parsed.CreateAccount();
        await ViewModel.AddSecretCandidateAsync(card.Id, candidate, _lifetime.Token);
    }

    private async void SecretVersionsMenuItem_Click(object sender, RoutedEventArgs args)
    {
        if (TryGetCard(sender, out AccountCardViewModel? card))
        {
            await RunSafelyAsync(() => ShowSecretVersionsAsync(card));
        }
    }

    private async Task ShowSecretVersionsAsync(AccountCardViewModel card)
    {
        IReadOnlyList<SecretVersionSummary> versions =
            await ViewModel.GetSecretVersionsAsync(card.Id, _lifetime.Token);
        SecretVersionSummary[] candidates = versions
            .Where(version => version.State == SecretVersionState.Candidate)
            .ToArray();
        var content = new StackPanel { Spacing = 12 };
        content.Children.Add(
            new TextBlock
            {
                Text =
                    "Activating a candidate changes generated codes immediately. " +
                    "The current active secret will be retained as an encrypted retired version.",
                TextWrapping = TextWrapping.Wrap,
            });

        var versionList = new StackPanel { Spacing = 8 };
        foreach (SecretVersionSummary version in versions.Take(200))
        {
            versionList.Children.Add(
                new TextBlock
                {
                    Text = FormatSecretVersion(version),
                    TextWrapping = TextWrapping.Wrap,
                });
        }

        if (versions.Count > 200)
        {
            versionList.Children.Add(
                new TextBlock
                {
                    Text = $"Showing the newest 200 of {versions.Count} versions.",
                    FontStyle = Windows.UI.Text.FontStyle.Italic,
                });
        }

        content.Children.Add(
            new ScrollViewer
            {
                MaxHeight = 320,
                Content = versionList,
            });

        ComboBox? candidatePicker = null;
        if (candidates.Length > 0)
        {
            candidatePicker = new ComboBox
            {
                Header = "Candidate to activate",
                HorizontalAlignment = HorizontalAlignment.Stretch,
            };
            foreach (SecretVersionSummary candidate in candidates)
            {
                candidatePicker.Items.Add(
                    new ComboBoxItem
                    {
                        Content = FormatSecretVersion(candidate),
                        Tag = candidate,
                    });
            }

            candidatePicker.SelectedIndex = 0;
            content.Children.Add(candidatePicker);
        }

        var dialog = new ContentDialog
        {
            XamlRoot = Root.XamlRoot,
            Title = $"Secret versions · {card.Issuer} — {card.AccountName}",
            Content = content,
            PrimaryButtonText = candidates.Length > 0
                ? "Activate selected candidate"
                : string.Empty,
            CloseButtonText = "Close",
            DefaultButton = ContentDialogButton.Close,
        };
        if (await dialog.ShowAsync() != ContentDialogResult.Primary ||
            candidatePicker?.SelectedItem is not ComboBoxItem selected ||
            selected.Tag is not SecretVersionSummary candidateVersion)
        {
            return;
        }

        await ViewModel.ActivateSecretCandidateAsync(
            card.Id,
            candidateVersion.Id,
            _lifetime.Token);
    }

    private async void AccountHistoryMenuItem_Click(object sender, RoutedEventArgs args)
    {
        if (TryGetCard(sender, out AccountCardViewModel? card))
        {
            await RunSafelyAsync(() => ShowAccountHistoryAsync(card));
        }
    }

    private async Task ShowAccountHistoryAsync(AccountCardViewModel card)
    {
        IReadOnlyList<AccountHistoryEntryV2> history =
            await ViewModel.GetAccountHistoryAsync(card.Id, _lifetime.Token);
        string historyText = history.Count == 0
            ? "No account history is available."
            : string.Join(
                "\n\n",
                history.Take(200).Select(FormatHistoryEntry));
        if (history.Count > 200)
        {
            historyText += $"\n\nShowing the newest 200 of {history.Count} entries.";
        }

        var dialog = new ContentDialog
        {
            XamlRoot = Root.XamlRoot,
            Title = $"Account history · {card.Issuer} — {card.AccountName}",
            Content = new ScrollViewer
            {
                MaxHeight = 420,
                Content = new TextBlock
                {
                    Text = historyText,
                    TextWrapping = TextWrapping.Wrap,
                },
            },
            CloseButtonText = "Close",
        };
        await dialog.ShowAsync();
    }

    private async void ArchivedAccountsButton_Click(object sender, RoutedEventArgs args)
    {
        await RunSafelyAsync(ShowArchivedAccountsAsync);
    }

    private async Task ShowArchivedAccountsAsync()
    {
        if (!ViewModel.IsUnlocked &&
            !await ViewModel.UnlockAsync(_lifetime.Token))
        {
            return;
        }

        IReadOnlyList<ArchivedAccountSummary> archived =
            await ViewModel.GetArchivedAccountsAsync(_lifetime.Token);
        if (archived.Count == 0)
        {
            var emptyDialog = new ContentDialog
            {
                XamlRoot = Root.XamlRoot,
                Title = "Archived accounts",
                Content = "There are no archived accounts.",
                CloseButtonText = "Close",
            };
            await emptyDialog.ShowAsync();
            return;
        }

        var picker = new ComboBox
        {
            Header = "Account to restore",
            HorizontalAlignment = HorizontalAlignment.Stretch,
        };
        foreach (ArchivedAccountSummary account in archived)
        {
            picker.Items.Add(
                new ComboBoxItem
                {
                    Content =
                        $"{account.Issuer} — {account.AccountName} · " +
                        $"archived {account.ArchivedAtUtc.ToLocalTime():g}",
                    Tag = account,
                });
        }

        picker.SelectedIndex = 0;
        var dialog = new ContentDialog
        {
            XamlRoot = Root.XamlRoot,
            Title = "Archived accounts",
            Content = picker,
            PrimaryButtonText = "Restore selected",
            CloseButtonText = "Close",
            DefaultButton = ContentDialogButton.Close,
        };
        if (await dialog.ShowAsync() == ContentDialogResult.Primary &&
            picker.SelectedItem is ComboBoxItem selected &&
            selected.Tag is ArchivedAccountSummary accountToRestore)
        {
            await ViewModel.RestoreArchivedAccountAsync(
                accountToRestore.Id,
                _lifetime.Token);
        }
    }

    private async void RevealSetupMenuItem_Click(object sender, RoutedEventArgs args)
    {
        if (TryGetCard(sender, out AccountCardViewModel? card))
        {
            await RunSafelyAsync(() => RevealSensitiveSetupAsync(card));
        }
    }

    private async Task RevealSensitiveSetupAsync(AccountCardViewModel card)
    {
        var warning = new ContentDialog
        {
            XamlRoot = Root.XamlRoot,
            Title = "Reveal sensitive setup information?",
            Content = new TextBlock
            {
                Text =
                    "The setup URI and QR code contain the active secret and can enroll another " +
                    "authenticator. Make sure nobody can see your screen. The sensitive screen " +
                    "closes after 60 seconds, and copied setup URIs clear after 15 seconds.",
                TextWrapping = TextWrapping.Wrap,
            },
            PrimaryButtonText = "Verify and reveal",
            CloseButtonText = "Cancel",
            DefaultButton = ContentDialogButton.Close,
        };
        if (await warning.ShowAsync() != ContentDialogResult.Primary)
        {
            return;
        }

        SensitiveSetupInfo? setup =
            await ViewModel.GetSensitiveSetupInfoAsync(card.Id, _lifetime.Token);
        if (setup is null)
        {
            return;
        }

        WriteableBitmap bitmap;
        using (QrCodePixels qr = _qrGenerator.Generate(setup.ProvisioningUri, 280))
        {
            bitmap = CreateQrBitmap(qr);
        }
        var uriText = new TextBlock
        {
            Text = setup.ProvisioningUri,
            TextWrapping = TextWrapping.Wrap,
            FontFamily = new FontFamily("Consolas"),
            FontSize = 12,
        };
        var copyButton = new Button
        {
            Content = "Copy setup URI for 15 seconds",
            HorizontalAlignment = HorizontalAlignment.Left,
        };
        RoutedEventHandler copyHandler = async (_, _) =>
        {
            try
            {
                await ViewModel.CopySensitiveSetupUriAsync(setup, _lifetime.Token);
            }
            catch (Exception exception)
            {
                ViewModel.NotifyError(exception);
            }
        };
        copyButton.Click += copyHandler;

        var content = new StackPanel { Spacing = 12 };
        var captureStatus = new InfoBar
        {
            IsOpen = true,
            IsClosable = false,
        };
        content.Children.Add(captureStatus);
        content.Children.Add(
            new Image
            {
                Width = 280,
                Height = 280,
                HorizontalAlignment = HorizontalAlignment.Center,
                Source = bitmap,
            });
        content.Children.Add(uriText);
        content.Children.Add(copyButton);
        content.Children.Add(
            new TextBlock
            {
                Text = "This screen closes automatically after 60 seconds.",
                TextWrapping = TextWrapping.Wrap,
            });

        var dialog = new ContentDialog
        {
            XamlRoot = Root.XamlRoot,
            Title = $"Sensitive setup · {setup.Issuer} — {setup.AccountName}",
            Content = new ScrollViewer
            {
                MaxHeight = 620,
                Content = content,
            },
            CloseButtonText = "Hide now",
            DefaultButton = ContentDialogButton.Close,
        };

        try
        {
            _sensitiveDialog = dialog;
            bool captureProtection = TrySetDisplayAffinity(
                NativeMethods.DisplayAffinityExcludeFromCapture);
            captureStatus.Severity = captureProtection
                ? InfoBarSeverity.Informational
                : InfoBarSeverity.Warning;
            captureStatus.Message = captureProtection
                ? "Windows screen-capture exclusion is active for this window."
                : "Windows could not enable screen-capture exclusion. Keep the screen private.";
            Task<ContentDialogResult> dialogTask = dialog.ShowAsync().AsTask();
            Task timeoutTask = Task.Delay(TimeSpan.FromSeconds(60), _lifetime.Token);
            if (await Task.WhenAny(dialogTask, timeoutTask) == timeoutTask &&
                !dialogTask.IsCompleted)
            {
                dialog.Hide();
            }

            await dialogTask;
        }
        finally
        {
            if (ReferenceEquals(_sensitiveDialog, dialog))
            {
                _sensitiveDialog = null;
            }

            copyButton.Click -= copyHandler;
            uriText.Text = string.Empty;
            ClearQrBitmap(bitmap);
            _ = TrySetDisplayAffinity(NativeMethods.DisplayAffinityNone);
        }
    }

    private async void SettingsButton_Click(object sender, RoutedEventArgs args)
    {
        var dialog = new SettingsDialog(ViewModel, _backupService, _windowHandle)
        {
            XamlRoot = Root.XamlRoot,
        };
        await dialog.ShowAsync();
        ApplyTheme();
    }

    private async Task<bool> EnsureMigrationChoiceResolvedAsync()
    {
        if (!ViewModel.IsMigrationChoiceRequired)
        {
            return true;
        }

        if (_migrationPromptShowing)
        {
            return false;
        }

        _migrationPromptShowing = true;
        try
        {
            var content = new StackPanel { Spacing = 12 };
            content.Children.Add(
                new TextBlock
                {
                    Text =
                        "Personal Authenticator found your existing v1 vault. " +
                        "Upgrading creates a separate encrypted v2 vault and verifies every account before activation.",
                    TextWrapping = TextWrapping.Wrap,
                });
            content.Children.Add(
                new InfoBar
                {
                    IsClosable = false,
                    IsOpen = true,
                    Severity = InfoBarSeverity.Informational,
                    Message =
                        "Your original vault.pav remains unchanged and a migration recovery copy is retained. " +
                        "You can also continue using v1 and upgrade later from Settings.",
                });
            var dialog = new ContentDialog
            {
                XamlRoot = Root.XamlRoot,
                Title = "Upgrade your local vault to v2?",
                Content = content,
                PrimaryButtonText = "Upgrade to v2",
                SecondaryButtonText = "Continue using v1",
                CloseButtonText = "Cancel",
                DefaultButton = ContentDialogButton.Close,
            };
            VaultMigrationChoice choice = await dialog.ShowAsync() switch
            {
                ContentDialogResult.Primary => VaultMigrationChoice.UpgradeToV2,
                ContentDialogResult.Secondary => VaultMigrationChoice.ContinueUsingV1,
                _ => VaultMigrationChoice.Cancel,
            };

            try
            {
                await ViewModel.ApplyMigrationChoiceAsync(choice, _lifetime.Token);
                return choice != VaultMigrationChoice.Cancel;
            }
            catch (Exception exception)
            {
                ViewModel.NotifyError(exception);
                return false;
            }
        }
        finally
        {
            _migrationPromptShowing = false;
        }
    }

    private async Task RunSafelyAsync(Func<Task> action)
    {
        try
        {
            await action();
        }
        catch (Exception exception)
        {
            ViewModel.NotifyError(exception);
        }
    }

    private void OnNotificationRequested(object? sender, NotificationEventArgs args)
    {
        NotificationBar.Title = args.Title;
        NotificationBar.Message = args.Message;
        NotificationBar.Severity = args.IsError ? InfoBarSeverity.Error : InfoBarSeverity.Success;
        NotificationBar.IsOpen = true;
    }

    private void OnSystemLockRequested(object? sender, EventArgs args)
    {
        DispatcherQueue.TryEnqueue(
            () =>
            {
                HideSensitiveDialog();
                if (ViewModel.Settings.LockWhenWindowsLocks)
                {
                    _ = LockSafelyAsync();
                }
            });
    }

    private void OnAppWindowChanged(AppWindow sender, AppWindowChangedEventArgs args)
    {
        if (!NativeMethods.IsIconic(_windowHandle))
        {
            return;
        }

        HideSensitiveDialog();
        if (ViewModel.Settings.LockWhenMinimised)
        {
            DispatcherQueue.TryEnqueue(() => _ = LockSafelyAsync());
        }
    }

    private void ApplyTheme()
    {
        Root.RequestedTheme = ViewModel.Settings.Theme switch
        {
            AppTheme.Light => ElementTheme.Light,
            AppTheme.Dark => ElementTheme.Dark,
            _ => ElementTheme.Default,
        };
    }

    private void TrySetMicaBackdrop()
    {
        try
        {
            SystemBackdrop = new MicaBackdrop();
        }
        catch (Exception)
        {
            SystemBackdrop = null;
        }
    }

    private bool TrySetDisplayAffinity(uint affinity)
    {
        try
        {
            return NativeMethods.SetWindowDisplayAffinity(_windowHandle, affinity);
        }
        catch (Exception exception) when (
            exception is DllNotFoundException or EntryPointNotFoundException)
        {
            return false;
        }
    }

    private void HideSensitiveDialog()
    {
        try
        {
            _sensitiveDialog?.Hide();
        }
        catch (InvalidOperationException)
        {
            _sensitiveDialog = null;
        }
    }

    private static bool TryGetCard(
        object sender,
        [NotNullWhen(true)] out AccountCardViewModel? card)
    {
        card = (sender as FrameworkElement)?.Tag as AccountCardViewModel;
        return card is not null;
    }

    private static WriteableBitmap CreateQrBitmap(QrCodePixels pixels)
    {
        var bitmap = new WriteableBitmap(pixels.Width, pixels.Height);
        using Stream stream = bitmap.PixelBuffer.AsStream();
        stream.Write(pixels.Pixels.Span);
        bitmap.Invalidate();
        return bitmap;
    }

    private static void ClearQrBitmap(WriteableBitmap bitmap)
    {
        byte[] cleared = new byte[checked(bitmap.PixelWidth * bitmap.PixelHeight * 4)];
        try
        {
            using Stream stream = bitmap.PixelBuffer.AsStream();
            stream.Position = 0;
            stream.Write(cleared);
            bitmap.Invalidate();
        }
        finally
        {
            CryptographicOperations.ZeroMemory(cleared);
        }
    }

    private static string FormatSecretVersion(SecretVersionSummary version)
    {
        string state = version.State switch
        {
            SecretVersionState.Active => "Active",
            SecretVersionState.Candidate => "Candidate",
            SecretVersionState.Retired => "Retired",
            _ => throw new ArgumentOutOfRangeException(nameof(version)),
        };
        string retired = version.RetiredAtUtc is null
            ? string.Empty
            : $" · retired {version.RetiredAtUtc.Value.ToLocalTime():g}";
        return
            $"{state} · {FormatAlgorithm(version.Algorithm)} · " +
            $"{version.Digits} digits · {version.Period} seconds · " +
            $"created {version.CreatedAtUtc.ToLocalTime():g}{retired}";
    }

    private static string FormatHistoryEntry(AccountHistoryEntryV2 entry)
    {
        string action = entry.Action switch
        {
            AccountHistoryAction.Migrated => "Migrated from the v1 vault",
            AccountHistoryAction.Added => "Account added",
            AccountHistoryAction.DisplayUpdated => "Display information changed",
            AccountHistoryAction.FavouriteChanged => "Favourite state changed",
            AccountHistoryAction.Reordered => "Account reordered",
            AccountHistoryAction.Archived => "Account archived",
            AccountHistoryAction.Restored => "Account restored",
            AccountHistoryAction.SecretCandidateAdded => "Candidate secret added",
            AccountHistoryAction.SecretActivated => "Secret activated",
            AccountHistoryAction.DuplicateAddedSeparately => "Duplicate kept separately",
            AccountHistoryAction.Imported => "Account imported",
            _ => "Account changed",
        };
        string actor = entry.ActorDeviceId is Guid actorDeviceId
            ? $"\nDevice {actorDeviceId:D}"
            : string.Empty;
        string related = entry.RelatedAccountId is Guid relatedAccountId
            ? $"\nRelated account {relatedAccountId:D}"
            : string.Empty;
        return $"{entry.OccurredAtUtc.ToLocalTime():g}\n{action}{actor}{related}";
    }

    private static string FormatAlgorithm(TotpAlgorithm algorithm) =>
        algorithm switch
        {
            TotpAlgorithm.Sha1 => "SHA-1",
            TotpAlgorithm.Sha256 => "SHA-256",
            TotpAlgorithm.Sha512 => "SHA-512",
            _ => throw new ArgumentOutOfRangeException(nameof(algorithm)),
        };

    private static void WriteSafeStartupDiagnostic(Exception exception)
    {
        string directory = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "PersonalAuthenticator");
        Directory.CreateDirectory(directory);
        string diagnostic =
            $"{DateTimeOffset.UtcNow:O} XAML startup failure. " +
            $"ErrorType={exception.GetType().Name}; HResult=0x{exception.HResult:X8}; Message={exception.Message}{Environment.NewLine}";
        File.AppendAllText(Path.Combine(directory, "startup.log"), diagnostic);
    }

    private static partial class NativeMethods
    {
        internal const uint DisplayAffinityNone = 0x00000000;
        internal const uint DisplayAffinityExcludeFromCapture = 0x00000011;

        [LibraryImport("user32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static partial bool IsIconic(nint windowHandle);

        [LibraryImport("user32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static partial bool SetWindowDisplayAffinity(
            nint windowHandle,
            uint affinity);
    }
}
