using System.Diagnostics.CodeAnalysis;
using System.Runtime.InteropServices;
using Microsoft.UI;
using Microsoft.UI.Dispatching;
using Microsoft.UI.Windowing;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Controls.Primitives;
using Microsoft.UI.Xaml.Input;
using Microsoft.UI.Xaml.Media;
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
    private readonly IAutomaticLockMonitor _lockMonitor;
    private readonly IBackupService _backupService;
    private readonly DispatcherQueueTimer _timer;
    private readonly CancellationTokenSource _lifetime = new();
    private readonly nint _windowHandle;
    private readonly AppWindow _appWindow;
    private DateTimeOffset _lastActivity = DateTimeOffset.UtcNow;
    private bool _initialised;
    private bool _shutdownStarted;
    private bool _disposed;

    public MainWindow(
        MainViewModel viewModel,
        IProvisioningUriParser parser,
        IQrCodeDecoder qrDecoder,
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
        Root.DataContext = ViewModel;
        Root.AddHandler(
            UIElement.KeyDownEvent,
            new KeyEventHandler(Root_KeyDown),
            handledEventsToo: true);
        Root.AddHandler(
            UIElement.PointerPressedEvent,
            new PointerEventHandler(Root_PointerPressed),
            handledEventsToo: true);
        _parser = parser;
        _qrDecoder = qrDecoder;
        _lockMonitor = lockMonitor;
        _backupService = backupService;
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
        if (_initialised)
        {
            return;
        }

        _initialised = true;
        try
        {
            await ViewModel.InitialiseAsync(_lifetime.Token);
            ApplyTheme();
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
        if (!ViewModel.IsUnlocked && !await ViewModel.UnlockAsync(_lifetime.Token))
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
            Guid? duplicateId = ViewModel.FindDuplicate(account);
            if (duplicateId is not null)
            {
                TotpAccount existing = ViewModel.FindAccount(duplicateId.Value)!;
                var duplicateDialog = new ContentDialog
                {
                    XamlRoot = Root.XamlRoot,
                    Title = "This account may already exist",
                    Content = new TextBlock
                    {
                        Text =
                            $"Existing account: {existing.Issuer} — {existing.AccountName}\n\n" +
                            "Replace it, add a separate copy, or cancel.",
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
            Title = $"Delete {card.Issuer} — {card.AccountName}?",
            Content = new TextBlock
            {
                Text =
                    "This cannot be undone without the original setup secret, an encrypted backup, " +
                    "or the service's recovery process.",
                TextWrapping = TextWrapping.Wrap,
            },
            PrimaryButtonText = "Delete account",
            CloseButtonText = "Cancel",
            DefaultButton = ContentDialogButton.Close,
        };
        if (await dialog.ShowAsync() == ContentDialogResult.Primary)
        {
            await RunSafelyAsync(() => ViewModel.DeleteAsync(card.Id, _lifetime.Token));
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
        if (ViewModel.Settings.LockWhenWindowsLocks)
        {
            DispatcherQueue.TryEnqueue(() => _ = LockSafelyAsync());
        }
    }

    private void OnAppWindowChanged(AppWindow sender, AppWindowChangedEventArgs args)
    {
        if (ViewModel.Settings.LockWhenMinimised && NativeMethods.IsIconic(_windowHandle))
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

    private static bool TryGetCard(
        object sender,
        [NotNullWhen(true)] out AccountCardViewModel? card)
    {
        card = (sender as FrameworkElement)?.Tag as AccountCardViewModel;
        return card is not null;
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
        [LibraryImport("user32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static partial bool IsIconic(nint windowHandle);
    }
}
