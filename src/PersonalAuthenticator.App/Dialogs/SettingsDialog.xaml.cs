using Microsoft.UI;
using Microsoft.UI.Windowing;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using PersonalAuthenticator.App.ViewModels;
using PersonalAuthenticator.Core.Abstractions;
using PersonalAuthenticator.Core.Domain;
using PersonalAuthenticator.Core.Exceptions;
using Windows.Graphics;
using Windows.Storage.Pickers;

namespace PersonalAuthenticator.App.Dialogs;

public sealed partial class SettingsDialog : Window
{
    private readonly MainViewModel _viewModel;
    private readonly IBackupService _backupService;
    private readonly IRecoveryService _recoveryService;
    private readonly ILocalFolderSyncService _syncService;
    private readonly IGitHubSyncService _githubSyncService;
    private readonly ISecurityLifecycleService _securityLifecycle;
    private readonly IUserVerificationService _userVerification;
    private readonly nint _windowHandle;

    public SettingsDialog(
        MainViewModel viewModel,
        IBackupService backupService,
        IRecoveryService recoveryService,
        ILocalFolderSyncService syncService,
        IGitHubSyncService githubSyncService,
        ISecurityLifecycleService securityLifecycle,
        IUserVerificationService userVerification)
    {
        InitializeComponent();
        _viewModel = viewModel;
        _backupService = backupService;
        _recoveryService = recoveryService;
        _syncService = syncService;
        _githubSyncService = githubSyncService;
        _securityLifecycle = securityLifecycle;
        _userVerification = userVerification;
        _windowHandle = WinRT.Interop.WindowNative.GetWindowHandle(this);
        SettingsRoot.RequestedTheme = viewModel.Settings.Theme switch
        {
            AppTheme.Light => ElementTheme.Light,
            AppTheme.Dark => ElementTheme.Dark,
            _ => ElementTheme.Default,
        };
        WindowId windowId = Win32Interop.GetWindowIdFromWindow(_windowHandle);
        AppWindow appWindow = AppWindow.GetFromWindowId(windowId);
        appWindow.Resize(new SizeInt32(900, 720));
        if (appWindow.Presenter is OverlappedPresenter presenter)
        {
            presenter.IsResizable = true;
            presenter.IsMaximizable = true;
            presenter.PreferredMinimumWidth = 540;
            presenter.PreferredMinimumHeight = 480;
        }

        SettingsNavigation.SelectedItem = SettingsNavigation.MenuItems[0];
        PopulateSettings(viewModel.Settings);
        PopulateMigrationState();
        _ = RefreshSyncStatusAsync();
        _ = RefreshGitHubStatusAsync();
        _ = RefreshDevicesAsync();
    }

    private async void SaveSettingsButton_Click(
        object sender,
        RoutedEventArgs args)
    {
        try
        {
            var settings = new AppSettings
            {
                Theme = ThemeBox.SelectedIndex switch
                {
                    1 => AppTheme.Light,
                    2 => AppTheme.Dark,
                    _ => AppTheme.System,
                },
                AutomaticLockMinutes = checked((int)AutoLockBox.Value),
                LockWhenMinimised = LockMinimisedToggle.IsOn,
                LockWhenWindowsLocks = LockWindowsToggle.IsOn,
                HideCodesByDefault = HideCodesToggle.IsOn,
                ClipboardClearSeconds = checked((int)ClipboardDelayBox.Value),
                RequireVerificationForCodes = VerificationToggle.IsOn,
                StartUnlocked = StartUnlockedToggle.IsOn,
            };
            await _viewModel.SaveSettingsAsync(settings, CancellationToken.None);
            Close();
        }
        catch (Exception exception)
        {
            ShowBackupStatus(
                exception is SafeApplicationException ? exception.Message : "Settings could not be saved.",
                isError: true);
        }
    }

    private void CloseSettingsButton_Click(
        object sender,
        RoutedEventArgs args) =>
        Close();

    private void SettingsNavigation_SelectionChanged(
        NavigationView sender,
        NavigationViewSelectionChangedEventArgs args)
    {
        if (args.SelectedItemContainer?.Tag is not string selectedPage)
        {
            return;
        }

        FrameworkElement[] pages =
        [
            GeneralPage,
            BackupRecoveryPage,
            SyncPage,
            DevicesPage,
            AboutPage,
        ];
        foreach (FrameworkElement page in pages)
        {
            page.Visibility = string.Equals(
                page.Name,
                selectedPage,
                StringComparison.Ordinal)
                ? Visibility.Visible
                : Visibility.Collapsed;
        }
    }

    private void SettingsRoot_SizeChanged(
        object sender,
        SizeChangedEventArgs args)
    {
        bool showFullPane = args.NewSize.Width >= 680;
        SettingsNavigation.PaneDisplayMode = showFullPane
            ? NavigationViewPaneDisplayMode.Left
            : NavigationViewPaneDisplayMode.LeftMinimal;
        SettingsNavigation.IsPaneOpen = showFullPane;
        SettingsPages.Margin = showFullPane
            ? new Thickness(0)
            : new Thickness(48, 0, 0, 0);
    }

    private async void ExportButton_Click(object sender, RoutedEventArgs args)
    {
        if (!_viewModel.IsUnlocked)
        {
            ShowBackupStatus("Unlock the vault before creating a backup.", isError: true);
            return;
        }

        string password = BackupPasswordBox.Password;
        if (!string.Equals(password, ConfirmPasswordBox.Password, StringComparison.Ordinal))
        {
            ShowBackupStatus("The backup passwords do not match.", isError: true);
            return;
        }

        var picker = new FileSavePicker
        {
            SuggestedFileName = $"PersonalAuthenticator-{DateTime.UtcNow:yyyy-MM-dd}",
            SuggestedStartLocation = PickerLocationId.DocumentsLibrary,
        };
        picker.FileTypeChoices.Add("Personal Authenticator backup", [".pab"]);
        WinRT.Interop.InitializeWithWindow.Initialize(picker, _windowHandle);
        Windows.Storage.StorageFile? file = await picker.PickSaveFileAsync();
        if (file is null)
        {
            ClearPasswords();
            return;
        }

        try
        {
            await _backupService.ExportAsync(
                file.Path,
                password.AsMemory(),
                _viewModel.FindAllAccounts(),
                overwriteExisting: true,
                CancellationToken.None);
            ShowBackupStatus("Encrypted backup exported successfully.", isError: false);
        }
        catch (Exception exception)
        {
            ShowBackupStatus(
                exception is SafeApplicationException ? exception.Message : "The encrypted backup could not be exported.",
                isError: true);
        }
        finally
        {
            ClearPasswords();
        }
    }

    private async void UpgradeVaultButton_Click(object sender, RoutedEventArgs args)
    {
        UpgradeVaultButton.IsEnabled = false;
        try
        {
            await _viewModel.ApplyMigrationChoiceAsync(
                VaultMigrationChoice.UpgradeToV2,
                CancellationToken.None);
            PopulateMigrationState();
            ShowBackupStatus(
                "The verified v2 vault is active. The original v1 vault remains unchanged.",
                isError: false);
        }
        catch (Exception exception)
        {
            ShowBackupStatus(
                exception is SafeApplicationException
                    ? exception.Message
                    : "The vault could not be upgraded safely.",
                isError: true);
        }
        finally
        {
            UpgradeVaultButton.IsEnabled = _viewModel.CanUpgradeVault;
        }
    }

    private async void ImportButton_Click(object sender, RoutedEventArgs args)
    {
        if (!_viewModel.IsUnlocked)
        {
            ShowBackupStatus("Unlock the vault before restoring a backup.", isError: true);
            return;
        }

        string password = BackupPasswordBox.Password;
        var picker = new FileOpenPicker
        {
            SuggestedStartLocation = PickerLocationId.DocumentsLibrary,
        };
        picker.FileTypeFilter.Add(".pab");
        WinRT.Interop.InitializeWithWindow.Initialize(picker, _windowHandle);
        Windows.Storage.StorageFile? file = await picker.PickSingleFileAsync();
        if (file is null)
        {
            ClearPasswords();
            return;
        }

        IReadOnlyList<TotpAccount>? imported = null;
        try
        {
            imported = await _backupService.ImportAsync(file.Path, password.AsMemory(), CancellationToken.None);
            BackupImportMode mode = ImportModeBox.SelectedIndex switch
            {
                1 => BackupImportMode.MergeReplaceDuplicates,
                2 => BackupImportMode.MergeAddDuplicates,
                3 => BackupImportMode.Replace,
                _ => BackupImportMode.Merge,
            };
            await _viewModel.ImportAsync(imported, mode, CancellationToken.None);
            imported = null;
            ShowBackupStatus("Encrypted backup restored successfully.", isError: false);
        }
        catch (Exception exception)
        {
            ShowBackupStatus(
                exception is SafeApplicationException ? exception.Message : "The encrypted backup could not be restored.",
                isError: true);
        }
        finally
        {
            if (imported is not null)
            {
                foreach (TotpAccount account in imported)
                {
                    account.Dispose();
                }
            }

            ClearPasswords();
        }
    }

    private void PopulateSettings(AppSettings settings)
    {
        ThemeBox.SelectedIndex = settings.Theme switch
        {
            AppTheme.Light => 1,
            AppTheme.Dark => 2,
            _ => 0,
        };
        AutoLockBox.Value = settings.AutomaticLockMinutes;
        LockMinimisedToggle.IsOn = settings.LockWhenMinimised;
        LockWindowsToggle.IsOn = settings.LockWhenWindowsLocks;
        HideCodesToggle.IsOn = settings.HideCodesByDefault;
        ClipboardDelayBox.Value = settings.ClipboardClearSeconds;
        VerificationToggle.IsOn = settings.RequireVerificationForCodes;
        StartUnlockedToggle.IsOn = settings.StartUnlocked;
    }

    private void PopulateMigrationState()
    {
        VaultModeText.Text = _viewModel.MigrationStatus switch
        {
            VaultMigrationStatus.ChoiceRequired =>
                "An existing v1 vault was detected. No v2 storage has been created.",
            VaultMigrationStatus.UsingLegacyV1 =>
                "The app is continuing to use the original v1 vault.",
            VaultMigrationStatus.UsingLocalV2 =>
                "The verified encrypted v2 vault is active.",
            _ => "No legacy vault migration is required.",
        };
        UpgradeVaultButton.Visibility = _viewModel.CanUpgradeVault
            ? Visibility.Visible
            : Visibility.Collapsed;
        UpgradeVaultButton.IsEnabled = _viewModel.CanUpgradeVault;
    }

    private async void CreateRecoveryButton_Click(object sender, RoutedEventArgs args)
    {
        if (!_viewModel.IsUnlocked)
        {
            ShowBackupStatus(
                "Unlock the vault before creating a recovery bundle.",
                isError: true);
            return;
        }

        string password = RecoveryPasswordBox.Password;
        if (!string.Equals(
                password,
                ConfirmRecoveryPasswordBox.Password,
                StringComparison.Ordinal))
        {
            ShowBackupStatus("The recovery passwords do not match.", isError: true);
            return;
        }

        var picker = new FolderPicker
        {
            SuggestedStartLocation = PickerLocationId.DocumentsLibrary,
        };
        picker.FileTypeFilter.Add("*");
        WinRT.Interop.InitializeWithWindow.Initialize(picker, _windowHandle);
        Windows.Storage.StorageFolder? folder = await picker.PickSingleFolderAsync();
        if (folder is null)
        {
            ClearRecoveryPasswords();
            return;
        }

        try
        {
            RecoveryBundleInfo info = await _recoveryService.CreateRecoveryBundleAsync(
                folder.Path,
                password.AsMemory(),
                CancellationToken.None);
            ShowBackupStatus(
                $"Recovery-{info.Slot} was encrypted and fully verified with sync history.",
                isError: false);
            await RefreshRecoveryHealthAsync();
        }
        catch (Exception exception)
        {
            ShowBackupStatus(
                exception is SafeApplicationException
                    ? exception.Message
                    : "The recovery bundle could not be created.",
                isError: true);
        }
        finally
        {
            ClearRecoveryPasswords();
        }
    }

    private async void VerifyRecoveryButton_Click(object sender, RoutedEventArgs args)
    {
        string password = RecoveryPasswordBox.Password;
        string? filePath = await PickRecoveryFileAsync();
        if (filePath is null)
        {
            ClearRecoveryPasswords();
            return;
        }

        try
        {
            RecoveryBundleInfo info = await _recoveryService.VerifyRecoveryBundleAsync(
                filePath,
                password.AsMemory(),
                CancellationToken.None);
            ShowBackupStatus(
                info.ContainsSyncHistory
                    ? $"Recovery-{info.Slot} passed complete record and sync-history verification."
                    : $"Recovery-{info.Slot} is an older bundle without sync history. It is importable, but restoring it starts a new sync history and requires sync reconfiguration.",
                isError: false);
            await RefreshRecoveryHealthAsync();
        }
        catch (Exception exception)
        {
            ShowBackupStatus(
                exception is SafeApplicationException
                    ? exception.Message
                    : "The recovery bundle failed verification.",
                isError: true);
        }
        finally
        {
            ClearRecoveryPasswords();
        }
    }

    private async void RestoreRecoveryButton_Click(object sender, RoutedEventArgs args)
    {
        string password = RecoveryPasswordBox.Password;
        if (!string.Equals(
                password,
                ConfirmRecoveryPasswordBox.Password,
                StringComparison.Ordinal))
        {
            ShowBackupStatus("The recovery passwords do not match.", isError: true);
            return;
        }

        string? filePath = await PickRecoveryFileAsync();
        if (filePath is null)
        {
            ClearRecoveryPasswords();
            return;
        }

        try
        {
            RecoveryBundleInfo info = await _recoveryService.RestoreRecoveryBundleAsync(
                filePath,
                password.AsMemory(),
                CancellationToken.None);
            await _viewModel.ReloadVaultAsync(CancellationToken.None);
            ShowBackupStatus(
                info.ContainsSyncHistory
                    ? $"Recovery-{info.Slot} restored the verified vault and existing sync history. The previous vault was retained."
                    : $"Recovery-{info.Slot} restored the verified vault. This older bundle started a new sync history; reconfigure sync before using a shared remote. The previous vault was retained.",
                isError: false);
            await RefreshRecoveryHealthAsync();
        }
        catch (Exception exception)
        {
            ShowBackupStatus(
                exception is SafeApplicationException
                    ? exception.Message
                    : "The recovery bundle could not be restored.",
                isError: true);
        }
        finally
        {
            ClearRecoveryPasswords();
        }
    }

    private async void RefreshRecoveryHealthButton_Click(
        object sender,
        RoutedEventArgs args) =>
        await RefreshRecoveryHealthAsync();

    private async Task RefreshRecoveryHealthAsync()
    {
        try
        {
            RecoveryHealthStatus health = await _recoveryService.GetRecoveryHealthAsync(
                CancellationToken.None);
            RecoveryHealthText.Text = !health.HasVerifiedRecovery
                ? "No verified Recovery-A or Recovery-B bundle is currently available."
                : health.IsOutdated
                    ? $"Recovery is outdated: {health.ChangesSinceVerifiedRecovery} vault changes since the last complete verification on {health.LastVerifiedAtUtc:yyyy-MM-dd HH:mm} UTC."
                    : $"Recovery is healthy: {health.ChangesSinceVerifiedRecovery} vault changes since verified Recovery-{health.LastVerifiedSlot} on {health.LastVerifiedAtUtc:yyyy-MM-dd HH:mm} UTC.";
        }
        catch (Exception exception)
        {
            RecoveryHealthText.Text = exception is SafeApplicationException
                ? exception.Message
                : "Recovery health could not be checked.";
        }
    }

    private async Task<string?> PickRecoveryFileAsync()
    {
        var picker = new FileOpenPicker
        {
            SuggestedStartLocation = PickerLocationId.DocumentsLibrary,
        };
        picker.FileTypeFilter.Add(".par");
        WinRT.Interop.InitializeWithWindow.Initialize(picker, _windowHandle);
        Windows.Storage.StorageFile? file = await picker.PickSingleFileAsync();
        return file?.Path;
    }

    private async void ChooseSyncFolderButton_Click(
        object sender,
        RoutedEventArgs args)
    {
        var picker = new FolderPicker
        {
            SuggestedStartLocation = PickerLocationId.DocumentsLibrary,
        };
        picker.FileTypeFilter.Add("*");
        WinRT.Interop.InitializeWithWindow.Initialize(picker, _windowHandle);
        Windows.Storage.StorageFolder? folder = await picker.PickSingleFolderAsync();
        if (folder is not null)
        {
            SyncFolderBox.Text = folder.Path;
        }
    }

    private async void ConfigureSyncButton_Click(
        object sender,
        RoutedEventArgs args)
    {
        string password = SyncPasswordBox.Password;
        try
        {
            await _syncService.ConfigureAsync(
                SyncFolderBox.Text,
                password.AsMemory(),
                CancellationToken.None);
            ShowBackupStatus(
                "Encrypted local-folder sync was configured. No network service or token is used.",
                isError: false);
            await RefreshSyncStatusAsync();
        }
        catch (Exception exception)
        {
            ShowBackupStatus(
                exception is SafeApplicationException
                    ? exception.Message
                    : "Local-folder sync could not be configured.",
                isError: true);
        }
        finally
        {
            SyncPasswordBox.Password = string.Empty;
        }
    }

    private async void SyncNowButton_Click(object sender, RoutedEventArgs args)
    {
        try
        {
            await _syncService.SyncNowAsync(CancellationToken.None);
            await _viewModel.ReloadVaultAsync(CancellationToken.None);
            ShowBackupStatus("Local-folder synchronisation completed.", isError: false);
        }
        catch (Exception exception)
        {
            ShowBackupStatus(
                exception is SafeApplicationException
                    ? exception.Message
                    : "Local-folder synchronisation failed. Pending changes remain queued.",
                isError: true);
        }
        finally
        {
            await RefreshSyncStatusAsync();
        }
    }

    private async void RefreshSyncButton_Click(
        object sender,
        RoutedEventArgs args) =>
        await RefreshSyncStatusAsync();

    private async void ResolveConflictButton_Click(
        object sender,
        RoutedEventArgs args)
    {
        if (ConflictBox.SelectedItem is not SyncConflictSummary conflict)
        {
            ShowBackupStatus("Select a conflict to resolve.", isError: true);
            return;
        }

        SyncConflictResolution resolution = ConflictResolutionBox.SelectedIndex switch
        {
            1 => SyncConflictResolution.KeepB,
            2 => SyncConflictResolution.KeepBoth,
            3 => SyncConflictResolution.SeparateAccounts,
            _ => SyncConflictResolution.KeepA,
        };
        try
        {
            await _syncService.ResolveConflictAsync(
                conflict.Id,
                resolution,
                CancellationToken.None);
            await _viewModel.ReloadVaultAsync(CancellationToken.None);
            ShowBackupStatus(
                "The conflict resolution was committed locally and queued for sync.",
                isError: false);
        }
        catch (Exception exception)
        {
            ShowBackupStatus(
                exception is SafeApplicationException
                    ? exception.Message
                    : "The conflict could not be resolved.",
                isError: true);
        }
        finally
        {
            await RefreshSyncStatusAsync();
        }
    }

    private async Task RefreshSyncStatusAsync()
    {
        try
        {
            SyncStatus status = await _syncService.GetSyncStatusAsync(
                CancellationToken.None);
            SyncFolderBox.Text = status.BackendPath ?? SyncFolderBox.Text;
            string lastSuccess = status.LastSuccessfulSyncAtUtc.HasValue
                ? status.LastSuccessfulSyncAtUtc.Value.ToString(
                    "yyyy-MM-dd HH:mm 'UTC'",
                    System.Globalization.CultureInfo.InvariantCulture)
                : "never";
            SyncStatusText.Text = !status.IsConfigured
                ? "Local-folder sync is not configured."
                : (status.IsReadOnlyCompatibilityMode
                    ? "Read-only compatibility mode · upgrade the app before this device can write sync objects · "
                    : string.Empty) +
                  $"Device {status.DeviceId:D} · {status.PendingOperationCount} pending · " +
                  $"{status.ConflictCount} conflict(s) · last success: {lastSuccess}" +
                  (string.IsNullOrWhiteSpace(status.LastError)
                      ? string.Empty
                      : $" · {status.LastError}");
            IReadOnlyList<SyncConflictSummary> conflicts =
                status.IsConfigured
                    ? await _syncService.GetConflictsAsync(CancellationToken.None)
                    : [];
            ConflictBox.ItemsSource = conflicts;
            ConflictBox.SelectedIndex = conflicts.Count == 0 ? -1 : 0;
        }
        catch (Exception exception)
        {
            SyncStatusText.Text = exception is SafeApplicationException
                ? exception.Message
                : "Sync status could not be read.";
            ConflictBox.ItemsSource = null;
        }
    }

    private async void ConfigureGitHubButton_Click(
        object sender,
        RoutedEventArgs args) =>
        await ConfigureGitHubAsync(replaceRepository: false);

    private async void ReplaceGitHubButton_Click(
        object sender,
        RoutedEventArgs args) =>
        await ConfigureGitHubAsync(replaceRepository: true);

    private async Task ConfigureGitHubAsync(bool replaceRepository)
    {
        string token = GitHubTokenBox.Password;
        string syncPassword = GitHubSyncPasswordBox.Password;
        var request = new GitHubConnectionRequest(
            GitHubOwnerBox.Text.Trim(),
            GitHubRepositoryBox.Text.Trim(),
            GitHubBranchBox.Text.Trim(),
            GitHubPathBox.Text.Trim(),
            GitHubBackgroundToggle.IsOn);
        try
        {
            if (replaceRepository)
            {
                await _githubSyncService.ReplaceGitHubRepositoryAsync(
                    request,
                    token.AsMemory(),
                    syncPassword.AsMemory(),
                    CancellationToken.None);
                ShowBackupStatus(
                    "The replacement repository was uploaded, downloaded with a fresh client, verified, and activated. The previous configuration remains disabled.",
                    isError: false);
            }
            else
            {
                await _githubSyncService.ConfigureGitHubAsync(
                    request,
                    token.AsMemory(),
                    syncPassword.AsMemory(),
                    CancellationToken.None);
                ShowBackupStatus(
                    "GitHub sync is connected to the verified private repository.",
                    isError: false);
            }
        }
        catch (Exception exception)
        {
            ShowBackupStatus(
                exception is SafeApplicationException
                    ? exception.Message
                    : "The GitHub connection could not be configured.",
                isError: true);
        }
        finally
        {
            ClearGitHubSecrets();
            await RefreshGitHubStatusAsync();
        }
    }

    private async void TestGitHubButton_Click(object sender, RoutedEventArgs args)
    {
        try
        {
            await _githubSyncService.TestGitHubConnectionAsync(
                CancellationToken.None);
            ShowBackupStatus(
                "GitHub authentication, privacy, repository identity, permissions, vault, and protocol checks passed.",
                isError: false);
        }
        catch (Exception exception)
        {
            ShowBackupStatus(
                exception is SafeApplicationException
                    ? exception.Message
                    : "The GitHub connection test failed.",
                isError: true);
        }
        finally
        {
            await RefreshGitHubStatusAsync();
        }
    }

    private async void SyncGitHubButton_Click(object sender, RoutedEventArgs args)
    {
        try
        {
            await _githubSyncService.SyncGitHubNowAsync(CancellationToken.None);
            await _viewModel.ReloadVaultAsync(CancellationToken.None);
            ShowBackupStatus("GitHub synchronisation completed.", isError: false);
        }
        catch (Exception exception)
        {
            ShowBackupStatus(
                exception is SafeApplicationException
                    ? exception.Message
                    : "GitHub synchronisation failed. Local changes remain queued.",
                isError: true);
        }
        finally
        {
            await RefreshGitHubStatusAsync();
        }
    }

    private async void RepairGitHubButton_Click(object sender, RoutedEventArgs args)
    {
        try
        {
            await _githubSyncService.RepairGitHubRemoteAsync(
                CancellationToken.None);
            ShowBackupStatus(
                "Remote Repair completed without deleting unknown remote files.",
                isError: false);
        }
        catch (Exception exception)
        {
            ShowBackupStatus(
                exception is SafeApplicationException
                    ? exception.Message
                    : "Remote Repair could not complete safely.",
                isError: true);
        }
        finally
        {
            await RefreshGitHubStatusAsync();
        }
    }

    private async void ForgetGitHubButton_Click(object sender, RoutedEventArgs args)
    {
        try
        {
            await _githubSyncService.DisableAndForgetGitHubAsync(
                CancellationToken.None);
            ShowBackupStatus(
                "GitHub sync and the stored DPAPI credential were removed. The repository was not deleted.",
                isError: false);
        }
        catch (Exception exception)
        {
            ShowBackupStatus(
                exception is SafeApplicationException
                    ? exception.Message
                    : "GitHub credentials could not be removed.",
                isError: true);
        }
        finally
        {
            ClearGitHubSecrets();
            await RefreshGitHubStatusAsync();
        }
    }

    private async Task RefreshGitHubStatusAsync()
    {
        try
        {
            GitHubSyncStatus status = await _githubSyncService.GetGitHubStatusAsync(
                CancellationToken.None);
            GitHubBackgroundToggle.IsOn = status.IsBackgroundSyncEnabled;
            GitHubStatusText.Text = !status.IsConfigured
                ? "GitHub sync is not configured."
                : $"{status.Repository} · repository ID {status.RepositoryId} · " +
                  $"{status.PendingOperationCount} pending · {status.RemoteHealth} · " +
                  $"last success: {(status.LastSuccessfulSyncAtUtc.HasValue ? status.LastSuccessfulSyncAtUtc.Value.ToString("yyyy-MM-dd HH:mm 'UTC'", System.Globalization.CultureInfo.InvariantCulture) : "never")}" +
                  (string.IsNullOrWhiteSpace(status.AuthenticationStatus)
                      ? string.Empty
                      : $" · {status.AuthenticationStatus}") +
                  (string.IsNullOrWhiteSpace(status.LastError)
                      ? string.Empty
                      : $" · {status.LastError}");
        }
        catch (Exception exception)
        {
            GitHubStatusText.Text = exception is SafeApplicationException
                ? exception.Message
                : "GitHub sync status could not be read.";
        }
    }

    private void ClearGitHubSecrets()
    {
        GitHubTokenBox.Password = string.Empty;
        GitHubSyncPasswordBox.Password = string.Empty;
    }

    private async Task RefreshDevicesAsync()
    {
        try
        {
            IReadOnlyList<AuthorisedDeviceInfo> devices =
                await _securityLifecycle.GetDevicesAsync(CancellationToken.None);
            DevicesList.ItemsSource = devices;
            DevicesList.Visibility =
                devices.Count == 0 ? Visibility.Collapsed : Visibility.Visible;
            DevicesEmptyText.Visibility =
                devices.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
            SecurityEpochStatus epoch =
                await _securityLifecycle.GetSecurityEpochStatusAsync(
                    CancellationToken.None);
            DeviceDetailsText.Text =
                $"{devices.Count(device => !device.IsRevoked)} authorised · " +
                $"{devices.Count(device => device.IsRevoked)} revoked · select a device to rename or revoke.";
            SecurityEpochText.Text =
                $"Active key epoch: {epoch.ActiveEpoch}" +
                (epoch.RotationPending ? $" · pending epoch: {epoch.PendingEpoch}" : string.Empty) +
                (epoch.PurgePending ? $" · purge pending for {epoch.PurgeAccountId}" : string.Empty) +
                (string.IsNullOrWhiteSpace(epoch.LastFailure)
                    ? string.Empty
                    : $" · last interruption: {epoch.LastFailure}");
        }
        catch (Exception exception)
        {
            DeviceDetailsText.Text = exception is SafeApplicationException
                ? exception.Message
                : "Device security state could not be read.";
        }
    }

    private async void RefreshDevicesButton_Click(
        object sender,
        RoutedEventArgs args) =>
        await RefreshDevicesAsync();

    private async void RenameDeviceButton_Click(
        object sender,
        RoutedEventArgs args)
    {
        if (DevicesList.SelectedItem is not AuthorisedDeviceInfo device)
        {
            ShowBackupStatus("Select a device first.", isError: true);
            return;
        }

        try
        {
            await _securityLifecycle.RenameDeviceAsync(
                device.DeviceId,
                DeviceNameBox.Text,
                CancellationToken.None);
            DeviceNameBox.Text = string.Empty;
            ShowBackupStatus("Device name updated.", isError: false);
        }
        catch (Exception exception)
        {
            ShowBackupStatus(
                exception is SafeApplicationException
                    ? exception.Message
                    : "The device could not be renamed.",
                isError: true);
        }
        finally
        {
            await RefreshDevicesAsync();
        }
    }

    private async void RevokeDeviceButton_Click(
        object sender,
        RoutedEventArgs args)
    {
        if (DevicesList.SelectedItem is not AuthorisedDeviceInfo device)
        {
            ShowBackupStatus("Select a device first.", isError: true);
            return;
        }

        try
        {
            if (!await _userVerification.RequestAsync(
                    "Verify your identity to revoke this Windows device",
                    CancellationToken.None))
            {
                return;
            }

            await _securityLifecycle.RevokeDeviceAsync(
                device.DeviceId,
                CancellationToken.None);
            ShowBackupStatus(
                "Future operations from this device are rejected. Revoke its GitHub token separately; copied secrets cannot be erased remotely.",
                isError: false);
        }
        catch (Exception exception)
        {
            ShowBackupStatus(
                exception is SafeApplicationException
                    ? exception.Message
                    : "The device could not be revoked.",
                isError: true);
        }
        finally
        {
            await RefreshDevicesAsync();
        }
    }

    private async void RotateKeysButton_Click(
        object sender,
        RoutedEventArgs args)
    {
        try
        {
            if (!await _userVerification.RequestAsync(
                    "Verify your identity to rotate authenticator encryption keys",
                    CancellationToken.None))
            {
                return;
            }

            await _securityLifecycle.RotateKeysAsync(
                SecurityRecoveryDirectoryBox.Text.Trim(),
                SecurityRecoveryPasswordBox.Password.AsMemory(),
                CancellationToken.None);
            ShowBackupStatus(
                "A new vault key epoch and verified Recovery-A/B bundle were activated. Previous encrypted files remain for rollback.",
                isError: false);
        }
        catch (Exception exception)
        {
            ShowBackupStatus(
                exception is SafeApplicationException
                    ? exception.Message
                    : "Key rotation did not activate. The previous epoch remains active.",
                isError: true);
        }
        finally
        {
            SecurityRecoveryPasswordBox.Password = string.Empty;
            await RefreshDevicesAsync();
        }
    }

    private async void PurgeAccountButton_Click(
        object sender,
        RoutedEventArgs args)
    {
        try
        {
            if (!Guid.TryParse(PurgeAccountIdBox.Text, out Guid accountId))
            {
                throw new SafeApplicationException(
                    "Security.PurgeAccountInvalid",
                    "Enter a valid archived account ID.");
            }

            if (!await _userVerification.RequestAsync(
                    "Verify your identity to permanently purge this archived account",
                    CancellationToken.None))
            {
                return;
            }

            await _securityLifecycle.PurgeAccountAsync(
                accountId,
                PurgeConfirmationBox.Text,
                SecurityRecoveryDirectoryBox.Text.Trim(),
                SecurityRecoveryPasswordBox.Password.AsMemory(),
                CancellationToken.None);
            PurgeConfirmationBox.Text = string.Empty;
            ShowBackupStatus(
                "The account was excluded from a clean local key epoch. Replace the remote generation and retire old recovery files where appropriate. Physical erasure is not guaranteed.",
                isError: false);
        }
        catch (Exception exception)
        {
            ShowBackupStatus(
                exception is SafeApplicationException
                    ? exception.Message
                    : "Permanent purge did not activate. The previous epoch remains active.",
                isError: true);
        }
        finally
        {
            SecurityRecoveryPasswordBox.Password = string.Empty;
            await RefreshDevicesAsync();
        }
    }

    private void ClearRecoveryPasswords()
    {
        RecoveryPasswordBox.Password = string.Empty;
        ConfirmRecoveryPasswordBox.Password = string.Empty;
    }

    private void Window_Closed(object sender, WindowEventArgs args)
    {
        ClearPasswords();
        ClearRecoveryPasswords();
        SyncPasswordBox.Password = string.Empty;
        ClearGitHubSecrets();
        SecurityRecoveryPasswordBox.Password = string.Empty;
    }

    private void ClearPasswords()
    {
        BackupPasswordBox.Password = string.Empty;
        ConfirmPasswordBox.Password = string.Empty;
    }

    private void ShowBackupStatus(string message, bool isError)
    {
        SettingsStatusText.Text = message;
        SettingsStatus.Severity = isError ? InfoBarSeverity.Error : InfoBarSeverity.Success;
        SettingsStatus.IsOpen = true;
    }
}
