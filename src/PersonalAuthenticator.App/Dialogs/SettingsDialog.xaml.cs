using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using PersonalAuthenticator.App.ViewModels;
using PersonalAuthenticator.Core.Abstractions;
using PersonalAuthenticator.Core.Domain;
using PersonalAuthenticator.Core.Exceptions;
using Windows.Storage.Pickers;

namespace PersonalAuthenticator.App.Dialogs;

public sealed partial class SettingsDialog : ContentDialog
{
    private readonly MainViewModel _viewModel;
    private readonly IBackupService _backupService;
    private readonly IRecoveryService _recoveryService;
    private readonly ILocalFolderSyncService _syncService;
    private readonly nint _windowHandle;

    public SettingsDialog(
        MainViewModel viewModel,
        IBackupService backupService,
        IRecoveryService recoveryService,
        ILocalFolderSyncService syncService,
        nint windowHandle)
    {
        InitializeComponent();
        _viewModel = viewModel;
        _backupService = backupService;
        _recoveryService = recoveryService;
        _syncService = syncService;
        _windowHandle = windowHandle;
        PopulateSettings(viewModel.Settings);
        PopulateMigrationState();
        _ = RefreshSyncStatusAsync();
    }

    private async void Dialog_PrimaryButtonClick(ContentDialog sender, ContentDialogButtonClickEventArgs args)
    {
        ContentDialogButtonClickDeferral deferral = args.GetDeferral();
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
        }
        catch (Exception exception)
        {
            args.Cancel = true;
            ShowBackupStatus(
                exception is SafeApplicationException ? exception.Message : "Settings could not be saved.",
                isError: true);
        }
        finally
        {
            deferral.Complete();
        }
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

    private void ClearRecoveryPasswords()
    {
        RecoveryPasswordBox.Password = string.Empty;
        ConfirmRecoveryPasswordBox.Password = string.Empty;
    }

    private void Dialog_Closed(ContentDialog sender, ContentDialogClosedEventArgs args)
    {
        ClearPasswords();
        ClearRecoveryPasswords();
        SyncPasswordBox.Password = string.Empty;
    }

    private void ClearPasswords()
    {
        BackupPasswordBox.Password = string.Empty;
        ConfirmPasswordBox.Password = string.Empty;
    }

    private void ShowBackupStatus(string message, bool isError)
    {
        SettingsStatus.Message = message;
        SettingsStatus.Severity = isError ? InfoBarSeverity.Error : InfoBarSeverity.Success;
        SettingsStatus.IsOpen = true;
    }
}
