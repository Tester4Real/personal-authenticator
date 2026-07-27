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
    private readonly nint _windowHandle;

    public SettingsDialog(
        MainViewModel viewModel,
        IBackupService backupService,
        nint windowHandle)
    {
        InitializeComponent();
        _viewModel = viewModel;
        _backupService = backupService;
        _windowHandle = windowHandle;
        PopulateSettings(viewModel.Settings);
        PopulateMigrationState();
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
