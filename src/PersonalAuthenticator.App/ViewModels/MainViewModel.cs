using System.Collections.ObjectModel;
using System.Diagnostics;
using CommunityToolkit.Mvvm.ComponentModel;
using PersonalAuthenticator.Core.Abstractions;
using PersonalAuthenticator.Core.Domain;
using PersonalAuthenticator.Core.Exceptions;

namespace PersonalAuthenticator.App.ViewModels;

public sealed partial class MainViewModel : ObservableObject
{
    private readonly IVaultService _vault;
    private readonly ITotpGenerator _generator;
    private readonly IClock _clock;
    private readonly ISecureClipboardService _clipboard;
    private readonly IUserVerificationService _verification;
    private readonly IAppSettingsStore _settingsStore;
    private readonly IVaultMigrationCoordinator _migrationCoordinator;
    private readonly IV2VaultFeatures _v2Features;
    private readonly Stopwatch _monotonicClock = Stopwatch.StartNew();
    private DateTimeOffset _lastWallClock;
    private TimeSpan _lastMonotonic;
    private bool _clockWarningShown;
    private bool _canUseV2Features;

    public MainViewModel(
        IVaultService vault,
        ITotpGenerator generator,
        IClock clock,
        ISecureClipboardService clipboard,
        IUserVerificationService verification,
        IAppSettingsStore settingsStore,
        IVaultMigrationCoordinator migrationCoordinator,
        IV2VaultFeatures v2Features)
    {
        _vault = vault;
        _generator = generator;
        _clock = clock;
        _clipboard = clipboard;
        _verification = verification;
        _settingsStore = settingsStore;
        _migrationCoordinator = migrationCoordinator;
        _v2Features = v2Features;
        _vault.AccountsChanged += OnVaultAccountsChanged;
        _vault.StateChanged += OnVaultStateChanged;
    }

    public ObservableCollection<AccountCardViewModel> VisibleAccounts { get; } = [];

    public AppSettings Settings { get; private set; } = new();

    public VaultMigrationStatus MigrationStatus { get; private set; } =
        VaultMigrationStatus.NotRequired;

    public bool IsMigrationChoiceRequired =>
        MigrationStatus == VaultMigrationStatus.ChoiceRequired;

    public bool CanUpgradeVault =>
        MigrationStatus is
            VaultMigrationStatus.ChoiceRequired or
            VaultMigrationStatus.UsingLegacyV1;

    public bool CanUseV2Features => _canUseV2Features;

    public bool IsUnlocked => _vault.State == VaultState.Unlocked;

    public bool IsLocked => !IsUnlocked;

    public bool HasAccounts => VisibleAccounts.Count > 0;

    public string LockButtonLabel => IsUnlocked ? "Lock vault" : "Unlock vault";

    [ObservableProperty]
    public partial string SearchText { get; set; } = string.Empty;

    [ObservableProperty]
    public partial bool FavouritesOnly { get; set; }

    public event EventHandler<NotificationEventArgs>? NotificationRequested;

    partial void OnSearchTextChanged(string value) => RebuildVisibleAccounts();

    partial void OnFavouritesOnlyChanged(bool value) => RebuildVisibleAccounts();

    public async Task InitialiseAsync(CancellationToken cancellationToken)
    {
        Settings = await _settingsStore.LoadAsync(cancellationToken);
        await _vault.InitialiseAsync(unlock: false, cancellationToken);
        await RefreshMigrationStatusAsync(cancellationToken);
        if (Settings.StartUnlocked &&
            _vault.State == VaultState.Locked &&
            !IsMigrationChoiceRequired)
        {
            await UnlockAsync(cancellationToken);
        }

        RebuildVisibleAccounts();
        DateTimeOffset now = _clock.UtcNow;
        _lastWallClock = now;
        _lastMonotonic = _monotonicClock.Elapsed;
        RefreshCodes();
    }

    public void RefreshCodes()
    {
        DateTimeOffset now = _clock.UtcNow;
        TimeSpan monotonic = _monotonicClock.Elapsed;
        if (_lastWallClock != default)
        {
            double driftSeconds = Math.Abs(
                (now - _lastWallClock - (monotonic - _lastMonotonic)).TotalSeconds);
            if (driftSeconds > 5 && !_clockWarningShown)
            {
                _clockWarningShown = true;
                Notify(
                    "Check your system clock",
                    "The Windows clock changed unexpectedly. Authenticator codes may be rejected until the clock is corrected.");
            }
        }

        _lastWallClock = now;
        _lastMonotonic = monotonic;
        foreach (AccountCardViewModel account in VisibleAccounts)
        {
            account.Refresh(now, IsUnlocked);
        }
    }

    public async Task<bool> UnlockAsync(CancellationToken cancellationToken)
    {
        if (IsUnlocked)
        {
            return true;
        }

        if (IsMigrationChoiceRequired)
        {
            throw new SafeApplicationException(
                "VaultMigration.ChoiceRequired",
                "Choose whether to upgrade the legacy vault or continue using v1 before unlocking.");
        }

        bool verified = await _verification.RequestAsync(
            "Verify your identity to unlock Personal Authenticator",
            cancellationToken);
        if (!verified)
        {
            Notify("Vault remains locked", "Windows user verification was cancelled.");
            return false;
        }

        await _vault.UnlockAsync(cancellationToken);
        RebuildVisibleAccounts();
        RefreshCodes();
        return true;
    }

    public async Task ApplyMigrationChoiceAsync(
        VaultMigrationChoice choice,
        CancellationToken cancellationToken)
    {
        await _migrationCoordinator.ApplyChoiceAsync(choice, cancellationToken);
        await RefreshMigrationStatusAsync(cancellationToken);
        if (choice == VaultMigrationChoice.UpgradeToV2)
        {
            Notify(
                "Vault upgraded",
                "The v2 vault was verified and activated. The original v1 vault remains unchanged.");
        }
        else if (choice == VaultMigrationChoice.ContinueUsingV1)
        {
            Notify(
                "Continuing with v1",
                "The app will keep using the original local vault. You can upgrade later from Settings.");
        }
    }

    public async Task LockAsync(CancellationToken cancellationToken)
    {
        await _clipboard.CancelPendingClearAsync();
        await _vault.LockAsync(cancellationToken);
        RebuildVisibleAccounts();
    }

    public async Task AddAsync(
        TotpAccount account,
        DuplicateResolution resolution,
        CancellationToken cancellationToken)
    {
        try
        {
            await _vault.AddAsync(account, resolution, cancellationToken);
            await RefreshMigrationStatusAsync(cancellationToken);
            Notify("Account added", $"{account.Issuer} — {account.AccountName}");
        }
        catch
        {
            if (!_vault.Accounts.Contains(account))
            {
                account.Dispose();
            }

            throw;
        }
    }

    public Guid? FindDuplicate(TotpAccount account) => _vault.FindLikelyDuplicate(account);

    public DuplicateAccountMatch? FindDuplicateMatch(TotpAccount account) =>
        _vault.FindDuplicate(account);

    public AccountCardViewModel? FindCard(Guid id) =>
        VisibleAccounts.FirstOrDefault(account => account.Id == id);

    public TotpAccount? FindAccount(Guid id) =>
        _vault.Accounts.FirstOrDefault(account => account.Id == id);

    public IReadOnlyCollection<TotpAccount> FindAllAccounts() => _vault.Accounts;

    public async Task EditAsync(
        Guid id,
        string issuer,
        string accountName,
        CancellationToken cancellationToken)
    {
        await _vault.UpdateDisplayAsync(id, issuer, accountName, cancellationToken);
        Notify("Account updated", "Display information was saved.");
    }

    public async Task ToggleFavouriteAsync(Guid id, CancellationToken cancellationToken)
    {
        TotpAccount account = FindAccount(id) ??
            throw new SafeApplicationException("Vault.NotFound", "The selected account no longer exists.");
        await _vault.SetFavouriteAsync(id, !account.Favourite, cancellationToken);
    }

    public async Task MoveAsync(Guid id, int offset, CancellationToken cancellationToken)
    {
        TotpAccount account = FindAccount(id) ??
            throw new SafeApplicationException("Vault.NotFound", "The selected account no longer exists.");
        int target = Math.Clamp(account.SortOrder + offset, 0, _vault.Accounts.Count - 1);
        if (target != account.SortOrder)
        {
            await _vault.MoveAsync(id, target, cancellationToken);
        }
    }

    public async Task DeleteAsync(Guid id, CancellationToken cancellationToken)
    {
        await _vault.DeleteAsync(id, cancellationToken);
        Notify(
            CanUseV2Features ? "Account archived" : "Account deleted",
            CanUseV2Features
                ? "The account and its encrypted secret history can be restored."
                : "The legacy encrypted vault was updated.");
    }

    public async Task AddSecretCandidateAsync(
        Guid accountId,
        TotpAccount candidate,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(candidate);
        try
        {
            await _v2Features.AddSecretCandidateAsync(
                accountId,
                candidate,
                cancellationToken);
            Notify(
                "Candidate secret saved",
                "The current secret remains active until you explicitly activate the candidate.");
        }
        finally
        {
            candidate.Dispose();
        }
    }

    public async Task AddDuplicateAccountAsync(
        Guid relatedAccountId,
        TotpAccount account,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(account);
        try
        {
            await _v2Features.AddDuplicateAccountAsync(
                relatedAccountId,
                account,
                cancellationToken);
            await _vault.ReloadAsync(cancellationToken);
            Notify(
                "Separate account added",
                "Both accounts record the duplicate decision in encrypted account history.");
        }
        finally
        {
            account.Dispose();
        }
    }

    public async Task<bool> ActivateSecretCandidateAsync(
        Guid accountId,
        Guid secretVersionId,
        CancellationToken cancellationToken)
    {
        if (!await _verification.RequestAsync(
                "Verify your identity to activate this candidate secret",
                cancellationToken))
        {
            return false;
        }

        await _v2Features.ActivateSecretCandidateAsync(
            accountId,
            secretVersionId,
            cancellationToken);
        await _vault.ReloadAsync(cancellationToken);
        Notify(
            "Secret activated",
            "The previous active secret was retained as an encrypted retired version.");
        return true;
    }

    public Task<IReadOnlyList<SecretVersionSummary>> GetSecretVersionsAsync(
        Guid accountId,
        CancellationToken cancellationToken) =>
        _v2Features.GetSecretVersionsAsync(accountId, cancellationToken);

    public Task<IReadOnlyList<ArchivedAccountSummary>> GetArchivedAccountsAsync(
        CancellationToken cancellationToken) =>
        _v2Features.GetArchivedAccountsAsync(cancellationToken);

    public async Task RestoreArchivedAccountAsync(
        Guid accountId,
        CancellationToken cancellationToken)
    {
        await _v2Features.RestoreArchivedAccountAsync(accountId, cancellationToken);
        if (IsUnlocked)
        {
            await _vault.ReloadAsync(cancellationToken);
        }

        Notify("Account restored", "The archived account is active again.");
    }

    public Task<IReadOnlyList<AccountHistoryEntryV2>> GetAccountHistoryAsync(
        Guid accountId,
        CancellationToken cancellationToken) =>
        _v2Features.GetAccountHistoryAsync(accountId, cancellationToken);

    public async Task<SensitiveSetupInfo?> GetSensitiveSetupInfoAsync(
        Guid accountId,
        CancellationToken cancellationToken)
    {
        if (!IsUnlocked)
        {
            throw new SafeApplicationException(
                "Vault.Locked",
                "Unlock the vault before revealing setup information.");
        }

        if (!await _verification.RequestAsync(
                "Verify your identity to reveal the setup URI and QR code",
                cancellationToken))
        {
            return null;
        }

        return await _v2Features.GetActiveSetupInfoAsync(accountId, cancellationToken);
    }

    public async Task CopySensitiveSetupUriAsync(
        SensitiveSetupInfo setupInfo,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(setupInfo);
        if (!IsUnlocked)
        {
            throw new SafeApplicationException(
                "Vault.Locked",
                "Unlock the vault before copying setup information.");
        }

        await _clipboard.CopySensitiveTextAsync(
            setupInfo.ProvisioningUri,
            TimeSpan.FromSeconds(15),
            cancellationToken);
        Notify(
            "Setup URI copied",
            "The clipboard will be cleared in 15 seconds if it is unchanged.");
    }

    public async Task RevealAsync(Guid id, CancellationToken cancellationToken)
    {
        AccountCardViewModel card = FindCard(id) ??
            throw new SafeApplicationException("Vault.NotFound", "The selected account no longer exists.");
        if (Settings.RequireVerificationForCodes &&
            !await _verification.RequestAsync("Verify your identity to reveal this code", cancellationToken))
        {
            return;
        }

        card.SetRevealed(!card.IsRevealed);
        card.Refresh(_clock.UtcNow, IsUnlocked);
    }

    public async Task CopyAsync(Guid id, CancellationToken cancellationToken)
    {
        if (!IsUnlocked)
        {
            throw new SafeApplicationException("Vault.Locked", "Unlock the vault before copying a code.");
        }

        if (Settings.RequireVerificationForCodes &&
            !await _verification.RequestAsync("Verify your identity to copy this code", cancellationToken))
        {
            return;
        }

        TotpAccount account = FindAccount(id) ??
            throw new SafeApplicationException("Vault.NotFound", "The selected account no longer exists.");
        string code = _generator.Generate(account, _clock.UtcNow);
        await _clipboard.CopyCodeAsync(
            code,
            TimeSpan.FromSeconds(Settings.ClipboardClearSeconds),
            cancellationToken);
        Notify("Code copied", $"Clipboard will be cleared in {Settings.ClipboardClearSeconds} seconds if it is unchanged.");
    }

    public async Task SaveSettingsAsync(AppSettings settings, CancellationToken cancellationToken)
    {
        await _settingsStore.SaveAsync(settings, cancellationToken);
        Settings = settings;
        RebuildVisibleAccounts();
        RefreshCodes();
        Notify("Settings saved", "Your preferences were updated.");
    }

    public async Task ImportAsync(
        IReadOnlyCollection<TotpAccount> accounts,
        BackupImportMode mode,
        CancellationToken cancellationToken)
    {
        await _vault.ImportAsync(accounts, mode, cancellationToken);
        await RefreshMigrationStatusAsync(cancellationToken);
        Notify("Backup restored", "Imported accounts were saved to the encrypted Windows vault.");
    }

    public void NotifyError(Exception exception)
    {
        string message = exception is SafeApplicationException safe
            ? safe.Message
            : "The operation could not be completed.";
        Notify("Something went wrong", message, isError: true);
    }

    private void RebuildVisibleAccounts()
    {
        VisibleAccounts.Clear();
        if (!IsUnlocked)
        {
            OnCollectionStateChanged();
            return;
        }

        IEnumerable<TotpAccount> filtered = _vault.Accounts
            .Where(account =>
                (!FavouritesOnly || account.Favourite) &&
                (string.IsNullOrWhiteSpace(SearchText) ||
                 account.Issuer.Contains(SearchText, StringComparison.CurrentCultureIgnoreCase) ||
                 account.AccountName.Contains(SearchText, StringComparison.CurrentCultureIgnoreCase)))
            .OrderByDescending(account => account.Favourite)
            .ThenBy(account => account.SortOrder);

        foreach (TotpAccount account in filtered)
        {
            var card = new AccountCardViewModel(account, _generator, Settings.HideCodesByDefault);
            card.Refresh(_clock.UtcNow, IsUnlocked);
            VisibleAccounts.Add(card);
        }

        OnCollectionStateChanged();
    }

    private void OnCollectionStateChanged()
    {
        OnPropertyChanged(nameof(HasAccounts));
        OnPropertyChanged(nameof(IsUnlocked));
        OnPropertyChanged(nameof(IsLocked));
        OnPropertyChanged(nameof(LockButtonLabel));
    }

    private async Task RefreshMigrationStatusAsync(CancellationToken cancellationToken)
    {
        MigrationStatus = await _migrationCoordinator.GetStatusAsync(cancellationToken);
        _canUseV2Features =
            MigrationStatus == VaultMigrationStatus.UsingLocalV2 ||
            await _v2Features.IsAvailableAsync(cancellationToken);
        OnPropertyChanged(nameof(MigrationStatus));
        OnPropertyChanged(nameof(IsMigrationChoiceRequired));
        OnPropertyChanged(nameof(CanUpgradeVault));
        OnPropertyChanged(nameof(CanUseV2Features));
    }

    private void OnVaultAccountsChanged(object? sender, EventArgs args) => RebuildVisibleAccounts();

    private void OnVaultStateChanged(object? sender, VaultState state) => OnCollectionStateChanged();

    private void Notify(string title, string message, bool isError = false) =>
        NotificationRequested?.Invoke(this, new NotificationEventArgs(title, message, isError));
}
