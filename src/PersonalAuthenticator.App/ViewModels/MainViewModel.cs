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
    private readonly Stopwatch _monotonicClock = Stopwatch.StartNew();
    private DateTimeOffset _lastWallClock;
    private TimeSpan _lastMonotonic;
    private bool _clockWarningShown;

    public MainViewModel(
        IVaultService vault,
        ITotpGenerator generator,
        IClock clock,
        ISecureClipboardService clipboard,
        IUserVerificationService verification,
        IAppSettingsStore settingsStore,
        IVaultMigrationCoordinator migrationCoordinator)
    {
        _vault = vault;
        _generator = generator;
        _clock = clock;
        _clipboard = clipboard;
        _verification = verification;
        _settingsStore = settingsStore;
        _migrationCoordinator = migrationCoordinator;
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
        Notify("Account deleted", "The encrypted vault was updated.");
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
        OnPropertyChanged(nameof(MigrationStatus));
        OnPropertyChanged(nameof(IsMigrationChoiceRequired));
        OnPropertyChanged(nameof(CanUpgradeVault));
    }

    private void OnVaultAccountsChanged(object? sender, EventArgs args) => RebuildVisibleAccounts();

    private void OnVaultStateChanged(object? sender, VaultState state) => OnCollectionStateChanged();

    private void Notify(string title, string message, bool isError = false) =>
        NotificationRequested?.Invoke(this, new NotificationEventArgs(title, message, isError));
}
