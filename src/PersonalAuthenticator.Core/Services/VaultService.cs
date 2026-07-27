using PersonalAuthenticator.Core.Abstractions;
using PersonalAuthenticator.Core.Domain;
using PersonalAuthenticator.Core.Exceptions;
using PersonalAuthenticator.Core.Security;

namespace PersonalAuthenticator.Core.Services;

public sealed class VaultService : IVaultService
{
    private readonly IVaultStore _store;
    private readonly IClock _clock;
    private readonly DuplicateDetector _duplicateDetector;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly List<TotpAccount> _accounts = [];
    private bool _disposed;

    public VaultService(IVaultStore store, IClock clock, DuplicateDetector duplicateDetector)
    {
        _store = store;
        _clock = clock;
        _duplicateDetector = duplicateDetector;
    }

    public VaultState State { get; private set; } = VaultState.Uninitialised;

    public IReadOnlyList<TotpAccount> Accounts => _accounts;

    public event EventHandler<VaultState>? StateChanged;

    public event EventHandler? AccountsChanged;

    public async Task InitialiseAsync(bool unlock, CancellationToken cancellationToken)
    {
        ThrowIfDisposed();
        await _gate.WaitAsync(cancellationToken);
        try
        {
            EnsureState(VaultState.Uninitialised);
            bool exists = await _store.ExistsAsync(cancellationToken);
            SetState(exists ? VaultState.Locked : VaultState.Unlocked);
            if (!exists)
            {
                await _store.SaveAsync([], cancellationToken);
            }
        }
        catch
        {
            SetState(VaultState.Faulted);
            throw;
        }
        finally
        {
            _gate.Release();
        }

        if (unlock && State == VaultState.Locked)
        {
            await UnlockAsync(cancellationToken);
        }
    }

    public async Task UnlockAsync(CancellationToken cancellationToken)
    {
        ThrowIfDisposed();
        await _gate.WaitAsync(cancellationToken);
        try
        {
            if (State == VaultState.Unlocked)
            {
                return;
            }

            if (State == VaultState.Faulted)
            {
                ClearAccounts();
                SetState(VaultState.Locked);
                AccountsChanged?.Invoke(this, EventArgs.Empty);
            }

            EnsureState(VaultState.Locked);
            SetState(VaultState.Unlocking);
            IReadOnlyList<TotpAccount> loaded = await _store.LoadAsync(cancellationToken);
            _accounts.AddRange(loaded.OrderBy(account => account.SortOrder));
            SetState(VaultState.Unlocked);
            AccountsChanged?.Invoke(this, EventArgs.Empty);
        }
        catch
        {
            ClearAccounts();
            SetState(VaultState.Faulted);
            throw;
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task LockAsync(CancellationToken cancellationToken)
    {
        ThrowIfDisposed();
        await _gate.WaitAsync(cancellationToken);
        try
        {
            if (State is VaultState.Locked or VaultState.Uninitialised)
            {
                return;
            }

            EnsureState(VaultState.Unlocked, VaultState.Faulted);
            SetState(VaultState.Locking);
            ClearAccounts();
            SetState(VaultState.Locked);
            AccountsChanged?.Invoke(this, EventArgs.Empty);
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task ReloadAsync(CancellationToken cancellationToken)
    {
        ThrowIfDisposed();
        await _gate.WaitAsync(cancellationToken);
        IReadOnlyList<TotpAccount>? loaded = null;
        try
        {
            EnsureState(VaultState.Unlocked);
            loaded = await _store.LoadAsync(cancellationToken);
            ClearAccounts();
            _accounts.AddRange(loaded.OrderBy(account => account.SortOrder));
            loaded = null;
            AccountsChanged?.Invoke(this, EventArgs.Empty);
        }
        catch
        {
            if (loaded is not null)
            {
                DisposeAccounts(loaded);
            }

            SetState(VaultState.Faulted);
            AccountsChanged?.Invoke(this, EventArgs.Empty);
            throw;
        }
        finally
        {
            _gate.Release();
        }
    }

    public Task AddAsync(TotpAccount account, CancellationToken cancellationToken) =>
        AddAsync(account, DuplicateResolution.Cancel, cancellationToken);

    public Guid? FindLikelyDuplicate(TotpAccount account)
    {
        ArgumentNullException.ThrowIfNull(account);
        ThrowIfDisposed();
        EnsureState(VaultState.Unlocked);
        return _accounts.FirstOrDefault(existing => _duplicateDetector.AreLikelyDuplicates(existing, account))?.Id;
    }

    public DuplicateAccountMatch? FindDuplicate(TotpAccount account)
    {
        ArgumentNullException.ThrowIfNull(account);
        ThrowIfDisposed();
        EnsureState(VaultState.Unlocked);
        foreach (TotpAccount existing in _accounts)
        {
            DuplicateMatchKind? kind = _duplicateDetector.Classify(existing, account);
            if (kind is not null)
            {
                return new DuplicateAccountMatch(existing.Id, kind.Value);
            }
        }

        return null;
    }

    public async Task AddAsync(
        TotpAccount account,
        DuplicateResolution duplicateResolution,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(account);
        if (!Enum.IsDefined(duplicateResolution))
        {
            throw new ArgumentOutOfRangeException(nameof(duplicateResolution));
        }

        await MutateAndSaveAsync(
            accounts =>
            {
                TotpAccount? duplicate = accounts.FirstOrDefault(
                    existing => _duplicateDetector.AreLikelyDuplicates(existing, account));
                if (duplicate is not null && duplicateResolution == DuplicateResolution.Cancel)
                {
                    throw new SafeApplicationException("Vault.Duplicate", "This account already exists.");
                }

                TotpAccount stagedAccount = CloneAccount(account);
                if (duplicate is not null && duplicateResolution == DuplicateResolution.ReplaceExisting)
                {
                    int index = accounts.IndexOf(duplicate);
                    accounts.RemoveAt(index);
                    duplicate.Dispose();
                    stagedAccount.SetSortOrder(index, _clock.UtcNow);
                    accounts.Insert(index, stagedAccount);
                    return;
                }

                stagedAccount.SetSortOrder(accounts.Count, _clock.UtcNow);
                accounts.Add(stagedAccount);
            },
            account.Dispose,
            cancellationToken);
    }

    public Task UpdateDisplayAsync(
        Guid id,
        string issuer,
        string accountName,
        CancellationToken cancellationToken) =>
        MutateAndSaveAsync(
            accounts => FindAccount(accounts, id).UpdateDisplay(issuer, accountName, _clock.UtcNow),
            onCommitted: null,
            cancellationToken);

    public Task SetFavouriteAsync(Guid id, bool favourite, CancellationToken cancellationToken) =>
        MutateAndSaveAsync(
            accounts => FindAccount(accounts, id).SetFavourite(favourite, _clock.UtcNow),
            onCommitted: null,
            cancellationToken);

    public Task MoveAsync(Guid id, int targetIndex, CancellationToken cancellationToken) =>
        MutateAndSaveAsync(
            accounts =>
            {
                if (targetIndex < 0 || targetIndex >= accounts.Count)
                {
                    throw new ArgumentOutOfRangeException(nameof(targetIndex));
                }

                TotpAccount account = FindAccount(accounts, id);
                accounts.Remove(account);
                accounts.Insert(targetIndex, account);
                for (int index = 0; index < accounts.Count; index++)
                {
                    accounts[index].SetSortOrder(index, _clock.UtcNow);
                }
            },
            onCommitted: null,
            cancellationToken);

    public Task DeleteAsync(Guid id, CancellationToken cancellationToken) =>
        MutateAndSaveAsync(
            accounts =>
            {
                TotpAccount account = FindAccount(accounts, id);
                accounts.Remove(account);
                account.Dispose();
                for (int index = 0; index < accounts.Count; index++)
                {
                    accounts[index].SetSortOrder(index, _clock.UtcNow);
                }
            },
            onCommitted: null,
            cancellationToken);

    public Task ImportAsync(
        IReadOnlyCollection<TotpAccount> importedAccounts,
        BackupImportMode mode,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(importedAccounts);
        if (!Enum.IsDefined(mode))
        {
            throw new ArgumentOutOfRangeException(nameof(mode));
        }

        TotpAccount[] sourceAccounts = importedAccounts.ToArray();
        return MutateAndSaveAsync(
            accounts =>
            {
                if (mode == BackupImportMode.Replace)
                {
                    DisposeAccounts(accounts);
                    accounts.Clear();
                }

                var accountIds = new HashSet<Guid>();
                foreach (TotpAccount existing in accounts)
                {
                    if (!accountIds.Add(existing.Id))
                    {
                        throw new SafeApplicationException(
                            "Vault.DuplicateId",
                            "The vault contains duplicate account identifiers and cannot be merged safely.");
                    }
                }

                foreach (TotpAccount imported in sourceAccounts)
                {
                    bool idCollision = accountIds.Contains(imported.Id);
                    if (idCollision && mode == BackupImportMode.Merge)
                    {
                        continue;
                    }

                    if (idCollision && mode == BackupImportMode.MergeReplaceDuplicates)
                    {
                        TotpAccount identityMatch = accounts.First(
                            existing => existing.Id == imported.Id);
                        int identityIndex = accounts.IndexOf(identityMatch);
                        TotpAccount identityReplacement = CloneAccount(imported);
                        accounts.RemoveAt(identityIndex);
                        identityMatch.Dispose();
                        identityReplacement.SetSortOrder(identityIndex, _clock.UtcNow);
                        accounts.Insert(identityIndex, identityReplacement);
                        continue;
                    }

                    if (idCollision)
                    {
                        Guid replacementId = CreateUniqueAccountId(accountIds);
                        TotpAccount collisionCopy = CloneAccount(imported, replacementId);
                        collisionCopy.SetSortOrder(accounts.Count, _clock.UtcNow);
                        accounts.Add(collisionCopy);
                        continue;
                    }

                    TotpAccount? duplicate = mode == BackupImportMode.Replace
                        ? null
                        : accounts.FirstOrDefault(
                            existing => _duplicateDetector.AreLikelyDuplicates(existing, imported));
                    if (duplicate is not null && mode == BackupImportMode.Merge)
                    {
                        continue;
                    }

                    TotpAccount stagedAccount = CloneAccount(imported);
                    if (duplicate is not null && mode == BackupImportMode.MergeReplaceDuplicates)
                    {
                        int index = accounts.IndexOf(duplicate);
                        accounts.RemoveAt(index);
                        accountIds.Remove(duplicate.Id);
                        accountIds.Add(imported.Id);
                        duplicate.Dispose();
                        stagedAccount.SetSortOrder(index, _clock.UtcNow);
                        accounts.Insert(index, stagedAccount);
                        continue;
                    }

                    accountIds.Add(imported.Id);
                    stagedAccount.SetSortOrder(accounts.Count, _clock.UtcNow);
                    accounts.Add(stagedAccount);
                }
            },
            () => DisposeAccounts(sourceAccounts),
            cancellationToken);
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        ClearAccounts();
        _duplicateDetector.Dispose();
        _gate.Dispose();
    }

    private async Task MutateAndSaveAsync(
        Action<List<TotpAccount>> mutation,
        Action? onCommitted,
        CancellationToken cancellationToken)
    {
        ThrowIfDisposed();
        await _gate.WaitAsync(cancellationToken);
        var stagedAccounts = new List<TotpAccount>(_accounts.Count);
        try
        {
            EnsureState(VaultState.Unlocked);
            try
            {
                foreach (TotpAccount account in _accounts)
                {
                    stagedAccounts.Add(CloneAccount(account));
                }
            }
            catch
            {
                SetState(VaultState.Faulted);
                AccountsChanged?.Invoke(this, EventArgs.Empty);
                throw;
            }

            mutation(stagedAccounts);
            try
            {
                await _store.SaveAsync(stagedAccounts, cancellationToken);
            }
            catch
            {
                SetState(VaultState.Faulted);
                AccountsChanged?.Invoke(this, EventArgs.Empty);
                throw;
            }

            ClearAccounts();
            _accounts.AddRange(stagedAccounts);
            stagedAccounts.Clear();
            onCommitted?.Invoke();
            AccountsChanged?.Invoke(this, EventArgs.Empty);
        }
        finally
        {
            DisposeAccounts(stagedAccounts);
            stagedAccounts.Clear();
            _gate.Release();
        }
    }

    private static TotpAccount FindAccount(IEnumerable<TotpAccount> accounts, Guid id) =>
        accounts.FirstOrDefault(account => account.Id == id) ??
        throw new SafeApplicationException("Vault.NotFound", "The selected account no longer exists.");

    private static TotpAccount CloneAccount(TotpAccount account) =>
        CloneAccount(account, account.Id);

    private static TotpAccount CloneAccount(TotpAccount account, Guid id) =>
        new(
            id,
            account.Issuer,
            account.AccountName,
            account.Secret,
            account.Algorithm,
            account.Digits,
            account.Period,
            account.Favourite,
            account.SortOrder,
            account.CreatedAtUtc,
            account.UpdatedAtUtc);

    private static Guid CreateUniqueAccountId(HashSet<Guid> accountIds)
    {
        while (true)
        {
            Guid candidate = Guid.NewGuid();
            if (accountIds.Add(candidate))
            {
                return candidate;
            }
        }
    }

    private void EnsureState(params VaultState[] states)
    {
        if (!states.Contains(State))
        {
            throw new InvalidOperationException($"Vault operation is not valid while in state {State}.");
        }
    }

    private void SetState(VaultState state)
    {
        State = state;
        StateChanged?.Invoke(this, state);
    }

    private void ClearAccounts()
    {
        DisposeAccounts(_accounts);
        _accounts.Clear();
    }

    private static void DisposeAccounts(IEnumerable<TotpAccount> accounts)
    {
        foreach (TotpAccount account in accounts)
        {
            account.Dispose();
        }
    }

    private void ThrowIfDisposed() => ObjectDisposedException.ThrowIf(_disposed, this);
}
