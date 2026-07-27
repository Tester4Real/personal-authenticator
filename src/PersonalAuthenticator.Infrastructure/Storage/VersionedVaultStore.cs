using Microsoft.Extensions.Logging;
using PersonalAuthenticator.Core.Abstractions;
using PersonalAuthenticator.Core.Domain;
using PersonalAuthenticator.Core.Exceptions;
using PersonalAuthenticator.Infrastructure.Otp;

namespace PersonalAuthenticator.Infrastructure.Storage;

public sealed class VersionedVaultStore :
    IVaultStore,
    IVaultMigrationCoordinator,
    IV2VaultFeatures,
    IDisposable
{
    private readonly string _baseDirectory;
    private readonly ILogger<DpapiVaultStore> _legacyLogger;
    private readonly DpapiVaultStore _defaultLegacyStore;
    private readonly ActiveVaultPointerStore _pointerStore;
    private readonly V1ToV2MigrationService _migrationService;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private bool _disposed;

    public VersionedVaultStore(
        ILogger<DpapiVaultStore> legacyLogger,
        string? baseDirectory = null)
    {
        ArgumentNullException.ThrowIfNull(legacyLogger);
        _legacyLogger = legacyLogger;
        _baseDirectory = Path.GetFullPath(
            baseDirectory ??
            Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "PersonalAuthenticator"));
        _defaultLegacyStore = new DpapiVaultStore(_legacyLogger, _baseDirectory);
        _pointerStore = new ActiveVaultPointerStore(
            Path.Combine(_baseDirectory, "active-store.ptr"));
        _migrationService = new V1ToV2MigrationService(_baseDirectory, _pointerStore);
    }

    public string VaultPath => _pointerStore.PointerPath;

    public async Task<bool> ExistsAsync(CancellationToken cancellationToken)
    {
        await _gate.WaitAsync(cancellationToken);
        try
        {
            if (!_pointerStore.Exists)
            {
                return await _defaultLegacyStore.ExistsAsync(cancellationToken);
            }

            ActiveVaultPointer pointer = await _pointerStore.LoadAsync(cancellationToken);
            bool exists = await SelectedStoreExistsAsync(pointer, cancellationToken);
            if (!exists)
            {
                throw new SafeApplicationException(
                    "VaultSelector.TargetMissing",
                    "The selected local vault is missing. Automatic fallback was not attempted.");
            }

            return true;
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task<IReadOnlyList<TotpAccount>> LoadAsync(
        CancellationToken cancellationToken)
    {
        await _gate.WaitAsync(cancellationToken);
        try
        {
            ActiveVaultPointer pointer;
            if (_pointerStore.Exists)
            {
                pointer = await _pointerStore.LoadAsync(cancellationToken);
            }
            else if (await _defaultLegacyStore.ExistsAsync(cancellationToken))
            {
                throw MigrationChoiceRequired();
            }
            else
            {
                throw new SafeApplicationException(
                    "Vault.NotFound",
                    "No local vault is available.");
            }

            return await CreateSelectedStore(pointer).LoadAsync(cancellationToken);
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task SaveAsync(
        IReadOnlyCollection<TotpAccount> accounts,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(accounts);
        await _gate.WaitAsync(cancellationToken);
        try
        {
            if (_pointerStore.Exists)
            {
                ActiveVaultPointer pointer = await _pointerStore.LoadAsync(cancellationToken);
                await CreateSelectedStore(pointer).SaveAsync(accounts, cancellationToken);
                return;
            }

            if (await _defaultLegacyStore.ExistsAsync(cancellationToken))
            {
                throw MigrationChoiceRequired();
            }

            await CreateAndActivateV2Async(accounts, cancellationToken);
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task RollbackToLegacyAsync(CancellationToken cancellationToken)
    {
        await _gate.WaitAsync(cancellationToken);
        try
        {
            if (!_pointerStore.Exists)
            {
                throw new SafeApplicationException(
                    "VaultRollback.NoActiveStore",
                    "There is no active v2 vault to roll back.");
            }

            ActiveVaultPointer activePointer = await _pointerStore.LoadAsync(cancellationToken);
            if (activePointer.Mode == ActiveVaultMode.LegacyLocalV1)
            {
                return;
            }

            IVaultStore activeStore = CreateSelectedStore(activePointer);
            IReadOnlyList<TotpAccount> activeAccounts =
                await activeStore.LoadAsync(cancellationToken);
            try
            {
                string rollbackFileName =
                    $"vault-v1-rollback-{DateTimeOffset.UtcNow:yyyyMMddHHmmss}-{Guid.NewGuid():N}.pav";
                var rollbackStore = new DpapiVaultStore(
                    _legacyLogger,
                    _baseDirectory,
                    rollbackFileName);
                await rollbackStore.SaveAsync(activeAccounts, cancellationToken);
                IReadOnlyList<TotpAccount> reopened =
                    await rollbackStore.LoadAsync(cancellationToken);
                try
                {
                    VaultAccountVerifier.VerifyEquivalent(activeAccounts, reopened);
                }
                finally
                {
                    DisposeAccounts(reopened);
                }

                var rollbackPointer = new ActiveVaultPointer(
                    ActiveVaultMode.LegacyLocalV1,
                    rollbackFileName,
                    activePointer.LegacySourceSha256,
                    DateTimeOffset.UtcNow);
                await _pointerStore.SaveAsync(rollbackPointer, cancellationToken);
            }
            finally
            {
                DisposeAccounts(activeAccounts);
            }
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task<VaultMigrationStatus> GetStatusAsync(
        CancellationToken cancellationToken)
    {
        await _gate.WaitAsync(cancellationToken);
        try
        {
            if (!_pointerStore.Exists)
            {
                return await _defaultLegacyStore.ExistsAsync(cancellationToken)
                    ? VaultMigrationStatus.ChoiceRequired
                    : VaultMigrationStatus.NotRequired;
            }

            ActiveVaultPointer pointer = await _pointerStore.LoadAsync(cancellationToken);
            return pointer.Mode switch
            {
                ActiveVaultMode.LegacyLocalV1 => VaultMigrationStatus.UsingLegacyV1,
                ActiveVaultMode.LocalV2 => VaultMigrationStatus.UsingLocalV2,
                _ => throw new SafeApplicationException(
                    "VaultSelector.Invalid",
                    "The active vault selector mode is not supported."),
            };
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task ApplyChoiceAsync(
        VaultMigrationChoice choice,
        CancellationToken cancellationToken)
    {
        if (!Enum.IsDefined(choice))
        {
            throw new ArgumentOutOfRangeException(nameof(choice));
        }

        await _gate.WaitAsync(cancellationToken);
        try
        {
            if (choice == VaultMigrationChoice.Cancel)
            {
                return;
            }

            ActiveVaultPointer? currentPointer = _pointerStore.Exists
                ? await _pointerStore.LoadAsync(cancellationToken)
                : null;
            if (choice == VaultMigrationChoice.ContinueUsingV1)
            {
                if (currentPointer?.Mode == ActiveVaultMode.LegacyLocalV1)
                {
                    return;
                }

                if (currentPointer is not null ||
                    !await _defaultLegacyStore.ExistsAsync(cancellationToken))
                {
                    throw new SafeApplicationException(
                        "VaultMigration.LegacyUnavailable",
                        "A legacy v1 vault is not available.");
                }

                await _pointerStore.SaveAsync(
                    new ActiveVaultPointer(
                        ActiveVaultMode.LegacyLocalV1,
                        Path.GetFileName(_defaultLegacyStore.VaultPath),
                        LegacySourceSha256: null,
                        DateTimeOffset.UtcNow),
                    cancellationToken);
                return;
            }

            if (currentPointer?.Mode == ActiveVaultMode.LocalV2)
            {
                return;
            }

            DpapiVaultStore sourceStore = currentPointer is null
                ? _defaultLegacyStore
                : new DpapiVaultStore(
                    _legacyLogger,
                    _baseDirectory,
                    currentPointer.StoreFileName);
            if (!await sourceStore.ExistsAsync(cancellationToken))
            {
                throw new SafeApplicationException(
                    "VaultMigration.LegacyUnavailable",
                    "A legacy v1 vault is not available.");
            }

            await _migrationService.MigrateAsync(sourceStore, cancellationToken);
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task<bool> IsAvailableAsync(CancellationToken cancellationToken)
    {
        await _gate.WaitAsync(cancellationToken);
        try
        {
            return _pointerStore.Exists &&
                (await _pointerStore.LoadAsync(cancellationToken)).Mode ==
                ActiveVaultMode.LocalV2;
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task AddSecretCandidateAsync(
        Guid accountId,
        TotpAccount candidate,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(candidate);
        await _gate.WaitAsync(cancellationToken);
        try
        {
            V2SqliteVaultStore store = await GetActiveV2StoreAsync(cancellationToken);
            using V2VaultSnapshot snapshot = await store.LoadAsync(cancellationToken);
            VaultAccountV2 account = FindV2Account(snapshot, accountId);
            EnsureNotArchived(account);
            if (snapshot.SecretVersions.Any(
                    version =>
                        version.AccountId == accountId &&
                        HasSameSecret(version, candidate)))
            {
                throw new SafeApplicationException(
                    "VaultV2.DuplicateSecretVersion",
                    "This secret version already exists for the account.");
            }

            using var canonicalCandidate = new TotpAccount(
                account.Id,
                account.Issuer,
                account.AccountName,
                candidate.Secret,
                candidate.Algorithm,
                candidate.Digits,
                candidate.Period);
            var candidateVersion = new SecretVersionV2(
                Guid.NewGuid(),
                accountId,
                candidate.Secret,
                candidate.Algorithm,
                candidate.Digits,
                candidate.Period,
                CanonicalProvisioningUri.Create(canonicalCandidate),
                ProvisioningUriOrigin.CanonicalGenerated,
                SecretVersionState.Candidate,
                DateTimeOffset.UtcNow);
            try
            {
                var versions = snapshot.SecretVersions
                    .Append(candidateVersion)
                    .ToList();
                var history = snapshot.HistoryEntries
                    .Append(
                        NewHistory(
                            accountId,
                            AccountHistoryAction.SecretCandidateAdded,
                            candidateVersion.Id))
                    .ToList();
                await store.SaveAsync(
                    snapshot.Accounts,
                    versions,
                    history,
                    cancellationToken);
            }
            finally
            {
                candidateVersion.Dispose();
            }
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task AddDuplicateAccountAsync(
        Guid relatedAccountId,
        TotpAccount account,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(account);
        await _gate.WaitAsync(cancellationToken);
        SecretVersionV2? newVersion = null;
        try
        {
            V2SqliteVaultStore store = await GetActiveV2StoreAsync(cancellationToken);
            using V2VaultSnapshot snapshot = await store.LoadAsync(cancellationToken);
            VaultAccountV2 related = FindV2Account(snapshot, relatedAccountId);
            EnsureNotArchived(related);
            if (snapshot.Accounts.Any(existing => existing.Id == account.Id))
            {
                throw new SafeApplicationException(
                    "VaultV2.DuplicateIdentifier",
                    "The new account identifier already exists.");
            }

            Guid versionId = Guid.NewGuid();
            int sortOrder = snapshot.Accounts
                .Where(existing => existing.ArchivedAtUtc is null)
                .Select(existing => existing.SortOrder)
                .DefaultIfEmpty(-1)
                .Max() + 1;
            var newAccount = new VaultAccountV2(
                account.Id,
                account.Issuer,
                account.AccountName,
                versionId,
                account.Favourite,
                sortOrder,
                account.CreatedAtUtc,
                account.UpdatedAtUtc);
            newVersion = new SecretVersionV2(
                versionId,
                account.Id,
                account.Secret,
                account.Algorithm,
                account.Digits,
                account.Period,
                CanonicalProvisioningUri.Create(account),
                ProvisioningUriOrigin.CanonicalGenerated,
                SecretVersionState.Active,
                account.UpdatedAtUtc);
            var accounts = snapshot.Accounts.Append(newAccount).ToList();
            var versions = snapshot.SecretVersions.Append(newVersion).ToList();
            var history = snapshot.HistoryEntries
                .Append(
                    NewHistory(
                        account.Id,
                        AccountHistoryAction.DuplicateAddedSeparately,
                        versionId,
                        relatedAccountId: relatedAccountId))
                .Append(
                    NewHistory(
                        relatedAccountId,
                        AccountHistoryAction.DuplicateAddedSeparately,
                        relatedAccountId: account.Id))
                .ToList();
            await store.SaveAsync(accounts, versions, history, cancellationToken);
        }
        finally
        {
            newVersion?.Dispose();
            _gate.Release();
        }
    }

    public async Task ActivateSecretCandidateAsync(
        Guid accountId,
        Guid secretVersionId,
        CancellationToken cancellationToken)
    {
        await _gate.WaitAsync(cancellationToken);
        var ownedVersions = new List<SecretVersionV2>();
        try
        {
            V2SqliteVaultStore store = await GetActiveV2StoreAsync(cancellationToken);
            using V2VaultSnapshot snapshot = await store.LoadAsync(cancellationToken);
            VaultAccountV2 account = FindV2Account(snapshot, accountId);
            EnsureNotArchived(account);
            SecretVersionV2 candidate = snapshot.SecretVersions.FirstOrDefault(
                version =>
                    version.Id == secretVersionId &&
                    version.AccountId == accountId) ??
                throw new SafeApplicationException(
                    "VaultV2.SecretVersionNotFound",
                    "The selected secret version no longer exists.");
            if (candidate.State != SecretVersionState.Candidate)
            {
                throw new SafeApplicationException(
                    "VaultV2.NotCandidate",
                    "Only a candidate secret can be activated.");
            }

            DateTimeOffset now = DateTimeOffset.UtcNow;
            var versions = new List<SecretVersionV2>(snapshot.SecretVersions.Count);
            foreach (SecretVersionV2 version in snapshot.SecretVersions)
            {
                if (version.AccountId != accountId)
                {
                    versions.Add(version);
                    continue;
                }

                if (version.Id == candidate.Id)
                {
                    SecretVersionV2 activated = CloneVersion(
                        version,
                        SecretVersionState.Active,
                        retiredAtUtc: null);
                    ownedVersions.Add(activated);
                    versions.Add(activated);
                    continue;
                }
                else if (version.State == SecretVersionState.Active)
                {
                    SecretVersionV2 retired = CloneVersion(
                        version,
                        SecretVersionState.Retired,
                        now);
                    ownedVersions.Add(retired);
                    versions.Add(retired);
                }
                else
                {
                    versions.Add(version);
                }
            }

            List<VaultAccountV2> accounts = snapshot.Accounts
                .Select(
                    item => item.Id == accountId
                        ? CloneAccount(
                            item,
                            activeSecretVersionId: candidate.Id,
                            updatedAtUtc: now,
                            archivedAtUtc: null)
                        : item)
                .ToList();
            var history = snapshot.HistoryEntries
                .Append(
                    NewHistory(
                        accountId,
                        AccountHistoryAction.SecretActivated,
                        candidate.Id,
                        account.ActiveSecretVersionId))
                .ToList();
            await store.SaveAsync(accounts, versions, history, cancellationToken);
        }
        finally
        {
            foreach (SecretVersionV2 version in ownedVersions)
            {
                version.Dispose();
            }

            _gate.Release();
        }
    }

    public async Task<IReadOnlyList<SecretVersionSummary>> GetSecretVersionsAsync(
        Guid accountId,
        CancellationToken cancellationToken)
    {
        await _gate.WaitAsync(cancellationToken);
        try
        {
            V2SqliteVaultStore store = await GetActiveV2StoreAsync(cancellationToken);
            using V2VaultSnapshot snapshot = await store.LoadAsync(cancellationToken);
            _ = FindV2Account(snapshot, accountId);
            return snapshot.SecretVersions
                .Where(version => version.AccountId == accountId)
                .OrderBy(version => version.State)
                .ThenByDescending(version => version.CreatedAtUtc)
                .Select(
                    version => new SecretVersionSummary(
                        version.Id,
                        version.State,
                        version.Algorithm,
                        version.Digits,
                        version.Period,
                        version.CreatedAtUtc,
                        version.RetiredAtUtc))
                .ToList();
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task<IReadOnlyList<ArchivedAccountSummary>> GetArchivedAccountsAsync(
        CancellationToken cancellationToken)
    {
        await _gate.WaitAsync(cancellationToken);
        try
        {
            V2SqliteVaultStore store = await GetActiveV2StoreAsync(cancellationToken);
            using V2VaultSnapshot snapshot = await store.LoadAsync(cancellationToken);
            return snapshot.Accounts
                .Where(account => account.ArchivedAtUtc is not null)
                .OrderByDescending(account => account.ArchivedAtUtc)
                .Select(
                    account => new ArchivedAccountSummary(
                        account.Id,
                        account.Issuer,
                        account.AccountName,
                        account.ArchivedAtUtc!.Value))
                .ToList();
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task RestoreArchivedAccountAsync(
        Guid accountId,
        CancellationToken cancellationToken)
    {
        await _gate.WaitAsync(cancellationToken);
        try
        {
            V2SqliteVaultStore store = await GetActiveV2StoreAsync(cancellationToken);
            using V2VaultSnapshot snapshot = await store.LoadAsync(cancellationToken);
            VaultAccountV2 archived = FindV2Account(snapshot, accountId);
            if (archived.ArchivedAtUtc is null)
            {
                return;
            }

            DateTimeOffset now = DateTimeOffset.UtcNow;
            List<VaultAccountV2> accounts = snapshot.Accounts
                .Select(
                    account => account.Id == accountId
                        ? CloneAccount(
                            account,
                            account.ActiveSecretVersionId,
                            now,
                            archivedAtUtc: null)
                        : account)
                .ToList();
            var history = snapshot.HistoryEntries
                .Append(
                    NewHistory(
                        accountId,
                        AccountHistoryAction.Restored,
                        archived.ActiveSecretVersionId))
                .ToList();
            await store.SaveAsync(
                accounts,
                snapshot.SecretVersions,
                history,
                cancellationToken);
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task<IReadOnlyList<AccountHistoryEntryV2>> GetAccountHistoryAsync(
        Guid accountId,
        CancellationToken cancellationToken)
    {
        await _gate.WaitAsync(cancellationToken);
        try
        {
            V2SqliteVaultStore store = await GetActiveV2StoreAsync(cancellationToken);
            using V2VaultSnapshot snapshot = await store.LoadAsync(cancellationToken);
            _ = FindV2Account(snapshot, accountId);
            return snapshot.HistoryEntries
                .Where(entry => entry.AccountId == accountId)
                .OrderByDescending(entry => entry.OccurredAtUtc)
                .ToList();
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task<SensitiveSetupInfo> GetActiveSetupInfoAsync(
        Guid accountId,
        CancellationToken cancellationToken)
    {
        await _gate.WaitAsync(cancellationToken);
        try
        {
            V2SqliteVaultStore store = await GetActiveV2StoreAsync(cancellationToken);
            using V2VaultSnapshot snapshot = await store.LoadAsync(cancellationToken);
            VaultAccountV2 account = FindV2Account(snapshot, accountId);
            EnsureNotArchived(account);
            SecretVersionV2 active = snapshot.SecretVersions.First(
                version => version.Id == account.ActiveSecretVersionId);
            string provisioningUri = active.ProvisioningUri;
            if (active.ProvisioningUriOrigin == ProvisioningUriOrigin.CanonicalGenerated)
            {
                using var canonicalAccount = new TotpAccount(
                    account.Id,
                    account.Issuer,
                    account.AccountName,
                    active.Secret,
                    active.Algorithm,
                    active.Digits,
                    active.Period);
                provisioningUri = CanonicalProvisioningUri.Create(canonicalAccount);
            }

            return new SensitiveSetupInfo(
                account.Id,
                account.Issuer,
                account.AccountName,
                provisioningUri);
        }
        finally
        {
            _gate.Release();
        }
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        _gate.Dispose();
    }

    private async Task CreateAndActivateV2Async(
        IReadOnlyCollection<TotpAccount> accounts,
        CancellationToken cancellationToken)
    {
        string databaseFileName = $"vault-v2-{Guid.NewGuid():N}.db";
        var pointer = new ActiveVaultPointer(
            ActiveVaultMode.LocalV2,
            databaseFileName,
            LegacySourceSha256: null,
            DateTimeOffset.UtcNow);
        IVaultStore store = CreateSelectedStore(pointer);
        await store.SaveAsync(accounts, cancellationToken);
        IReadOnlyList<TotpAccount> reopened = await store.LoadAsync(cancellationToken);
        try
        {
            VaultAccountVerifier.VerifyEquivalent(accounts, reopened);
        }
        finally
        {
            DisposeAccounts(reopened);
        }

        await _pointerStore.SaveAsync(pointer, cancellationToken);
    }

    private IVaultStore CreateSelectedStore(ActiveVaultPointer pointer)
    {
        string selectedPath = ResolveSelectedPath(pointer.StoreFileName);
        return pointer.Mode switch
        {
            ActiveVaultMode.LegacyLocalV1 => new DpapiVaultStore(
                _legacyLogger,
                _baseDirectory,
                pointer.StoreFileName),
            ActiveVaultMode.LocalV2 => new V2VaultStoreAdapter(
                new V2SqliteVaultStore(
                    selectedPath,
                    Path.Combine(_baseDirectory, "vault-v2.key"))),
            _ => throw new SafeApplicationException(
                "VaultSelector.Invalid",
                "The active vault selector mode is not supported."),
        };
    }

    private async Task<bool> SelectedStoreExistsAsync(
        ActiveVaultPointer pointer,
        CancellationToken cancellationToken) =>
        await CreateSelectedStore(pointer).ExistsAsync(cancellationToken);

    private string ResolveSelectedPath(string fileName)
    {
        string combined = Path.GetFullPath(Path.Combine(_baseDirectory, fileName));
        string expectedDirectory = Path.TrimEndingDirectorySeparator(_baseDirectory);
        if (!string.Equals(
                Path.GetDirectoryName(combined),
                expectedDirectory,
                StringComparison.OrdinalIgnoreCase))
        {
            throw new SafeApplicationException(
                "VaultSelector.InvalidPath",
                "The active vault selector path is invalid.");
        }

        return combined;
    }

    private async Task<V2SqliteVaultStore> GetActiveV2StoreAsync(
        CancellationToken cancellationToken)
    {
        if (!_pointerStore.Exists)
        {
            throw V2Required();
        }

        ActiveVaultPointer pointer = await _pointerStore.LoadAsync(cancellationToken);
        if (pointer.Mode != ActiveVaultMode.LocalV2)
        {
            throw V2Required();
        }

        return new V2SqliteVaultStore(
            ResolveSelectedPath(pointer.StoreFileName),
            Path.Combine(_baseDirectory, "vault-v2.key"));
    }

    private static VaultAccountV2 FindV2Account(
        V2VaultSnapshot snapshot,
        Guid accountId) =>
        snapshot.Accounts.FirstOrDefault(account => account.Id == accountId) ??
        throw new SafeApplicationException(
            "VaultV2.AccountNotFound",
            "The selected account no longer exists.");

    private static void EnsureNotArchived(VaultAccountV2 account)
    {
        if (account.ArchivedAtUtc is not null)
        {
            throw new SafeApplicationException(
                "VaultV2.AccountArchived",
                "Restore the archived account before changing its secret.");
        }
    }

    private static bool HasSameSecret(
        SecretVersionV2 version,
        TotpAccount account) =>
        version.Algorithm == account.Algorithm &&
        version.Digits == account.Digits &&
        version.Period == account.Period &&
        System.Security.Cryptography.CryptographicOperations.FixedTimeEquals(
            version.Secret,
            account.Secret);

    private static SecretVersionV2 CloneVersion(
        SecretVersionV2 version,
        SecretVersionState state,
        DateTimeOffset? retiredAtUtc) =>
        new(
            version.Id,
            version.AccountId,
            version.Secret,
            version.Algorithm,
            version.Digits,
            version.Period,
            version.ProvisioningUri,
            version.ProvisioningUriOrigin,
            state,
            version.CreatedAtUtc,
            retiredAtUtc);

    private static VaultAccountV2 CloneAccount(
        VaultAccountV2 account,
        Guid activeSecretVersionId,
        DateTimeOffset updatedAtUtc,
        DateTimeOffset? archivedAtUtc) =>
        new(
            account.Id,
            account.Issuer,
            account.AccountName,
            activeSecretVersionId,
            account.Favourite,
            account.SortOrder,
            account.CreatedAtUtc,
            updatedAtUtc,
            archivedAtUtc);

    private static AccountHistoryEntryV2 NewHistory(
        Guid accountId,
        AccountHistoryAction action,
        Guid? secretVersionId = null,
        Guid? previousSecretVersionId = null,
        Guid? relatedAccountId = null) =>
        new(
            Guid.NewGuid(),
            accountId,
            action,
            DateTimeOffset.UtcNow,
            secretVersionId,
            previousSecretVersionId,
            relatedAccountId);

    private static void DisposeAccounts(IEnumerable<TotpAccount> accounts)
    {
        foreach (TotpAccount account in accounts)
        {
            account.Dispose();
        }
    }

    private static SafeApplicationException MigrationChoiceRequired() =>
        new(
            "VaultMigration.ChoiceRequired",
            "Choose whether to upgrade the legacy vault or continue using v1 before unlocking.");

    private static SafeApplicationException V2Required() =>
        new(
            "VaultV2.Required",
            "Upgrade the local vault to v2 before using this feature.");
}
