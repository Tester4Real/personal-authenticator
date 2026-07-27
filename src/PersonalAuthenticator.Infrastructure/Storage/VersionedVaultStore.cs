using Microsoft.Extensions.Logging;
using PersonalAuthenticator.Core.Abstractions;
using PersonalAuthenticator.Core.Domain;
using PersonalAuthenticator.Core.Exceptions;

namespace PersonalAuthenticator.Infrastructure.Storage;

public sealed class VersionedVaultStore : IVaultStore, IDisposable
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
                pointer = await _migrationService.MigrateAsync(
                    _defaultLegacyStore,
                    cancellationToken);
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
                ActiveVaultPointer migrated = await _migrationService.MigrateAsync(
                    _defaultLegacyStore,
                    cancellationToken);
                await CreateSelectedStore(migrated).SaveAsync(accounts, cancellationToken);
                return;
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

    private static void DisposeAccounts(IEnumerable<TotpAccount> accounts)
    {
        foreach (TotpAccount account in accounts)
        {
            account.Dispose();
        }
    }
}
