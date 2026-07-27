using System.Security.Cryptography;
using PersonalAuthenticator.Core.Domain;
using PersonalAuthenticator.Core.Exceptions;
using PersonalAuthenticator.Core.Services;
using PersonalAuthenticator.Infrastructure.Otp;

namespace PersonalAuthenticator.Infrastructure.Storage;

internal sealed class V1ToV2MigrationService
{
    private const long MaximumLegacyVaultBytes = 64L * 1024 * 1024;
    private static readonly DateTimeOffset VerificationTime =
        new(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
    private readonly string _baseDirectory;
    private readonly ActiveVaultPointerStore _pointerStore;
    private readonly ProvisioningUriParser _provisioningUriParser = new();
    private readonly OtpNetTotpGenerator _totpGenerator = new();

    public V1ToV2MigrationService(
        string baseDirectory,
        ActiveVaultPointerStore pointerStore)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(baseDirectory);
        ArgumentNullException.ThrowIfNull(pointerStore);
        _baseDirectory = Path.GetFullPath(baseDirectory);
        _pointerStore = pointerStore;
    }

    public async Task<ActiveVaultPointer> MigrateAsync(
        DpapiVaultStore legacyStore,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(legacyStore);
        cancellationToken.ThrowIfCancellationRequested();

        await using var sourceLock = new FileStream(
            legacyStore.VaultPath,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            bufferSize: 65_536,
            FileOptions.Asynchronous | FileOptions.SequentialScan);
        if (sourceLock.Length is <= 0 or > MaximumLegacyVaultBytes)
        {
            throw new SafeApplicationException(
                "VaultMigration.InvalidSource",
                "The legacy vault is empty or too large to migrate safely.");
        }

        byte[] sourceEnvelope = GC.AllocateUninitializedArray<byte>((int)sourceLock.Length);
        IReadOnlyList<TotpAccount>? sourceAccounts = null;
        var migratedVersions = new List<SecretVersionV2>();
        try
        {
            await sourceLock.ReadExactlyAsync(sourceEnvelope, cancellationToken);
            byte[] sourceHash = SHA256.HashData(sourceEnvelope);
            string sourceHashText = Convert.ToHexString(sourceHash);
            CryptographicOperations.ZeroMemory(sourceHash);

            sourceAccounts = await legacyStore.LoadAsync(cancellationToken);
            await SaveRecoveryCopyAsync(
                sourceEnvelope,
                sourceHashText,
                cancellationToken);

            string generation = Guid.NewGuid().ToString("N");
            string stagingFileName = $"vault-v2-{generation}.staging.db";
            string activeFileName = $"vault-v2-{generation}.db";
            string stagingPath = Path.Combine(_baseDirectory, stagingFileName);
            string activePath = Path.Combine(_baseDirectory, activeFileName);
            string keyPath = Path.Combine(_baseDirectory, "vault-v2.key");

            var migratedAccounts = new List<VaultAccountV2>(sourceAccounts.Count);
            foreach (TotpAccount source in sourceAccounts)
            {
                Guid versionId = Guid.NewGuid();
                migratedAccounts.Add(
                    new VaultAccountV2(
                        source.Id,
                        source.Issuer,
                        source.AccountName,
                        versionId,
                        source.Favourite,
                        source.SortOrder,
                        source.CreatedAtUtc,
                        source.UpdatedAtUtc));
                migratedVersions.Add(
                    new SecretVersionV2(
                        versionId,
                        source.Id,
                        source.Secret,
                        source.Algorithm,
                        source.Digits,
                        source.Period,
                        CanonicalProvisioningUri.Create(source),
                        ProvisioningUriOrigin.CanonicalGenerated,
                        SecretVersionState.Active,
                        source.CreatedAtUtc));
            }

            var stagingStore = new V2SqliteVaultStore(stagingPath, keyPath);
            await stagingStore.SaveAsync(
                migratedAccounts,
                migratedVersions,
                cancellationToken);
            await VerifyV2Async(stagingStore, sourceAccounts, cancellationToken);

            File.Move(stagingPath, activePath, overwrite: false);
            var activeStore = new V2SqliteVaultStore(activePath, keyPath);
            await VerifyV2Async(activeStore, sourceAccounts, cancellationToken);
            await VerifyLockedSourceUnchangedAsync(
                sourceLock,
                sourceHashText,
                cancellationToken);

            var pointer = new ActiveVaultPointer(
                ActiveVaultMode.LocalV2,
                activeFileName,
                sourceHashText,
                DateTimeOffset.UtcNow);
            await _pointerStore.SaveAsync(pointer, cancellationToken);
            return pointer;
        }
        catch (SafeApplicationException)
        {
            throw;
        }
        catch (Exception exception) when (
            exception is IOException or
                UnauthorizedAccessException or
                CryptographicException)
        {
            throw new SafeApplicationException(
                "VaultMigration.Failed",
                "The legacy vault could not be migrated safely.",
                exception);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(sourceEnvelope);
            if (sourceAccounts is not null)
            {
                DisposeAccounts(sourceAccounts);
            }

            foreach (SecretVersionV2 version in migratedVersions)
            {
                version.Dispose();
            }
        }
    }

    private async Task VerifyV2Async(
        V2SqliteVaultStore store,
        IReadOnlyList<TotpAccount> sourceAccounts,
        CancellationToken cancellationToken)
    {
        var adapter = new V2VaultStoreAdapter(store);
        IReadOnlyList<TotpAccount> reopened = await adapter.LoadAsync(cancellationToken);
        try
        {
            VaultAccountVerifier.VerifyEquivalent(sourceAccounts, reopened);
            Dictionary<Guid, TotpAccount> reopenedById =
                reopened.ToDictionary(account => account.Id);
            Dictionary<Guid, TotpAccount> sourceById =
                sourceAccounts.ToDictionary(account => account.Id);
            using V2VaultSnapshot snapshot = await store.LoadAsync(cancellationToken);
            Dictionary<Guid, SecretVersionV2> versions =
                snapshot.SecretVersions.ToDictionary(version => version.Id);
            foreach (VaultAccountV2 account in snapshot.Accounts)
            {
                TotpAccount source = sourceById[account.Id];
                SecretVersionV2 version = versions[account.ActiveSecretVersionId];
                using var parsed = _provisioningUriParser.Parse(version.ProvisioningUri);
                if (!string.Equals(parsed.Issuer, source.Issuer, StringComparison.Ordinal) ||
                    !string.Equals(
                        parsed.AccountName,
                        source.AccountName,
                        StringComparison.Ordinal) ||
                    parsed.Algorithm != source.Algorithm ||
                    parsed.Digits != source.Digits ||
                    parsed.Period != source.Period)
                {
                    throw VerificationFailed();
                }

                using TotpAccount uriAccount = parsed.CreateAccount();
                if (!CryptographicOperations.FixedTimeEquals(
                        uriAccount.Secret,
                        source.Secret))
                {
                    throw VerificationFailed();
                }

                TotpAccount migrated = reopenedById[source.Id];
                if (!string.Equals(
                        _totpGenerator.Generate(source, VerificationTime),
                        _totpGenerator.Generate(migrated, VerificationTime),
                        StringComparison.Ordinal))
                {
                    throw VerificationFailed();
                }
            }
        }
        finally
        {
            DisposeAccounts(reopened);
        }
    }

    private async Task SaveRecoveryCopyAsync(
        ReadOnlyMemory<byte> sourceEnvelope,
        string sourceHash,
        CancellationToken cancellationToken)
    {
        string recoveryDirectory = Path.Combine(_baseDirectory, "migration-recovery");
        Directory.CreateDirectory(recoveryDirectory);
        string recoveryPath = Path.Combine(
            recoveryDirectory,
            $"vault-v1-{sourceHash}.pav");
        if (File.Exists(recoveryPath))
        {
            if (new FileInfo(recoveryPath).Length != sourceEnvelope.Length)
            {
                throw new SafeApplicationException(
                    "VaultMigration.RecoveryCopyMismatch",
                    "The existing migration recovery copy does not match the source vault.");
            }

            byte[] existing = await File.ReadAllBytesAsync(recoveryPath, cancellationToken);
            try
            {
                byte[] existingHash = SHA256.HashData(existing);
                try
                {
                    if (!string.Equals(
                            Convert.ToHexString(existingHash),
                            sourceHash,
                            StringComparison.Ordinal))
                    {
                        throw new SafeApplicationException(
                            "VaultMigration.RecoveryCopyMismatch",
                            "The existing migration recovery copy does not match the source vault.");
                    }
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(existingHash);
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(existing);
            }

            return;
        }

        await AtomicFile.WriteAsync(
            recoveryPath,
            sourceEnvelope,
            retainPrevious: false,
            overwriteExisting: false,
            cancellationToken);
    }

    private static async Task VerifyLockedSourceUnchangedAsync(
        FileStream sourceLock,
        string expectedHash,
        CancellationToken cancellationToken)
    {
        sourceLock.Position = 0;
        byte[] current = GC.AllocateUninitializedArray<byte>((int)sourceLock.Length);
        try
        {
            await sourceLock.ReadExactlyAsync(current, cancellationToken);
            byte[] currentHash = SHA256.HashData(current);
            try
            {
                if (!string.Equals(
                        Convert.ToHexString(currentHash),
                        expectedHash,
                        StringComparison.Ordinal))
                {
                    throw new SafeApplicationException(
                        "VaultMigration.SourceChanged",
                        "The legacy vault changed while migration was in progress.");
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(currentHash);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(current);
        }
    }

    private static SafeApplicationException VerificationFailed() =>
        new(
            "VaultMigration.VerificationFailed",
            "The migrated vault did not pass complete verification.");

    private static void DisposeAccounts(IEnumerable<TotpAccount> accounts)
    {
        foreach (TotpAccount account in accounts)
        {
            account.Dispose();
        }
    }
}
