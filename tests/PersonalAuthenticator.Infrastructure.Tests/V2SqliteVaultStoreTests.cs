using System.Security.Cryptography;
using System.Text;
using Microsoft.Data.Sqlite;
using PersonalAuthenticator.Core.Domain;
using PersonalAuthenticator.Core.Exceptions;
using PersonalAuthenticator.Infrastructure.Storage;

namespace PersonalAuthenticator.Infrastructure.Tests;

public sealed class V2SqliteVaultStoreTests : IDisposable
{
    private readonly string _directory =
        Path.Combine(Path.GetTempPath(), $"pa-v2-tests-{Guid.NewGuid():N}");

    [Fact]
    public async Task SaveAndLoad_EncryptedRecords_RoundTripsWithoutPlaintext()
    {
        string databasePath = Path.Combine(_directory, "vault-v2.db");
        using var keyProvider = new FixedRootKeyProvider();
        var store = new V2SqliteVaultStore(databasePath, keyProvider);
        Guid accountId = Guid.NewGuid();
        Guid activeVersionId = Guid.NewGuid();
        Guid retiredVersionId = Guid.NewGuid();
        var account = new VaultAccountV2(
            accountId,
            "PrivateIssuerMarker",
            "alice@example.test",
            activeVersionId,
            favourite: true,
            sortOrder: 4,
            createdAtUtc: new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero),
            updatedAtUtc: new DateTimeOffset(2026, 1, 2, 0, 0, 0, TimeSpan.Zero));
        byte[] activeSecret = Enumerable.Range(1, 20).Select(value => (byte)value).ToArray();
        using var activeVersion = new SecretVersionV2(
            activeVersionId,
            accountId,
            activeSecret,
            TotpAlgorithm.Sha256,
            8,
            60,
            "otpauth://totp/PrivateIssuerMarker%3Aalice%40example.test?secret=AEBAGBAFAYDQQCIKBMGA2DQPCAIREEYU&issuer=PrivateIssuerMarker&algorithm=SHA256&digits=8&period=60",
            ProvisioningUriOrigin.CanonicalGenerated,
            createdAtUtc: new DateTimeOffset(2026, 1, 2, 0, 0, 0, TimeSpan.Zero));
        using var retiredVersion = new SecretVersionV2(
            retiredVersionId,
            accountId,
            Enumerable.Range(21, 20).Select(value => (byte)value).ToArray(),
            TotpAlgorithm.Sha1,
            6,
            30,
            "otpauth://totp/PrivateIssuerMarker%3Aalice%40example.test?secret=CUKBOGAZDINRYHI6D4QCCIRDEQSSMJZH&issuer=PrivateIssuerMarker",
            ProvisioningUriOrigin.Original,
            SecretVersionState.Retired,
            new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero),
            new DateTimeOffset(2026, 1, 2, 0, 0, 0, TimeSpan.Zero));

        await store.SaveAsync(
            [account],
            [activeVersion, retiredVersion],
            TestContext.Current.CancellationToken);

        byte[] persisted = await File.ReadAllBytesAsync(
            databasePath,
            TestContext.Current.CancellationToken);
        Assert.DoesNotContain("PrivateIssuerMarker"u8.ToArray(), persisted);
        Assert.DoesNotContain("alice@example.test"u8.ToArray(), persisted);
        Assert.False(persisted.AsSpan().IndexOf(activeSecret) >= 0);

        using V2VaultSnapshot loaded = await store.LoadAsync(
            TestContext.Current.CancellationToken);
        VaultAccountV2 loadedAccount = Assert.Single(loaded.Accounts);
        Assert.Equal(account.Id, loadedAccount.Id);
        Assert.Equal(account.Issuer, loadedAccount.Issuer);
        Assert.Equal(account.AccountName, loadedAccount.AccountName);
        Assert.Equal(account.ActiveSecretVersionId, loadedAccount.ActiveSecretVersionId);
        Assert.Equal(2, loaded.SecretVersions.Count);
        SecretVersionV2 loadedActive = Assert.Single(
            loaded.SecretVersions,
            version => version.State == SecretVersionState.Active);
        Assert.Equal(activeSecret, loadedActive.Secret.ToArray());
        Assert.Equal(activeVersion.ProvisioningUri, loadedActive.ProvisioningUri);
    }

    [Fact]
    public async Task Load_TamperedEncryptedRecord_IsRejected()
    {
        string databasePath = Path.Combine(_directory, "vault-v2.db");
        using var keyProvider = new FixedRootKeyProvider();
        var store = new V2SqliteVaultStore(databasePath, keyProvider);
        (VaultAccountV2 account, SecretVersionV2 version) = CreateActiveAccount();
        using (version)
        {
            await store.SaveAsync(
                [account],
                [version],
                TestContext.Current.CancellationToken);
        }

        var connectionString = new SqliteConnectionStringBuilder
        {
            DataSource = databasePath,
            Pooling = false,
        }.ToString();
        await using (var connection = new SqliteConnection(connectionString))
        {
            await connection.OpenAsync(TestContext.Current.CancellationToken);
            await using SqliteCommand command = connection.CreateCommand();
            command.CommandText =
                """
                UPDATE account_records
                SET ciphertext = randomblob(length(ciphertext));
                """;
            await command.ExecuteNonQueryAsync(TestContext.Current.CancellationToken);
        }

        await Assert.ThrowsAsync<SafeApplicationException>(
            () => store.LoadAsync(TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task Save_AccountWithoutMatchingActiveSecret_IsRejectedBeforeCreatingDatabase()
    {
        string databasePath = Path.Combine(_directory, "vault-v2.db");
        using var keyProvider = new FixedRootKeyProvider();
        var store = new V2SqliteVaultStore(databasePath, keyProvider);
        var account = new VaultAccountV2(
            Guid.NewGuid(),
            "Example",
            "alice",
            Guid.NewGuid());

        SafeApplicationException exception = await Assert.ThrowsAsync<SafeApplicationException>(
            () => store.SaveAsync(
                [account],
                [],
                TestContext.Current.CancellationToken));

        Assert.Equal("VaultV2.InvalidDatabase", exception.ErrorCode);
        Assert.False(File.Exists(databasePath));
    }

    [Fact]
    public async Task Load_SchemaOneDatabase_UpgradesHistorySchemaTransactionally()
    {
        string databasePath = Path.Combine(_directory, "vault-v2.db");
        using var keyProvider = new FixedRootKeyProvider();
        var store = new V2SqliteVaultStore(databasePath, keyProvider);
        (VaultAccountV2 account, SecretVersionV2 version) = CreateActiveAccount();
        using (version)
        {
            await store.SaveAsync(
                [account],
                [version],
                TestContext.Current.CancellationToken);
        }

        var connectionString = new SqliteConnectionStringBuilder
        {
            DataSource = databasePath,
            Pooling = false,
        }.ToString();
        await using (var connection = new SqliteConnection(connectionString))
        {
            await connection.OpenAsync(TestContext.Current.CancellationToken);
            await using SqliteCommand command = connection.CreateCommand();
            command.CommandText =
                "DROP TABLE account_history_records; PRAGMA user_version = 1;";
            await command.ExecuteNonQueryAsync(TestContext.Current.CancellationToken);
        }

        using V2VaultSnapshot snapshot = await store.LoadAsync(
            TestContext.Current.CancellationToken);
        Assert.Single(snapshot.Accounts);
        Assert.Empty(snapshot.HistoryEntries);

        await using var verificationConnection = new SqliteConnection(connectionString);
        await verificationConnection.OpenAsync(TestContext.Current.CancellationToken);
        await using SqliteCommand versionCommand = verificationConnection.CreateCommand();
        versionCommand.CommandText = "PRAGMA user_version;";
        Assert.Equal(
            2L,
            (long)(await versionCommand.ExecuteScalarAsync(
                TestContext.Current.CancellationToken))!);
        await using SqliteCommand tableCommand = verificationConnection.CreateCommand();
        tableCommand.CommandText =
            "SELECT COUNT(*) FROM sqlite_schema WHERE type = 'table' AND name = 'account_history_records';";
        Assert.Equal(
            1L,
            (long)(await tableCommand.ExecuteScalarAsync(
                TestContext.Current.CancellationToken))!);
    }

    [Fact]
    public async Task SaveAndLoad_HistoryRecords_AreEncryptedAndRoundTrip()
    {
        string databasePath = Path.Combine(_directory, "vault-v2.db");
        using var keyProvider = new FixedRootKeyProvider();
        var store = new V2SqliteVaultStore(databasePath, keyProvider);
        (VaultAccountV2 account, SecretVersionV2 version) = CreateActiveAccount();
        var occurredAt = new DateTimeOffset(2099, 12, 31, 23, 59, 59, TimeSpan.Zero);
        var history = new AccountHistoryEntryV2(
            Guid.NewGuid(),
            account.Id,
            AccountHistoryAction.SecretActivated,
            occurredAt,
            version.Id);
        using (version)
        {
            await store.SaveAsync(
                [account],
                [version],
                [history],
                TestContext.Current.CancellationToken);
        }

        byte[] persisted = await File.ReadAllBytesAsync(
            databasePath,
            TestContext.Current.CancellationToken);
        Assert.DoesNotContain("2099-12-31"u8.ToArray(), persisted);

        using V2VaultSnapshot snapshot = await store.LoadAsync(
            TestContext.Current.CancellationToken);
        AccountHistoryEntryV2 loaded = Assert.Single(snapshot.HistoryEntries);
        Assert.Equal(history.Id, loaded.Id);
        Assert.Equal(history.AccountId, loaded.AccountId);
        Assert.Equal(history.Action, loaded.Action);
        Assert.Equal(occurredAt, loaded.OccurredAtUtc);
        Assert.Equal(version.Id, loaded.SecretVersionId);
    }

    [Fact]
    public async Task DpapiRootKeyProvider_PersistsOnlyProtectedKeyMaterial()
    {
        string keyPath = Path.Combine(_directory, "vault-v2.key");
        var firstProvider = new DpapiV2RootKeyProvider(keyPath, _ => Directory.CreateDirectory(_directory));
        byte[] first = await firstProvider.LoadOrCreateAsync(TestContext.Current.CancellationToken);
        try
        {
            var secondProvider = new DpapiV2RootKeyProvider(
                keyPath,
                _ => throw new InvalidOperationException("An existing key must not be recreated."));
            byte[] second = await secondProvider.LoadAsync(TestContext.Current.CancellationToken);
            try
            {
                Assert.Equal(first, second);
                byte[] envelope = await File.ReadAllBytesAsync(
                    keyPath,
                    TestContext.Current.CancellationToken);
                Assert.Equal("PAVKEY02", Encoding.ASCII.GetString(envelope, 0, 8));
                Assert.False(envelope.AsSpan().IndexOf(first) >= 0);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(second);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(first);
        }
    }

    public void Dispose()
    {
        if (Directory.Exists(_directory))
        {
            Directory.Delete(_directory, recursive: true);
        }
    }

    private static (VaultAccountV2 Account, SecretVersionV2 Version) CreateActiveAccount()
    {
        Guid accountId = Guid.NewGuid();
        Guid versionId = Guid.NewGuid();
        var account = new VaultAccountV2(
            accountId,
            "Example",
            "alice",
            versionId);
        var version = new SecretVersionV2(
            versionId,
            accountId,
            Enumerable.Range(1, 20).Select(value => (byte)value).ToArray(),
            TotpAlgorithm.Sha1,
            6,
            30,
            "otpauth://totp/Example%3Aalice?secret=AEBAGBAFAYDQQCIKBMGA2DQPCAIREEYU&issuer=Example",
            ProvisioningUriOrigin.CanonicalGenerated);
        return (account, version);
    }

    private sealed class FixedRootKeyProvider : IVaultRootKeyProvider, IDisposable
    {
        private readonly byte[] _key = RandomNumberGenerator.GetBytes(
            V2RecordCryptography.KeyLength);

        public bool Exists { get; private set; }

        public Task<byte[]> LoadAsync(CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!Exists)
            {
                throw new FileNotFoundException();
            }

            return Task.FromResult(_key.ToArray());
        }

        public Task<byte[]> LoadOrCreateAsync(CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Exists = true;
            return Task.FromResult(_key.ToArray());
        }

        public void Dispose() => CryptographicOperations.ZeroMemory(_key);
    }
}
