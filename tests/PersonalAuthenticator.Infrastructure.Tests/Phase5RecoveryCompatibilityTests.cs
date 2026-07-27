using System.Buffers.Binary;
using System.Security.Cryptography;
using PersonalAuthenticator.Core.Domain;
using PersonalAuthenticator.Infrastructure.Recovery;
using PersonalAuthenticator.Infrastructure.Storage;
using PersonalAuthenticator.Infrastructure.Sync;

namespace PersonalAuthenticator.Infrastructure.Tests;

public sealed class Phase5RecoveryCompatibilityTests : IDisposable
{
    private readonly string _directory =
        Path.Combine(Path.GetTempPath(), $"pa-recovery-v2-tests-{Guid.NewGuid():N}");

    [Fact]
    public async Task NewPayload_RestoresOperationHistoryCoverageConflictsAndOutbox()
    {
        V2SqliteVaultStore source = CreateStore("source");
        (VaultAccountV2 account, SecretVersionV2 secret) = CreateAccount();
        using (secret)
        {
            await source.SaveAsync(
                [account],
                [secret],
                TestContext.Current.CancellationToken);
        }

        var configuration = new SyncRecoveryConfiguration(
            "github",
            Guid.NewGuid(),
            Guid.NewGuid(),
            RepositoryId: 123456,
            RepositoryOwner: "owner",
            RepositoryName: "private-repository",
            Branch: "personal-authenticator-sync",
            PathPrefix: ".pav",
            Enabled: true,
            BackgroundSyncEnabled: true);
        using SyncRecoveryState syncState =
            await source.ExportSyncRecoveryStateAsync(
                configuration,
                TestContext.Current.CancellationToken);
        using V2VaultSnapshot snapshot =
            await source.LoadAsync(TestContext.Current.CancellationToken);
        byte[] payload = RecoveryPayloadSerializer.Serialize(
            snapshot,
            DateTimeOffset.UtcNow,
            syncState);
        try
        {
            using RecoveryPayload decoded =
                RecoveryPayloadSerializer.Deserialize(payload);
            Assert.NotNull(decoded.SyncState);
            Assert.NotEmpty(decoded.SyncState.SerializedOperations);
            Assert.NotEmpty(decoded.SyncState.DeviceSequenceCoverage);
            Assert.Single(decoded.SyncState.OutboxOperationIds);
            Assert.Equal("github", decoded.SyncState.Configuration?.BackendKind);
            Assert.Equal(123456, decoded.SyncState.Configuration?.RepositoryId);

            V2SqliteVaultStore target = CreateStore("target");
            await target.SaveRecoveredAsync(
                decoded.Snapshot.Accounts,
                decoded.Snapshot.SecretVersions,
                decoded.Snapshot.HistoryEntries,
                decoded.Snapshot.ChangeSequence,
                TestContext.Current.CancellationToken);
            await target.ImportSyncRecoveryStateAsync(
                decoded.SyncState,
                TestContext.Current.CancellationToken);
            Assert.Equal(
                decoded.SyncState.OutboxOperationIds.Count,
                await target.GetOutboxCountAsync(
                    TestContext.Current.CancellationToken));
            using V2VaultSnapshot restored =
                await target.LoadAsync(TestContext.Current.CancellationToken);
            Assert.Single(restored.Accounts);
            Assert.Single(restored.SecretVersions);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(payload);
        }
    }

    [Fact]
    public async Task LegacyPayloadVersionOne_RemainsImportableWithoutSyncHistory()
    {
        V2SqliteVaultStore source = CreateStore("legacy");
        (VaultAccountV2 account, SecretVersionV2 secret) = CreateAccount();
        using (secret)
        {
            await source.SaveAsync(
                [account],
                [secret],
                TestContext.Current.CancellationToken);
        }

        using V2VaultSnapshot snapshot =
            await source.LoadAsync(TestContext.Current.CancellationToken);
        byte[] current = RecoveryPayloadSerializer.Serialize(
            snapshot,
            DateTimeOffset.UtcNow,
            syncState: null);
        byte[] legacy = current[..^1].ToArray();
        BinaryPrimitives.WriteInt32LittleEndian(legacy, 1);
        try
        {
            using RecoveryPayload decoded =
                RecoveryPayloadSerializer.Deserialize(legacy);
            Assert.Null(decoded.SyncState);
            Assert.Single(decoded.Snapshot.Accounts);
            Assert.Single(decoded.Snapshot.SecretVersions);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(current);
            CryptographicOperations.ZeroMemory(legacy);
        }
    }

    public void Dispose()
    {
        if (Directory.Exists(_directory))
        {
            Directory.Delete(_directory, recursive: true);
        }
    }

    private V2SqliteVaultStore CreateStore(string name)
    {
        string directory = Path.Combine(_directory, name);
        return new V2SqliteVaultStore(
            Path.Combine(directory, "vault.db"),
            Path.Combine(directory, "vault.key"));
    }

    private static (VaultAccountV2 Account, SecretVersionV2 Secret) CreateAccount()
    {
        Guid accountId = Guid.NewGuid();
        Guid versionId = Guid.NewGuid();
        return (
            new VaultAccountV2(accountId, "Recovery", "alice", versionId),
            new SecretVersionV2(
                versionId,
                accountId,
                Enumerable.Range(1, 20).Select(value => (byte)value).ToArray(),
                TotpAlgorithm.Sha1,
                6,
                30,
                "otpauth://totp/Recovery%3Aalice?secret=AEBAGBAFAYDQQCIKBMGA2DQPCAIREEYU&issuer=Recovery",
                ProvisioningUriOrigin.CanonicalGenerated));
    }
}
