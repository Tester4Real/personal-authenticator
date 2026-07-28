using Microsoft.Extensions.Logging.Abstractions;
using PersonalAuthenticator.Core.Domain;
using PersonalAuthenticator.Core.Exceptions;
using PersonalAuthenticator.Infrastructure.GitHub;
using PersonalAuthenticator.Infrastructure.Security;
using PersonalAuthenticator.Infrastructure.Storage;
using PersonalAuthenticator.Infrastructure.Sync;

namespace PersonalAuthenticator.Infrastructure.Tests;

public sealed class Phase6SecurityHardeningTests : IDisposable
{
    private readonly string _directory =
        Path.Combine(Path.GetTempPath(), $"pa-phase6-{Guid.NewGuid():N}");
    private static string RecoveryPassword => new('r', 20);

    [Fact]
    public async Task DeviceScreenState_RenamesCurrentDevice_AndBlocksSelfRevocation()
    {
        using VersionedVaultStore store = CreateStore("devices");
        await store.SaveAsync([], TestContext.Current.CancellationToken);
        AuthorisedDeviceInfo current = Assert.Single(
            await store.GetDevicesAsync(TestContext.Current.CancellationToken));
        Assert.True(current.IsCurrent);

        await store.RenameDeviceAsync(
            current.DeviceId,
            "Primary Windows",
            TestContext.Current.CancellationToken);
        Assert.Equal(
            "Primary Windows",
            Assert.Single(await store.GetDevicesAsync(
                TestContext.Current.CancellationToken)).DisplayName);

        SafeApplicationException exception =
            await Assert.ThrowsAsync<SafeApplicationException>(
                () => store.RevokeDeviceAsync(
                    current.DeviceId,
                    TestContext.Current.CancellationToken));
        Assert.Equal("Security.CurrentDeviceRevocation", exception.ErrorCode);
    }

    [Fact]
    public async Task RevokedDevice_PreservesAcceptedHistory_ButRejectsNewSequence()
    {
        string root = Path.Combine(_directory, "revocation-policy");
        var store = new V2SqliteVaultStore(
            Path.Combine(root, "vault.db"),
            Path.Combine(root, "vault.key"));
        await store.SaveAsync([], [], TestContext.Current.CancellationToken);
        Guid deviceId = Guid.NewGuid();
        using SyncOperation first = CreateRemoteOperation(deviceId, 1);
        await store.ApplyRemoteOperationsAsync(
            [first],
            TestContext.Current.CancellationToken);
        store.SetRemoteOperationValidator(
            (incomingDevice, sequence) =>
                incomingDevice != deviceId || sequence <= 1);

        await store.ApplyRemoteOperationsAsync(
            [first],
            TestContext.Current.CancellationToken);
        using SyncOperation second = CreateRemoteOperation(deviceId, 2);
        SafeApplicationException rejected =
            await Assert.ThrowsAsync<SafeApplicationException>(
                () => store.ApplyRemoteOperationsAsync(
                    [second],
                    TestContext.Current.CancellationToken));
        Assert.Equal("Sync.DeviceRevoked", rejected.ErrorCode);
        using V2VaultSnapshot snapshot =
            await store.LoadAsync(TestContext.Current.CancellationToken);
        Assert.Single(snapshot.Accounts);
    }

    [Fact]
    public async Task KeyRotation_VerifiesRecoveryAndAtomicallyActivatesNewEpoch()
    {
        using VersionedVaultStore store = CreateStore("rotation");
        using TotpAccount account = CreateAccount("Rotation", "alice", 3);
        await store.SaveAsync([account], TestContext.Current.CancellationToken);
        string recovery = Path.Combine(_directory, "rotation-recovery");

        await store.RotateKeysAsync(
            recovery,
            RecoveryPassword.AsMemory(),
            TestContext.Current.CancellationToken);

        SecurityEpochStatus status = await store.GetSecurityEpochStatusAsync(
            TestContext.Current.CancellationToken);
        Assert.Equal(2, status.ActiveEpoch);
        Assert.False(status.RotationPending);
        Assert.True(Directory.GetFiles(recovery, "*.par").Length == 1);
        IReadOnlyList<TotpAccount> reopened = await store.LoadAsync(
            TestContext.Current.CancellationToken);
        try
        {
            Assert.Equal("Rotation", Assert.Single(reopened).Issuer);
        }
        finally
        {
            DisposeAccounts(reopened);
        }
    }

    [Theory]
    [InlineData((int)SecurityCheckpoint.AfterPendingEpochPersisted)]
    [InlineData((int)SecurityCheckpoint.AfterReplacementVaultWritten)]
    [InlineData((int)SecurityCheckpoint.AfterReplacementVaultVerified)]
    [InlineData((int)SecurityCheckpoint.AfterRecoveryRotated)]
    [InlineData((int)SecurityCheckpoint.BeforeEpochActivation)]
    public async Task RotationInterruption_NeverActivatesUnverifiedEpoch(
        int failurePointValue)
    {
        var failurePoint = (SecurityCheckpoint)failurePointValue;
        string name = $"rotation-fault-{failurePoint}";
        using VersionedVaultStore store = CreateStore(
            name,
            checkpoint =>
            {
                if (checkpoint == failurePoint)
                {
                    throw new IOException("Injected rotation interruption.");
                }
            });
        using TotpAccount account = CreateAccount("Rollback", "safe", 5);
        await store.SaveAsync([account], TestContext.Current.CancellationToken);

        await Assert.ThrowsAsync<IOException>(
            () => store.RotateKeysAsync(
                Path.Combine(_directory, name, "recovery"),
                RecoveryPassword.AsMemory(),
                TestContext.Current.CancellationToken));
        IReadOnlyList<TotpAccount> active = await store.LoadAsync(
            TestContext.Current.CancellationToken);
        try
        {
            Assert.Equal("Rollback", Assert.Single(active).Issuer);
        }
        finally
        {
            DisposeAccounts(active);
        }

        SecurityEpochStatus status = await store.GetSecurityEpochStatusAsync(
            TestContext.Current.CancellationToken);
        Assert.Equal(1, status.ActiveEpoch);
        Assert.Equal(2, status.PendingEpoch);
    }

    [Fact]
    public async Task Purge_RequiresArchiveAndTypedConfirmation_ThenCreatesCleanEpoch()
    {
        using VersionedVaultStore store = CreateStore("purge");
        using TotpAccount account = CreateAccount("Purge", "alice", 7);
        await store.SaveAsync([account], TestContext.Current.CancellationToken);
        await store.SaveAsync([], TestContext.Current.CancellationToken);
        ArchivedAccountSummary archived = Assert.Single(
            await store.GetArchivedAccountsAsync(
                TestContext.Current.CancellationToken));
        SafeApplicationException confirmation =
            await Assert.ThrowsAsync<SafeApplicationException>(
                () => store.PurgeAccountAsync(
                    archived.Id,
                    "purge",
                    Path.Combine(_directory, "purge-recovery"),
                    RecoveryPassword.AsMemory(),
                    TestContext.Current.CancellationToken));
        Assert.Equal("Security.PurgeConfirmation", confirmation.ErrorCode);

        await store.PurgeAccountAsync(
            archived.Id,
            "PURGE",
            Path.Combine(_directory, "purge-recovery"),
            RecoveryPassword.AsMemory(),
            TestContext.Current.CancellationToken);

        Assert.Empty(await store.GetArchivedAccountsAsync(
            TestContext.Current.CancellationToken));
        Assert.Empty(await store.LoadAsync(TestContext.Current.CancellationToken));
        SecurityEpochStatus status = await store.GetSecurityEpochStatusAsync(
            TestContext.Current.CancellationToken);
        Assert.Equal(2, status.ActiveEpoch);
        Assert.False(status.PurgePending);
    }

    [Fact]
    public async Task CorruptDpapiSecurityState_FailsClosedWithoutExposingDetails()
    {
        using VersionedVaultStore store = CreateStore("dpapi-loss");
        await store.SaveAsync([], TestContext.Current.CancellationToken);
        _ = await store.GetDevicesAsync(TestContext.Current.CancellationToken);
        string path = Path.Combine(_directory, "dpapi-loss", "security-state.dat");
        byte[] bytes = await File.ReadAllBytesAsync(
            path,
            TestContext.Current.CancellationToken);
        bytes[^1] ^= 0x80;
        await File.WriteAllBytesAsync(
            path,
            bytes,
            TestContext.Current.CancellationToken);

        SafeApplicationException exception =
            await Assert.ThrowsAsync<SafeApplicationException>(
                () => store.GetSecurityEpochStatusAsync(
                    TestContext.Current.CancellationToken));
        Assert.Equal("Security.StateUnavailable", exception.ErrorCode);
        Assert.DoesNotContain("byte", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task LocalOnlyMode_NeverCreatesGitHubClient()
    {
        var factory = new CountingGitHubFactory();
        using var store = new VersionedVaultStore(
            NullLogger<DpapiVaultStore>.Instance,
            Path.Combine(_directory, "local-only"),
            recoveryCodec: null,
            recoveryCheckpoint: null,
            syncCheckpoint: null,
            factory);
        using TotpAccount account = CreateAccount("Offline", "only", 9);
        await store.SaveAsync([account], TestContext.Current.CancellationToken);
        _ = await store.LoadAsync(TestContext.Current.CancellationToken);
        _ = await store.GetDevicesAsync(TestContext.Current.CancellationToken);
        Assert.Equal(0, factory.CreateCount);
    }

    public void Dispose()
    {
        if (Directory.Exists(_directory))
        {
            Directory.Delete(_directory, recursive: true);
        }
    }

    private VersionedVaultStore CreateStore(
        string name,
        Action<SecurityCheckpoint>? checkpoint = null) =>
        new(
            NullLogger<DpapiVaultStore>.Instance,
            Path.Combine(_directory, name),
            recoveryCodec: null,
            recoveryCheckpoint: null,
            syncCheckpoint: null,
            githubClientFactory: null,
            checkpoint);

    private static TotpAccount CreateAccount(
        string issuer,
        string accountName,
        byte discriminator) =>
        new(
            Guid.NewGuid(),
            issuer,
            accountName,
            Enumerable.Range(discriminator, 20).Select(value => (byte)value).ToArray(),
            TotpAlgorithm.Sha1,
            6,
            30);

    private static SyncOperation CreateRemoteOperation(
        Guid deviceId,
        long sequence)
    {
        Guid accountId = Guid.NewGuid();
        Guid secretId = Guid.NewGuid();
        var account = new VaultAccountV2(
            accountId,
            "Remote",
            $"device-{sequence}",
            secretId);
        var secret = new SecretVersionV2(
            secretId,
            accountId,
            Enumerable.Range(1, 20).Select(value => (byte)value).ToArray(),
            TotpAlgorithm.Sha1,
            6,
            30,
            "otpauth://totp/Remote%3Adevice?secret=AEBAGBAFAYDQQCIKBMGA2DQPCAIREEYU",
            ProvisioningUriOrigin.CanonicalGenerated);
        return new SyncOperation(
            Guid.NewGuid(),
            deviceId,
            sequence,
            sequence,
            DateTimeOffset.UtcNow.AddSeconds(sequence),
            accountId,
            SyncOperationKind.AccountAdded,
            SyncFieldKeys.Existence,
            [],
            new SyncOperationPayload
            {
                Account = account,
                SecretVersion = secret,
            });
    }

    private static void DisposeAccounts(IEnumerable<TotpAccount> accounts)
    {
        foreach (TotpAccount account in accounts)
        {
            account.Dispose();
        }
    }

    private sealed class CountingGitHubFactory : IGitHubApiClientFactory
    {
        public int CreateCount { get; private set; }

        public IGitHubApiClient Create(ReadOnlyMemory<char> token)
        {
            CreateCount++;
            throw new InvalidOperationException(
                "Local-only mode created a GitHub client.");
        }
    }
}
