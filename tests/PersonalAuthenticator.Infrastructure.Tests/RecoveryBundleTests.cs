using System.Buffers.Binary;
using System.Security.Cryptography;
using Microsoft.Extensions.Logging.Abstractions;
using PersonalAuthenticator.Core.Domain;
using PersonalAuthenticator.Core.Exceptions;
using PersonalAuthenticator.Infrastructure.Recovery;
using PersonalAuthenticator.Infrastructure.Storage;

namespace PersonalAuthenticator.Infrastructure.Tests;

public sealed class RecoveryBundleTests : IDisposable
{
    private readonly char[] _password = "correct horse battery staple".ToCharArray();
    private readonly string _directory = Path.Combine(
        Path.GetTempPath(),
        $"PersonalAuthenticator-RecoveryTests-{Guid.NewGuid():N}");

    public RecoveryBundleTests() => Directory.CreateDirectory(_directory);

    [Fact]
    public async Task Bundle_RoundTripsEveryRecord_WithoutPlaintextLeakage()
    {
        var codec = CreateTestCodec();
        using V2VaultSnapshot snapshot = CreateSnapshot(changeSequence: 7);
        byte[] envelope = await codec.EncryptAsync(
            RecoverySlot.A,
            snapshot,
            _password,
            new DateTimeOffset(2026, 7, 1, 12, 0, 0, TimeSpan.Zero),
            TestContext.Current.CancellationToken);
        try
        {
            Assert.DoesNotContain("RecoveryPrivateIssuer"u8.ToArray(), envelope);
            Assert.DoesNotContain("alice@example.test"u8.ToArray(), envelope);
            Assert.DoesNotContain(snapshot.SecretVersions[0].Secret.ToArray(), envelope);

            using DecodedRecoveryBundle decoded = await codec.DecryptAsync(
                envelope,
                _password,
                Path.Combine(_directory, "memory.par"),
                TestContext.Current.CancellationToken);
            Assert.Equal(RecoverySlot.A, decoded.Slot);
            Assert.Equal(7, decoded.Payload.Snapshot.ChangeSequence);
            Assert.Single(decoded.Payload.Snapshot.Accounts);
            Assert.Equal(3, decoded.Payload.Snapshot.SecretVersions.Count);
            Assert.Equal(3, decoded.Payload.Snapshot.HistoryEntries.Count);
            Assert.Contains(
                decoded.Payload.Snapshot.SecretVersions,
                version => version.State == SecretVersionState.Candidate);
            Assert.Contains(
                decoded.Payload.Snapshot.SecretVersions,
                version => version.State == SecretVersionState.Retired);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(envelope);
        }
    }

    [Fact]
    public async Task Bundle_WrongPasswordTamperingTruncationAndUnsafeKdf_AreRejected()
    {
        var codec = CreateTestCodec();
        using V2VaultSnapshot snapshot = CreateSnapshot(changeSequence: 3);
        byte[] envelope = await codec.EncryptAsync(
            RecoverySlot.A,
            snapshot,
            _password,
            DateTimeOffset.UtcNow,
            TestContext.Current.CancellationToken);
        try
        {
            SafeApplicationException wrongPassword =
                await Assert.ThrowsAsync<SafeApplicationException>(
                    () => codec.DecryptAsync(
                        envelope,
                        "this password is wrong".AsMemory(),
                        Path.Combine(_directory, "wrong.par"),
                        TestContext.Current.CancellationToken));
            Assert.Equal("Recovery.AuthenticationFailed", wrongPassword.ErrorCode);

            byte[] tampered = envelope.ToArray();
            tampered[60] ^= 0x80;
            SafeApplicationException tamper =
                await Assert.ThrowsAsync<SafeApplicationException>(
                    () => codec.DecryptAsync(
                        tampered,
                        _password,
                        Path.Combine(_directory, "tampered.par"),
                        TestContext.Current.CancellationToken));
            Assert.Equal("Recovery.AuthenticationFailed", tamper.ErrorCode);

            SafeApplicationException truncated =
                await Assert.ThrowsAsync<SafeApplicationException>(
                    () => codec.DecryptAsync(
                        envelope.AsMemory(0, 20),
                        _password,
                        Path.Combine(_directory, "truncated.par"),
                        TestContext.Current.CancellationToken));
            Assert.Equal("Recovery.InvalidBundle", truncated.ErrorCode);

            byte[] unsafeKdf = envelope.ToArray();
            BinaryPrimitives.WriteInt32LittleEndian(unsafeKdf.AsSpan(12, 4), int.MaxValue);
            SafeApplicationException unsafeParameters =
                await Assert.ThrowsAsync<SafeApplicationException>(
                    () => codec.DecryptAsync(
                        unsafeKdf,
                        _password,
                        Path.Combine(_directory, "unsafe.par"),
                        TestContext.Current.CancellationToken));
            Assert.Equal("Recovery.InvalidBundle", unsafeParameters.ErrorCode);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(envelope);
        }
    }

    [Fact]
    public void Payload_OversizedCollectionLength_IsRejectedBeforeAllocation()
    {
        byte[] payload = new byte[32];
        BinaryPrimitives.WriteInt32LittleEndian(payload.AsSpan(0, 4), 1);
        BinaryPrimitives.WriteInt64LittleEndian(
            payload.AsSpan(4, 8),
            DateTimeOffset.UtcNow.UtcTicks);
        BinaryPrimitives.WriteInt64LittleEndian(payload.AsSpan(12, 8), 0);
        BinaryPrimitives.WriteInt32LittleEndian(
            payload.AsSpan(20, 4),
            int.MaxValue);

        SafeApplicationException exception = Assert.Throws<SafeApplicationException>(
            () => RecoveryPayloadSerializer.Deserialize(payload));

        Assert.Equal("Recovery.InvalidBundle", exception.ErrorCode);
    }

    [Fact]
    public async Task Rotation_InterruptedWritingB_PreservesVerifiedA()
    {
        RecoveryCheckpoint? failAt = null;
        var manager = CreateManager(checkpoint =>
        {
            if (checkpoint == failAt)
            {
                throw new IOException("Simulated write interruption.");
            }
        });
        using V2VaultSnapshot first = CreateSnapshot(changeSequence: 1);
        RecoveryBundleInfo slotA = await manager.CreateAsync(
            _directory,
            _password,
            first,
            TestContext.Current.CancellationToken);
        Assert.Equal(RecoverySlot.A, slotA.Slot);

        failAt = RecoveryCheckpoint.AfterSlotWriteBeforeVerification;
        using V2VaultSnapshot second = CreateSnapshot(changeSequence: 2);
        await Assert.ThrowsAsync<SafeApplicationException>(
            () => manager.CreateAsync(
                _directory,
                _password,
                second,
                TestContext.Current.CancellationToken));

        RecoveryBundleInfo verifiedA = await manager.VerifyAsync(
            Path.Combine(_directory, RecoveryBundleManager.SlotAFileName),
            _password,
            TestContext.Current.CancellationToken);
        Assert.Equal(1, verifiedA.ChangeSequence);
        Assert.False(File.Exists(
            Path.Combine(_directory, RecoveryBundleManager.SlotBFileName)));
    }

    [Fact]
    public async Task Rotation_InterruptedWritingA_PreservesVerifiedB()
    {
        RecoveryCheckpoint? failAt = null;
        var manager = CreateManager(checkpoint =>
        {
            if (checkpoint == failAt)
            {
                throw new IOException("Simulated activation interruption.");
            }
        });
        using V2VaultSnapshot first = CreateSnapshot(changeSequence: 1);
        await manager.CreateAsync(
            _directory,
            _password,
            first,
            TestContext.Current.CancellationToken);
        using V2VaultSnapshot second = CreateSnapshot(changeSequence: 2);
        RecoveryBundleInfo slotB = await manager.CreateAsync(
            _directory,
            _password,
            second,
            TestContext.Current.CancellationToken);
        Assert.Equal(RecoverySlot.B, slotB.Slot);

        failAt = RecoveryCheckpoint.AfterVerificationBeforeActivation;
        using V2VaultSnapshot third = CreateSnapshot(changeSequence: 3);
        await Assert.ThrowsAsync<SafeApplicationException>(
            () => manager.CreateAsync(
                _directory,
                _password,
                third,
                TestContext.Current.CancellationToken));

        RecoveryBundleInfo verifiedB = await manager.VerifyAsync(
            Path.Combine(_directory, RecoveryBundleManager.SlotBFileName),
            _password,
            TestContext.Current.CancellationToken);
        Assert.Equal(2, verifiedB.ChangeSequence);
    }

    [Fact]
    public async Task Health_TracksExactChangesAndWarnsAtThreshold()
    {
        var manager = CreateManager();
        using V2VaultSnapshot snapshot = CreateSnapshot(changeSequence: 5);
        await manager.CreateAsync(
            _directory,
            _password,
            snapshot,
            TestContext.Current.CancellationToken);

        RecoveryHealthStatus healthy = await manager.GetHealthAsync(
            12,
            TestContext.Current.CancellationToken);
        Assert.True(healthy.HasVerifiedRecovery);
        Assert.False(healthy.IsOutdated);
        Assert.Equal(7, healthy.ChangesSinceVerifiedRecovery);

        RecoveryHealthStatus outdated = await manager.GetHealthAsync(
            25,
            TestContext.Current.CancellationToken);
        Assert.True(outdated.IsOutdated);
        Assert.Equal(20, outdated.ChangesSinceVerifiedRecovery);
    }

    [Fact]
    public async Task Health_TamperedVerifiedFile_IsNoLongerHealthy()
    {
        var manager = CreateManager();
        using V2VaultSnapshot snapshot = CreateSnapshot(changeSequence: 5);
        RecoveryBundleInfo info = await manager.CreateAsync(
            _directory,
            _password,
            snapshot,
            TestContext.Current.CancellationToken);
        byte[] bundle = await File.ReadAllBytesAsync(
            info.FilePath,
            TestContext.Current.CancellationToken);
        bundle[60] ^= 0x40;
        await File.WriteAllBytesAsync(
            info.FilePath,
            bundle,
            TestContext.Current.CancellationToken);

        RecoveryHealthStatus health = await manager.GetHealthAsync(
            5,
            TestContext.Current.CancellationToken);

        Assert.False(health.HasVerifiedRecovery);
        Assert.True(health.IsOutdated);
    }

    [Fact]
    public async Task Rotation_WriteFailure_DoesNotReplaceVerifiedSlot()
    {
        RecoveryCheckpoint? failAt = null;
        var manager = CreateManager(checkpoint =>
        {
            if (checkpoint == failAt)
            {
                throw new IOException("Simulated disk-full failure.");
            }
        });
        using V2VaultSnapshot first = CreateSnapshot(changeSequence: 10);
        await manager.CreateAsync(
            _directory,
            _password,
            first,
            TestContext.Current.CancellationToken);
        byte[] original = await File.ReadAllBytesAsync(
            Path.Combine(_directory, RecoveryBundleManager.SlotAFileName),
            TestContext.Current.CancellationToken);

        failAt = RecoveryCheckpoint.BeforeSlotWrite;
        using V2VaultSnapshot second = CreateSnapshot(changeSequence: 11);
        await Assert.ThrowsAsync<SafeApplicationException>(
            () => manager.CreateAsync(
                _directory,
                _password,
                second,
                TestContext.Current.CancellationToken));

        byte[] preserved = await File.ReadAllBytesAsync(
            Path.Combine(_directory, RecoveryBundleManager.SlotAFileName),
            TestContext.Current.CancellationToken);
        Assert.Equal(original, preserved);
    }

    public void Dispose()
    {
        Array.Clear(_password);
        if (Directory.Exists(_directory))
        {
            Directory.Delete(_directory, recursive: true);
        }
    }

    internal static V2VaultSnapshot CreateSnapshot(long changeSequence)
    {
        Guid accountId = Guid.NewGuid();
        Guid activeId = Guid.NewGuid();
        Guid candidateId = Guid.NewGuid();
        Guid retiredId = Guid.NewGuid();
        DateTimeOffset created = new(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
        var account = new VaultAccountV2(
            accountId,
            "RecoveryPrivateIssuer",
            "alice@example.test",
            activeId,
            favourite: true,
            sortOrder: 0,
            createdAtUtc: created,
            updatedAtUtc: created.AddDays(2));
        var active = new SecretVersionV2(
            activeId,
            accountId,
            Enumerable.Range(1, 20).Select(value => (byte)value).ToArray(),
            TotpAlgorithm.Sha256,
            8,
            60,
            "otpauth://totp/RecoveryPrivateIssuer%3Aalice%40example.test?secret=AEBAGBAFAYDQQCIKBMGA2DQPCAIREEYU&issuer=RecoveryPrivateIssuer",
            ProvisioningUriOrigin.Original,
            SecretVersionState.Active,
            created.AddDays(2));
        var candidate = new SecretVersionV2(
            candidateId,
            accountId,
            Enumerable.Range(31, 20).Select(value => (byte)value).ToArray(),
            TotpAlgorithm.Sha1,
            6,
            30,
            "otpauth://totp/RecoveryPrivateIssuer%3Aalice%40example.test?secret=D4QCCIRDEQSSMJZHFAUSUKZMFUXC6MBR&issuer=RecoveryPrivateIssuer",
            ProvisioningUriOrigin.CanonicalGenerated,
            SecretVersionState.Candidate,
            created.AddDays(3));
        var retired = new SecretVersionV2(
            retiredId,
            accountId,
            Enumerable.Range(61, 20).Select(value => (byte)value).ToArray(),
            TotpAlgorithm.Sha1,
            6,
            30,
            "otpauth://totp/RecoveryPrivateIssuer%3Aalice%40example.test?secret=H5AUEQ2EIVDEOSCJJJFUYTKOJ5IFCUST&issuer=RecoveryPrivateIssuer",
            ProvisioningUriOrigin.Original,
            SecretVersionState.Retired,
            created,
            created.AddDays(2));
        AccountHistoryEntryV2[] history =
        [
            new(
                Guid.NewGuid(),
                accountId,
                AccountHistoryAction.Added,
                created,
                retiredId),
            new(
                Guid.NewGuid(),
                accountId,
                AccountHistoryAction.SecretActivated,
                created.AddDays(2),
                activeId,
                retiredId),
            new(
                Guid.NewGuid(),
                accountId,
                AccountHistoryAction.SecretCandidateAdded,
                created.AddDays(3),
                candidateId),
        ];
        return new V2VaultSnapshot(
            [account],
            [active, candidate, retired],
            history,
            changeSequence);
    }

    private RecoveryBundleManager CreateManager(
        Action<RecoveryCheckpoint>? checkpoint = null) =>
        new(_directory, CreateTestCodec(), checkpoint);

    private static RecoveryBundleCodec CreateTestCodec() =>
        new(memorySizeKiB: 8192, iterations: 1, parallelism: 1);
}
