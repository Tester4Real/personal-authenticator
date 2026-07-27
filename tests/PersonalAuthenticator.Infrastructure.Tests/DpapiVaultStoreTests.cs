using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Logging.Abstractions;
using PersonalAuthenticator.Core.Domain;
using PersonalAuthenticator.Core.Exceptions;
using PersonalAuthenticator.Infrastructure.Storage;

namespace PersonalAuthenticator.Infrastructure.Tests;

public sealed class DpapiVaultStoreTests : IDisposable
{
    private readonly string _directory = Path.Combine(Path.GetTempPath(), $"pa-tests-{Guid.NewGuid():N}");

    [Fact]
    public async Task SaveAndLoad_MultipleAccounts_RoundTripsWithoutPlaintext()
    {
        var store = new DpapiVaultStore(NullLogger<DpapiVaultStore>.Instance, _directory);
        byte[] secret = RandomNumberGenerator.GetBytes(20);
        using var first = new TotpAccount(Guid.NewGuid(), "PrivateIssuerMarker", "alice", secret);
        using var second = new TotpAccount(Guid.NewGuid(), "Another", "bob", RandomNumberGenerator.GetBytes(32), TotpAlgorithm.Sha256, 8);

        await store.SaveAsync([first, second], TestContext.Current.CancellationToken);
        byte[] persisted = await File.ReadAllBytesAsync(store.VaultPath, TestContext.Current.CancellationToken);
        Assert.False(persisted.AsSpan().IndexOf(secret) >= 0);
        Assert.DoesNotContain("PrivateIssuerMarker"u8.ToArray(), persisted);

        IReadOnlyList<TotpAccount> loaded = await store.LoadAsync(TestContext.Current.CancellationToken);
        try
        {
            Assert.Equal(2, loaded.Count);
            Assert.Equal(secret, loaded[0].Secret.ToArray());
        }
        finally
        {
            foreach (TotpAccount account in loaded)
            {
                account.Dispose();
            }
        }
    }

    [Fact]
    public async Task Save_EmptyVault_MatchesFrozenV1EnvelopeHeader()
    {
        var store = new DpapiVaultStore(NullLogger<DpapiVaultStore>.Instance, _directory);

        await store.SaveAsync([], TestContext.Current.CancellationToken);

        byte[] envelope = await File.ReadAllBytesAsync(
            store.VaultPath,
            TestContext.Current.CancellationToken);
        Assert.True(envelope.Length > 54);
        Assert.Equal("PAVLT001", Encoding.ASCII.GetString(envelope, 0, 8));
        Assert.Equal(1, BinaryPrimitives.ReadUInt16LittleEndian(envelope.AsSpan(8, 2)));
        int protectedLength = BinaryPrimitives.ReadInt32LittleEndian(envelope.AsSpan(18, 4));
        Assert.Equal(envelope.Length - 54, protectedLength);
        Assert.Equal(
            SHA256.HashData(envelope.AsSpan(54)),
            envelope.AsSpan(22, 32).ToArray());
    }

    [Fact]
    public async Task CorruptedCiphertext_IsRejected()
    {
        var store = new DpapiVaultStore(NullLogger<DpapiVaultStore>.Instance, _directory);
        using var account = new TotpAccount(Guid.NewGuid(), "Example", "account", RandomNumberGenerator.GetBytes(20));
        await store.SaveAsync([account], TestContext.Current.CancellationToken);
        byte[] bytes = await File.ReadAllBytesAsync(store.VaultPath, TestContext.Current.CancellationToken);
        bytes[^1] ^= 0x40;
        await File.WriteAllBytesAsync(store.VaultPath, bytes, TestContext.Current.CancellationToken);

        await Assert.ThrowsAsync<SafeApplicationException>(
            () => store.LoadAsync(TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task InvalidVersion_IsRejected()
    {
        var store = new DpapiVaultStore(NullLogger<DpapiVaultStore>.Instance, _directory);
        await store.SaveAsync([], TestContext.Current.CancellationToken);
        byte[] bytes = await File.ReadAllBytesAsync(store.VaultPath, TestContext.Current.CancellationToken);
        bytes[8] = 99;
        await File.WriteAllBytesAsync(store.VaultPath, bytes, TestContext.Current.CancellationToken);

        await Assert.ThrowsAsync<SafeApplicationException>(
            () => store.LoadAsync(TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task Save_WhenStorageSecurityFails_DoesNotReplaceCommittedVault()
    {
        var store = new DpapiVaultStore(NullLogger<DpapiVaultStore>.Instance, _directory);
        using var original = new TotpAccount(
            Guid.NewGuid(),
            "Original",
            "account",
            RandomNumberGenerator.GetBytes(20));
        await store.SaveAsync([original], TestContext.Current.CancellationToken);
        byte[] committed = await File.ReadAllBytesAsync(
            store.VaultPath,
            TestContext.Current.CancellationToken);
        var failingStore = new DpapiVaultStore(
            NullLogger<DpapiVaultStore>.Instance,
            _directory,
            _ => throw new UnauthorizedAccessException("Simulated ACL failure."));
        using var replacement = new TotpAccount(
            Guid.NewGuid(),
            "Replacement",
            "account",
            RandomNumberGenerator.GetBytes(20));

        SafeApplicationException exception = await Assert.ThrowsAsync<SafeApplicationException>(
            () => failingStore.SaveAsync([replacement], TestContext.Current.CancellationToken));

        Assert.Equal("Vault.SecurityFailed", exception.ErrorCode);
        byte[] afterFailure = await File.ReadAllBytesAsync(
            store.VaultPath,
            TestContext.Current.CancellationToken);
        Assert.Equal(committed, afterFailure);
    }

    public void Dispose()
    {
        if (Directory.Exists(_directory))
        {
            Directory.Delete(_directory, recursive: true);
        }
    }
}
