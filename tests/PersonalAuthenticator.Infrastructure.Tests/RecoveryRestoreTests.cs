using System.Security.Cryptography;
using Microsoft.Extensions.Logging.Abstractions;
using PersonalAuthenticator.Core.Domain;
using PersonalAuthenticator.Core.Exceptions;
using PersonalAuthenticator.Infrastructure.Recovery;
using PersonalAuthenticator.Infrastructure.Storage;

namespace PersonalAuthenticator.Infrastructure.Tests;

public sealed class RecoveryRestoreTests : IDisposable
{
    private readonly string _directory = Path.Combine(
        Path.GetTempPath(),
        $"PersonalAuthenticator-RecoveryRestoreTests-{Guid.NewGuid():N}");
    private readonly char[] _password = "restore password kept offline".ToCharArray();

    public RecoveryRestoreTests() => Directory.CreateDirectory(_directory);

    [Fact]
    public async Task Restore_CorruptDatabase_CreatesVerifiedReplacementAndPreservesOldVault()
    {
        (string databasePath, _, _) = await CreateActiveVaultAsync();
        string recoveryDirectory = Path.Combine(_directory, "recovery");
        var service = CreateService();
        RecoveryBundleInfo bundle = await service.CreateRecoveryBundleAsync(
            recoveryDirectory,
            _password,
            TestContext.Current.CancellationToken);

        byte[] corruptBytes = RandomNumberGenerator.GetBytes(4096);
        await File.WriteAllBytesAsync(
            databasePath,
            corruptBytes,
            TestContext.Current.CancellationToken);

        RecoveryBundleInfo restored = await service.RestoreRecoveryBundleAsync(
            bundle.FilePath,
            _password,
            TestContext.Current.CancellationToken);
        Assert.Equal(bundle.ChangeSequence, restored.ChangeSequence);

        var pointerStore = new ActiveVaultPointerStore(
            Path.Combine(_directory, "active-store.ptr"));
        ActiveVaultPointer pointer = await pointerStore.LoadAsync(
            TestContext.Current.CancellationToken);
        Assert.NotEqual(Path.GetFileName(databasePath), pointer.StoreFileName);
        Assert.NotNull(pointer.RootKeyFileName);
        Assert.Equal(
            corruptBytes,
            await File.ReadAllBytesAsync(
                databasePath,
                TestContext.Current.CancellationToken));

        IReadOnlyList<TotpAccount> accounts = await service.LoadAsync(
            TestContext.Current.CancellationToken);
        try
        {
            TotpAccount account = Assert.Single(accounts);
            Assert.Equal("RecoveryPrivateIssuer", account.Issuer);
        }
        finally
        {
            DisposeAccounts(accounts);
        }

        var recoveredStore = new V2SqliteVaultStore(
            Path.Combine(_directory, pointer.StoreFileName),
            Path.Combine(_directory, pointer.RootKeyFileName!));
        using V2VaultSnapshot recovered = await recoveredStore.LoadAsync(
            TestContext.Current.CancellationToken);
        Assert.Equal(bundle.ChangeSequence + 1, recovered.ChangeSequence);
        Assert.Contains(
            recovered.HistoryEntries,
            entry => entry.Action == AccountHistoryAction.Recovered);

        RecoveryHealthStatus health = await service.GetRecoveryHealthAsync(
            TestContext.Current.CancellationToken);
        Assert.Equal(1, health.ChangesSinceVerifiedRecovery);
    }

    [Fact]
    public async Task Restore_MissingRootKey_RecoversWithoutDeletingOriginalDatabase()
    {
        (string databasePath, string keyPath, _) = await CreateActiveVaultAsync();
        var service = CreateService();
        RecoveryBundleInfo bundle = await service.CreateRecoveryBundleAsync(
            Path.Combine(_directory, "recovery"),
            _password,
            TestContext.Current.CancellationToken);
        byte[] originalDatabase = await File.ReadAllBytesAsync(
            databasePath,
            TestContext.Current.CancellationToken);
        File.Delete(keyPath);

        await service.RestoreRecoveryBundleAsync(
            bundle.FilePath,
            _password,
            TestContext.Current.CancellationToken);

        Assert.False(File.Exists(keyPath));
        Assert.Equal(
            originalDatabase,
            await File.ReadAllBytesAsync(
                databasePath,
                TestContext.Current.CancellationToken));
        IReadOnlyList<TotpAccount> accounts = await service.LoadAsync(
            TestContext.Current.CancellationToken);
        DisposeAccounts(accounts);
    }

    [Fact]
    public async Task Restore_InterruptedBeforePointerActivation_PreservesOldPointer()
    {
        await CreateActiveVaultAsync();
        var creator = CreateService();
        RecoveryBundleInfo bundle = await creator.CreateRecoveryBundleAsync(
            Path.Combine(_directory, "recovery"),
            _password,
            TestContext.Current.CancellationToken);
        string pointerPath = Path.Combine(_directory, "active-store.ptr");
        byte[] pointerBefore = await File.ReadAllBytesAsync(
            pointerPath,
            TestContext.Current.CancellationToken);

        var interrupted = new VersionedVaultStore(
            NullLogger<DpapiVaultStore>.Instance,
            _directory,
            new RecoveryBundleCodec(8192, 1, 1),
            checkpoint =>
            {
                if (checkpoint ==
                    RecoveryCheckpoint.AfterRecoveredVaultVerificationBeforeActivation)
                {
                    throw new IOException("Simulated activation interruption.");
                }
            });
        await Assert.ThrowsAsync<IOException>(
            () => interrupted.RestoreRecoveryBundleAsync(
                bundle.FilePath,
                _password,
                TestContext.Current.CancellationToken));

        Assert.Equal(
            pointerBefore,
            await File.ReadAllBytesAsync(
                pointerPath,
                TestContext.Current.CancellationToken));
        Assert.Empty(
            Directory.GetFiles(_directory, "vault-v2-recovered-*.db"));
        Assert.Empty(
            Directory.GetFiles(_directory, "vault-v2-recovered-*.key"));
    }

    [Fact]
    public async Task Restore_DiskFullBeforeReplacementWrite_PreservesOldPointer()
    {
        await CreateActiveVaultAsync();
        var creator = CreateService();
        RecoveryBundleInfo bundle = await creator.CreateRecoveryBundleAsync(
            Path.Combine(_directory, "recovery"),
            _password,
            TestContext.Current.CancellationToken);
        string pointerPath = Path.Combine(_directory, "active-store.ptr");
        byte[] pointerBefore = await File.ReadAllBytesAsync(
            pointerPath,
            TestContext.Current.CancellationToken);

        var diskFull = new VersionedVaultStore(
            NullLogger<DpapiVaultStore>.Instance,
            _directory,
            new RecoveryBundleCodec(8192, 1, 1),
            checkpoint =>
            {
                if (checkpoint == RecoveryCheckpoint.BeforeRecoveredVaultWrite)
                {
                    throw new IOException("Simulated disk-full failure.");
                }
            });
        await Assert.ThrowsAsync<IOException>(
            () => diskFull.RestoreRecoveryBundleAsync(
                bundle.FilePath,
                _password,
                TestContext.Current.CancellationToken));

        Assert.Equal(
            pointerBefore,
            await File.ReadAllBytesAsync(
                pointerPath,
                TestContext.Current.CancellationToken));
        Assert.Empty(
            Directory.GetFiles(_directory, "vault-v2-recovered-*"));
    }

    public void Dispose()
    {
        Array.Clear(_password);
        if (Directory.Exists(_directory))
        {
            Directory.Delete(_directory, recursive: true);
        }
    }

    private async Task<(string DatabasePath, string KeyPath, ActiveVaultPointer Pointer)>
        CreateActiveVaultAsync()
    {
        string databaseFileName = "vault-v2-current.db";
        string keyFileName = "vault-v2-current.key";
        string databasePath = Path.Combine(_directory, databaseFileName);
        string keyPath = Path.Combine(_directory, keyFileName);
        using V2VaultSnapshot source = RecoveryBundleTests.CreateSnapshot(0);
        var store = new V2SqliteVaultStore(databasePath, keyPath);
        await store.SaveAsync(
            source.Accounts,
            source.SecretVersions,
            source.HistoryEntries,
            TestContext.Current.CancellationToken);
        var pointer = new ActiveVaultPointer(
            ActiveVaultMode.LocalV2,
            databaseFileName,
            LegacySourceSha256: null,
            DateTimeOffset.UtcNow,
            keyFileName);
        var pointerStore = new ActiveVaultPointerStore(
            Path.Combine(_directory, "active-store.ptr"));
        await pointerStore.SaveAsync(pointer, TestContext.Current.CancellationToken);
        return (databasePath, keyPath, pointer);
    }

    private VersionedVaultStore CreateService() =>
        new(
            NullLogger<DpapiVaultStore>.Instance,
            _directory,
            new RecoveryBundleCodec(8192, 1, 1),
            recoveryCheckpoint: null);

    private static void DisposeAccounts(IEnumerable<TotpAccount> accounts)
    {
        foreach (TotpAccount account in accounts)
        {
            account.Dispose();
        }
    }
}
