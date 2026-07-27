using System.Security.Cryptography;
using Microsoft.Extensions.Logging.Abstractions;
using PersonalAuthenticator.Core.Domain;
using PersonalAuthenticator.Core.Exceptions;
using PersonalAuthenticator.Core.Services;
using PersonalAuthenticator.Infrastructure.Storage;

namespace PersonalAuthenticator.Infrastructure.Tests;

public sealed class VersionedVaultStoreTests : IDisposable
{
    private readonly string _directory =
        Path.Combine(Path.GetTempPath(), $"pa-migration-tests-{Guid.NewGuid():N}");

    [Fact]
    public async Task UpgradeChoice_MigratesAndActivatesOnlyAfterFullVerification()
    {
        var legacy = new DpapiVaultStore(
            NullLogger<DpapiVaultStore>.Instance,
            _directory);
        using TotpAccount first = CreateAccount(
            "Example:Team",
            "alice:primary",
            discriminator: 0,
            sortOrder: 0);
        using TotpAccount second = CreateAccount(
            "Other",
            "bob",
            discriminator: 10,
            sortOrder: 1);
        await legacy.SaveAsync([first, second], TestContext.Current.CancellationToken);
        byte[] original = await File.ReadAllBytesAsync(
            legacy.VaultPath,
            TestContext.Current.CancellationToken);

        using var versioned = new VersionedVaultStore(
            NullLogger<DpapiVaultStore>.Instance,
            _directory);
        Assert.Equal(
            VaultMigrationStatus.ChoiceRequired,
            await versioned.GetStatusAsync(TestContext.Current.CancellationToken));
        Assert.False(File.Exists(Path.Combine(_directory, "active-store.ptr")));
        Assert.False(File.Exists(Path.Combine(_directory, "vault-v2.key")));
        Assert.Empty(Directory.GetFiles(_directory, "vault-v2-*.db"));

        await versioned.ApplyChoiceAsync(
            VaultMigrationChoice.UpgradeToV2,
            TestContext.Current.CancellationToken);

        Assert.Equal(
            VaultMigrationStatus.UsingLocalV2,
            await versioned.GetStatusAsync(TestContext.Current.CancellationToken));
        IReadOnlyList<TotpAccount> migrated =
            await versioned.LoadAsync(TestContext.Current.CancellationToken);
        try
        {
            VaultAccountVerifier.VerifyEquivalent([first, second], migrated);
        }
        finally
        {
            DisposeAccounts(migrated);
        }

        Assert.Equal(
            original,
            await File.ReadAllBytesAsync(
                legacy.VaultPath,
                TestContext.Current.CancellationToken));
        string recoveryPath = Assert.Single(
            Directory.GetFiles(
                Path.Combine(_directory, "migration-recovery"),
                "*.pav"));
        Assert.Equal(
            original,
            await File.ReadAllBytesAsync(
                recoveryPath,
                TestContext.Current.CancellationToken));

        var pointerStore = new ActiveVaultPointerStore(
            Path.Combine(_directory, "active-store.ptr"));
        ActiveVaultPointer pointer = await pointerStore.LoadAsync(
            TestContext.Current.CancellationToken);
        Assert.Equal(ActiveVaultMode.LocalV2, pointer.Mode);
        Assert.True(File.Exists(Path.Combine(_directory, pointer.StoreFileName)));
        Assert.True(File.Exists(Path.Combine(_directory, "vault-v2.key")));

        var v2Store = new V2SqliteVaultStore(
            Path.Combine(_directory, pointer.StoreFileName),
            Path.Combine(_directory, "vault-v2.key"));
        using V2VaultSnapshot snapshot = await v2Store.LoadAsync(
            TestContext.Current.CancellationToken);
        Assert.All(
            snapshot.SecretVersions,
            version => Assert.Equal(
                ProvisioningUriOrigin.CanonicalGenerated,
                version.ProvisioningUriOrigin));
        SecretVersionV2 firstVersion = snapshot.SecretVersions.Single(
            version => version.AccountId == first.Id);
        using ParsedTotpProvisioning parsed =
            new ProvisioningUriParser().Parse(firstVersion.ProvisioningUri);
        Assert.Equal(first.Issuer, parsed.Issuer);
        Assert.Equal(first.AccountName, parsed.AccountName);

        byte[] database = await File.ReadAllBytesAsync(
            v2Store.DatabasePath,
            TestContext.Current.CancellationToken);
        Assert.DoesNotContain("Example:Team"u8.ToArray(), database);
        Assert.DoesNotContain("alice:primary"u8.ToArray(), database);
    }

    [Fact]
    public async Task UpgradeChoice_InterruptedActivation_LeavesChoicePendingAndLegacyUnchanged()
    {
        var legacy = new DpapiVaultStore(
            NullLogger<DpapiVaultStore>.Instance,
            _directory);
        using TotpAccount account = CreateAccount(
            "Example",
            "alice",
            discriminator: 0,
            sortOrder: 0);
        await legacy.SaveAsync([account], TestContext.Current.CancellationToken);
        byte[] original = await File.ReadAllBytesAsync(
            legacy.VaultPath,
            TestContext.Current.CancellationToken);
        string blockedPointerPath = Path.Combine(_directory, "active-store.ptr");
        Directory.CreateDirectory(blockedPointerPath);
        using var versioned = new VersionedVaultStore(
            NullLogger<DpapiVaultStore>.Instance,
            _directory);

        await Assert.ThrowsAsync<SafeApplicationException>(
            () => versioned.ApplyChoiceAsync(
                VaultMigrationChoice.UpgradeToV2,
                TestContext.Current.CancellationToken));

        Assert.Equal(
            VaultMigrationStatus.ChoiceRequired,
            await versioned.GetStatusAsync(TestContext.Current.CancellationToken));
        Assert.False(File.Exists(blockedPointerPath));
        Assert.Equal(
            original,
            await File.ReadAllBytesAsync(
                legacy.VaultPath,
                TestContext.Current.CancellationToken));
        IReadOnlyList<TotpAccount> reopened = await legacy.LoadAsync(
            TestContext.Current.CancellationToken);
        try
        {
            VaultAccountVerifier.VerifyEquivalent([account], reopened);
        }
        finally
        {
            DisposeAccounts(reopened);
        }

        Directory.Delete(blockedPointerPath);
        await versioned.ApplyChoiceAsync(
            VaultMigrationChoice.UpgradeToV2,
            TestContext.Current.CancellationToken);
        Assert.Equal(
            VaultMigrationStatus.UsingLocalV2,
            await versioned.GetStatusAsync(TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task ContinueChoice_PersistsLegacySelectionWithoutCreatingV2Storage()
    {
        var legacy = new DpapiVaultStore(
            NullLogger<DpapiVaultStore>.Instance,
            _directory);
        using TotpAccount account = CreateAccount(
            "Example",
            "alice",
            discriminator: 0,
            sortOrder: 0);
        await legacy.SaveAsync([account], TestContext.Current.CancellationToken);
        byte[] original = await File.ReadAllBytesAsync(
            legacy.VaultPath,
            TestContext.Current.CancellationToken);
        using var versioned = new VersionedVaultStore(
            NullLogger<DpapiVaultStore>.Instance,
            _directory);

        await versioned.ApplyChoiceAsync(
            VaultMigrationChoice.ContinueUsingV1,
            TestContext.Current.CancellationToken);

        Assert.Equal(
            VaultMigrationStatus.UsingLegacyV1,
            await versioned.GetStatusAsync(TestContext.Current.CancellationToken));
        Assert.False(File.Exists(Path.Combine(_directory, "vault-v2.key")));
        Assert.Empty(Directory.GetFiles(_directory, "vault-v2-*.db"));
        Assert.False(Directory.Exists(Path.Combine(_directory, "migration-recovery")));
        IReadOnlyList<TotpAccount> loaded = await versioned.LoadAsync(
            TestContext.Current.CancellationToken);
        try
        {
            VaultAccountVerifier.VerifyEquivalent([account], loaded);
        }
        finally
        {
            DisposeAccounts(loaded);
        }

        using var restarted = new VersionedVaultStore(
            NullLogger<DpapiVaultStore>.Instance,
            _directory);
        Assert.Equal(
            VaultMigrationStatus.UsingLegacyV1,
            await restarted.GetStatusAsync(TestContext.Current.CancellationToken));
        await restarted.ApplyChoiceAsync(
            VaultMigrationChoice.UpgradeToV2,
            TestContext.Current.CancellationToken);
        Assert.Equal(
            VaultMigrationStatus.UsingLocalV2,
            await restarted.GetStatusAsync(TestContext.Current.CancellationToken));
        Assert.Equal(
            original,
            await File.ReadAllBytesAsync(
                legacy.VaultPath,
                TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task CancelChoice_IsNoOpAndLeavesMigrationPromptPending()
    {
        var legacy = new DpapiVaultStore(
            NullLogger<DpapiVaultStore>.Instance,
            _directory);
        using TotpAccount account = CreateAccount(
            "Example",
            "alice",
            discriminator: 0,
            sortOrder: 0);
        await legacy.SaveAsync([account], TestContext.Current.CancellationToken);
        using var versioned = new VersionedVaultStore(
            NullLogger<DpapiVaultStore>.Instance,
            _directory);

        await versioned.ApplyChoiceAsync(
            VaultMigrationChoice.Cancel,
            TestContext.Current.CancellationToken);

        Assert.Equal(
            VaultMigrationStatus.ChoiceRequired,
            await versioned.GetStatusAsync(TestContext.Current.CancellationToken));
        Assert.False(File.Exists(Path.Combine(_directory, "active-store.ptr")));
        Assert.False(File.Exists(Path.Combine(_directory, "vault-v2.key")));
        Assert.Empty(Directory.GetFiles(_directory, "vault-v2-*.db"));
        SafeApplicationException exception = await Assert.ThrowsAsync<SafeApplicationException>(
            () => versioned.LoadAsync(TestContext.Current.CancellationToken));
        Assert.Equal("VaultMigration.ChoiceRequired", exception.ErrorCode);
    }

    [Fact]
    public async Task Rollback_CreatesVerifiedSeparateV1VaultAndPreservesOriginalAndV2()
    {
        var legacy = new DpapiVaultStore(
            NullLogger<DpapiVaultStore>.Instance,
            _directory);
        using TotpAccount originalAccount = CreateAccount(
            "Example",
            "alice",
            discriminator: 0,
            sortOrder: 0);
        await legacy.SaveAsync(
            [originalAccount],
            TestContext.Current.CancellationToken);
        byte[] originalVault = await File.ReadAllBytesAsync(
            legacy.VaultPath,
            TestContext.Current.CancellationToken);
        using var versioned = new VersionedVaultStore(
            NullLogger<DpapiVaultStore>.Instance,
            _directory);
        await versioned.ApplyChoiceAsync(
            VaultMigrationChoice.UpgradeToV2,
            TestContext.Current.CancellationToken);
        IReadOnlyList<TotpAccount> current =
            await versioned.LoadAsync(TestContext.Current.CancellationToken);
        using TotpAccount added = CreateAccount(
            "Other",
            "bob",
            discriminator: 20,
            sortOrder: 1);
        try
        {
            current[0].UpdateDisplay(
                "Example Updated",
                current[0].AccountName,
                new DateTimeOffset(2026, 2, 1, 0, 0, 0, TimeSpan.Zero));
            await versioned.SaveAsync(
                [current[0], added],
                TestContext.Current.CancellationToken);
        }
        finally
        {
            DisposeAccounts(current);
        }

        var pointerStore = new ActiveVaultPointerStore(
            Path.Combine(_directory, "active-store.ptr"));
        ActiveVaultPointer v2Pointer = await pointerStore.LoadAsync(
            TestContext.Current.CancellationToken);
        string v2Path = Path.Combine(_directory, v2Pointer.StoreFileName);

        await versioned.RollbackToLegacyAsync(TestContext.Current.CancellationToken);

        ActiveVaultPointer rollbackPointer = await pointerStore.LoadAsync(
            TestContext.Current.CancellationToken);
        Assert.Equal(ActiveVaultMode.LegacyLocalV1, rollbackPointer.Mode);
        Assert.NotEqual("vault.pav", rollbackPointer.StoreFileName);
        Assert.True(File.Exists(Path.Combine(_directory, rollbackPointer.StoreFileName)));
        Assert.True(File.Exists(v2Path));
        Assert.True(File.Exists(pointerStore.PointerPath + ".previous"));
        Assert.Equal(
            originalVault,
            await File.ReadAllBytesAsync(
                legacy.VaultPath,
                TestContext.Current.CancellationToken));

        IReadOnlyList<TotpAccount> rolledBack =
            await versioned.LoadAsync(TestContext.Current.CancellationToken);
        try
        {
            Assert.Equal(2, rolledBack.Count);
            Assert.Contains(
                rolledBack,
                account => account.Issuer == "Example Updated");
            Assert.Contains(
                rolledBack,
                account => account.AccountName == "bob");
        }
        finally
        {
            DisposeAccounts(rolledBack);
        }
    }

    [Fact]
    public async Task Save_NewInstallation_CreatesV2WithoutLegacyVault()
    {
        using var versioned = new VersionedVaultStore(
            NullLogger<DpapiVaultStore>.Instance,
            _directory);

        await versioned.SaveAsync([], TestContext.Current.CancellationToken);

        Assert.True(await versioned.ExistsAsync(TestContext.Current.CancellationToken));
        Assert.False(File.Exists(Path.Combine(_directory, "vault.pav")));
        var pointerStore = new ActiveVaultPointerStore(
            Path.Combine(_directory, "active-store.ptr"));
        ActiveVaultPointer pointer = await pointerStore.LoadAsync(
            TestContext.Current.CancellationToken);
        Assert.Equal(ActiveVaultMode.LocalV2, pointer.Mode);
    }

    [Fact]
    public async Task Save_MetadataOnlyChange_ReusesActiveSecretVersion()
    {
        using TotpAccount account = CreateAccount(
            "Example",
            "alice",
            discriminator: 0,
            sortOrder: 0);
        using var versioned = new VersionedVaultStore(
            NullLogger<DpapiVaultStore>.Instance,
            _directory);
        await versioned.SaveAsync(
            [account],
            TestContext.Current.CancellationToken);
        var pointerStore = new ActiveVaultPointerStore(
            Path.Combine(_directory, "active-store.ptr"));
        ActiveVaultPointer pointer = await pointerStore.LoadAsync(
            TestContext.Current.CancellationToken);
        var v2Store = new V2SqliteVaultStore(
            Path.Combine(_directory, pointer.StoreFileName),
            Path.Combine(_directory, "vault-v2.key"));
        Guid originalVersionId;
        using (V2VaultSnapshot before = await v2Store.LoadAsync(
                   TestContext.Current.CancellationToken))
        {
            originalVersionId = Assert.Single(before.SecretVersions).Id;
        }

        account.UpdateDisplay(
            "Updated",
            account.AccountName,
            new DateTimeOffset(2026, 2, 1, 0, 0, 0, TimeSpan.Zero));
        await versioned.SaveAsync(
            [account],
            TestContext.Current.CancellationToken);

        using V2VaultSnapshot after = await v2Store.LoadAsync(
            TestContext.Current.CancellationToken);
        Assert.Equal(originalVersionId, Assert.Single(after.SecretVersions).Id);
        Assert.Equal("Updated", Assert.Single(after.Accounts).Issuer);
    }

    [Fact]
    public async Task Exists_CorruptActivePointer_DoesNotFallBackToLegacyVault()
    {
        var legacy = new DpapiVaultStore(
            NullLogger<DpapiVaultStore>.Instance,
            _directory);
        using TotpAccount account = CreateAccount(
            "Example",
            "alice",
            discriminator: 0,
            sortOrder: 0);
        await legacy.SaveAsync([account], TestContext.Current.CancellationToken);
        using var versioned = new VersionedVaultStore(
            NullLogger<DpapiVaultStore>.Instance,
            _directory);
        await versioned.ApplyChoiceAsync(
            VaultMigrationChoice.UpgradeToV2,
            TestContext.Current.CancellationToken);
        IReadOnlyList<TotpAccount> migrated =
            await versioned.LoadAsync(TestContext.Current.CancellationToken);
        DisposeAccounts(migrated);
        string pointerPath = Path.Combine(_directory, "active-store.ptr");
        byte[] pointer = await File.ReadAllBytesAsync(
            pointerPath,
            TestContext.Current.CancellationToken);
        pointer[^1] ^= 0x40;
        await File.WriteAllBytesAsync(
            pointerPath,
            pointer,
            TestContext.Current.CancellationToken);

        await Assert.ThrowsAsync<SafeApplicationException>(
            () => versioned.ExistsAsync(TestContext.Current.CancellationToken));
    }

    public void Dispose()
    {
        if (Directory.Exists(_directory))
        {
            Directory.Delete(_directory, recursive: true);
        }
    }

    private static TotpAccount CreateAccount(
        string issuer,
        string accountName,
        byte discriminator,
        int sortOrder)
    {
        byte[] secret = Enumerable.Range(1, 20)
            .Select(value => (byte)(value + discriminator))
            .ToArray();
        return new TotpAccount(
            Guid.NewGuid(),
            issuer,
            accountName,
            secret,
            discriminator == 0 ? TotpAlgorithm.Sha1 : TotpAlgorithm.Sha256,
            discriminator == 0 ? 6 : 8,
            discriminator == 0 ? 30 : 60,
            favourite: discriminator == 0,
            sortOrder,
            createdAtUtc: new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero),
            updatedAtUtc: new DateTimeOffset(2026, 1, 2, 0, 0, 0, TimeSpan.Zero));
    }

    private static void DisposeAccounts(IEnumerable<TotpAccount> accounts)
    {
        foreach (TotpAccount account in accounts)
        {
            account.Dispose();
        }
    }
}
