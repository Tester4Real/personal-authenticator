using PersonalAuthenticator.Core.Abstractions;
using PersonalAuthenticator.Core.Domain;
using PersonalAuthenticator.Core.Security;
using PersonalAuthenticator.Core.Services;

namespace PersonalAuthenticator.Core.Tests;

public sealed class VaultServiceTests
{
    [Fact]
    public async Task InitialiseAddLockUnlock_RoundTripsAndClearsActiveAccounts()
    {
        var store = new InMemoryVaultStore();
        using var service = new VaultService(store, new FixedClock(), new DuplicateDetector());
        await service.InitialiseAsync(unlock: true, TestContext.Current.CancellationToken);
        var account = CreateAccount("one");

        await service.AddAsync(account, TestContext.Current.CancellationToken);
        Assert.Single(service.Accounts);

        await service.LockAsync(TestContext.Current.CancellationToken);
        Assert.Equal(VaultState.Locked, service.State);
        Assert.Empty(service.Accounts);

        await service.UnlockAsync(TestContext.Current.CancellationToken);
        Assert.Equal(VaultState.Unlocked, service.State);
        Assert.Single(service.Accounts);
        Assert.Throws<ObjectDisposedException>(() => account.Secret.ToArray());
    }

    [Fact]
    public async Task Add_Duplicate_IsRejected()
    {
        var store = new InMemoryVaultStore();
        using var service = new VaultService(store, new FixedClock(), new DuplicateDetector());
        await service.InitialiseAsync(unlock: true, TestContext.Current.CancellationToken);
        TotpAccount first = CreateAccount("same");
        TotpAccount duplicate = CreateAccount("same");
        await service.AddAsync(first, TestContext.Current.CancellationToken);

        await Assert.ThrowsAsync<PersonalAuthenticator.Core.Exceptions.SafeApplicationException>(
            () => service.AddAsync(duplicate, TestContext.Current.CancellationToken));
        duplicate.Dispose();
    }

    [Fact]
    public async Task FavouriteMoveDelete_PersistsExpectedOrder()
    {
        var store = new InMemoryVaultStore();
        using var service = new VaultService(store, new FixedClock(), new DuplicateDetector());
        await service.InitialiseAsync(unlock: true, TestContext.Current.CancellationToken);
        TotpAccount first = CreateAccount("one", 1);
        TotpAccount second = CreateAccount("two", 2);
        await service.AddAsync(first, TestContext.Current.CancellationToken);
        await service.AddAsync(second, TestContext.Current.CancellationToken);

        await service.SetFavouriteAsync(second.Id, true, TestContext.Current.CancellationToken);
        await service.MoveAsync(second.Id, 0, TestContext.Current.CancellationToken);
        await service.DeleteAsync(first.Id, TestContext.Current.CancellationToken);

        TotpAccount remaining = Assert.Single(service.Accounts);
        Assert.Equal("two", remaining.AccountName);
        Assert.True(remaining.Favourite);
        Assert.Equal(0, remaining.SortOrder);
    }

    [Fact]
    public async Task FailedDelete_RetainsLiveAccountAndEntersFaultedState()
    {
        var store = new InMemoryVaultStore();
        using var service = new VaultService(store, new FixedClock(), new DuplicateDetector());
        await service.InitialiseAsync(unlock: true, TestContext.Current.CancellationToken);
        await service.AddAsync(CreateAccount("one"), TestContext.Current.CancellationToken);
        TotpAccount active = Assert.Single(service.Accounts);
        byte[] expectedSecret = active.Secret.ToArray();
        store.FailSaves = true;

        await Assert.ThrowsAsync<IOException>(
            () => service.DeleteAsync(active.Id, TestContext.Current.CancellationToken));

        Assert.Equal(VaultState.Faulted, service.State);
        TotpAccount retained = Assert.Single(service.Accounts);
        Assert.Equal(active.Id, retained.Id);
        Assert.Equal(expectedSecret, retained.Secret.ToArray());

        store.FailSaves = false;
        await service.UnlockAsync(TestContext.Current.CancellationToken);
        Assert.Equal(VaultState.Unlocked, service.State);
        Assert.Equal(active.Id, Assert.Single(service.Accounts).Id);
    }

    [Fact]
    public async Task FailedReplaceImport_RollsBackAndLeavesImportedAccountWithCaller()
    {
        var store = new InMemoryVaultStore();
        using var service = new VaultService(store, new FixedClock(), new DuplicateDetector());
        await service.InitialiseAsync(unlock: true, TestContext.Current.CancellationToken);
        await service.AddAsync(CreateAccount("existing"), TestContext.Current.CancellationToken);
        Guid existingId = Assert.Single(service.Accounts).Id;
        using TotpAccount imported = CreateAccount("imported", 7);
        byte[] importedSecret = imported.Secret.ToArray();
        store.FailSaves = true;

        await Assert.ThrowsAsync<IOException>(
            () => service.ImportAsync(
                [imported],
                BackupImportMode.Replace,
                TestContext.Current.CancellationToken));

        Assert.Equal(VaultState.Faulted, service.State);
        Assert.Equal(existingId, Assert.Single(service.Accounts).Id);
        Assert.Equal(importedSecret, imported.Secret.ToArray());
    }

    [Fact]
    public async Task ReplaceImport_PreservesIntentionalDuplicatesFromBackup()
    {
        var store = new InMemoryVaultStore();
        using var service = new VaultService(store, new FixedClock(), new DuplicateDetector());
        await service.InitialiseAsync(unlock: true, TestContext.Current.CancellationToken);
        using TotpAccount first = CreateAccount("same");
        using TotpAccount second = CreateAccount("same");

        await service.ImportAsync(
            [first, second],
            BackupImportMode.Replace,
            TestContext.Current.CancellationToken);

        Assert.Equal(2, service.Accounts.Count);
    }

    [Fact]
    public async Task MergeReplaceDuplicates_ReplacesTheMatchingAccount()
    {
        var store = new InMemoryVaultStore();
        using var service = new VaultService(store, new FixedClock(), new DuplicateDetector());
        await service.InitialiseAsync(unlock: true, TestContext.Current.CancellationToken);
        await service.AddAsync(CreateAccount("same"), TestContext.Current.CancellationToken);
        Guid originalId = Assert.Single(service.Accounts).Id;
        using TotpAccount imported = CreateAccount("same");

        await service.ImportAsync(
            [imported],
            BackupImportMode.MergeReplaceDuplicates,
            TestContext.Current.CancellationToken);

        TotpAccount replacement = Assert.Single(service.Accounts);
        Assert.NotEqual(originalId, replacement.Id);
        Assert.Equal(imported.Id, replacement.Id);
    }

    [Fact]
    public async Task MergeAddDuplicates_PreservesBothAccounts()
    {
        var store = new InMemoryVaultStore();
        using var service = new VaultService(store, new FixedClock(), new DuplicateDetector());
        await service.InitialiseAsync(unlock: true, TestContext.Current.CancellationToken);
        await service.AddAsync(CreateAccount("same"), TestContext.Current.CancellationToken);
        using TotpAccount imported = CreateAccount("same");

        await service.ImportAsync(
            [imported],
            BackupImportMode.MergeAddDuplicates,
            TestContext.Current.CancellationToken);

        Assert.Equal(2, service.Accounts.Count);
    }

    [Fact]
    public async Task MergeImport_IdCollision_PreservesExistingAccount()
    {
        var store = new InMemoryVaultStore();
        using var service = new VaultService(store, new FixedClock(), new DuplicateDetector());
        await service.InitialiseAsync(unlock: true, TestContext.Current.CancellationToken);
        Guid sharedId = Guid.NewGuid();
        await service.AddAsync(
            CreateAccount("existing", discriminator: 0, sharedId),
            TestContext.Current.CancellationToken);
        using TotpAccount imported = CreateAccount("imported", discriminator: 10, sharedId);

        await service.ImportAsync(
            [imported],
            BackupImportMode.Merge,
            TestContext.Current.CancellationToken);

        TotpAccount retained = Assert.Single(service.Accounts);
        Assert.Equal(sharedId, retained.Id);
        Assert.Equal("existing", retained.AccountName);
    }

    [Fact]
    public async Task MergeReplaceImport_IdCollision_ReplacesThatIdentity()
    {
        var store = new InMemoryVaultStore();
        using var service = new VaultService(store, new FixedClock(), new DuplicateDetector());
        await service.InitialiseAsync(unlock: true, TestContext.Current.CancellationToken);
        Guid sharedId = Guid.NewGuid();
        await service.AddAsync(
            CreateAccount("existing", discriminator: 0, sharedId),
            TestContext.Current.CancellationToken);
        using TotpAccount imported = CreateAccount("imported", discriminator: 10, sharedId);

        await service.ImportAsync(
            [imported],
            BackupImportMode.MergeReplaceDuplicates,
            TestContext.Current.CancellationToken);

        TotpAccount replacement = Assert.Single(service.Accounts);
        Assert.Equal(sharedId, replacement.Id);
        Assert.Equal("imported", replacement.AccountName);
    }

    [Fact]
    public async Task MergeAddImport_IdCollision_PreservesBothWithUniqueIds()
    {
        var store = new InMemoryVaultStore();
        using var service = new VaultService(store, new FixedClock(), new DuplicateDetector());
        await service.InitialiseAsync(unlock: true, TestContext.Current.CancellationToken);
        Guid sharedId = Guid.NewGuid();
        await service.AddAsync(
            CreateAccount("existing", discriminator: 0, sharedId),
            TestContext.Current.CancellationToken);
        using TotpAccount imported = CreateAccount("imported", discriminator: 10, sharedId);

        await service.ImportAsync(
            [imported],
            BackupImportMode.MergeAddDuplicates,
            TestContext.Current.CancellationToken);

        Assert.Equal(2, service.Accounts.Count);
        Assert.Equal(2, service.Accounts.Select(account => account.Id).Distinct().Count());
        Assert.Contains(service.Accounts, account => account.Id == sharedId && account.AccountName == "existing");
        Assert.Contains(service.Accounts, account => account.Id != sharedId && account.AccountName == "imported");
    }

    [Fact]
    public async Task ReplaceImport_RepeatedId_PreservesEveryAccountWithUniqueIds()
    {
        var store = new InMemoryVaultStore();
        using var service = new VaultService(store, new FixedClock(), new DuplicateDetector());
        await service.InitialiseAsync(unlock: true, TestContext.Current.CancellationToken);
        Guid sharedId = Guid.NewGuid();
        using TotpAccount first = CreateAccount("first", discriminator: 1, sharedId);
        using TotpAccount second = CreateAccount("second", discriminator: 2, sharedId);

        await service.ImportAsync(
            [first, second],
            BackupImportMode.Replace,
            TestContext.Current.CancellationToken);

        Assert.Equal(2, service.Accounts.Count);
        Assert.Equal(2, service.Accounts.Select(account => account.Id).Distinct().Count());
        Assert.Contains(service.Accounts, account => account.Id == sharedId && account.AccountName == "first");
        Assert.Contains(service.Accounts, account => account.Id != sharedId && account.AccountName == "second");
    }

    private static TotpAccount CreateAccount(string name, byte discriminator = 0, Guid? id = null)
    {
        byte[] secret = Enumerable.Range(1, 20).Select(index => (byte)(index + discriminator)).ToArray();
        return new TotpAccount(id ?? Guid.NewGuid(), "Example", name, secret);
    }

    private sealed class FixedClock : IClock
    {
        public DateTimeOffset UtcNow { get; } = new(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
    }

    private sealed class InMemoryVaultStore : IVaultStore
    {
        private readonly List<TotpAccount> _stored = [];

        public string VaultPath => "memory";

        public bool FailSaves { get; set; }

        public Task<bool> ExistsAsync(CancellationToken cancellationToken) =>
            Task.FromResult(_stored.Count > 0);

        public Task<IReadOnlyList<TotpAccount>> LoadAsync(CancellationToken cancellationToken) =>
            Task.FromResult<IReadOnlyList<TotpAccount>>(_stored.Select(Clone).ToList());

        public Task SaveAsync(IReadOnlyCollection<TotpAccount> accounts, CancellationToken cancellationToken)
        {
            if (FailSaves)
            {
                throw new IOException("Simulated save failure.");
            }

            foreach (TotpAccount account in _stored)
            {
                account.Dispose();
            }

            _stored.Clear();
            _stored.AddRange(accounts.Select(Clone));
            return Task.CompletedTask;
        }

        private static TotpAccount Clone(TotpAccount account) =>
            new(
                account.Id,
                account.Issuer,
                account.AccountName,
                account.Secret,
                account.Algorithm,
                account.Digits,
                account.Period,
                account.Favourite,
                account.SortOrder,
                account.CreatedAtUtc,
                account.UpdatedAtUtc);
    }
}
