using System.Security.Cryptography;
using Microsoft.Data.Sqlite;
using PersonalAuthenticator.Core.Domain;
using PersonalAuthenticator.Core.Exceptions;
using PersonalAuthenticator.Infrastructure.Storage;
using PersonalAuthenticator.Infrastructure.Sync;

namespace PersonalAuthenticator.Infrastructure.Tests;

public sealed class Phase4LocalSyncTests : IDisposable
{
    private readonly string _directory =
        Path.Combine(Path.GetTempPath(), $"pa-sync-tests-{Guid.NewGuid():N}");

    [Fact]
    public void OperationSerializer_RoundTripsAndRejectsTampering()
    {
        using SyncOperation operation = CreateAccountOperation(
            Guid.NewGuid(),
            Guid.NewGuid(),
            Guid.NewGuid());
        byte[] bytes = SyncOperationSerializer.Serialize(operation);
        try
        {
            using SyncOperation reopened = SyncOperationSerializer.Deserialize(bytes);
            Assert.Equal(operation.Id, reopened.Id);
            Assert.Equal(operation.DeviceId, reopened.DeviceId);
            Assert.Equal(operation.AccountId, reopened.AccountId);

            byte[] truncated = bytes[..^1].ToArray();
            CryptographicOperations.ZeroMemory(bytes);
            bytes = truncated;
            SafeApplicationException exception =
                Assert.Throws<SafeApplicationException>(
                    () => SyncOperationSerializer.Deserialize(bytes));
            Assert.Equal("Sync.InvalidOperation", exception.ErrorCode);

            CryptographicOperations.ZeroMemory(bytes);
            bytes = SyncOperationSerializer.Serialize(operation);
            System.Buffers.Binary.BinaryPrimitives.WriteInt32LittleEndian(
                bytes,
                99);
            SafeApplicationException unsupported =
                Assert.Throws<SafeApplicationException>(
                    () => SyncOperationSerializer.Deserialize(bytes));
            Assert.Equal(
                "Sync.UnsupportedRequiredFeature",
                unsupported.ErrorCode);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
        }
    }

    [Fact]
    public async Task LocalChange_CommitsOutboxAndImmutableOperationTogether()
    {
        string root = Path.Combine(_directory, "atomic-outbox");
        string databasePath = Path.Combine(root, "vault.db");
        using var keyProvider = new FixedRootKeyProvider();
        var store = new V2SqliteVaultStore(databasePath, keyProvider);
        (VaultAccountV2 account, SecretVersionV2 secret) =
            CreateAccount("Atomic", "alice", 18);
        using (secret)
        {
            await store.SaveAsync(
                [account],
                [secret],
                TestContext.Current.CancellationToken);
        }

        Assert.Equal(
            1,
            await store.GetOutboxCountAsync(
                TestContext.Current.CancellationToken));
        using (V2VaultSnapshot snapshot =
               await store.LoadAsync(TestContext.Current.CancellationToken))
        {
            Assert.Single(snapshot.Accounts);
        }

        string connectionString = new SqliteConnectionStringBuilder
        {
            DataSource = databasePath,
            Pooling = false,
        }.ToString();
        await using var connection = new SqliteConnection(connectionString);
        await connection.OpenAsync(TestContext.Current.CancellationToken);
        await using SqliteCommand command = connection.CreateCommand();
        command.CommandText =
            "UPDATE sync_operations SET logical_clock = logical_clock + 1;";
        SqliteException exception = await Assert.ThrowsAsync<SqliteException>(
            () => command.ExecuteNonQueryAsync(
                TestContext.Current.CancellationToken));
        Assert.Contains("immutable", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ManifestAndDpapiConfig_AuthenticateWithoutStoringPassword()
    {
        string folder = Path.Combine(_directory, "manifest-folder");
        string configPath = Path.Combine(_directory, "manifest-config.dat");
        const string password = "correct horse battery staple";
        using LocalFolderSyncConfig created =
            await LocalFolderSyncManifest.OpenOrCreateAsync(
                folder,
                password.AsMemory(),
                memoryKiB: 8192,
                iterations: 1,
                parallelism: 1,
                TestContext.Current.CancellationToken);
        using LocalFolderSyncConfig reopened =
            await LocalFolderSyncManifest.OpenOrCreateAsync(
                folder,
                password.AsMemory(),
                memoryKiB: 8192,
                iterations: 1,
                parallelism: 1,
                TestContext.Current.CancellationToken);
        Assert.Equal(created.RepositoryId, reopened.RepositoryId);
        Assert.Equal(created.GenerationId, reopened.GenerationId);
        Assert.Equal(created.SyncKey, reopened.SyncKey);
        SafeApplicationException wrongPassword =
            await Assert.ThrowsAsync<SafeApplicationException>(
                () => LocalFolderSyncManifest.OpenOrCreateAsync(
                    folder,
                    "this password is incorrect".AsMemory(),
                    memoryKiB: 8192,
                    iterations: 1,
                    parallelism: 1,
                    TestContext.Current.CancellationToken));
        Assert.Equal("Sync.AuthenticationFailed", wrongPassword.ErrorCode);

        var configStore = new LocalFolderSyncConfigStore(configPath);
        await configStore.SaveAsync(created, TestContext.Current.CancellationToken);
        using LocalFolderSyncConfig loaded =
            await configStore.LoadAsync(TestContext.Current.CancellationToken);
        Assert.Equal(created.FolderPath, loaded.FolderPath);
        Assert.Equal(created.SyncKey, loaded.SyncKey);
        byte[] manifestBytes = await File.ReadAllBytesAsync(
            Path.Combine(folder, "PersonalAuthenticator.sync"),
            TestContext.Current.CancellationToken);
        byte[] configBytes = await File.ReadAllBytesAsync(
            configPath,
            TestContext.Current.CancellationToken);
        byte[] passwordBytes = System.Text.Encoding.UTF8.GetBytes(password);
        try
        {
            Assert.True(manifestBytes.AsSpan().IndexOf(passwordBytes) < 0);
            Assert.True(configBytes.AsSpan().IndexOf(passwordBytes) < 0);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(manifestBytes);
            CryptographicOperations.ZeroMemory(configBytes);
            CryptographicOperations.ZeroMemory(passwordBytes);
        }
    }

    [Fact]
    public async Task TwoDevices_OfflineDifferentFields_MergeDeterministically()
    {
        await using SyncPair pair = await SyncPair.CreateAsync(_directory);
        (VaultAccountV2 account, SecretVersionV2 secret) =
            CreateAccount("Example", "alice", 1);
        using (secret)
        {
            await pair.A.SaveAsync(
                [account],
                [secret],
                TestContext.Current.CancellationToken);
        }

        await pair.SynchronizeAsync();

        using V2VaultSnapshot aBefore =
            await pair.A.LoadAsync(TestContext.Current.CancellationToken);
        using V2VaultSnapshot bBefore =
            await pair.B.LoadAsync(TestContext.Current.CancellationToken);
        VaultAccountV2 aChanged = CloneAccount(
            aBefore.Accounts.Single(),
            issuer: "Example A");
        VaultAccountV2 bChanged = CloneAccount(
            bBefore.Accounts.Single(),
            favourite: true);
        await pair.A.SaveAsync(
            [aChanged],
            aBefore.SecretVersions,
            TestContext.Current.CancellationToken);
        await pair.B.SaveAsync(
            [bChanged],
            bBefore.SecretVersions,
            TestContext.Current.CancellationToken);

        await pair.SynchronizeAsync(reverseDownloadOrder: true);
        await pair.SynchronizeAsync();

        using V2VaultSnapshot aAfter =
            await pair.A.LoadAsync(TestContext.Current.CancellationToken);
        using V2VaultSnapshot bAfter =
            await pair.B.LoadAsync(TestContext.Current.CancellationToken);
        Assert.Equal("Example A", aAfter.Accounts.Single().Issuer);
        Assert.True(aAfter.Accounts.Single().Favourite);
        Assert.Equal("Example A", bAfter.Accounts.Single().Issuer);
        Assert.True(bAfter.Accounts.Single().Favourite);
        Assert.Empty(await pair.A.GetUnresolvedConflictsAsync(
            TestContext.Current.CancellationToken));
        Assert.Empty(await pair.B.GetUnresolvedConflictsAsync(
            TestContext.Current.CancellationToken));

        await pair.B.RebuildStateFromOperationsAsync(
            TestContext.Current.CancellationToken);
        using V2VaultSnapshot rebuilt =
            await pair.B.LoadAsync(TestContext.Current.CancellationToken);
        Assert.Equal("Example A", rebuilt.Accounts.Single().Issuer);
        Assert.True(rebuilt.Accounts.Single().Favourite);
    }

    [Fact]
    public async Task ConcurrentIdenticalImports_CollapseToOneAccount()
    {
        await using SyncPair pair = await SyncPair.CreateAsync(
            Path.Combine(_directory, "duplicates"));
        (VaultAccountV2 accountA, SecretVersionV2 secretA) =
            CreateAccount("Example", "alice", 7);
        (VaultAccountV2 accountB, SecretVersionV2 secretB) =
            CreateAccount("example", "ALICE", 7);
        using (secretA)
        using (secretB)
        {
            await pair.A.SaveAsync(
                [accountA],
                [secretA],
                TestContext.Current.CancellationToken);
            await pair.B.SaveAsync(
                [accountB],
                [secretB],
                TestContext.Current.CancellationToken);
        }

        await pair.SynchronizeAsync();
        await pair.SynchronizeAsync();
        using V2VaultSnapshot snapshot =
            await pair.A.LoadAsync(TestContext.Current.CancellationToken);
        Assert.Single(snapshot.Accounts);
        Assert.Single(snapshot.SecretVersions);
        Assert.Empty(await pair.A.GetUnresolvedConflictsAsync(
            TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task ConcurrentSameField_CreatesConflict_AndKeepBIsApplied()
    {
        await using SyncPair pair = await SyncPair.CreateAsync(
            Path.Combine(_directory, "metadata-conflict"));
        (VaultAccountV2 account, SecretVersionV2 secret) =
            CreateAccount("Example", "alice", 8);
        using (secret)
        {
            await pair.A.SaveAsync(
                [account],
                [secret],
                TestContext.Current.CancellationToken);
        }

        await pair.SynchronizeAsync();
        using V2VaultSnapshot aBefore =
            await pair.A.LoadAsync(TestContext.Current.CancellationToken);
        using V2VaultSnapshot bBefore =
            await pair.B.LoadAsync(TestContext.Current.CancellationToken);
        await pair.A.SaveAsync(
            [CloneAccount(aBefore.Accounts.Single(), issuer: "Issuer A")],
            aBefore.SecretVersions,
            TestContext.Current.CancellationToken);
        await pair.B.SaveAsync(
            [CloneAccount(bBefore.Accounts.Single(), issuer: "Issuer B")],
            bBefore.SecretVersions,
            TestContext.Current.CancellationToken);
        Dictionary<Guid, string?> values = [];
        await AddOutboxTextValuesAsync(pair.A, values);
        await AddOutboxTextValuesAsync(pair.B, values);

        await pair.SynchronizeAsync();
        SyncConflictSummary conflict = Assert.Single(
            await pair.A.GetUnresolvedConflictsAsync(
                TestContext.Current.CancellationToken));
        Assert.Equal(SyncConflictKind.Metadata, conflict.Kind);
        await pair.A.QueueConflictResolutionAsync(
            conflict.Id,
            SyncConflictResolution.KeepB,
            TestContext.Current.CancellationToken);
        using V2VaultSnapshot resolved =
            await pair.A.LoadAsync(TestContext.Current.CancellationToken);
        Assert.Equal(values[conflict.OperationBId], resolved.Accounts.Single().Issuer);
    }

    [Fact]
    public async Task ArchiveAndUnrelatedMetadata_MergeWithoutConflict()
    {
        await using SyncPair pair = await SyncPair.CreateAsync(
            Path.Combine(_directory, "archive-metadata"));
        (VaultAccountV2 account, SecretVersionV2 secret) =
            CreateAccount("Example", "alice", 9);
        using (secret)
        {
            await pair.A.SaveAsync(
                [account],
                [secret],
                TestContext.Current.CancellationToken);
        }

        await pair.SynchronizeAsync();
        using V2VaultSnapshot aBefore =
            await pair.A.LoadAsync(TestContext.Current.CancellationToken);
        using V2VaultSnapshot bBefore =
            await pair.B.LoadAsync(TestContext.Current.CancellationToken);
        DateTimeOffset archivedAt = DateTimeOffset.UtcNow.AddSeconds(3);
        await pair.A.SaveAsync(
            [CloneAccount(aBefore.Accounts.Single(), archivedAtUtc: archivedAt)],
            aBefore.SecretVersions,
            TestContext.Current.CancellationToken);
        await pair.B.SaveAsync(
            [CloneAccount(bBefore.Accounts.Single(), accountName: "alice renamed")],
            bBefore.SecretVersions,
            TestContext.Current.CancellationToken);

        await pair.SynchronizeAsync();
        using V2VaultSnapshot merged =
            await pair.A.LoadAsync(TestContext.Current.CancellationToken);
        Assert.Equal("alice renamed", merged.Accounts.Single().AccountName);
        Assert.Equal(archivedAt, merged.Accounts.Single().ArchivedAtUtc);
        Assert.Empty(await pair.A.GetUnresolvedConflictsAsync(
            TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task RestoreConcurrentWithPurge_CreatesConflictBeforeDataRemoval()
    {
        await using SyncPair pair = await SyncPair.CreateAsync(
            Path.Combine(_directory, "restore-purge"));
        (VaultAccountV2 account, SecretVersionV2 secret) =
            CreateAccount("Example", "alice", 10);
        VaultAccountV2 archived = CloneAccount(
            account,
            archivedAtUtc: DateTimeOffset.UtcNow.AddSeconds(1));
        using (secret)
        {
            await pair.A.SaveAsync(
                [archived],
                [secret],
                TestContext.Current.CancellationToken);
        }

        await pair.SynchronizeAsync();
        using V2VaultSnapshot bBefore =
            await pair.B.LoadAsync(TestContext.Current.CancellationToken);
        await pair.A.SaveAsync(
            [],
            [],
            TestContext.Current.CancellationToken);
        await pair.B.SaveAsync(
            [CloneAccount(bBefore.Accounts.Single(), archivedAtUtc: null)],
            bBefore.SecretVersions,
            TestContext.Current.CancellationToken);

        await pair.SynchronizeAsync();
        SyncConflictSummary conflict = Assert.Single(
            await pair.A.GetUnresolvedConflictsAsync(
                TestContext.Current.CancellationToken));
        Assert.Equal(SyncConflictKind.RestoreVersusPurge, conflict.Kind);
        using V2VaultSnapshot preserved =
            await pair.A.LoadAsync(TestContext.Current.CancellationToken);
        Assert.Single(preserved.Accounts);
        Assert.Single(preserved.SecretVersions);
    }

    [Fact]
    public async Task ConcurrentActiveSecretChoices_CreateConflictWithoutDeletingVersions()
    {
        await using SyncPair pair = await SyncPair.CreateAsync(
            Path.Combine(_directory, "active-secret"));
        (VaultAccountV2 account, SecretVersionV2 initial) =
            CreateAccount("Example", "alice", 13);
        using (initial)
        {
            await pair.A.SaveAsync(
                [account],
                [initial],
                TestContext.Current.CancellationToken);
        }

        await pair.SynchronizeAsync();
        using (V2VaultSnapshot first =
               await pair.A.LoadAsync(TestContext.Current.CancellationToken))
        using (SecretVersionV2 candidateA = CreateCandidate(
                   account.Id,
                   41,
                   DateTimeOffset.UtcNow.AddSeconds(1)))
        {
            await pair.A.SaveAsync(
                first.Accounts,
                [.. first.SecretVersions, candidateA],
                TestContext.Current.CancellationToken);
        }

        await pair.SynchronizeAsync();
        using (V2VaultSnapshot second =
               await pair.A.LoadAsync(TestContext.Current.CancellationToken))
        using (SecretVersionV2 candidateB = CreateCandidate(
                   account.Id,
                   71,
                   DateTimeOffset.UtcNow.AddSeconds(2)))
        {
            await pair.A.SaveAsync(
                second.Accounts,
                [.. second.SecretVersions, candidateB],
                TestContext.Current.CancellationToken);
        }

        await pair.SynchronizeAsync();
        using V2VaultSnapshot aBefore =
            await pair.A.LoadAsync(TestContext.Current.CancellationToken);
        using V2VaultSnapshot bBefore =
            await pair.B.LoadAsync(TestContext.Current.CancellationToken);
        Guid candidateAId = aBefore.SecretVersions
            .Single(item => item.Secret[0] == 41)
            .Id;
        Guid candidateBId = aBefore.SecretVersions
            .Single(item => item.Secret[0] == 71)
            .Id;
        List<SecretVersionV2> aSelected = SelectActive(aBefore, candidateAId);
        List<SecretVersionV2> bSelected = SelectActive(bBefore, candidateBId);
        try
        {
            await pair.A.SaveAsync(
                [CloneAccountWithActive(aBefore.Accounts.Single(), candidateAId)],
                aSelected,
                TestContext.Current.CancellationToken);
            await pair.B.SaveAsync(
                [CloneAccountWithActive(bBefore.Accounts.Single(), candidateBId)],
                bSelected,
                TestContext.Current.CancellationToken);
        }
        finally
        {
            DisposeVersions(aSelected);
            DisposeVersions(bSelected);
        }

        await pair.SynchronizeAsync();
        SyncConflictSummary conflict = Assert.Single(
            await pair.A.GetUnresolvedConflictsAsync(
                TestContext.Current.CancellationToken));
        Assert.Equal(SyncConflictKind.ActiveSecret, conflict.Kind);
        using V2VaultSnapshot conflicted =
            await pair.A.LoadAsync(TestContext.Current.CancellationToken);
        Assert.Equal(3, conflicted.SecretVersions.Count);
    }

    [Fact]
    public async Task IncompatibleDuplicateDecisions_CreateConflict()
    {
        await using SyncPair pair = await SyncPair.CreateAsync(
            Path.Combine(_directory, "duplicate-decisions"));
        (VaultAccountV2 firstAccount, SecretVersionV2 firstSecret) =
            CreateAccount("Example", "alice", 15);
        (VaultAccountV2 secondAccount, SecretVersionV2 secondSecret) =
            CreateAccount("Example", "alice-alt-a", 16);
        (VaultAccountV2 thirdAccount, SecretVersionV2 thirdSecret) =
            CreateAccount("Example", "alice-alt-b", 17);
        using (firstSecret)
        using (secondSecret)
        using (thirdSecret)
        {
            await pair.A.SaveAsync(
                [firstAccount, secondAccount, thirdAccount],
                [firstSecret, secondSecret, thirdSecret],
                TestContext.Current.CancellationToken);
        }

        await pair.SynchronizeAsync();
        using V2VaultSnapshot aBefore =
            await pair.A.LoadAsync(TestContext.Current.CancellationToken);
        using V2VaultSnapshot bBefore =
            await pair.B.LoadAsync(TestContext.Current.CancellationToken);
        var decisionA = new AccountHistoryEntryV2(
            Guid.NewGuid(),
            firstAccount.Id,
            AccountHistoryAction.DuplicateAddedSeparately,
            DateTimeOffset.UtcNow.AddSeconds(3),
            relatedAccountId: secondAccount.Id);
        var decisionB = new AccountHistoryEntryV2(
            Guid.NewGuid(),
            firstAccount.Id,
            AccountHistoryAction.DuplicateAddedSeparately,
            DateTimeOffset.UtcNow.AddSeconds(3),
            relatedAccountId: thirdAccount.Id);
        await pair.A.SaveAsync(
            aBefore.Accounts,
            aBefore.SecretVersions,
            [.. aBefore.HistoryEntries, decisionA],
            TestContext.Current.CancellationToken);
        await pair.B.SaveAsync(
            bBefore.Accounts,
            bBefore.SecretVersions,
            [.. bBefore.HistoryEntries, decisionB],
            TestContext.Current.CancellationToken);

        await pair.SynchronizeAsync();
        SyncConflictSummary conflict = Assert.Single(
            await pair.A.GetUnresolvedConflictsAsync(
                TestContext.Current.CancellationToken));
        Assert.Equal(SyncConflictKind.DuplicateDecision, conflict.Kind);
    }

    [Theory]
    [InlineData(SyncConflictResolution.KeepA)]
    [InlineData(SyncConflictResolution.KeepB)]
    [InlineData(SyncConflictResolution.KeepBoth)]
    [InlineData(SyncConflictResolution.SeparateAccounts)]
    public async Task SecretConflict_PreservesVersions_AndSupportsEveryResolution(
        SyncConflictResolution resolution)
    {
        string root = Path.Combine(_directory, "secret-" + resolution);
        await using SyncPair pair = await SyncPair.CreateAsync(root);
        (VaultAccountV2 account, SecretVersionV2 secret) =
            CreateAccount("Example", "alice", 2);
        using (secret)
        {
            await pair.A.SaveAsync(
                [account],
                [secret],
                TestContext.Current.CancellationToken);
        }

        await pair.SynchronizeAsync();
        using V2VaultSnapshot aBefore =
            await pair.A.LoadAsync(TestContext.Current.CancellationToken);
        using V2VaultSnapshot bBefore =
            await pair.B.LoadAsync(TestContext.Current.CancellationToken);
        using SecretVersionV2 candidateA = CreateCandidate(
            account.Id,
            31,
            DateTimeOffset.UtcNow.AddSeconds(1));
        using SecretVersionV2 candidateB = CreateCandidate(
            account.Id,
            61,
            DateTimeOffset.UtcNow.AddSeconds(1));
        await pair.A.SaveAsync(
            aBefore.Accounts,
            [.. aBefore.SecretVersions, candidateA],
            TestContext.Current.CancellationToken);
        await pair.B.SaveAsync(
            bBefore.Accounts,
            [.. bBefore.SecretVersions, candidateB],
            TestContext.Current.CancellationToken);

        await pair.SynchronizeAsync();
        IReadOnlyList<SyncConflictSummary> conflicts =
            await pair.A.GetUnresolvedConflictsAsync(
                TestContext.Current.CancellationToken);
        SyncConflictSummary conflict = Assert.Single(conflicts);
        Assert.Equal(SyncConflictKind.SecretAdded, conflict.Kind);
        using (V2VaultSnapshot conflicted =
               await pair.A.LoadAsync(TestContext.Current.CancellationToken))
        {
            Assert.Equal(3, conflicted.SecretVersions.Count);
            Assert.Contains(
                conflicted.SecretVersions,
                item => item.Id == candidateA.Id);
            Assert.Contains(
                conflicted.SecretVersions,
                item => item.Id == candidateB.Id);
        }

        await pair.A.QueueConflictResolutionAsync(
            conflict.Id,
            resolution,
            TestContext.Current.CancellationToken);
        Assert.Empty(await pair.A.GetUnresolvedConflictsAsync(
            TestContext.Current.CancellationToken));
        using V2VaultSnapshot resolved =
            await pair.A.LoadAsync(TestContext.Current.CancellationToken);
        Assert.True(resolved.SecretVersions.Count >= 3);
        Assert.Equal(
            resolution == SyncConflictResolution.SeparateAccounts ? 2 : 1,
            resolved.Accounts.Count);
    }

    [Fact]
    public async Task OutOfOrderOperation_WaitsForMissingParent_ThenAppliesAndRebuilds()
    {
        string deviceRoot = Path.Combine(_directory, "causal");
        using var keyProvider = new FixedRootKeyProvider();
        var store = new V2SqliteVaultStore(
            Path.Combine(deviceRoot, "vault.db"),
            keyProvider);
        await store.SaveAsync(
            [],
            [],
            TestContext.Current.CancellationToken);
        Guid parentId = Guid.NewGuid();
        Guid deviceId = Guid.NewGuid();
        Guid accountId = Guid.NewGuid();
        using SyncOperation parent = CreateAccountOperation(
            parentId,
            deviceId,
            accountId);
        using var child = new SyncOperation(
            Guid.NewGuid(),
            deviceId,
            2,
            2,
            DateTimeOffset.UtcNow.AddSeconds(1),
            accountId,
            SyncOperationKind.IssuerChanged,
            SyncFieldKeys.Issuer,
            [parentId],
            new SyncOperationPayload { TextValue = "Changed after parent" });

        await store.ApplyRemoteOperationsAsync(
            [child],
            TestContext.Current.CancellationToken);
        Assert.Equal(
            1,
            await store.GetPendingApplicationCountAsync(
                TestContext.Current.CancellationToken));
        using (V2VaultSnapshot pending =
               await store.LoadAsync(TestContext.Current.CancellationToken))
        {
            Assert.Empty(pending.Accounts);
        }

        await store.ApplyRemoteOperationsAsync(
            [parent],
            TestContext.Current.CancellationToken);
        Assert.Equal(
            0,
            await store.GetPendingApplicationCountAsync(
                TestContext.Current.CancellationToken));
        using (V2VaultSnapshot applied =
               await store.LoadAsync(TestContext.Current.CancellationToken))
        {
            Assert.Equal("Changed after parent", applied.Accounts.Single().Issuer);
        }

        await store.RebuildStateFromOperationsAsync(
            TestContext.Current.CancellationToken);
        using V2VaultSnapshot rebuilt =
            await store.LoadAsync(TestContext.Current.CancellationToken);
        Assert.Equal("Changed after parent", rebuilt.Accounts.Single().Issuer);
    }

    [Fact]
    public async Task CorruptObject_IsQuarantined_AndUploadInterruptionLeavesOutbox()
    {
        string root = Path.Combine(_directory, "faults");
        string deviceRoot = Path.Combine(root, "device");
        string folder = Path.Combine(root, "folder");
        Directory.CreateDirectory(folder);
        using var keyProvider = new FixedRootKeyProvider();
        var store = new V2SqliteVaultStore(
            Path.Combine(deviceRoot, "vault.db"),
            keyProvider);
        (VaultAccountV2 account, SecretVersionV2 secret) =
            CreateAccount("Fault", "alice", 4);
        using (secret)
        {
            await store.SaveAsync(
                [account],
                [secret],
                TestContext.Current.CancellationToken);
        }

        using var config = new LocalFolderSyncConfig(
            folder,
            Guid.NewGuid(),
            Guid.NewGuid(),
            RandomNumberGenerator.GetBytes(32),
            null);
        IReadOnlyList<SyncOperation> outbox =
            await store.LoadOutboxAsync(TestContext.Current.CancellationToken);
        try
        {
            var interruptedStore = new LocalFolderSyncObjectStore(checkpoint =>
            {
                if (checkpoint == LocalSyncCheckpoint.BeforeObjectWrite)
                {
                    throw new IOException("Simulated disk-full interruption.");
                }
            });
            await Assert.ThrowsAsync<IOException>(
                () => interruptedStore.UploadAsync(
                    config,
                    outbox.Single(),
                    TestContext.Current.CancellationToken));
            Assert.Equal(
                1,
                await store.GetOutboxCountAsync(
                    TestContext.Current.CancellationToken));

            var objectStore = new LocalFolderSyncObjectStore();
            await objectStore.UploadAsync(
                config,
                outbox.Single(),
                TestContext.Current.CancellationToken);
            string id = outbox.Single().Id.ToString("N");
            string path = Path.Combine(folder, "objects", id[..2], id + ".pao");
            byte[] bytes = await File.ReadAllBytesAsync(
                path,
                TestContext.Current.CancellationToken);
            try
            {
                bytes[^1] ^= 0x80;
                await File.WriteAllBytesAsync(
                    path,
                    bytes,
                    TestContext.Current.CancellationToken);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(bytes);
            }

            using LocalFolderDownloadResult result =
                await objectStore.DownloadAsync(
                    config,
                    TestContext.Current.CancellationToken);
            Assert.Empty(result.Operations);
            Assert.Equal(1, result.QuarantinedObjectCount);
            Assert.Single(Directory.GetFiles(
                Path.Combine(folder, "quarantine"),
                "*.bad"));
        }
        finally
        {
            foreach (SyncOperation operation in outbox)
            {
                operation.Dispose();
            }
        }
    }

    public void Dispose()
    {
        if (Directory.Exists(_directory))
        {
            Directory.Delete(_directory, recursive: true);
        }
    }

    private static SyncOperation CreateAccountOperation(
        Guid operationId,
        Guid deviceId,
        Guid accountId)
    {
        (VaultAccountV2 account, SecretVersionV2 secret) =
            CreateAccount("Example", "alice", 12, accountId);
        return new SyncOperation(
            operationId,
            deviceId,
            1,
            1,
            DateTimeOffset.UtcNow,
            account.Id,
            SyncOperationKind.AccountAdded,
            SyncFieldKeys.Existence,
            [],
            new SyncOperationPayload
            {
                Account = account,
                SecretVersion = secret,
            });
    }

    private static (VaultAccountV2 Account, SecretVersionV2 Secret) CreateAccount(
        string issuer,
        string accountName,
        int discriminator,
        Guid? accountId = null)
    {
        Guid id = accountId ?? Guid.NewGuid();
        Guid versionId = Guid.NewGuid();
        var account = new VaultAccountV2(
            id,
            issuer,
            accountName,
            versionId,
            createdAtUtc: DateTimeOffset.UtcNow,
            updatedAtUtc: DateTimeOffset.UtcNow);
        var secret = new SecretVersionV2(
            versionId,
            id,
            Enumerable.Range(discriminator, 20).Select(value => (byte)value).ToArray(),
            TotpAlgorithm.Sha1,
            6,
            30,
            $"otpauth://totp/{Uri.EscapeDataString(issuer + ":" + accountName)}" +
            $"?secret=AEBAGBAFAYDQQCIKBMGA2DQPCAIREEYU&issuer={Uri.EscapeDataString(issuer)}",
            ProvisioningUriOrigin.CanonicalGenerated);
        return (account, secret);
    }

    private static SecretVersionV2 CreateCandidate(
        Guid accountId,
        int discriminator,
        DateTimeOffset createdAtUtc) =>
        new(
            Guid.NewGuid(),
            accountId,
            Enumerable.Range(discriminator, 20).Select(value => (byte)value).ToArray(),
            TotpAlgorithm.Sha1,
            6,
            30,
            $"otpauth://totp/Example%3Aalice?secret=AEBAGBAFAYDQQCIKBMGA2DQPCAIREEYU&v={discriminator}",
            ProvisioningUriOrigin.CanonicalGenerated,
            SecretVersionState.Candidate,
            createdAtUtc);

    private static VaultAccountV2 CloneAccount(
        VaultAccountV2 account,
        string? issuer = null,
        string? accountName = null,
        bool? favourite = null,
        DateTimeOffset? archivedAtUtc = null) =>
        new(
            account.Id,
            issuer ?? account.Issuer,
            accountName ?? account.AccountName,
            account.ActiveSecretVersionId,
            favourite ?? account.Favourite,
            account.SortOrder,
            account.CreatedAtUtc,
            DateTimeOffset.UtcNow.AddSeconds(2),
            archivedAtUtc);

    private static VaultAccountV2 CloneAccountWithActive(
        VaultAccountV2 account,
        Guid activeSecretVersionId) =>
        new(
            account.Id,
            account.Issuer,
            account.AccountName,
            activeSecretVersionId,
            account.Favourite,
            account.SortOrder,
            account.CreatedAtUtc,
            DateTimeOffset.UtcNow.AddSeconds(4),
            account.ArchivedAtUtc);

    private static List<SecretVersionV2> SelectActive(
        V2VaultSnapshot snapshot,
        Guid selectedId)
    {
        DateTimeOffset now = DateTimeOffset.UtcNow.AddSeconds(4);
        return snapshot.SecretVersions.Select(version =>
        {
            SecretVersionState state = version.Id == selectedId
                ? SecretVersionState.Active
                : version.State == SecretVersionState.Active
                    ? SecretVersionState.Retired
                    : SecretVersionState.Candidate;
            return new SecretVersionV2(
                version.Id,
                version.AccountId,
                version.Secret,
                version.Algorithm,
                version.Digits,
                version.Period,
                version.ProvisioningUri,
                version.ProvisioningUriOrigin,
                state,
                version.CreatedAtUtc,
                state == SecretVersionState.Retired ? now : null);
        }).ToList();
    }

    private static void DisposeVersions(IEnumerable<SecretVersionV2> versions)
    {
        foreach (SecretVersionV2 version in versions)
        {
            version.Dispose();
        }
    }

    private static async Task AddOutboxTextValuesAsync(
        V2SqliteVaultStore store,
        Dictionary<Guid, string?> values)
    {
        IReadOnlyList<SyncOperation> operations =
            await store.LoadOutboxAsync(TestContext.Current.CancellationToken);
        try
        {
            foreach (SyncOperation operation in operations)
            {
                values[operation.Id] = operation.Payload.TextValue;
            }
        }
        finally
        {
            foreach (SyncOperation operation in operations)
            {
                operation.Dispose();
            }
        }
    }

    private sealed class FixedRootKeyProvider : IVaultRootKeyProvider, IDisposable
    {
        private readonly byte[] _key =
            RandomNumberGenerator.GetBytes(V2RecordCryptography.KeyLength);

        public bool Exists { get; private set; }

        public Task<byte[]> LoadAsync(CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return Exists
                ? Task.FromResult(_key.ToArray())
                : throw new FileNotFoundException();
        }

        public Task<byte[]> LoadOrCreateAsync(CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Exists = true;
            return Task.FromResult(_key.ToArray());
        }

        public void Dispose() => CryptographicOperations.ZeroMemory(_key);
    }

    private sealed class SyncPair : IAsyncDisposable
    {
        private readonly FixedRootKeyProvider _keyA;
        private readonly FixedRootKeyProvider _keyB;
        private readonly LocalFolderSyncObjectStore _objects = new();

        private SyncPair(
            V2SqliteVaultStore a,
            V2SqliteVaultStore b,
            FixedRootKeyProvider keyA,
            FixedRootKeyProvider keyB,
            LocalFolderSyncConfig config)
        {
            A = a;
            B = b;
            _keyA = keyA;
            _keyB = keyB;
            Config = config;
        }

        public V2SqliteVaultStore A { get; }

        public V2SqliteVaultStore B { get; }

        public LocalFolderSyncConfig Config { get; }

        public static async Task<SyncPair> CreateAsync(string root)
        {
            Directory.CreateDirectory(root);
            var keyA = new FixedRootKeyProvider();
            var keyB = new FixedRootKeyProvider();
            var a = new V2SqliteVaultStore(
                Path.Combine(root, "device-a", "vault.db"),
                keyA);
            var b = new V2SqliteVaultStore(
                Path.Combine(root, "device-b", "vault.db"),
                keyB);
            await a.SaveAsync([], [], TestContext.Current.CancellationToken);
            await b.SaveAsync([], [], TestContext.Current.CancellationToken);
            var config = new LocalFolderSyncConfig(
                Path.Combine(root, "shared"),
                Guid.NewGuid(),
                Guid.NewGuid(),
                RandomNumberGenerator.GetBytes(32),
                null);
            Directory.CreateDirectory(config.FolderPath);
            return new SyncPair(a, b, keyA, keyB, config);
        }

        public async Task SynchronizeAsync(bool reverseDownloadOrder = false)
        {
            await UploadOutboxAsync(A);
            await UploadOutboxAsync(B);
            if (reverseDownloadOrder)
            {
                await DownloadIntoAsync(B, reverse: true);
                await DownloadIntoAsync(A, reverse: true);
            }
            else
            {
                await DownloadIntoAsync(A, reverse: false);
                await DownloadIntoAsync(B, reverse: false);
            }
        }

        public async ValueTask DisposeAsync()
        {
            Config.Dispose();
            _keyA.Dispose();
            _keyB.Dispose();
            await Task.CompletedTask;
        }

        private async Task UploadOutboxAsync(V2SqliteVaultStore store)
        {
            IReadOnlyList<SyncOperation> outbox =
                await store.LoadOutboxAsync(TestContext.Current.CancellationToken);
            try
            {
                foreach (SyncOperation operation in outbox)
                {
                    await _objects.UploadAsync(
                        Config,
                        operation,
                        TestContext.Current.CancellationToken);
                }

                await store.MarkOutboxSentAsync(
                    outbox.Select(item => item.Id).ToArray(),
                    TestContext.Current.CancellationToken);
            }
            finally
            {
                foreach (SyncOperation operation in outbox)
                {
                    operation.Dispose();
                }
            }
        }

        private async Task DownloadIntoAsync(
            V2SqliteVaultStore store,
            bool reverse)
        {
            using LocalFolderDownloadResult result =
                await _objects.DownloadAsync(
                    Config,
                    TestContext.Current.CancellationToken);
            IReadOnlyCollection<SyncOperation> operations = reverse
                ? result.Operations.Reverse().ToArray()
                : result.Operations.ToArray();
            await store.ApplyRemoteOperationsAsync(
                operations,
                TestContext.Current.CancellationToken);
        }
    }
}
