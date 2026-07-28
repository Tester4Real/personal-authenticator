using System.Security.Cryptography;
using Microsoft.Extensions.Logging.Abstractions;
using PersonalAuthenticator.Core.Domain;
using PersonalAuthenticator.Core.Exceptions;
using PersonalAuthenticator.Infrastructure.GitHub;
using PersonalAuthenticator.Infrastructure.Storage;
using PersonalAuthenticator.Infrastructure.Sync;

namespace PersonalAuthenticator.Infrastructure.Tests;

public sealed class Phase5GitHubSyncTests : IDisposable
{
    private static string TestCredential => new('t', 32);

    private static string SyncPassword => new('p', 20);
    private readonly string _directory =
        Path.Combine(Path.GetTempPath(), $"pa-github-tests-{Guid.NewGuid():N}");

    [Fact]
    public async Task FirstConnection_UploadsAndVerifiesPrivateEncryptedObjects()
    {
        var remote = new FakeGitHubRemote();
        var factory = new FakeGitHubApiClientFactory(remote);
        using VersionedVaultStore store = CreateStore("first", factory);
        using TotpAccount account = CreateAccount("Example", "alice", 1);
        await store.SaveAsync([account], TestContext.Current.CancellationToken);

        await ConfigureAsync(store, "primary");
        GitHubSyncStatus status = await store.SyncGitHubNowAsync(
            TestContext.Current.CancellationToken);

        Assert.Equal(0, status.PendingOperationCount);
        Assert.NotNull(status.LastSuccessfulSyncAtUtc);
        Assert.Contains(
            remote.Files.Keys,
            path => path.EndsWith("/descriptor.json", StringComparison.Ordinal));
        Assert.Contains(
            remote.Files.Keys,
            path => path.EndsWith(".pao", StringComparison.Ordinal));
        byte[] allRemoteBytes = remote.Files.Values
            .SelectMany(file => file.Content)
            .ToArray();
        byte[] secret = account.Secret.ToArray();
        try
        {
            Assert.True(allRemoteBytes.AsSpan().IndexOf(secret) < 0);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(allRemoteBytes);
            CryptographicOperations.ZeroMemory(secret);
        }

        byte[] config = await File.ReadAllBytesAsync(
            Path.Combine(_directory, "first", "github-sync.dat"),
            TestContext.Current.CancellationToken);
        byte[] credential = System.Text.Encoding.UTF8.GetBytes(TestCredential);
        try
        {
            Assert.True(config.AsSpan().IndexOf(credential) < 0);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(config);
            CryptographicOperations.ZeroMemory(credential);
        }
    }

    [Fact]
    public async Task FirstConnection_InitializesEmptyRepositoryAndRequestedBranch()
    {
        var remote = new FakeGitHubRemote
        {
            DefaultBranch = "main",
        };
        remote.Branches.Clear();
        var factory = new FakeGitHubApiClientFactory(remote);
        using VersionedVaultStore store = CreateStore("empty-repository", factory);
        await store.SaveAsync([], TestContext.Current.CancellationToken);

        await ConfigureAsync(store, "empty");

        Assert.Equal(1, remote.InitializationCount);
        Assert.Contains("main", remote.Branches);
        Assert.Contains("sync", remote.Branches);
        Assert.Contains("sync", remote.CreatedBranches);
        Assert.Contains(
            remote.Files.Keys,
            path => path.EndsWith("/descriptor.json", StringComparison.Ordinal));
        GitHubSyncStatus status = await store.GetGitHubStatusAsync(
            TestContext.Current.CancellationToken);
        Assert.Equal("owner/empty@sync", status.Repository);
    }

    [Fact]
    public async Task TwoWindowsDevices_OfflineThenSync_Converge()
    {
        var remote = new FakeGitHubRemote();
        var factory = new FakeGitHubApiClientFactory(remote);
        using VersionedVaultStore first = CreateStore("device-a", factory);
        using VersionedVaultStore second = CreateStore("device-b", factory);
        await first.SaveAsync([], TestContext.Current.CancellationToken);
        await second.SaveAsync([], TestContext.Current.CancellationToken);
        await ConfigureAsync(first, "primary");
        await ConfigureAsync(second, "primary");

        using TotpAccount account = CreateAccount("Offline", "alice", 9);
        await first.SaveAsync([account], TestContext.Current.CancellationToken);
        await first.SyncGitHubNowAsync(TestContext.Current.CancellationToken);
        await second.SyncGitHubNowAsync(TestContext.Current.CancellationToken);

        IReadOnlyList<TotpAccount> downloaded = await second.LoadAsync(
            TestContext.Current.CancellationToken);
        try
        {
            TotpAccount actual = Assert.Single(downloaded);
            Assert.Equal("Offline", actual.Issuer);
            Assert.Equal("alice", actual.AccountName);
        }
        finally
        {
            DisposeAccounts(downloaded);
        }
    }

    [Fact]
    public async Task LostUploadResponse_IsRecovered_AndDuplicateSyncIsIdempotent()
    {
        var remote = new FakeGitHubRemote();
        var factory = new FakeGitHubApiClientFactory(remote);
        using VersionedVaultStore store = CreateStore("lost", factory);
        using TotpAccount account = CreateAccount("Lost", "response", 3);
        await store.SaveAsync([account], TestContext.Current.CancellationToken);
        await ConfigureAsync(store, "primary");
        remote.LoseNextObjectPutResponse = true;

        await store.SyncGitHubNowAsync(TestContext.Current.CancellationToken);
        int operationCount = remote.Files.Keys.Count(path =>
            path.EndsWith(".pao", StringComparison.Ordinal));
        await store.SyncGitHubNowAsync(TestContext.Current.CancellationToken);

        Assert.Equal(
            operationCount,
            remote.Files.Keys.Count(path =>
                path.EndsWith(".pao", StringComparison.Ordinal)));
        Assert.Equal(
            0,
            (await store.GetGitHubStatusAsync(
                TestContext.Current.CancellationToken)).PendingOperationCount);
    }

    [Theory]
    [InlineData(FakeFailure.InvalidToken, "GitHub.AuthenticationFailed")]
    [InlineData(FakeFailure.PermissionDenied, "GitHub.PermissionDenied")]
    [InlineData(FakeFailure.NotFound, "GitHub.NotFoundOrInaccessible")]
    [InlineData(FakeFailure.PublicRepository, "GitHub.RepositoryPublic")]
    [InlineData(FakeFailure.RateLimited, "GitHub.RateLimited")]
    public async Task RepositoryFailures_AreDistinct_AndLeaveOutboxQueued(
        FakeFailure failure,
        string expectedCode)
    {
        var remote = new FakeGitHubRemote();
        var factory = new FakeGitHubApiClientFactory(remote);
        using VersionedVaultStore store = CreateStore(failure.ToString(), factory);
        using TotpAccount account = CreateAccount("Queued", "change", 5);
        await store.SaveAsync([account], TestContext.Current.CancellationToken);
        await ConfigureAsync(store, "primary");
        remote.Failure = failure;

        SafeApplicationException exception =
            await Assert.ThrowsAsync<SafeApplicationException>(
                () => store.SyncGitHubNowAsync(
                    TestContext.Current.CancellationToken));

        Assert.Equal(expectedCode, exception.ErrorCode);
        Assert.True(
            (await store.GetGitHubStatusAsync(
                TestContext.Current.CancellationToken)).PendingOperationCount > 0);
    }

    [Fact]
    public async Task RecreatedRepositoryAndRollback_PauseWithoutChangingLocalVault()
    {
        var remote = new FakeGitHubRemote();
        var factory = new FakeGitHubApiClientFactory(remote);
        using VersionedVaultStore store = CreateStore("rollback", factory);
        using TotpAccount account = CreateAccount("Local", "safe", 7);
        await store.SaveAsync([account], TestContext.Current.CancellationToken);
        await ConfigureAsync(store, "primary");
        await store.SyncGitHubNowAsync(TestContext.Current.CancellationToken);

        remote.RepositoryId++;
        SafeApplicationException recreated =
            await Assert.ThrowsAsync<SafeApplicationException>(
                () => store.SyncGitHubNowAsync(
                    TestContext.Current.CancellationToken));
        Assert.Equal("GitHub.RepositoryRecreated", recreated.ErrorCode);
        remote.RepositoryId--;
        remote.ForceDivergence = true;
        SafeApplicationException rollback =
            await Assert.ThrowsAsync<SafeApplicationException>(
                () => store.SyncGitHubNowAsync(
                    TestContext.Current.CancellationToken));
        Assert.Equal("GitHub.RemoteRollback", rollback.ErrorCode);
        Assert.True(
            (await store.GetGitHubStatusAsync(
                TestContext.Current.CancellationToken)).UploadsPaused);

        IReadOnlyList<TotpAccount> local = await store.LoadAsync(
            TestContext.Current.CancellationToken);
        try
        {
            Assert.Equal("Local", Assert.Single(local).Issuer);
        }
        finally
        {
            DisposeAccounts(local);
        }
    }

    [Fact]
    public async Task CorruptUnknownObject_IsQuarantined_AndNeverApplied()
    {
        var remote = new FakeGitHubRemote();
        var factory = new FakeGitHubApiClientFactory(remote);
        using VersionedVaultStore source = CreateStore("corrupt-source", factory);
        using TotpAccount account = CreateAccount("Remote", "corrupt", 11);
        await source.SaveAsync([account], TestContext.Current.CancellationToken);
        await ConfigureAsync(source, "primary");
        await source.SyncGitHubNowAsync(TestContext.Current.CancellationToken);
        remote.CorruptFirstOperation();

        using VersionedVaultStore target = CreateStore("corrupt-target", factory);
        await target.SaveAsync([], TestContext.Current.CancellationToken);
        await ConfigureAsync(target, "primary");
        await Assert.ThrowsAnyAsync<Exception>(
            () => target.SyncGitHubNowAsync(
                TestContext.Current.CancellationToken));

        string quarantine = Path.Combine(
            _directory,
            "corrupt-target",
            "github-quarantine");
        Assert.Single(Directory.GetFiles(quarantine, "*.bad"));
        IReadOnlyList<TotpAccount> local = await target.LoadAsync(
            TestContext.Current.CancellationToken);
        try
        {
            Assert.Empty(local);
        }
        finally
        {
            DisposeAccounts(local);
        }
    }

    [Fact]
    public async Task MissingKnownObject_PausesThenRemoteRepairRestoresIt()
    {
        var remote = new FakeGitHubRemote();
        var factory = new FakeGitHubApiClientFactory(remote);
        using VersionedVaultStore store = CreateStore("repair", factory);
        using TotpAccount account = CreateAccount("Repair", "remote", 15);
        await store.SaveAsync([account], TestContext.Current.CancellationToken);
        await ConfigureAsync(store, "primary");
        await store.SyncGitHubNowAsync(TestContext.Current.CancellationToken);
        string operationPath = remote.Files.Keys.First(path =>
            path.EndsWith(".pao", StringComparison.Ordinal));
        remote.Files.Remove(operationPath);

        SafeApplicationException missing =
            await Assert.ThrowsAsync<SafeApplicationException>(
                () => store.SyncGitHubNowAsync(
                    TestContext.Current.CancellationToken));
        Assert.Equal("GitHub.RemoteRollback", missing.ErrorCode);

        await store.RepairGitHubRemoteAsync(
            TestContext.Current.CancellationToken);
        Assert.True(remote.Files.ContainsKey(operationPath));
        Assert.False(
            (await store.GetGitHubStatusAsync(
                TestContext.Current.CancellationToken)).UploadsPaused);
    }

    [Fact]
    public async Task RenameOrTransfer_IsReportedWithoutUploading()
    {
        var remote = new FakeGitHubRemote();
        var factory = new FakeGitHubApiClientFactory(remote);
        using VersionedVaultStore store = CreateStore("renamed", factory);
        await store.SaveAsync([], TestContext.Current.CancellationToken);
        await ConfigureAsync(store, "primary");
        int fileCount = remote.Files.Count;
        remote.CanonicalOwner = "new-owner";

        SafeApplicationException exception =
            await Assert.ThrowsAsync<SafeApplicationException>(
                () => store.SyncGitHubNowAsync(
                    TestContext.Current.CancellationToken));

        Assert.Equal(
            "GitHub.RepositoryRenamedOrTransferred",
            exception.ErrorCode);
        Assert.Equal(fileCount, remote.Files.Count);
    }

    [Fact]
    public async Task Replacement_IsActivatedOnlyAfterFreshVerification()
    {
        var remote = new FakeGitHubRemote();
        var factory = new FakeGitHubApiClientFactory(remote);
        using VersionedVaultStore store = CreateStore("replacement", factory);
        using TotpAccount account = CreateAccount("Replacement", "verified", 17);
        await store.SaveAsync([account], TestContext.Current.CancellationToken);
        await ConfigureAsync(store, "primary");
        await store.SyncGitHubNowAsync(TestContext.Current.CancellationToken);
        GitHubSyncStatus before = await store.GetGitHubStatusAsync(
            TestContext.Current.CancellationToken);

        await store.ReplaceGitHubRepositoryAsync(
            new GitHubConnectionRequest(
                "owner",
                "replacement",
                "sync",
                ".replacement-authenticator",
                BackgroundSyncEnabled: false),
            TestCredential.AsMemory(),
            SyncPassword.AsMemory(),
            TestContext.Current.CancellationToken);

        GitHubSyncStatus after = await store.GetGitHubStatusAsync(
            TestContext.Current.CancellationToken);
        Assert.Equal(
            "owner/replacement@sync",
            after.Repository);
        Assert.NotEqual(before.RemoteGeneration, after.RemoteGeneration);
        Assert.Contains(
            remote.Files.Keys,
            path => path.StartsWith(
                ".replacement-authenticator/objects/",
                StringComparison.Ordinal));
        Assert.True(File.Exists(
            Path.Combine(
                _directory,
                "replacement",
                "github-sync.dat.disabled-fallback")));
    }

    [Fact]
    public void ImmutableOperationEncryption_IsByteStableAndCollisionSafe()
    {
        byte[] key = RandomNumberGenerator.GetBytes(32);
        using var configuration = new GitHubSyncConfiguration(
            "owner",
            "repo",
            "sync",
            ".auth",
            42,
            Guid.NewGuid(),
            Guid.NewGuid(),
            key,
            true,
            false,
            false,
            null,
            [],
            [],
            null,
            null,
            null);
        using SyncOperation operation = CreateOperation();
        byte[] first = GitHubRemoteProtocol.EncryptOperation(
            configuration,
            operation);
        byte[] second = GitHubRemoteProtocol.EncryptOperation(
            configuration,
            operation);
        try
        {
            Assert.Equal(first, second);
            second[^1] ^= 0x40;
            Assert.ThrowsAny<CryptographicException>(
                () => GitHubRemoteProtocol.DecryptOperation(
                    configuration,
                    second));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(first);
            CryptographicOperations.ZeroMemory(second);
        }
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
        IGitHubApiClientFactory factory) =>
        new(
            NullLogger<DpapiVaultStore>.Instance,
            Path.Combine(_directory, name),
            recoveryCodec: null,
            recoveryCheckpoint: null,
            syncCheckpoint: null,
            factory);

    private static Task ConfigureAsync(
        VersionedVaultStore store,
        string repository) =>
        store.ConfigureGitHubAsync(
            new GitHubConnectionRequest(
                "owner",
                repository,
                "sync",
                ".personal-authenticator",
                BackgroundSyncEnabled: false),
            TestCredential.AsMemory(),
            SyncPassword.AsMemory(),
            TestContext.Current.CancellationToken);

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

    private static SyncOperation CreateOperation()
    {
        using TotpAccount source = CreateAccount("Stable", "bytes", 13);
        var account = new VaultAccountV2(
            source.Id,
            source.Issuer,
            source.AccountName,
            Guid.NewGuid());
        var secret = new SecretVersionV2(
            account.ActiveSecretVersionId,
            account.Id,
            source.Secret,
            source.Algorithm,
            source.Digits,
            source.Period,
            "otpauth://totp/Stable%3Abytes?secret=AEBAGBAFAYDQQCIKBMGA2DQPCAIREEYU",
            ProvisioningUriOrigin.CanonicalGenerated);
        return new SyncOperation(
            Guid.NewGuid(),
            Guid.NewGuid(),
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

    private static void DisposeAccounts(IEnumerable<TotpAccount> accounts)
    {
        foreach (TotpAccount account in accounts)
        {
            account.Dispose();
        }
    }

    public enum FakeFailure
    {
        None,
        InvalidToken,
        PermissionDenied,
        NotFound,
        PublicRepository,
        RateLimited,
    }

    private sealed class FakeGitHubApiClientFactory(FakeGitHubRemote remote)
        : IGitHubApiClientFactory
    {
        public IGitHubApiClient Create(ReadOnlyMemory<char> token) =>
            new FakeGitHubApiClient(remote, new string(token.Span));
    }

    private sealed class FakeGitHubApiClient(
        FakeGitHubRemote remote,
        string credential) : IGitHubApiClient
    {
        public DateTimeOffset? RateLimitResetsAtUtc =>
            remote.Failure == FakeFailure.RateLimited
                ? DateTimeOffset.UtcNow.AddMinutes(5)
                : null;

        public Task<GitHubUserInfo> GetUserAsync(CancellationToken cancellationToken)
        {
            Check(cancellationToken);
            return Task.FromResult(new GitHubUserInfo(1, "owner"));
        }

        public Task<GitHubRepositoryInfo> GetRepositoryAsync(
            string owner,
            string repository,
            CancellationToken cancellationToken)
        {
            Check(cancellationToken);
            return Task.FromResult(
                new GitHubRepositoryInfo(
                    remote.RepositoryId,
                    remote.CanonicalOwner,
                    remote.CanonicalName ?? repository,
                    remote.Failure != FakeFailure.PublicRepository,
                    remote.Failure == FakeFailure.PermissionDenied
                        ? "contents:read"
                        : "contents:write",
                    remote.DefaultBranch));
        }

        public Task<GitHubRemoteFile?> GetFileAsync(
            string owner,
            string repository,
            string path,
            string branch,
            string? etag,
            CancellationToken cancellationToken)
        {
            Check(cancellationToken);
            return Task.FromResult(
                remote.Files.TryGetValue(path, out FakeFile? file)
                    ? new GitHubRemoteFile(
                        file.Content.ToArray(),
                        file.Sha,
                        $"\"{file.Sha}\"")
                    : null);
        }

        public Task<IReadOnlyList<GitHubRemoteEntry>> ListFilesAsync(
            string owner,
            string repository,
            string branch,
            string pathPrefix,
            CancellationToken cancellationToken)
        {
            Check(cancellationToken);
            IReadOnlyList<GitHubRemoteEntry> entries = remote.Files
                .Where(pair => pair.Key.StartsWith(
                    pathPrefix + "/",
                    StringComparison.Ordinal))
                .Select(pair => new GitHubRemoteEntry(
                    pair.Key,
                    pair.Value.Sha,
                    pair.Value.Content.Length))
                .ToList();
            return Task.FromResult(entries);
        }

        public Task<GitHubPutResult> PutFileAsync(
            string owner,
            string repository,
            string path,
            string branch,
            ReadOnlyMemory<byte> content,
            string? existingSha,
            CancellationToken cancellationToken)
        {
            Check(cancellationToken);
            if (!remote.Branches.Contains(branch))
            {
                throw new SafeApplicationException(
                    "GitHub.BranchMissing",
                    "The requested branch does not exist.");
            }

            if (remote.Files.TryGetValue(path, out FakeFile? current))
            {
                if (existingSha != current.Sha)
                {
                    throw new SafeApplicationException(
                        "GitHub.RequestFailed",
                        "Concurrent update.");
                }
            }
            else if (existingSha is not null)
            {
                throw new SafeApplicationException(
                    "GitHub.RequestFailed",
                    "Missing update target.");
            }

            string sha = Convert.ToHexString(SHA256.HashData(content.Span));
            remote.Files[path] = new FakeFile(content.ToArray(), sha);
            remote.AdvanceHead();
            if (remote.LoseNextObjectPutResponse &&
                path.EndsWith(".pao", StringComparison.Ordinal))
            {
                remote.LoseNextObjectPutResponse = false;
                throw new SafeApplicationException(
                    "GitHub.RequestFailed",
                    "Simulated lost response.");
            }

            return Task.FromResult(new GitHubPutResult(sha, remote.Head));
        }

        public Task<GitHubPutResult> InitializeEmptyRepositoryAsync(
            string owner,
            string repository,
            string path,
            ReadOnlyMemory<byte> content,
            CancellationToken cancellationToken)
        {
            Check(cancellationToken);
            if (remote.Branches.Count != 0)
            {
                throw new SafeApplicationException(
                    "GitHub.RequestFailed",
                    "The repository is not empty.");
            }

            string sha = Convert.ToHexString(SHA256.HashData(content.Span));
            remote.Files[path] = new FakeFile(content.ToArray(), sha);
            remote.Branches.Add(remote.DefaultBranch);
            remote.AdvanceHead();
            remote.InitializationCount++;
            return Task.FromResult(new GitHubPutResult(sha, remote.Head));
        }

        public Task CreateBranchAsync(
            string owner,
            string repository,
            string branch,
            string commitSha,
            CancellationToken cancellationToken)
        {
            Check(cancellationToken);
            if (remote.Branches.Count == 0 ||
                !string.Equals(commitSha, remote.Head, StringComparison.Ordinal) ||
                !remote.Branches.Add(branch))
            {
                throw new SafeApplicationException(
                    "GitHub.RequestFailed",
                    "The branch could not be created.");
            }

            remote.CreatedBranches.Add(branch);
            return Task.CompletedTask;
        }

        public Task<string?> TryGetBranchHeadAsync(
            string owner,
            string repository,
            string branch,
            CancellationToken cancellationToken)
        {
            Check(cancellationToken);
            return Task.FromResult(
                remote.Branches.Contains(branch) ? remote.Head : null);
        }

        public Task<string> GetBranchHeadAsync(
            string owner,
            string repository,
            string branch,
            CancellationToken cancellationToken)
        {
            Check(cancellationToken);
            if (!remote.Branches.Contains(branch))
            {
                throw new SafeApplicationException(
                    "GitHub.BranchMissing",
                    "The requested branch does not exist.");
            }

            return Task.FromResult(remote.Head);
        }

        public Task<bool> IsAncestorAsync(
            string owner,
            string repository,
            string ancestor,
            string descendant,
            CancellationToken cancellationToken)
        {
            Check(cancellationToken);
            return Task.FromResult(!remote.ForceDivergence);
        }

        public ValueTask DisposeAsync() => ValueTask.CompletedTask;

        private void Check(CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!string.Equals(
                    credential,
                    TestCredential,
                    StringComparison.Ordinal))
            {
                throw new SafeApplicationException(
                    "GitHub.AuthenticationFailed",
                    "Invalid test credential.");
            }

            SafeApplicationException? failure = remote.Failure switch
            {
                FakeFailure.InvalidToken => new SafeApplicationException(
                    "GitHub.AuthenticationFailed",
                    "The token is invalid."),
                FakeFailure.NotFound => new SafeApplicationException(
                    "GitHub.NotFoundOrInaccessible",
                    "The private repository is inaccessible."),
                FakeFailure.RateLimited => new SafeApplicationException(
                    "GitHub.RateLimited",
                    "The rate limit is active."),
                _ => null,
            };
            if (failure is not null)
            {
                throw failure;
            }
        }
    }

    private sealed class FakeGitHubRemote
    {
        private int _head;

        public long RepositoryId { get; set; } = 1001;

        public string CanonicalOwner { get; set; } = "owner";

        public string? CanonicalName { get; set; }

        public string DefaultBranch { get; set; } = "sync";

        public HashSet<string> Branches { get; } =
            new(StringComparer.Ordinal) { "sync" };

        public List<string> CreatedBranches { get; } = [];

        public int InitializationCount { get; set; }

        public Dictionary<string, FakeFile> Files { get; } =
            new(StringComparer.Ordinal);

        public FakeFailure Failure { get; set; }

        public bool LoseNextObjectPutResponse { get; set; }

        public bool ForceDivergence { get; set; }

        public string Head => $"commit-{_head:D8}";

        public void AdvanceHead() => _head++;

        public void CorruptFirstOperation()
        {
            string path = Files.Keys.First(item =>
                item.EndsWith(".pao", StringComparison.Ordinal));
            byte[] content = Files[path].Content.ToArray();
            content[^1] ^= 0x80;
            Files[path] = new FakeFile(
                content,
                Convert.ToHexString(SHA256.HashData(content)));
        }
    }

    private sealed record FakeFile(byte[] Content, string Sha);
}
