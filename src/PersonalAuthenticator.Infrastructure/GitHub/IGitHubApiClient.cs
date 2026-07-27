namespace PersonalAuthenticator.Infrastructure.GitHub;

internal interface IGitHubApiClient : IAsyncDisposable
{
    DateTimeOffset? RateLimitResetsAtUtc { get; }

    Task<GitHubUserInfo> GetUserAsync(CancellationToken cancellationToken);

    Task<GitHubRepositoryInfo> GetRepositoryAsync(
        string owner,
        string repository,
        CancellationToken cancellationToken);

    Task<GitHubRemoteFile?> GetFileAsync(
        string owner,
        string repository,
        string path,
        string branch,
        string? etag,
        CancellationToken cancellationToken);

    Task<IReadOnlyList<GitHubRemoteEntry>> ListFilesAsync(
        string owner,
        string repository,
        string branch,
        string pathPrefix,
        CancellationToken cancellationToken);

    Task<GitHubPutResult> PutFileAsync(
        string owner,
        string repository,
        string path,
        string branch,
        ReadOnlyMemory<byte> content,
        string? existingSha,
        CancellationToken cancellationToken);

    Task<string> GetBranchHeadAsync(
        string owner,
        string repository,
        string branch,
        CancellationToken cancellationToken);

    Task<bool> IsAncestorAsync(
        string owner,
        string repository,
        string ancestor,
        string descendant,
        CancellationToken cancellationToken);
}

internal interface IGitHubApiClientFactory
{
    IGitHubApiClient Create(ReadOnlyMemory<char> token);
}

internal sealed record GitHubUserInfo(long Id, string Login);

internal sealed record GitHubRepositoryInfo(
    long Id,
    string Owner,
    string Name,
    bool IsPrivate,
    string Permissions);

internal sealed record GitHubRemoteFile(
    byte[] Content,
    string Sha,
    string? ETag) : IDisposable
{
    public void Dispose() =>
        System.Security.Cryptography.CryptographicOperations.ZeroMemory(Content);
}

internal sealed record GitHubRemoteEntry(string Path, string Sha, long Size);

internal sealed record GitHubPutResult(string BlobSha, string CommitSha);
