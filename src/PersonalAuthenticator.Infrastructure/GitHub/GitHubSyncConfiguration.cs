using System.Security.Cryptography;

namespace PersonalAuthenticator.Infrastructure.GitHub;

internal sealed record GitHubSyncConfiguration(
    string Owner,
    string Repository,
    string Branch,
    string PathPrefix,
    long RepositoryId,
    Guid VaultId,
    Guid RemoteGeneration,
    byte[] SyncKey,
    bool Enabled,
    bool BackgroundSyncEnabled,
    bool UploadsPaused,
    string? KnownBranchHead,
    Dictionary<Guid, string> KnownObjectHashes,
    Dictionary<Guid, long> VerifiedDeviceSequences,
    DateTimeOffset? LastSuccessfulSyncAtUtc,
    DateTimeOffset? RateLimitResetsAtUtc,
    string? LastError) : IDisposable
{
    public void Dispose() => CryptographicOperations.ZeroMemory(SyncKey);
}
