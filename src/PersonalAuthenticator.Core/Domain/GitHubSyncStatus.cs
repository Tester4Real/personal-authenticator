namespace PersonalAuthenticator.Core.Domain;

public sealed record GitHubSyncStatus(
    bool IsConfigured,
    bool IsEnabled,
    bool IsBackgroundSyncEnabled,
    bool IsSyncing,
    bool UploadsPaused,
    string? Repository,
    long? RepositoryId,
    Guid? VaultId,
    Guid? RemoteGeneration,
    int PendingOperationCount,
    DateTimeOffset? LastSuccessfulSyncAtUtc,
    DateTimeOffset? RateLimitResetsAtUtc,
    string RemoteHealth,
    string? AuthenticationStatus,
    string? LastError);
