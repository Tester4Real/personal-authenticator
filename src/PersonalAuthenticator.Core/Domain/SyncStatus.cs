namespace PersonalAuthenticator.Core.Domain;

public sealed record SyncStatus(
    bool IsConfigured,
    bool IsSyncing,
    bool IsReadOnlyCompatibilityMode,
    string? BackendPath,
    Guid? DeviceId,
    int PendingOperationCount,
    int ConflictCount,
    DateTimeOffset? LastSuccessfulSyncAtUtc,
    string? LastError);
