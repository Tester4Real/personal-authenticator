namespace PersonalAuthenticator.Core.Domain;

public sealed record SecurityEpochStatus(
    int ActiveEpoch,
    int? PendingEpoch,
    bool RotationPending,
    bool PurgePending,
    Guid? PurgeAccountId,
    string? LastFailure);
