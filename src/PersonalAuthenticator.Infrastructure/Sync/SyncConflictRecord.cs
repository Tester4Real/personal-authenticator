using PersonalAuthenticator.Core.Domain;

namespace PersonalAuthenticator.Infrastructure.Sync;

internal sealed record SyncConflictRecord(
    Guid Id,
    Guid AccountId,
    SyncConflictKind Kind,
    string FieldKey,
    Guid OperationAId,
    Guid OperationBId,
    Guid? SecretVersionAId,
    Guid? SecretVersionBId,
    DateTimeOffset DetectedAtUtc,
    bool Resolved);
