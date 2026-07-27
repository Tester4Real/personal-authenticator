namespace PersonalAuthenticator.Core.Domain;

public sealed record SyncConflictSummary(
    Guid Id,
    Guid AccountId,
    SyncConflictKind Kind,
    string FieldName,
    Guid OperationAId,
    Guid OperationBId,
    Guid? SecretVersionAId,
    Guid? SecretVersionBId,
    DateTimeOffset DetectedAtUtc)
{
    public string Description =>
        $"{Kind}: {FieldName} on account {AccountId:D}";
}
