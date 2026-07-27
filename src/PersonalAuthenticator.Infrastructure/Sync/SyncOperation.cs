using PersonalAuthenticator.Core.Domain;

namespace PersonalAuthenticator.Infrastructure.Sync;

internal sealed record SyncOperation(
    Guid Id,
    Guid DeviceId,
    long DeviceSequence,
    long LogicalClock,
    DateTimeOffset OccurredAtUtc,
    Guid? AccountId,
    SyncOperationKind Kind,
    string FieldKey,
    IReadOnlyList<Guid> CausalParents,
    SyncOperationPayload Payload) : IDisposable
{
    public void Dispose() => Payload.Dispose();
}

internal sealed record SyncOperationDraft(
    Guid? AccountId,
    SyncOperationKind Kind,
    string FieldKey,
    DateTimeOffset OccurredAtUtc,
    SyncOperationPayload Payload) : IDisposable
{
    public void Dispose() => Payload.Dispose();
}

internal sealed class SyncOperationPayload : IDisposable
{
    public string? TextValue { get; init; }

    public bool? BoolValue { get; init; }

    public int? IntValue { get; init; }

    public DateTimeOffset? DateValue { get; init; }

    public Guid? GuidValue { get; init; }

    public Guid? SecondaryGuidValue { get; init; }

    public VaultAccountV2? Account { get; init; }

    public SecretVersionV2? SecretVersion { get; init; }

    public AccountHistoryEntryV2? HistoryEntry { get; init; }

    public Guid? ConflictId { get; init; }

    public SyncConflictResolution? Resolution { get; init; }

    public void Dispose() => SecretVersion?.Dispose();
}

internal static class SyncFieldKeys
{
    public const string Existence = "account";
    public const string Issuer = "issuer";
    public const string AccountName = "account-name";
    public const string Favourite = "favourite";
    public const string SortOrder = "sort-order";
    public const string Archive = "archive";
    public const string SecretSet = "secret-set";
    public const string ActiveSecret = "active-secret";
    public const string History = "history";
    public const string DuplicateDecision = "duplicate-decision";
    public const string Purge = "purge";
    public const string Resolution = "resolution";
}
