namespace PersonalAuthenticator.Core.Domain;

public sealed class AccountHistoryEntryV2
{
    public AccountHistoryEntryV2(
        Guid id,
        Guid accountId,
        AccountHistoryAction action,
        DateTimeOffset occurredAtUtc,
        Guid? secretVersionId = null,
        Guid? previousSecretVersionId = null,
        Guid? relatedAccountId = null,
        Guid? actorDeviceId = null)
    {
        if (id == Guid.Empty)
        {
            throw new ArgumentException("A history identifier cannot be empty.", nameof(id));
        }

        if (accountId == Guid.Empty)
        {
            throw new ArgumentException("An account identifier cannot be empty.", nameof(accountId));
        }

        if (!Enum.IsDefined(action))
        {
            throw new ArgumentOutOfRangeException(nameof(action));
        }

        if (occurredAtUtc == default)
        {
            throw new ArgumentException("A history timestamp is required.", nameof(occurredAtUtc));
        }

        Id = id;
        AccountId = accountId;
        Action = action;
        OccurredAtUtc = occurredAtUtc.ToUniversalTime();
        SecretVersionId = ValidateOptionalId(secretVersionId, nameof(secretVersionId));
        PreviousSecretVersionId = ValidateOptionalId(
            previousSecretVersionId,
            nameof(previousSecretVersionId));
        RelatedAccountId = ValidateOptionalId(relatedAccountId, nameof(relatedAccountId));
        ActorDeviceId = ValidateOptionalId(actorDeviceId, nameof(actorDeviceId));
    }

    public Guid Id { get; }

    public Guid AccountId { get; }

    public AccountHistoryAction Action { get; }

    public DateTimeOffset OccurredAtUtc { get; }

    public Guid? SecretVersionId { get; }

    public Guid? PreviousSecretVersionId { get; }

    public Guid? RelatedAccountId { get; }

    public Guid? ActorDeviceId { get; }

    private static Guid? ValidateOptionalId(Guid? value, string parameterName)
    {
        if (value == Guid.Empty)
        {
            throw new ArgumentException(
                "An optional identifier cannot be empty when provided.",
                parameterName);
        }

        return value;
    }
}
