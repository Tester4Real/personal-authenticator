namespace PersonalAuthenticator.Core.Domain;

public sealed class VaultAccountV2
{
    public VaultAccountV2(
        Guid id,
        string issuer,
        string accountName,
        Guid activeSecretVersionId,
        bool favourite = false,
        int sortOrder = 0,
        DateTimeOffset? createdAtUtc = null,
        DateTimeOffset? updatedAtUtc = null,
        DateTimeOffset? archivedAtUtc = null)
    {
        ValidateDisplayValue(issuer, nameof(issuer));
        ValidateDisplayValue(accountName, nameof(accountName));

        if (id == Guid.Empty)
        {
            throw new ArgumentException("A v2 account identifier cannot be empty.", nameof(id));
        }

        if (activeSecretVersionId == Guid.Empty)
        {
            throw new ArgumentException(
                "An active secret-version identifier cannot be empty.",
                nameof(activeSecretVersionId));
        }

        ArgumentOutOfRangeException.ThrowIfNegative(sortOrder);

        DateTimeOffset now = DateTimeOffset.UtcNow;
        DateTimeOffset created = (createdAtUtc ?? now).ToUniversalTime();
        DateTimeOffset updated = (updatedAtUtc ?? now).ToUniversalTime();
        if (updated < created)
        {
            throw new ArgumentException(
                "The account update time cannot precede its creation time.",
                nameof(updatedAtUtc));
        }

        DateTimeOffset? archived = archivedAtUtc?.ToUniversalTime();
        if (archived < created)
        {
            throw new ArgumentException(
                "The archive time cannot precede the account creation time.",
                nameof(archivedAtUtc));
        }

        Id = id;
        Issuer = issuer.Trim();
        AccountName = accountName.Trim();
        ActiveSecretVersionId = activeSecretVersionId;
        Favourite = favourite;
        SortOrder = sortOrder;
        CreatedAtUtc = created;
        UpdatedAtUtc = updated;
        ArchivedAtUtc = archived;
    }

    public Guid Id { get; }

    public string Issuer { get; }

    public string AccountName { get; }

    public Guid ActiveSecretVersionId { get; }

    public bool Favourite { get; }

    public int SortOrder { get; }

    public DateTimeOffset CreatedAtUtc { get; }

    public DateTimeOffset UpdatedAtUtc { get; }

    public DateTimeOffset? ArchivedAtUtc { get; }

    private static void ValidateDisplayValue(string value, string parameterName)
    {
        ArgumentNullException.ThrowIfNull(value);
        if (string.IsNullOrWhiteSpace(value) || value.Length > 256)
        {
            throw new ArgumentException(
                "Display values must contain 1 to 256 non-whitespace characters.",
                parameterName);
        }
    }
}
