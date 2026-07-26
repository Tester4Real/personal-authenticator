using PersonalAuthenticator.Core.Security;

namespace PersonalAuthenticator.Core.Domain;

public sealed class TotpAccount : IDisposable
{
    private readonly SensitiveBuffer _secret;

    public TotpAccount(
        Guid id,
        string issuer,
        string accountName,
        ReadOnlySpan<byte> secret,
        TotpAlgorithm algorithm = TotpAlgorithm.Sha1,
        int digits = 6,
        int period = 30,
        bool favourite = false,
        int sortOrder = 0,
        DateTimeOffset? createdAtUtc = null,
        DateTimeOffset? updatedAtUtc = null)
    {
        ValidateDisplayValue(issuer, nameof(issuer));
        ValidateDisplayValue(accountName, nameof(accountName));

        if (secret.Length is < 10 or > 128)
        {
            throw new ArgumentOutOfRangeException(nameof(secret), "Secret must contain between 10 and 128 bytes.");
        }

        if (digits is not (6 or 8))
        {
            throw new ArgumentOutOfRangeException(nameof(digits), "TOTP digits must be 6 or 8.");
        }

        if (period is < 15 or > 300)
        {
            throw new ArgumentOutOfRangeException(nameof(period), "TOTP period must be between 15 and 300 seconds.");
        }

        DateTimeOffset now = DateTimeOffset.UtcNow;
        Id = id == Guid.Empty ? Guid.NewGuid() : id;
        Issuer = issuer.Trim();
        AccountName = accountName.Trim();
        Algorithm = algorithm;
        Digits = digits;
        Period = period;
        Favourite = favourite;
        SortOrder = sortOrder;
        CreatedAtUtc = createdAtUtc ?? now;
        UpdatedAtUtc = updatedAtUtc ?? now;
        _secret = new SensitiveBuffer(secret);
    }

    public Guid Id { get; }

    public string Issuer { get; private set; }

    public string AccountName { get; private set; }

    public TotpAlgorithm Algorithm { get; }

    public int Digits { get; }

    public int Period { get; }

    public bool Favourite { get; private set; }

    public int SortOrder { get; private set; }

    public DateTimeOffset CreatedAtUtc { get; }

    public DateTimeOffset UpdatedAtUtc { get; private set; }

    public ReadOnlySpan<byte> Secret => _secret.AsSpan();

    public void UpdateDisplay(string issuer, string accountName, DateTimeOffset now)
    {
        ValidateDisplayValue(issuer, nameof(issuer));
        ValidateDisplayValue(accountName, nameof(accountName));
        Issuer = issuer.Trim();
        AccountName = accountName.Trim();
        UpdatedAtUtc = now;
    }

    public void SetFavourite(bool favourite, DateTimeOffset now)
    {
        Favourite = favourite;
        UpdatedAtUtc = now;
    }

    public void SetSortOrder(int sortOrder, DateTimeOffset now)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(sortOrder);

        SortOrder = sortOrder;
        UpdatedAtUtc = now;
    }

    public void Dispose() => _secret.Dispose();

    private static void ValidateDisplayValue(string value, string parameterName)
    {
        ArgumentNullException.ThrowIfNull(value);
        if (string.IsNullOrWhiteSpace(value) || value.Length > 256)
        {
            throw new ArgumentException("Display values must contain 1 to 256 non-whitespace characters.", parameterName);
        }
    }
}
