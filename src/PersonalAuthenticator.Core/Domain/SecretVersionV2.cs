using PersonalAuthenticator.Core.Security;

namespace PersonalAuthenticator.Core.Domain;

public sealed class SecretVersionV2 : IDisposable
{
    private readonly SensitiveBuffer _secret;

    public SecretVersionV2(
        Guid id,
        Guid accountId,
        ReadOnlySpan<byte> secret,
        TotpAlgorithm algorithm,
        int digits,
        int period,
        string provisioningUri,
        ProvisioningUriOrigin provisioningUriOrigin,
        SecretVersionState state = SecretVersionState.Active,
        DateTimeOffset? createdAtUtc = null,
        DateTimeOffset? retiredAtUtc = null)
    {
        if (id == Guid.Empty)
        {
            throw new ArgumentException("A secret-version identifier cannot be empty.", nameof(id));
        }

        if (accountId == Guid.Empty)
        {
            throw new ArgumentException("An account identifier cannot be empty.", nameof(accountId));
        }

        if (secret.Length is < 10 or > 128)
        {
            throw new ArgumentOutOfRangeException(
                nameof(secret),
                "Secret must contain between 10 and 128 bytes.");
        }

        if (!Enum.IsDefined(algorithm))
        {
            throw new ArgumentOutOfRangeException(nameof(algorithm));
        }

        if (digits is not (6 or 8))
        {
            throw new ArgumentOutOfRangeException(nameof(digits), "TOTP digits must be 6 or 8.");
        }

        if (period is < 15 or > 300)
        {
            throw new ArgumentOutOfRangeException(
                nameof(period),
                "TOTP period must be between 15 and 300 seconds.");
        }

        ArgumentException.ThrowIfNullOrWhiteSpace(provisioningUri);
        if (provisioningUri.Length > 4096 ||
            !Uri.TryCreate(provisioningUri, UriKind.Absolute, out Uri? parsedUri) ||
            !string.Equals(parsedUri.Scheme, "otpauth", StringComparison.OrdinalIgnoreCase))
        {
            throw new ArgumentException(
                "The provisioning URI must be a valid otpauth URI no longer than 4096 characters.",
                nameof(provisioningUri));
        }

        if (!Enum.IsDefined(provisioningUriOrigin))
        {
            throw new ArgumentOutOfRangeException(nameof(provisioningUriOrigin));
        }

        if (!Enum.IsDefined(state))
        {
            throw new ArgumentOutOfRangeException(nameof(state));
        }

        DateTimeOffset created = (createdAtUtc ?? DateTimeOffset.UtcNow).ToUniversalTime();
        DateTimeOffset? retired = retiredAtUtc?.ToUniversalTime();
        if (retired < created)
        {
            throw new ArgumentException(
                "The retirement time cannot precede the secret-version creation time.",
                nameof(retiredAtUtc));
        }

        if (state == SecretVersionState.Retired && retired is null)
        {
            throw new ArgumentException(
                "A retired secret version must include its retirement time.",
                nameof(retiredAtUtc));
        }

        if (state != SecretVersionState.Retired && retired is not null)
        {
            throw new ArgumentException(
                "Only a retired secret version may include a retirement time.",
                nameof(retiredAtUtc));
        }

        Id = id;
        AccountId = accountId;
        Algorithm = algorithm;
        Digits = digits;
        Period = period;
        ProvisioningUri = provisioningUri;
        ProvisioningUriOrigin = provisioningUriOrigin;
        State = state;
        CreatedAtUtc = created;
        RetiredAtUtc = retired;
        _secret = new SensitiveBuffer(secret);
    }

    public Guid Id { get; }

    public Guid AccountId { get; }

    public TotpAlgorithm Algorithm { get; }

    public int Digits { get; }

    public int Period { get; }

    public string ProvisioningUri { get; }

    public ProvisioningUriOrigin ProvisioningUriOrigin { get; }

    public SecretVersionState State { get; }

    public DateTimeOffset CreatedAtUtc { get; }

    public DateTimeOffset? RetiredAtUtc { get; }

    public ReadOnlySpan<byte> Secret => _secret.AsSpan();

    public void Dispose() => _secret.Dispose();
}
