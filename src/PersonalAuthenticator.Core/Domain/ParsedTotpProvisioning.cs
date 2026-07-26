using PersonalAuthenticator.Core.Security;

namespace PersonalAuthenticator.Core.Domain;

public sealed class ParsedTotpProvisioning : IDisposable
{
    private readonly SensitiveBuffer _secret;

    public ParsedTotpProvisioning(
        string issuer,
        string accountName,
        ReadOnlySpan<byte> secret,
        TotpAlgorithm algorithm,
        int digits,
        int period)
    {
        Issuer = issuer;
        AccountName = accountName;
        Algorithm = algorithm;
        Digits = digits;
        Period = period;
        _secret = new SensitiveBuffer(secret);
    }

    public string Issuer { get; }

    public string AccountName { get; }

    public TotpAlgorithm Algorithm { get; }

    public int Digits { get; }

    public int Period { get; }

    public string MaskedSecretSuffix
    {
        get
        {
            ReadOnlySpan<byte> secret = _secret.AsSpan();
            return $"••••{Convert.ToHexString(secret[^Math.Min(2, secret.Length)..])}";
        }
    }

    public TotpAccount CreateAccount(int sortOrder = 0) =>
        new(
            Guid.NewGuid(),
            Issuer,
            AccountName,
            _secret.AsSpan(),
            Algorithm,
            Digits,
            Period,
            sortOrder: sortOrder);

    public void Dispose() => _secret.Dispose();
}
