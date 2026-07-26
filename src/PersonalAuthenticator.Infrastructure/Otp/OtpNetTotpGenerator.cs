using System.Security.Cryptography;
using OtpNet;
using PersonalAuthenticator.Core.Abstractions;
using PersonalAuthenticator.Core.Domain;

namespace PersonalAuthenticator.Infrastructure.Otp;

public sealed class OtpNetTotpGenerator : ITotpGenerator
{
    public string Generate(TotpAccount account, DateTimeOffset timestamp)
    {
        ArgumentNullException.ThrowIfNull(account);
        byte[] secret = account.Secret.ToArray();
        try
        {
            var totp = new Totp(
                secret,
                step: account.Period,
                mode: ToOtpHashMode(account.Algorithm),
                totpSize: account.Digits);
            return totp.ComputeTotp(timestamp.UtcDateTime);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(secret);
        }
    }

    public int GetSecondsRemaining(TotpAccount account, DateTimeOffset timestamp)
    {
        ArgumentNullException.ThrowIfNull(account);
        long unixSeconds = timestamp.ToUnixTimeSeconds();
        int elapsed = (int)(unixSeconds % account.Period);
        return elapsed == 0 ? account.Period : account.Period - elapsed;
    }

    public long GetTimeStep(TotpAccount account, DateTimeOffset timestamp)
    {
        ArgumentNullException.ThrowIfNull(account);
        return timestamp.ToUnixTimeSeconds() / account.Period;
    }

    private static OtpHashMode ToOtpHashMode(TotpAlgorithm algorithm) =>
        algorithm switch
        {
            TotpAlgorithm.Sha1 => OtpHashMode.Sha1,
            TotpAlgorithm.Sha256 => OtpHashMode.Sha256,
            TotpAlgorithm.Sha512 => OtpHashMode.Sha512,
            _ => throw new ArgumentOutOfRangeException(nameof(algorithm)),
        };
}
