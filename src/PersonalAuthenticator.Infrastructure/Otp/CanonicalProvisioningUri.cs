using System.Security.Cryptography;
using OtpNet;
using PersonalAuthenticator.Core.Domain;

namespace PersonalAuthenticator.Infrastructure.Otp;

internal static class CanonicalProvisioningUri
{
    public static string Create(TotpAccount account)
    {
        ArgumentNullException.ThrowIfNull(account);
        byte[] secret = account.Secret.ToArray();
        try
        {
            string encodedSecret = Base32Encoding.ToString(secret);
            string algorithm = account.Algorithm switch
            {
                TotpAlgorithm.Sha1 => "SHA1",
                TotpAlgorithm.Sha256 => "SHA256",
                TotpAlgorithm.Sha512 => "SHA512",
                _ => throw new ArgumentOutOfRangeException(nameof(account)),
            };
            string encodedIssuer = Uri.EscapeDataString(account.Issuer);
            string encodedAccountName = Uri.EscapeDataString(account.AccountName);
            return FormattableString.Invariant(
                $"otpauth://totp/{encodedIssuer}:{encodedAccountName}?secret={encodedSecret}&issuer={encodedIssuer}&algorithm={algorithm}&digits={account.Digits}&period={account.Period}");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(secret);
        }
    }
}
