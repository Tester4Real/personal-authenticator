using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using PersonalAuthenticator.Core.Domain;

namespace PersonalAuthenticator.Core.Security;

public sealed class DuplicateDetector : IDisposable
{
    private readonly byte[] _sessionKey = RandomNumberGenerator.GetBytes(32);

    public bool AreLikelyDuplicates(TotpAccount left, TotpAccount right)
    {
        Span<byte> leftFingerprint = stackalloc byte[32];
        Span<byte> rightFingerprint = stackalloc byte[32];
        ComputeFingerprint(left, leftFingerprint);
        ComputeFingerprint(right, rightFingerprint);
        bool result = CryptographicOperations.FixedTimeEquals(leftFingerprint, rightFingerprint);
        CryptographicOperations.ZeroMemory(leftFingerprint);
        CryptographicOperations.ZeroMemory(rightFingerprint);
        return result;
    }

    public void Dispose() => CryptographicOperations.ZeroMemory(_sessionKey);

    private void ComputeFingerprint(TotpAccount account, Span<byte> destination)
    {
        using IncrementalHash hmac = IncrementalHash.CreateHMAC(HashAlgorithmName.SHA256, _sessionKey);
        byte[] issuer = Encoding.UTF8.GetBytes(account.Issuer.Normalize(NormalizationForm.FormKC).ToUpperInvariant());
        byte[] accountName = Encoding.UTF8.GetBytes(account.AccountName.Normalize(NormalizationForm.FormKC).ToUpperInvariant());
        Span<byte> lengthPrefix = stackalloc byte[4];
        Span<byte> parameters = stackalloc byte[12];
        BinaryPrimitives.WriteInt32LittleEndian(parameters, (int)account.Algorithm);
        BinaryPrimitives.WriteInt32LittleEndian(parameters[4..], account.Digits);
        BinaryPrimitives.WriteInt32LittleEndian(parameters[8..], account.Period);
        try
        {
            AppendLengthPrefixed(hmac, issuer, lengthPrefix);
            AppendLengthPrefixed(hmac, accountName, lengthPrefix);
            hmac.AppendData(parameters);
            hmac.AppendData(account.Secret);
            if (!hmac.TryGetHashAndReset(destination, out int bytesWritten) ||
                bytesWritten != destination.Length)
            {
                throw new CryptographicException("The duplicate fingerprint could not be computed.");
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(issuer);
            CryptographicOperations.ZeroMemory(accountName);
            CryptographicOperations.ZeroMemory(lengthPrefix);
            CryptographicOperations.ZeroMemory(parameters);
        }
    }

    private static void AppendLengthPrefixed(
        IncrementalHash hmac,
        ReadOnlySpan<byte> value,
        Span<byte> lengthPrefix)
    {
        BinaryPrimitives.WriteInt32LittleEndian(lengthPrefix, value.Length);
        hmac.AppendData(lengthPrefix);
        hmac.AppendData(value);
    }
}
