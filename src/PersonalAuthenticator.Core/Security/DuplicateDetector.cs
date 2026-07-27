using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using PersonalAuthenticator.Core.Domain;

namespace PersonalAuthenticator.Core.Security;

public sealed class DuplicateDetector : IDisposable
{
    private readonly byte[] _sessionKey = RandomNumberGenerator.GetBytes(32);

    public bool AreLikelyDuplicates(TotpAccount left, TotpAccount right)
        => Classify(left, right) == DuplicateMatchKind.Exact;

    public DuplicateMatchKind? Classify(TotpAccount left, TotpAccount right)
    {
        Span<byte> leftFingerprint = stackalloc byte[32];
        Span<byte> rightFingerprint = stackalloc byte[32];
        ComputeIdentityFingerprint(left, leftFingerprint);
        ComputeIdentityFingerprint(right, rightFingerprint);
        bool sameIdentity = CryptographicOperations.FixedTimeEquals(
            leftFingerprint,
            rightFingerprint);
        CryptographicOperations.ZeroMemory(leftFingerprint);
        CryptographicOperations.ZeroMemory(rightFingerprint);
        if (!sameIdentity)
        {
            return null;
        }

        bool sameSecret =
            left.Algorithm == right.Algorithm &&
            left.Digits == right.Digits &&
            left.Period == right.Period &&
            CryptographicOperations.FixedTimeEquals(left.Secret, right.Secret);
        return sameSecret
            ? DuplicateMatchKind.Exact
            : DuplicateMatchKind.SameAccountDifferentSecret;
    }

    public void Dispose() => CryptographicOperations.ZeroMemory(_sessionKey);

    private void ComputeIdentityFingerprint(TotpAccount account, Span<byte> destination)
    {
        using IncrementalHash hmac = IncrementalHash.CreateHMAC(HashAlgorithmName.SHA256, _sessionKey);
        byte[] issuer = Encoding.UTF8.GetBytes(account.Issuer.Normalize(NormalizationForm.FormKC).ToUpperInvariant());
        byte[] accountName = Encoding.UTF8.GetBytes(account.AccountName.Normalize(NormalizationForm.FormKC).ToUpperInvariant());
        Span<byte> lengthPrefix = stackalloc byte[4];
        try
        {
            AppendLengthPrefixed(hmac, issuer, lengthPrefix);
            AppendLengthPrefixed(hmac, accountName, lengthPrefix);
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
