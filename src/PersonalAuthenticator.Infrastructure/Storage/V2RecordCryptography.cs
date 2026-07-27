using System.Security.Cryptography;

namespace PersonalAuthenticator.Infrastructure.Storage;

internal static class V2RecordCryptography
{
    public const int NonceLength = 12;
    public const int TagLength = 16;
    public const int KeyLength = 32;

    public static EncryptedPayload Encrypt(
        ReadOnlySpan<byte> plaintext,
        ReadOnlySpan<byte> key,
        ReadOnlySpan<byte> associatedData)
    {
        ValidateKey(key);
        byte[] nonce = RandomNumberGenerator.GetBytes(NonceLength);
        byte[] ciphertext = GC.AllocateUninitializedArray<byte>(plaintext.Length);
        byte[] tag = GC.AllocateUninitializedArray<byte>(TagLength);
        try
        {
            using var aes = new AesGcm(key, TagLength);
            aes.Encrypt(nonce, plaintext, ciphertext, tag, associatedData);
            return new EncryptedPayload(nonce, ciphertext, tag);
        }
        catch
        {
            CryptographicOperations.ZeroMemory(nonce);
            CryptographicOperations.ZeroMemory(ciphertext);
            CryptographicOperations.ZeroMemory(tag);
            throw;
        }
    }

    public static byte[] Decrypt(
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> ciphertext,
        ReadOnlySpan<byte> tag,
        ReadOnlySpan<byte> key,
        ReadOnlySpan<byte> associatedData)
    {
        ValidateKey(key);
        if (nonce.Length != NonceLength)
        {
            throw new CryptographicException("The encrypted record nonce length is invalid.");
        }

        if (tag.Length != TagLength)
        {
            throw new CryptographicException("The encrypted record tag length is invalid.");
        }

        byte[] plaintext = GC.AllocateUninitializedArray<byte>(ciphertext.Length);
        try
        {
            using var aes = new AesGcm(key, TagLength);
            aes.Decrypt(nonce, ciphertext, tag, plaintext, associatedData);
            return plaintext;
        }
        catch
        {
            CryptographicOperations.ZeroMemory(plaintext);
            throw;
        }
    }

    private static void ValidateKey(ReadOnlySpan<byte> key)
    {
        if (key.Length != KeyLength)
        {
            throw new ArgumentException("The v2 encryption key must contain 32 bytes.", nameof(key));
        }
    }
}
