namespace PersonalAuthenticator.Infrastructure.Storage;

internal sealed record EncryptedPayload(byte[] Nonce, byte[] Ciphertext, byte[] Tag);
