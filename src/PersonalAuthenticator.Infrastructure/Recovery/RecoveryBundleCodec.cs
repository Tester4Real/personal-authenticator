using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Konscious.Security.Cryptography;
using PersonalAuthenticator.Core.Domain;
using PersonalAuthenticator.Core.Exceptions;

namespace PersonalAuthenticator.Infrastructure.Recovery;

internal sealed class RecoveryBundleCodec
{
    private static readonly byte[] Magic = "PAVREC03"u8.ToArray();
    private const ushort FormatVersion = 1;
    private const int HeaderLength = 56;
    private const int SaltLength = 16;
    private const int NonceLength = 12;
    private const int TagLength = 16;
    private const int KeyLength = 32;
    private const int MaximumBundleBytes = 128 * 1024 * 1024;
    private readonly int _memorySizeKiB;
    private readonly int _iterations;
    private readonly int _parallelism;

    public RecoveryBundleCodec(
        int memorySizeKiB = 64 * 1024,
        int iterations = 3,
        int parallelism = 2)
    {
        ValidateKdfParameters(memorySizeKiB, iterations, parallelism);
        _memorySizeKiB = memorySizeKiB;
        _iterations = iterations;
        _parallelism = parallelism;
    }

    public async Task<byte[]> EncryptAsync(
        RecoverySlot slot,
        V2VaultSnapshot snapshot,
        ReadOnlyMemory<char> password,
        DateTimeOffset createdAtUtc,
        CancellationToken cancellationToken)
    {
        ValidatePassword(password);
        byte[] plaintext = RecoveryPayloadSerializer.Serialize(snapshot, createdAtUtc);
        byte[] passwordBytes = EncodePassword(password);
        byte[] salt = RandomNumberGenerator.GetBytes(SaltLength);
        byte[] nonce = RandomNumberGenerator.GetBytes(NonceLength);
        byte[] key = [];
        byte[] ciphertext = GC.AllocateUninitializedArray<byte>(plaintext.Length);
        byte[] tag = GC.AllocateUninitializedArray<byte>(TagLength);
        byte[] header = CreateHeader(
            slot,
            _memorySizeKiB,
            _iterations,
            _parallelism,
            salt,
            nonce,
            ciphertext.Length);
        try
        {
            key = await DeriveKeyAsync(
                passwordBytes,
                salt,
                _memorySizeKiB,
                _iterations,
                _parallelism,
                cancellationToken);
            using (var aes = new AesGcm(key, TagLength))
            {
                aes.Encrypt(nonce, plaintext, ciphertext, tag, header);
            }

            byte[] envelope = GC.AllocateUninitializedArray<byte>(
                checked(HeaderLength + ciphertext.Length + TagLength));
            header.CopyTo(envelope, 0);
            ciphertext.CopyTo(envelope, HeaderLength);
            tag.CopyTo(envelope, HeaderLength + ciphertext.Length);
            return envelope;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext);
            CryptographicOperations.ZeroMemory(passwordBytes);
            CryptographicOperations.ZeroMemory(salt);
            CryptographicOperations.ZeroMemory(nonce);
            CryptographicOperations.ZeroMemory(key);
            CryptographicOperations.ZeroMemory(ciphertext);
            CryptographicOperations.ZeroMemory(tag);
            CryptographicOperations.ZeroMemory(header);
        }
    }

    public async Task<DecodedRecoveryBundle> DecryptFileAsync(
        string filePath,
        ReadOnlyMemory<char> password,
        CancellationToken cancellationToken)
    {
        _ = _memorySizeKiB;
        ArgumentException.ThrowIfNullOrWhiteSpace(filePath);
        ValidatePassword(password);
        var file = new FileInfo(Path.GetFullPath(filePath));
        if (!file.Exists || file.Length is < HeaderLength + TagLength or > MaximumBundleBytes)
        {
            throw InvalidBundle("The recovery bundle has an invalid size.");
        }

        byte[] envelope;
        try
        {
            envelope = await File.ReadAllBytesAsync(file.FullName, cancellationToken);
        }
        catch (IOException exception)
        {
            throw new SafeApplicationException(
                "Recovery.ReadFailed",
                "The recovery bundle could not be read.",
                exception);
        }

        try
        {
            return await DecryptAsync(envelope, password, file.FullName, cancellationToken);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(envelope);
        }
    }

    public async Task<DecodedRecoveryBundle> DecryptAsync(
        ReadOnlyMemory<byte> envelope,
        ReadOnlyMemory<char> password,
        string filePath,
        CancellationToken cancellationToken)
    {
        _ = _memorySizeKiB;
        ValidatePassword(password);
        if (envelope.Length is < HeaderLength + TagLength or > MaximumBundleBytes)
        {
            throw InvalidBundle("The recovery bundle has an invalid size.");
        }

        byte[] header = envelope.Span[..HeaderLength].ToArray();
        if (!header.AsSpan(0, Magic.Length).SequenceEqual(Magic))
        {
            throw InvalidBundle("The selected file is not a recovery bundle.");
        }

        ushort version = BinaryPrimitives.ReadUInt16LittleEndian(header.AsSpan(8, 2));
        if (version != FormatVersion || header[11] != 0)
        {
            throw InvalidBundle("The recovery bundle version is not supported.");
        }

        var slot = (RecoverySlot)header[10];
        if (!Enum.IsDefined(slot))
        {
            throw InvalidBundle("The recovery slot is invalid.");
        }

        int memorySizeKiB = BinaryPrimitives.ReadInt32LittleEndian(header.AsSpan(12, 4));
        int iterations = BinaryPrimitives.ReadInt32LittleEndian(header.AsSpan(16, 4));
        int parallelism = BinaryPrimitives.ReadInt32LittleEndian(header.AsSpan(20, 4));
        try
        {
            ValidateKdfParameters(memorySizeKiB, iterations, parallelism);
        }
        catch (ArgumentOutOfRangeException exception)
        {
            throw new SafeApplicationException(
                "Recovery.InvalidBundle",
                "The recovery key-derivation parameters are unsafe or unsupported.",
                exception);
        }

        int ciphertextLength = BinaryPrimitives.ReadInt32LittleEndian(header.AsSpan(52, 4));
        if (ciphertextLength <= 0 ||
            ciphertextLength != envelope.Length - HeaderLength - TagLength)
        {
            throw InvalidBundle("The recovery bundle is truncated or malformed.");
        }

        byte[] salt = header.AsSpan(24, SaltLength).ToArray();
        byte[] nonce = header.AsSpan(40, NonceLength).ToArray();
        byte[] passwordBytes = EncodePassword(password);
        byte[] key = [];
        byte[] plaintext = GC.AllocateUninitializedArray<byte>(ciphertextLength);
        try
        {
            key = await DeriveKeyAsync(
                passwordBytes,
                salt,
                memorySizeKiB,
                iterations,
                parallelism,
                cancellationToken);
            try
            {
                using var aes = new AesGcm(key, TagLength);
                aes.Decrypt(
                    nonce,
                    envelope.Span.Slice(HeaderLength, ciphertextLength),
                    envelope.Span[^TagLength..],
                    plaintext,
                    header);
            }
            catch (AuthenticationTagMismatchException exception)
            {
                throw new SafeApplicationException(
                    "Recovery.AuthenticationFailed",
                    "The recovery password is incorrect or the bundle was modified.",
                    exception);
            }

            RecoveryPayload payload = RecoveryPayloadSerializer.Deserialize(plaintext);
            return new DecodedRecoveryBundle(slot, Path.GetFullPath(filePath), payload);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(salt);
            CryptographicOperations.ZeroMemory(nonce);
            CryptographicOperations.ZeroMemory(passwordBytes);
            CryptographicOperations.ZeroMemory(key);
            CryptographicOperations.ZeroMemory(plaintext);
        }
    }

    private static byte[] CreateHeader(
        RecoverySlot slot,
        int memorySizeKiB,
        int iterations,
        int parallelism,
        ReadOnlySpan<byte> salt,
        ReadOnlySpan<byte> nonce,
        int ciphertextLength)
    {
        byte[] header = GC.AllocateUninitializedArray<byte>(HeaderLength);
        Magic.CopyTo(header, 0);
        BinaryPrimitives.WriteUInt16LittleEndian(header.AsSpan(8, 2), FormatVersion);
        header[10] = (byte)slot;
        header[11] = 0;
        BinaryPrimitives.WriteInt32LittleEndian(header.AsSpan(12, 4), memorySizeKiB);
        BinaryPrimitives.WriteInt32LittleEndian(header.AsSpan(16, 4), iterations);
        BinaryPrimitives.WriteInt32LittleEndian(header.AsSpan(20, 4), parallelism);
        salt.CopyTo(header.AsSpan(24, SaltLength));
        nonce.CopyTo(header.AsSpan(40, NonceLength));
        BinaryPrimitives.WriteInt32LittleEndian(header.AsSpan(52, 4), ciphertextLength);
        return header;
    }

    private static async Task<byte[]> DeriveKeyAsync(
        byte[] password,
        byte[] salt,
        int memorySizeKiB,
        int iterations,
        int parallelism,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        using var argon2 = new Argon2id(password)
        {
            Salt = salt,
            MemorySize = memorySizeKiB,
            Iterations = iterations,
            DegreeOfParallelism = parallelism,
        };
        byte[] key = await argon2.GetBytesAsync(KeyLength);
        cancellationToken.ThrowIfCancellationRequested();
        return key;
    }

    private static byte[] EncodePassword(ReadOnlyMemory<char> password)
    {
        char[] characters = password.ToArray();
        try
        {
            return Encoding.UTF8.GetBytes(characters);
        }
        finally
        {
            Array.Clear(characters);
        }
    }

    private static void ValidatePassword(ReadOnlyMemory<char> password)
    {
        if (password.Length is < 12 or > 1024)
        {
            throw new SafeApplicationException(
                "Recovery.WeakPassword",
                "Use a recovery password containing 12 to 1024 characters.");
        }
    }

    private static void ValidateKdfParameters(
        int memorySizeKiB,
        int iterations,
        int parallelism)
    {
        if (memorySizeKiB is < 8192 or > 262144)
        {
            throw new ArgumentOutOfRangeException(nameof(memorySizeKiB));
        }

        if (iterations is < 1 or > 10)
        {
            throw new ArgumentOutOfRangeException(nameof(iterations));
        }

        if (parallelism is < 1 or > 16)
        {
            throw new ArgumentOutOfRangeException(nameof(parallelism));
        }
    }

    private static SafeApplicationException InvalidBundle(string message) =>
        new("Recovery.InvalidBundle", message);
}

internal sealed record DecodedRecoveryBundle(
    RecoverySlot Slot,
    string FilePath,
    RecoveryPayload Payload) : IDisposable
{
    public RecoveryBundleInfo ToInfo(DateTimeOffset verifiedAtUtc) =>
        new(
            Slot,
            FilePath,
            Payload.CreatedAtUtc,
            verifiedAtUtc.ToUniversalTime(),
            Payload.Snapshot.ChangeSequence,
            Payload.Snapshot.Accounts.Count,
            Payload.Snapshot.SecretVersions.Count,
            Payload.Snapshot.HistoryEntries.Count);

    public void Dispose() => Payload.Dispose();
}
