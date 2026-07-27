using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Konscious.Security.Cryptography;
using PersonalAuthenticator.Core.Exceptions;
using PersonalAuthenticator.Infrastructure.Sync;

namespace PersonalAuthenticator.Infrastructure.GitHub;

internal static class GitHubRemoteProtocol
{
    public const int ProtocolVersion = 1;
    public const string RequiredFeature = "immutable-operations-v1";
    private static readonly byte[] ObjectMagic = "PAVGHO01"u8.ToArray();
    private const int ObjectHeaderLength = 84;
    private const int TagLength = 16;

    public static async Task<(GitHubRemoteDescriptor Descriptor, byte[] Key)>
        CreateDescriptorAsync(
            long repositoryId,
            Guid vaultId,
            Guid generation,
            ReadOnlyMemory<char> password,
            CancellationToken cancellationToken)
    {
        ValidatePassword(password);
        byte[] salt = RandomNumberGenerator.GetBytes(16);
        byte[] key = await DeriveKeyAsync(password, salt, cancellationToken);
        byte[] nonce = RandomNumberGenerator.GetBytes(12);
        byte[] verifier = CreateVerifier(repositoryId, vaultId, generation);
        byte[] ciphertext = new byte[32];
        byte[] tag = new byte[16];
        try
        {
            using var aes = new AesGcm(key, 16);
            aes.Encrypt(nonce, verifier, ciphertext, tag);
            return (
                new GitHubRemoteDescriptor(
                    ProtocolVersion,
                    [RequiredFeature],
                    repositoryId,
                    vaultId,
                    generation,
                    Convert.ToBase64String(salt),
                    Convert.ToBase64String(nonce),
                    Convert.ToBase64String(ciphertext),
                    Convert.ToBase64String(tag)),
                key);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(salt);
            CryptographicOperations.ZeroMemory(nonce);
            CryptographicOperations.ZeroMemory(verifier);
            CryptographicOperations.ZeroMemory(ciphertext);
            CryptographicOperations.ZeroMemory(tag);
        }
    }

    public static async Task<byte[]> OpenDescriptorAsync(
        GitHubRemoteDescriptor descriptor,
        long repositoryId,
        ReadOnlyMemory<char> password,
        CancellationToken cancellationToken)
    {
        if (descriptor.ProtocolVersion != ProtocolVersion ||
            descriptor.RequiredFeatures.Any(feature => feature != RequiredFeature))
        {
            throw new SafeApplicationException(
                "GitHub.UnsupportedRequiredFeature",
                "The repository requires a newer sync protocol.");
        }

        if (descriptor.RepositoryId != repositoryId ||
            descriptor.VaultId == Guid.Empty ||
            descriptor.RemoteGeneration == Guid.Empty)
        {
            throw new SafeApplicationException(
                "GitHub.WrongVaultRepository",
                "This repository belongs to a different authenticator vault or repository identity.");
        }

        byte[] salt = Decode(descriptor.Salt, 16);
        byte[] nonce = Decode(descriptor.Nonce, 12);
        byte[] ciphertext = Decode(descriptor.VerifierCiphertext, 32);
        byte[] tag = Decode(descriptor.VerifierTag, 16);
        byte[] key = await DeriveKeyAsync(password, salt, cancellationToken);
        byte[] actual = new byte[32];
        byte[] expected = CreateVerifier(
            repositoryId,
            descriptor.VaultId,
            descriptor.RemoteGeneration);
        try
        {
            try
            {
                using var aes = new AesGcm(key, 16);
                aes.Decrypt(nonce, ciphertext, tag, actual);
            }
            catch (AuthenticationTagMismatchException exception)
            {
                throw new SafeApplicationException(
                    "GitHub.SyncPasswordInvalid",
                    "The GitHub sync password is incorrect or the descriptor was modified.",
                    exception);
            }

            if (!CryptographicOperations.FixedTimeEquals(actual, expected))
            {
                throw new SafeApplicationException(
                    "GitHub.DescriptorInvalid",
                    "The GitHub sync descriptor is invalid.");
            }

            return key;
        }
        catch
        {
            CryptographicOperations.ZeroMemory(key);
            throw;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(salt);
            CryptographicOperations.ZeroMemory(nonce);
            CryptographicOperations.ZeroMemory(ciphertext);
            CryptographicOperations.ZeroMemory(tag);
            CryptographicOperations.ZeroMemory(actual);
            CryptographicOperations.ZeroMemory(expected);
        }
    }

    public static byte[] SerializeDescriptor(GitHubRemoteDescriptor descriptor) =>
        JsonSerializer.SerializeToUtf8Bytes(descriptor);

    public static GitHubRemoteDescriptor DeserializeDescriptor(
        ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length is < 64 or > 16 * 1024)
        {
            throw InvalidRemote();
        }

        try
        {
            return JsonSerializer.Deserialize<GitHubRemoteDescriptor>(bytes) ??
                throw InvalidRemote();
        }
        catch (JsonException exception)
        {
            throw new SafeApplicationException(
                "GitHub.DescriptorInvalid",
                "The GitHub sync descriptor is malformed.",
                exception);
        }
    }

    public static byte[] EncryptOperation(
        GitHubSyncConfiguration configuration,
        SyncOperation operation)
    {
        byte[] plaintext = SyncOperationSerializer.Serialize(operation);
        try
        {
            return Encrypt(
                configuration.RepositoryId,
                configuration.VaultId,
                configuration.RemoteGeneration,
                operation.Id,
                configuration.SyncKey,
                plaintext);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext);
        }
    }

    public static SyncOperation DecryptOperation(
        GitHubSyncConfiguration configuration,
        ReadOnlySpan<byte> envelope)
    {
        (Guid objectId, byte[] plaintext) = Decrypt(configuration, envelope);
        try
        {
            SyncOperation operation = SyncOperationSerializer.Deserialize(plaintext);
            if (operation.Id != objectId)
            {
                operation.Dispose();
                throw InvalidRemote();
            }

            return operation;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext);
        }
    }

    public static byte[] EncryptMetadata(
        GitHubSyncConfiguration configuration,
        Guid objectId,
        ReadOnlySpan<byte> plaintext) =>
        Encrypt(
            configuration.RepositoryId,
            configuration.VaultId,
            configuration.RemoteGeneration,
            objectId,
            configuration.SyncKey,
            plaintext);

    private static byte[] Encrypt(
        long repositoryId,
        Guid vaultId,
        Guid generation,
        Guid objectId,
        byte[] key,
        ReadOnlySpan<byte> plaintext)
    {
        byte[] nonce = CreateObjectNonce(
            repositoryId,
            vaultId,
            generation,
            objectId,
            key);
        byte[] result = new byte[ObjectHeaderLength + plaintext.Length + TagLength];
        try
        {
            ObjectMagic.CopyTo(result, 0);
            BinaryPrimitives.WriteUInt16LittleEndian(result.AsSpan(8, 2), 1);
            BinaryPrimitives.WriteUInt16LittleEndian(result.AsSpan(10, 2), 0);
            BinaryPrimitives.WriteInt64LittleEndian(result.AsSpan(12, 8), repositoryId);
            vaultId.TryWriteBytes(result.AsSpan(20, 16));
            generation.TryWriteBytes(result.AsSpan(36, 16));
            objectId.TryWriteBytes(result.AsSpan(52, 16));
            nonce.CopyTo(result, 68);
            BinaryPrimitives.WriteInt32LittleEndian(
                result.AsSpan(80, 4),
                plaintext.Length);
            using var aes = new AesGcm(key, TagLength);
            aes.Encrypt(
                nonce,
                plaintext,
                result.AsSpan(ObjectHeaderLength, plaintext.Length),
                result.AsSpan(ObjectHeaderLength + plaintext.Length, TagLength),
                result.AsSpan(0, ObjectHeaderLength));
            return result;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(nonce);
        }
    }

    private static (Guid ObjectId, byte[] Plaintext) Decrypt(
        GitHubSyncConfiguration configuration,
        ReadOnlySpan<byte> envelope)
    {
        if (envelope.Length is < ObjectHeaderLength + TagLength or >
                ObjectHeaderLength +
                SyncOperationSerializer.MaximumOperationBytes +
                TagLength ||
            !envelope[..8].SequenceEqual(ObjectMagic))
        {
            throw InvalidRemote();
        }

        if (BinaryPrimitives.ReadUInt16LittleEndian(envelope[8..10]) != 1 ||
            BinaryPrimitives.ReadUInt16LittleEndian(envelope[10..12]) != 0)
        {
            throw new SafeApplicationException(
                "GitHub.UnsupportedRequiredFeature",
                "The repository contains objects requiring a newer protocol.");
        }

        long repositoryId = BinaryPrimitives.ReadInt64LittleEndian(envelope[12..20]);
        Guid vaultId = new(envelope[20..36]);
        Guid generation = new(envelope[36..52]);
        Guid objectId = new(envelope[52..68]);
        int length = BinaryPrimitives.ReadInt32LittleEndian(envelope[80..84]);
        if (repositoryId != configuration.RepositoryId ||
            vaultId != configuration.VaultId ||
            generation != configuration.RemoteGeneration ||
            objectId == Guid.Empty ||
            length is < 64 or > SyncOperationSerializer.MaximumOperationBytes ||
            envelope.Length != ObjectHeaderLength + length + TagLength)
        {
            throw InvalidRemote();
        }

        byte[] plaintext = new byte[length];
        try
        {
            using var aes = new AesGcm(configuration.SyncKey, TagLength);
            aes.Decrypt(
                envelope[68..80],
                envelope.Slice(ObjectHeaderLength, length),
                envelope.Slice(ObjectHeaderLength + length, TagLength),
                plaintext,
                envelope[..ObjectHeaderLength]);
            return (objectId, plaintext);
        }
        catch
        {
            CryptographicOperations.ZeroMemory(plaintext);
            throw;
        }
    }

    private static async Task<byte[]> DeriveKeyAsync(
        ReadOnlyMemory<char> password,
        byte[] salt,
        CancellationToken cancellationToken)
    {
        ValidatePassword(password);
        char[] characters = password.ToArray();
        byte[] bytes = Encoding.UTF8.GetBytes(characters);
        try
        {
            using var argon = new Argon2id(bytes)
            {
                Salt = salt,
                MemorySize = 64 * 1024,
                Iterations = 3,
                DegreeOfParallelism = 2,
            };
            byte[] key = await argon.GetBytesAsync(32);
            cancellationToken.ThrowIfCancellationRequested();
            return key;
        }
        finally
        {
            Array.Clear(characters);
            CryptographicOperations.ZeroMemory(bytes);
        }
    }

    private static byte[] CreateVerifier(
        long repositoryId,
        Guid vaultId,
        Guid generation)
    {
        Span<byte> input = stackalloc byte[40];
        BinaryPrimitives.WriteInt64LittleEndian(input[..8], repositoryId);
        vaultId.TryWriteBytes(input[8..24]);
        generation.TryWriteBytes(input[24..40]);
        return SHA256.HashData(input);
    }

    private static byte[] CreateObjectNonce(
        long repositoryId,
        Guid vaultId,
        Guid generation,
        Guid objectId,
        byte[] key)
    {
        Span<byte> input = stackalloc byte[56];
        BinaryPrimitives.WriteInt64LittleEndian(input[..8], repositoryId);
        vaultId.TryWriteBytes(input[8..24]);
        generation.TryWriteBytes(input[24..40]);
        objectId.TryWriteBytes(input[40..56]);
        byte[] digest = HMACSHA256.HashData(key, input);
        try
        {
            return digest[..12];
        }
        finally
        {
            CryptographicOperations.ZeroMemory(digest);
        }
    }

    private static byte[] Decode(string value, int expectedLength)
    {
        try
        {
            byte[] bytes = Convert.FromBase64String(value);
            return bytes.Length == expectedLength ? bytes : throw InvalidRemote();
        }
        catch (FormatException exception)
        {
            throw new SafeApplicationException(
                "GitHub.DescriptorInvalid",
                "The GitHub sync descriptor is malformed.",
                exception);
        }
    }

    private static void ValidatePassword(ReadOnlyMemory<char> password)
    {
        if (password.Length is < 12 or > 1024)
        {
            throw new SafeApplicationException(
                "GitHub.WeakSyncPassword",
                "Use a GitHub sync password containing 12 to 1024 characters.");
        }
    }

    private static SafeApplicationException InvalidRemote() =>
        new(
            "GitHub.InvalidRemoteObject",
            "A GitHub sync object is malformed, corrupt, or belongs to another vault.");
}

internal sealed record GitHubRemoteDescriptor(
    int ProtocolVersion,
    IReadOnlyList<string> RequiredFeatures,
    long RepositoryId,
    Guid VaultId,
    Guid RemoteGeneration,
    string Salt,
    string Nonce,
    string VerifierCiphertext,
    string VerifierTag);
