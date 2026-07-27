using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Konscious.Security.Cryptography;
using PersonalAuthenticator.Core.Exceptions;
using PersonalAuthenticator.Infrastructure.Storage;

namespace PersonalAuthenticator.Infrastructure.Sync;

internal static class LocalFolderSyncManifest
{
    private static readonly byte[] Magic = "PAVSYNC4"u8.ToArray();
    private static readonly byte[] VerifierLabel =
        SHA256.HashData("Personal Authenticator local sync verifier"u8);
    private const ushort Version = 1;
    private const int HeaderLength = 84;
    private const int FileLength = 132;
    private const int MemoryKiB = 64 * 1024;
    private const int Iterations = 3;
    private const int Parallelism = 2;

    public static async Task<LocalFolderSyncConfig> OpenOrCreateAsync(
        string folderPath,
        ReadOnlyMemory<char> password,
        int memoryKiB,
        int iterations,
        int parallelism,
        CancellationToken cancellationToken)
    {
        if (password.Length is < 12 or > 1024)
        {
            throw new SafeApplicationException(
                "Sync.WeakPassword",
                "Use a local sync password containing 12 to 1024 characters.");
        }

        string folder = Path.GetFullPath(folderPath);
        Directory.CreateDirectory(folder);
        string manifestPath = Path.Combine(folder, "PersonalAuthenticator.sync");
        if (File.Exists(manifestPath))
        {
            return await OpenAsync(
                manifestPath,
                folder,
                password,
                cancellationToken);
        }

        ValidateKdf(memoryKiB, iterations, parallelism);
        Guid repositoryId = Guid.NewGuid();
        Guid generationId = Guid.NewGuid();
        byte[] salt = RandomNumberGenerator.GetBytes(16);
        byte[] nonce = RandomNumberGenerator.GetBytes(12);
        byte[] key = [];
        byte[] verifier = CreateVerifier(repositoryId, generationId);
        byte[] ciphertext = new byte[32];
        byte[] tag = new byte[16];
        byte[] manifest = new byte[FileLength];
        try
        {
            WriteHeader(
                manifest,
                repositoryId,
                generationId,
                memoryKiB,
                iterations,
                parallelism,
                salt,
                nonce);
            key = await DeriveKeyAsync(
                password,
                salt,
                memoryKiB,
                iterations,
                parallelism,
                cancellationToken);
            using (var aes = new AesGcm(key, 16))
            {
                aes.Encrypt(
                    nonce,
                    verifier,
                    ciphertext,
                    tag,
                    manifest.AsSpan(0, HeaderLength));
            }

            ciphertext.CopyTo(manifest, HeaderLength);
            tag.CopyTo(manifest, HeaderLength + ciphertext.Length);
            try
            {
                await AtomicFile.WriteAsync(
                    manifestPath,
                    manifest,
                    retainPrevious: false,
                    overwriteExisting: false,
                    cancellationToken);
            }
            catch (IOException) when (File.Exists(manifestPath))
            {
                CryptographicOperations.ZeroMemory(key);
                return await OpenAsync(
                    manifestPath,
                    folder,
                    password,
                    cancellationToken);
            }

            byte[] returnedKey = key.ToArray();
            return new LocalFolderSyncConfig(
                folder,
                repositoryId,
                generationId,
                returnedKey,
                LastSuccessfulSyncAtUtc: null);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(salt);
            CryptographicOperations.ZeroMemory(nonce);
            CryptographicOperations.ZeroMemory(key);
            CryptographicOperations.ZeroMemory(verifier);
            CryptographicOperations.ZeroMemory(ciphertext);
            CryptographicOperations.ZeroMemory(tag);
            CryptographicOperations.ZeroMemory(manifest);
        }
    }

    public static Task<LocalFolderSyncConfig> OpenOrCreateAsync(
        string folderPath,
        ReadOnlyMemory<char> password,
        CancellationToken cancellationToken) =>
        OpenOrCreateAsync(
            folderPath,
            password,
            MemoryKiB,
            Iterations,
            Parallelism,
            cancellationToken);

    private static async Task<LocalFolderSyncConfig> OpenAsync(
        string manifestPath,
        string folderPath,
        ReadOnlyMemory<char> password,
        CancellationToken cancellationToken)
    {
        byte[] manifest = await File.ReadAllBytesAsync(
            manifestPath,
            cancellationToken);
        byte[] key = [];
        byte[] verifier = [];
        try
        {
            if (manifest.Length != FileLength ||
                !manifest.AsSpan(0, 8).SequenceEqual(Magic) ||
                BinaryPrimitives.ReadUInt16LittleEndian(
                    manifest.AsSpan(8, 2)) != Version ||
                BinaryPrimitives.ReadUInt16LittleEndian(
                    manifest.AsSpan(10, 2)) != 0)
            {
                throw InvalidManifest();
            }

            Guid repositoryId = new(manifest.AsSpan(12, 16));
            Guid generationId = new(manifest.AsSpan(28, 16));
            int memoryKiB = BinaryPrimitives.ReadInt32LittleEndian(
                manifest.AsSpan(44, 4));
            int iterations = BinaryPrimitives.ReadInt32LittleEndian(
                manifest.AsSpan(48, 4));
            int parallelism = BinaryPrimitives.ReadInt32LittleEndian(
                manifest.AsSpan(52, 4));
            ValidateKdf(memoryKiB, iterations, parallelism);
            byte[] salt = manifest.AsSpan(56, 16).ToArray();
            byte[] nonce = manifest.AsSpan(72, 12).ToArray();
            try
            {
                key = await DeriveKeyAsync(
                    password,
                    salt,
                    memoryKiB,
                    iterations,
                    parallelism,
                    cancellationToken);
                verifier = new byte[32];
                try
                {
                    using var aes = new AesGcm(key, 16);
                    aes.Decrypt(
                        nonce,
                        manifest.AsSpan(HeaderLength, 32),
                        manifest.AsSpan(HeaderLength + 32, 16),
                        verifier,
                        manifest.AsSpan(0, HeaderLength));
                }
                catch (AuthenticationTagMismatchException exception)
                {
                    throw new SafeApplicationException(
                        "Sync.AuthenticationFailed",
                        "The local-folder sync password is incorrect or the manifest was modified.",
                        exception);
                }

                byte[] expected = CreateVerifier(repositoryId, generationId);
                try
                {
                    if (!CryptographicOperations.FixedTimeEquals(verifier, expected))
                    {
                        throw InvalidManifest();
                    }
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(expected);
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(salt);
                CryptographicOperations.ZeroMemory(nonce);
            }

            byte[] returnedKey = key.ToArray();
            return new LocalFolderSyncConfig(
                folderPath,
                repositoryId,
                generationId,
                returnedKey,
                LastSuccessfulSyncAtUtc: null);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(manifest);
            CryptographicOperations.ZeroMemory(key);
            CryptographicOperations.ZeroMemory(verifier);
        }
    }

    private static void WriteHeader(
        Span<byte> manifest,
        Guid repositoryId,
        Guid generationId,
        int memoryKiB,
        int iterations,
        int parallelism,
        ReadOnlySpan<byte> salt,
        ReadOnlySpan<byte> nonce)
    {
        Magic.CopyTo(manifest);
        BinaryPrimitives.WriteUInt16LittleEndian(manifest[8..10], Version);
        BinaryPrimitives.WriteUInt16LittleEndian(manifest[10..12], 0);
        repositoryId.TryWriteBytes(manifest[12..28]);
        generationId.TryWriteBytes(manifest[28..44]);
        BinaryPrimitives.WriteInt32LittleEndian(manifest[44..48], memoryKiB);
        BinaryPrimitives.WriteInt32LittleEndian(manifest[48..52], iterations);
        BinaryPrimitives.WriteInt32LittleEndian(manifest[52..56], parallelism);
        salt.CopyTo(manifest[56..72]);
        nonce.CopyTo(manifest[72..84]);
    }

    private static byte[] CreateVerifier(Guid repositoryId, Guid generationId)
    {
        byte[] input = new byte[VerifierLabel.Length + 32];
        VerifierLabel.CopyTo(input, 0);
        repositoryId.TryWriteBytes(input.AsSpan(VerifierLabel.Length, 16));
        generationId.TryWriteBytes(input.AsSpan(VerifierLabel.Length + 16, 16));
        try
        {
            return SHA256.HashData(input);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(input);
        }
    }

    private static async Task<byte[]> DeriveKeyAsync(
        ReadOnlyMemory<char> password,
        byte[] salt,
        int memoryKiB,
        int iterations,
        int parallelism,
        CancellationToken cancellationToken)
    {
        char[] chars = password.ToArray();
        byte[] passwordBytes = Encoding.UTF8.GetBytes(chars);
        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            using var argon = new Argon2id(passwordBytes)
            {
                Salt = salt,
                MemorySize = memoryKiB,
                Iterations = iterations,
                DegreeOfParallelism = parallelism,
            };
            byte[] key = await argon.GetBytesAsync(32);
            cancellationToken.ThrowIfCancellationRequested();
            return key;
        }
        finally
        {
            Array.Clear(chars);
            CryptographicOperations.ZeroMemory(passwordBytes);
        }
    }

    private static void ValidateKdf(int memoryKiB, int iterations, int parallelism)
    {
        if (memoryKiB is < 8192 or > 262144 ||
            iterations is < 1 or > 10 ||
            parallelism is < 1 or > 16)
        {
            throw InvalidManifest();
        }
    }

    private static SafeApplicationException InvalidManifest() =>
        new(
            "Sync.InvalidManifest",
            "The local-folder sync manifest is invalid or unsupported.");
}
