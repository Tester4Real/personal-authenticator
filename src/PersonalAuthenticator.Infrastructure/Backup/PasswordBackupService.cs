using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Logging;
using PersonalAuthenticator.Core.Abstractions;
using PersonalAuthenticator.Core.Domain;
using PersonalAuthenticator.Core.Exceptions;
using PersonalAuthenticator.Infrastructure.Logging;
using PersonalAuthenticator.Infrastructure.Serialization;
using PersonalAuthenticator.Infrastructure.Storage;

namespace PersonalAuthenticator.Infrastructure.Backup;

public sealed class PasswordBackupService : IBackupService
{
    private static readonly byte[] Magic = "PABKUP01"u8.ToArray();
    private const ushort FormatVersion = 1;
    private const byte KdfPbkdf2Sha512 = 1;
    public const int DefaultIterations = 600_000;
    private const int SaltLength = 16;
    private const int NonceLength = 12;
    private const int TagLength = 16;
    private const int FixedHeaderLength = 8 + 2 + 1 + 1 + 4 + 1 + 1 + 1 + 1 + 4;
    private const int MaximumBackupBytes = 64 * 1024 * 1024;
    private readonly ILogger<PasswordBackupService> _logger;
    private readonly int _iterations;

    public PasswordBackupService(
        ILogger<PasswordBackupService> logger,
        int iterations = DefaultIterations)
    {
        if (iterations is < 100_000 or > 5_000_000)
        {
            throw new ArgumentOutOfRangeException(nameof(iterations));
        }

        _logger = logger;
        _iterations = iterations;
    }

    public async Task ExportAsync(
        string path,
        ReadOnlyMemory<char> password,
        IReadOnlyCollection<TotpAccount> accounts,
        bool overwriteExisting,
        CancellationToken cancellationToken)
    {
        ValidatePassword(password.Span);
        if (!overwriteExisting && File.Exists(path))
        {
            throw new SafeApplicationException(
                "Backup.FileExists",
                "A file already exists at the selected location. Confirm replacement in the save dialog first.");
        }

        byte[] plaintext = VaultJsonSerializer.Serialize(accounts);
        byte[] salt = RandomNumberGenerator.GetBytes(SaltLength);
        byte[] nonce = RandomNumberGenerator.GetBytes(NonceLength);
        char[] passwordCharacters = password.ToArray();
        byte[] passwordBytes = Encoding.UTF8.GetBytes(passwordCharacters);
        byte[] key = GC.AllocateUninitializedArray<byte>(32);
        byte[] ciphertext = GC.AllocateUninitializedArray<byte>(plaintext.Length);
        byte[] tag = GC.AllocateUninitializedArray<byte>(TagLength);
        byte[] envelope = [];
        try
        {
            envelope = await Task.Run(
                () =>
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    Rfc2898DeriveBytes.Pbkdf2(
                        passwordBytes,
                        salt,
                        key,
                        _iterations,
                        HashAlgorithmName.SHA512);
                    cancellationToken.ThrowIfCancellationRequested();
                    byte[] header = CreateHeader(ciphertext.Length, salt, nonce, _iterations);
                    using (var aes = new AesGcm(key, TagLength))
                    {
                        aes.Encrypt(nonce, plaintext, ciphertext, tag, header);
                    }

                    cancellationToken.ThrowIfCancellationRequested();
                    byte[] result = GC.AllocateUninitializedArray<byte>(
                        header.Length + ciphertext.Length + tag.Length);
                    header.CopyTo(result, 0);
                    ciphertext.CopyTo(result, header.Length);
                    tag.CopyTo(result, header.Length + ciphertext.Length);
                    return result;
                },
                cancellationToken).ConfigureAwait(false);
            try
            {
                await AtomicFile.WriteAsync(
                    path,
                    envelope,
                    retainPrevious: false,
                    overwriteExisting,
                    cancellationToken).ConfigureAwait(false);
            }
            catch (IOException exception) when (!overwriteExisting && File.Exists(path))
            {
                throw new SafeApplicationException(
                    "Backup.FileExists",
                    "A file already exists at the selected location. Confirm replacement in the save dialog first.",
                    exception);
            }

            InfrastructureLog.BackupExported(_logger, accounts.Count);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext);
            CryptographicOperations.ZeroMemory(passwordBytes);
            CryptographicOperations.ZeroMemory(System.Runtime.InteropServices.MemoryMarshal.AsBytes(passwordCharacters.AsSpan()));
            CryptographicOperations.ZeroMemory(key);
            CryptographicOperations.ZeroMemory(ciphertext);
            CryptographicOperations.ZeroMemory(tag);
            CryptographicOperations.ZeroMemory(envelope);
            CryptographicOperations.ZeroMemory(salt);
            CryptographicOperations.ZeroMemory(nonce);
        }
    }

    public async Task<IReadOnlyList<TotpAccount>> ImportAsync(
        string path,
        ReadOnlyMemory<char> password,
        CancellationToken cancellationToken)
    {
        ValidatePassword(password.Span);
        var file = new FileInfo(path);
        if (!file.Exists || file.Length is < FixedHeaderLength or > MaximumBackupBytes)
        {
            throw new SafeApplicationException("Backup.InvalidFile", "The backup file is missing, invalid, or too large.");
        }

        byte[] envelope = await File.ReadAllBytesAsync(path, cancellationToken).ConfigureAwait(false);
        char[] passwordCharacters = password.ToArray();
        byte[] passwordBytes = Encoding.UTF8.GetBytes(passwordCharacters);
        byte[] key = GC.AllocateUninitializedArray<byte>(32);
        byte[] plaintext = [];
        try
        {
            return await Task.Run(
                () =>
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    ParsedHeader header = ParseHeader(envelope);
                    plaintext = GC.AllocateUninitializedArray<byte>(header.CiphertextLength);
                    Rfc2898DeriveBytes.Pbkdf2(
                        passwordBytes,
                        header.Salt.Span,
                        key,
                        header.Iterations,
                        HashAlgorithmName.SHA512);
                    cancellationToken.ThrowIfCancellationRequested();
                    try
                    {
                        using var aes = new AesGcm(key, TagLength);
                        aes.Decrypt(
                            header.Nonce.Span,
                            header.Ciphertext.Span,
                            header.Tag.Span,
                            plaintext,
                            header.AuthenticatedHeader.Span);
                    }
                    catch (CryptographicException exception)
                    {
                        InfrastructureLog.BackupAuthenticationFailed(_logger, exception.GetType().Name);
                        throw new SafeApplicationException(
                            "Backup.AuthenticationFailed",
                            "The backup password is incorrect or the backup was modified.",
                            exception);
                    }

                    cancellationToken.ThrowIfCancellationRequested();
                    return VaultJsonSerializer.Deserialize(plaintext);
                },
                cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(envelope);
            CryptographicOperations.ZeroMemory(passwordBytes);
            CryptographicOperations.ZeroMemory(System.Runtime.InteropServices.MemoryMarshal.AsBytes(passwordCharacters.AsSpan()));
            CryptographicOperations.ZeroMemory(key);
            CryptographicOperations.ZeroMemory(plaintext);
        }
    }

    private static byte[] CreateHeader(int ciphertextLength, byte[] salt, byte[] nonce, int iterations)
    {
        byte[] header = GC.AllocateUninitializedArray<byte>(FixedHeaderLength + salt.Length + nonce.Length);
        Magic.CopyTo(header, 0);
        BinaryPrimitives.WriteUInt16LittleEndian(header.AsSpan(8, 2), FormatVersion);
        header[10] = KdfPbkdf2Sha512;
        header[11] = 0;
        BinaryPrimitives.WriteInt32LittleEndian(header.AsSpan(12, 4), iterations);
        header[16] = SaltLength;
        header[17] = NonceLength;
        header[18] = TagLength;
        header[19] = 0;
        BinaryPrimitives.WriteInt32LittleEndian(header.AsSpan(20, 4), ciphertextLength);
        salt.CopyTo(header, FixedHeaderLength);
        nonce.CopyTo(header, FixedHeaderLength + salt.Length);
        return header;
    }

    private static ParsedHeader ParseHeader(byte[] envelope)
    {
        ReadOnlySpan<byte> span = envelope;
        if (span.Length < FixedHeaderLength || !span[..Magic.Length].SequenceEqual(Magic))
        {
            throw new SafeApplicationException("Backup.InvalidMagic", "The selected file is not a Personal Authenticator backup.");
        }

        ushort version = BinaryPrimitives.ReadUInt16LittleEndian(span[8..10]);
        if (version != FormatVersion)
        {
            throw new SafeApplicationException("Backup.UnsupportedVersion", "The backup format version is not supported.");
        }

        byte kdf = span[10];
        int iterations = BinaryPrimitives.ReadInt32LittleEndian(span[12..16]);
        int saltLength = span[16];
        int nonceLength = span[17];
        int tagLength = span[18];
        int ciphertextLength = BinaryPrimitives.ReadInt32LittleEndian(span[20..24]);
        if (kdf != KdfPbkdf2Sha512 ||
            iterations is < 100_000 or > 5_000_000 ||
            saltLength != SaltLength ||
            nonceLength != NonceLength ||
            tagLength != TagLength ||
            ciphertextLength < 0)
        {
            throw new SafeApplicationException("Backup.InvalidParameters", "The backup encryption parameters are invalid.");
        }

        int headerLength = FixedHeaderLength + saltLength + nonceLength;
        long expectedLength = headerLength + (long)ciphertextLength + tagLength;
        if (expectedLength != envelope.LongLength)
        {
            throw new SafeApplicationException("Backup.InvalidLength", "The backup file is truncated or corrupt.");
        }

        return new ParsedHeader(
            iterations,
            ciphertextLength,
            envelope.AsMemory(0, headerLength),
            envelope.AsMemory(FixedHeaderLength, saltLength),
            envelope.AsMemory(FixedHeaderLength + saltLength, nonceLength),
            envelope.AsMemory(headerLength, ciphertextLength),
            envelope.AsMemory(headerLength + ciphertextLength, tagLength));
    }

    private static void ValidatePassword(ReadOnlySpan<char> password)
    {
        if (password.Length is < 12 or > 1024)
        {
            throw new SafeApplicationException(
                "Backup.WeakPassword",
                "Use a backup password containing at least 12 characters.");
        }
    }

    private sealed record ParsedHeader(
        int Iterations,
        int CiphertextLength,
        ReadOnlyMemory<byte> AuthenticatedHeader,
        ReadOnlyMemory<byte> Salt,
        ReadOnlyMemory<byte> Nonce,
        ReadOnlyMemory<byte> Ciphertext,
        ReadOnlyMemory<byte> Tag);
}
