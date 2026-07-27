using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using PersonalAuthenticator.Core.Exceptions;
using PersonalAuthenticator.Infrastructure.Storage;

namespace PersonalAuthenticator.Infrastructure.Sync;

internal sealed class LocalFolderSyncConfigStore
{
    private static readonly byte[] Magic = "PAVSCFG4"u8.ToArray();
    private static readonly byte[] Entropy =
        SHA256.HashData("Personal Authenticator local-folder sync config v1"u8);
    private const ushort Version = 1;
    private const int MaximumConfigBytes = 64 * 1024;
    private readonly string _path;

    public LocalFolderSyncConfigStore(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        _path = Path.GetFullPath(path);
    }

    public bool Exists => File.Exists(_path);

    public async Task SaveAsync(
        LocalFolderSyncConfig config,
        CancellationToken cancellationToken)
    {
        Validate(config);
        byte[] folderBytes = Encoding.UTF8.GetBytes(config.FolderPath);
        byte[] plaintext = GC.AllocateUninitializedArray<byte>(
            8 + 2 + 4 + folderBytes.Length + 16 + 16 + 32 + 8);
        byte[] protectedBytes = [];
        try
        {
            int offset = 0;
            Magic.CopyTo(plaintext, offset);
            offset += 8;
            BinaryPrimitives.WriteUInt16LittleEndian(
                plaintext.AsSpan(offset, 2),
                Version);
            offset += 2;
            BinaryPrimitives.WriteInt32LittleEndian(
                plaintext.AsSpan(offset, 4),
                folderBytes.Length);
            offset += 4;
            folderBytes.CopyTo(plaintext, offset);
            offset += folderBytes.Length;
            config.RepositoryId.TryWriteBytes(plaintext.AsSpan(offset, 16));
            offset += 16;
            config.GenerationId.TryWriteBytes(plaintext.AsSpan(offset, 16));
            offset += 16;
            config.SyncKey.CopyTo(plaintext.AsSpan(offset, 32));
            offset += 32;
            BinaryPrimitives.WriteInt64LittleEndian(
                plaintext.AsSpan(offset, 8),
                config.LastSuccessfulSyncAtUtc?.UtcTicks ?? 0);
            protectedBytes = ProtectedData.Protect(
                plaintext,
                Entropy,
                DataProtectionScope.CurrentUser);
            await AtomicFile.WriteAsync(
                _path,
                protectedBytes,
                retainPrevious: true,
                overwriteExisting: true,
                cancellationToken);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(folderBytes);
            CryptographicOperations.ZeroMemory(plaintext);
            CryptographicOperations.ZeroMemory(protectedBytes);
        }
    }

    public async Task<LocalFolderSyncConfig> LoadAsync(
        CancellationToken cancellationToken)
    {
        byte[] protectedBytes = [];
        byte[] plaintext = [];
        byte[] key = [];
        try
        {
            protectedBytes = await File.ReadAllBytesAsync(_path, cancellationToken);
            if (protectedBytes.Length is < 32 or > MaximumConfigBytes)
            {
                throw InvalidConfig();
            }

            plaintext = ProtectedData.Unprotect(
                protectedBytes,
                Entropy,
                DataProtectionScope.CurrentUser);
            ReadOnlySpan<byte> span = plaintext;
            if (span.Length < 86 || !span[..8].SequenceEqual(Magic))
            {
                throw InvalidConfig();
            }

            ushort version = BinaryPrimitives.ReadUInt16LittleEndian(span[8..10]);
            int folderLength = BinaryPrimitives.ReadInt32LittleEndian(span[10..14]);
            if (version != Version ||
                folderLength is < 1 or > 4096 ||
                plaintext.Length != 86 + folderLength)
            {
                throw InvalidConfig();
            }

            string folderPath = new UTF8Encoding(false, true).GetString(
                span.Slice(14, folderLength));
            int offset = 14 + folderLength;
            Guid repositoryId = new(span.Slice(offset, 16));
            offset += 16;
            Guid generationId = new(span.Slice(offset, 16));
            offset += 16;
            key = span.Slice(offset, 32).ToArray();
            offset += 32;
            long lastSyncTicks = BinaryPrimitives.ReadInt64LittleEndian(
                span.Slice(offset, 8));
            DateTimeOffset? lastSync = lastSyncTicks == 0
                ? null
                : new DateTimeOffset(lastSyncTicks, TimeSpan.Zero);
            var config = new LocalFolderSyncConfig(
                Path.GetFullPath(folderPath),
                repositoryId,
                generationId,
                key,
                lastSync);
            key = [];
            Validate(config);
            return config;
        }
        catch (SafeApplicationException)
        {
            throw;
        }
        catch (Exception exception) when (
            exception is IOException or
                CryptographicException or
                DecoderFallbackException or
                ArgumentException)
        {
            throw new SafeApplicationException(
                "Sync.ConfigInvalid",
                "The local-folder sync configuration is unavailable or corrupt.",
                exception);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(protectedBytes);
            CryptographicOperations.ZeroMemory(plaintext);
            CryptographicOperations.ZeroMemory(key);
        }
    }

    private static void Validate(LocalFolderSyncConfig config)
    {
        if (string.IsNullOrWhiteSpace(config.FolderPath) ||
            !Path.IsPathFullyQualified(config.FolderPath) ||
            config.FolderPath.Length > 4096 ||
            config.RepositoryId == Guid.Empty ||
            config.GenerationId == Guid.Empty ||
            config.SyncKey.Length != 32)
        {
            throw InvalidConfig();
        }
    }

    private static SafeApplicationException InvalidConfig() =>
        new(
            "Sync.ConfigInvalid",
            "The local-folder sync configuration is unavailable or corrupt.");
}

internal sealed record LocalFolderSyncConfig(
    string FolderPath,
    Guid RepositoryId,
    Guid GenerationId,
    byte[] SyncKey,
    DateTimeOffset? LastSuccessfulSyncAtUtc) : IDisposable
{
    public void Dispose() => CryptographicOperations.ZeroMemory(SyncKey);
}
