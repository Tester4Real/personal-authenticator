using System.Buffers.Binary;
using System.Security.Cryptography;
using PersonalAuthenticator.Core.Exceptions;
using PersonalAuthenticator.Infrastructure.Storage;

namespace PersonalAuthenticator.Infrastructure.Sync;

internal sealed class LocalFolderSyncObjectStore
{
    private static readonly byte[] Magic = "PAVOBJ04"u8.ToArray();
    private const ushort Version = 1;
    private const int HeaderLength = 76;
    private const int TagLength = 16;
    private const int MaximumObjectBytes =
        HeaderLength + SyncOperationSerializer.MaximumOperationBytes + TagLength;
    private const int MaximumObjects = 100_000;
    private readonly Action<LocalSyncCheckpoint>? _checkpoint;

    public LocalFolderSyncObjectStore(Action<LocalSyncCheckpoint>? checkpoint = null)
    {
        _checkpoint = checkpoint;
    }

    public async Task UploadAsync(
        LocalFolderSyncConfig config,
        SyncOperation operation,
        CancellationToken cancellationToken)
    {
        byte[] plaintext = SyncOperationSerializer.Serialize(operation);
        byte[] objectBytes = [];
        try
        {
            objectBytes = Encrypt(config, operation.Id, plaintext);
            string targetPath = GetObjectPath(config.FolderPath, operation.Id);
            if (File.Exists(targetPath))
            {
                byte[] existing = await ReadBoundedFileAsync(
                    targetPath,
                    MaximumObjectBytes,
                    cancellationToken);
                try
                {
                    if (!CryptographicOperations.FixedTimeEquals(existing, objectBytes))
                    {
                        throw new SafeApplicationException(
                            "Sync.ObjectCollision",
                            "A sync object identifier already exists with different bytes.");
                    }
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(existing);
                }

                return;
            }

            _checkpoint?.Invoke(LocalSyncCheckpoint.BeforeObjectWrite);
            try
            {
                await AtomicFile.WriteAsync(
                    targetPath,
                    objectBytes,
                    retainPrevious: false,
                    overwriteExisting: false,
                    cancellationToken);
            }
            catch (IOException) when (File.Exists(targetPath))
            {
                byte[] raced = await ReadBoundedFileAsync(
                    targetPath,
                    MaximumObjectBytes,
                    cancellationToken);
                try
                {
                    if (!CryptographicOperations.FixedTimeEquals(raced, objectBytes))
                    {
                        throw new SafeApplicationException(
                            "Sync.ObjectCollision",
                            "A sync object identifier already exists with different bytes.");
                    }
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(raced);
                }
            }

            _checkpoint?.Invoke(LocalSyncCheckpoint.AfterObjectWriteBeforeVerification);
            byte[] verified = await ReadBoundedFileAsync(
                targetPath,
                MaximumObjectBytes,
                cancellationToken);
            try
            {
                if (!CryptographicOperations.FixedTimeEquals(verified, objectBytes))
                {
                    throw new SafeApplicationException(
                        "Sync.UploadVerificationFailed",
                        "A local-folder sync object did not pass post-write verification.");
                }

                using SyncOperation reopened = Decrypt(config, verified);
                if (reopened.Id != operation.Id)
                {
                    throw InvalidObject();
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(verified);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext);
            CryptographicOperations.ZeroMemory(objectBytes);
        }
    }

    public async Task<LocalFolderDownloadResult> DownloadAsync(
        LocalFolderSyncConfig config,
        CancellationToken cancellationToken)
    {
        string objectsDirectory = Path.Combine(config.FolderPath, "objects");
        if (!Directory.Exists(objectsDirectory))
        {
            return new LocalFolderDownloadResult([], 0);
        }

        string[] paths = Directory.EnumerateFiles(
                objectsDirectory,
                "*.pao",
                new EnumerationOptions
                {
                    RecurseSubdirectories = true,
                    AttributesToSkip =
                        FileAttributes.Hidden |
                        FileAttributes.System |
                        FileAttributes.ReparsePoint,
                    IgnoreInaccessible = false,
                    ReturnSpecialDirectories = false,
                })
            .Take(MaximumObjects + 1)
            .ToArray();
        if (paths.Length > MaximumObjects)
        {
            throw new SafeApplicationException(
                "Sync.CollectionTooLarge",
                "The local sync folder contains too many operation objects.");
        }

        var operations = new List<SyncOperation>(paths.Length);
        int quarantined = 0;
        try
        {
            foreach (string path in paths.Order(StringComparer.OrdinalIgnoreCase))
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (!TryValidateObjectPath(objectsDirectory, path, out Guid expectedId))
                {
                    await QuarantineAsync(config.FolderPath, path, cancellationToken);
                    quarantined++;
                    continue;
                }

                byte[] bytes = [];
                try
                {
                    _checkpoint?.Invoke(LocalSyncCheckpoint.BeforeObjectRead);
                    bytes = await ReadBoundedFileAsync(
                        path,
                        MaximumObjectBytes,
                        cancellationToken);
                    SyncOperation operation = Decrypt(config, bytes);
                    if (operation.Id != expectedId)
                    {
                        operation.Dispose();
                        throw InvalidObject();
                    }

                    operations.Add(operation);
                }
                catch (SafeApplicationException exception) when (
                    exception.ErrorCode is
                        "Sync.InvalidObject" or
                        "Sync.ObjectTooLarge" or
                        "Sync.InvalidOperation")
                {
                    await QuarantineAsync(config.FolderPath, path, cancellationToken);
                    quarantined++;
                }
                catch (CryptographicException)
                {
                    await QuarantineAsync(config.FolderPath, path, cancellationToken);
                    quarantined++;
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(bytes);
                }
            }

            return new LocalFolderDownloadResult(operations, quarantined);
        }
        catch
        {
            foreach (SyncOperation operation in operations)
            {
                operation.Dispose();
            }

            throw;
        }
    }

    private static byte[] Encrypt(
        LocalFolderSyncConfig config,
        Guid operationId,
        ReadOnlySpan<byte> plaintext)
    {
        byte[] nonce = RandomNumberGenerator.GetBytes(12);
        byte[] result = new byte[HeaderLength + plaintext.Length + TagLength];
        try
        {
            WriteHeader(
                result,
                config.RepositoryId,
                config.GenerationId,
                operationId,
                nonce,
                plaintext.Length);
            using var aes = new AesGcm(config.SyncKey, TagLength);
            aes.Encrypt(
                nonce,
                plaintext,
                result.AsSpan(HeaderLength, plaintext.Length),
                result.AsSpan(HeaderLength + plaintext.Length, TagLength),
                result.AsSpan(0, HeaderLength));
            return result;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(nonce);
        }
    }

    private static SyncOperation Decrypt(
        LocalFolderSyncConfig config,
        ReadOnlySpan<byte> objectBytes)
    {
        if (objectBytes.Length is < HeaderLength + TagLength or > MaximumObjectBytes ||
            !objectBytes[..8].SequenceEqual(Magic))
        {
            throw InvalidObject();
        }

        if (BinaryPrimitives.ReadUInt16LittleEndian(objectBytes[8..10]) != Version ||
            BinaryPrimitives.ReadUInt16LittleEndian(objectBytes[10..12]) != 0)
        {
            throw new SafeApplicationException(
                "Sync.UnsupportedRequiredFeature",
                "The sync folder requires a newer protocol. Sync is read-only until the application is upgraded.");
        }

        Guid repositoryId = new(objectBytes[12..28]);
        Guid generationId = new(objectBytes[28..44]);
        Guid operationId = new(objectBytes[44..60]);
        int ciphertextLength =
            BinaryPrimitives.ReadInt32LittleEndian(objectBytes[72..76]);
        if (repositoryId != config.RepositoryId ||
            generationId != config.GenerationId ||
            operationId == Guid.Empty ||
            ciphertextLength is < 64 or > SyncOperationSerializer.MaximumOperationBytes ||
            objectBytes.Length != HeaderLength + ciphertextLength + TagLength)
        {
            throw InvalidObject();
        }

        byte[] plaintext = new byte[ciphertextLength];
        try
        {
            using var aes = new AesGcm(config.SyncKey, TagLength);
            aes.Decrypt(
                objectBytes[60..72],
                objectBytes.Slice(HeaderLength, ciphertextLength),
                objectBytes.Slice(HeaderLength + ciphertextLength, TagLength),
                plaintext,
                objectBytes[..HeaderLength]);
            SyncOperation operation = SyncOperationSerializer.Deserialize(plaintext);
            if (operation.Id != operationId)
            {
                operation.Dispose();
                throw InvalidObject();
            }

            return operation;
        }
        catch (AuthenticationTagMismatchException exception)
        {
            throw new SafeApplicationException(
                "Sync.InvalidObject",
                "A local-folder sync object failed authentication.",
                exception);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext);
        }
    }

    private static void WriteHeader(
        Span<byte> target,
        Guid repositoryId,
        Guid generationId,
        Guid operationId,
        ReadOnlySpan<byte> nonce,
        int plaintextLength)
    {
        Magic.CopyTo(target);
        BinaryPrimitives.WriteUInt16LittleEndian(target[8..10], Version);
        BinaryPrimitives.WriteUInt16LittleEndian(target[10..12], 0);
        repositoryId.TryWriteBytes(target[12..28]);
        generationId.TryWriteBytes(target[28..44]);
        operationId.TryWriteBytes(target[44..60]);
        nonce.CopyTo(target[60..72]);
        BinaryPrimitives.WriteInt32LittleEndian(target[72..76], plaintextLength);
    }

    private static string GetObjectPath(string folderPath, Guid operationId)
    {
        string id = operationId.ToString("N");
        return Path.Combine(folderPath, "objects", id[..2], id + ".pao");
    }

    private static bool TryValidateObjectPath(
        string objectsDirectory,
        string path,
        out Guid operationId)
    {
        operationId = Guid.Empty;
        string fullObjects = Path.TrimEndingDirectorySeparator(
            Path.GetFullPath(objectsDirectory));
        string fullPath = Path.GetFullPath(path);
        string? parent = Path.GetDirectoryName(fullPath);
        string? grandparent = parent is null ? null : Path.GetDirectoryName(parent);
        string fileName = Path.GetFileNameWithoutExtension(fullPath);
        return string.Equals(grandparent, fullObjects, StringComparison.OrdinalIgnoreCase) &&
            parent is not null &&
            Path.GetFileName(parent).Length == 2 &&
            fileName.Length == 32 &&
            string.Equals(
                Path.GetFileName(parent),
                fileName[..2],
                StringComparison.OrdinalIgnoreCase) &&
            Guid.TryParseExact(fileName, "N", out operationId) &&
            operationId != Guid.Empty;
    }

    private static async Task<byte[]> ReadBoundedFileAsync(
        string path,
        int maximumBytes,
        CancellationToken cancellationToken)
    {
        var file = new FileInfo(path);
        if (!file.Exists || file.Length is < 1 || file.Length > maximumBytes)
        {
            throw new SafeApplicationException(
                "Sync.ObjectTooLarge",
                "A local-folder sync object has an invalid size.");
        }

        int length = checked((int)file.Length);
        byte[] bytes = new byte[length];
        await using var stream = new FileStream(
            path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            65_536,
            FileOptions.Asynchronous | FileOptions.SequentialScan);
        int offset = 0;
        while (offset < bytes.Length)
        {
            int read = await stream.ReadAsync(
                bytes.AsMemory(offset),
                cancellationToken);
            if (read == 0)
            {
                CryptographicOperations.ZeroMemory(bytes);
                throw InvalidObject();
            }

            offset += read;
        }

        if (stream.ReadByte() != -1)
        {
            CryptographicOperations.ZeroMemory(bytes);
            throw InvalidObject();
        }

        return bytes;
    }

    private static Task QuarantineAsync(
        string folderPath,
        string sourcePath,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        string quarantine = Path.Combine(folderPath, "quarantine");
        Directory.CreateDirectory(quarantine);
        string destination = Path.Combine(
            quarantine,
            $"{Path.GetFileName(sourcePath)}.{DateTimeOffset.UtcNow:yyyyMMddHHmmssfff}.{Guid.NewGuid():N}.bad");
        File.Move(sourcePath, destination);
        return Task.CompletedTask;
    }

    private static SafeApplicationException InvalidObject() =>
        new(
            "Sync.InvalidObject",
            "A local-folder sync object is malformed, corrupt, or belongs to another repository.");
}

internal sealed record LocalFolderDownloadResult(
    IReadOnlyList<SyncOperation> Operations,
    int QuarantinedObjectCount) : IDisposable
{
    public void Dispose()
    {
        foreach (SyncOperation operation in Operations)
        {
            operation.Dispose();
        }
    }
}
