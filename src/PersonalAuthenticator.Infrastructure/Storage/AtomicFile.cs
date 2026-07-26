namespace PersonalAuthenticator.Infrastructure.Storage;

internal static class AtomicFile
{
    public static async Task WriteAsync(
        string targetPath,
        ReadOnlyMemory<byte> content,
        bool retainPrevious,
        bool overwriteExisting,
        CancellationToken cancellationToken)
    {
        string? directory = Path.GetDirectoryName(targetPath);
        if (string.IsNullOrEmpty(directory))
        {
            throw new ArgumentException("Target path must include a directory.", nameof(targetPath));
        }

        Directory.CreateDirectory(directory);
        string temporaryPath = Path.Combine(directory, $".{Path.GetFileName(targetPath)}.{Guid.NewGuid():N}.tmp");
        string backupPath = targetPath + ".previous";

        try
        {
            await using (var stream = new FileStream(
                temporaryPath,
                FileMode.CreateNew,
                FileAccess.Write,
                FileShare.None,
                65_536,
                FileOptions.Asynchronous | FileOptions.WriteThrough))
            {
                await stream.WriteAsync(content, cancellationToken);
                await stream.FlushAsync(cancellationToken);
                stream.Flush(flushToDisk: true);
            }

            if (File.Exists(targetPath))
            {
                if (!overwriteExisting)
                {
                    throw new IOException("The target file already exists.");
                }

                if (retainPrevious && File.Exists(backupPath))
                {
                    File.Delete(backupPath);
                }

                File.Replace(temporaryPath, targetPath, retainPrevious ? backupPath : null, ignoreMetadataErrors: true);
            }
            else
            {
                File.Move(temporaryPath, targetPath);
            }
        }
        finally
        {
            if (File.Exists(temporaryPath))
            {
                File.Delete(temporaryPath);
            }
        }
    }
}
