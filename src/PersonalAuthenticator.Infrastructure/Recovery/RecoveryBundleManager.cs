using System.Security.Cryptography;
using PersonalAuthenticator.Core.Domain;
using PersonalAuthenticator.Core.Exceptions;
using PersonalAuthenticator.Infrastructure.Sync;

namespace PersonalAuthenticator.Infrastructure.Recovery;

internal sealed class RecoveryBundleManager
{
    internal const string SlotAFileName = "PersonalAuthenticator-Recovery-A.par";
    internal const string SlotBFileName = "PersonalAuthenticator-Recovery-B.par";
    private const long OutdatedChangeThreshold = 20;
    private static readonly TimeSpan OutdatedAge = TimeSpan.FromDays(30);
    private readonly RecoveryBundleCodec _codec;
    private readonly RecoveryHealthStore _healthStore;
    private readonly Action<RecoveryCheckpoint>? _checkpoint;

    public RecoveryBundleManager(
        string baseDirectory,
        RecoveryBundleCodec? codec = null,
        Action<RecoveryCheckpoint>? checkpoint = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(baseDirectory);
        string fullBaseDirectory = Path.GetFullPath(baseDirectory);
        _codec = codec ?? new RecoveryBundleCodec();
        _healthStore = new RecoveryHealthStore(
            Path.Combine(fullBaseDirectory, "recovery-health.dat"));
        _checkpoint = checkpoint;
    }

    public async Task<RecoveryBundleInfo> CreateAsync(
        string directoryPath,
        ReadOnlyMemory<char> password,
        V2VaultSnapshot snapshot,
        CancellationToken cancellationToken,
        SyncRecoveryState? syncState = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(directoryPath);
        ArgumentNullException.ThrowIfNull(snapshot);
        string directory = Path.GetFullPath(directoryPath);
        Directory.CreateDirectory(directory);
        RecoverySlot slot = await SelectInactiveSlotAsync(
            directory,
            password,
            cancellationToken);
        string targetPath = GetSlotPath(directory, slot);
        string temporaryPath = Path.Combine(
            directory,
            $".{Path.GetFileName(targetPath)}.{Guid.NewGuid():N}.tmp");
        byte[] envelope = [];
        try
        {
            _checkpoint?.Invoke(RecoveryCheckpoint.BeforeSlotWrite);
            DateTimeOffset createdAtUtc = DateTimeOffset.UtcNow;
            envelope = await _codec.EncryptAsync(
                slot,
                snapshot,
                password,
                createdAtUtc,
                cancellationToken,
                syncState);
            await WriteThroughAsync(temporaryPath, envelope, cancellationToken);
            _checkpoint?.Invoke(RecoveryCheckpoint.AfterSlotWriteBeforeVerification);

            using (DecodedRecoveryBundle staged = await _codec.DecryptFileAsync(
                       temporaryPath,
                       password,
                       cancellationToken))
            {
                VerifyExpected(staged, slot, snapshot.ChangeSequence);
            }

            _checkpoint?.Invoke(RecoveryCheckpoint.AfterVerificationBeforeActivation);
            ActivateSlotFile(temporaryPath, targetPath);
            _checkpoint?.Invoke(RecoveryCheckpoint.AfterActivationBeforeHealthUpdate);

            DateTimeOffset verifiedAtUtc = DateTimeOffset.UtcNow;
            using DecodedRecoveryBundle activated = await _codec.DecryptFileAsync(
                targetPath,
                password,
                cancellationToken);
            VerifyExpected(activated, slot, snapshot.ChangeSequence);
            RecoveryBundleInfo info = activated.ToInfo(verifiedAtUtc);
            await _healthStore.SaveAsync(
                new RecoveryVerificationState(
                    slot,
                    targetPath,
                    info.ChangeSequence,
                    verifiedAtUtc,
                    await ComputeFileSha256Async(targetPath, cancellationToken)),
                cancellationToken);
            return info;
        }
        catch (SafeApplicationException)
        {
            throw;
        }
        catch (Exception exception) when (
            exception is IOException or
                UnauthorizedAccessException or
                CryptographicException)
        {
            throw new SafeApplicationException(
                "Recovery.WriteFailed",
                "The recovery slot could not be written and verified.",
                exception);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(envelope);
            TryDeleteTemporary(temporaryPath);
        }
    }

    public async Task<RecoveryBundleInfo> VerifyAsync(
        string filePath,
        ReadOnlyMemory<char> password,
        CancellationToken cancellationToken)
    {
        DateTimeOffset verifiedAtUtc = DateTimeOffset.UtcNow;
        using DecodedRecoveryBundle bundle = await _codec.DecryptFileAsync(
            filePath,
            password,
            cancellationToken);
        RecoveryBundleInfo info = bundle.ToInfo(verifiedAtUtc);
        await _healthStore.SaveAsync(
            new RecoveryVerificationState(
                info.Slot,
                info.FilePath,
                info.ChangeSequence,
                verifiedAtUtc,
                await ComputeFileSha256Async(info.FilePath, cancellationToken)),
            cancellationToken);
        return info;
    }

    public Task<DecodedRecoveryBundle> OpenAsync(
        string filePath,
        ReadOnlyMemory<char> password,
        CancellationToken cancellationToken) =>
        _codec.DecryptFileAsync(filePath, password, cancellationToken);

    public async Task MarkVerifiedAsync(
        RecoveryBundleInfo info,
        CancellationToken cancellationToken)
    {
        string hash = await ComputeFileSha256Async(
            info.FilePath,
            cancellationToken);
        await _healthStore.SaveAsync(
            new RecoveryVerificationState(
                info.Slot,
                info.FilePath,
                info.ChangeSequence,
                info.VerifiedAtUtc,
                hash),
            cancellationToken);
    }

    public async Task<RecoveryHealthStatus> GetHealthAsync(
        long currentChangeSequence,
        CancellationToken cancellationToken)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(currentChangeSequence);
        RecoveryVerificationState? state;
        try
        {
            state = await _healthStore.LoadAsync(cancellationToken);
        }
        catch (SafeApplicationException exception) when (
            exception.ErrorCode == "Recovery.HealthInvalid")
        {
            return RecoveryHealthStatus.Missing;
        }

        if (state is null || !File.Exists(state.FilePath))
        {
            return RecoveryHealthStatus.Missing;
        }

        string currentHash;
        try
        {
            currentHash = await ComputeFileSha256Async(
                state.FilePath,
                cancellationToken);
        }
        catch (SafeApplicationException)
        {
            return RecoveryHealthStatus.Missing;
        }

        if (!CryptographicOperations.FixedTimeEquals(
                Convert.FromHexString(state.BundleSha256),
                Convert.FromHexString(currentHash)))
        {
            return RecoveryHealthStatus.Missing;
        }

        bool sequenceRolledBack = currentChangeSequence < state.VerifiedSequence;
        long changes = sequenceRolledBack
            ? 0
            : currentChangeSequence - state.VerifiedSequence;
        bool outdated =
            sequenceRolledBack ||
            changes >= OutdatedChangeThreshold ||
            DateTimeOffset.UtcNow - state.VerifiedAtUtc.ToUniversalTime() >= OutdatedAge;
        return new RecoveryHealthStatus(
            true,
            outdated,
            changes,
            state.VerifiedAtUtc.ToUniversalTime(),
            state.Slot,
            state.FilePath);
    }

    private async Task<RecoverySlot> SelectInactiveSlotAsync(
        string directory,
        ReadOnlyMemory<char> password,
        CancellationToken cancellationToken)
    {
        RecoveryVerificationState? state = null;
        try
        {
            state = await _healthStore.LoadAsync(cancellationToken);
        }
        catch (SafeApplicationException exception) when (
            exception.ErrorCode == "Recovery.HealthInvalid")
        {
        }

        if (state is not null &&
            File.Exists(state.FilePath) &&
            string.Equals(
                Path.GetDirectoryName(state.FilePath),
                directory,
                StringComparison.OrdinalIgnoreCase))
        {
            return Opposite(state.Slot);
        }

        string pathA = GetSlotPath(directory, RecoverySlot.A);
        string pathB = GetSlotPath(directory, RecoverySlot.B);
        var valid = new List<(RecoverySlot Slot, long Sequence, DateTimeOffset Created)>();
        bool invalidExistingSlot = false;
        foreach ((RecoverySlot slot, string path) in new[]
                 {
                     (RecoverySlot.A, pathA),
                     (RecoverySlot.B, pathB),
                 })
        {
            if (!File.Exists(path))
            {
                continue;
            }

            try
            {
                using DecodedRecoveryBundle bundle = await _codec.DecryptFileAsync(
                    path,
                    password,
                    cancellationToken);
                valid.Add(
                    (
                        slot,
                        bundle.Payload.Snapshot.ChangeSequence,
                        bundle.Payload.CreatedAtUtc));
            }
            catch (SafeApplicationException)
            {
                invalidExistingSlot = true;
            }
        }

        if (valid.Count > 0)
        {
            RecoverySlot latest = valid
                .OrderByDescending(item => item.Sequence)
                .ThenByDescending(item => item.Created)
                .First()
                .Slot;
            return Opposite(latest);
        }

        if (invalidExistingSlot)
        {
            throw new SafeApplicationException(
                "Recovery.SlotUnsafe",
                "Existing recovery slot files could not be verified. Choose another folder to avoid overwriting them.");
        }

        return RecoverySlot.A;
    }

    private static async Task WriteThroughAsync(
        string filePath,
        ReadOnlyMemory<byte> content,
        CancellationToken cancellationToken)
    {
        await using var stream = new FileStream(
            filePath,
            FileMode.CreateNew,
            FileAccess.Write,
            FileShare.None,
            65_536,
            FileOptions.Asynchronous | FileOptions.WriteThrough);
        await stream.WriteAsync(content, cancellationToken);
        await stream.FlushAsync(cancellationToken);
        stream.Flush(flushToDisk: true);
    }

    private static async Task<string> ComputeFileSha256Async(
        string filePath,
        CancellationToken cancellationToken)
    {
        var file = new FileInfo(filePath);
        if (!file.Exists || file.Length is < 72 or > 128 * 1024 * 1024)
        {
            throw new SafeApplicationException(
                "Recovery.InvalidBundle",
                "The verified recovery bundle is missing or has an invalid size.");
        }

        try
        {
            await using var stream = new FileStream(
                file.FullName,
                FileMode.Open,
                FileAccess.Read,
                FileShare.Read,
                65_536,
                FileOptions.Asynchronous | FileOptions.SequentialScan);
            byte[] hash = await SHA256.HashDataAsync(stream, cancellationToken);
            try
            {
                return Convert.ToHexString(hash);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(hash);
            }
        }
        catch (IOException exception)
        {
            throw new SafeApplicationException(
                "Recovery.ReadFailed",
                "The verified recovery bundle could not be read.",
                exception);
        }
    }

    private static void ActivateSlotFile(string temporaryPath, string targetPath)
    {
        if (File.Exists(targetPath))
        {
            string previousPath =
                $"{targetPath}.previous-{DateTime.UtcNow:yyyyMMddHHmmss}-{Guid.NewGuid():N}";
            File.Replace(temporaryPath, targetPath, previousPath, ignoreMetadataErrors: true);
        }
        else
        {
            File.Move(temporaryPath, targetPath);
        }
    }

    private static void VerifyExpected(
        DecodedRecoveryBundle bundle,
        RecoverySlot slot,
        long changeSequence)
    {
        if (bundle.Slot != slot ||
            bundle.Payload.Snapshot.ChangeSequence != changeSequence)
        {
            throw new SafeApplicationException(
                "Recovery.VerificationFailed",
                "The recovery slot did not reopen with the expected contents.");
        }
    }

    private static string GetSlotPath(string directory, RecoverySlot slot) =>
        Path.Combine(
            directory,
            slot == RecoverySlot.A ? SlotAFileName : SlotBFileName);

    private static RecoverySlot Opposite(RecoverySlot slot) =>
        slot == RecoverySlot.A ? RecoverySlot.B : RecoverySlot.A;

    private static void TryDeleteTemporary(string filePath)
    {
        try
        {
            if (File.Exists(filePath))
            {
                File.Delete(filePath);
            }
        }
        catch (IOException)
        {
        }
        catch (UnauthorizedAccessException)
        {
        }
    }
}
