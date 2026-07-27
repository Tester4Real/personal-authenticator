using System.Security.Cryptography;
using PersonalAuthenticator.Core.Domain;
using PersonalAuthenticator.Core.Exceptions;
using PersonalAuthenticator.Infrastructure.Sync;

namespace PersonalAuthenticator.Infrastructure.Storage;

public sealed partial class VersionedVaultStore
{
    private bool _isSyncing;
    private string? _lastSyncError;

    public async Task ConfigureAsync(
        string folderPath,
        ReadOnlyMemory<char> password,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(folderPath);
        await _gate.WaitAsync(cancellationToken);
        try
        {
            _ = await GetActiveV2StoreAsync(cancellationToken);
            using LocalFolderSyncConfig config =
                await LocalFolderSyncManifest.OpenOrCreateAsync(
                    folderPath,
                    password,
                    cancellationToken);
            await _syncConfigStore.SaveAsync(config, cancellationToken);
            _lastSyncError = null;
        }
        catch (SafeApplicationException)
        {
            throw;
        }
        catch (Exception exception) when (
            exception is IOException or
                UnauthorizedAccessException or
                ArgumentException or
                NotSupportedException)
        {
            throw new SafeApplicationException(
                "Sync.ConfigurationFailed",
                "The local-folder sync backend could not be configured.",
                exception);
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task<SyncStatus> GetSyncStatusAsync(
        CancellationToken cancellationToken)
    {
        await _gate.WaitAsync(cancellationToken);
        try
        {
            return await GetSyncStatusCoreAsync(cancellationToken);
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task<SyncStatus> SyncNowAsync(CancellationToken cancellationToken)
    {
        await _gate.WaitAsync(cancellationToken);
        try
        {
            if (!_syncConfigStore.Exists)
            {
                throw new SafeApplicationException(
                    "Sync.NotConfigured",
                    "Configure a local sync folder before synchronising.");
            }

            _isSyncing = true;
            using LocalFolderSyncConfig config =
                await _syncConfigStore.LoadAsync(cancellationToken);
            V2SqliteVaultStore store =
                await GetActiveV2StoreAsync(cancellationToken);
            IReadOnlyList<SyncOperation>? outbox = null;
            try
            {
                outbox = await store.LoadOutboxAsync(cancellationToken);
                var uploadedIds = new List<Guid>(outbox.Count);
                foreach (SyncOperation operation in outbox)
                {
                    await _syncObjectStore.UploadAsync(
                        config,
                        operation,
                        cancellationToken);
                    uploadedIds.Add(operation.Id);
                }

                // Uploads are acknowledged only after every object has been
                // atomically written, reopened, authenticated, and compared.
                await store.MarkOutboxSentAsync(uploadedIds, cancellationToken);
                using LocalFolderDownloadResult download =
                    await _syncObjectStore.DownloadAsync(
                        config,
                        cancellationToken);
                await store.ApplyRemoteOperationsAsync(
                    download.Operations,
                    cancellationToken);
                LocalFolderSyncConfig updated = config with
                {
                    SyncKey = config.SyncKey.ToArray(),
                    LastSuccessfulSyncAtUtc = DateTimeOffset.UtcNow,
                };
                using (updated)
                {
                    await _syncConfigStore.SaveAsync(updated, cancellationToken);
                }

                _lastSyncError = download.QuarantinedObjectCount == 0
                    ? null
                    : $"{download.QuarantinedObjectCount} invalid sync object(s) were quarantined.";
            }
            catch (SafeApplicationException exception)
            {
                _lastSyncError = exception.Message;
                throw;
            }
            catch (Exception exception) when (
                exception is IOException or
                    UnauthorizedAccessException or
                    CryptographicException)
            {
                _lastSyncError =
                    "Local-folder synchronisation failed. Pending changes remain queued.";
                throw new SafeApplicationException(
                    "Sync.Failed",
                    _lastSyncError,
                    exception);
            }
            finally
            {
                if (outbox is not null)
                {
                    foreach (SyncOperation operation in outbox)
                    {
                        operation.Dispose();
                    }
                }
            }

            return await GetSyncStatusCoreAsync(cancellationToken);
        }
        finally
        {
            _isSyncing = false;
            _gate.Release();
        }
    }

    public async Task<IReadOnlyList<SyncConflictSummary>> GetConflictsAsync(
        CancellationToken cancellationToken)
    {
        await _gate.WaitAsync(cancellationToken);
        try
        {
            V2SqliteVaultStore store =
                await GetActiveV2StoreAsync(cancellationToken);
            return await store.GetUnresolvedConflictsAsync(cancellationToken);
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task ResolveConflictAsync(
        Guid conflictId,
        SyncConflictResolution resolution,
        CancellationToken cancellationToken)
    {
        await _gate.WaitAsync(cancellationToken);
        try
        {
            V2SqliteVaultStore store =
                await GetActiveV2StoreAsync(cancellationToken);
            await store.QueueConflictResolutionAsync(
                conflictId,
                resolution,
                cancellationToken);
        }
        finally
        {
            _gate.Release();
        }
    }

    private async Task<SyncStatus> GetSyncStatusCoreAsync(
        CancellationToken cancellationToken)
    {
        if (!_syncConfigStore.Exists)
        {
            return new SyncStatus(
                IsConfigured: false,
                _isSyncing,
                BackendPath: null,
                DeviceId: null,
                PendingOperationCount: 0,
                ConflictCount: 0,
                LastSuccessfulSyncAtUtc: null,
                _lastSyncError);
        }

        using LocalFolderSyncConfig config =
            await _syncConfigStore.LoadAsync(cancellationToken);
        V2SqliteVaultStore store = await GetActiveV2StoreAsync(cancellationToken);
        int pending = checked(
            await store.GetOutboxCountAsync(cancellationToken) +
            await store.GetPendingApplicationCountAsync(cancellationToken));
        IReadOnlyList<SyncConflictSummary> conflicts =
            await store.GetUnresolvedConflictsAsync(cancellationToken);
        Guid deviceId = await store.GetSyncDeviceIdAsync(cancellationToken);
        return new SyncStatus(
            IsConfigured: true,
            _isSyncing,
            config.FolderPath,
            deviceId,
            pending,
            conflicts.Count,
            config.LastSuccessfulSyncAtUtc,
            _lastSyncError);
    }
}
