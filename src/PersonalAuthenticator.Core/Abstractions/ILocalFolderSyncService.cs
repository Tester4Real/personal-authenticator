using PersonalAuthenticator.Core.Domain;

namespace PersonalAuthenticator.Core.Abstractions;

public interface ILocalFolderSyncService
{
    Task ConfigureAsync(
        string folderPath,
        ReadOnlyMemory<char> password,
        CancellationToken cancellationToken);

    Task<SyncStatus> GetSyncStatusAsync(CancellationToken cancellationToken);

    Task<SyncStatus> SyncNowAsync(CancellationToken cancellationToken);

    Task<IReadOnlyList<SyncConflictSummary>> GetConflictsAsync(
        CancellationToken cancellationToken);

    Task ResolveConflictAsync(
        Guid conflictId,
        SyncConflictResolution resolution,
        CancellationToken cancellationToken);
}
