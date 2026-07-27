using System.Security.Cryptography;

namespace PersonalAuthenticator.Infrastructure.Sync;

internal sealed record SyncRecoveryState(
    int ProtocolVersion,
    IReadOnlyList<string> RequiredFeatures,
    Guid DeviceId,
    IReadOnlyDictionary<Guid, long> DeviceSequenceCoverage,
    IReadOnlyList<byte[]> SerializedOperations,
    IReadOnlySet<Guid> OutboxOperationIds,
    IReadOnlyList<SyncConflictRecord> UnresolvedConflicts,
    SyncRecoveryConfiguration? Configuration) : IDisposable
{
    public void Dispose()
    {
        foreach (byte[] operation in SerializedOperations)
        {
            CryptographicOperations.ZeroMemory(operation);
        }
    }
}

internal sealed record SyncRecoveryConfiguration(
    string BackendKind,
    Guid VaultId,
    Guid RemoteGeneration,
    long? RepositoryId,
    string? RepositoryOwner,
    string? RepositoryName,
    string? Branch,
    string? PathPrefix,
    bool Enabled,
    bool BackgroundSyncEnabled);
