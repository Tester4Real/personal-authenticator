using PersonalAuthenticator.Core.Domain;

namespace PersonalAuthenticator.Core.Abstractions;

public interface IRecoveryService
{
    Task<RecoveryBundleInfo> CreateRecoveryBundleAsync(
        string directoryPath,
        ReadOnlyMemory<char> password,
        CancellationToken cancellationToken);

    Task<RecoveryBundleInfo> VerifyRecoveryBundleAsync(
        string filePath,
        ReadOnlyMemory<char> password,
        CancellationToken cancellationToken);

    Task<RecoveryBundleInfo> RestoreRecoveryBundleAsync(
        string filePath,
        ReadOnlyMemory<char> password,
        CancellationToken cancellationToken);

    Task<RecoveryHealthStatus> GetRecoveryHealthAsync(
        CancellationToken cancellationToken);
}
