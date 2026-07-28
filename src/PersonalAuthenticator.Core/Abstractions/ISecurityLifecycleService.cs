using PersonalAuthenticator.Core.Domain;

namespace PersonalAuthenticator.Core.Abstractions;

public interface ISecurityLifecycleService
{
    Task<IReadOnlyList<AuthorisedDeviceInfo>> GetDevicesAsync(
        CancellationToken cancellationToken);

    Task RenameDeviceAsync(
        Guid deviceId,
        string displayName,
        CancellationToken cancellationToken);

    Task RevokeDeviceAsync(
        Guid deviceId,
        CancellationToken cancellationToken);

    Task<SecurityEpochStatus> GetSecurityEpochStatusAsync(
        CancellationToken cancellationToken);

    Task RotateKeysAsync(
        string recoveryDirectory,
        ReadOnlyMemory<char> recoveryPassword,
        CancellationToken cancellationToken);

    Task PurgeAccountAsync(
        Guid accountId,
        string typedConfirmation,
        string recoveryDirectory,
        ReadOnlyMemory<char> recoveryPassword,
        CancellationToken cancellationToken);
}
