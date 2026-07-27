using PersonalAuthenticator.Core.Domain;

namespace PersonalAuthenticator.Core.Abstractions;

public interface IVaultMigrationCoordinator
{
    Task<VaultMigrationStatus> GetStatusAsync(CancellationToken cancellationToken);

    Task ApplyChoiceAsync(
        VaultMigrationChoice choice,
        CancellationToken cancellationToken);
}
