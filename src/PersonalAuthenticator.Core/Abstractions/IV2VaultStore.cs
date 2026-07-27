using PersonalAuthenticator.Core.Domain;

namespace PersonalAuthenticator.Core.Abstractions;

public interface IV2VaultStore
{
    string DatabasePath { get; }

    Task<bool> ExistsAsync(CancellationToken cancellationToken);

    Task<V2VaultSnapshot> LoadAsync(CancellationToken cancellationToken);

    Task SaveAsync(
        IReadOnlyCollection<VaultAccountV2> accounts,
        IReadOnlyCollection<SecretVersionV2> secretVersions,
        CancellationToken cancellationToken);
}
