using PersonalAuthenticator.Core.Domain;

namespace PersonalAuthenticator.Core.Abstractions;

public interface IVaultStore
{
    string VaultPath { get; }

    Task<bool> ExistsAsync(CancellationToken cancellationToken);

    Task<IReadOnlyList<TotpAccount>> LoadAsync(CancellationToken cancellationToken);

    Task SaveAsync(IReadOnlyCollection<TotpAccount> accounts, CancellationToken cancellationToken);
}
