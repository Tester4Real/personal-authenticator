using PersonalAuthenticator.Core.Domain;

namespace PersonalAuthenticator.Core.Abstractions;

public interface IVaultService : IDisposable
{
    VaultState State { get; }

    IReadOnlyList<TotpAccount> Accounts { get; }

    event EventHandler<VaultState>? StateChanged;

    event EventHandler? AccountsChanged;

    Task InitialiseAsync(bool unlock, CancellationToken cancellationToken);

    Task UnlockAsync(CancellationToken cancellationToken);

    Task LockAsync(CancellationToken cancellationToken);

    Task AddAsync(TotpAccount account, CancellationToken cancellationToken);

    Guid? FindLikelyDuplicate(TotpAccount account);

    Task AddAsync(
        TotpAccount account,
        DuplicateResolution duplicateResolution,
        CancellationToken cancellationToken);

    Task UpdateDisplayAsync(Guid id, string issuer, string accountName, CancellationToken cancellationToken);

    Task SetFavouriteAsync(Guid id, bool favourite, CancellationToken cancellationToken);

    Task MoveAsync(Guid id, int targetIndex, CancellationToken cancellationToken);

    Task DeleteAsync(Guid id, CancellationToken cancellationToken);

    Task ImportAsync(
        IReadOnlyCollection<TotpAccount> importedAccounts,
        BackupImportMode mode,
        CancellationToken cancellationToken);
}
