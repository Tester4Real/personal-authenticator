using PersonalAuthenticator.Core.Domain;

namespace PersonalAuthenticator.Core.Abstractions;

public interface IV2VaultFeatures
{
    Task<bool> IsAvailableAsync(CancellationToken cancellationToken);

    Task AddSecretCandidateAsync(
        Guid accountId,
        TotpAccount candidate,
        CancellationToken cancellationToken);

    Task AddDuplicateAccountAsync(
        Guid relatedAccountId,
        TotpAccount account,
        CancellationToken cancellationToken);

    Task ActivateSecretCandidateAsync(
        Guid accountId,
        Guid secretVersionId,
        CancellationToken cancellationToken);

    Task<IReadOnlyList<SecretVersionSummary>> GetSecretVersionsAsync(
        Guid accountId,
        CancellationToken cancellationToken);

    Task<IReadOnlyList<ArchivedAccountSummary>> GetArchivedAccountsAsync(
        CancellationToken cancellationToken);

    Task RestoreArchivedAccountAsync(
        Guid accountId,
        CancellationToken cancellationToken);

    Task<IReadOnlyList<AccountHistoryEntryV2>> GetAccountHistoryAsync(
        Guid accountId,
        CancellationToken cancellationToken);

    Task<SensitiveSetupInfo> GetActiveSetupInfoAsync(
        Guid accountId,
        CancellationToken cancellationToken);
}
