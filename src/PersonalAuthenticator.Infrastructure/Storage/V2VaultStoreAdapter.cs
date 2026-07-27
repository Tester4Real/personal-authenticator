using System.Security.Cryptography;
using PersonalAuthenticator.Core.Abstractions;
using PersonalAuthenticator.Core.Domain;
using PersonalAuthenticator.Core.Exceptions;
using PersonalAuthenticator.Infrastructure.Otp;

namespace PersonalAuthenticator.Infrastructure.Storage;

internal sealed class V2VaultStoreAdapter : IVaultStore
{
    private readonly IV2VaultStore _store;

    public V2VaultStoreAdapter(IV2VaultStore store)
    {
        ArgumentNullException.ThrowIfNull(store);
        _store = store;
    }

    public string VaultPath => _store.DatabasePath;

    public Task<bool> ExistsAsync(CancellationToken cancellationToken) =>
        _store.ExistsAsync(cancellationToken);

    public async Task<IReadOnlyList<TotpAccount>> LoadAsync(
        CancellationToken cancellationToken)
    {
        using V2VaultSnapshot snapshot = await _store.LoadAsync(cancellationToken);
        Dictionary<Guid, SecretVersionV2> versions;
        try
        {
            versions = snapshot.SecretVersions.ToDictionary(version => version.Id);
        }
        catch (ArgumentException exception)
        {
            throw new SafeApplicationException(
                "VaultV2.DuplicateIdentifier",
                "The v2 vault contains duplicate secret-version identifiers.",
                exception);
        }

        var accounts = new List<TotpAccount>(snapshot.Accounts.Count);
        try
        {
            foreach (VaultAccountV2 account in snapshot.Accounts.OrderBy(item => item.SortOrder))
            {
                if (!versions.TryGetValue(
                        account.ActiveSecretVersionId,
                        out SecretVersionV2? activeVersion) ||
                    activeVersion.AccountId != account.Id ||
                    activeVersion.State != SecretVersionState.Active)
                {
                    throw new SafeApplicationException(
                        "VaultV2.InvalidActiveSecret",
                        "The v2 vault contains an invalid active secret reference.");
                }

                accounts.Add(
                    new TotpAccount(
                        account.Id,
                        account.Issuer,
                        account.AccountName,
                        activeVersion.Secret,
                        activeVersion.Algorithm,
                        activeVersion.Digits,
                        activeVersion.Period,
                        account.Favourite,
                        account.SortOrder,
                        account.CreatedAtUtc,
                        account.UpdatedAtUtc));
            }

            return accounts;
        }
        catch
        {
            DisposeAccounts(accounts);
            throw;
        }
    }

    public async Task SaveAsync(
        IReadOnlyCollection<TotpAccount> accounts,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(accounts);
        cancellationToken.ThrowIfCancellationRequested();

        V2VaultSnapshot? existing = null;
        var ownedVersions = new List<SecretVersionV2>();
        try
        {
            if (await _store.ExistsAsync(cancellationToken))
            {
                existing = await _store.LoadAsync(cancellationToken);
            }

            Dictionary<Guid, VaultAccountV2> existingAccounts =
                existing?.Accounts.ToDictionary(account => account.Id) ?? [];
            Dictionary<Guid, SecretVersionV2> existingVersions =
                existing?.SecretVersions.ToDictionary(version => version.Id) ?? [];
            ILookup<Guid, SecretVersionV2> versionsByAccount =
                (existing?.SecretVersions ?? []).ToLookup(version => version.AccountId);
            var v2Accounts = new List<VaultAccountV2>(accounts.Count);
            var versionsToSave = new List<SecretVersionV2>();

            foreach (TotpAccount account in accounts)
            {
                Guid activeVersionId;
                bool reusedActiveVersion = false;
                if (existingAccounts.TryGetValue(
                        account.Id,
                        out VaultAccountV2? existingAccount) &&
                    existingVersions.TryGetValue(
                        existingAccount.ActiveSecretVersionId,
                        out SecretVersionV2? existingActive) &&
                    HasSameSecret(existingActive, account))
                {
                    activeVersionId = existingActive.Id;
                    reusedActiveVersion = true;
                }
                else
                {
                    activeVersionId = Guid.NewGuid();
                    var newVersion = new SecretVersionV2(
                        activeVersionId,
                        account.Id,
                        account.Secret,
                        account.Algorithm,
                        account.Digits,
                        account.Period,
                        CanonicalProvisioningUri.Create(account),
                        ProvisioningUriOrigin.CanonicalGenerated,
                        SecretVersionState.Active,
                        account.UpdatedAtUtc);
                    ownedVersions.Add(newVersion);
                }

                v2Accounts.Add(
                    new VaultAccountV2(
                        account.Id,
                        account.Issuer,
                        account.AccountName,
                        activeVersionId,
                        account.Favourite,
                        account.SortOrder,
                        account.CreatedAtUtc,
                        account.UpdatedAtUtc));

                foreach (SecretVersionV2 existingVersion in versionsByAccount[account.Id])
                {
                    if (existingVersion.State != SecretVersionState.Active ||
                        reusedActiveVersion && existingVersion.Id == activeVersionId)
                    {
                        versionsToSave.Add(existingVersion);
                    }
                }

                if (!reusedActiveVersion)
                {
                    versionsToSave.Add(ownedVersions[^1]);
                }
            }

            await _store.SaveAsync(
                v2Accounts,
                versionsToSave,
                cancellationToken);
        }
        finally
        {
            existing?.Dispose();
            foreach (SecretVersionV2 version in ownedVersions)
            {
                version.Dispose();
            }
        }
    }

    private static bool HasSameSecret(
        SecretVersionV2 version,
        TotpAccount account) =>
        version.Algorithm == account.Algorithm &&
        version.Digits == account.Digits &&
        version.Period == account.Period &&
        CryptographicOperations.FixedTimeEquals(version.Secret, account.Secret);

    private static void DisposeAccounts(IEnumerable<TotpAccount> accounts)
    {
        foreach (TotpAccount account in accounts)
        {
            account.Dispose();
        }
    }
}
