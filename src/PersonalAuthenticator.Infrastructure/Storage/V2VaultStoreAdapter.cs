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
            foreach (VaultAccountV2 account in snapshot.Accounts
                         .Where(item => item.ArchivedAtUtc is null)
                         .OrderBy(item => item.SortOrder))
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
            var v2Accounts = new List<VaultAccountV2>(
                Math.Max(accounts.Count, existingAccounts.Count));
            var versionsToSave = new List<SecretVersionV2>();
            var historyToSave = new List<AccountHistoryEntryV2>(
                existing?.HistoryEntries ?? []);
            var activeAccountIds = new HashSet<Guid>();
            DateTimeOffset now = DateTimeOffset.UtcNow;

            foreach (TotpAccount account in accounts)
            {
                if (!activeAccountIds.Add(account.Id))
                {
                    throw new SafeApplicationException(
                        "VaultV2.DuplicateIdentifier",
                        "The v2 vault contains duplicate account identifiers.");
                }

                Guid activeVersionId;
                bool reusedActiveVersion = false;
                SecretVersionV2? previousActive = null;
                SecretVersionV2? newActiveVersion = null;
                if (existingAccounts.TryGetValue(
                        account.Id,
                        out VaultAccountV2? existingAccount) &&
                    existingVersions.TryGetValue(
                        existingAccount.ActiveSecretVersionId,
                        out previousActive) &&
                    HasSameSecret(previousActive, account))
                {
                    activeVersionId = previousActive.Id;
                    reusedActiveVersion = true;
                }
                else
                {
                    activeVersionId = Guid.NewGuid();
                    newActiveVersion = new SecretVersionV2(
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
                    ownedVersions.Add(newActiveVersion);
                }

                existingAccounts.TryGetValue(account.Id, out VaultAccountV2? previousAccount);
                v2Accounts.Add(
                    new VaultAccountV2(
                        account.Id,
                        account.Issuer,
                        account.AccountName,
                        activeVersionId,
                        account.Favourite,
                        account.SortOrder,
                        account.CreatedAtUtc,
                        account.UpdatedAtUtc,
                        archivedAtUtc: null));

                foreach (SecretVersionV2 existingVersion in versionsByAccount[account.Id])
                {
                    if (existingVersion.State == SecretVersionState.Active &&
                        !reusedActiveVersion)
                    {
                        SecretVersionV2 retired = CloneVersion(
                            existingVersion,
                            SecretVersionState.Retired,
                            now);
                        ownedVersions.Add(retired);
                        versionsToSave.Add(retired);
                    }
                    else
                    {
                        versionsToSave.Add(existingVersion);
                    }
                }

                if (!reusedActiveVersion)
                {
                    versionsToSave.Add(newActiveVersion!);
                }

                AppendAccountChanges(
                    historyToSave,
                    previousAccount,
                    account,
                    activeVersionId,
                    previousActive?.Id,
                    reusedActiveVersion,
                    now);
            }

            foreach (VaultAccountV2 previousAccount in existingAccounts.Values)
            {
                if (activeAccountIds.Contains(previousAccount.Id))
                {
                    continue;
                }

                bool newlyArchived = previousAccount.ArchivedAtUtc is null;
                v2Accounts.Add(
                    new VaultAccountV2(
                        previousAccount.Id,
                        previousAccount.Issuer,
                        previousAccount.AccountName,
                        previousAccount.ActiveSecretVersionId,
                        previousAccount.Favourite,
                        previousAccount.SortOrder,
                        previousAccount.CreatedAtUtc,
                        newlyArchived ? now : previousAccount.UpdatedAtUtc,
                        previousAccount.ArchivedAtUtc ?? now));
                versionsToSave.AddRange(versionsByAccount[previousAccount.Id]);
                if (newlyArchived)
                {
                    historyToSave.Add(
                        NewHistory(
                            previousAccount.Id,
                            AccountHistoryAction.Archived,
                            now,
                            previousAccount.ActiveSecretVersionId));
                }
            }

            await _store.SaveAsync(
                v2Accounts,
                versionsToSave,
                historyToSave,
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

    private static SecretVersionV2 CloneVersion(
        SecretVersionV2 version,
        SecretVersionState state,
        DateTimeOffset? retiredAtUtc) =>
        new(
            version.Id,
            version.AccountId,
            version.Secret,
            version.Algorithm,
            version.Digits,
            version.Period,
            version.ProvisioningUri,
            version.ProvisioningUriOrigin,
            state,
            version.CreatedAtUtc,
            retiredAtUtc);

    private static void AppendAccountChanges(
        List<AccountHistoryEntryV2> history,
        VaultAccountV2? previous,
        TotpAccount current,
        Guid activeVersionId,
        Guid? previousVersionId,
        bool reusedActiveVersion,
        DateTimeOffset now)
    {
        if (previous is null)
        {
            history.Add(
                NewHistory(
                    current.Id,
                    AccountHistoryAction.Added,
                    now,
                    activeVersionId));
            return;
        }

        if (previous.ArchivedAtUtc is not null)
        {
            history.Add(
                NewHistory(
                    current.Id,
                    AccountHistoryAction.Restored,
                    now,
                    activeVersionId));
        }

        if (!string.Equals(previous.Issuer, current.Issuer, StringComparison.Ordinal) ||
            !string.Equals(
                previous.AccountName,
                current.AccountName,
                StringComparison.Ordinal))
        {
            history.Add(NewHistory(current.Id, AccountHistoryAction.DisplayUpdated, now));
        }

        if (previous.Favourite != current.Favourite)
        {
            history.Add(NewHistory(current.Id, AccountHistoryAction.FavouriteChanged, now));
        }

        if (previous.SortOrder != current.SortOrder)
        {
            history.Add(NewHistory(current.Id, AccountHistoryAction.Reordered, now));
        }

        if (!reusedActiveVersion)
        {
            history.Add(
                NewHistory(
                    current.Id,
                    AccountHistoryAction.SecretActivated,
                    now,
                    activeVersionId,
                    previousVersionId));
        }
    }

    private static AccountHistoryEntryV2 NewHistory(
        Guid accountId,
        AccountHistoryAction action,
        DateTimeOffset occurredAtUtc,
        Guid? versionId = null,
        Guid? previousVersionId = null) =>
        new(
            Guid.NewGuid(),
            accountId,
            action,
            occurredAtUtc,
            versionId,
            previousVersionId);

    private static void DisposeAccounts(IEnumerable<TotpAccount> accounts)
    {
        foreach (TotpAccount account in accounts)
        {
            account.Dispose();
        }
    }
}
