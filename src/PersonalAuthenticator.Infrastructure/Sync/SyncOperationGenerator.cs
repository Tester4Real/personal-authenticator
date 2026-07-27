using PersonalAuthenticator.Core.Domain;

namespace PersonalAuthenticator.Infrastructure.Sync;

internal static class SyncOperationGenerator
{
    public static List<SyncOperationDraft> Generate(
        V2VaultSnapshot previous,
        IReadOnlyCollection<VaultAccountV2> accounts,
        IReadOnlyCollection<SecretVersionV2> secretVersions,
        IReadOnlyCollection<AccountHistoryEntryV2> historyEntries)
    {
        ArgumentNullException.ThrowIfNull(previous);
        var drafts = new List<SyncOperationDraft>();
        Dictionary<Guid, VaultAccountV2> oldAccounts =
            previous.Accounts.ToDictionary(account => account.Id);
        Dictionary<Guid, VaultAccountV2> newAccounts =
            accounts.ToDictionary(account => account.Id);
        Dictionary<Guid, SecretVersionV2> oldVersions =
            previous.SecretVersions.ToDictionary(version => version.Id);
        Dictionary<Guid, SecretVersionV2> newVersions =
            secretVersions.ToDictionary(version => version.Id);
        HashSet<Guid> oldHistoryIds =
            previous.HistoryEntries.Select(entry => entry.Id).ToHashSet();

        try
        {
            foreach (VaultAccountV2 account in accounts.OrderBy(item => item.Id))
            {
                if (!oldAccounts.TryGetValue(account.Id, out VaultAccountV2? old))
                {
                    SecretVersionV2 active = newVersions[account.ActiveSecretVersionId];
                    drafts.Add(
                        NewDraft(
                            account.Id,
                            SyncOperationKind.AccountAdded,
                            SyncFieldKeys.Existence,
                            account.UpdatedAtUtc,
                            new SyncOperationPayload
                            {
                                Account = CloneAccount(account),
                                SecretVersion = CloneVersion(active),
                            }));
                    foreach (SecretVersionV2 version in secretVersions
                                 .Where(version =>
                                     version.AccountId == account.Id &&
                                     version.Id != active.Id)
                                 .OrderBy(version => version.Id))
                    {
                        drafts.Add(NewSecretDraft(version));
                    }

                    continue;
                }

                if (!string.Equals(old.Issuer, account.Issuer, StringComparison.Ordinal))
                {
                    drafts.Add(
                        NewDraft(
                            account.Id,
                            SyncOperationKind.IssuerChanged,
                            SyncFieldKeys.Issuer,
                            account.UpdatedAtUtc,
                            new SyncOperationPayload { TextValue = account.Issuer }));
                }

                if (!string.Equals(
                        old.AccountName,
                        account.AccountName,
                        StringComparison.Ordinal))
                {
                    drafts.Add(
                        NewDraft(
                            account.Id,
                            SyncOperationKind.AccountNameChanged,
                            SyncFieldKeys.AccountName,
                            account.UpdatedAtUtc,
                            new SyncOperationPayload { TextValue = account.AccountName }));
                }

                if (old.Favourite != account.Favourite)
                {
                    drafts.Add(
                        NewDraft(
                            account.Id,
                            SyncOperationKind.FavouriteChanged,
                            SyncFieldKeys.Favourite,
                            account.UpdatedAtUtc,
                            new SyncOperationPayload { BoolValue = account.Favourite }));
                }

                if (old.SortOrder != account.SortOrder)
                {
                    drafts.Add(
                        NewDraft(
                            account.Id,
                            SyncOperationKind.SortOrderChanged,
                            SyncFieldKeys.SortOrder,
                            account.UpdatedAtUtc,
                            new SyncOperationPayload { IntValue = account.SortOrder }));
                }

                if (old.ArchivedAtUtc != account.ArchivedAtUtc)
                {
                    drafts.Add(
                        NewDraft(
                            account.Id,
                            SyncOperationKind.ArchiveChanged,
                            SyncFieldKeys.Archive,
                            account.UpdatedAtUtc,
                            new SyncOperationPayload
                            {
                                DateValue = account.ArchivedAtUtc,
                            }));
                }

                foreach (SecretVersionV2 version in secretVersions
                             .Where(version =>
                                 version.AccountId == account.Id &&
                                 !oldVersions.ContainsKey(version.Id))
                             .OrderBy(version => version.Id))
                {
                    drafts.Add(NewSecretDraft(version));
                }

                if (old.ActiveSecretVersionId != account.ActiveSecretVersionId)
                {
                    drafts.Add(
                        NewDraft(
                            account.Id,
                            SyncOperationKind.ActiveSecretChanged,
                            SyncFieldKeys.ActiveSecret,
                            account.UpdatedAtUtc,
                            new SyncOperationPayload
                            {
                                GuidValue = account.ActiveSecretVersionId,
                                SecondaryGuidValue = old.ActiveSecretVersionId,
                            }));
                }
            }

            foreach (VaultAccountV2 removed in previous.Accounts
                         .Where(account => !newAccounts.ContainsKey(account.Id))
                         .OrderBy(account => account.Id))
            {
                drafts.Add(
                    NewDraft(
                        removed.Id,
                        SyncOperationKind.Purged,
                        SyncFieldKeys.Archive,
                        DateTimeOffset.UtcNow,
                        new SyncOperationPayload()));
            }

            foreach (AccountHistoryEntryV2 entry in historyEntries
                         .Where(entry => !oldHistoryIds.Contains(entry.Id))
                         .OrderBy(entry => entry.OccurredAtUtc)
                         .ThenBy(entry => entry.Id))
            {
                bool duplicateDecision =
                    entry.Action == AccountHistoryAction.DuplicateAddedSeparately;
                drafts.Add(
                    NewDraft(
                        entry.AccountId,
                        duplicateDecision
                            ? SyncOperationKind.DuplicateDecision
                            : SyncOperationKind.HistoryAdded,
                        duplicateDecision
                            ? SyncFieldKeys.DuplicateDecision
                            : SyncFieldKeys.History + ":" + entry.Id.ToString("N"),
                        entry.OccurredAtUtc,
                        new SyncOperationPayload
                        {
                            HistoryEntry = CloneHistory(entry),
                            GuidValue = entry.RelatedAccountId,
                        }));
            }

            return drafts;
        }
        catch
        {
            foreach (SyncOperationDraft draft in drafts)
            {
                draft.Dispose();
            }

            throw;
        }
    }

    private static SyncOperationDraft NewSecretDraft(SecretVersionV2 version) =>
        NewDraft(
            version.AccountId,
            SyncOperationKind.SecretAdded,
            SyncFieldKeys.SecretSet,
            version.CreatedAtUtc,
            new SyncOperationPayload
            {
                SecretVersion = CloneVersion(version),
            });

    private static SyncOperationDraft NewDraft(
        Guid accountId,
        SyncOperationKind kind,
        string fieldKey,
        DateTimeOffset occurredAtUtc,
        SyncOperationPayload payload) =>
        new(accountId, kind, fieldKey, occurredAtUtc, payload);

    internal static VaultAccountV2 CloneAccount(
        VaultAccountV2 account,
        Guid? id = null,
        Guid? activeSecretVersionId = null) =>
        new(
            id ?? account.Id,
            account.Issuer,
            account.AccountName,
            activeSecretVersionId ?? account.ActiveSecretVersionId,
            account.Favourite,
            account.SortOrder,
            account.CreatedAtUtc,
            account.UpdatedAtUtc,
            account.ArchivedAtUtc);

    internal static SecretVersionV2 CloneVersion(
        SecretVersionV2 version,
        Guid? accountId = null,
        Guid? id = null,
        SecretVersionState? state = null,
        DateTimeOffset? retiredAtUtc = null) =>
        new(
            id ?? version.Id,
            accountId ?? version.AccountId,
            version.Secret,
            version.Algorithm,
            version.Digits,
            version.Period,
            version.ProvisioningUri,
            version.ProvisioningUriOrigin,
            state ?? version.State,
            version.CreatedAtUtc,
            state == SecretVersionState.Retired
                ? retiredAtUtc ?? version.RetiredAtUtc ?? DateTimeOffset.UtcNow
                : state.HasValue
                    ? null
                    : version.RetiredAtUtc);

    internal static AccountHistoryEntryV2 CloneHistory(
        AccountHistoryEntryV2 entry,
        Guid? accountId = null,
        Guid? secretVersionId = null,
        Guid? relatedAccountId = null) =>
        new(
            entry.Id,
            accountId ?? entry.AccountId,
            entry.Action,
            entry.OccurredAtUtc,
            secretVersionId ?? entry.SecretVersionId,
            entry.PreviousSecretVersionId,
            relatedAccountId ?? entry.RelatedAccountId,
            entry.ActorDeviceId);
}
