using System.Security.Cryptography;
using PersonalAuthenticator.Core.Domain;
using PersonalAuthenticator.Core.Exceptions;
using PersonalAuthenticator.Infrastructure.Storage;

namespace PersonalAuthenticator.Infrastructure.Sync;

internal static class SyncMergeEngine
{
    public static SyncMergeResult Apply(
        V2VaultSnapshot current,
        IReadOnlyDictionary<Guid, SyncOperation> operations,
        IReadOnlySet<Guid> alreadyApplied,
        IReadOnlyDictionary<SyncFieldAddress, IReadOnlyList<SyncFieldHead>> currentHeads,
        IReadOnlyCollection<SyncConflictRecord> currentConflicts,
        IReadOnlyDictionary<Guid, Guid> currentAccountAliases,
        IReadOnlyDictionary<Guid, Guid> currentSecretAliases)
    {
        var accounts = current.Accounts
            .Select(account => SyncOperationGenerator.CloneAccount(account))
            .ToList();
        var versions = current.SecretVersions
            .Select(version => SyncOperationGenerator.CloneVersion(version))
            .ToList();
        var history = current.HistoryEntries
            .Select(entry => SyncOperationGenerator.CloneHistory(entry))
            .ToList();
        var applied = alreadyApplied.ToHashSet();
        var heads = currentHeads.ToDictionary(
            item => item.Key,
            item => item.Value.ToList());
        var conflicts = currentConflicts.ToDictionary(item => item.Id);
        var accountAliases = currentAccountAliases.ToDictionary();
        var secretAliases = currentSecretAliases.ToDictionary();
        bool changed = false;
        try
        {
            bool progress;
            do
            {
                progress = false;
                foreach (SyncOperation operation in operations.Values
                             .Where(operation => !applied.Contains(operation.Id))
                             .OrderBy(operation => operation.LogicalClock)
                             .ThenBy(operation => operation.DeviceId)
                             .ThenBy(operation => operation.DeviceSequence)
                             .ThenBy(operation => operation.Id))
                {
                    if (operation.CausalParents.Any(parent => !applied.Contains(parent)))
                    {
                        continue;
                    }

                    try
                    {
                        ApplyOne(
                            operation,
                            operations,
                            accounts,
                            versions,
                            history,
                            heads,
                            conflicts,
                            accountAliases,
                            secretAliases,
                            ref changed);
                    }
                    catch (SyncDependencyMissingException)
                    {
                        continue;
                    }

                    applied.Add(operation.Id);
                    progress = true;
                }
            }
            while (progress);

            V2SqliteVaultStore.ValidateSnapshot(accounts, versions, history);
            return new SyncMergeResult(
                accounts,
                versions,
                history,
                applied,
                heads,
                conflicts.Values.ToList(),
                accountAliases,
                secretAliases,
                changed);
        }
        catch
        {
            DisposeVersions(versions);
            throw;
        }
    }

    private static void ApplyOne(
        SyncOperation operation,
        IReadOnlyDictionary<Guid, SyncOperation> operations,
        List<VaultAccountV2> accounts,
        List<SecretVersionV2> versions,
        List<AccountHistoryEntryV2> history,
        Dictionary<SyncFieldAddress, List<SyncFieldHead>> heads,
        Dictionary<Guid, SyncConflictRecord> conflicts,
        Dictionary<Guid, Guid> accountAliases,
        Dictionary<Guid, Guid> secretAliases,
        ref bool changed)
    {
        Guid? originalAccountId = operation.AccountId;
        Guid? accountId = originalAccountId.HasValue
            ? ResolveAlias(accountAliases, originalAccountId.Value)
            : null;
        if (operation.Kind == SyncOperationKind.AccountAdded)
        {
            ApplyAccountAdded(
                operation,
                accounts,
                versions,
                history,
                accountAliases,
                secretAliases,
                ref changed);
            accountId = ResolveAlias(accountAliases, operation.AccountId!.Value);
        }
        else if (accountId.HasValue &&
                 accounts.All(account => account.Id != accountId.Value) &&
                 operation.Kind is not SyncOperationKind.Purged)
        {
            throw new SyncDependencyMissingException();
        }

        if (!accountId.HasValue)
        {
            return;
        }

        var address = new SyncFieldAddress(accountId.Value, operation.FieldKey);
        List<SyncFieldHead> fieldHeads = heads.GetValueOrDefault(address) ?? [];
        byte[] semanticHash = SyncSemanticHasher.Compute(operation);
        try
        {
            if (operation.Kind == SyncOperationKind.Purged)
            {
                SyncOperation[] concurrentRestores = operations.Values
                    .Where(candidate =>
                        candidate.Id != operation.Id &&
                        candidate.AccountId == operation.AccountId &&
                        IsRestore(candidate) &&
                        !IsAncestor(candidate.Id, operation.Id, operations) &&
                        !IsAncestor(operation.Id, candidate.Id, operations))
                    .ToArray();
                if (concurrentRestores.Length > 0)
                {
                    foreach (SyncOperation restore in concurrentRestores)
                    {
                        if (CreateConflict(
                            operation,
                            restore,
                            accountId.Value,
                            conflicts))
                        {
                            changed = true;
                        }
                    }

                    UpdateHeads(
                        heads,
                        address,
                        operation,
                        semanticHash,
                        []);
                    return;
                }
            }

            SyncHeadDecision decision = EvaluateHeads(
                operation,
                semanticHash,
                fieldHeads,
                operations);
            if (operation.Kind == SyncOperationKind.SecretAdded)
            {
                ApplySecretAdded(
                    operation,
                    accountId.Value,
                    versions,
                    secretAliases,
                    ref changed);
            }

            if (decision.ConcurrentDifferent)
            {
                foreach (SyncFieldHead head in decision.ConcurrentHeads)
                {
                    if (CreateConflict(
                        operation,
                        operations[head.OperationId],
                        accountId.Value,
                        conflicts))
                    {
                        changed = true;
                    }
                }

                UpdateHeads(
                    heads,
                    address,
                    operation,
                    semanticHash,
                    decision.AncestorHeads);
                return;
            }

            if (decision.IncomingIsOlder || decision.Identical)
            {
                UpdateHeads(
                    heads,
                    address,
                    operation,
                    semanticHash,
                    decision.AncestorHeads);
                return;
            }

            switch (operation.Kind)
            {
                case SyncOperationKind.AccountAdded:
                case SyncOperationKind.SecretAdded:
                    break;
                case SyncOperationKind.IssuerChanged:
                    ReplaceAccount(
                        accounts,
                        accountId.Value,
                        account => CloneAccount(
                            account,
                            issuer: operation.Payload.TextValue,
                            updatedAtUtc: operation.OccurredAtUtc),
                        ref changed);
                    break;
                case SyncOperationKind.AccountNameChanged:
                    ReplaceAccount(
                        accounts,
                        accountId.Value,
                        account => CloneAccount(
                            account,
                            accountName: operation.Payload.TextValue,
                            updatedAtUtc: operation.OccurredAtUtc),
                        ref changed);
                    break;
                case SyncOperationKind.FavouriteChanged:
                    ReplaceAccount(
                        accounts,
                        accountId.Value,
                        account => CloneAccount(
                            account,
                            favourite: operation.Payload.BoolValue,
                            updatedAtUtc: operation.OccurredAtUtc),
                        ref changed);
                    break;
                case SyncOperationKind.SortOrderChanged:
                    ReplaceAccount(
                        accounts,
                        accountId.Value,
                        account => CloneAccount(
                            account,
                            sortOrder: operation.Payload.IntValue,
                            updatedAtUtc: operation.OccurredAtUtc),
                        ref changed);
                    break;
                case SyncOperationKind.ArchiveChanged:
                    ReplaceAccount(
                        accounts,
                        accountId.Value,
                        account => CloneAccount(
                            account,
                            archivedAtUtc: operation.Payload.DateValue,
                            setArchive: true,
                            updatedAtUtc: operation.OccurredAtUtc),
                        ref changed);
                    break;
                case SyncOperationKind.ActiveSecretChanged:
                    ApplyActiveSecret(
                        operation,
                        accountId.Value,
                        accounts,
                        versions,
                        secretAliases,
                        ref changed);
                    break;
                case SyncOperationKind.HistoryAdded:
                case SyncOperationKind.DuplicateDecision:
                    ApplyHistory(
                        operation,
                        accountId.Value,
                        accounts,
                        versions,
                        history,
                        accountAliases,
                        secretAliases,
                        ref changed);
                    break;
                case SyncOperationKind.Purged:
                    if (conflicts.Values.Any(conflict =>
                            !conflict.Resolved &&
                            conflict.AccountId == accountId.Value))
                    {
                        break;
                    }

                    RemoveAccount(
                        accountId.Value,
                        accounts,
                        versions,
                        history,
                        ref changed);
                    break;
                case SyncOperationKind.ConflictResolved:
                    ApplyResolution(
                        operation,
                        operations,
                        accounts,
                        versions,
                        history,
                        conflicts,
                        accountAliases,
                        secretAliases,
                        ref changed);
                    break;
                default:
                    throw new SafeApplicationException(
                        "Sync.InvalidOperation",
                        "The sync operation kind is not supported.");
            }

            UpdateHeads(
                heads,
                address,
                operation,
                semanticHash,
                decision.AncestorHeads);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(semanticHash);
        }
    }

    private static void ApplyAccountAdded(
        SyncOperation operation,
        List<VaultAccountV2> accounts,
        List<SecretVersionV2> versions,
        List<AccountHistoryEntryV2> history,
        Dictionary<Guid, Guid> accountAliases,
        Dictionary<Guid, Guid> secretAliases,
        ref bool changed)
    {
        VaultAccountV2 incomingAccount = operation.Payload.Account ??
            throw new SyncDependencyMissingException();
        SecretVersionV2 incomingSecret = operation.Payload.SecretVersion ??
            throw new SyncDependencyMissingException();
        Guid incomingId = incomingAccount.Id;
        Guid resolvedIncoming = ResolveAlias(accountAliases, incomingId);
        if (accounts.Any(account => account.Id == resolvedIncoming))
        {
            return;
        }

        VaultAccountV2? duplicate = accounts.FirstOrDefault(
            account =>
                string.Equals(
                    account.Issuer.Trim(),
                    incomingAccount.Issuer.Trim(),
                    StringComparison.OrdinalIgnoreCase) &&
                string.Equals(
                    account.AccountName.Trim(),
                    incomingAccount.AccountName.Trim(),
                    StringComparison.OrdinalIgnoreCase) &&
                versions.Any(version =>
                    version.Id == account.ActiveSecretVersionId &&
                    SameSecret(version, incomingSecret)));
        if (duplicate is null)
        {
            accounts.Add(SyncOperationGenerator.CloneAccount(incomingAccount));
            versions.Add(SyncOperationGenerator.CloneVersion(incomingSecret));
            changed = true;
            return;
        }

        SecretVersionV2 duplicateActive =
            versions.First(version => version.Id == duplicate.ActiveSecretVersionId);
        Guid canonicalAccountId = MinGuid(duplicate.Id, incomingId);
        Guid canonicalSecretId = MinGuid(duplicateActive.Id, incomingSecret.Id);
        accountAliases[duplicate.Id] = canonicalAccountId;
        accountAliases[incomingId] = canonicalAccountId;
        secretAliases[duplicateActive.Id] = canonicalSecretId;
        secretAliases[incomingSecret.Id] = canonicalSecretId;
        if (duplicate.Id == canonicalAccountId &&
            duplicateActive.Id == canonicalSecretId)
        {
            return;
        }

        RenameAccount(
            duplicate,
            incomingAccount,
            incomingSecret,
            canonicalAccountId,
            canonicalSecretId,
            accounts,
            versions,
            history);
        changed = true;
    }

    private static void ApplySecretAdded(
        SyncOperation operation,
        Guid accountId,
        List<SecretVersionV2> versions,
        Dictionary<Guid, Guid> secretAliases,
        ref bool changed)
    {
        SecretVersionV2 incoming = operation.Payload.SecretVersion ??
            throw new SyncDependencyMissingException();
        Guid incomingId = ResolveAlias(secretAliases, incoming.Id);
        if (versions.Any(version => version.Id == incomingId))
        {
            return;
        }

        SecretVersionV2? identical = versions.FirstOrDefault(
            version => version.AccountId == accountId && SameSecret(version, incoming));
        if (identical is not null)
        {
            secretAliases[incoming.Id] = identical.Id;
            return;
        }

        versions.Add(
            SyncOperationGenerator.CloneVersion(
                incoming,
                accountId,
                state: SecretVersionState.Candidate));
        changed = true;
    }

    private static void ApplyActiveSecret(
        SyncOperation operation,
        Guid accountId,
        List<VaultAccountV2> accounts,
        List<SecretVersionV2> versions,
        Dictionary<Guid, Guid> secretAliases,
        ref bool changed)
    {
        if (!operation.Payload.GuidValue.HasValue)
        {
            throw new SyncDependencyMissingException();
        }

        Guid targetId = ResolveAlias(secretAliases, operation.Payload.GuidValue.Value);
        SecretVersionV2 target = versions.FirstOrDefault(version =>
                version.Id == targetId && version.AccountId == accountId) ??
            throw new SyncDependencyMissingException();
        VaultAccountV2 account =
            accounts.First(item => item.Id == accountId);
        if (account.ActiveSecretVersionId == targetId)
        {
            return;
        }

        for (int index = 0; index < versions.Count; index++)
        {
            SecretVersionV2 version = versions[index];
            if (version.AccountId != accountId)
            {
                continue;
            }

            SecretVersionState state = version.Id == targetId
                ? SecretVersionState.Active
                : version.Id == account.ActiveSecretVersionId
                    ? SecretVersionState.Retired
                    : version.State;
            DateTimeOffset? retired = state == SecretVersionState.Retired
                ? operation.OccurredAtUtc
                : null;
            if (state != version.State ||
                (state == SecretVersionState.Retired &&
                 version.RetiredAtUtc != retired))
            {
                SecretVersionV2 replacement = SyncOperationGenerator.CloneVersion(
                    version,
                    state: state,
                    retiredAtUtc: retired);
                versions[index] = replacement;
                version.Dispose();
            }
        }

        ReplaceAccount(
            accounts,
            accountId,
            current => CloneAccount(
                current,
                activeSecretVersionId: target.Id,
                updatedAtUtc: operation.OccurredAtUtc),
            ref changed);
    }

    private static void ApplyHistory(
        SyncOperation operation,
        Guid accountId,
        IReadOnlyCollection<VaultAccountV2> accounts,
        IReadOnlyCollection<SecretVersionV2> versions,
        List<AccountHistoryEntryV2> history,
        Dictionary<Guid, Guid> accountAliases,
        Dictionary<Guid, Guid> secretAliases,
        ref bool changed)
    {
        AccountHistoryEntryV2 incoming = operation.Payload.HistoryEntry ??
            throw new SyncDependencyMissingException();
        if (history.Any(entry => entry.Id == incoming.Id))
        {
            return;
        }

        Guid? secretId = incoming.SecretVersionId.HasValue
            ? ResolveAlias(secretAliases, incoming.SecretVersionId.Value)
            : null;
        Guid? previousId = incoming.PreviousSecretVersionId.HasValue
            ? ResolveAlias(secretAliases, incoming.PreviousSecretVersionId.Value)
            : null;
        Guid? relatedId = incoming.RelatedAccountId.HasValue
            ? ResolveAlias(accountAliases, incoming.RelatedAccountId.Value)
            : null;
        if (accounts.All(account => account.Id != accountId) ||
            (secretId.HasValue &&
             versions.All(version => version.Id != secretId.Value)) ||
            (previousId.HasValue &&
             versions.All(version => version.Id != previousId.Value)) ||
            (relatedId.HasValue &&
             accounts.All(account => account.Id != relatedId.Value)))
        {
            throw new SyncDependencyMissingException();
        }

        history.Add(
            new AccountHistoryEntryV2(
                incoming.Id,
                accountId,
                incoming.Action,
                incoming.OccurredAtUtc,
                secretId,
                previousId,
                relatedId,
                incoming.ActorDeviceId));
        changed = true;
    }

    private static void ApplyResolution(
        SyncOperation operation,
        IReadOnlyDictionary<Guid, SyncOperation> operations,
        List<VaultAccountV2> accounts,
        List<SecretVersionV2> versions,
        List<AccountHistoryEntryV2> history,
        Dictionary<Guid, SyncConflictRecord> conflicts,
        Dictionary<Guid, Guid> accountAliases,
        Dictionary<Guid, Guid> secretAliases,
        ref bool changed)
    {
        if (!operation.Payload.ConflictId.HasValue ||
            !operation.Payload.Resolution.HasValue ||
            !conflicts.TryGetValue(
                operation.Payload.ConflictId.Value,
                out SyncConflictRecord? conflict))
        {
            throw new SyncDependencyMissingException();
        }

        if (conflict.Resolved)
        {
            return;
        }

        Guid selectedOperationId =
            operation.Payload.Resolution == SyncConflictResolution.KeepB
                ? conflict.OperationBId
                : conflict.OperationAId;
        SyncOperation selectedOperation = operations.GetValueOrDefault(
                selectedOperationId) ??
            throw new SyncDependencyMissingException();
        if (operation.Payload.Resolution ==
            SyncConflictResolution.SeparateAccounts)
        {
            Guid versionId = conflict.SecretVersionBId ??
                throw new SafeApplicationException(
                    "Sync.InvalidResolution",
                    "Only a secret conflict can be separated.");
            SecretVersionV2 version =
                versions.First(item => item.Id == ResolveAlias(secretAliases, versionId));
            VaultAccountV2 source =
                accounts.First(item => item.Id == conflict.AccountId);
            Guid newAccountId = operation.Payload.GuidValue ??
                throw new SyncDependencyMissingException();
            Guid newVersionId = operation.Payload.SecondaryGuidValue ??
                throw new SyncDependencyMissingException();
            versions.Add(
                SyncOperationGenerator.CloneVersion(
                    version,
                    newAccountId,
                    newVersionId,
                    SecretVersionState.Active));
            accounts.Add(
                new VaultAccountV2(
                    newAccountId,
                    source.Issuer,
                    source.AccountName + " (separate)",
                    newVersionId,
                    source.Favourite,
                    accounts.Count,
                    operation.OccurredAtUtc,
                    operation.OccurredAtUtc));
            changed = true;
        }
        else if (operation.Payload.Resolution is
                 SyncConflictResolution.KeepA or
                 SyncConflictResolution.KeepB)
        {
            if (conflict.Kind is
                SyncConflictKind.SecretAdded or SyncConflictKind.ActiveSecret)
            {
                Guid selectedVersionId = selectedOperationId == conflict.OperationAId
                    ? conflict.SecretVersionAId ?? Guid.Empty
                    : conflict.SecretVersionBId ?? Guid.Empty;
                if (selectedVersionId != Guid.Empty)
                {
                    ApplyActiveSecret(
                        new SyncOperation(
                            operation.Id,
                            operation.DeviceId,
                            operation.DeviceSequence,
                            operation.LogicalClock,
                            operation.OccurredAtUtc,
                            conflict.AccountId,
                            SyncOperationKind.ActiveSecretChanged,
                            SyncFieldKeys.ActiveSecret,
                            operation.CausalParents,
                            new SyncOperationPayload
                            {
                                GuidValue = selectedVersionId,
                            }),
                        conflict.AccountId,
                        accounts,
                        versions,
                        secretAliases,
                        ref changed);
                }
            }
            else if (conflict.Kind == SyncConflictKind.Metadata)
            {
                ApplySelectedMetadata(
                    selectedOperation,
                    conflict.AccountId,
                    accounts,
                    ref changed);
            }
            else if (conflict.Kind == SyncConflictKind.RestoreVersusPurge)
            {
                if (selectedOperation.Kind == SyncOperationKind.Purged)
                {
                    RemoveAccount(
                        conflict.AccountId,
                        accounts,
                        versions,
                        history,
                        ref changed);
                }
                else
                {
                    ReplaceAccount(
                        accounts,
                        conflict.AccountId,
                        account => CloneAccount(
                            account,
                            archivedAtUtc: selectedOperation.Payload.DateValue,
                            setArchive: true,
                            updatedAtUtc: operation.OccurredAtUtc),
                        ref changed);
                }
            }
            else if (conflict.Kind == SyncConflictKind.DuplicateDecision)
            {
                ApplyHistory(
                    selectedOperation,
                    conflict.AccountId,
                    accounts,
                    versions,
                    history,
                    accountAliases,
                    secretAliases,
                    ref changed);
            }
        }

        conflicts[conflict.Id] = conflict with { Resolved = true };
    }

    private static void ApplySelectedMetadata(
        SyncOperation selected,
        Guid accountId,
        List<VaultAccountV2> accounts,
        ref bool changed)
    {
        Func<VaultAccountV2, VaultAccountV2> replacement = selected.Kind switch
        {
            SyncOperationKind.IssuerChanged =>
                account => CloneAccount(
                    account,
                    issuer: selected.Payload.TextValue,
                    updatedAtUtc: selected.OccurredAtUtc),
            SyncOperationKind.AccountNameChanged =>
                account => CloneAccount(
                    account,
                    accountName: selected.Payload.TextValue,
                    updatedAtUtc: selected.OccurredAtUtc),
            SyncOperationKind.FavouriteChanged =>
                account => CloneAccount(
                    account,
                    favourite: selected.Payload.BoolValue,
                    updatedAtUtc: selected.OccurredAtUtc),
            SyncOperationKind.SortOrderChanged =>
                account => CloneAccount(
                    account,
                    sortOrder: selected.Payload.IntValue,
                    updatedAtUtc: selected.OccurredAtUtc),
            SyncOperationKind.ArchiveChanged =>
                account => CloneAccount(
                    account,
                    archivedAtUtc: selected.Payload.DateValue,
                    setArchive: true,
                    updatedAtUtc: selected.OccurredAtUtc),
            _ => throw new SafeApplicationException(
                "Sync.InvalidResolution",
                "The selected operation is not a metadata change."),
        };
        ReplaceAccount(accounts, accountId, replacement, ref changed);
    }

    private static SyncHeadDecision EvaluateHeads(
        SyncOperation incoming,
        byte[] incomingHash,
        IReadOnlyCollection<SyncFieldHead> heads,
        IReadOnlyDictionary<Guid, SyncOperation> operations)
    {
        var ancestors = new List<Guid>();
        var concurrent = new List<SyncFieldHead>();
        bool older = false;
        bool identical = false;
        foreach (SyncFieldHead head in heads)
        {
            if (CryptographicOperations.FixedTimeEquals(
                    head.ValueHash,
                    incomingHash))
            {
                identical = true;
            }

            if (IsAncestor(head.OperationId, incoming.Id, operations))
            {
                ancestors.Add(head.OperationId);
            }
            else if (IsAncestor(incoming.Id, head.OperationId, operations))
            {
                older = true;
            }
            else if (!CryptographicOperations.FixedTimeEquals(
                         head.ValueHash,
                         incomingHash))
            {
                concurrent.Add(head);
            }
        }

        return new SyncHeadDecision(
            ancestors,
            concurrent,
            older && ancestors.Count == 0 && concurrent.Count == 0,
            identical && concurrent.Count == 0,
            concurrent.Count > 0);
    }

    private static bool IsAncestor(
        Guid candidate,
        Guid descendant,
        IReadOnlyDictionary<Guid, SyncOperation> operations)
    {
        if (candidate == descendant)
        {
            return true;
        }

        var pending = new Stack<Guid>();
        var visited = new HashSet<Guid>();
        pending.Push(descendant);
        while (pending.Count > 0)
        {
            Guid current = pending.Pop();
            if (!visited.Add(current) ||
                !operations.TryGetValue(current, out SyncOperation? operation))
            {
                continue;
            }

            foreach (Guid parent in operation.CausalParents)
            {
                if (parent == candidate)
                {
                    return true;
                }

                pending.Push(parent);
            }
        }

        return false;
    }

    private static void UpdateHeads(
        Dictionary<SyncFieldAddress, List<SyncFieldHead>> heads,
        SyncFieldAddress address,
        SyncOperation operation,
        byte[] semanticHash,
        IReadOnlyCollection<Guid> ancestorHeads)
    {
        List<SyncFieldHead> fieldHeads = heads.GetValueOrDefault(address) ?? [];
        fieldHeads.RemoveAll(head => ancestorHeads.Contains(head.OperationId));
        if (fieldHeads.All(head => head.OperationId != operation.Id))
        {
            fieldHeads.Add(
                new SyncFieldHead(
                    operation.Id,
                    semanticHash.ToArray()));
        }

        heads[address] = fieldHeads;
    }

    private static bool CreateConflict(
        SyncOperation incoming,
        SyncOperation existing,
        Guid accountId,
        Dictionary<Guid, SyncConflictRecord> conflicts)
    {
        Guid first = MinGuid(incoming.Id, existing.Id);
        Guid second = first == incoming.Id ? existing.Id : incoming.Id;
        Span<byte> input = stackalloc byte[32];
        first.TryWriteBytes(input[..16]);
        second.TryWriteBytes(input[16..]);
        Span<byte> hash = stackalloc byte[32];
        SHA256.HashData(input, hash);
        Guid conflictId = new(hash[..16]);
        SyncConflictKind kind = ClassifyConflict(incoming, existing);
        Guid? firstSecret = GetSecretVersionId(
            first == incoming.Id ? incoming : existing);
        Guid? secondSecret = GetSecretVersionId(
            second == incoming.Id ? incoming : existing);
        bool added = conflicts.TryAdd(
            conflictId,
            new SyncConflictRecord(
                conflictId,
                accountId,
                kind,
                incoming.FieldKey,
                first,
                second,
                firstSecret,
                secondSecret,
                incoming.OccurredAtUtc >= existing.OccurredAtUtc
                    ? incoming.OccurredAtUtc
                    : existing.OccurredAtUtc,
                Resolved: false));
        CryptographicOperations.ZeroMemory(input);
        CryptographicOperations.ZeroMemory(hash);
        return added;
    }

    private static SyncConflictKind ClassifyConflict(
        SyncOperation first,
        SyncOperation second)
    {
        if ((first.Kind == SyncOperationKind.Purged &&
             IsRestore(second)) ||
            (second.Kind == SyncOperationKind.Purged &&
             IsRestore(first)))
        {
            return SyncConflictKind.RestoreVersusPurge;
        }

        return first.Kind switch
        {
            SyncOperationKind.SecretAdded => SyncConflictKind.SecretAdded,
            SyncOperationKind.ActiveSecretChanged => SyncConflictKind.ActiveSecret,
            SyncOperationKind.DuplicateDecision => SyncConflictKind.DuplicateDecision,
            _ => SyncConflictKind.Metadata,
        };
    }

    private static bool IsRestore(SyncOperation operation) =>
        operation.Kind == SyncOperationKind.ArchiveChanged &&
        operation.Payload.DateValue is null;

    private static Guid? GetSecretVersionId(SyncOperation operation) =>
        operation.Kind == SyncOperationKind.SecretAdded
            ? operation.Payload.SecretVersion?.Id
            : operation.Kind == SyncOperationKind.ActiveSecretChanged
                ? operation.Payload.GuidValue
                : null;

    private static void RenameAccount(
        VaultAccountV2 existing,
        VaultAccountV2 incoming,
        SecretVersionV2 incomingSecret,
        Guid accountId,
        Guid activeSecretId,
        List<VaultAccountV2> accounts,
        List<SecretVersionV2> versions,
        List<AccountHistoryEntryV2> history)
    {
        Guid existingId = existing.Id;
        Guid existingActiveId = existing.ActiveSecretVersionId;
        accounts.Remove(existing);
        accounts.Add(
            new VaultAccountV2(
                accountId,
                string.Compare(
                    existing.Issuer,
                    incoming.Issuer,
                    StringComparison.Ordinal) <= 0
                    ? existing.Issuer
                    : incoming.Issuer,
                string.Compare(
                    existing.AccountName,
                    incoming.AccountName,
                    StringComparison.Ordinal) <= 0
                    ? existing.AccountName
                    : incoming.AccountName,
                activeSecretId,
                existing.Favourite || incoming.Favourite,
                Math.Min(existing.SortOrder, incoming.SortOrder),
                existing.CreatedAtUtc <= incoming.CreatedAtUtc
                    ? existing.CreatedAtUtc
                    : incoming.CreatedAtUtc,
                existing.UpdatedAtUtc >= incoming.UpdatedAtUtc
                    ? existing.UpdatedAtUtc
                    : incoming.UpdatedAtUtc,
                existing.ArchivedAtUtc ?? incoming.ArchivedAtUtc));

        for (int index = versions.Count - 1; index >= 0; index--)
        {
            SecretVersionV2 version = versions[index];
            if (version.AccountId != existingId)
            {
                continue;
            }

            versions.RemoveAt(index);
            if (version.Id == existingActiveId)
            {
                versions.Add(
                    SyncOperationGenerator.CloneVersion(
                        activeSecretId == incomingSecret.Id ? incomingSecret : version,
                        accountId,
                        activeSecretId,
                        SecretVersionState.Active));
            }
            else
            {
                versions.Add(
                    SyncOperationGenerator.CloneVersion(
                        version,
                        accountId));
            }

            version.Dispose();
        }

        for (int index = 0; index < history.Count; index++)
        {
            AccountHistoryEntryV2 entry = history[index];
            if (entry.AccountId == existingId ||
                entry.RelatedAccountId == existingId)
            {
                history[index] = new AccountHistoryEntryV2(
                    entry.Id,
                    entry.AccountId == existingId ? accountId : entry.AccountId,
                    entry.Action,
                    entry.OccurredAtUtc,
                    entry.SecretVersionId == existingActiveId
                        ? activeSecretId
                        : entry.SecretVersionId,
                    entry.PreviousSecretVersionId == existingActiveId
                        ? activeSecretId
                        : entry.PreviousSecretVersionId,
                    entry.RelatedAccountId == existingId
                        ? accountId
                        : entry.RelatedAccountId,
                    entry.ActorDeviceId);
            }
        }
    }

    private static VaultAccountV2 CloneAccount(
        VaultAccountV2 account,
        string? issuer = null,
        string? accountName = null,
        bool? favourite = null,
        int? sortOrder = null,
        Guid? activeSecretVersionId = null,
        DateTimeOffset? archivedAtUtc = null,
        bool setArchive = false,
        DateTimeOffset? updatedAtUtc = null) =>
        new(
            account.Id,
            issuer ?? account.Issuer,
            accountName ?? account.AccountName,
            activeSecretVersionId ?? account.ActiveSecretVersionId,
            favourite ?? account.Favourite,
            sortOrder ?? account.SortOrder,
            account.CreatedAtUtc,
            updatedAtUtc ?? account.UpdatedAtUtc,
            setArchive ? archivedAtUtc : account.ArchivedAtUtc);

    private static void ReplaceAccount(
        List<VaultAccountV2> accounts,
        Guid accountId,
        Func<VaultAccountV2, VaultAccountV2> replacement,
        ref bool changed)
    {
        int index = accounts.FindIndex(account => account.Id == accountId);
        if (index < 0)
        {
            throw new SyncDependencyMissingException();
        }

        accounts[index] = replacement(accounts[index]);
        changed = true;
    }

    private static void RemoveAccount(
        Guid accountId,
        List<VaultAccountV2> accounts,
        List<SecretVersionV2> versions,
        List<AccountHistoryEntryV2> history,
        ref bool changed)
    {
        accounts.RemoveAll(account => account.Id == accountId);
        for (int index = versions.Count - 1; index >= 0; index--)
        {
            if (versions[index].AccountId == accountId)
            {
                versions[index].Dispose();
                versions.RemoveAt(index);
            }
        }

        history.RemoveAll(entry =>
            entry.AccountId == accountId || entry.RelatedAccountId == accountId);
        changed = true;
    }

    private static bool SameSecret(
        SecretVersionV2 first,
        SecretVersionV2 second) =>
        first.Algorithm == second.Algorithm &&
        first.Digits == second.Digits &&
        first.Period == second.Period &&
        CryptographicOperations.FixedTimeEquals(first.Secret, second.Secret);

    private static Guid ResolveAlias(
        Dictionary<Guid, Guid> aliases,
        Guid value)
    {
        var visited = new HashSet<Guid>();
        Guid current = value;
        while (aliases.TryGetValue(current, out Guid next) &&
               next != current &&
               visited.Add(current))
        {
            current = next;
        }

        return current;
    }

    private static Guid MinGuid(Guid first, Guid second) =>
        first.CompareTo(second) <= 0 ? first : second;

    private static void DisposeVersions(IEnumerable<SecretVersionV2> versions)
    {
        foreach (SecretVersionV2 version in versions)
        {
            version.Dispose();
        }
    }
}

internal sealed record SyncFieldAddress(Guid AccountId, string FieldKey);

internal sealed record SyncFieldHead(Guid OperationId, byte[] ValueHash);

internal sealed record SyncHeadDecision(
    IReadOnlyList<Guid> AncestorHeads,
    IReadOnlyList<SyncFieldHead> ConcurrentHeads,
    bool IncomingIsOlder,
    bool Identical,
    bool ConcurrentDifferent);

internal sealed class SyncMergeResult : IDisposable
{
    public SyncMergeResult(
        List<VaultAccountV2> accounts,
        List<SecretVersionV2> secretVersions,
        List<AccountHistoryEntryV2> historyEntries,
        HashSet<Guid> appliedOperationIds,
        Dictionary<SyncFieldAddress, List<SyncFieldHead>> fieldHeads,
        List<SyncConflictRecord> conflicts,
        Dictionary<Guid, Guid> accountAliases,
        Dictionary<Guid, Guid> secretAliases,
        bool changed)
    {
        Accounts = accounts;
        SecretVersions = secretVersions;
        HistoryEntries = historyEntries;
        AppliedOperationIds = appliedOperationIds;
        FieldHeads = fieldHeads;
        Conflicts = conflicts;
        AccountAliases = accountAliases;
        SecretAliases = secretAliases;
        Changed = changed;
    }

    public List<VaultAccountV2> Accounts { get; }

    public List<SecretVersionV2> SecretVersions { get; }

    public List<AccountHistoryEntryV2> HistoryEntries { get; }

    public HashSet<Guid> AppliedOperationIds { get; }

    public Dictionary<SyncFieldAddress, List<SyncFieldHead>> FieldHeads { get; }

    public List<SyncConflictRecord> Conflicts { get; }

    public Dictionary<Guid, Guid> AccountAliases { get; }

    public Dictionary<Guid, Guid> SecretAliases { get; }

    public bool Changed { get; }

    public void Dispose()
    {
        foreach (SecretVersionV2 version in SecretVersions)
        {
            version.Dispose();
        }

        foreach (List<SyncFieldHead> heads in FieldHeads.Values)
        {
            foreach (SyncFieldHead head in heads)
            {
                CryptographicOperations.ZeroMemory(head.ValueHash);
            }
        }
    }
}

internal sealed class SyncDependencyMissingException : Exception;
