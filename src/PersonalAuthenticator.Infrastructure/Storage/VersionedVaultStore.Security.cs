using System.Security.Cryptography;
using PersonalAuthenticator.Core.Domain;
using PersonalAuthenticator.Core.Exceptions;
using PersonalAuthenticator.Infrastructure.GitHub;
using PersonalAuthenticator.Infrastructure.Security;
using PersonalAuthenticator.Infrastructure.Sync;

namespace PersonalAuthenticator.Infrastructure.Storage;

public sealed partial class VersionedVaultStore
{
    public async Task<IReadOnlyList<AuthorisedDeviceInfo>> GetDevicesAsync(
        CancellationToken cancellationToken)
    {
        await _gate.WaitAsync(cancellationToken);
        try
        {
            V2SqliteVaultStore store =
                await GetActiveV2StoreAsync(cancellationToken);
            Guid currentDeviceId =
                await store.GetSyncDeviceIdAsync(cancellationToken);
            IReadOnlyList<SyncDeviceActivity> activity =
                await store.GetSyncDeviceActivityAsync(cancellationToken);
            SecurityState state =
                await _securityStateStore.LoadAsync(cancellationToken);
            DateTimeOffset now = DateTimeOffset.UtcNow;
            foreach (SyncDeviceActivity item in activity)
            {
                if (!state.Devices.TryGetValue(
                        item.DeviceId,
                        out SecurityDeviceState? device))
                {
                    device = new SecurityDeviceState
                    {
                        DisplayName = item.DeviceId == currentDeviceId
                            ? Environment.MachineName
                            : $"Windows device {item.DeviceId:N}"[..31],
                        FirstSeenAtUtc = item.FirstSeenAtUtc,
                    };
                    state.Devices[item.DeviceId] = device;
                }

                device.FirstSeenAtUtc =
                    device.FirstSeenAtUtc == default
                        ? item.FirstSeenAtUtc
                        : DateTimeOffset.Compare(
                            device.FirstSeenAtUtc,
                            item.FirstSeenAtUtc) <= 0
                            ? device.FirstSeenAtUtc
                            : item.FirstSeenAtUtc;
                device.LastSeenAtUtc =
                    DateTimeOffset.Compare(
                        device.LastSeenAtUtc,
                        item.LastSeenAtUtc) >= 0
                        ? device.LastSeenAtUtc
                        : item.LastSeenAtUtc;
                device.HighestSequence =
                    Math.Max(device.HighestSequence, item.HighestSequence);
            }

            if (!state.Devices.ContainsKey(currentDeviceId))
            {
                state.Devices[currentDeviceId] = new SecurityDeviceState
                {
                    DisplayName = Environment.MachineName,
                    FirstSeenAtUtc = now,
                    LastSeenAtUtc = now,
                };
            }

            await _securityStateStore.SaveAsync(state, cancellationToken);
            return state.Devices
                .Select(pair => new AuthorisedDeviceInfo(
                    pair.Key,
                    pair.Value.DisplayName,
                    pair.Key == currentDeviceId,
                    pair.Value.RevokedAtUtc.HasValue,
                    pair.Value.FirstSeenAtUtc,
                    pair.Value.LastSeenAtUtc,
                    pair.Value.HighestSequence,
                    pair.Value.RevokedAtUtc,
                    pair.Value.RevokedAfterSequence))
                .OrderByDescending(device => device.IsCurrent)
                .ThenBy(device => device.IsRevoked)
                .ThenByDescending(device => device.LastSeenAtUtc)
                .ToList();
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task RenameDeviceAsync(
        Guid deviceId,
        string displayName,
        CancellationToken cancellationToken)
    {
        string normalized = displayName.Trim();
        if (deviceId == Guid.Empty || normalized.Length is < 1 or > 80)
        {
            throw new SafeApplicationException(
                "Security.InvalidDevice",
                "Choose an authorised device and a name containing 1 to 80 characters.");
        }

        await _gate.WaitAsync(cancellationToken);
        try
        {
            SecurityState state =
                await _securityStateStore.LoadAsync(cancellationToken);
            if (!state.Devices.TryGetValue(
                    deviceId,
                    out SecurityDeviceState? device))
            {
                throw new SafeApplicationException(
                    "Security.DeviceNotFound",
                    "The selected device is not authorised in this vault.");
            }

            device.DisplayName = normalized;
            await _securityStateStore.SaveAsync(state, cancellationToken);
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task RevokeDeviceAsync(
        Guid deviceId,
        CancellationToken cancellationToken)
    {
        await _gate.WaitAsync(cancellationToken);
        try
        {
            V2SqliteVaultStore store =
                await GetActiveV2StoreAsync(cancellationToken);
            Guid current =
                await store.GetSyncDeviceIdAsync(cancellationToken);
            if (deviceId == current)
            {
                throw new SafeApplicationException(
                    "Security.CurrentDeviceRevocation",
                    "The current Windows device cannot revoke itself.");
            }

            SecurityState state =
                await _securityStateStore.LoadAsync(cancellationToken);
            if (!state.Devices.TryGetValue(
                    deviceId,
                    out SecurityDeviceState? device))
            {
                throw new SafeApplicationException(
                    "Security.DeviceNotFound",
                    "The selected device is not authorised in this vault.");
            }

            device.RevokedAtUtc ??= DateTimeOffset.UtcNow;
            device.RevokedAfterSequence ??= device.HighestSequence;
            await _securityStateStore.SaveAsync(state, cancellationToken);
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task<SecurityEpochStatus> GetSecurityEpochStatusAsync(
        CancellationToken cancellationToken)
    {
        SecurityState state =
            await _securityStateStore.LoadAsync(cancellationToken);
        return ToEpochStatus(state);
    }

    public async Task RotateKeysAsync(
        string recoveryDirectory,
        ReadOnlyMemory<char> recoveryPassword,
        CancellationToken cancellationToken)
    {
        await _gate.WaitAsync(cancellationToken);
        try
        {
            await RotateVaultGenerationAsync(
                recoveryDirectory,
                recoveryPassword,
                purgeAccountId: null,
                cancellationToken);
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task PurgeAccountAsync(
        Guid accountId,
        string typedConfirmation,
        string recoveryDirectory,
        ReadOnlyMemory<char> recoveryPassword,
        CancellationToken cancellationToken)
    {
        if (!string.Equals(
                typedConfirmation.Trim(),
                "PURGE",
                StringComparison.Ordinal))
        {
            throw new SafeApplicationException(
                "Security.PurgeConfirmation",
                "Type PURGE exactly to confirm permanent purge.");
        }

        await _gate.WaitAsync(cancellationToken);
        try
        {
            V2SqliteVaultStore store =
                await GetActiveV2StoreAsync(cancellationToken);
            using V2VaultSnapshot snapshot =
                await store.LoadAsync(cancellationToken);
            VaultAccountV2 account =
                snapshot.Accounts.FirstOrDefault(item => item.Id == accountId) ??
                throw new SafeApplicationException(
                    "Security.PurgeAccountMissing",
                    "The selected archived account no longer exists.");
            if (account.ArchivedAtUtc is null)
            {
                throw new SafeApplicationException(
                    "Security.PurgeRequiresArchive",
                    "Archive the account before requesting permanent purge.");
            }

            if ((await store.GetUnresolvedConflictsAsync(cancellationToken))
                .Any(conflict => conflict.AccountId == accountId))
            {
                throw new SafeApplicationException(
                    "Security.PurgeConflict",
                    "Resolve every conflict for this account before purge.");
            }

            await RotateVaultGenerationAsync(
                recoveryDirectory,
                recoveryPassword,
                accountId,
                cancellationToken);
        }
        finally
        {
            _gate.Release();
        }
    }

    private async Task RotateVaultGenerationAsync(
        string recoveryDirectory,
        ReadOnlyMemory<char> recoveryPassword,
        Guid? purgeAccountId,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(recoveryDirectory);
        V2SqliteVaultStore source =
            await GetActiveV2StoreAsync(cancellationToken);
        using V2VaultSnapshot sourceSnapshot =
            await source.LoadAsync(cancellationToken);
        using SyncRecoveryState sourceSync =
            await source.ExportSyncRecoveryStateAsync(
                configuration: null,
                cancellationToken);
        SecurityState security =
            await _securityStateStore.LoadAsync(cancellationToken);
        int pendingEpoch = checked(security.ActiveEpoch + 1);
        security.PendingEpoch = pendingEpoch;
        security.PurgeAccountId = purgeAccountId;
        security.LastFailure = null;
        await _securityStateStore.SaveAsync(security, cancellationToken);
        _securityCheckpoint?.Invoke(
            purgeAccountId.HasValue
                ? SecurityCheckpoint.AfterPurgePendingPersisted
                : SecurityCheckpoint.AfterPendingEpochPersisted);

        string databaseName = $"vault-v2-epoch-{pendingEpoch}-{Guid.NewGuid():N}.db";
        string keyName = $"vault-v2-epoch-{pendingEpoch}-{Guid.NewGuid():N}.key";
        string databasePath = ResolveSelectedPath(databaseName);
        string keyPath = ResolveSelectedPath(keyName);
        bool activated = false;
        try
        {
            IReadOnlyList<VaultAccountV2> accounts = purgeAccountId.HasValue
                ? sourceSnapshot.Accounts
                    .Where(item => item.Id != purgeAccountId.Value)
                    .ToList()
                : sourceSnapshot.Accounts;
            IReadOnlyList<SecretVersionV2> versions = purgeAccountId.HasValue
                ? sourceSnapshot.SecretVersions
                    .Where(item => item.AccountId != purgeAccountId.Value)
                    .ToList()
                : sourceSnapshot.SecretVersions;
            IReadOnlyList<AccountHistoryEntryV2> history = purgeAccountId.HasValue
                ? sourceSnapshot.HistoryEntries
                    .Where(item => item.AccountId != purgeAccountId.Value)
                    .ToList()
                : sourceSnapshot.HistoryEntries;
            var replacement =
                new V2SqliteVaultStore(databasePath, keyPath);
            await replacement.SaveRecoveredAsync(
                accounts,
                versions,
                history,
                sourceSnapshot.ChangeSequence,
                cancellationToken);
            if (!purgeAccountId.HasValue)
            {
                await replacement.ImportSyncRecoveryStateAsync(
                    sourceSync,
                    cancellationToken);
            }

            _securityCheckpoint?.Invoke(
                SecurityCheckpoint.AfterReplacementVaultWritten);
            using V2VaultSnapshot verified =
                await replacement.LoadAsync(cancellationToken);
            VerifyEpochSnapshot(
                accounts,
                versions,
                history,
                verified,
                purgeAccountId);
            _securityCheckpoint?.Invoke(
                SecurityCheckpoint.AfterReplacementVaultVerified);

            using SyncRecoveryState replacementSync =
                await replacement.ExportSyncRecoveryStateAsync(
                    configuration: null,
                    cancellationToken);
            await _recoveryBundles.CreateAsync(
                recoveryDirectory,
                recoveryPassword,
                verified,
                cancellationToken,
                replacementSync);
            _securityCheckpoint?.Invoke(SecurityCheckpoint.AfterRecoveryRotated);
            _securityCheckpoint?.Invoke(SecurityCheckpoint.BeforeEpochActivation);
            await _pointerStore.SaveAsync(
                new ActiveVaultPointer(
                    ActiveVaultMode.LocalV2,
                    databaseName,
                    LegacySourceSha256: null,
                    DateTimeOffset.UtcNow,
                    keyName),
                cancellationToken);
            activated = true;
            security.ActiveEpoch = pendingEpoch;
            security.PendingEpoch = null;
            security.PurgeAccountId = null;
            security.LastFailure = null;
            await _securityStateStore.SaveAsync(security, cancellationToken);

            if (_githubConfigStore.Exists)
            {
                using GitHubSyncConfiguration github =
                    await _githubConfigStore.LoadAsync(cancellationToken);
                await PauseGitHubUploadsAsync(
                    github,
                    purgeAccountId.HasValue
                        ? "Purge created a clean local epoch. Replace the GitHub repository generation before resuming uploads."
                        : "Key rotation created a new local epoch. Verify Recovery-A/B and replace the remote generation before resuming uploads.",
                    cancellationToken);
            }
        }
        catch (Exception exception)
        {
            security.LastFailure = exception is SafeApplicationException
                ? exception.Message
                : "Security epoch creation was interrupted.";
            await _securityStateStore.SaveAsync(
                security,
                CancellationToken.None);
            throw;
        }
        finally
        {
            if (!activated)
            {
                TryDeleteRecoveryStaging(databasePath);
                TryDeleteRecoveryStaging(keyPath);
            }
        }
    }

    private static void VerifyEpochSnapshot(
        IReadOnlyList<VaultAccountV2> expectedAccounts,
        IReadOnlyList<SecretVersionV2> expectedVersions,
        IReadOnlyList<AccountHistoryEntryV2> expectedHistory,
        V2VaultSnapshot actual,
        Guid? purgeAccountId)
    {
        if (actual.Accounts.Count != expectedAccounts.Count ||
            actual.SecretVersions.Count != expectedVersions.Count ||
            actual.HistoryEntries.Count != expectedHistory.Count ||
            expectedAccounts.Any(expected =>
                !actual.Accounts.Any(item => item.Id == expected.Id)) ||
            expectedVersions.Any(expected =>
                !actual.SecretVersions.Any(item =>
                    item.Id == expected.Id &&
                    CryptographicOperations.FixedTimeEquals(
                        item.Secret,
                        expected.Secret))) ||
            purgeAccountId.HasValue &&
            (actual.Accounts.Any(item => item.Id == purgeAccountId.Value) ||
             actual.SecretVersions.Any(
                 item => item.AccountId == purgeAccountId.Value) ||
             actual.HistoryEntries.Any(
                 item => item.AccountId == purgeAccountId.Value)))
        {
            throw new SafeApplicationException(
                "Security.EpochVerificationFailed",
                "The replacement key epoch failed complete vault verification.");
        }
    }

    private static SecurityEpochStatus ToEpochStatus(SecurityState state) =>
        new(
            state.ActiveEpoch,
            state.PendingEpoch,
            state.PendingEpoch.HasValue,
            state.PurgeAccountId.HasValue,
            state.PurgeAccountId,
            state.LastFailure);
}
