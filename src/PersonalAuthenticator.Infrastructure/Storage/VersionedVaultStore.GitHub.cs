using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using PersonalAuthenticator.Core.Domain;
using PersonalAuthenticator.Core.Exceptions;
using PersonalAuthenticator.Infrastructure.GitHub;
using PersonalAuthenticator.Infrastructure.Sync;

namespace PersonalAuthenticator.Infrastructure.Storage;

public sealed partial class VersionedVaultStore
{
    private bool _githubIsSyncing;
    private string? _githubAuthenticationStatus;

    public async Task ConfigureGitHubAsync(
        GitHubConnectionRequest request,
        ReadOnlyMemory<char> token,
        ReadOnlyMemory<char> syncPassword,
        CancellationToken cancellationToken)
    {
        await _gate.WaitAsync(cancellationToken);
        try
        {
            _ = await GetActiveV2StoreAsync(cancellationToken);
            GitHubSyncConfiguration configuration =
                await BuildVerifiedGitHubConfigurationAsync(
                    request,
                    token,
                    syncPassword,
                    cancellationToken);
            using (configuration)
            {
                await _githubCredentialStore.SaveAsync(token, cancellationToken);
                await _githubConfigStore.SaveAsync(configuration, cancellationToken);
                ConfigureGitHubTimer(configuration.BackgroundSyncEnabled);
            }
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task<GitHubSyncStatus> TestGitHubConnectionAsync(
        CancellationToken cancellationToken)
    {
        await _gate.WaitAsync(cancellationToken);
        try
        {
            using GitHubSyncConfiguration configuration =
                await RequireGitHubConfigurationAsync(cancellationToken);
            char[] token = await _githubCredentialStore.LoadAsync(cancellationToken);
            try
            {
                await using IGitHubApiClient client =
                    _githubClientFactory.Create(token);
                await VerifyRepositoryAsync(
                    client,
                    configuration,
                    cancellationToken);
                _githubAuthenticationStatus = "Authenticated with Contents read/write access.";
                return await GetGitHubStatusCoreAsync(
                    configuration,
                    cancellationToken);
            }
            finally
            {
                Array.Clear(token);
            }
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task<GitHubSyncStatus> SyncGitHubNowAsync(
        CancellationToken cancellationToken)
    {
        await _gate.WaitAsync(cancellationToken);
        try
        {
            using GitHubSyncConfiguration configuration =
                await RequireGitHubConfigurationAsync(cancellationToken);
            if (!configuration.Enabled)
            {
                throw new SafeApplicationException(
                    "GitHub.Disabled",
                    "GitHub sync is disabled.");
            }

            _githubIsSyncing = true;
            try
            {
                using GitHubSyncConfiguration synced =
                    await SyncGitHubCoreAsync(
                    configuration,
                    repair: false,
                    uploadCompleteHistory: false,
                    persistConfiguration: true,
                    cancellationToken);
                using GitHubSyncConfiguration refreshed =
                    await _githubConfigStore.LoadAsync(cancellationToken);
                return await GetGitHubStatusCoreAsync(
                    refreshed,
                    cancellationToken);
            }
            finally
            {
                _githubIsSyncing = false;
            }
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task SetGitHubBackgroundSyncAsync(
        bool enabled,
        CancellationToken cancellationToken)
    {
        await _gate.WaitAsync(cancellationToken);
        try
        {
            using GitHubSyncConfiguration configuration =
                await RequireGitHubConfigurationAsync(cancellationToken);
            using GitHubSyncConfiguration updated = CloneConfiguration(
                configuration,
                backgroundSyncEnabled: enabled);
            await _githubConfigStore.SaveAsync(updated, cancellationToken);
            ConfigureGitHubTimer(enabled);
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task ReplaceGitHubRepositoryAsync(
        GitHubConnectionRequest request,
        ReadOnlyMemory<char> token,
        ReadOnlyMemory<char> syncPassword,
        CancellationToken cancellationToken)
    {
        await _gate.WaitAsync(cancellationToken);
        try
        {
            V2SqliteVaultStore store =
                await GetActiveV2StoreAsync(cancellationToken);
            using V2VaultSnapshot verified =
                await store.LoadAsync(cancellationToken);
            using GitHubSyncConfiguration candidate =
                await BuildVerifiedGitHubConfigurationAsync(
                    request,
                    token,
                    syncPassword,
                    cancellationToken,
                    forceNewGeneration: true);
            using GitHubSyncConfiguration uploaded =
                await SyncGitHubCoreAsync(
                candidate,
                repair: true,
                uploadCompleteHistory: true,
                persistConfiguration: false,
                cancellationToken,
                token);

            // A fresh client and full download are required before activation.
            await using (IGitHubApiClient freshClient =
                         _githubClientFactory.Create(token))
            {
                await VerifyCompleteRemoteAsync(
                    freshClient,
                    uploaded,
                    store,
                    cancellationToken);
            }

            if (_githubConfigStore.Exists)
            {
                using GitHubSyncConfiguration previous =
                    await _githubConfigStore.LoadAsync(cancellationToken);
                await _githubConfigStore.SaveFallbackAsync(
                    previous,
                    cancellationToken);
            }

            await _githubCredentialStore.SaveAsync(token, cancellationToken);
            await _githubConfigStore.SaveAsync(uploaded, cancellationToken);
            ConfigureGitHubTimer(uploaded.BackgroundSyncEnabled);
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task RepairGitHubRemoteAsync(CancellationToken cancellationToken)
    {
        await _gate.WaitAsync(cancellationToken);
        try
        {
            using GitHubSyncConfiguration configuration =
                await RequireGitHubConfigurationAsync(cancellationToken);
            using GitHubSyncConfiguration repaired =
                await SyncGitHubCoreAsync(
                configuration,
                repair: true,
                uploadCompleteHistory: true,
                persistConfiguration: true,
                cancellationToken);
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task DisableAndForgetGitHubAsync(
        CancellationToken cancellationToken)
    {
        await _gate.WaitAsync(cancellationToken);
        try
        {
            _githubBackgroundTimer?.Dispose();
            _githubBackgroundTimer = null;
            _githubDebounceTimer?.Dispose();
            _githubDebounceTimer = null;
            _githubCredentialStore.Delete();
            if (_githubCredentialStore.Exists)
            {
                throw new SafeApplicationException(
                    "GitHub.CredentialRemovalFailed",
                    "Windows could not verify removal of the stored GitHub token.");
            }

            _githubConfigStore.Delete();
            _githubAuthenticationStatus = null;
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task<GitHubSyncStatus> GetGitHubStatusAsync(
        CancellationToken cancellationToken)
    {
        await _gate.WaitAsync(cancellationToken);
        try
        {
            if (!_githubConfigStore.Exists)
            {
                return EmptyGitHubStatus();
            }

            using GitHubSyncConfiguration configuration =
                await _githubConfigStore.LoadAsync(cancellationToken);
            return await GetGitHubStatusCoreAsync(
                configuration,
                cancellationToken);
        }
        finally
        {
            _gate.Release();
        }
    }

    private async Task<GitHubSyncConfiguration> SyncGitHubCoreAsync(
        GitHubSyncConfiguration configuration,
        bool repair,
        bool uploadCompleteHistory,
        bool persistConfiguration,
        CancellationToken cancellationToken,
        ReadOnlyMemory<char>? suppliedToken = null)
    {
        char[]? storedToken = null;
        ReadOnlyMemory<char> token;
        if (suppliedToken.HasValue)
        {
            token = suppliedToken.Value;
        }
        else
        {
            storedToken =
                await _githubCredentialStore.LoadAsync(cancellationToken);
            token = storedToken;
        }

        try
        {
            await using IGitHubApiClient client = _githubClientFactory.Create(token);
            await VerifyRepositoryAsync(client, configuration, cancellationToken);
            string branchHead = await client.GetBranchHeadAsync(
                configuration.Owner,
                configuration.Repository,
                configuration.Branch,
                cancellationToken);
            if (!repair &&
                configuration.KnownBranchHead is not null &&
                !await client.IsAncestorAsync(
                    configuration.Owner,
                    configuration.Repository,
                    configuration.KnownBranchHead,
                    branchHead,
                    cancellationToken))
            {
                await PauseGitHubUploadsAsync(
                    configuration,
                    "Remote rollback or force-push detected. Use Remote Repair.",
                    cancellationToken);
                throw new SafeApplicationException(
                    "GitHub.RemoteRollback",
                    "GitHub history moved backwards or diverged. Local data was not rolled back and uploads are paused.");
            }

            IReadOnlyList<GitHubRemoteEntry> entries = await client.ListFilesAsync(
                configuration.Owner,
                configuration.Repository,
                configuration.Branch,
                configuration.PathPrefix,
                cancellationToken);
            Dictionary<string, GitHubRemoteEntry> byPath =
                entries.ToDictionary(item => item.Path, StringComparer.Ordinal);
            if (!repair)
            {
                foreach ((Guid operationId, string knownSha) in
                         configuration.KnownObjectHashes)
                {
                    string path = GetOperationPath(configuration, operationId);
                    if (!byPath.TryGetValue(path, out GitHubRemoteEntry? entry) ||
                        entry.Sha != knownSha)
                    {
                        await PauseGitHubUploadsAsync(
                            configuration,
                            "Previously verified remote objects disappeared or changed. Use Remote Repair.",
                            cancellationToken);
                        throw new SafeApplicationException(
                            "GitHub.RemoteRollback",
                            "Previously verified GitHub objects disappeared or changed. Local data was not rolled back.");
                    }
                }
            }

            V2SqliteVaultStore store =
                await GetActiveV2StoreAsync(cancellationToken);
            var downloaded = new List<SyncOperation>();
            var known = new Dictionary<Guid, string>(
                configuration.KnownObjectHashes);
            try
            {
                foreach (GitHubRemoteEntry entry in entries.Where(item =>
                             item.Path.Contains("/objects/", StringComparison.Ordinal)))
                {
                    Guid operationId = ParseOperationId(entry.Path);
                    if (known.TryGetValue(operationId, out string? sha) &&
                        sha == entry.Sha)
                    {
                        continue;
                    }

                    using GitHubRemoteFile remote =
                        await client.GetFileAsync(
                            configuration.Owner,
                            configuration.Repository,
                            entry.Path,
                            configuration.Branch,
                            etag: null,
                            cancellationToken) ??
                        throw new SafeApplicationException(
                            "GitHub.RemoteObjectMissing",
                            "A listed GitHub sync object disappeared during download.");
                    try
                    {
                        downloaded.Add(
                            GitHubRemoteProtocol.DecryptOperation(
                                configuration,
                                remote.Content));
                        known[operationId] = remote.Sha;
                    }
                    catch (Exception exception) when (
                        exception is CryptographicException or
                            SafeApplicationException)
                    {
                        await QuarantineGitHubObjectAsync(
                            operationId,
                            remote.Content,
                            cancellationToken);
                        await PauseGitHubUploadsAsync(
                            configuration,
                            "A corrupt or incompatible remote object was quarantined.",
                            cancellationToken);
                        throw;
                    }
                }

                await store.ApplyRemoteOperationsAsync(
                    downloaded,
                    cancellationToken);
            }
            finally
            {
                foreach (SyncOperation operation in downloaded)
                {
                    operation.Dispose();
                }
            }

            if (configuration.UploadsPaused && !repair)
            {
                throw new SafeApplicationException(
                    "GitHub.UploadsPaused",
                    "GitHub uploads are paused until Remote Repair succeeds.");
            }

            IReadOnlyList<SyncOperation> toUpload;
            SyncRecoveryState? completeState = null;
            if (uploadCompleteHistory)
            {
                completeState = await store.ExportSyncRecoveryStateAsync(
                    configuration: null,
                    cancellationToken);
                toUpload = completeState.SerializedOperations
                    .Select(bytes => SyncOperationSerializer.Deserialize(bytes))
                    .ToList();
            }
            else
            {
                toUpload = await store.LoadOutboxAsync(cancellationToken);
            }

            try
            {
                var acknowledged = new List<Guid>();
                foreach (SyncOperation operation in toUpload)
                {
                    byte[] envelope =
                        GitHubRemoteProtocol.EncryptOperation(
                            configuration,
                            operation);
                    try
                    {
                        string path = GetOperationPath(configuration, operation.Id);
                        GitHubRemoteFile? existing = await client.GetFileAsync(
                            configuration.Owner,
                            configuration.Repository,
                            path,
                            configuration.Branch,
                            etag: null,
                            cancellationToken);
                        if (existing is not null)
                        {
                            using (existing)
                            {
                                if (!CryptographicOperations.FixedTimeEquals(
                                        existing.Content,
                                        envelope))
                                {
                                    throw new SafeApplicationException(
                                        "GitHub.ObjectCollision",
                                        "An immutable GitHub object ID already exists with different bytes.");
                                }

                                known[operation.Id] = existing.Sha;
                            }
                        }
                        else
                        {
                            GitHubPutResult put = await PutWithLostResponseRecoveryAsync(
                                client,
                                configuration,
                                path,
                                envelope,
                                cancellationToken);
                            using GitHubRemoteFile verified =
                                await client.GetFileAsync(
                                    configuration.Owner,
                                    configuration.Repository,
                                    path,
                                    configuration.Branch,
                                    etag: null,
                                    cancellationToken) ??
                                throw new SafeApplicationException(
                                    "GitHub.UploadVerificationFailed",
                                    "GitHub did not return the uploaded sync object.");
                            if (!CryptographicOperations.FixedTimeEquals(
                                    verified.Content,
                                    envelope))
                            {
                                throw new SafeApplicationException(
                                    "GitHub.UploadVerificationFailed",
                                    "The uploaded GitHub object failed verification.");
                            }

                            known[operation.Id] = verified.Sha;
                            _ = put;
                        }

                        acknowledged.Add(operation.Id);
                    }
                    finally
                    {
                        CryptographicOperations.ZeroMemory(envelope);
                    }
                }

                if (persistConfiguration)
                {
                    await store.MarkOutboxSentAsync(
                        acknowledged,
                        cancellationToken);
                }
            }
            finally
            {
                foreach (SyncOperation operation in toUpload)
                {
                    operation.Dispose();
                }

                completeState?.Dispose();
            }

            using SyncRecoveryState state = await store.ExportSyncRecoveryStateAsync(
                configuration: null,
                cancellationToken);
            await UploadIndexesAsync(
                client,
                configuration,
                state,
                cancellationToken);
            string finalHead = await client.GetBranchHeadAsync(
                configuration.Owner,
                configuration.Repository,
                configuration.Branch,
                cancellationToken);
            using GitHubSyncConfiguration updated = CloneConfiguration(
                configuration,
                uploadsPaused: false,
                knownBranchHead: finalHead,
                knownObjectHashes: known,
                verifiedDeviceSequences:
                    state.DeviceSequenceCoverage.ToDictionary(),
                lastSuccessfulSyncAtUtc: DateTimeOffset.UtcNow,
                rateLimitResetsAtUtc: client.RateLimitResetsAtUtc,
                clearLastError: true);
            if (persistConfiguration)
            {
                await _githubConfigStore.SaveAsync(updated, cancellationToken);
            }

            _githubAuthenticationStatus = "Authenticated";
            return CloneConfiguration(updated);
        }
        catch (SafeApplicationException exception)
        {
            if (persistConfiguration && _githubConfigStore.Exists)
            {
                using GitHubSyncConfiguration current =
                    await _githubConfigStore.LoadAsync(CancellationToken.None);
                using GitHubSyncConfiguration failed = CloneConfiguration(
                    current,
                    lastError: exception.Message);
                await _githubConfigStore.SaveAsync(
                    failed,
                    CancellationToken.None);
            }

            throw;
        }
        finally
        {
            if (storedToken is not null)
            {
                Array.Clear(storedToken);
            }
        }
    }

    private async Task<GitHubSyncConfiguration>
        BuildVerifiedGitHubConfigurationAsync(
            GitHubConnectionRequest request,
            ReadOnlyMemory<char> token,
            ReadOnlyMemory<char> syncPassword,
            CancellationToken cancellationToken,
            bool forceNewGeneration = false)
    {
        ValidateGitHubRequest(request);
        await using IGitHubApiClient client = _githubClientFactory.Create(token);
        _ = await client.GetUserAsync(cancellationToken);
        GitHubRepositoryInfo repository = await client.GetRepositoryAsync(
            request.Owner,
            request.Repository,
            cancellationToken);
        EnsurePrivateWritable(repository);
        string? requestedBranchHead = await client.TryGetBranchHeadAsync(
            request.Owner,
            request.Repository,
            request.Branch,
            cancellationToken);
        bool initializeEmptyRepository = false;
        string branchHead;
        if (requestedBranchHead is not null)
        {
            branchHead = requestedBranchHead;
        }
        else
        {
            string? defaultBranchHead =
                string.Equals(
                    request.Branch,
                    repository.DefaultBranch,
                    StringComparison.Ordinal)
                    ? null
                    : await client.TryGetBranchHeadAsync(
                        request.Owner,
                        request.Repository,
                        repository.DefaultBranch,
                        cancellationToken);
            if (defaultBranchHead is null)
            {
                initializeEmptyRepository = true;
                branchHead = string.Empty;
            }
            else
            {
                await client.CreateBranchAsync(
                    request.Owner,
                    request.Repository,
                    request.Branch,
                    defaultBranchHead,
                    cancellationToken);
                branchHead = defaultBranchHead;
            }
        }

        string descriptorPath = request.PathPrefix + "/descriptor.json";
        GitHubRemoteDescriptor descriptor;
        byte[] key;
        using GitHubRemoteFile? remote = await client.GetFileAsync(
            request.Owner,
            request.Repository,
            descriptorPath,
            request.Branch,
            etag: null,
            cancellationToken);
        if (forceNewGeneration && remote is not null)
        {
            throw new SafeApplicationException(
                "GitHub.ReplacementNotEmpty",
                "The replacement sync path already contains an authenticator descriptor. Choose an empty path or repository.");
        }

        if (remote is null)
        {
            (descriptor, key) =
                await GitHubRemoteProtocol.CreateDescriptorAsync(
                    repository.Id,
                    Guid.NewGuid(),
                    Guid.NewGuid(),
                    syncPassword,
                    cancellationToken);
            byte[] bytes = GitHubRemoteProtocol.SerializeDescriptor(descriptor);
            try
            {
                if (initializeEmptyRepository)
                {
                    GitHubPutResult initialized =
                        await client.InitializeEmptyRepositoryAsync(
                            request.Owner,
                            request.Repository,
                            descriptorPath,
                            bytes,
                            cancellationToken);
                    branchHead = initialized.CommitSha;
                    if (!string.Equals(
                            request.Branch,
                            repository.DefaultBranch,
                            StringComparison.Ordinal))
                    {
                        await client.CreateBranchAsync(
                            request.Owner,
                            request.Repository,
                            request.Branch,
                            initialized.CommitSha,
                            cancellationToken);
                    }
                }
                else
                {
                    await client.PutFileAsync(
                        request.Owner,
                        request.Repository,
                        descriptorPath,
                        request.Branch,
                        bytes,
                        existingSha: null,
                        cancellationToken);
                }

                using GitHubRemoteFile reopened =
                    await client.GetFileAsync(
                        request.Owner,
                        request.Repository,
                        descriptorPath,
                        request.Branch,
                        etag: null,
                        cancellationToken) ??
                    throw new SafeApplicationException(
                        "GitHub.DescriptorVerificationFailed",
                        "The GitHub sync descriptor could not be reopened after upload.");
                if (!CryptographicOperations.FixedTimeEquals(
                        reopened.Content,
                        bytes))
                {
                    throw new SafeApplicationException(
                        "GitHub.DescriptorVerificationFailed",
                        "The uploaded GitHub sync descriptor failed verification.");
                }

                GitHubRemoteDescriptor verified =
                    GitHubRemoteProtocol.DeserializeDescriptor(reopened.Content);
                if (verified.RepositoryId != descriptor.RepositoryId ||
                    verified.VaultId != descriptor.VaultId ||
                    verified.RemoteGeneration != descriptor.RemoteGeneration)
                {
                    throw new SafeApplicationException(
                        "GitHub.DescriptorVerificationFailed",
                        "The uploaded GitHub sync descriptor identifies different data.");
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(bytes);
            }

            branchHead = await client.GetBranchHeadAsync(
                request.Owner,
                request.Repository,
                request.Branch,
                cancellationToken);
        }
        else
        {
            descriptor =
                GitHubRemoteProtocol.DeserializeDescriptor(remote.Content);
            key = await GitHubRemoteProtocol.OpenDescriptorAsync(
                descriptor,
                repository.Id,
                syncPassword,
                cancellationToken);
        }

        return new GitHubSyncConfiguration(
            repository.Owner,
            repository.Name,
            request.Branch,
            request.PathPrefix,
            repository.Id,
            descriptor.VaultId,
            descriptor.RemoteGeneration,
            key,
            Enabled: true,
            request.BackgroundSyncEnabled,
            UploadsPaused: false,
            branchHead,
            [],
            [],
            LastSuccessfulSyncAtUtc: null,
            RateLimitResetsAtUtc: null,
            LastError: null);
    }

    private static async Task VerifyRepositoryAsync(
        IGitHubApiClient client,
        GitHubSyncConfiguration configuration,
        CancellationToken cancellationToken)
    {
        _ = await client.GetUserAsync(cancellationToken);
        GitHubRepositoryInfo repository = await client.GetRepositoryAsync(
            configuration.Owner,
            configuration.Repository,
            cancellationToken);
        EnsurePrivateWritable(repository);
        if (repository.Id != configuration.RepositoryId)
        {
            throw new SafeApplicationException(
                "GitHub.RepositoryRecreated",
                "The repository name now points to a different numeric repository ID. Uploads were stopped.");
        }

        if (!string.Equals(
                repository.Owner,
                configuration.Owner,
                StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(
                repository.Name,
                configuration.Repository,
                StringComparison.OrdinalIgnoreCase))
        {
            throw new SafeApplicationException(
                "GitHub.RepositoryRenamedOrTransferred",
                "The repository was renamed or transferred. Reconnect only after verifying its identity.");
        }

        using GitHubRemoteFile descriptorFile =
            await client.GetFileAsync(
                configuration.Owner,
                configuration.Repository,
                configuration.PathPrefix + "/descriptor.json",
                configuration.Branch,
                etag: null,
                cancellationToken) ??
            throw new SafeApplicationException(
                "GitHub.DescriptorMissing",
                "The GitHub sync descriptor is missing.");
        GitHubRemoteDescriptor descriptor =
            GitHubRemoteProtocol.DeserializeDescriptor(descriptorFile.Content);
        if (descriptor.ProtocolVersion != GitHubRemoteProtocol.ProtocolVersion ||
            descriptor.RequiredFeatures.Any(feature =>
                feature != GitHubRemoteProtocol.RequiredFeature))
        {
            throw new SafeApplicationException(
                "GitHub.UnsupportedRequiredFeature",
                "The repository requires a newer sync protocol. Uploads were stopped.");
        }

        if (descriptor.RepositoryId != configuration.RepositoryId ||
            descriptor.VaultId != configuration.VaultId ||
            descriptor.RemoteGeneration != configuration.RemoteGeneration)
        {
            throw new SafeApplicationException(
                "GitHub.WrongVaultRepository",
                "The GitHub repository belongs to a different vault or remote generation.");
        }
    }

    private static async Task VerifyCompleteRemoteAsync(
        IGitHubApiClient client,
        GitHubSyncConfiguration configuration,
        V2SqliteVaultStore store,
        CancellationToken cancellationToken)
    {
        await VerifyRepositoryAsync(client, configuration, cancellationToken);
        using SyncRecoveryState state = await store.ExportSyncRecoveryStateAsync(
            configuration: null,
            cancellationToken);
        IReadOnlyList<GitHubRemoteEntry> entries = await client.ListFilesAsync(
            configuration.Owner,
            configuration.Repository,
            configuration.Branch,
            configuration.PathPrefix,
            cancellationToken);
        Dictionary<Guid, GitHubRemoteEntry> remoteOperations = entries
            .Where(item => item.Path.Contains("/objects/", StringComparison.Ordinal))
            .ToDictionary(item => ParseOperationId(item.Path));
        foreach (byte[] expectedBytes in state.SerializedOperations)
        {
            using SyncOperation expected =
                SyncOperationSerializer.Deserialize(expectedBytes);
            if (!remoteOperations.TryGetValue(
                    expected.Id,
                    out GitHubRemoteEntry? entry))
            {
                throw ReplacementVerificationFailed();
            }

            using GitHubRemoteFile remote =
                await client.GetFileAsync(
                    configuration.Owner,
                    configuration.Repository,
                    entry.Path,
                    configuration.Branch,
                    etag: null,
                    cancellationToken) ??
                throw ReplacementVerificationFailed();
            if (!string.Equals(remote.Sha, entry.Sha, StringComparison.Ordinal))
            {
                throw ReplacementVerificationFailed();
            }

            using SyncOperation reopened =
                GitHubRemoteProtocol.DecryptOperation(
                    configuration,
                    remote.Content);
            byte[] actualBytes = SyncOperationSerializer.Serialize(reopened);
            try
            {
                if (!CryptographicOperations.FixedTimeEquals(
                        expectedBytes,
                        actualBytes))
                {
                    throw ReplacementVerificationFailed();
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(actualBytes);
            }
        }
    }

    private static SafeApplicationException ReplacementVerificationFailed() =>
        new(
            "GitHub.ReplacementVerificationFailed",
            "The replacement repository failed encrypted operation, hash, or coverage verification.");

    private static async Task UploadIndexesAsync(
        IGitHubApiClient client,
        GitHubSyncConfiguration configuration,
        SyncRecoveryState state,
        CancellationToken cancellationToken)
    {
        byte[] snapshotPlaintext = JsonSerializer.SerializeToUtf8Bytes(
            new
            {
                protocol = state.ProtocolVersion,
                required = state.RequiredFeatures,
                coverage = state.DeviceSequenceCoverage,
                operations = state.SerializedOperations.Count,
                conflicts = state.UnresolvedConflicts.Count,
            });
        byte[] headPlaintext = JsonSerializer.SerializeToUtf8Bytes(
            new
            {
                protocol = state.ProtocolVersion,
                required = state.RequiredFeatures,
                deviceId = state.DeviceId,
                highestSequence = state.DeviceSequenceCoverage
                    .GetValueOrDefault(state.DeviceId),
                coverage = state.DeviceSequenceCoverage,
            });
        Guid snapshotId = Guid.NewGuid();
        Guid headObjectId = Guid.NewGuid();
        byte[] encryptedSnapshot = GitHubRemoteProtocol.EncryptMetadata(
            configuration,
            snapshotId,
            snapshotPlaintext);
        byte[] encryptedHead = GitHubRemoteProtocol.EncryptMetadata(
            configuration,
            headObjectId,
            headPlaintext);
        string snapshotPath =
            $"{configuration.PathPrefix}/snapshots/{snapshotId:N}.pas";
        string headPath =
            $"{configuration.PathPrefix}/heads/{state.DeviceId:N}.pah";
        try
        {
            await PutAndVerifyAsync(
                client,
                configuration,
                snapshotPath,
                encryptedSnapshot,
                existingSha: null,
                cancellationToken);
            using GitHubRemoteFile? existingHead = await client.GetFileAsync(
                configuration.Owner,
                configuration.Repository,
                headPath,
                configuration.Branch,
                etag: null,
                cancellationToken);
            await PutAndVerifyAsync(
                client,
                configuration,
                headPath,
                encryptedHead,
                existingHead?.Sha,
                cancellationToken);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(snapshotPlaintext);
            CryptographicOperations.ZeroMemory(headPlaintext);
            CryptographicOperations.ZeroMemory(encryptedSnapshot);
            CryptographicOperations.ZeroMemory(encryptedHead);
        }
    }

    private static async Task PutAndVerifyAsync(
        IGitHubApiClient client,
        GitHubSyncConfiguration configuration,
        string path,
        byte[] content,
        string? existingSha,
        CancellationToken cancellationToken)
    {
        await client.PutFileAsync(
            configuration.Owner,
            configuration.Repository,
            path,
            configuration.Branch,
            content,
            existingSha,
            cancellationToken);
        using GitHubRemoteFile verified =
            await client.GetFileAsync(
                configuration.Owner,
                configuration.Repository,
                path,
                configuration.Branch,
                etag: null,
                cancellationToken) ??
            throw new SafeApplicationException(
                "GitHub.UploadVerificationFailed",
                "GitHub did not return an uploaded encrypted index.");
        if (!CryptographicOperations.FixedTimeEquals(verified.Content, content))
        {
            throw new SafeApplicationException(
                "GitHub.UploadVerificationFailed",
                "An uploaded encrypted index failed verification.");
        }
    }

    private static async Task<GitHubPutResult> PutWithLostResponseRecoveryAsync(
        IGitHubApiClient client,
        GitHubSyncConfiguration configuration,
        string path,
        byte[] content,
        CancellationToken cancellationToken)
    {
        try
        {
            return await client.PutFileAsync(
                configuration.Owner,
                configuration.Repository,
                path,
                configuration.Branch,
                content,
                existingSha: null,
                cancellationToken);
        }
        catch (SafeApplicationException exception) when (
            exception.ErrorCode is
                "GitHub.NetworkUnavailable" or
                "GitHub.RequestFailed")
        {
            using GitHubRemoteFile? recovered = await client.GetFileAsync(
                configuration.Owner,
                configuration.Repository,
                path,
                configuration.Branch,
                etag: null,
                cancellationToken);
            if (recovered is not null &&
                CryptographicOperations.FixedTimeEquals(
                    recovered.Content,
                    content))
            {
                return new GitHubPutResult(recovered.Sha, string.Empty);
            }

            throw;
        }
    }

    private async Task PauseGitHubUploadsAsync(
        GitHubSyncConfiguration configuration,
        string reason,
        CancellationToken cancellationToken)
    {
        using GitHubSyncConfiguration paused = CloneConfiguration(
            configuration,
            uploadsPaused: true,
            lastError: reason);
        await _githubConfigStore.SaveAsync(paused, cancellationToken);
    }

    private async Task QuarantineGitHubObjectAsync(
        Guid operationId,
        byte[] encryptedBytes,
        CancellationToken cancellationToken)
    {
        string path = Path.Combine(
            _baseDirectory,
            "github-quarantine",
            $"{operationId:N}.{DateTimeOffset.UtcNow:yyyyMMddHHmmssfff}.bad");
        await AtomicFile.WriteAsync(
            path,
            encryptedBytes,
            retainPrevious: false,
            overwriteExisting: false,
            cancellationToken);
    }

    private async Task<GitHubSyncConfiguration>
        RequireGitHubConfigurationAsync(CancellationToken cancellationToken)
    {
        if (!_githubConfigStore.Exists || !_githubCredentialStore.Exists)
        {
            throw new SafeApplicationException(
                "GitHub.NotConfigured",
                "Configure GitHub sync and a repository token first.");
        }

        return await _githubConfigStore.LoadAsync(cancellationToken);
    }

    private async Task<GitHubSyncStatus> GetGitHubStatusCoreAsync(
        GitHubSyncConfiguration configuration,
        CancellationToken cancellationToken)
    {
        int pending = 0;
        try
        {
            V2SqliteVaultStore store =
                await GetActiveV2StoreAsync(cancellationToken);
            pending = await store.GetOutboxCountAsync(cancellationToken);
        }
        catch (SafeApplicationException)
        {
            // Status remains available while the vault is locked/unavailable.
        }

        return new GitHubSyncStatus(
            IsConfigured: true,
            configuration.Enabled,
            configuration.BackgroundSyncEnabled,
            _githubIsSyncing,
            configuration.UploadsPaused,
            $"{configuration.Owner}/{configuration.Repository}@{configuration.Branch}",
            configuration.RepositoryId,
            configuration.VaultId,
            configuration.RemoteGeneration,
            pending,
            configuration.LastSuccessfulSyncAtUtc,
            configuration.RateLimitResetsAtUtc,
            configuration.UploadsPaused ? "Uploads paused" : "Healthy",
            _githubAuthenticationStatus,
            configuration.LastError);
    }

    private void ConfigureGitHubTimer(bool enabled)
    {
        _githubBackgroundTimer?.Dispose();
        _githubBackgroundTimer = null;
        if (!enabled)
        {
            return;
        }

        _githubBackgroundTimer = new Timer(
            static state =>
            {
                var store = (VersionedVaultStore)state!;
                _ = store.RunBackgroundGitHubSyncAsync();
            },
            this,
            TimeSpan.FromMinutes(5),
            TimeSpan.FromMinutes(15));
    }

    private async Task RunBackgroundGitHubSyncAsync()
    {
        try
        {
            if (!_githubConfigStore.Exists || !_githubCredentialStore.Exists)
            {
                return;
            }

            using GitHubSyncConfiguration configuration =
                await _githubConfigStore.LoadAsync(CancellationToken.None);
            if (!configuration.Enabled ||
                !configuration.BackgroundSyncEnabled)
            {
                return;
            }

            await SyncGitHubNowAsync(CancellationToken.None);
        }
        catch (Exception exception) when (
            exception is SafeApplicationException or OperationCanceledException)
        {
            // Safe status is persisted by the coordinator; no diagnostic body,
            // token, response, or authorization header is logged.
        }
    }

    private void ScheduleGitHubSyncAfterLocalChange()
    {
        if (!_githubConfigStore.Exists || _disposed)
        {
            return;
        }

        _githubDebounceTimer?.Dispose();
        _githubDebounceTimer = new Timer(
            static state =>
            {
                var store = (VersionedVaultStore)state!;
                _ = store.RunBackgroundGitHubSyncAsync();
            },
            this,
            TimeSpan.FromSeconds(5),
            Timeout.InfiniteTimeSpan);
    }

    private static string GetOperationPath(
        GitHubSyncConfiguration configuration,
        Guid operationId)
    {
        string id = operationId.ToString("N");
        return $"{configuration.PathPrefix}/objects/{id[..2]}/{id}.pao";
    }

    private static Guid ParseOperationId(string path)
    {
        string name = Path.GetFileNameWithoutExtension(path);
        if (name.Length != 32 ||
            !Guid.TryParseExact(name, "N", out Guid id) ||
            id == Guid.Empty)
        {
            throw new SafeApplicationException(
                "GitHub.InvalidRemotePath",
                "The GitHub sync repository contains an invalid object path.");
        }

        return id;
    }

    private static void ValidateGitHubRequest(GitHubConnectionRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        string[] values =
        [
            request.Owner,
            request.Repository,
            request.Branch,
            request.PathPrefix,
        ];
        if (values.Any(value =>
                string.IsNullOrWhiteSpace(value) ||
                value.Length > 200 ||
                value.Contains("..", StringComparison.Ordinal) ||
                value.Contains('\\') ||
                value.StartsWith('/') ||
                value.EndsWith('/')))
        {
            throw new SafeApplicationException(
                "GitHub.InvalidConfiguration",
                "The GitHub owner, repository, branch, or sync path is invalid.");
        }
    }

    private static void EnsurePrivateWritable(GitHubRepositoryInfo repository)
    {
        if (!repository.IsPrivate)
        {
            throw new SafeApplicationException(
                "GitHub.RepositoryPublic",
                "The GitHub repository is public. Uploads were stopped immediately.");
        }

        if (repository.Permissions != "contents:write")
        {
            throw new SafeApplicationException(
                "GitHub.PermissionDenied",
                "The token needs Contents read/write access to the selected private repository.");
        }
    }

    private static GitHubSyncConfiguration CloneConfiguration(
        GitHubSyncConfiguration source,
        bool? backgroundSyncEnabled = null,
        bool? uploadsPaused = null,
        string? knownBranchHead = null,
        Dictionary<Guid, string>? knownObjectHashes = null,
        Dictionary<Guid, long>? verifiedDeviceSequences = null,
        DateTimeOffset? lastSuccessfulSyncAtUtc = null,
        DateTimeOffset? rateLimitResetsAtUtc = null,
        string? lastError = null,
        bool clearLastError = false) =>
        source with
        {
            SyncKey = source.SyncKey.ToArray(),
            BackgroundSyncEnabled =
                backgroundSyncEnabled ?? source.BackgroundSyncEnabled,
            UploadsPaused = uploadsPaused ?? source.UploadsPaused,
            KnownBranchHead = knownBranchHead ?? source.KnownBranchHead,
            KnownObjectHashes =
                knownObjectHashes ?? new(source.KnownObjectHashes),
            VerifiedDeviceSequences =
                verifiedDeviceSequences ?? new(source.VerifiedDeviceSequences),
            LastSuccessfulSyncAtUtc =
                lastSuccessfulSyncAtUtc ?? source.LastSuccessfulSyncAtUtc,
            RateLimitResetsAtUtc =
                rateLimitResetsAtUtc ?? source.RateLimitResetsAtUtc,
            LastError = clearLastError ? null : lastError ?? source.LastError,
        };

    private static GitHubSyncStatus EmptyGitHubStatus() =>
        new(
            IsConfigured: false,
            IsEnabled: false,
            IsBackgroundSyncEnabled: false,
            IsSyncing: false,
            UploadsPaused: false,
            Repository: null,
            RepositoryId: null,
            VaultId: null,
            RemoteGeneration: null,
            PendingOperationCount: 0,
            LastSuccessfulSyncAtUtc: null,
            RateLimitResetsAtUtc: null,
            RemoteHealth: "Not configured",
            AuthenticationStatus: null,
            LastError: null);
}
