using System.Security.Cryptography;
using System.Text.Json;
using PersonalAuthenticator.Core.Exceptions;
using PersonalAuthenticator.Infrastructure.Storage;

namespace PersonalAuthenticator.Infrastructure.GitHub;

internal sealed class GitHubSyncConfigStore
{
    private static readonly byte[] Entropy =
        SHA256.HashData("Personal Authenticator GitHub configuration v1"u8);
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
    };
    private readonly string _path;
    private readonly string _fallbackPath;

    public GitHubSyncConfigStore(string path)
    {
        _path = Path.GetFullPath(path);
        _fallbackPath = _path + ".disabled-fallback";
    }

    public bool Exists => File.Exists(_path);

    public Task SaveAsync(
        GitHubSyncConfiguration configuration,
        CancellationToken cancellationToken) =>
        SaveToAsync(_path, configuration, cancellationToken);

    public async Task SaveFallbackAsync(
        GitHubSyncConfiguration configuration,
        CancellationToken cancellationToken)
    {
        using GitHubSyncConfiguration fallback = configuration with
        {
            SyncKey = configuration.SyncKey.ToArray(),
            Enabled = false,
            BackgroundSyncEnabled = false,
        };
        await SaveToAsync(_fallbackPath, fallback, cancellationToken);
    }

    public async Task<GitHubSyncConfiguration> LoadAsync(
        CancellationToken cancellationToken)
    {
        byte[] protectedBytes = [];
        byte[] plaintext = [];
        try
        {
            protectedBytes = await File.ReadAllBytesAsync(_path, cancellationToken);
            plaintext = ProtectedData.Unprotect(
                protectedBytes,
                Entropy,
                DataProtectionScope.CurrentUser);
            GitHubSyncConfiguration? configuration =
                JsonSerializer.Deserialize<GitHubSyncConfiguration>(
                    plaintext,
                    JsonOptions);
            return Validate(configuration);
        }
        catch (SafeApplicationException)
        {
            throw;
        }
        catch (Exception exception) when (
            exception is IOException or
                CryptographicException or
                JsonException or
                ArgumentException)
        {
            throw new SafeApplicationException(
                "GitHub.ConfigInvalid",
                "The GitHub sync configuration is unavailable or invalid.",
                exception);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(protectedBytes);
            CryptographicOperations.ZeroMemory(plaintext);
        }
    }

    public void Delete()
    {
        if (File.Exists(_path))
        {
            File.Delete(_path);
        }
    }

    private static GitHubSyncConfiguration Validate(
        GitHubSyncConfiguration? configuration)
    {
        if (configuration is null ||
            configuration.RepositoryId <= 0 ||
            configuration.VaultId == Guid.Empty ||
            configuration.RemoteGeneration == Guid.Empty ||
            configuration.SyncKey.Length != 32 ||
            configuration.Owner.Length is < 1 or > 100 ||
            configuration.Repository.Length is < 1 or > 100 ||
            configuration.Branch.Length is < 1 or > 200 ||
            configuration.PathPrefix.Length is < 1 or > 200 ||
            configuration.KnownObjectHashes.Count > 1_000_000 ||
            configuration.VerifiedDeviceSequences.Count > 10_000)
        {
            configuration?.Dispose();
            throw new SafeApplicationException(
                "GitHub.ConfigInvalid",
                "The GitHub sync configuration is unavailable or invalid.");
        }

        return configuration;
    }

    private static async Task SaveToAsync(
        string path,
        GitHubSyncConfiguration configuration,
        CancellationToken cancellationToken)
    {
        byte[] plaintext = JsonSerializer.SerializeToUtf8Bytes(
            configuration,
            JsonOptions);
        byte[] protectedBytes = [];
        try
        {
            if (plaintext.Length > 32 * 1024 * 1024)
            {
                throw new SafeApplicationException(
                    "GitHub.ConfigTooLarge",
                    "The GitHub sync tracking state is too large.");
            }

            protectedBytes = ProtectedData.Protect(
                plaintext,
                Entropy,
                DataProtectionScope.CurrentUser);
            await AtomicFile.WriteAsync(
                path,
                protectedBytes,
                retainPrevious: true,
                overwriteExisting: true,
                cancellationToken);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext);
            CryptographicOperations.ZeroMemory(protectedBytes);
        }
    }
}
