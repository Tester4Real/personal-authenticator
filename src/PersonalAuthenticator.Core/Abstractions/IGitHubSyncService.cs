using PersonalAuthenticator.Core.Domain;

namespace PersonalAuthenticator.Core.Abstractions;

public interface IGitHubSyncService
{
    Task ConfigureGitHubAsync(
        GitHubConnectionRequest request,
        ReadOnlyMemory<char> token,
        ReadOnlyMemory<char> syncPassword,
        CancellationToken cancellationToken);

    Task<GitHubSyncStatus> TestGitHubConnectionAsync(
        CancellationToken cancellationToken);

    Task<GitHubSyncStatus> SyncGitHubNowAsync(
        CancellationToken cancellationToken);

    Task SetGitHubBackgroundSyncAsync(
        bool enabled,
        CancellationToken cancellationToken);

    Task ReplaceGitHubRepositoryAsync(
        GitHubConnectionRequest request,
        ReadOnlyMemory<char> token,
        ReadOnlyMemory<char> syncPassword,
        CancellationToken cancellationToken);

    Task RepairGitHubRemoteAsync(CancellationToken cancellationToken);

    Task DisableAndForgetGitHubAsync(CancellationToken cancellationToken);

    Task<GitHubSyncStatus> GetGitHubStatusAsync(
        CancellationToken cancellationToken);
}
