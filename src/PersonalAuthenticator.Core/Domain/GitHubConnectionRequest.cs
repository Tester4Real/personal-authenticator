namespace PersonalAuthenticator.Core.Domain;

public sealed record GitHubConnectionRequest(
    string Owner,
    string Repository,
    string Branch,
    string PathPrefix,
    bool BackgroundSyncEnabled);
