namespace PersonalAuthenticator.Core.Domain;

public sealed class V2VaultSnapshot : IDisposable
{
    private bool _disposed;

    public V2VaultSnapshot(
        IReadOnlyList<VaultAccountV2> accounts,
        IReadOnlyList<SecretVersionV2> secretVersions)
    {
        ArgumentNullException.ThrowIfNull(accounts);
        ArgumentNullException.ThrowIfNull(secretVersions);
        Accounts = accounts;
        SecretVersions = secretVersions;
    }

    public IReadOnlyList<VaultAccountV2> Accounts { get; }

    public IReadOnlyList<SecretVersionV2> SecretVersions { get; }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        foreach (SecretVersionV2 version in SecretVersions)
        {
            version.Dispose();
        }
    }
}
