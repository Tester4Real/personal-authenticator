namespace PersonalAuthenticator.Infrastructure.Storage;

internal interface IVaultRootKeyProvider
{
    bool Exists { get; }

    Task<byte[]> LoadAsync(CancellationToken cancellationToken);

    Task<byte[]> LoadOrCreateAsync(CancellationToken cancellationToken);
}
