using System.Security.Cryptography;
using PersonalAuthenticator.Core.Exceptions;
using PersonalAuthenticator.Infrastructure.Storage;

namespace PersonalAuthenticator.Infrastructure.Sync;

internal sealed class DpapiDeviceIdentityStore
{
    private static readonly byte[] Entropy =
        SHA256.HashData("Personal Authenticator Windows sync device identity v1"u8);
    private readonly string _path;

    public DpapiDeviceIdentityStore(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        _path = Path.GetFullPath(path);
    }

    public async Task<Guid> LoadOrCreateAsync(CancellationToken cancellationToken)
    {
        if (File.Exists(_path))
        {
            return await LoadAsync(cancellationToken);
        }

        Guid deviceId = Guid.NewGuid();
        byte[] plaintext = deviceId.ToByteArray();
        byte[] protectedBytes = [];
        try
        {
            protectedBytes = ProtectedData.Protect(
                plaintext,
                Entropy,
                DataProtectionScope.CurrentUser);
            await AtomicFile.WriteAsync(
                _path,
                protectedBytes,
                retainPrevious: true,
                overwriteExisting: false,
                cancellationToken);
            return deviceId;
        }
        catch (IOException) when (File.Exists(_path))
        {
            return await LoadAsync(cancellationToken);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext);
            CryptographicOperations.ZeroMemory(protectedBytes);
        }
    }

    private async Task<Guid> LoadAsync(CancellationToken cancellationToken)
    {
        byte[] protectedBytes = [];
        byte[] plaintext = [];
        try
        {
            protectedBytes = await File.ReadAllBytesAsync(_path, cancellationToken);
            if (protectedBytes.Length is < 16 or > 4096)
            {
                throw InvalidIdentity();
            }

            plaintext = ProtectedData.Unprotect(
                protectedBytes,
                Entropy,
                DataProtectionScope.CurrentUser);
            if (plaintext.Length != 16)
            {
                throw InvalidIdentity();
            }

            Guid deviceId = new(plaintext);
            return deviceId != Guid.Empty ? deviceId : throw InvalidIdentity();
        }
        catch (SafeApplicationException)
        {
            throw;
        }
        catch (Exception exception) when (
            exception is IOException or CryptographicException)
        {
            throw new SafeApplicationException(
                "Sync.DeviceIdentityInvalid",
                "The local Windows sync device identity is unavailable or corrupt.",
                exception);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(protectedBytes);
            CryptographicOperations.ZeroMemory(plaintext);
        }
    }

    private static SafeApplicationException InvalidIdentity() =>
        new(
            "Sync.DeviceIdentityInvalid",
            "The local Windows sync device identity is unavailable or corrupt.");
}
