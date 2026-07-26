using System.Buffers.Binary;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using Microsoft.Extensions.Logging;
using PersonalAuthenticator.Core.Abstractions;
using PersonalAuthenticator.Core.Domain;
using PersonalAuthenticator.Core.Exceptions;
using PersonalAuthenticator.Infrastructure.Logging;
using PersonalAuthenticator.Infrastructure.Serialization;

namespace PersonalAuthenticator.Infrastructure.Storage;

public sealed class DpapiVaultStore : IVaultStore
{
    private static readonly byte[] Magic = "PAVLT001"u8.ToArray();
    private static readonly byte[] Entropy = SHA256.HashData("Personal Authenticator DPAPI vault v1"u8);
    private const ushort FormatVersion = 1;
    private const int HeaderLength = 8 + 2 + 8 + 4 + 32;
    private const int MaximumVaultBytes = 64 * 1024 * 1024;
    private readonly ILogger<DpapiVaultStore> _logger;
    private readonly Action<string> _prepareRestrictiveStorage;

    public DpapiVaultStore(ILogger<DpapiVaultStore> logger, string? baseDirectory = null)
        : this(logger, baseDirectory, PrepareRestrictiveStorage)
    {
    }

    internal DpapiVaultStore(
        ILogger<DpapiVaultStore> logger,
        string? baseDirectory,
        Action<string> prepareRestrictiveStorage)
    {
        ArgumentNullException.ThrowIfNull(logger);
        ArgumentNullException.ThrowIfNull(prepareRestrictiveStorage);

        _logger = logger;
        _prepareRestrictiveStorage = prepareRestrictiveStorage;
        string directory = baseDirectory ??
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "PersonalAuthenticator");
        VaultPath = Path.Combine(directory, "vault.pav");
    }

    public string VaultPath { get; }

    public Task<bool> ExistsAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return Task.FromResult(File.Exists(VaultPath));
    }

    public async Task<IReadOnlyList<TotpAccount>> LoadAsync(CancellationToken cancellationToken)
    {
        byte[] envelope;
        try
        {
            envelope = await File.ReadAllBytesAsync(VaultPath, cancellationToken);
        }
        catch (IOException exception)
        {
            InfrastructureLog.VaultReadFailed(_logger, exception, exception.GetType().Name);
            throw new SafeApplicationException("Vault.ReadFailed", "The encrypted vault could not be read.", exception);
        }

        if (envelope.Length is < HeaderLength or > MaximumVaultBytes)
        {
            throw new SafeApplicationException("Vault.InvalidEnvelope", "The vault file is corrupt or too large.");
        }

        byte[] protectedPayload = [];
        byte[] plaintext = [];
        try
        {
            ReadOnlySpan<byte> span = envelope;
            if (!span[..Magic.Length].SequenceEqual(Magic))
            {
                throw new SafeApplicationException("Vault.InvalidMagic", "The selected file is not a Personal Authenticator vault.");
            }

            ushort version = BinaryPrimitives.ReadUInt16LittleEndian(span[8..10]);
            if (version != FormatVersion)
            {
                throw new SafeApplicationException("Vault.UnsupportedVersion", "The vault format version is not supported.");
            }

            int protectedLength = BinaryPrimitives.ReadInt32LittleEndian(span[18..22]);
            if (protectedLength <= 0 || protectedLength != envelope.Length - HeaderLength)
            {
                throw new SafeApplicationException("Vault.InvalidLength", "The vault file is truncated or corrupt.");
            }

            ReadOnlySpan<byte> expectedHash = span[22..54];
            protectedPayload = span[HeaderLength..].ToArray();
            Span<byte> actualHash = stackalloc byte[32];
            SHA256.HashData(protectedPayload, actualHash);
            if (!CryptographicOperations.FixedTimeEquals(expectedHash, actualHash))
            {
                CryptographicOperations.ZeroMemory(actualHash);
                throw new SafeApplicationException("Vault.IntegrityFailed", "The vault file is corrupt.");
            }

            CryptographicOperations.ZeroMemory(actualHash);
            try
            {
                plaintext = ProtectedData.Unprotect(protectedPayload, Entropy, DataProtectionScope.CurrentUser);
            }
            catch (CryptographicException exception)
            {
                InfrastructureLog.VaultDecryptionFailed(_logger, exception.GetType().Name);
                throw new SafeApplicationException(
                    "Vault.DecryptionFailed",
                    "The vault cannot be decrypted for the current Windows user.",
                    exception);
            }

            return VaultJsonSerializer.Deserialize(plaintext);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(envelope);
            CryptographicOperations.ZeroMemory(protectedPayload);
            CryptographicOperations.ZeroMemory(plaintext);
        }
    }

    public async Task SaveAsync(IReadOnlyCollection<TotpAccount> accounts, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(accounts);
        cancellationToken.ThrowIfCancellationRequested();

        try
        {
            _prepareRestrictiveStorage(VaultPath);
        }
        catch (Exception exception) when (
            exception is IOException or
                UnauthorizedAccessException or
                InvalidOperationException or
                System.Security.SecurityException)
        {
            InfrastructureLog.VaultWriteFailed(_logger, exception, exception.GetType().Name);
            throw new SafeApplicationException(
                "Vault.SecurityFailed",
                "The vault storage permissions could not be secured.",
                exception);
        }

        byte[] plaintext = VaultJsonSerializer.Serialize(accounts);
        byte[] protectedPayload = [];
        byte[] envelope = [];
        try
        {
            protectedPayload = ProtectedData.Protect(plaintext, Entropy, DataProtectionScope.CurrentUser);
            envelope = CreateEnvelope(protectedPayload);
            await AtomicFile.WriteAsync(
                VaultPath,
                envelope,
                retainPrevious: true,
                overwriteExisting: true,
                cancellationToken);
            InfrastructureLog.VaultSaved(_logger, accounts.Count);
        }
        catch (IOException exception)
        {
            InfrastructureLog.VaultWriteFailed(_logger, exception, exception.GetType().Name);
            throw new SafeApplicationException("Vault.WriteFailed", "The encrypted vault could not be saved.", exception);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext);
            CryptographicOperations.ZeroMemory(protectedPayload);
            CryptographicOperations.ZeroMemory(envelope);
        }
    }

    private static byte[] CreateEnvelope(byte[] protectedPayload)
    {
        byte[] envelope = GC.AllocateUninitializedArray<byte>(HeaderLength + protectedPayload.Length);
        Magic.CopyTo(envelope, 0);
        BinaryPrimitives.WriteUInt16LittleEndian(envelope.AsSpan(8, 2), FormatVersion);
        BinaryPrimitives.WriteInt64LittleEndian(envelope.AsSpan(10, 8), DateTimeOffset.UtcNow.ToUnixTimeSeconds());
        BinaryPrimitives.WriteInt32LittleEndian(envelope.AsSpan(18, 4), protectedPayload.Length);
        SHA256.HashData(protectedPayload, envelope.AsSpan(22, 32));
        protectedPayload.CopyTo(envelope, HeaderLength);
        return envelope;
    }

    private static void PrepareRestrictiveStorage(string vaultPath)
    {
        string directory = Path.GetDirectoryName(vaultPath) ??
            throw new InvalidOperationException("The vault path must include a directory.");
        Directory.CreateDirectory(directory);

        using WindowsIdentity identity = WindowsIdentity.GetCurrent();
        SecurityIdentifier user = identity.User ??
            throw new InvalidOperationException("The current Windows user SID is unavailable.");

        var directorySecurity = new DirectorySecurity();
        ConfigureRestrictiveAcl(
            directorySecurity,
            user,
            InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit);
        new DirectoryInfo(directory).SetAccessControl(directorySecurity);

        ApplyRestrictiveFileAclIfPresent(vaultPath, user);
        ApplyRestrictiveFileAclIfPresent(vaultPath + ".previous", user);
    }

    private static void ApplyRestrictiveFileAclIfPresent(string path, SecurityIdentifier user)
    {
        if (!File.Exists(path))
        {
            return;
        }

        var security = new FileSecurity();
        ConfigureRestrictiveAcl(security, user, InheritanceFlags.None);
        new FileInfo(path).SetAccessControl(security);
    }

    private static void ConfigureRestrictiveAcl(
        FileSystemSecurity security,
        SecurityIdentifier user,
        InheritanceFlags inheritanceFlags)
    {
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        security.SetOwner(user);
        security.AddAccessRule(new FileSystemAccessRule(
            user,
            FileSystemRights.FullControl,
            inheritanceFlags,
            PropagationFlags.None,
            AccessControlType.Allow));
        security.AddAccessRule(new FileSystemAccessRule(
            new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
            FileSystemRights.FullControl,
            inheritanceFlags,
            PropagationFlags.None,
            AccessControlType.Allow));
    }
}
