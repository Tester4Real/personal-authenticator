using System.Buffers.Binary;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using PersonalAuthenticator.Core.Exceptions;

namespace PersonalAuthenticator.Infrastructure.Storage;

internal sealed class DpapiV2RootKeyProvider : IVaultRootKeyProvider
{
    private static readonly byte[] Magic = "PAVKEY02"u8.ToArray();
    private static readonly byte[] Entropy =
        SHA256.HashData("Personal Authenticator v2 vault root key"u8);
    private const ushort FormatVersion = 1;
    private const int HeaderLength = 8 + 2 + 4 + 32;
    private const int RootKeyLength = 32;
    private const int MaximumEnvelopeLength = 16 * 1024;
    private readonly Action<string> _prepareRestrictiveStorage;

    public DpapiV2RootKeyProvider(string keyPath)
        : this(keyPath, PrepareRestrictiveStorage)
    {
    }

    internal DpapiV2RootKeyProvider(
        string keyPath,
        Action<string> prepareRestrictiveStorage)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(keyPath);
        ArgumentNullException.ThrowIfNull(prepareRestrictiveStorage);
        KeyPath = Path.GetFullPath(keyPath);
        _prepareRestrictiveStorage = prepareRestrictiveStorage;
    }

    public string KeyPath { get; }

    public bool Exists => File.Exists(KeyPath);

    public async Task<byte[]> LoadAsync(CancellationToken cancellationToken)
    {
        byte[] envelope;
        try
        {
            envelope = await File.ReadAllBytesAsync(KeyPath, cancellationToken);
        }
        catch (IOException exception)
        {
            throw new SafeApplicationException(
                "VaultV2.KeyReadFailed",
                "The encrypted v2 vault key could not be read.",
                exception);
        }

        if (envelope.Length is < HeaderLength or > MaximumEnvelopeLength)
        {
            CryptographicOperations.ZeroMemory(envelope);
            throw new SafeApplicationException(
                "VaultV2.InvalidKeyEnvelope",
                "The encrypted v2 vault key is corrupt.");
        }

        byte[] protectedKey = [];
        byte[] rootKey = [];
        try
        {
            ReadOnlySpan<byte> span = envelope;
            if (!span[..Magic.Length].SequenceEqual(Magic))
            {
                throw new SafeApplicationException(
                    "VaultV2.InvalidKeyMagic",
                    "The selected key is not a Personal Authenticator v2 vault key.");
            }

            ushort version = BinaryPrimitives.ReadUInt16LittleEndian(span[8..10]);
            if (version != FormatVersion)
            {
                throw new SafeApplicationException(
                    "VaultV2.UnsupportedKeyVersion",
                    "The v2 vault key format is not supported.");
            }

            int protectedLength = BinaryPrimitives.ReadInt32LittleEndian(span[10..14]);
            if (protectedLength <= 0 || protectedLength != envelope.Length - HeaderLength)
            {
                throw new SafeApplicationException(
                    "VaultV2.InvalidKeyLength",
                    "The encrypted v2 vault key is truncated or corrupt.");
            }

            protectedKey = span[HeaderLength..].ToArray();
            Span<byte> actualHash = stackalloc byte[32];
            SHA256.HashData(protectedKey, actualHash);
            bool validHash = CryptographicOperations.FixedTimeEquals(span[14..46], actualHash);
            CryptographicOperations.ZeroMemory(actualHash);
            if (!validHash)
            {
                throw new SafeApplicationException(
                    "VaultV2.KeyIntegrityFailed",
                    "The encrypted v2 vault key is corrupt.");
            }

            try
            {
                rootKey = ProtectedData.Unprotect(
                    protectedKey,
                    Entropy,
                    DataProtectionScope.CurrentUser);
            }
            catch (CryptographicException exception)
            {
                throw new SafeApplicationException(
                    "VaultV2.KeyDecryptionFailed",
                    "The v2 vault key cannot be decrypted for the current Windows user.",
                    exception);
            }

            if (rootKey.Length != RootKeyLength)
            {
                CryptographicOperations.ZeroMemory(rootKey);
                rootKey = [];
                throw new SafeApplicationException(
                    "VaultV2.InvalidRootKey",
                    "The decrypted v2 vault key has an invalid length.");
            }

            return rootKey;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(envelope);
            CryptographicOperations.ZeroMemory(protectedKey);
        }
    }

    public async Task<byte[]> LoadOrCreateAsync(CancellationToken cancellationToken)
    {
        if (Exists)
        {
            return await LoadAsync(cancellationToken);
        }

        try
        {
            _prepareRestrictiveStorage(KeyPath);
        }
        catch (Exception exception) when (
            exception is IOException or
                UnauthorizedAccessException or
                InvalidOperationException or
                System.Security.SecurityException)
        {
            throw new SafeApplicationException(
                "VaultV2.KeySecurityFailed",
                "The v2 vault key storage permissions could not be secured.",
                exception);
        }

        byte[] rootKey = RandomNumberGenerator.GetBytes(RootKeyLength);
        byte[] protectedKey = [];
        byte[] envelope = [];
        bool returnRootKey = false;
        try
        {
            protectedKey = ProtectedData.Protect(
                rootKey,
                Entropy,
                DataProtectionScope.CurrentUser);
            envelope = CreateEnvelope(protectedKey);
            try
            {
                await AtomicFile.WriteAsync(
                    KeyPath,
                    envelope,
                    retainPrevious: false,
                    overwriteExisting: false,
                    cancellationToken);
            }
            catch (IOException) when (Exists)
            {
                CryptographicOperations.ZeroMemory(rootKey);
                rootKey = await LoadAsync(cancellationToken);
            }

            returnRootKey = true;
            return rootKey;
        }
        finally
        {
            if (!returnRootKey)
            {
                CryptographicOperations.ZeroMemory(rootKey);
            }

            CryptographicOperations.ZeroMemory(protectedKey);
            CryptographicOperations.ZeroMemory(envelope);
        }
    }

    private static byte[] CreateEnvelope(byte[] protectedKey)
    {
        byte[] envelope = GC.AllocateUninitializedArray<byte>(HeaderLength + protectedKey.Length);
        Magic.CopyTo(envelope, 0);
        BinaryPrimitives.WriteUInt16LittleEndian(envelope.AsSpan(8, 2), FormatVersion);
        BinaryPrimitives.WriteInt32LittleEndian(envelope.AsSpan(10, 4), protectedKey.Length);
        SHA256.HashData(protectedKey, envelope.AsSpan(14, 32));
        protectedKey.CopyTo(envelope, HeaderLength);
        return envelope;
    }

    private static void PrepareRestrictiveStorage(string keyPath)
    {
        string directory = Path.GetDirectoryName(keyPath) ??
            throw new InvalidOperationException("The v2 key path must include a directory.");
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

        if (File.Exists(keyPath))
        {
            var fileSecurity = new FileSecurity();
            ConfigureRestrictiveAcl(fileSecurity, user, InheritanceFlags.None);
            new FileInfo(keyPath).SetAccessControl(fileSecurity);
        }
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
