using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text.Json;
using PersonalAuthenticator.Core.Exceptions;

namespace PersonalAuthenticator.Infrastructure.Storage;

internal sealed class ActiveVaultPointerStore
{
    private static readonly byte[] Magic = "PAVPTR02"u8.ToArray();
    private static readonly byte[] Entropy =
        SHA256.HashData("Personal Authenticator active vault pointer v2"u8);
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = false,
        MaxDepth = 8,
    };
    private const ushort EnvelopeFormatVersion = 1;
    private const int LegacyPayloadFormatVersion = 1;
    private const int CurrentPayloadFormatVersion = 2;
    private const int HeaderLength = 8 + 2 + 4 + 32;
    private const int MaximumPointerBytes = 64 * 1024;

    public ActiveVaultPointerStore(string pointerPath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(pointerPath);
        PointerPath = Path.GetFullPath(pointerPath);
    }

    public string PointerPath { get; }

    public bool Exists => File.Exists(PointerPath);

    public async Task<ActiveVaultPointer> LoadAsync(CancellationToken cancellationToken)
    {
        byte[] envelope;
        try
        {
            envelope = await File.ReadAllBytesAsync(PointerPath, cancellationToken);
        }
        catch (IOException exception)
        {
            throw new SafeApplicationException(
                "VaultSelector.ReadFailed",
                "The active vault selector could not be read.",
                exception);
        }

        if (envelope.Length is < HeaderLength or > MaximumPointerBytes)
        {
            CryptographicOperations.ZeroMemory(envelope);
            throw InvalidPointer("The active vault selector is corrupt.");
        }

        byte[] protectedPayload = [];
        byte[] plaintext = [];
        try
        {
            ReadOnlySpan<byte> span = envelope;
            if (!span[..Magic.Length].SequenceEqual(Magic))
            {
                throw InvalidPointer("The active vault selector has an invalid header.");
            }

            ushort version = BinaryPrimitives.ReadUInt16LittleEndian(span[8..10]);
            if (version != EnvelopeFormatVersion)
            {
                throw InvalidPointer("The active vault selector version is not supported.");
            }

            int protectedLength = BinaryPrimitives.ReadInt32LittleEndian(span[10..14]);
            if (protectedLength <= 0 || protectedLength != envelope.Length - HeaderLength)
            {
                throw InvalidPointer("The active vault selector is truncated or corrupt.");
            }

            protectedPayload = span[HeaderLength..].ToArray();
            Span<byte> actualHash = stackalloc byte[32];
            SHA256.HashData(protectedPayload, actualHash);
            bool hashMatches = CryptographicOperations.FixedTimeEquals(
                span[14..46],
                actualHash);
            CryptographicOperations.ZeroMemory(actualHash);
            if (!hashMatches)
            {
                throw InvalidPointer("The active vault selector failed its integrity check.");
            }

            try
            {
                plaintext = ProtectedData.Unprotect(
                    protectedPayload,
                    Entropy,
                    DataProtectionScope.CurrentUser);
            }
            catch (CryptographicException exception)
            {
                throw new SafeApplicationException(
                    "VaultSelector.DecryptionFailed",
                    "The active vault selector cannot be decrypted for the current Windows user.",
                    exception);
            }

            PointerDto? dto;
            try
            {
                dto = JsonSerializer.Deserialize<PointerDto>(plaintext, JsonOptions);
            }
            catch (JsonException exception)
            {
                throw new SafeApplicationException(
                    "VaultSelector.Invalid",
                    "The active vault selector is corrupt.",
                    exception);
            }

            if (dto is null ||
                dto.FormatVersion is not (
                    LegacyPayloadFormatVersion or CurrentPayloadFormatVersion) ||
                (dto.FormatVersion == LegacyPayloadFormatVersion &&
                 dto.RootKeyFileName is not null))
            {
                throw InvalidPointer("The active vault selector is invalid.");
            }

            var pointer = new ActiveVaultPointer(
                dto.Mode,
                dto.StoreFileName ?? string.Empty,
                dto.LegacySourceSha256,
                dto.ActivatedAtUtc,
                dto.RootKeyFileName);
            Validate(pointer);
            return pointer;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(envelope);
            CryptographicOperations.ZeroMemory(protectedPayload);
            CryptographicOperations.ZeroMemory(plaintext);
        }
    }

    public async Task SaveAsync(
        ActiveVaultPointer pointer,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(pointer);
        Validate(pointer);
        var dto = new PointerDto
        {
            FormatVersion = pointer.RootKeyFileName is null
                ? LegacyPayloadFormatVersion
                : CurrentPayloadFormatVersion,
            Mode = pointer.Mode,
            StoreFileName = pointer.StoreFileName,
            LegacySourceSha256 = pointer.LegacySourceSha256,
            ActivatedAtUtc = pointer.ActivatedAtUtc.ToUniversalTime(),
            RootKeyFileName = pointer.RootKeyFileName,
        };

        byte[] plaintext = JsonSerializer.SerializeToUtf8Bytes(dto, JsonOptions);
        byte[] protectedPayload = [];
        byte[] envelope = [];
        try
        {
            try
            {
                protectedPayload = ProtectedData.Protect(
                    plaintext,
                    Entropy,
                    DataProtectionScope.CurrentUser);
            }
            catch (CryptographicException exception)
            {
                throw new SafeApplicationException(
                    "VaultSelector.EncryptionFailed",
                    "The active vault selector could not be protected for the current Windows user.",
                    exception);
            }

            envelope = CreateEnvelope(protectedPayload);
            await AtomicFile.WriteAsync(
                PointerPath,
                envelope,
                retainPrevious: true,
                overwriteExisting: true,
                cancellationToken);
        }
        catch (IOException exception)
        {
            throw new SafeApplicationException(
                "VaultSelector.WriteFailed",
                "The active vault selector could not be saved.",
                exception);
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
        BinaryPrimitives.WriteUInt16LittleEndian(
            envelope.AsSpan(8, 2),
            EnvelopeFormatVersion);
        BinaryPrimitives.WriteInt32LittleEndian(
            envelope.AsSpan(10, 4),
            protectedPayload.Length);
        SHA256.HashData(protectedPayload, envelope.AsSpan(14, 32));
        protectedPayload.CopyTo(envelope, HeaderLength);
        return envelope;
    }

    private static void Validate(ActiveVaultPointer pointer)
    {
        if (!Enum.IsDefined(pointer.Mode))
        {
            throw InvalidPointer("The active vault selector mode is invalid.");
        }

        if (string.IsNullOrWhiteSpace(pointer.StoreFileName) ||
            pointer.StoreFileName.Length > 128 ||
            !pointer.StoreFileName.All(
                character =>
                    char.IsAsciiLetterOrDigit(character) ||
                    character is '-' or '_' or '.') ||
            !string.Equals(
                Path.GetFileName(pointer.StoreFileName),
                pointer.StoreFileName,
                StringComparison.Ordinal))
        {
            throw InvalidPointer("The active vault selector path is invalid.");
        }

        string expectedExtension = pointer.Mode == ActiveVaultMode.LocalV2 ? ".db" : ".pav";
        if (!string.Equals(
                Path.GetExtension(pointer.StoreFileName),
                expectedExtension,
                StringComparison.OrdinalIgnoreCase))
        {
            throw InvalidPointer("The active vault selector file type is invalid.");
        }

        if (pointer.LegacySourceSha256 is not null &&
            (pointer.LegacySourceSha256.Length != 64 ||
             !pointer.LegacySourceSha256.All(Uri.IsHexDigit)))
        {
            throw InvalidPointer("The active vault selector source hash is invalid.");
        }

        if (pointer.RootKeyFileName is not null &&
            (pointer.Mode != ActiveVaultMode.LocalV2 ||
             string.IsNullOrWhiteSpace(pointer.RootKeyFileName) ||
             pointer.RootKeyFileName.Length > 128 ||
             !pointer.RootKeyFileName.All(
                 character =>
                     char.IsAsciiLetterOrDigit(character) ||
                     character is '-' or '_' or '.') ||
             !string.Equals(
                 Path.GetFileName(pointer.RootKeyFileName),
                 pointer.RootKeyFileName,
                 StringComparison.Ordinal) ||
             !string.Equals(
                 Path.GetExtension(pointer.RootKeyFileName),
                 ".key",
                 StringComparison.OrdinalIgnoreCase)))
        {
            throw InvalidPointer("The active vault selector key path is invalid.");
        }

        if (pointer.ActivatedAtUtc == default)
        {
            throw InvalidPointer("The active vault selector activation time is invalid.");
        }
    }

    private static SafeApplicationException InvalidPointer(string message) =>
        new("VaultSelector.Invalid", message);

    private sealed class PointerDto
    {
        public int FormatVersion { get; set; }

        public ActiveVaultMode Mode { get; set; }

        public string? StoreFileName { get; set; }

        public string? LegacySourceSha256 { get; set; }

        public DateTimeOffset ActivatedAtUtc { get; set; }

        public string? RootKeyFileName { get; set; }
    }
}
