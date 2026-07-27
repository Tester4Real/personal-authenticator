using System.Security.Cryptography;
using System.Text;
using PersonalAuthenticator.Core.Domain;
using PersonalAuthenticator.Core.Exceptions;
using PersonalAuthenticator.Infrastructure.Serialization;

namespace PersonalAuthenticator.Infrastructure.Sync;

internal static class SyncOperationSerializer
{
    private const int FormatVersion = 1;
    private const int MaximumParents = 64;
    private const int MaximumTextBytes = 16 * 1024;
    private const int MaximumAccountBytes = 16 * 1024;
    private const int MaximumSecretBytes = 32 * 1024;
    private const int MaximumHistoryBytes = 8 * 1024;
    internal const int MaximumOperationBytes = 128 * 1024;
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);

    public static byte[] Serialize(SyncOperation operation)
    {
        ArgumentNullException.ThrowIfNull(operation);
        ValidateOperation(operation);
        using var stream = new MemoryStream();
        try
        {
            using (var writer = new BinaryWriter(stream, StrictUtf8, leaveOpen: true))
            {
                writer.Write(FormatVersion);
                WriteGuid(writer, operation.Id);
                WriteGuid(writer, operation.DeviceId);
                writer.Write(operation.DeviceSequence);
                writer.Write(operation.LogicalClock);
                writer.Write(operation.OccurredAtUtc.UtcTicks);
                WriteNullableGuid(writer, operation.AccountId);
                writer.Write((int)operation.Kind);
                WriteString(writer, operation.FieldKey);
                writer.Write(operation.CausalParents.Count);
                foreach (Guid parent in operation.CausalParents.Order())
                {
                    WriteGuid(writer, parent);
                }

                WritePayload(writer, operation.Payload);
            }

            if (stream.Length > MaximumOperationBytes)
            {
                throw InvalidOperation("A sync operation is too large.");
            }

            return stream.ToArray();
        }
        finally
        {
            if (stream.TryGetBuffer(out ArraySegment<byte> buffer))
            {
                CryptographicOperations.ZeroMemory(
                    buffer.AsSpan(0, checked((int)stream.Length)));
            }
        }
    }

    public static SyncOperation Deserialize(ReadOnlySpan<byte> serialized)
    {
        if (serialized.Length is < 64 or > MaximumOperationBytes)
        {
            throw InvalidOperation("A sync operation has an invalid size.");
        }

        byte[] copy = serialized.ToArray();
        try
        {
            using var stream = new MemoryStream(copy, writable: false);
            using var reader = new BinaryReader(stream, StrictUtf8, leaveOpen: false);
            if (reader.ReadInt32() != FormatVersion)
            {
                throw InvalidOperation("The sync operation version is not supported.");
            }

            Guid id = ReadGuid(reader);
            Guid deviceId = ReadGuid(reader);
            long deviceSequence = reader.ReadInt64();
            long logicalClock = reader.ReadInt64();
            DateTimeOffset occurredAtUtc = ReadDateTime(reader);
            Guid? accountId = ReadNullableGuid(reader);
            var kind = (SyncOperationKind)reader.ReadInt32();
            string fieldKey = ReadString(reader);
            int parentCount = reader.ReadInt32();
            if (parentCount is < 0 or > MaximumParents)
            {
                throw InvalidOperation("A sync operation has too many causal parents.");
            }

            var parents = new List<Guid>(parentCount);
            for (int index = 0; index < parentCount; index++)
            {
                parents.Add(ReadGuid(reader));
            }

            SyncOperationPayload payload = ReadPayload(reader);
            if (stream.Position != stream.Length)
            {
                payload.Dispose();
                throw InvalidOperation("A sync operation contains trailing data.");
            }

            var operation = new SyncOperation(
                id,
                deviceId,
                deviceSequence,
                logicalClock,
                occurredAtUtc,
                accountId,
                kind,
                fieldKey,
                parents,
                payload);
            try
            {
                ValidateOperation(operation);
                return operation;
            }
            catch
            {
                operation.Dispose();
                throw;
            }
        }
        catch (SafeApplicationException)
        {
            throw;
        }
        catch (Exception exception) when (
            exception is EndOfStreamException or
                IOException or
                ArgumentException or
                System.Text.Json.JsonException or
                OverflowException)
        {
            throw new SafeApplicationException(
                "Sync.InvalidOperation",
                "A sync operation is malformed or truncated.",
                exception);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(copy);
        }
    }

    public static byte[] ComputeValueHash(SyncOperation operation)
    {
        byte[] serialized = Serialize(operation);
        try
        {
            return SHA256.HashData(serialized);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(serialized);
        }
    }

    private static void WritePayload(BinaryWriter writer, SyncOperationPayload payload)
    {
        int flags = 0;
        flags |= payload.TextValue is null ? 0 : 1 << 0;
        flags |= payload.BoolValue.HasValue ? 1 << 1 : 0;
        flags |= payload.IntValue.HasValue ? 1 << 2 : 0;
        flags |= payload.DateValue.HasValue ? 1 << 3 : 0;
        flags |= payload.GuidValue.HasValue ? 1 << 4 : 0;
        flags |= payload.SecondaryGuidValue.HasValue ? 1 << 5 : 0;
        flags |= payload.Account is null ? 0 : 1 << 6;
        flags |= payload.SecretVersion is null ? 0 : 1 << 7;
        flags |= payload.HistoryEntry is null ? 0 : 1 << 8;
        flags |= payload.ConflictId.HasValue ? 1 << 9 : 0;
        flags |= payload.Resolution.HasValue ? 1 << 10 : 0;
        writer.Write(flags);
        if (payload.TextValue is not null)
        {
            WriteString(writer, payload.TextValue);
        }

        if (payload.BoolValue.HasValue)
        {
            writer.Write(payload.BoolValue.Value);
        }

        if (payload.IntValue.HasValue)
        {
            writer.Write(payload.IntValue.Value);
        }

        if (payload.DateValue.HasValue)
        {
            writer.Write(payload.DateValue.Value.UtcTicks);
        }

        if (payload.GuidValue.HasValue)
        {
            WriteGuid(writer, payload.GuidValue.Value);
        }

        if (payload.SecondaryGuidValue.HasValue)
        {
            WriteGuid(writer, payload.SecondaryGuidValue.Value);
        }

        if (payload.Account is not null)
        {
            WriteBlob(writer, V2RecordSerializer.SerializeAccount(payload.Account));
        }

        if (payload.SecretVersion is not null)
        {
            WriteBlob(writer, V2RecordSerializer.SerializeSecretVersion(payload.SecretVersion));
        }

        if (payload.HistoryEntry is not null)
        {
            WriteBlob(writer, V2RecordSerializer.SerializeHistoryEntry(payload.HistoryEntry));
        }

        if (payload.ConflictId.HasValue)
        {
            WriteGuid(writer, payload.ConflictId.Value);
        }

        if (payload.Resolution.HasValue)
        {
            writer.Write((int)payload.Resolution.Value);
        }
    }

    private static SyncOperationPayload ReadPayload(BinaryReader reader)
    {
        int flags = reader.ReadInt32();
        if ((flags & ~0x7FF) != 0)
        {
            throw InvalidOperation("A sync operation contains unknown required payload fields.");
        }

        string? text = (flags & (1 << 0)) != 0 ? ReadString(reader) : null;
        bool? boolean = (flags & (1 << 1)) != 0 ? ReadBooleanStrict(reader) : null;
        int? integer = (flags & (1 << 2)) != 0 ? reader.ReadInt32() : null;
        DateTimeOffset? date =
            (flags & (1 << 3)) != 0 ? ReadDateTime(reader) : null;
        Guid? guid = (flags & (1 << 4)) != 0 ? ReadGuid(reader) : null;
        Guid? secondaryGuid =
            (flags & (1 << 5)) != 0 ? ReadGuid(reader) : null;
        VaultAccountV2? account = null;
        SecretVersionV2? secret = null;
        AccountHistoryEntryV2? history = null;
        try
        {
            if ((flags & (1 << 6)) != 0)
            {
                byte[] bytes = ReadBlob(reader, MaximumAccountBytes);
                try
                {
                    Guid accountId = PeekAccountId(bytes);
                    account = V2RecordSerializer.DeserializeAccount(bytes, accountId);
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(bytes);
                }
            }

            if ((flags & (1 << 7)) != 0)
            {
                byte[] bytes = ReadBlob(reader, MaximumSecretBytes);
                try
                {
                    (Guid versionId, Guid accountId) = PeekSecretIds(bytes);
                    secret = V2RecordSerializer.DeserializeSecretVersion(
                        bytes,
                        versionId,
                        accountId);
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(bytes);
                }
            }

            if ((flags & (1 << 8)) != 0)
            {
                byte[] bytes = ReadBlob(reader, MaximumHistoryBytes);
                try
                {
                    (Guid historyId, Guid accountId) = PeekHistoryIds(bytes);
                    history = V2RecordSerializer.DeserializeHistoryEntry(
                        bytes,
                        historyId,
                        accountId);
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(bytes);
                }
            }

            Guid? conflictId =
                (flags & (1 << 9)) != 0 ? ReadGuid(reader) : null;
            SyncConflictResolution? resolution = (flags & (1 << 10)) != 0
                ? (SyncConflictResolution)reader.ReadInt32()
                : null;
            return new SyncOperationPayload
            {
                TextValue = text,
                BoolValue = boolean,
                IntValue = integer,
                DateValue = date,
                GuidValue = guid,
                SecondaryGuidValue = secondaryGuid,
                Account = account,
                SecretVersion = secret,
                HistoryEntry = history,
                ConflictId = conflictId,
                Resolution = resolution,
            };
        }
        catch
        {
            secret?.Dispose();
            throw;
        }
    }

    private static void ValidateOperation(SyncOperation operation)
    {
        if (operation.Id == Guid.Empty ||
            operation.DeviceId == Guid.Empty ||
            operation.DeviceSequence <= 0 ||
            operation.LogicalClock <= 0 ||
            operation.OccurredAtUtc == default ||
            !Enum.IsDefined(operation.Kind) ||
            operation.FieldKey.Length is < 1 or > 64 ||
            operation.CausalParents.Count > MaximumParents ||
            operation.CausalParents.Contains(Guid.Empty) ||
            operation.CausalParents.Contains(operation.Id) ||
            operation.CausalParents.Distinct().Count() !=
                operation.CausalParents.Count)
        {
            throw InvalidOperation("A sync operation contains invalid metadata.");
        }

        if (!operation.AccountId.HasValue ||
            operation.AccountId.Value == Guid.Empty)
        {
            throw InvalidOperation("A sync operation must target a valid account.");
        }

        Guid accountId = operation.AccountId.Value;
        bool validPayload = operation.Kind switch
        {
            SyncOperationKind.AccountAdded =>
                operation.FieldKey == SyncFieldKeys.Existence &&
                operation.Payload.Account is not null &&
                operation.Payload.SecretVersion is not null &&
                operation.Payload.Account.Id == accountId &&
                operation.Payload.SecretVersion.AccountId == accountId &&
                operation.Payload.Account.ActiveSecretVersionId ==
                    operation.Payload.SecretVersion.Id,
            SyncOperationKind.IssuerChanged =>
                operation.FieldKey == SyncFieldKeys.Issuer &&
                IsDisplayValue(operation.Payload.TextValue),
            SyncOperationKind.AccountNameChanged =>
                operation.FieldKey == SyncFieldKeys.AccountName &&
                IsDisplayValue(operation.Payload.TextValue),
            SyncOperationKind.FavouriteChanged =>
                operation.FieldKey == SyncFieldKeys.Favourite &&
                operation.Payload.BoolValue.HasValue,
            SyncOperationKind.SortOrderChanged =>
                operation.FieldKey == SyncFieldKeys.SortOrder &&
                operation.Payload.IntValue is >= 0,
            SyncOperationKind.ArchiveChanged =>
                operation.FieldKey == SyncFieldKeys.Archive,
            SyncOperationKind.SecretAdded =>
                operation.FieldKey == SyncFieldKeys.SecretSet &&
                operation.Payload.SecretVersion is not null &&
                operation.Payload.SecretVersion.AccountId == accountId,
            SyncOperationKind.ActiveSecretChanged =>
                operation.FieldKey == SyncFieldKeys.ActiveSecret &&
                operation.Payload.GuidValue is { } activeId &&
                activeId != Guid.Empty,
            SyncOperationKind.HistoryAdded =>
                operation.FieldKey.StartsWith(
                    SyncFieldKeys.History + ":",
                    StringComparison.Ordinal) &&
                operation.Payload.HistoryEntry is not null &&
                operation.Payload.HistoryEntry.AccountId == accountId,
            SyncOperationKind.DuplicateDecision =>
                operation.FieldKey == SyncFieldKeys.DuplicateDecision &&
                operation.Payload.HistoryEntry is not null &&
                operation.Payload.HistoryEntry.AccountId == accountId,
            SyncOperationKind.Purged =>
                operation.FieldKey == SyncFieldKeys.Archive,
            SyncOperationKind.ConflictResolved =>
                operation.FieldKey.StartsWith(
                    SyncFieldKeys.Resolution + ":",
                    StringComparison.Ordinal) &&
                operation.Payload.ConflictId is { } conflictId &&
                conflictId != Guid.Empty &&
                operation.Payload.Resolution.HasValue &&
                Enum.IsDefined(operation.Payload.Resolution.Value),
            _ => false,
        };
        if (!validPayload)
        {
            throw InvalidOperation(
                "A sync operation payload does not match its declared kind.");
        }
    }

    private static bool IsDisplayValue(string? value) =>
        !string.IsNullOrWhiteSpace(value) && value.Length <= 256;

    private static void WriteString(BinaryWriter writer, string value)
    {
        byte[] bytes = StrictUtf8.GetBytes(value);
        try
        {
            if (bytes.Length > MaximumTextBytes)
            {
                throw InvalidOperation("A sync text field is too large.");
            }

            writer.Write(bytes.Length);
            writer.Write(bytes);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
        }
    }

    private static string ReadString(BinaryReader reader)
    {
        byte[] bytes = ReadBlob(reader, MaximumTextBytes);
        try
        {
            return StrictUtf8.GetString(bytes);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
        }
    }

    private static void WriteBlob(BinaryWriter writer, byte[] bytes)
    {
        try
        {
            writer.Write(bytes.Length);
            writer.Write(bytes);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
        }
    }

    private static byte[] ReadBlob(BinaryReader reader, int maximum)
    {
        int length = reader.ReadInt32();
        long remaining = reader.BaseStream.Length - reader.BaseStream.Position;
        if (length is < 0 || length > maximum || length > remaining)
        {
            throw InvalidOperation("A sync field has an invalid length.");
        }

        byte[] bytes = reader.ReadBytes(length);
        if (bytes.Length != length)
        {
            throw new EndOfStreamException();
        }

        return bytes;
    }

    private static void WriteGuid(BinaryWriter writer, Guid value) =>
        writer.Write(value.ToByteArray());

    private static Guid ReadGuid(BinaryReader reader)
    {
        byte[] bytes = reader.ReadBytes(16);
        return bytes.Length == 16 ? new Guid(bytes) : throw new EndOfStreamException();
    }

    private static void WriteNullableGuid(BinaryWriter writer, Guid? value)
    {
        writer.Write(value.HasValue);
        if (value.HasValue)
        {
            WriteGuid(writer, value.Value);
        }
    }

    private static Guid? ReadNullableGuid(BinaryReader reader) =>
        ReadBooleanStrict(reader) ? ReadGuid(reader) : null;

    private static bool ReadBooleanStrict(BinaryReader reader) =>
        reader.ReadByte() switch
        {
            0 => false,
            1 => true,
            _ => throw InvalidOperation("A sync Boolean field is invalid."),
        };

    private static DateTimeOffset ReadDateTime(BinaryReader reader)
    {
        try
        {
            return new DateTimeOffset(reader.ReadInt64(), TimeSpan.Zero);
        }
        catch (ArgumentOutOfRangeException exception)
        {
            throw new SafeApplicationException(
                "Sync.InvalidOperation",
                "A sync timestamp is invalid.",
                exception);
        }
    }

    private static Guid PeekAccountId(byte[] bytes)
    {
        using var document = System.Text.Json.JsonDocument.Parse(bytes);
        return document.RootElement.GetProperty("id").GetGuid();
    }

    private static (Guid VersionId, Guid AccountId) PeekSecretIds(byte[] bytes)
    {
        using var document = System.Text.Json.JsonDocument.Parse(bytes);
        return (
            document.RootElement.GetProperty("id").GetGuid(),
            document.RootElement.GetProperty("accountId").GetGuid());
    }

    private static (Guid HistoryId, Guid AccountId) PeekHistoryIds(byte[] bytes)
    {
        using var document = System.Text.Json.JsonDocument.Parse(bytes);
        return (
            document.RootElement.GetProperty("id").GetGuid(),
            document.RootElement.GetProperty("accountId").GetGuid());
    }

    private static SafeApplicationException InvalidOperation(string message) =>
        new("Sync.InvalidOperation", message);
}
