using System.Security.Cryptography;
using System.Text;
using PersonalAuthenticator.Core.Domain;
using PersonalAuthenticator.Core.Exceptions;
using PersonalAuthenticator.Infrastructure.Storage;
using PersonalAuthenticator.Infrastructure.Sync;

namespace PersonalAuthenticator.Infrastructure.Recovery;

internal static class RecoveryPayloadSerializer
{
    private static readonly UTF8Encoding StrictUtf8 = new(
        encoderShouldEmitUTF8Identifier: false,
        throwOnInvalidBytes: true);
    private const int PayloadVersion = 2;
    private const int MaximumAccounts = 10_000;
    private const int MaximumSecretVersions = 100_000;
    private const int MaximumHistoryEntries = 1_000_000;
    private const int MaximumStringBytes = 16 * 1024;
    private const int MaximumSecretBytes = 128;
    private const int MaximumPayloadBytes = 128 * 1024 * 1024;

    public static byte[] Serialize(
        V2VaultSnapshot snapshot,
        DateTimeOffset createdAtUtc,
        SyncRecoveryState? syncState = null)
    {
        ArgumentNullException.ThrowIfNull(snapshot);
        V2SqliteVaultStore.ValidateSnapshot(
            snapshot.Accounts,
            snapshot.SecretVersions,
            snapshot.HistoryEntries);

        using var stream = new MemoryStream();
        try
        {
            using (var writer = new BinaryWriter(stream, StrictUtf8, leaveOpen: true))
            {
                writer.Write(PayloadVersion);
                writer.Write(createdAtUtc.ToUniversalTime().Ticks);
                writer.Write(snapshot.ChangeSequence);
                writer.Write(snapshot.Accounts.Count);
                writer.Write(snapshot.SecretVersions.Count);
                writer.Write(snapshot.HistoryEntries.Count);

                foreach (VaultAccountV2 account in snapshot.Accounts.OrderBy(item => item.Id))
                {
                    WriteGuid(writer, account.Id);
                    WriteString(writer, account.Issuer);
                    WriteString(writer, account.AccountName);
                    WriteGuid(writer, account.ActiveSecretVersionId);
                    writer.Write(account.Favourite);
                    writer.Write(account.SortOrder);
                    writer.Write(account.CreatedAtUtc.UtcTicks);
                    writer.Write(account.UpdatedAtUtc.UtcTicks);
                    WriteNullableDateTime(writer, account.ArchivedAtUtc);
                }

                foreach (SecretVersionV2 version in snapshot.SecretVersions.OrderBy(item => item.Id))
                {
                    WriteGuid(writer, version.Id);
                    WriteGuid(writer, version.AccountId);
                    writer.Write(version.Secret.Length);
                    writer.Write(version.Secret);
                    writer.Write((int)version.Algorithm);
                    writer.Write(version.Digits);
                    writer.Write(version.Period);
                    WriteString(writer, version.ProvisioningUri);
                    writer.Write((int)version.ProvisioningUriOrigin);
                    writer.Write((int)version.State);
                    writer.Write(version.CreatedAtUtc.UtcTicks);
                    WriteNullableDateTime(writer, version.RetiredAtUtc);
                }

                foreach (AccountHistoryEntryV2 entry in snapshot.HistoryEntries.OrderBy(item => item.Id))
                {
                    WriteGuid(writer, entry.Id);
                    WriteGuid(writer, entry.AccountId);
                    writer.Write((int)entry.Action);
                    writer.Write(entry.OccurredAtUtc.UtcTicks);
                    WriteNullableGuid(writer, entry.SecretVersionId);
                    WriteNullableGuid(writer, entry.PreviousSecretVersionId);
                    WriteNullableGuid(writer, entry.RelatedAccountId);
                    WriteNullableGuid(writer, entry.ActorDeviceId);
                }

                writer.Write(syncState is not null);
                if (syncState is not null)
                {
                    WriteSyncState(writer, syncState);
                }
            }

            if (stream.Length > MaximumPayloadBytes)
            {
                throw InvalidBundle("The recovery payload is too large.");
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

    public static RecoveryPayload Deserialize(byte[] payload)
    {
        if (payload.Length is < 28 or > MaximumPayloadBytes)
        {
            throw InvalidBundle("The recovery payload has an invalid size.");
        }

        var accounts = new List<VaultAccountV2>();
        var versions = new List<SecretVersionV2>();
        var history = new List<AccountHistoryEntryV2>();
        try
        {
            using var stream = new MemoryStream(payload, writable: false);
            using var reader = new BinaryReader(stream, StrictUtf8, leaveOpen: false);
            int payloadVersion = reader.ReadInt32();
            if (payloadVersion is not (1 or PayloadVersion))
            {
                throw InvalidBundle("The recovery payload version is not supported.");
            }

            DateTimeOffset createdAtUtc = ReadDateTime(reader);
            long changeSequence = reader.ReadInt64();
            if (changeSequence < 0)
            {
                throw InvalidBundle("The recovery change sequence is invalid.");
            }

            int accountCount = ReadCount(reader, MaximumAccounts, "account");
            int versionCount = ReadCount(reader, MaximumSecretVersions, "secret-version");
            int historyCount = ReadCount(reader, MaximumHistoryEntries, "history");

            for (int index = 0; index < accountCount; index++)
            {
                accounts.Add(
                    new VaultAccountV2(
                        ReadGuid(reader),
                        ReadString(reader),
                        ReadString(reader),
                        ReadGuid(reader),
                        ReadBooleanStrict(reader),
                        reader.ReadInt32(),
                        ReadDateTime(reader),
                        ReadDateTime(reader),
                        ReadNullableDateTime(reader)));
            }

            for (int index = 0; index < versionCount; index++)
            {
                Guid id = ReadGuid(reader);
                Guid accountId = ReadGuid(reader);
                byte[] secret = ReadBytes(reader, MaximumSecretBytes);
                try
                {
                    versions.Add(
                        new SecretVersionV2(
                            id,
                            accountId,
                            secret,
                            (TotpAlgorithm)reader.ReadInt32(),
                            reader.ReadInt32(),
                            reader.ReadInt32(),
                            ReadString(reader),
                            (ProvisioningUriOrigin)reader.ReadInt32(),
                            (SecretVersionState)reader.ReadInt32(),
                            ReadDateTime(reader),
                            ReadNullableDateTime(reader)));
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(secret);
                }
            }

            for (int index = 0; index < historyCount; index++)
            {
                history.Add(
                    new AccountHistoryEntryV2(
                        ReadGuid(reader),
                        ReadGuid(reader),
                        (AccountHistoryAction)reader.ReadInt32(),
                        ReadDateTime(reader),
                        ReadNullableGuid(reader),
                        ReadNullableGuid(reader),
                        ReadNullableGuid(reader),
                        ReadNullableGuid(reader)));
            }

            SyncRecoveryState? syncState = payloadVersion >= 2 &&
                ReadBooleanStrict(reader)
                    ? ReadSyncState(reader)
                    : null;
            if (stream.Position != stream.Length)
            {
                syncState?.Dispose();
                throw InvalidBundle("The recovery payload contains trailing data.");
            }

            V2SqliteVaultStore.ValidateSnapshot(accounts, versions, history);
            var snapshot = new V2VaultSnapshot(accounts, versions, history, changeSequence);
            return new RecoveryPayload(snapshot, createdAtUtc, syncState);
        }
        catch (SafeApplicationException)
        {
            DisposeVersions(versions);
            throw;
        }
        catch (Exception exception) when (
            exception is EndOfStreamException or
                IOException or
                ArgumentException or
                OverflowException)
        {
            DisposeVersions(versions);
            throw new SafeApplicationException(
                "Recovery.InvalidBundle",
                "The recovery bundle is malformed or truncated.",
                exception);
        }
    }

    private static int ReadCount(BinaryReader reader, int maximum, string name)
    {
        int count = reader.ReadInt32();
        if (count < 0 || count > maximum)
        {
            throw InvalidBundle($"The recovery {name} collection is too large.");
        }

        return count;
    }

    private static void WriteSyncState(
        BinaryWriter writer,
        SyncRecoveryState state)
    {
        writer.Write(state.ProtocolVersion);
        writer.Write(state.RequiredFeatures.Count);
        foreach (string feature in state.RequiredFeatures.Order(StringComparer.Ordinal))
        {
            WriteString(writer, feature);
        }

        WriteGuid(writer, state.DeviceId);
        writer.Write(state.DeviceSequenceCoverage.Count);
        foreach ((Guid deviceId, long sequence) in
                 state.DeviceSequenceCoverage.OrderBy(item => item.Key))
        {
            WriteGuid(writer, deviceId);
            writer.Write(sequence);
        }

        writer.Write(state.SerializedOperations.Count);
        foreach (byte[] operation in state.SerializedOperations)
        {
            if (operation.Length is < 64 or >
                SyncOperationSerializer.MaximumOperationBytes)
            {
                throw InvalidBundle("A recovery sync operation has an invalid size.");
            }

            writer.Write(operation.Length);
            writer.Write(operation);
        }

        writer.Write(state.OutboxOperationIds.Count);
        foreach (Guid operationId in state.OutboxOperationIds.Order())
        {
            WriteGuid(writer, operationId);
        }

        writer.Write(state.UnresolvedConflicts.Count);
        foreach (SyncConflictRecord conflict in
                 state.UnresolvedConflicts.OrderBy(item => item.Id))
        {
            WriteGuid(writer, conflict.Id);
            WriteGuid(writer, conflict.AccountId);
            writer.Write((int)conflict.Kind);
            WriteString(writer, conflict.FieldKey);
            WriteGuid(writer, conflict.OperationAId);
            WriteGuid(writer, conflict.OperationBId);
            WriteNullableGuid(writer, conflict.SecretVersionAId);
            WriteNullableGuid(writer, conflict.SecretVersionBId);
            writer.Write(conflict.DetectedAtUtc.UtcTicks);
        }

        writer.Write(state.Configuration is not null);
        if (state.Configuration is { } configuration)
        {
            WriteString(writer, configuration.BackendKind);
            WriteGuid(writer, configuration.VaultId);
            WriteGuid(writer, configuration.RemoteGeneration);
            writer.Write(configuration.RepositoryId.HasValue);
            if (configuration.RepositoryId.HasValue)
            {
                writer.Write(configuration.RepositoryId.Value);
            }

            WriteNullableString(writer, configuration.RepositoryOwner);
            WriteNullableString(writer, configuration.RepositoryName);
            WriteNullableString(writer, configuration.Branch);
            WriteNullableString(writer, configuration.PathPrefix);
            writer.Write(configuration.Enabled);
            writer.Write(configuration.BackgroundSyncEnabled);
        }
    }

    private static SyncRecoveryState ReadSyncState(BinaryReader reader)
    {
        int protocolVersion = reader.ReadInt32();
        int featureCount = ReadCount(reader, 64, "required-feature");
        var features = new List<string>(featureCount);
        for (int index = 0; index < featureCount; index++)
        {
            features.Add(ReadString(reader));
        }

        Guid deviceId = ReadGuid(reader);
        int coverageCount = ReadCount(reader, 10_000, "device-coverage");
        var coverage = new Dictionary<Guid, long>(coverageCount);
        for (int index = 0; index < coverageCount; index++)
        {
            Guid id = ReadGuid(reader);
            long sequence = reader.ReadInt64();
            if (sequence < 0 || !coverage.TryAdd(id, sequence))
            {
                throw InvalidBundle("Recovery device coverage is invalid.");
            }
        }

        int operationCount = ReadCount(reader, 1_000_000, "operation");
        var operations = new List<byte[]>(operationCount);
        try
        {
            for (int index = 0; index < operationCount; index++)
            {
                operations.Add(
                    ReadBytes(
                        reader,
                        SyncOperationSerializer.MaximumOperationBytes));
            }

            int outboxCount = ReadCount(reader, operationCount, "outbox");
            var outbox = new HashSet<Guid>();
            for (int index = 0; index < outboxCount; index++)
            {
                if (!outbox.Add(ReadGuid(reader)))
                {
                    throw InvalidBundle("Recovery outbox entries are duplicated.");
                }
            }

            int conflictCount = ReadCount(reader, 100_000, "conflict");
            var conflicts = new List<SyncConflictRecord>(conflictCount);
            for (int index = 0; index < conflictCount; index++)
            {
                conflicts.Add(
                    new SyncConflictRecord(
                        ReadGuid(reader),
                        ReadGuid(reader),
                        (SyncConflictKind)reader.ReadInt32(),
                        ReadString(reader),
                        ReadGuid(reader),
                        ReadGuid(reader),
                        ReadNullableGuid(reader),
                        ReadNullableGuid(reader),
                        ReadDateTime(reader),
                        Resolved: false));
            }

            SyncRecoveryConfiguration? configuration =
                ReadBooleanStrict(reader)
                    ? new SyncRecoveryConfiguration(
                        ReadString(reader),
                        ReadGuid(reader),
                        ReadGuid(reader),
                        ReadBooleanStrict(reader) ? reader.ReadInt64() : null,
                        ReadNullableString(reader),
                        ReadNullableString(reader),
                        ReadNullableString(reader),
                        ReadNullableString(reader),
                        ReadBooleanStrict(reader),
                        ReadBooleanStrict(reader))
                    : null;
            return new SyncRecoveryState(
                protocolVersion,
                features,
                deviceId,
                coverage,
                operations,
                outbox,
                conflicts,
                configuration);
        }
        catch
        {
            foreach (byte[] operation in operations)
            {
                CryptographicOperations.ZeroMemory(operation);
            }

            throw;
        }
    }

    private static void WriteGuid(BinaryWriter writer, Guid value) =>
        writer.Write(value.ToByteArray());

    private static Guid ReadGuid(BinaryReader reader)
    {
        byte[] bytes = reader.ReadBytes(16);
        if (bytes.Length != 16)
        {
            throw new EndOfStreamException();
        }

        return new Guid(bytes);
    }

    private static void WriteString(BinaryWriter writer, string value)
    {
        byte[] bytes = StrictUtf8.GetBytes(value);
        try
        {
            if (bytes.Length > MaximumStringBytes)
            {
                throw InvalidBundle("A recovery text field is too large.");
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
        byte[] bytes = ReadBytes(reader, MaximumStringBytes);
        try
        {
            return StrictUtf8.GetString(bytes);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
        }
    }

    private static void WriteNullableString(BinaryWriter writer, string? value)
    {
        writer.Write(value is not null);
        if (value is not null)
        {
            WriteString(writer, value);
        }
    }

    private static string? ReadNullableString(BinaryReader reader) =>
        ReadBooleanStrict(reader) ? ReadString(reader) : null;

    private static byte[] ReadBytes(BinaryReader reader, int maximumLength)
    {
        int length = reader.ReadInt32();
        long remaining = reader.BaseStream.Length - reader.BaseStream.Position;
        if (length < 0 || length > maximumLength || length > remaining)
        {
            throw InvalidBundle("A recovery field has an invalid length.");
        }

        byte[] bytes = reader.ReadBytes(length);
        if (bytes.Length != length)
        {
            throw new EndOfStreamException();
        }

        return bytes;
    }

    private static DateTimeOffset ReadDateTime(BinaryReader reader)
    {
        long ticks = reader.ReadInt64();
        try
        {
            return new DateTimeOffset(ticks, TimeSpan.Zero);
        }
        catch (ArgumentOutOfRangeException exception)
        {
            throw new SafeApplicationException(
                "Recovery.InvalidBundle",
                "A recovery timestamp is invalid.",
                exception);
        }
    }

    private static void WriteNullableDateTime(BinaryWriter writer, DateTimeOffset? value)
    {
        writer.Write(value.HasValue);
        if (value.HasValue)
        {
            writer.Write(value.Value.UtcTicks);
        }
    }

    private static DateTimeOffset? ReadNullableDateTime(BinaryReader reader) =>
        ReadBooleanStrict(reader) ? ReadDateTime(reader) : null;

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

    private static bool ReadBooleanStrict(BinaryReader reader)
    {
        byte value = reader.ReadByte();
        return value switch
        {
            0 => false,
            1 => true,
            _ => throw InvalidBundle("A recovery Boolean field is invalid."),
        };
    }

    private static void DisposeVersions(IEnumerable<SecretVersionV2> versions)
    {
        foreach (SecretVersionV2 version in versions)
        {
            version.Dispose();
        }
    }

    private static SafeApplicationException InvalidBundle(string message) =>
        new("Recovery.InvalidBundle", message);
}

internal sealed record RecoveryPayload(
    V2VaultSnapshot Snapshot,
    DateTimeOffset CreatedAtUtc,
    SyncRecoveryState? SyncState) : IDisposable
{
    public void Dispose()
    {
        Snapshot.Dispose();
        SyncState?.Dispose();
    }
}
