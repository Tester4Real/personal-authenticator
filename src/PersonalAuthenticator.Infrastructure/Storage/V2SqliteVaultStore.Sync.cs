using System.Security.Cryptography;
using System.Text;
using Microsoft.Data.Sqlite;
using PersonalAuthenticator.Core.Domain;
using PersonalAuthenticator.Core.Exceptions;
using PersonalAuthenticator.Infrastructure.Sync;

namespace PersonalAuthenticator.Infrastructure.Storage;

public sealed partial class V2SqliteVaultStore
{
    private static async Task<V2VaultSnapshot> LoadSnapshotForSyncAsync(
        SqliteConnection connection,
        ReadOnlyMemory<byte> rootKey,
        CancellationToken cancellationToken)
    {
        var accounts = new List<VaultAccountV2>();
        var versions = new List<SecretVersionV2>();
        var history = new List<AccountHistoryEntryV2>();
        try
        {
            await LoadAccountsAsync(connection, rootKey, accounts, cancellationToken);
            await LoadSecretVersionsAsync(connection, rootKey, versions, cancellationToken);
            await LoadHistoryEntriesAsync(connection, rootKey, history, cancellationToken);
            long sequence = await ReadChangeSequenceAsync(
                connection,
                transaction: null,
                cancellationToken);
            ValidateSnapshot(accounts, versions, history);
            return new V2VaultSnapshot(accounts, versions, history, sequence);
        }
        catch
        {
            DisposeSecretVersions(versions);
            throw;
        }
    }

    private static async Task AppendLocalSyncOperationsAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        ReadOnlyMemory<byte> rootKey,
        Guid localDeviceId,
        IReadOnlyList<SyncOperationDraft> drafts,
        CancellationToken cancellationToken)
    {
        (Guid? storedDeviceId, long nextSequence, long logicalClock) =
            await ReadSyncStateAsync(connection, transaction, cancellationToken);
        if (storedDeviceId.HasValue && storedDeviceId.Value != localDeviceId)
        {
            throw new SafeApplicationException(
                "Sync.DeviceIdentityMismatch",
                "This local vault belongs to a different Windows sync device identity.");
        }

        var frontier = await ReadGuidSetAsync(
            connection,
            transaction,
            "SELECT operation_id FROM sync_frontier ORDER BY operation_id;",
            cancellationToken);
        foreach (SyncOperationDraft draft in drafts)
        {
            long deviceSequence = nextSequence++;
            logicalClock = checked(logicalClock + 1);
            Guid operationId = Guid.NewGuid();
            Guid[] parents = frontier.Order().ToArray();
            using var operation = new SyncOperation(
                operationId,
                localDeviceId,
                deviceSequence,
                logicalClock,
                draft.OccurredAtUtc,
                draft.AccountId,
                draft.Kind,
                draft.FieldKey,
                parents,
                ClonePayload(draft.Payload));
            await InsertOperationAsync(
                connection,
                transaction,
                rootKey,
                operation,
                enqueue: true,
                applied: true,
                cancellationToken);
            await ReplaceGlobalFrontierAsync(
                connection,
                transaction,
                parents,
                operationId,
                cancellationToken);
            if (operation.AccountId.HasValue)
            {
                await ReplaceFieldHeadsAsync(
                    connection,
                    transaction,
                    operation.AccountId.Value,
                    operation.FieldKey,
                    operation,
                    cancellationToken);
            }

            frontier.Clear();
            frontier.Add(operationId);
        }

        await WriteSyncStateAsync(
            connection,
            transaction,
            localDeviceId,
            nextSequence,
            logicalClock,
            cancellationToken);
    }

    internal async Task<IReadOnlyList<SyncOperation>> LoadOutboxAsync(
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        byte[] rootKey = await _rootKeyProvider.LoadAsync(cancellationToken);
        var operations = new List<SyncOperation>();
        try
        {
            await using SqliteConnection connection = CreateConnection(SqliteOpenMode.ReadWrite);
            await OpenAndConfigureAsync(connection, writable: true, cancellationToken);
            await EnsureSchemaAsync(connection, databaseExisted: true, cancellationToken);
            await VerifySchemaAndIntegrityAsync(connection, cancellationToken);
            await using SqliteCommand command = connection.CreateCommand();
            command.CommandText =
                """
                SELECT o.operation_id, o.nonce, o.ciphertext, o.tag
                FROM sync_outbox q
                INNER JOIN sync_operations o
                    ON o.operation_id = q.operation_id
                ORDER BY o.device_sequence, o.operation_id;
                """;
            await using SqliteDataReader reader =
                await command.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken))
            {
                if (operations.Count >= 100_000)
                {
                    throw InvalidDatabase("The sync outbox is too large.");
                }

                Guid operationId = ReadGuid(reader, 0, "sync operation");
                byte[] nonce = ReadBlob(
                    reader,
                    1,
                    V2RecordCryptography.NonceLength,
                    "sync nonce");
                byte[] ciphertext = ReadBlob(
                    reader,
                    2,
                    SyncOperationSerializer.MaximumOperationBytes,
                    "sync operation");
                byte[] tag = ReadBlob(
                    reader,
                    3,
                    V2RecordCryptography.TagLength,
                    "sync tag");
                byte[] associatedData = CreateSyncAssociatedData(operationId);
                byte[] plaintext = [];
                try
                {
                    plaintext = V2RecordCryptography.Decrypt(
                        nonce,
                        ciphertext,
                        tag,
                        rootKey,
                        associatedData);
                    SyncOperation operation =
                        SyncOperationSerializer.Deserialize(plaintext);
                    if (operation.Id != operationId)
                    {
                        operation.Dispose();
                        throw InvalidDatabase("A sync operation identifier is inconsistent.");
                    }

                    operations.Add(operation);
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(nonce);
                    CryptographicOperations.ZeroMemory(ciphertext);
                    CryptographicOperations.ZeroMemory(tag);
                    CryptographicOperations.ZeroMemory(associatedData);
                    CryptographicOperations.ZeroMemory(plaintext);
                }
            }

            return operations;
        }
        catch
        {
            foreach (SyncOperation operation in operations)
            {
                operation.Dispose();
            }

            throw;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(rootKey);
        }
    }

    internal async Task MarkOutboxSentAsync(
        IReadOnlyCollection<Guid> operationIds,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(operationIds);
        if (operationIds.Count == 0)
        {
            return;
        }

        await using SqliteConnection connection = CreateConnection(SqliteOpenMode.ReadWrite);
        await OpenAndConfigureAsync(connection, writable: true, cancellationToken);
        await using SqliteTransaction transaction =
            (SqliteTransaction)await connection.BeginTransactionAsync(
                cancellationToken);
        try
        {
            foreach (Guid operationId in operationIds.Distinct())
            {
                await using SqliteCommand command = connection.CreateCommand();
                command.Transaction = transaction;
                command.CommandText =
                    "DELETE FROM sync_outbox WHERE operation_id = $operationId;";
                command.Parameters.AddWithValue(
                    "$operationId",
                    operationId.ToString("D"));
                await command.ExecuteNonQueryAsync(cancellationToken);
            }

            await transaction.CommitAsync(cancellationToken);
        }
        catch
        {
            await transaction.RollbackAsync(CancellationToken.None);
            throw;
        }
    }

    internal async Task<int> GetOutboxCountAsync(CancellationToken cancellationToken)
    {
        await using SqliteConnection connection = CreateConnection(SqliteOpenMode.ReadWrite);
        await OpenAndConfigureAsync(connection, writable: true, cancellationToken);
        await EnsureSchemaAsync(connection, databaseExisted: true, cancellationToken);
        long count = await ExecuteScalarInt64Async(
            connection,
            "SELECT COUNT(*) FROM sync_outbox;",
            cancellationToken);
        return checked((int)count);
    }

    internal async Task<int> GetPendingApplicationCountAsync(
        CancellationToken cancellationToken)
    {
        await using SqliteConnection connection = CreateConnection(SqliteOpenMode.ReadWrite);
        await OpenAndConfigureAsync(connection, writable: true, cancellationToken);
        await EnsureSchemaAsync(connection, databaseExisted: true, cancellationToken);
        long count = await ExecuteScalarInt64Async(
            connection,
            """
            SELECT COUNT(*)
            FROM sync_operations o
            LEFT JOIN sync_applied_operations a
                ON a.operation_id = o.operation_id
            WHERE a.operation_id IS NULL;
            """,
            cancellationToken);
        return checked((int)count);
    }

    private static async Task InsertOperationAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        ReadOnlyMemory<byte> rootKey,
        SyncOperation operation,
        bool enqueue,
        bool applied,
        CancellationToken cancellationToken)
    {
        byte[] serialized = SyncOperationSerializer.Serialize(operation);
        byte[] objectHash = SHA256.HashData(serialized);
        byte[] associatedData = CreateSyncAssociatedData(operation.Id);
        EncryptedPayload? encrypted = null;
        try
        {
            encrypted = V2RecordCryptography.Encrypt(
                serialized,
                rootKey.Span,
                associatedData);
            await using SqliteCommand command = connection.CreateCommand();
            command.Transaction = transaction;
            command.CommandText =
                """
                INSERT INTO sync_operations(
                    operation_id,
                    device_id,
                    device_sequence,
                    logical_clock,
                    occurred_utc_ticks,
                    account_id,
                    kind,
                    field_key,
                    object_hash,
                    nonce,
                    ciphertext,
                    tag)
                VALUES (
                    $operationId,
                    $deviceId,
                    $deviceSequence,
                    $logicalClock,
                    $occurredTicks,
                    $accountId,
                    $kind,
                    $fieldKey,
                    $objectHash,
                    $nonce,
                    $ciphertext,
                    $tag);
                """;
            command.Parameters.AddWithValue(
                "$operationId",
                operation.Id.ToString("D"));
            command.Parameters.AddWithValue(
                "$deviceId",
                operation.DeviceId.ToString("D"));
            command.Parameters.AddWithValue("$deviceSequence", operation.DeviceSequence);
            command.Parameters.AddWithValue("$logicalClock", operation.LogicalClock);
            command.Parameters.AddWithValue(
                "$occurredTicks",
                operation.OccurredAtUtc.UtcTicks);
            command.Parameters.AddWithValue(
                "$accountId",
                operation.AccountId?.ToString("D") ?? (object)DBNull.Value);
            command.Parameters.AddWithValue("$kind", (int)operation.Kind);
            command.Parameters.AddWithValue("$fieldKey", operation.FieldKey);
            command.Parameters.Add("$objectHash", SqliteType.Blob).Value = objectHash;
            command.Parameters.Add("$nonce", SqliteType.Blob).Value = encrypted.Nonce;
            command.Parameters.Add("$ciphertext", SqliteType.Blob).Value =
                encrypted.Ciphertext;
            command.Parameters.Add("$tag", SqliteType.Blob).Value = encrypted.Tag;
            await command.ExecuteNonQueryAsync(cancellationToken);

            foreach (Guid parent in operation.CausalParents)
            {
                await using SqliteCommand parentCommand = connection.CreateCommand();
                parentCommand.Transaction = transaction;
                parentCommand.CommandText =
                    """
                    INSERT INTO sync_operation_parents(operation_id, parent_id)
                    VALUES ($operationId, $parentId);
                    """;
                parentCommand.Parameters.AddWithValue(
                    "$operationId",
                    operation.Id.ToString("D"));
                parentCommand.Parameters.AddWithValue(
                    "$parentId",
                    parent.ToString("D"));
                await parentCommand.ExecuteNonQueryAsync(cancellationToken);
            }

            if (applied)
            {
                await ExecuteOperationMarkerAsync(
                    connection,
                    transaction,
                    "sync_applied_operations",
                    operation.Id,
                    cancellationToken);
            }

            if (enqueue)
            {
                await using SqliteCommand outboxCommand = connection.CreateCommand();
                outboxCommand.Transaction = transaction;
                outboxCommand.CommandText =
                    """
                    INSERT INTO sync_outbox(
                        operation_id,
                        queued_utc_ticks,
                        attempt_count,
                        last_error)
                    VALUES ($operationId, $queuedTicks, 0, NULL);
                    """;
                outboxCommand.Parameters.AddWithValue(
                    "$operationId",
                    operation.Id.ToString("D"));
                outboxCommand.Parameters.AddWithValue(
                    "$queuedTicks",
                    DateTimeOffset.UtcNow.UtcTicks);
                await outboxCommand.ExecuteNonQueryAsync(cancellationToken);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(serialized);
            CryptographicOperations.ZeroMemory(objectHash);
            CryptographicOperations.ZeroMemory(associatedData);
            if (encrypted is not null)
            {
                CryptographicOperations.ZeroMemory(encrypted.Nonce);
                CryptographicOperations.ZeroMemory(encrypted.Ciphertext);
                CryptographicOperations.ZeroMemory(encrypted.Tag);
            }
        }
    }

    private static async Task ExecuteOperationMarkerAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        string tableName,
        Guid operationId,
        CancellationToken cancellationToken)
    {
        ArgumentOutOfRangeException.ThrowIfNotEqual(
            tableName,
            "sync_applied_operations");

        await using SqliteCommand command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText =
            """
            INSERT INTO sync_applied_operations(operation_id, applied_utc_ticks)
            VALUES ($operationId, $appliedTicks);
            """;
        command.Parameters.AddWithValue("$operationId", operationId.ToString("D"));
        command.Parameters.AddWithValue(
            "$appliedTicks",
            DateTimeOffset.UtcNow.UtcTicks);
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    private static async Task ReplaceGlobalFrontierAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        IReadOnlyCollection<Guid> parents,
        Guid operationId,
        CancellationToken cancellationToken)
    {
        foreach (Guid parent in parents)
        {
            await using SqliteCommand delete = connection.CreateCommand();
            delete.Transaction = transaction;
            delete.CommandText =
                "DELETE FROM sync_frontier WHERE operation_id = $operationId;";
            delete.Parameters.AddWithValue("$operationId", parent.ToString("D"));
            await delete.ExecuteNonQueryAsync(cancellationToken);
        }

        await using SqliteCommand insert = connection.CreateCommand();
        insert.Transaction = transaction;
        insert.CommandText =
            "INSERT OR IGNORE INTO sync_frontier(operation_id) VALUES ($operationId);";
        insert.Parameters.AddWithValue("$operationId", operationId.ToString("D"));
        await insert.ExecuteNonQueryAsync(cancellationToken);
    }

    private static async Task ReplaceFieldHeadsAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        Guid accountId,
        string fieldKey,
        SyncOperation operation,
        CancellationToken cancellationToken)
    {
        await using (SqliteCommand delete = connection.CreateCommand())
        {
            delete.Transaction = transaction;
            delete.CommandText =
                """
                DELETE FROM sync_field_heads
                WHERE account_id = $accountId AND field_key = $fieldKey;
                """;
            delete.Parameters.AddWithValue("$accountId", accountId.ToString("D"));
            delete.Parameters.AddWithValue("$fieldKey", fieldKey);
            await delete.ExecuteNonQueryAsync(cancellationToken);
        }

        byte[] valueHash = SyncSemanticHasher.Compute(operation);
        try
        {
            await using SqliteCommand insert = connection.CreateCommand();
            insert.Transaction = transaction;
            insert.CommandText =
                """
                INSERT INTO sync_field_heads(
                    account_id,
                    field_key,
                    operation_id,
                    value_hash)
                VALUES ($accountId, $fieldKey, $operationId, $valueHash);
                """;
            insert.Parameters.AddWithValue("$accountId", accountId.ToString("D"));
            insert.Parameters.AddWithValue("$fieldKey", fieldKey);
            insert.Parameters.AddWithValue(
                "$operationId",
                operation.Id.ToString("D"));
            insert.Parameters.Add("$valueHash", SqliteType.Blob).Value = valueHash;
            await insert.ExecuteNonQueryAsync(cancellationToken);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(valueHash);
        }
    }

    private static async Task<(Guid? DeviceId, long NextSequence, long LogicalClock)>
        ReadSyncStateAsync(
            SqliteConnection connection,
            SqliteTransaction transaction,
            CancellationToken cancellationToken)
    {
        await using SqliteCommand command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText =
            """
            SELECT device_id, next_device_sequence, logical_clock
            FROM sync_state
            WHERE singleton_id = 1;
            """;
        await using SqliteDataReader reader =
            await command.ExecuteReaderAsync(cancellationToken);
        if (!await reader.ReadAsync(cancellationToken))
        {
            throw InvalidDatabase("The sync state is missing.");
        }

        Guid? deviceId = reader.IsDBNull(0)
            ? null
            : Guid.TryParse(reader.GetString(0), out Guid parsed)
                ? parsed
                : throw InvalidDatabase("The sync device identifier is invalid.");
        long nextSequence = reader.GetInt64(1);
        long logicalClock = reader.GetInt64(2);
        if (nextSequence < 1 || logicalClock < 0)
        {
            throw InvalidDatabase("The sync sequence state is invalid.");
        }

        return (deviceId, nextSequence, logicalClock);
    }

    private static async Task WriteSyncStateAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        Guid deviceId,
        long nextSequence,
        long logicalClock,
        CancellationToken cancellationToken)
    {
        await using SqliteCommand command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText =
            """
            UPDATE sync_state
            SET device_id = $deviceId,
                next_device_sequence = $nextSequence,
                logical_clock = $logicalClock
            WHERE singleton_id = 1;
            """;
        command.Parameters.AddWithValue("$deviceId", deviceId.ToString("D"));
        command.Parameters.AddWithValue("$nextSequence", nextSequence);
        command.Parameters.AddWithValue("$logicalClock", logicalClock);
        if (await command.ExecuteNonQueryAsync(cancellationToken) != 1)
        {
            throw InvalidDatabase("The sync state could not be updated.");
        }
    }

    private static async Task<HashSet<Guid>> ReadGuidSetAsync(
        SqliteConnection connection,
        SqliteTransaction? transaction,
        string commandText,
        CancellationToken cancellationToken)
    {
        var result = new HashSet<Guid>();
        await using SqliteCommand command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = commandText;
        await using SqliteDataReader reader =
            await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            if (!Guid.TryParse(reader.GetString(0), out Guid id) || id == Guid.Empty)
            {
                throw InvalidDatabase("A sync identifier is invalid.");
            }

            result.Add(id);
        }

        return result;
    }

    private static byte[] CreateSyncAssociatedData(Guid operationId) =>
        Encoding.UTF8.GetBytes($"PersonalAuthenticator|v2|sync-operation|{operationId:D}");

    internal async Task ApplyRemoteOperationsAsync(
        IReadOnlyCollection<SyncOperation> remoteOperations,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(remoteOperations);
        cancellationToken.ThrowIfCancellationRequested();
        byte[] rootKey = await _rootKeyProvider.LoadAsync(cancellationToken);
        List<SyncOperation>? existingOperations = null;
        V2VaultSnapshot? current = null;
        SyncMergeResult? result = null;
        try
        {
            await using SqliteConnection connection = CreateConnection(SqliteOpenMode.ReadWrite);
            await OpenAndConfigureAsync(connection, writable: true, cancellationToken);
            await EnsureSchemaAsync(connection, databaseExisted: true, cancellationToken);
            await VerifySchemaAndIntegrityAsync(connection, cancellationToken);
            current = await LoadSnapshotForSyncAsync(
                connection,
                rootKey,
                cancellationToken);
            existingOperations = await LoadAllOperationsAsync(
                connection,
                rootKey,
                cancellationToken);
            if (existingOperations.Count == 0 && current.Accounts.Count > 0)
            {
                using var emptyBaseline =
                    new V2VaultSnapshot([], [], [], changeSequence: 0);
                List<SyncOperationDraft> baselineDrafts =
                    SyncOperationGenerator.Generate(
                        emptyBaseline,
                        current.Accounts,
                        current.SecretVersions,
                        current.HistoryEntries);
                try
                {
                    Guid localDeviceId =
                        await _deviceIdentityStore.LoadOrCreateAsync(
                            cancellationToken);
                    await using SqliteTransaction baselineTransaction =
                        (SqliteTransaction)await connection.BeginTransactionAsync(
                            cancellationToken);
                    try
                    {
                        await AppendLocalSyncOperationsAsync(
                            connection,
                            baselineTransaction,
                            rootKey,
                            localDeviceId,
                            baselineDrafts,
                            cancellationToken);
                        await baselineTransaction.CommitAsync(cancellationToken);
                    }
                    catch
                    {
                        await baselineTransaction.RollbackAsync(
                            CancellationToken.None);
                        throw;
                    }
                }
                finally
                {
                    foreach (SyncOperationDraft draft in baselineDrafts)
                    {
                        draft.Dispose();
                    }
                }

                existingOperations = await LoadAllOperationsAsync(
                    connection,
                    rootKey,
                    cancellationToken);
            }

            var operations = existingOperations.ToDictionary(operation => operation.Id);
            var newOperations = new List<SyncOperation>();
            foreach (SyncOperation remote in remoteOperations)
            {
                if (operations.TryGetValue(remote.Id, out SyncOperation? existing))
                {
                    if (!OperationsEqual(existing, remote))
                    {
                        throw new SafeApplicationException(
                            "Sync.ObjectCollision",
                            "A sync operation identifier already exists with different bytes.");
                    }

                    continue;
                }

                if (_remoteOperationValidator is not null &&
                    !_remoteOperationValidator(
                        remote.DeviceId,
                        remote.DeviceSequence))
                {
                    throw new SafeApplicationException(
                        "Sync.DeviceRevoked",
                        "A new operation from a revoked Windows device was rejected. Previously accepted history remains unchanged.");
                }

                if (operations.Values.Any(operation =>
                        operation.DeviceId == remote.DeviceId &&
                        operation.DeviceSequence == remote.DeviceSequence))
                {
                    throw new SafeApplicationException(
                        "Sync.SequenceCollision",
                        "A device sequence already exists with a different operation.");
                }

                operations.Add(remote.Id, remote);
                newOperations.Add(remote);
            }

            var applied = new HashSet<Guid>();
            using var empty = new V2VaultSnapshot([], [], [], changeSequence: 0);
            result = SyncMergeEngine.Apply(
                empty,
                operations,
                applied,
                new Dictionary<SyncFieldAddress, IReadOnlyList<SyncFieldHead>>(),
                [],
                new Dictionary<Guid, Guid>(),
                new Dictionary<Guid, Guid>());
            bool materialChanged = HasMaterialChanges(current, result);

            await using SqliteTransaction transaction =
                (SqliteTransaction)await connection.BeginTransactionAsync(
                    cancellationToken);
            try
            {
                foreach (SyncOperation operation in newOperations)
                {
                    await InsertOperationAsync(
                        connection,
                        transaction,
                        rootKey,
                        operation,
                        enqueue: false,
                        applied: false,
                        cancellationToken);
                }

                await RebuildGlobalFrontierAsync(
                    connection,
                    transaction,
                    cancellationToken);
                if (materialChanged)
                {
                    await ReplaceVaultRecordsAsync(
                        connection,
                        transaction,
                        rootKey,
                        result.Accounts,
                        result.SecretVersions,
                        result.HistoryEntries,
                        cancellationToken);
                    long sequence = await ReadChangeSequenceAsync(
                        connection,
                        transaction,
                        cancellationToken);
                    await WriteChangeSequenceAsync(
                        connection,
                        transaction,
                        checked(sequence + 1),
                        cancellationToken);
                }

                await ExecuteAsync(
                    connection,
                    transaction,
                    "DELETE FROM sync_applied_operations;",
                    cancellationToken);
                await PersistMergeMetadataAsync(
                    connection,
                    transaction,
                    new HashSet<Guid>(),
                    result,
                    cancellationToken);
                long maximumClock = operations.Count == 0
                    ? 0
                    : operations.Values.Max(operation => operation.LogicalClock);
                await using (SqliteCommand clock = connection.CreateCommand())
                {
                    clock.Transaction = transaction;
                    clock.CommandText =
                        """
                        UPDATE sync_state
                        SET logical_clock = max(logical_clock, $logicalClock)
                        WHERE singleton_id = 1;
                        """;
                    clock.Parameters.AddWithValue("$logicalClock", maximumClock);
                    await clock.ExecuteNonQueryAsync(cancellationToken);
                }

                await transaction.CommitAsync(cancellationToken);
            }
            catch
            {
                await transaction.RollbackAsync(CancellationToken.None);
                throw;
            }
        }
        finally
        {
            result?.Dispose();
            current?.Dispose();
            if (existingOperations is not null)
            {
                foreach (SyncOperation operation in existingOperations)
                {
                    operation.Dispose();
                }
            }

            CryptographicOperations.ZeroMemory(rootKey);
        }
    }

    internal async Task<IReadOnlyList<SyncDeviceActivity>>
        GetSyncDeviceActivityAsync(CancellationToken cancellationToken)
    {
        byte[] rootKey = await _rootKeyProvider.LoadAsync(cancellationToken);
        List<SyncOperation>? operations = null;
        try
        {
            await using SqliteConnection connection =
                CreateConnection(SqliteOpenMode.ReadOnly);
            await OpenAndConfigureAsync(
                connection,
                writable: false,
                cancellationToken);
            await VerifySchemaAndIntegrityAsync(connection, cancellationToken);
            operations = await LoadAllOperationsAsync(
                connection,
                rootKey,
                cancellationToken);
            return operations
                .GroupBy(operation => operation.DeviceId)
                .Select(group => new SyncDeviceActivity(
                    group.Key,
                    group.Min(operation => operation.OccurredAtUtc),
                    group.Max(operation => operation.OccurredAtUtc),
                    group.Max(operation => operation.DeviceSequence)))
                .OrderByDescending(item => item.LastSeenAtUtc)
                .ToList();
        }
        finally
        {
            CryptographicOperations.ZeroMemory(rootKey);
            if (operations is not null)
            {
                foreach (SyncOperation operation in operations)
                {
                    operation.Dispose();
                }
            }
        }
    }

    internal async Task<IReadOnlyList<SyncConflictSummary>>
        GetUnresolvedConflictsAsync(CancellationToken cancellationToken)
    {
        await using SqliteConnection connection = CreateConnection(SqliteOpenMode.ReadWrite);
        await OpenAndConfigureAsync(connection, writable: true, cancellationToken);
        await EnsureSchemaAsync(connection, databaseExisted: true, cancellationToken);
        List<SyncConflictRecord> records = await ReadConflictRecordsAsync(
            connection,
            cancellationToken);
        return records
            .Where(record => !record.Resolved)
            .OrderBy(record => record.DetectedAtUtc)
            .ThenBy(record => record.Id)
            .Select(record => new SyncConflictSummary(
                record.Id,
                record.AccountId,
                record.Kind,
                record.FieldKey,
                record.OperationAId,
                record.OperationBId,
                record.SecretVersionAId,
                record.SecretVersionBId,
                record.DetectedAtUtc))
            .ToList();
    }

    internal async Task QueueConflictResolutionAsync(
        Guid conflictId,
        SyncConflictResolution resolution,
        CancellationToken cancellationToken)
    {
        if (conflictId == Guid.Empty || !Enum.IsDefined(resolution))
        {
            throw new SafeApplicationException(
                "Sync.InvalidResolution",
                "The selected conflict resolution is invalid.");
        }

        byte[] rootKey = await _rootKeyProvider.LoadAsync(cancellationToken);
        SyncOperation? operation = null;
        try
        {
            await using SqliteConnection connection =
                CreateConnection(SqliteOpenMode.ReadWrite);
            await OpenAndConfigureAsync(connection, writable: true, cancellationToken);
            await EnsureSchemaAsync(connection, databaseExisted: true, cancellationToken);
            List<SyncConflictRecord> conflicts = await ReadConflictRecordsAsync(
                connection,
                cancellationToken);
            SyncConflictRecord conflict = conflicts.FirstOrDefault(
                    item => item.Id == conflictId && !item.Resolved) ??
                throw new SafeApplicationException(
                    "Sync.ConflictNotFound",
                    "The selected conflict no longer exists or is already resolved.");
            bool isSecretConflict = conflict.Kind is
                SyncConflictKind.SecretAdded or SyncConflictKind.ActiveSecret;
            if (!isSecretConflict &&
                resolution is
                    SyncConflictResolution.KeepBoth or
                    SyncConflictResolution.SeparateAccounts)
            {
                throw new SafeApplicationException(
                    "Sync.InvalidResolution",
                    "This resolution is available only for secret conflicts.");
            }

            Guid localDeviceId =
                await _deviceIdentityStore.LoadOrCreateAsync(cancellationToken);
            await using SqliteTransaction transaction =
                (SqliteTransaction)await connection.BeginTransactionAsync(
                    cancellationToken);
            try
            {
                (Guid? storedDeviceId, long nextSequence, long logicalClock) =
                    await ReadSyncStateAsync(
                        connection,
                        transaction,
                        cancellationToken);
                if (storedDeviceId.HasValue &&
                    storedDeviceId.Value != localDeviceId)
                {
                    throw new SafeApplicationException(
                        "Sync.DeviceIdentityMismatch",
                        "This local vault belongs to a different Windows sync device identity.");
                }

                HashSet<Guid> frontier = await ReadGuidSetAsync(
                    connection,
                    transaction,
                    "SELECT operation_id FROM sync_frontier ORDER BY operation_id;",
                    cancellationToken);
                frontier.Add(conflict.OperationAId);
                frontier.Add(conflict.OperationBId);
                Guid operationId = Guid.NewGuid();
                operation = new SyncOperation(
                    operationId,
                    localDeviceId,
                    nextSequence,
                    checked(logicalClock + 1),
                    DateTimeOffset.UtcNow,
                    conflict.AccountId,
                    SyncOperationKind.ConflictResolved,
                    SyncFieldKeys.Resolution + ":" + conflictId.ToString("N"),
                    frontier.Order().ToArray(),
                    new SyncOperationPayload
                    {
                        ConflictId = conflictId,
                        Resolution = resolution,
                        GuidValue = resolution ==
                            SyncConflictResolution.SeparateAccounts
                                ? Guid.NewGuid()
                                : null,
                        SecondaryGuidValue = resolution ==
                            SyncConflictResolution.SeparateAccounts
                                ? Guid.NewGuid()
                                : null,
                    });
                await InsertOperationAsync(
                    connection,
                    transaction,
                    rootKey,
                    operation,
                    enqueue: true,
                    applied: false,
                    cancellationToken);
                await ReplaceGlobalFrontierAsync(
                    connection,
                    transaction,
                    frontier,
                    operationId,
                    cancellationToken);
                await WriteSyncStateAsync(
                    connection,
                    transaction,
                    localDeviceId,
                    checked(nextSequence + 1),
                    checked(logicalClock + 1),
                    cancellationToken);
                await transaction.CommitAsync(cancellationToken);
            }
            catch
            {
                await transaction.RollbackAsync(CancellationToken.None);
                throw;
            }
        }
        finally
        {
            operation?.Dispose();
            CryptographicOperations.ZeroMemory(rootKey);
        }

        // The durable operation and outbox row are committed first. Applying it is
        // retryable, so an interruption cannot lose the user's resolution choice.
        await ApplyRemoteOperationsAsync([], cancellationToken);
    }

    internal async Task<Guid> GetSyncDeviceIdAsync(
        CancellationToken cancellationToken) =>
        await _deviceIdentityStore.LoadOrCreateAsync(cancellationToken);

    internal async Task RebuildStateFromOperationsAsync(
        CancellationToken cancellationToken)
    {
        byte[] rootKey = await _rootKeyProvider.LoadAsync(cancellationToken);
        List<SyncOperation>? operations = null;
        SyncMergeResult? result = null;
        try
        {
            await using SqliteConnection connection = CreateConnection(SqliteOpenMode.ReadWrite);
            await OpenAndConfigureAsync(connection, writable: true, cancellationToken);
            await EnsureSchemaAsync(connection, databaseExisted: true, cancellationToken);
            operations = await LoadAllOperationsAsync(
                connection,
                rootKey,
                cancellationToken);
            using var empty = new V2VaultSnapshot([], [], [], changeSequence: 0);
            result = SyncMergeEngine.Apply(
                empty,
                operations.ToDictionary(operation => operation.Id),
                new HashSet<Guid>(),
                new Dictionary<SyncFieldAddress, IReadOnlyList<SyncFieldHead>>(),
                [],
                new Dictionary<Guid, Guid>(),
                new Dictionary<Guid, Guid>());
            if (result.AppliedOperationIds.Count != operations.Count)
            {
                throw new SafeApplicationException(
                    "Sync.MissingOperations",
                    "The operation log has missing causal parents and cannot rebuild state.");
            }

            await using SqliteTransaction transaction =
                (SqliteTransaction)await connection.BeginTransactionAsync(
                    cancellationToken);
            try
            {
                await ReplaceVaultRecordsAsync(
                    connection,
                    transaction,
                    rootKey,
                    result.Accounts,
                    result.SecretVersions,
                    result.HistoryEntries,
                    cancellationToken);
                long sequence = await ReadChangeSequenceAsync(
                    connection,
                    transaction,
                    cancellationToken);
                await WriteChangeSequenceAsync(
                    connection,
                    transaction,
                    checked(sequence + 1),
                    cancellationToken);
                await ExecuteAsync(
                    connection,
                    transaction,
                    """
                    DELETE FROM sync_applied_operations;
                    DELETE FROM sync_field_heads;
                    DELETE FROM sync_conflicts;
                    DELETE FROM sync_account_aliases;
                    DELETE FROM sync_secret_aliases;
                    """,
                    cancellationToken);
                await PersistMergeMetadataAsync(
                    connection,
                    transaction,
                    new HashSet<Guid>(),
                    result,
                    cancellationToken);
                await transaction.CommitAsync(cancellationToken);
            }
            catch
            {
                await transaction.RollbackAsync(CancellationToken.None);
                throw;
            }
        }
        finally
        {
            result?.Dispose();
            if (operations is not null)
            {
                foreach (SyncOperation operation in operations)
                {
                    operation.Dispose();
                }
            }

            CryptographicOperations.ZeroMemory(rootKey);
        }
    }

    internal async Task<SyncRecoveryState> ExportSyncRecoveryStateAsync(
        SyncRecoveryConfiguration? configuration,
        CancellationToken cancellationToken)
    {
        byte[] rootKey = await _rootKeyProvider.LoadAsync(cancellationToken);
        List<SyncOperation>? operations = null;
        var serialized = new List<byte[]>();
        try
        {
            await using SqliteConnection connection =
                CreateConnection(SqliteOpenMode.ReadWrite);
            await OpenAndConfigureAsync(connection, writable: true, cancellationToken);
            await EnsureSchemaAsync(connection, databaseExisted: true, cancellationToken);
            await VerifySchemaAndIntegrityAsync(connection, cancellationToken);
            operations = await LoadAllOperationsAsync(
                connection,
                rootKey,
                cancellationToken);
            foreach (SyncOperation operation in operations)
            {
                serialized.Add(SyncOperationSerializer.Serialize(operation));
            }

            HashSet<Guid> outbox = await ReadGuidSetAsync(
                connection,
                transaction: null,
                "SELECT operation_id FROM sync_outbox ORDER BY operation_id;",
                cancellationToken);
            List<SyncConflictRecord> conflicts =
                (await ReadConflictRecordsAsync(connection, cancellationToken))
                .Where(item => !item.Resolved)
                .ToList();
            Dictionary<Guid, long> coverage = operations
                .GroupBy(item => item.DeviceId)
                .ToDictionary(
                    group => group.Key,
                    group => group.Max(item => item.DeviceSequence));
            Guid deviceId =
                await _deviceIdentityStore.LoadOrCreateAsync(cancellationToken);
            return new SyncRecoveryState(
                ProtocolVersion: 1,
                RequiredFeatures:
                [
                    "immutable-operations-v1",
                    "causal-parents-v1",
                    "conflicts-v1",
                ],
                deviceId,
                coverage,
                serialized,
                outbox,
                conflicts,
                configuration);
        }
        catch
        {
            foreach (byte[] operation in serialized)
            {
                CryptographicOperations.ZeroMemory(operation);
            }

            throw;
        }
        finally
        {
            if (operations is not null)
            {
                foreach (SyncOperation operation in operations)
                {
                    operation.Dispose();
                }
            }

            CryptographicOperations.ZeroMemory(rootKey);
        }
    }

    internal async Task SetRecoveryChangeSequenceAsync(
        long changeSequence,
        CancellationToken cancellationToken)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(changeSequence);
        await using SqliteConnection connection =
            CreateConnection(SqliteOpenMode.ReadWrite);
        await OpenAndConfigureAsync(connection, writable: true, cancellationToken);
        await using SqliteTransaction transaction =
            (SqliteTransaction)await connection.BeginTransactionAsync(
                cancellationToken);
        try
        {
            await WriteChangeSequenceAsync(
                connection,
                transaction,
                changeSequence,
                cancellationToken);
            await transaction.CommitAsync(cancellationToken);
        }
        catch
        {
            await transaction.RollbackAsync(CancellationToken.None);
            throw;
        }
    }

    internal async Task ImportSyncRecoveryStateAsync(
        SyncRecoveryState state,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(state);
        if (state.ProtocolVersion != 1 ||
            state.RequiredFeatures.Any(feature =>
                feature is not (
                    "immutable-operations-v1" or
                    "causal-parents-v1" or
                    "conflicts-v1")))
        {
            throw new SafeApplicationException(
                "Recovery.UnsupportedSyncProtocol",
                "The recovery bundle requires a newer sync protocol.");
        }

        byte[] rootKey = await _rootKeyProvider.LoadAsync(cancellationToken);
        var operations = new List<SyncOperation>(state.SerializedOperations.Count);
        try
        {
            foreach (byte[] serialized in state.SerializedOperations)
            {
                operations.Add(SyncOperationSerializer.Deserialize(serialized));
            }

            if (operations.Select(item => item.Id).Distinct().Count() !=
                    operations.Count ||
                operations.GroupBy(item => (item.DeviceId, item.DeviceSequence))
                    .Any(group => group.Count() != 1) ||
                state.OutboxOperationIds.Any(id =>
                    operations.All(operation => operation.Id != id)))
            {
                throw new SafeApplicationException(
                    "Recovery.InvalidSyncState",
                    "The recovery sync history is inconsistent.");
            }

            await using SqliteConnection connection =
                CreateConnection(SqliteOpenMode.ReadWrite);
            await OpenAndConfigureAsync(connection, writable: true, cancellationToken);
            await EnsureSchemaAsync(connection, databaseExisted: true, cancellationToken);
            await using SqliteTransaction transaction =
                (SqliteTransaction)await connection.BeginTransactionAsync(
                    cancellationToken);
            try
            {
                await ExecuteAsync(
                    connection,
                    transaction,
                    """
                    DROP TRIGGER IF EXISTS sync_operations_no_update;
                    DROP TRIGGER IF EXISTS sync_operations_no_delete;
                    DELETE FROM sync_outbox;
                    DELETE FROM sync_applied_operations;
                    DELETE FROM sync_frontier;
                    DELETE FROM sync_field_heads;
                    DELETE FROM sync_conflicts;
                    DELETE FROM sync_account_aliases;
                    DELETE FROM sync_secret_aliases;
                    DELETE FROM sync_operation_parents;
                    DELETE FROM sync_operations;
                    """,
                    cancellationToken);
                foreach (SyncOperation operation in operations)
                {
                    await InsertOperationAsync(
                        connection,
                        transaction,
                        rootKey,
                        operation,
                        enqueue: state.OutboxOperationIds.Contains(operation.Id),
                        applied: false,
                        cancellationToken);
                }

                Guid localDeviceId =
                    await _deviceIdentityStore.LoadOrCreateAsync(cancellationToken);
                long nextSequence = checked(
                    operations
                        .Where(item => item.DeviceId == localDeviceId)
                        .Select(item => item.DeviceSequence)
                        .DefaultIfEmpty(0)
                        .Max() + 1);
                long logicalClock = operations
                    .Select(item => item.LogicalClock)
                    .DefaultIfEmpty(0)
                    .Max();
                await WriteSyncStateAsync(
                    connection,
                    transaction,
                    localDeviceId,
                    nextSequence,
                    logicalClock,
                    cancellationToken);
                await RebuildGlobalFrontierAsync(
                    connection,
                    transaction,
                    cancellationToken);
                await ExecuteAsync(
                    connection,
                    transaction,
                    """
                    CREATE TRIGGER sync_operations_no_update
                    BEFORE UPDATE ON sync_operations
                    BEGIN
                        SELECT RAISE(ABORT, 'sync operations are immutable');
                    END;
                    CREATE TRIGGER sync_operations_no_delete
                    BEFORE DELETE ON sync_operations
                    BEGIN
                        SELECT RAISE(ABORT, 'sync operations are immutable');
                    END;
                    """,
                    cancellationToken);
                await transaction.CommitAsync(cancellationToken);
            }
            catch
            {
                await transaction.RollbackAsync(CancellationToken.None);
                throw;
            }
        }
        finally
        {
            foreach (SyncOperation operation in operations)
            {
                operation.Dispose();
            }

            CryptographicOperations.ZeroMemory(rootKey);
        }

        await ApplyRemoteOperationsAsync([], cancellationToken);
    }

    private static async Task<List<SyncOperation>> LoadAllOperationsAsync(
        SqliteConnection connection,
        ReadOnlyMemory<byte> rootKey,
        CancellationToken cancellationToken)
    {
        var operations = new List<SyncOperation>();
        try
        {
            await using SqliteCommand command = connection.CreateCommand();
            command.CommandText =
                """
                SELECT operation_id, object_hash, nonce, ciphertext, tag
                FROM sync_operations
                ORDER BY logical_clock, device_id, device_sequence, operation_id;
                """;
            await using SqliteDataReader reader =
                await command.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken))
            {
                if (operations.Count >= 1_000_000)
                {
                    throw InvalidDatabase("The operation log is too large.");
                }

                Guid operationId = ReadGuid(reader, 0, "sync operation");
                byte[] expectedHash = ReadBlob(reader, 1, 32, "sync object hash");
                byte[] nonce = ReadBlob(reader, 2, 12, "sync nonce");
                byte[] ciphertext = ReadBlob(
                    reader,
                    3,
                    SyncOperationSerializer.MaximumOperationBytes,
                    "sync operation");
                byte[] tag = ReadBlob(reader, 4, 16, "sync tag");
                byte[] associatedData = CreateSyncAssociatedData(operationId);
                byte[] plaintext = [];
                try
                {
                    plaintext = V2RecordCryptography.Decrypt(
                        nonce,
                        ciphertext,
                        tag,
                        rootKey.Span,
                        associatedData);
                    byte[] actualHash = SHA256.HashData(plaintext);
                    try
                    {
                        if (!CryptographicOperations.FixedTimeEquals(
                                expectedHash,
                                actualHash))
                        {
                            throw InvalidDatabase(
                                "A sync operation failed its object hash check.");
                        }
                    }
                    finally
                    {
                        CryptographicOperations.ZeroMemory(actualHash);
                    }

                    SyncOperation operation =
                        SyncOperationSerializer.Deserialize(plaintext);
                    if (operation.Id != operationId)
                    {
                        operation.Dispose();
                        throw InvalidDatabase(
                            "A sync operation identifier is inconsistent.");
                    }

                    operations.Add(operation);
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(expectedHash);
                    CryptographicOperations.ZeroMemory(nonce);
                    CryptographicOperations.ZeroMemory(ciphertext);
                    CryptographicOperations.ZeroMemory(tag);
                    CryptographicOperations.ZeroMemory(associatedData);
                    CryptographicOperations.ZeroMemory(plaintext);
                }
            }

            return operations;
        }
        catch
        {
            foreach (SyncOperation operation in operations)
            {
                operation.Dispose();
            }

            throw;
        }
    }

    private static async Task<HashSet<Guid>> ReadAppliedOperationIdsAsync(
        SqliteConnection connection,
        CancellationToken cancellationToken)
    {
        var result = new HashSet<Guid>();
        await using SqliteCommand command = connection.CreateCommand();
        command.CommandText =
            """
            SELECT operation_id
            FROM sync_applied_operations
            ORDER BY operation_id;
            """;
        await using SqliteDataReader reader =
            await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            result.Add(ReadGuid(reader, 0, "applied operation"));
        }

        return result;
    }

    private static async Task<
        Dictionary<SyncFieldAddress, IReadOnlyList<SyncFieldHead>>>
        ReadFieldHeadsAsync(
            SqliteConnection connection,
            CancellationToken cancellationToken)
    {
        var result = new Dictionary<SyncFieldAddress, List<SyncFieldHead>>();
        await using SqliteCommand command = connection.CreateCommand();
        command.CommandText =
            """
            SELECT account_id, field_key, operation_id, value_hash
            FROM sync_field_heads
            ORDER BY account_id, field_key, operation_id;
            """;
        await using SqliteDataReader reader =
            await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            Guid accountId = ReadGuid(reader, 0, "field-head account");
            string fieldKey = reader.GetString(1);
            Guid operationId = ReadGuid(reader, 2, "field-head operation");
            byte[] valueHash = ReadBlob(reader, 3, 32, "field-head hash");
            var address = new SyncFieldAddress(accountId, fieldKey);
            if (!result.TryGetValue(address, out List<SyncFieldHead>? list))
            {
                list = [];
                result.Add(address, list);
            }

            list.Add(new SyncFieldHead(operationId, valueHash));
        }

        return result.ToDictionary(
            item => item.Key,
            item => (IReadOnlyList<SyncFieldHead>)item.Value);
    }

    private static async Task<List<SyncConflictRecord>> ReadConflictRecordsAsync(
        SqliteConnection connection,
        CancellationToken cancellationToken)
    {
        var records = new List<SyncConflictRecord>();
        await using SqliteCommand command = connection.CreateCommand();
        command.CommandText =
            """
            SELECT conflict_id,
                   account_id,
                   kind,
                   field_key,
                   operation_a_id,
                   operation_b_id,
                   secret_version_a_id,
                   secret_version_b_id,
                   detected_utc_ticks,
                   resolved
            FROM sync_conflicts
            ORDER BY detected_utc_ticks, conflict_id;
            """;
        await using SqliteDataReader reader =
            await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            var kind = (SyncConflictKind)reader.GetInt32(2);
            if (!Enum.IsDefined(kind))
            {
                throw InvalidDatabase("A sync conflict kind is invalid.");
            }

            records.Add(
                new SyncConflictRecord(
                    ReadGuid(reader, 0, "conflict"),
                    ReadGuid(reader, 1, "conflict account"),
                    kind,
                    reader.GetString(3),
                    ReadGuid(reader, 4, "conflict operation A"),
                    ReadGuid(reader, 5, "conflict operation B"),
                    reader.IsDBNull(6)
                        ? null
                        : ReadGuid(reader, 6, "conflict secret A"),
                    reader.IsDBNull(7)
                        ? null
                        : ReadGuid(reader, 7, "conflict secret B"),
                    new DateTimeOffset(reader.GetInt64(8), TimeSpan.Zero),
                    reader.GetInt64(9) == 1));
        }

        return records;
    }

    private static async Task<Dictionary<Guid, Guid>> ReadAliasesAsync(
        SqliteConnection connection,
        string tableName,
        string sourceColumn,
        string canonicalColumn,
        CancellationToken cancellationToken)
    {
        bool valid =
            (tableName == "sync_account_aliases" &&
             sourceColumn == "source_account_id" &&
             canonicalColumn == "canonical_account_id") ||
            (tableName == "sync_secret_aliases" &&
             sourceColumn == "source_secret_version_id" &&
             canonicalColumn == "canonical_secret_version_id");
        if (!valid)
        {
            throw new ArgumentOutOfRangeException(nameof(tableName));
        }

        var result = new Dictionary<Guid, Guid>();
        await using SqliteCommand command = connection.CreateCommand();
        command.CommandText =
            $"SELECT {sourceColumn}, {canonicalColumn} FROM {tableName} ORDER BY {sourceColumn};";
        await using SqliteDataReader reader =
            await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            result.Add(
                ReadGuid(reader, 0, "alias source"),
                ReadGuid(reader, 1, "alias target"));
        }

        return result;
    }

    private static async Task ReplaceVaultRecordsAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        ReadOnlyMemory<byte> rootKey,
        IReadOnlyCollection<VaultAccountV2> accounts,
        IReadOnlyCollection<SecretVersionV2> versions,
        IReadOnlyCollection<AccountHistoryEntryV2> history,
        CancellationToken cancellationToken)
    {
        ValidateSnapshot(accounts, versions, history);
        await ExecuteAsync(
            connection,
            transaction,
            """
            DELETE FROM account_history_records;
            DELETE FROM secret_version_records;
            DELETE FROM account_records;
            """,
            cancellationToken);
        foreach (VaultAccountV2 account in accounts.OrderBy(item => item.Id))
        {
            await InsertAccountAsync(
                connection,
                transaction,
                rootKey,
                account,
                cancellationToken);
        }

        foreach (SecretVersionV2 version in versions.OrderBy(item => item.Id))
        {
            await InsertSecretVersionAsync(
                connection,
                transaction,
                rootKey,
                version,
                cancellationToken);
        }

        foreach (AccountHistoryEntryV2 entry in history.OrderBy(item => item.Id))
        {
            await InsertHistoryEntryAsync(
                connection,
                transaction,
                rootKey,
                entry,
                cancellationToken);
        }
    }

    private static async Task PersistMergeMetadataAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        HashSet<Guid> previouslyApplied,
        SyncMergeResult result,
        CancellationToken cancellationToken)
    {
        foreach (Guid operationId in result.AppliedOperationIds
                     .Where(id => !previouslyApplied.Contains(id)))
        {
            await using SqliteCommand applied = connection.CreateCommand();
            applied.Transaction = transaction;
            applied.CommandText =
                """
                INSERT OR IGNORE INTO sync_applied_operations(
                    operation_id,
                    applied_utc_ticks)
                VALUES ($operationId, $appliedTicks);
                """;
            applied.Parameters.AddWithValue(
                "$operationId",
                operationId.ToString("D"));
            applied.Parameters.AddWithValue(
                "$appliedTicks",
                DateTimeOffset.UtcNow.UtcTicks);
            await applied.ExecuteNonQueryAsync(cancellationToken);
        }

        await ExecuteAsync(
            connection,
            transaction,
            """
            DELETE FROM sync_field_heads;
            DELETE FROM sync_conflicts;
            DELETE FROM sync_account_aliases;
            DELETE FROM sync_secret_aliases;
            """,
            cancellationToken);
        foreach ((SyncFieldAddress address, List<SyncFieldHead> fieldHeads) in
                 result.FieldHeads)
        {
            foreach (SyncFieldHead head in fieldHeads)
            {
                await using SqliteCommand command = connection.CreateCommand();
                command.Transaction = transaction;
                command.CommandText =
                    """
                    INSERT INTO sync_field_heads(
                        account_id,
                        field_key,
                        operation_id,
                        value_hash)
                    VALUES ($accountId, $fieldKey, $operationId, $valueHash);
                    """;
                command.Parameters.AddWithValue(
                    "$accountId",
                    address.AccountId.ToString("D"));
                command.Parameters.AddWithValue("$fieldKey", address.FieldKey);
                command.Parameters.AddWithValue(
                    "$operationId",
                    head.OperationId.ToString("D"));
                command.Parameters.Add("$valueHash", SqliteType.Blob).Value =
                    head.ValueHash;
                await command.ExecuteNonQueryAsync(cancellationToken);
            }
        }

        foreach (SyncConflictRecord conflict in result.Conflicts)
        {
            await using SqliteCommand command = connection.CreateCommand();
            command.Transaction = transaction;
            command.CommandText =
                """
                INSERT INTO sync_conflicts(
                    conflict_id,
                    account_id,
                    kind,
                    field_key,
                    operation_a_id,
                    operation_b_id,
                    secret_version_a_id,
                    secret_version_b_id,
                    detected_utc_ticks,
                    resolved)
                VALUES (
                    $conflictId,
                    $accountId,
                    $kind,
                    $fieldKey,
                    $operationA,
                    $operationB,
                    $secretA,
                    $secretB,
                    $detectedTicks,
                    $resolved);
                """;
            command.Parameters.AddWithValue(
                "$conflictId",
                conflict.Id.ToString("D"));
            command.Parameters.AddWithValue(
                "$accountId",
                conflict.AccountId.ToString("D"));
            command.Parameters.AddWithValue("$kind", (int)conflict.Kind);
            command.Parameters.AddWithValue("$fieldKey", conflict.FieldKey);
            command.Parameters.AddWithValue(
                "$operationA",
                conflict.OperationAId.ToString("D"));
            command.Parameters.AddWithValue(
                "$operationB",
                conflict.OperationBId.ToString("D"));
            command.Parameters.AddWithValue(
                "$secretA",
                conflict.SecretVersionAId?.ToString("D") ?? (object)DBNull.Value);
            command.Parameters.AddWithValue(
                "$secretB",
                conflict.SecretVersionBId?.ToString("D") ?? (object)DBNull.Value);
            command.Parameters.AddWithValue(
                "$detectedTicks",
                conflict.DetectedAtUtc.UtcTicks);
            command.Parameters.AddWithValue("$resolved", conflict.Resolved ? 1 : 0);
            await command.ExecuteNonQueryAsync(cancellationToken);
        }

        await PersistAliasesAsync(
            connection,
            transaction,
            "sync_account_aliases",
            "source_account_id",
            "canonical_account_id",
            result.AccountAliases,
            cancellationToken);
        await PersistAliasesAsync(
            connection,
            transaction,
            "sync_secret_aliases",
            "source_secret_version_id",
            "canonical_secret_version_id",
            result.SecretAliases,
            cancellationToken);
    }

    private static bool HasMaterialChanges(
        V2VaultSnapshot current,
        SyncMergeResult rebuilt)
    {
        List<SyncOperationDraft> drafts = SyncOperationGenerator.Generate(
            current,
            rebuilt.Accounts,
            rebuilt.SecretVersions,
            rebuilt.HistoryEntries);
        try
        {
            return drafts.Count != 0;
        }
        finally
        {
            foreach (SyncOperationDraft draft in drafts)
            {
                draft.Dispose();
            }
        }
    }

    private static async Task PersistAliasesAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        string tableName,
        string sourceColumn,
        string canonicalColumn,
        IReadOnlyDictionary<Guid, Guid> aliases,
        CancellationToken cancellationToken)
    {
        foreach ((Guid source, Guid canonical) in aliases)
        {
            await using SqliteCommand command = connection.CreateCommand();
            command.Transaction = transaction;
            command.CommandText =
                $"INSERT INTO {tableName}({sourceColumn}, {canonicalColumn}) VALUES ($source, $canonical);";
            command.Parameters.AddWithValue("$source", source.ToString("D"));
            command.Parameters.AddWithValue("$canonical", canonical.ToString("D"));
            await command.ExecuteNonQueryAsync(cancellationToken);
        }
    }

    private static async Task RebuildGlobalFrontierAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        CancellationToken cancellationToken) =>
        await ExecuteAsync(
            connection,
            transaction,
            """
            DELETE FROM sync_frontier;
            INSERT INTO sync_frontier(operation_id)
            SELECT operation_id
            FROM sync_operations
            WHERE operation_id NOT IN (
                SELECT parent_id FROM sync_operation_parents
            );
            """,
            cancellationToken);

    private static bool OperationsEqual(
        SyncOperation first,
        SyncOperation second)
    {
        byte[] firstBytes = SyncOperationSerializer.Serialize(first);
        byte[] secondBytes = SyncOperationSerializer.Serialize(second);
        try
        {
            return firstBytes.Length == secondBytes.Length &&
                CryptographicOperations.FixedTimeEquals(firstBytes, secondBytes);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(firstBytes);
            CryptographicOperations.ZeroMemory(secondBytes);
        }
    }

    private static SyncOperationPayload ClonePayload(SyncOperationPayload payload) =>
        new()
        {
            TextValue = payload.TextValue,
            BoolValue = payload.BoolValue,
            IntValue = payload.IntValue,
            DateValue = payload.DateValue,
            GuidValue = payload.GuidValue,
            SecondaryGuidValue = payload.SecondaryGuidValue,
            Account = payload.Account is null
                ? null
                : SyncOperationGenerator.CloneAccount(payload.Account),
            SecretVersion = payload.SecretVersion is null
                ? null
                : SyncOperationGenerator.CloneVersion(payload.SecretVersion),
            HistoryEntry = payload.HistoryEntry is null
                ? null
                : SyncOperationGenerator.CloneHistory(payload.HistoryEntry),
            ConflictId = payload.ConflictId,
            Resolution = payload.Resolution,
        };
}
