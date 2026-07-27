using System.Data;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Data.Sqlite;
using PersonalAuthenticator.Core.Abstractions;
using PersonalAuthenticator.Core.Domain;
using PersonalAuthenticator.Core.Exceptions;
using PersonalAuthenticator.Infrastructure.Serialization;

namespace PersonalAuthenticator.Infrastructure.Storage;

public sealed class V2SqliteVaultStore : IV2VaultStore
{
    private const int ApplicationId = 0x50415632;
    private const int SchemaVersion = 3;
    private const int MaximumAccounts = 10_000;
    private const int MaximumSecretVersions = 100_000;
    private const int MaximumHistoryEntries = 1_000_000;
    private const int MaximumAccountPayloadBytes = 16 * 1024;
    private const int MaximumSecretPayloadBytes = 32 * 1024;
    private const int MaximumHistoryPayloadBytes = 8 * 1024;
    private const long MaximumDatabaseBytes = 256L * 1024 * 1024;
    private readonly IVaultRootKeyProvider _rootKeyProvider;

    public V2SqliteVaultStore(string databasePath, string? keyPath = null)
        : this(
            databasePath,
            new DpapiV2RootKeyProvider(
                keyPath ??
                Path.Combine(
                    Path.GetDirectoryName(Path.GetFullPath(databasePath)) ??
                        throw new ArgumentException(
                            "The database path must include a directory.",
                            nameof(databasePath)),
                    "vault-v2.key")))
    {
    }

    internal V2SqliteVaultStore(
        string databasePath,
        IVaultRootKeyProvider rootKeyProvider)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(databasePath);
        ArgumentNullException.ThrowIfNull(rootKeyProvider);
        DatabasePath = Path.GetFullPath(databasePath);
        _rootKeyProvider = rootKeyProvider;
    }

    public string DatabasePath { get; }

    public Task<bool> ExistsAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return Task.FromResult(File.Exists(DatabasePath) && _rootKeyProvider.Exists);
    }

    public async Task<V2VaultSnapshot> LoadAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ValidateDatabaseSize();
        if (!File.Exists(DatabasePath) || !_rootKeyProvider.Exists)
        {
            throw new SafeApplicationException(
                "VaultV2.NotFound",
                "The encrypted v2 vault is not available.");
        }

        byte[] rootKey = await _rootKeyProvider.LoadAsync(cancellationToken);
        var accounts = new List<VaultAccountV2>();
        var secretVersions = new List<SecretVersionV2>();
        var historyEntries = new List<AccountHistoryEntryV2>();
        try
        {
            await using SqliteConnection connection = CreateConnection(SqliteOpenMode.ReadWrite);
            await OpenAndConfigureAsync(connection, writable: true, cancellationToken);
            await EnsureSchemaAsync(connection, databaseExisted: true, cancellationToken);
            await VerifySchemaAndIntegrityAsync(connection, cancellationToken);
            await LoadAccountsAsync(connection, rootKey, accounts, cancellationToken);
            await LoadSecretVersionsAsync(
                connection,
                rootKey,
                secretVersions,
                cancellationToken);
            await LoadHistoryEntriesAsync(
                connection,
                rootKey,
                historyEntries,
                cancellationToken);
            long changeSequence = await ReadChangeSequenceAsync(
                connection,
                transaction: null,
                cancellationToken);
            ValidateSnapshot(accounts, secretVersions, historyEntries);
            return new V2VaultSnapshot(
                accounts,
                secretVersions,
                historyEntries,
                changeSequence);
        }
        catch (SafeApplicationException)
        {
            DisposeSecretVersions(secretVersions);
            throw;
        }
        catch (Exception exception) when (
            exception is SqliteException or
                IOException or
                CryptographicException or
                FormatException)
        {
            DisposeSecretVersions(secretVersions);
            throw new SafeApplicationException(
                "VaultV2.ReadFailed",
                "The encrypted v2 vault could not be read or verified.",
                exception);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(rootKey);
        }
    }

    public async Task SaveAsync(
        IReadOnlyCollection<VaultAccountV2> accounts,
        IReadOnlyCollection<SecretVersionV2> secretVersions,
        CancellationToken cancellationToken) =>
        await SaveAsync(accounts, secretVersions, [], cancellationToken);

    public async Task SaveAsync(
        IReadOnlyCollection<VaultAccountV2> accounts,
        IReadOnlyCollection<SecretVersionV2> secretVersions,
        IReadOnlyCollection<AccountHistoryEntryV2> historyEntries,
        CancellationToken cancellationToken) =>
        await SaveCoreAsync(
            accounts,
            secretVersions,
            historyEntries,
            minimumPreviousSequence: 0,
            cancellationToken);

    internal async Task SaveRecoveredAsync(
        IReadOnlyCollection<VaultAccountV2> accounts,
        IReadOnlyCollection<SecretVersionV2> secretVersions,
        IReadOnlyCollection<AccountHistoryEntryV2> historyEntries,
        long sourceChangeSequence,
        CancellationToken cancellationToken)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(sourceChangeSequence);
        await SaveCoreAsync(
            accounts,
            secretVersions,
            historyEntries,
            sourceChangeSequence,
            cancellationToken);
    }

    private async Task SaveCoreAsync(
        IReadOnlyCollection<VaultAccountV2> accounts,
        IReadOnlyCollection<SecretVersionV2> secretVersions,
        IReadOnlyCollection<AccountHistoryEntryV2> historyEntries,
        long minimumPreviousSequence,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(accounts);
        ArgumentNullException.ThrowIfNull(secretVersions);
        ArgumentNullException.ThrowIfNull(historyEntries);
        cancellationToken.ThrowIfCancellationRequested();
        ValidateSnapshot(accounts, secretVersions, historyEntries);

        string directory = Path.GetDirectoryName(DatabasePath) ??
            throw new InvalidOperationException("The v2 database path must include a directory.");
        Directory.CreateDirectory(directory);
        ValidateDatabaseSize();

        byte[] rootKey = await _rootKeyProvider.LoadOrCreateAsync(cancellationToken);
        try
        {
            bool databaseExisted = File.Exists(DatabasePath) &&
                new FileInfo(DatabasePath).Length > 0;
            await using SqliteConnection connection = CreateConnection(SqliteOpenMode.ReadWriteCreate);
            await OpenAndConfigureAsync(connection, writable: true, cancellationToken);
            await EnsureSchemaAsync(connection, databaseExisted, cancellationToken);

            await using SqliteTransaction transaction =
                (SqliteTransaction)await connection.BeginTransactionAsync(
                    IsolationLevel.Serializable,
                    cancellationToken);
            try
            {
                long currentSequence = await ReadChangeSequenceAsync(
                    connection,
                    transaction,
                    cancellationToken);
                long nextSequence = checked(
                    Math.Max(currentSequence, minimumPreviousSequence) + 1);
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

                foreach (SecretVersionV2 version in secretVersions.OrderBy(item => item.Id))
                {
                    await InsertSecretVersionAsync(
                        connection,
                        transaction,
                        rootKey,
                        version,
                        cancellationToken);
                }

                foreach (AccountHistoryEntryV2 entry in historyEntries.OrderBy(item => item.Id))
                {
                    await InsertHistoryEntryAsync(
                        connection,
                        transaction,
                        rootKey,
                        entry,
                        cancellationToken);
                }

                await WriteChangeSequenceAsync(
                    connection,
                    transaction,
                    nextSequence,
                    cancellationToken);
                await transaction.CommitAsync(cancellationToken);
            }
            catch
            {
                await transaction.RollbackAsync(CancellationToken.None);
                throw;
            }
        }
        catch (SafeApplicationException)
        {
            throw;
        }
        catch (Exception exception) when (
            exception is SqliteException or
                IOException or
                CryptographicException or
                UnauthorizedAccessException)
        {
            throw new SafeApplicationException(
                "VaultV2.WriteFailed",
                "The encrypted v2 vault could not be saved.",
                exception);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(rootKey);
        }
    }

    private static async Task LoadAccountsAsync(
        SqliteConnection connection,
        ReadOnlyMemory<byte> rootKey,
        List<VaultAccountV2> accounts,
        CancellationToken cancellationToken)
    {
        await using SqliteCommand command = connection.CreateCommand();
        command.CommandText =
            """
            SELECT account_id, nonce, ciphertext, tag
            FROM account_records
            ORDER BY account_id;
            """;
        await using SqliteDataReader reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            if (accounts.Count >= MaximumAccounts)
            {
                throw InvalidDatabase("The v2 vault contains too many accounts.");
            }

            Guid accountId = ReadGuid(reader, 0, "account");
            byte[] nonce = ReadBlob(reader, 1, V2RecordCryptography.NonceLength, "account nonce");
            byte[] ciphertext = ReadBlob(
                reader,
                2,
                MaximumAccountPayloadBytes,
                "account payload");
            byte[] tag = ReadBlob(reader, 3, V2RecordCryptography.TagLength, "account tag");
            byte[] associatedData = CreateAccountAssociatedData(accountId);
            byte[] plaintext = [];
            try
            {
                plaintext = V2RecordCryptography.Decrypt(
                    nonce,
                    ciphertext,
                    tag,
                    rootKey.Span,
                    associatedData);
                accounts.Add(V2RecordSerializer.DeserializeAccount(plaintext, accountId));
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
    }

    private static async Task LoadSecretVersionsAsync(
        SqliteConnection connection,
        ReadOnlyMemory<byte> rootKey,
        List<SecretVersionV2> versions,
        CancellationToken cancellationToken)
    {
        await using SqliteCommand command = connection.CreateCommand();
        command.CommandText =
            """
            SELECT version_id, account_id,
                   dek_nonce, wrapped_dek, dek_tag,
                   payload_nonce, payload_ciphertext, payload_tag
            FROM secret_version_records
            ORDER BY version_id;
            """;
        await using SqliteDataReader reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            if (versions.Count >= MaximumSecretVersions)
            {
                throw InvalidDatabase("The v2 vault contains too many secret versions.");
            }

            Guid versionId = ReadGuid(reader, 0, "secret version");
            Guid accountId = ReadGuid(reader, 1, "secret-version account");
            byte[] dekNonce = ReadBlob(
                reader,
                2,
                V2RecordCryptography.NonceLength,
                "wrapped-key nonce");
            byte[] wrappedDek = ReadBlob(
                reader,
                3,
                V2RecordCryptography.KeyLength,
                "wrapped key");
            byte[] dekTag = ReadBlob(
                reader,
                4,
                V2RecordCryptography.TagLength,
                "wrapped-key tag");
            byte[] payloadNonce = ReadBlob(
                reader,
                5,
                V2RecordCryptography.NonceLength,
                "secret payload nonce");
            byte[] payloadCiphertext = ReadBlob(
                reader,
                6,
                MaximumSecretPayloadBytes,
                "secret payload");
            byte[] payloadTag = ReadBlob(
                reader,
                7,
                V2RecordCryptography.TagLength,
                "secret payload tag");
            byte[] dekAssociatedData = CreateDekAssociatedData(accountId, versionId);
            byte[] payloadAssociatedData = CreateSecretAssociatedData(accountId, versionId);
            byte[] dek = [];
            byte[] plaintext = [];
            try
            {
                dek = V2RecordCryptography.Decrypt(
                    dekNonce,
                    wrappedDek,
                    dekTag,
                    rootKey.Span,
                    dekAssociatedData);
                plaintext = V2RecordCryptography.Decrypt(
                    payloadNonce,
                    payloadCiphertext,
                    payloadTag,
                    dek,
                    payloadAssociatedData);
                versions.Add(
                    V2RecordSerializer.DeserializeSecretVersion(
                        plaintext,
                        versionId,
                        accountId));
            }
            finally
            {
                CryptographicOperations.ZeroMemory(dekNonce);
                CryptographicOperations.ZeroMemory(wrappedDek);
                CryptographicOperations.ZeroMemory(dekTag);
                CryptographicOperations.ZeroMemory(payloadNonce);
                CryptographicOperations.ZeroMemory(payloadCiphertext);
                CryptographicOperations.ZeroMemory(payloadTag);
                CryptographicOperations.ZeroMemory(dekAssociatedData);
                CryptographicOperations.ZeroMemory(payloadAssociatedData);
                CryptographicOperations.ZeroMemory(dek);
                CryptographicOperations.ZeroMemory(plaintext);
            }
        }
    }

    private static async Task LoadHistoryEntriesAsync(
        SqliteConnection connection,
        ReadOnlyMemory<byte> rootKey,
        List<AccountHistoryEntryV2> entries,
        CancellationToken cancellationToken)
    {
        await using SqliteCommand command = connection.CreateCommand();
        command.CommandText =
            """
            SELECT history_id, account_id, nonce, ciphertext, tag
            FROM account_history_records
            ORDER BY history_id;
            """;
        await using SqliteDataReader reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            if (entries.Count >= MaximumHistoryEntries)
            {
                throw InvalidDatabase("The v2 vault contains too many account-history entries.");
            }

            Guid historyId = ReadGuid(reader, 0, "history");
            Guid accountId = ReadGuid(reader, 1, "history account");
            byte[] nonce = ReadBlob(reader, 2, V2RecordCryptography.NonceLength, "history nonce");
            byte[] ciphertext = ReadBlob(
                reader,
                3,
                MaximumHistoryPayloadBytes,
                "history payload");
            byte[] tag = ReadBlob(reader, 4, V2RecordCryptography.TagLength, "history tag");
            byte[] associatedData = CreateHistoryAssociatedData(accountId, historyId);
            byte[] plaintext = [];
            try
            {
                plaintext = V2RecordCryptography.Decrypt(
                    nonce,
                    ciphertext,
                    tag,
                    rootKey.Span,
                    associatedData);
                entries.Add(
                    V2RecordSerializer.DeserializeHistoryEntry(
                        plaintext,
                        historyId,
                        accountId));
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
    }

    private static async Task InsertAccountAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        ReadOnlyMemory<byte> rootKey,
        VaultAccountV2 account,
        CancellationToken cancellationToken)
    {
        byte[] plaintext = V2RecordSerializer.SerializeAccount(account);
        byte[] associatedData = CreateAccountAssociatedData(account.Id);
        EncryptedPayload? encrypted = null;
        try
        {
            encrypted = V2RecordCryptography.Encrypt(
                plaintext,
                rootKey.Span,
                associatedData);
            await using SqliteCommand command = connection.CreateCommand();
            command.Transaction = transaction;
            command.CommandText =
                """
                INSERT INTO account_records(account_id, nonce, ciphertext, tag)
                VALUES ($accountId, $nonce, $ciphertext, $tag);
                """;
            command.Parameters.AddWithValue("$accountId", account.Id.ToString("D"));
            command.Parameters.Add("$nonce", SqliteType.Blob).Value = encrypted.Nonce;
            command.Parameters.Add("$ciphertext", SqliteType.Blob).Value = encrypted.Ciphertext;
            command.Parameters.Add("$tag", SqliteType.Blob).Value = encrypted.Tag;
            await command.ExecuteNonQueryAsync(cancellationToken);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext);
            CryptographicOperations.ZeroMemory(associatedData);
            ClearEncryptedPayload(encrypted);
        }
    }

    private static async Task InsertSecretVersionAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        ReadOnlyMemory<byte> rootKey,
        SecretVersionV2 version,
        CancellationToken cancellationToken)
    {
        byte[] plaintext = V2RecordSerializer.SerializeSecretVersion(version);
        byte[] dek = RandomNumberGenerator.GetBytes(V2RecordCryptography.KeyLength);
        byte[] dekAssociatedData = CreateDekAssociatedData(version.AccountId, version.Id);
        byte[] payloadAssociatedData = CreateSecretAssociatedData(version.AccountId, version.Id);
        EncryptedPayload? wrappedDek = null;
        EncryptedPayload? encryptedPayload = null;
        try
        {
            wrappedDek = V2RecordCryptography.Encrypt(
                dek,
                rootKey.Span,
                dekAssociatedData);
            encryptedPayload = V2RecordCryptography.Encrypt(
                plaintext,
                dek,
                payloadAssociatedData);

            await using SqliteCommand command = connection.CreateCommand();
            command.Transaction = transaction;
            command.CommandText =
                """
                INSERT INTO secret_version_records(
                    version_id, account_id,
                    dek_nonce, wrapped_dek, dek_tag,
                    payload_nonce, payload_ciphertext, payload_tag)
                VALUES (
                    $versionId, $accountId,
                    $dekNonce, $wrappedDek, $dekTag,
                    $payloadNonce, $payloadCiphertext, $payloadTag);
                """;
            command.Parameters.AddWithValue("$versionId", version.Id.ToString("D"));
            command.Parameters.AddWithValue("$accountId", version.AccountId.ToString("D"));
            command.Parameters.Add("$dekNonce", SqliteType.Blob).Value = wrappedDek.Nonce;
            command.Parameters.Add("$wrappedDek", SqliteType.Blob).Value = wrappedDek.Ciphertext;
            command.Parameters.Add("$dekTag", SqliteType.Blob).Value = wrappedDek.Tag;
            command.Parameters.Add("$payloadNonce", SqliteType.Blob).Value = encryptedPayload.Nonce;
            command.Parameters.Add("$payloadCiphertext", SqliteType.Blob).Value =
                encryptedPayload.Ciphertext;
            command.Parameters.Add("$payloadTag", SqliteType.Blob).Value = encryptedPayload.Tag;
            await command.ExecuteNonQueryAsync(cancellationToken);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext);
            CryptographicOperations.ZeroMemory(dek);
            CryptographicOperations.ZeroMemory(dekAssociatedData);
            CryptographicOperations.ZeroMemory(payloadAssociatedData);
            ClearEncryptedPayload(wrappedDek);
            ClearEncryptedPayload(encryptedPayload);
        }
    }

    private static async Task InsertHistoryEntryAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        ReadOnlyMemory<byte> rootKey,
        AccountHistoryEntryV2 entry,
        CancellationToken cancellationToken)
    {
        byte[] plaintext = V2RecordSerializer.SerializeHistoryEntry(entry);
        byte[] associatedData = CreateHistoryAssociatedData(entry.AccountId, entry.Id);
        EncryptedPayload? encrypted = null;
        try
        {
            encrypted = V2RecordCryptography.Encrypt(
                plaintext,
                rootKey.Span,
                associatedData);
            await using SqliteCommand command = connection.CreateCommand();
            command.Transaction = transaction;
            command.CommandText =
                """
                INSERT INTO account_history_records(
                    history_id, account_id, nonce, ciphertext, tag)
                VALUES ($historyId, $accountId, $nonce, $ciphertext, $tag);
                """;
            command.Parameters.AddWithValue("$historyId", entry.Id.ToString("D"));
            command.Parameters.AddWithValue("$accountId", entry.AccountId.ToString("D"));
            command.Parameters.Add("$nonce", SqliteType.Blob).Value = encrypted.Nonce;
            command.Parameters.Add("$ciphertext", SqliteType.Blob).Value =
                encrypted.Ciphertext;
            command.Parameters.Add("$tag", SqliteType.Blob).Value = encrypted.Tag;
            await command.ExecuteNonQueryAsync(cancellationToken);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext);
            CryptographicOperations.ZeroMemory(associatedData);
            ClearEncryptedPayload(encrypted);
        }
    }

    internal static void ValidateSnapshot(
        IReadOnlyCollection<VaultAccountV2> accounts,
        IReadOnlyCollection<SecretVersionV2> secretVersions,
        IReadOnlyCollection<AccountHistoryEntryV2> historyEntries)
    {
        if (accounts.Count > MaximumAccounts)
        {
            throw new SafeApplicationException(
                "VaultV2.TooManyAccounts",
                "The v2 vault contains too many accounts.");
        }

        if (secretVersions.Count > MaximumSecretVersions)
        {
            throw new SafeApplicationException(
                "VaultV2.TooManySecretVersions",
                "The v2 vault contains too many secret versions.");
        }

        if (historyEntries.Count > MaximumHistoryEntries)
        {
            throw new SafeApplicationException(
                "VaultV2.TooManyHistoryEntries",
                "The v2 vault contains too many account-history entries.");
        }

        Dictionary<Guid, VaultAccountV2> accountsById;
        Dictionary<Guid, SecretVersionV2> versionsById;
        try
        {
            accountsById = accounts.ToDictionary(account => account.Id);
            versionsById = secretVersions.ToDictionary(version => version.Id);
        }
        catch (ArgumentException exception)
        {
            throw new SafeApplicationException(
                "VaultV2.DuplicateIdentifier",
                "The v2 vault contains duplicate identifiers.",
                exception);
        }

        var activeVersionCounts = new Dictionary<Guid, int>();
        foreach (SecretVersionV2 version in secretVersions)
        {
            if (!accountsById.ContainsKey(version.AccountId))
            {
                throw InvalidDatabase(
                    "A v2 secret version refers to an account that does not exist.");
            }

            if (version.State == SecretVersionState.Active)
            {
                activeVersionCounts.TryGetValue(version.AccountId, out int count);
                activeVersionCounts[version.AccountId] = count + 1;
            }
        }

        foreach (VaultAccountV2 account in accounts)
        {
            if (!versionsById.TryGetValue(
                    account.ActiveSecretVersionId,
                    out SecretVersionV2? activeVersion) ||
                activeVersion.AccountId != account.Id ||
                activeVersion.State != SecretVersionState.Active)
            {
                throw InvalidDatabase(
                    "A v2 account does not refer to a valid active secret version.");
            }

            if (!activeVersionCounts.TryGetValue(account.Id, out int activeCount) ||
                activeCount != 1)
            {
                throw InvalidDatabase(
                    "A v2 account must contain exactly one active secret version.");
            }
        }

        HashSet<Guid> historyIds = [];
        foreach (AccountHistoryEntryV2 entry in historyEntries)
        {
            if (!historyIds.Add(entry.Id))
            {
                throw new SafeApplicationException(
                    "VaultV2.DuplicateIdentifier",
                    "The v2 vault contains duplicate history identifiers.");
            }

            if (!accountsById.ContainsKey(entry.AccountId))
            {
                throw InvalidDatabase(
                    "A v2 account-history entry refers to an account that does not exist.");
            }

            if (entry.RelatedAccountId is Guid relatedAccountId &&
                !accountsById.ContainsKey(relatedAccountId))
            {
                throw InvalidDatabase(
                    "A v2 account-history entry refers to a related account that does not exist.");
            }

            if (entry.SecretVersionId is Guid versionId &&
                !versionsById.ContainsKey(versionId))
            {
                throw InvalidDatabase(
                    "A v2 account-history entry refers to a secret version that does not exist.");
            }

            if (entry.PreviousSecretVersionId is Guid previousVersionId &&
                !versionsById.ContainsKey(previousVersionId))
            {
                throw InvalidDatabase(
                    "A v2 account-history entry refers to a previous secret version that does not exist.");
            }
        }
    }

    private static async Task<long> ReadChangeSequenceAsync(
        SqliteConnection connection,
        SqliteTransaction? transaction,
        CancellationToken cancellationToken)
    {
        await using SqliteCommand command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText =
            """
            SELECT change_sequence
            FROM vault_metadata
            WHERE singleton_id = 1;
            """;
        object? result = await command.ExecuteScalarAsync(cancellationToken);
        if (result is not long sequence || sequence < 0)
        {
            throw InvalidDatabase("The v2 vault change sequence is invalid.");
        }

        return sequence;
    }

    private static async Task WriteChangeSequenceAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        long sequence,
        CancellationToken cancellationToken)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(sequence);
        await using SqliteCommand command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText =
            """
            UPDATE vault_metadata
            SET change_sequence = $sequence
            WHERE singleton_id = 1;
            """;
        command.Parameters.AddWithValue("$sequence", sequence);
        int rowsChanged = await command.ExecuteNonQueryAsync(cancellationToken);
        if (rowsChanged != 1)
        {
            throw InvalidDatabase("The v2 vault change sequence could not be updated.");
        }
    }

    private static async Task EnsureSchemaAsync(
        SqliteConnection connection,
        bool databaseExisted,
        CancellationToken cancellationToken)
    {
        long applicationId = await ExecuteScalarInt64Async(
            connection,
            "PRAGMA application_id;",
            cancellationToken);
        long schemaVersion = await ExecuteScalarInt64Async(
            connection,
            "PRAGMA user_version;",
            cancellationToken);

        if (databaseExisted &&
            (applicationId != ApplicationId ||
             schemaVersion is < 1 or > SchemaVersion))
        {
            throw InvalidDatabase("The selected database is not a supported v2 vault.");
        }

        if (applicationId == 0 && schemaVersion == 0)
        {
            await using SqliteTransaction transaction =
                (SqliteTransaction)await connection.BeginTransactionAsync(
                    IsolationLevel.Serializable,
                    cancellationToken);
            try
            {
                await ExecuteAsync(
                    connection,
                    transaction,
                    $"""
                    PRAGMA application_id = {ApplicationId.ToString(CultureInfo.InvariantCulture)};
                    PRAGMA user_version = {SchemaVersion.ToString(CultureInfo.InvariantCulture)};
                    CREATE TABLE account_records (
                        account_id TEXT PRIMARY KEY NOT NULL
                            CHECK(length(account_id) = 36),
                        nonce BLOB NOT NULL CHECK(length(nonce) = 12),
                        ciphertext BLOB NOT NULL
                            CHECK(length(ciphertext) BETWEEN 1 AND {MaximumAccountPayloadBytes}),
                        tag BLOB NOT NULL CHECK(length(tag) = 16)
                    ) STRICT;
                    CREATE TABLE secret_version_records (
                        version_id TEXT PRIMARY KEY NOT NULL
                            CHECK(length(version_id) = 36),
                        account_id TEXT NOT NULL
                            CHECK(length(account_id) = 36),
                        dek_nonce BLOB NOT NULL CHECK(length(dek_nonce) = 12),
                        wrapped_dek BLOB NOT NULL CHECK(length(wrapped_dek) = 32),
                        dek_tag BLOB NOT NULL CHECK(length(dek_tag) = 16),
                        payload_nonce BLOB NOT NULL CHECK(length(payload_nonce) = 12),
                        payload_ciphertext BLOB NOT NULL
                            CHECK(length(payload_ciphertext) BETWEEN 1 AND {MaximumSecretPayloadBytes}),
                        payload_tag BLOB NOT NULL CHECK(length(payload_tag) = 16),
                        FOREIGN KEY(account_id) REFERENCES account_records(account_id)
                            ON DELETE CASCADE
                    ) STRICT;
                    CREATE INDEX secret_version_account_idx
                        ON secret_version_records(account_id);
                    CREATE TABLE account_history_records (
                        history_id TEXT PRIMARY KEY NOT NULL
                            CHECK(length(history_id) = 36),
                        account_id TEXT NOT NULL
                            CHECK(length(account_id) = 36),
                        nonce BLOB NOT NULL CHECK(length(nonce) = 12),
                        ciphertext BLOB NOT NULL
                            CHECK(length(ciphertext) BETWEEN 1 AND {MaximumHistoryPayloadBytes}),
                        tag BLOB NOT NULL CHECK(length(tag) = 16),
                        FOREIGN KEY(account_id) REFERENCES account_records(account_id)
                            ON DELETE CASCADE
                    ) STRICT;
                CREATE INDEX account_history_account_idx
                    ON account_history_records(account_id);
                CREATE TABLE vault_metadata (
                    singleton_id INTEGER PRIMARY KEY NOT NULL
                        CHECK(singleton_id = 1),
                    change_sequence INTEGER NOT NULL
                        CHECK(change_sequence >= 0)
                ) STRICT;
                INSERT INTO vault_metadata(singleton_id, change_sequence)
                    VALUES (1, 0);
                """,
                cancellationToken);
                await transaction.CommitAsync(cancellationToken);
            }
            catch
            {
                await transaction.RollbackAsync(CancellationToken.None);
                throw;
            }

            return;
        }

        if (applicationId == ApplicationId && schemaVersion == 1)
        {
            await using SqliteTransaction transaction =
                (SqliteTransaction)await connection.BeginTransactionAsync(
                    IsolationLevel.Serializable,
                    cancellationToken);
            try
            {
                await ExecuteAsync(
                    connection,
                    transaction,
                    $"""
                    CREATE TABLE account_history_records (
                        history_id TEXT PRIMARY KEY NOT NULL
                            CHECK(length(history_id) = 36),
                        account_id TEXT NOT NULL
                            CHECK(length(account_id) = 36),
                        nonce BLOB NOT NULL CHECK(length(nonce) = 12),
                        ciphertext BLOB NOT NULL
                            CHECK(length(ciphertext) BETWEEN 1 AND {MaximumHistoryPayloadBytes}),
                        tag BLOB NOT NULL CHECK(length(tag) = 16),
                        FOREIGN KEY(account_id) REFERENCES account_records(account_id)
                            ON DELETE CASCADE
                    ) STRICT;
                CREATE INDEX account_history_account_idx
                    ON account_history_records(account_id);
                CREATE TABLE vault_metadata (
                    singleton_id INTEGER PRIMARY KEY NOT NULL
                        CHECK(singleton_id = 1),
                    change_sequence INTEGER NOT NULL
                        CHECK(change_sequence >= 0)
                ) STRICT;
                INSERT INTO vault_metadata(singleton_id, change_sequence)
                    VALUES (1, 0);
                PRAGMA user_version = {SchemaVersion.ToString(CultureInfo.InvariantCulture)};
                """,
                cancellationToken);
                await transaction.CommitAsync(cancellationToken);
            }
            catch
            {
                await transaction.RollbackAsync(CancellationToken.None);
                throw;
            }

            return;
        }

        if (applicationId == ApplicationId && schemaVersion == 2)
        {
            await using SqliteTransaction transaction =
                (SqliteTransaction)await connection.BeginTransactionAsync(
                    IsolationLevel.Serializable,
                    cancellationToken);
            try
            {
                await ExecuteAsync(
                    connection,
                    transaction,
                    $"""
                    CREATE TABLE vault_metadata (
                        singleton_id INTEGER PRIMARY KEY NOT NULL
                            CHECK(singleton_id = 1),
                        change_sequence INTEGER NOT NULL
                            CHECK(change_sequence >= 0)
                    ) STRICT;
                    INSERT INTO vault_metadata(singleton_id, change_sequence)
                        VALUES (1, 0);
                    PRAGMA user_version = {SchemaVersion.ToString(CultureInfo.InvariantCulture)};
                    """,
                    cancellationToken);
                await transaction.CommitAsync(cancellationToken);
            }
            catch
            {
                await transaction.RollbackAsync(CancellationToken.None);
                throw;
            }

            return;
        }

        if (applicationId != ApplicationId || schemaVersion != SchemaVersion)
        {
            throw InvalidDatabase("The selected database is not a supported v2 vault.");
        }
    }

    private static async Task VerifySchemaAndIntegrityAsync(
        SqliteConnection connection,
        CancellationToken cancellationToken)
    {
        long applicationId = await ExecuteScalarInt64Async(
            connection,
            "PRAGMA application_id;",
            cancellationToken);
        long schemaVersion = await ExecuteScalarInt64Async(
            connection,
            "PRAGMA user_version;",
            cancellationToken);
        if (applicationId != ApplicationId || schemaVersion != SchemaVersion)
        {
            throw InvalidDatabase("The selected database is not a supported v2 vault.");
        }

        await using SqliteCommand command = connection.CreateCommand();
        command.CommandText = "PRAGMA integrity_check;";
        object? result = await command.ExecuteScalarAsync(cancellationToken);
        if (!string.Equals(result as string, "ok", StringComparison.Ordinal))
        {
            throw InvalidDatabase("The v2 vault database failed its integrity check.");
        }
    }

    private static async Task OpenAndConfigureAsync(
        SqliteConnection connection,
        bool writable,
        CancellationToken cancellationToken)
    {
        await connection.OpenAsync(cancellationToken);
        await ExecuteAsync(
            connection,
            transaction: null,
            writable
                ? """
                  PRAGMA foreign_keys = ON;
                  PRAGMA journal_mode = DELETE;
                  PRAGMA synchronous = FULL;
                  PRAGMA secure_delete = ON;
                  PRAGMA busy_timeout = 5000;
                  """
                : """
                  PRAGMA foreign_keys = ON;
                  PRAGMA query_only = ON;
                  PRAGMA busy_timeout = 5000;
                  """,
            cancellationToken);
    }

    private SqliteConnection CreateConnection(SqliteOpenMode mode)
    {
        var builder = new SqliteConnectionStringBuilder
        {
            DataSource = DatabasePath,
            Mode = mode,
            Cache = SqliteCacheMode.Private,
            Pooling = false,
        };
        return new SqliteConnection(builder.ToString());
    }

    private void ValidateDatabaseSize()
    {
        if (File.Exists(DatabasePath) && new FileInfo(DatabasePath).Length > MaximumDatabaseBytes)
        {
            throw new SafeApplicationException(
                "VaultV2.DatabaseTooLarge",
                "The v2 vault database is too large to open safely.");
        }
    }

    private static async Task ExecuteAsync(
        SqliteConnection connection,
        SqliteTransaction? transaction,
        string commandText,
        CancellationToken cancellationToken)
    {
        await using SqliteCommand command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = commandText;
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    private static async Task<long> ExecuteScalarInt64Async(
        SqliteConnection connection,
        string commandText,
        CancellationToken cancellationToken)
    {
        await using SqliteCommand command = connection.CreateCommand();
        command.CommandText = commandText;
        object? result = await command.ExecuteScalarAsync(cancellationToken);
        return Convert.ToInt64(result, CultureInfo.InvariantCulture);
    }

    private static Guid ReadGuid(SqliteDataReader reader, int ordinal, string fieldName)
    {
        string value = reader.GetString(ordinal);
        if (value.Length != 36 || !Guid.TryParseExact(value, "D", out Guid parsed))
        {
            throw InvalidDatabase($"The v2 {fieldName} identifier is invalid.");
        }

        return parsed;
    }

    private static byte[] ReadBlob(
        SqliteDataReader reader,
        int ordinal,
        int maximumLength,
        string fieldName)
    {
        long length = reader.GetBytes(ordinal, 0, null, 0, 0);
        int minimumLength = maximumLength is V2RecordCryptography.NonceLength or
            V2RecordCryptography.TagLength or
            V2RecordCryptography.KeyLength
            ? maximumLength
            : 1;
        if (length < minimumLength || length > maximumLength)
        {
            throw InvalidDatabase($"The v2 {fieldName} length is invalid.");
        }

        byte[] value = GC.AllocateUninitializedArray<byte>((int)length);
        long bytesRead = reader.GetBytes(ordinal, 0, value, 0, value.Length);
        if (bytesRead != length)
        {
            CryptographicOperations.ZeroMemory(value);
            throw InvalidDatabase($"The v2 {fieldName} is truncated.");
        }

        return value;
    }

    private static byte[] CreateAccountAssociatedData(Guid accountId) =>
        Encoding.UTF8.GetBytes($"PAV2/account/{accountId:D}/1");

    private static byte[] CreateSecretAssociatedData(Guid accountId, Guid versionId) =>
        Encoding.UTF8.GetBytes($"PAV2/secret/{accountId:D}/{versionId:D}/1");

    private static byte[] CreateDekAssociatedData(Guid accountId, Guid versionId) =>
        Encoding.UTF8.GetBytes($"PAV2/dek/{accountId:D}/{versionId:D}/1");

    private static byte[] CreateHistoryAssociatedData(Guid accountId, Guid historyId) =>
        Encoding.UTF8.GetBytes($"PAV2/history/{accountId:D}/{historyId:D}/1");

    private static SafeApplicationException InvalidDatabase(string message) =>
        new("VaultV2.InvalidDatabase", message);

    private static void ClearEncryptedPayload(EncryptedPayload? payload)
    {
        if (payload is null)
        {
            return;
        }

        CryptographicOperations.ZeroMemory(payload.Nonce);
        CryptographicOperations.ZeroMemory(payload.Ciphertext);
        CryptographicOperations.ZeroMemory(payload.Tag);
    }

    private static void DisposeSecretVersions(IEnumerable<SecretVersionV2> versions)
    {
        foreach (SecretVersionV2 version in versions)
        {
            version.Dispose();
        }
    }
}
