package com.tester4real.personalauthenticator.vault.db

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import androidx.room.Transaction

@Dao
abstract class VaultDao {
    @Query("SELECT * FROM accounts ORDER BY favourite DESC, sortOrder, id")
    abstract suspend fun loadAccounts(): List<AccountEntity>

    @Query("SELECT * FROM secret_versions WHERE accountId = :accountId")
    abstract suspend fun loadSecretVersions(
        accountId: String,
    ): List<SecretVersionEntity>

    @Query(
        "SELECT * FROM unresolved_conflicts " +
            "WHERE accountId = :accountId AND resolved = 0",
    )
    abstract suspend fun loadUnresolvedConflicts(
        accountId: String,
    ): List<ConflictEntity>

    @Query("SELECT COUNT(*) FROM outbox")
    abstract suspend fun outboxCount(): Int

    @Insert(onConflict = OnConflictStrategy.ABORT)
    protected abstract suspend fun insertAccount(account: AccountEntity)

    @Insert(onConflict = OnConflictStrategy.ABORT)
    protected abstract suspend fun insertSecret(secret: SecretVersionEntity)

    @Insert(onConflict = OnConflictStrategy.ABORT)
    protected abstract suspend fun insertOperation(
        operation: SyncOperationEntity,
    )

    @Insert(onConflict = OnConflictStrategy.ABORT)
    protected abstract suspend fun insertParents(
        parents: List<CausalParentEntity>,
    )

    @Insert(onConflict = OnConflictStrategy.ABORT)
    protected abstract suspend fun insertAppliedIdentity(
        identity: AppliedIdentityEntity,
    )

    @Insert(onConflict = OnConflictStrategy.ABORT)
    protected abstract suspend fun insertOutbox(outbox: OutboxEntity)

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    protected abstract suspend fun upsertClock(clock: DeviceClockEntity)

    @Transaction
    open suspend fun commitAccountAdded(
        account: AccountEntity,
        secret: SecretVersionEntity,
        operation: SyncOperationEntity,
        parents: List<CausalParentEntity>,
        identity: AppliedIdentityEntity,
        outbox: OutboxEntity,
        nextClock: DeviceClockEntity,
    ) {
        insertAccount(account)
        insertSecret(secret)
        insertOperation(operation)
        if (parents.isNotEmpty()) {
            insertParents(parents)
        }
        insertAppliedIdentity(identity)
        insertOutbox(outbox)
        upsertClock(nextClock)
    }

    @Query(
        "UPDATE accounts SET archivedAtUtcTicks = :archivedAtUtcTicks, " +
            "updatedAtUtcTicks = :updatedAtUtcTicks WHERE id = :accountId",
    )
    protected abstract suspend fun updateArchiveState(
        accountId: String,
        archivedAtUtcTicks: Long?,
        updatedAtUtcTicks: Long,
    ): Int

    @Transaction
    open suspend fun commitArchiveChanged(
        accountId: String,
        archivedAtUtcTicks: Long?,
        updatedAtUtcTicks: Long,
        operation: SyncOperationEntity,
        parents: List<CausalParentEntity>,
        identity: AppliedIdentityEntity,
        outbox: OutboxEntity,
        nextClock: DeviceClockEntity,
    ) {
        check(
            updateArchiveState(
                accountId,
                archivedAtUtcTicks,
                updatedAtUtcTicks,
            ) == 1,
        ) { "The account does not exist." }
        insertOperation(operation)
        if (parents.isNotEmpty()) {
            insertParents(parents)
        }
        insertAppliedIdentity(identity)
        insertOutbox(outbox)
        upsertClock(nextClock)
    }
}
