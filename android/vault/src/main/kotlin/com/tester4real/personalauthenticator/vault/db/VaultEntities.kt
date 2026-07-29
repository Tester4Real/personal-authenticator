package com.tester4real.personalauthenticator.vault.db

import androidx.room.ColumnInfo
import androidx.room.Entity
import androidx.room.Index

@Entity(tableName = "accounts")
data class AccountEntity(
    @androidx.room.PrimaryKey val id: String,
    @ColumnInfo(typeAffinity = ColumnInfo.BLOB)
    val issuerCiphertext: ByteArray,
    @ColumnInfo(typeAffinity = ColumnInfo.BLOB)
    val accountNameCiphertext: ByteArray,
    val activeSecretVersionId: String,
    val favourite: Boolean,
    val sortOrder: Int,
    val createdAtUtcTicks: Long,
    val updatedAtUtcTicks: Long,
    val archivedAtUtcTicks: Long?,
)

@Entity(
    tableName = "secret_versions",
    indices = [Index("accountId")],
)
data class SecretVersionEntity(
    @androidx.room.PrimaryKey val id: String,
    val accountId: String,
    @ColumnInfo(typeAffinity = ColumnInfo.BLOB)
    val encryptedRecord: ByteArray,
    val algorithm: Int,
    val digits: Int,
    val periodSeconds: Int,
    val state: Int,
    val createdAtUtcTicks: Long,
    val retiredAtUtcTicks: Long?,
)

@Entity(
    tableName = "account_history",
    indices = [Index("accountId"), Index("occurredAtUtcTicks")],
)
data class AccountHistoryEntity(
    @androidx.room.PrimaryKey val id: String,
    val accountId: String,
    val action: Int,
    val occurredAtUtcTicks: Long,
    @ColumnInfo(typeAffinity = ColumnInfo.BLOB)
    val encryptedRecord: ByteArray,
)

@Entity(
    tableName = "sync_operations",
    indices = [
        Index(value = ["deviceId", "deviceSequence"], unique = true),
        Index(value = ["logicalClock", "deviceId", "deviceSequence"]),
        Index("accountId"),
    ],
)
data class SyncOperationEntity(
    @androidx.room.PrimaryKey val id: String,
    val deviceId: String,
    val deviceSequence: Long,
    val logicalClock: Long,
    val occurredAtUtcTicks: Long,
    val accountId: String,
    val kind: Int,
    val fieldKey: String,
    @ColumnInfo(typeAffinity = ColumnInfo.BLOB)
    val originalSerializedBytes: ByteArray,
    @ColumnInfo(typeAffinity = ColumnInfo.BLOB)
    val originalBytesSha256: ByteArray,
    @ColumnInfo(typeAffinity = ColumnInfo.BLOB)
    val semanticHash: ByteArray,
)

@Entity(
    tableName = "causal_parents",
    primaryKeys = ["operationId", "parentOperationId"],
    indices = [Index("parentOperationId")],
)
data class CausalParentEntity(
    val operationId: String,
    val parentOperationId: String,
)

@Entity(
    tableName = "applied_identities",
    indices = [
        Index(value = ["deviceId", "deviceSequence"], unique = true),
    ],
)
data class AppliedIdentityEntity(
    @androidx.room.PrimaryKey val operationId: String,
    val deviceId: String,
    val deviceSequence: Long,
    @ColumnInfo(typeAffinity = ColumnInfo.BLOB)
    val originalBytesSha256: ByteArray,
)

@Entity(
    tableName = "field_heads",
    primaryKeys = ["accountId", "fieldKey", "operationId"],
    indices = [Index("operationId")],
)
data class FieldHeadEntity(
    val accountId: String,
    val fieldKey: String,
    val operationId: String,
    @ColumnInfo(typeAffinity = ColumnInfo.BLOB)
    val semanticHash: ByteArray,
)

@Entity(
    tableName = "aliases",
    primaryKeys = ["aliasKind", "sourceId"],
    indices = [Index("targetId")],
)
data class AliasEntity(
    val aliasKind: Int,
    val sourceId: String,
    val targetId: String,
)

@Entity(
    tableName = "unresolved_conflicts",
    indices = [Index("accountId"), Index("resolved")],
)
data class ConflictEntity(
    @androidx.room.PrimaryKey val id: String,
    val accountId: String,
    val kind: Int,
    val fieldKey: String,
    val operationAId: String,
    val operationBId: String,
    val secretVersionAId: String?,
    val secretVersionBId: String?,
    val detectedAtUtcTicks: Long,
    val resolved: Boolean,
)

@Entity(
    tableName = "outbox",
    indices = [Index("nextAttemptAtUtcTicks")],
)
data class OutboxEntity(
    @androidx.room.PrimaryKey val operationId: String,
    @ColumnInfo(typeAffinity = ColumnInfo.BLOB)
    val preparedEnvelope: ByteArray?,
    val attemptCount: Int,
    val nextAttemptAtUtcTicks: Long?,
)

@Entity(
    tableName = "remote_ciphertext_staging",
    indices = [Index("receivedAtUtcTicks")],
)
data class RemoteCiphertextStagingEntity(
    @androidx.room.PrimaryKey val objectId: String,
    val repositoryPath: String,
    @ColumnInfo(typeAffinity = ColumnInfo.BLOB)
    val encryptedBytes: ByteArray,
    @ColumnInfo(typeAffinity = ColumnInfo.BLOB)
    val sha256: ByteArray,
    val receivedAtUtcTicks: Long,
)

@Entity(tableName = "device_clocks")
data class DeviceClockEntity(
    @androidx.room.PrimaryKey val deviceId: String,
    val nextDeviceSequence: Long,
    val lamportClock: Long,
)

@Entity(tableName = "sync_health")
data class SyncHealthEntity(
    @androidx.room.PrimaryKey val singletonId: Int = 1,
    val status: Int,
    val pendingCount: Int,
    val lastSuccessfulSyncAtUtcTicks: Long?,
    val repositoryId: Long?,
    val vaultId: String?,
    val remoteGenerationId: String?,
    val knownBranchHead: String?,
    val readOnlyReason: String?,
    val lastErrorCode: String?,
)

@Entity(
    tableName = "known_git_objects",
    indices = [Index("gitBlobSha")],
)
data class KnownGitObjectEntity(
    @androidx.room.PrimaryKey val objectId: String,
    val gitBlobSha: String,
    @ColumnInfo(typeAffinity = ColumnInfo.BLOB)
    val encryptedBytesSha256: ByteArray,
)
