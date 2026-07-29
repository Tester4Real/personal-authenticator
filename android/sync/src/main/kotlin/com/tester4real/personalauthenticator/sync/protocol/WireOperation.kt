package com.tester4real.personalauthenticator.sync.protocol

import java.util.UUID

enum class SyncOperationKind {
    ACCOUNT_ADDED,
    ISSUER_CHANGED,
    ACCOUNT_NAME_CHANGED,
    FAVOURITE_CHANGED,
    SORT_ORDER_CHANGED,
    ARCHIVE_CHANGED,
    SECRET_ADDED,
    ACTIVE_SECRET_CHANGED,
    HISTORY_ADDED,
    DUPLICATE_DECISION,
    PURGED,
    CONFLICT_RESOLVED,
}

data class WireOperationPayload(
    val flags: Int,
    val textValue: String? = null,
    val boolValue: Boolean? = null,
    val intValue: Int? = null,
    val dateUtcTicks: Long? = null,
    val guidValue: UUID? = null,
    val secondaryGuidValue: UUID? = null,
    val accountJson: ByteArray? = null,
    val secretVersionJson: ByteArray? = null,
    val historyJson: ByteArray? = null,
    val conflictId: UUID? = null,
    val conflictResolution: Int? = null,
)

data class WireOperation(
    val id: UUID,
    val deviceId: UUID,
    val deviceSequence: Long,
    val logicalClock: Long,
    val occurredAtUtcTicks: Long,
    val accountId: UUID?,
    val kind: SyncOperationKind,
    val fieldKey: String,
    val causalParents: List<UUID>,
    val payload: WireOperationPayload,
    val originalSerializedBytes: ByteArray? = null,
)
