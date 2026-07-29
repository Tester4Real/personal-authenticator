package com.tester4real.personalauthenticator.sync.protocol

import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets
import java.util.UUID

object SyncOperationCodec {
    const val MAXIMUM_OPERATION_BYTES = 128 * 1_024
    private const val FORMAT_VERSION = 1
    private const val MAXIMUM_PARENTS = 64
    private const val MAXIMUM_TEXT_BYTES = 16 * 1_024
    private const val MAXIMUM_ACCOUNT_BYTES = 16 * 1_024
    private const val MAXIMUM_SECRET_BYTES = 32 * 1_024
    private const val MAXIMUM_HISTORY_BYTES = 8 * 1_024
    private const val KNOWN_PAYLOAD_FLAGS = 0x7ff

    fun decode(serialized: ByteArray): WireOperation {
        if (serialized.size !in 64..MAXIMUM_OPERATION_BYTES) {
            invalid()
        }
        try {
            val reader = Reader(serialized)
            if (reader.readInt() != FORMAT_VERSION) {
                unsupported()
            }
            val id = reader.readGuid()
            val deviceId = reader.readGuid()
            val deviceSequence = reader.readLong()
            val logicalClock = reader.readLong()
            val occurredAtUtcTicks = reader.readLong()
            val accountId = if (reader.readBoolean()) reader.readGuid() else null
            val kindValue = reader.readInt()
            val kind = SyncOperationKind.entries.getOrNull(kindValue)
                ?: unsupported()
            val fieldKey = reader.readString(MAXIMUM_TEXT_BYTES)
            val parentCount = reader.readInt()
            if (parentCount !in 0..MAXIMUM_PARENTS) {
                invalid()
            }
            val parents = List(parentCount) { reader.readGuid() }
            val flags = reader.readInt()
            if (flags and KNOWN_PAYLOAD_FLAGS.inv() != 0) {
                unsupported()
            }
            val payload = WireOperationPayload(
                flags = flags,
                textValue = reader.ifFlag(flags, 0) {
                    readString(MAXIMUM_TEXT_BYTES)
                },
                boolValue = reader.ifFlag(flags, 1) { readBoolean() },
                intValue = reader.ifFlag(flags, 2) { readInt() },
                dateUtcTicks = reader.ifFlag(flags, 3) { readLong() },
                guidValue = reader.ifFlag(flags, 4) { readGuid() },
                secondaryGuidValue = reader.ifFlag(flags, 5) { readGuid() },
                accountJson = reader.ifFlag(flags, 6) {
                    readBlob(MAXIMUM_ACCOUNT_BYTES)
                },
                secretVersionJson = reader.ifFlag(flags, 7) {
                    readBlob(MAXIMUM_SECRET_BYTES)
                },
                historyJson = reader.ifFlag(flags, 8) {
                    readBlob(MAXIMUM_HISTORY_BYTES)
                },
                conflictId = reader.ifFlag(flags, 9) { readGuid() },
                conflictResolution = reader.ifFlag(flags, 10) { readInt() },
            )
            if (reader.remaining != 0) {
                invalid()
            }
            val operation = WireOperation(
                id,
                deviceId,
                deviceSequence,
                logicalClock,
                occurredAtUtcTicks,
                accountId,
                kind,
                fieldKey,
                parents,
                payload,
                serialized.copyOf(),
            )
            validate(operation)
            return operation
        } catch (exception: ProtocolException) {
            throw exception
        } catch (exception: Exception) {
            throw ProtocolException(
                "Sync.InvalidOperation",
                "The sync operation is malformed or truncated.",
                exception,
            )
        }
    }

    fun encode(operation: WireOperation): ByteArray {
        validate(operation)
        val writer = Writer()
        writer.writeInt(FORMAT_VERSION)
        writer.writeGuid(operation.id)
        writer.writeGuid(operation.deviceId)
        writer.writeLong(operation.deviceSequence)
        writer.writeLong(operation.logicalClock)
        writer.writeLong(operation.occurredAtUtcTicks)
        writer.writeBoolean(operation.accountId != null)
        operation.accountId?.let(writer::writeGuid)
        writer.writeInt(operation.kind.ordinal)
        writer.writeString(operation.fieldKey)
        val parents = operation.causalParents.sortedWith(DotNetGuid.comparator)
        writer.writeInt(parents.size)
        parents.forEach(writer::writeGuid)
        val payload = operation.payload
        writer.writeInt(payload.flags)
        writer.ifFlag(payload.flags, 0) { writeString(payload.textValue!!) }
        writer.ifFlag(payload.flags, 1) { writeBoolean(payload.boolValue!!) }
        writer.ifFlag(payload.flags, 2) { writeInt(payload.intValue!!) }
        writer.ifFlag(payload.flags, 3) { writeLong(payload.dateUtcTicks!!) }
        writer.ifFlag(payload.flags, 4) { writeGuid(payload.guidValue!!) }
        writer.ifFlag(payload.flags, 5) {
            writeGuid(payload.secondaryGuidValue!!)
        }
        writer.ifFlag(payload.flags, 6) { writeBlob(payload.accountJson!!) }
        writer.ifFlag(payload.flags, 7) {
            writeBlob(payload.secretVersionJson!!)
        }
        writer.ifFlag(payload.flags, 8) { writeBlob(payload.historyJson!!) }
        writer.ifFlag(payload.flags, 9) { writeGuid(payload.conflictId!!) }
        writer.ifFlag(payload.flags, 10) {
            writeInt(payload.conflictResolution!!)
        }
        return writer.toByteArray().also {
            if (it.size > MAXIMUM_OPERATION_BYTES) {
                it.fill(0)
                invalid()
            }
        }
    }

    private fun validate(operation: WireOperation) {
        if (operation.id == EMPTY_GUID ||
            operation.deviceId == EMPTY_GUID ||
            operation.deviceSequence <= 0 ||
            operation.logicalClock <= 0 ||
            operation.occurredAtUtcTicks <= 0 ||
            operation.accountId == null ||
            operation.accountId == EMPTY_GUID ||
            operation.fieldKey.isEmpty() ||
            operation.fieldKey.length > 64 ||
            operation.causalParents.size > MAXIMUM_PARENTS ||
            operation.causalParents.any { it == EMPTY_GUID || it == operation.id } ||
            operation.causalParents.distinct().size !=
            operation.causalParents.size ||
            operation.payload.flags and KNOWN_PAYLOAD_FLAGS.inv() != 0
        ) {
            invalid()
        }
        val payload = operation.payload
        requireFlag(payload.flags, 0, payload.textValue)
        requireFlag(payload.flags, 1, payload.boolValue)
        requireFlag(payload.flags, 2, payload.intValue)
        requireFlag(payload.flags, 3, payload.dateUtcTicks)
        requireFlag(payload.flags, 4, payload.guidValue)
        requireFlag(payload.flags, 5, payload.secondaryGuidValue)
        requireFlag(payload.flags, 6, payload.accountJson)
        requireFlag(payload.flags, 7, payload.secretVersionJson)
        requireFlag(payload.flags, 8, payload.historyJson)
        requireFlag(payload.flags, 9, payload.conflictId)
        requireFlag(payload.flags, 10, payload.conflictResolution)
    }

    private fun requireFlag(flags: Int, bit: Int, value: Any?) {
        if (((flags and (1 shl bit)) != 0) != (value != null)) {
            invalid()
        }
    }

    private class Reader(private val bytes: ByteArray) {
        private var position = 0
        val remaining: Int get() = bytes.size - position

        fun readInt(): Int = take(4).order(ByteOrder.LITTLE_ENDIAN).int
        fun readLong(): Long = take(8).order(ByteOrder.LITTLE_ENDIAN).long
        fun readBoolean(): Boolean = when (readByte().toInt()) {
            0 -> false
            1 -> true
            else -> invalid()
        }
        fun readGuid(): UUID {
            val value = ByteArray(16)
            take(16).get(value)
            return DotNetGuid.fromByteArray(value)
        }
        fun readString(maximum: Int): String {
            val value = readBlob(maximum)
            return try {
                StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(value))
                    .toString()
            } finally {
                value.fill(0)
            }
        }
        fun readBlob(maximum: Int): ByteArray {
            val length = readInt()
            if (length < 0 || length > maximum || length > remaining) {
                invalid()
            }
            return ByteArray(length).also { take(length).get(it) }
        }
        inline fun <T> ifFlag(flags: Int, bit: Int, block: Reader.() -> T): T? =
            if (flags and (1 shl bit) != 0) block() else null
        private fun readByte(): Byte = take(1).get()
        private fun take(count: Int): ByteBuffer {
            if (count < 0 || count > remaining) {
                invalid()
            }
            val result = ByteBuffer.wrap(bytes, position, count).slice()
            position += count
            return result
        }
    }

    private class Writer {
        private val output = ByteArrayOutputStream()
        fun writeInt(value: Int) = writeBuffer(4) { putInt(value) }
        fun writeLong(value: Long) = writeBuffer(8) { putLong(value) }
        fun writeBoolean(value: Boolean) = output.write(if (value) 1 else 0)
        fun writeGuid(value: UUID) = output.write(DotNetGuid.toByteArray(value))
        fun writeString(value: String) {
            val bytes = value.toByteArray(StandardCharsets.UTF_8)
            try {
                if (bytes.size > MAXIMUM_TEXT_BYTES) invalid()
                writeBlob(bytes)
            } finally {
                bytes.fill(0)
            }
        }
        fun writeBlob(value: ByteArray) {
            writeInt(value.size)
            output.write(value)
        }
        inline fun ifFlag(flags: Int, bit: Int, block: Writer.() -> Unit) {
            if (flags and (1 shl bit) != 0) block()
        }
        fun toByteArray(): ByteArray = output.toByteArray()
        private inline fun writeBuffer(
            size: Int,
            block: ByteBuffer.() -> Unit,
        ) {
            val bytes = ByteArray(size)
            ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN).block()
            output.write(bytes)
        }
    }

    private fun invalid(): Nothing =
        throw ProtocolException(
            "Sync.InvalidOperation",
            "The sync operation is invalid.",
        )

    private fun unsupported(): Nothing =
        throw ProtocolException(
            "Sync.UnsupportedRequiredFeature",
            "The operation requires an unsupported protocol feature.",
        )

    private val EMPTY_GUID = UUID(0, 0)
}

class ProtocolException(
    val errorCode: String,
    message: String,
    cause: Throwable? = null,
) : IllegalArgumentException(message, cause)
