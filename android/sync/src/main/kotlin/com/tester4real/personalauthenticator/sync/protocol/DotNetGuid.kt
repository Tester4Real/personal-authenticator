package com.tester4real.personalauthenticator.sync.protocol

import java.nio.ByteBuffer
import java.util.UUID

object DotNetGuid {
    fun toByteArray(value: UUID): ByteArray {
        val network = ByteBuffer.allocate(16)
            .putLong(value.mostSignificantBits)
            .putLong(value.leastSignificantBits)
            .array()
        swapDotNetFields(network)
        return network
    }

    fun fromByteArray(bytes: ByteArray, offset: Int = 0): UUID {
        require(offset >= 0 && bytes.size - offset >= 16)
        val network = bytes.copyOfRange(offset, offset + 16)
        swapDotNetFields(network)
        val buffer = ByteBuffer.wrap(network)
        return UUID(buffer.long, buffer.long)
    }

    val comparator: Comparator<UUID> = Comparator { first, second ->
        val firstBytes = canonicalBytes(first)
        val secondBytes = canonicalBytes(second)
        for (index in firstBytes.indices) {
            val comparison = (firstBytes[index].toInt() and 0xff)
                .compareTo(secondBytes[index].toInt() and 0xff)
            if (comparison != 0) {
                return@Comparator comparison
            }
        }
        0
    }

    private fun canonicalBytes(value: UUID): ByteArray =
        ByteBuffer.allocate(16)
            .putLong(value.mostSignificantBits)
            .putLong(value.leastSignificantBits)
            .array()

    private fun swapDotNetFields(bytes: ByteArray) {
        bytes.swap(0, 3)
        bytes.swap(1, 2)
        bytes.swap(4, 5)
        bytes.swap(6, 7)
    }

    private fun ByteArray.swap(first: Int, second: Int) {
        val value = this[first]
        this[first] = this[second]
        this[second] = value
    }
}
