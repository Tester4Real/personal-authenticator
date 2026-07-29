package com.tester4real.personalauthenticator.sync.protocol

import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.util.UUID
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

object GitHubObjectEnvelope {
    private val MAGIC = "PAVGHO01".toByteArray(StandardCharsets.US_ASCII)
    private const val HEADER_BYTES = 84
    private const val TAG_BYTES = 16

    fun encrypt(
        repositoryId: Long,
        vaultId: UUID,
        generationId: UUID,
        operation: WireOperation,
        syncKey: ByteArray,
    ): ByteArray {
        require(syncKey.size == 32)
        val plaintext = SyncOperationCodec.encode(operation)
        val nonce = createNonce(
            repositoryId,
            vaultId,
            generationId,
            operation.id,
            syncKey,
        )
        val header = createHeader(
            repositoryId,
            vaultId,
            generationId,
            operation.id,
            nonce,
            plaintext.size,
        )
        return try {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(
                Cipher.ENCRYPT_MODE,
                SecretKeySpec(syncKey, "AES"),
                GCMParameterSpec(TAG_BYTES * 8, nonce),
            )
            cipher.updateAAD(header)
            header + cipher.doFinal(plaintext)
        } finally {
            plaintext.fill(0)
            nonce.fill(0)
            header.fill(0)
        }
    }

    fun decrypt(
        envelope: ByteArray,
        repositoryId: Long,
        vaultId: UUID,
        generationId: UUID,
        syncKey: ByteArray,
    ): WireOperation {
        if (envelope.size !in
            (HEADER_BYTES + 64 + TAG_BYTES)..
            (HEADER_BYTES + SyncOperationCodec.MAXIMUM_OPERATION_BYTES + TAG_BYTES)
        ) {
            invalid()
        }
        val header = envelope.copyOfRange(0, HEADER_BYTES)
        val reader = ByteBuffer.wrap(header).order(ByteOrder.LITTLE_ENDIAN)
        val magic = ByteArray(8).also(reader::get)
        if (!MessageDigest.isEqual(magic, MAGIC) ||
            reader.short.toInt() != 1 ||
            reader.short.toInt() != 0 ||
            reader.long != repositoryId
        ) {
            invalid()
        }
        val headerVaultId = readGuid(reader)
        val headerGenerationId = readGuid(reader)
        val objectId = readGuid(reader)
        val nonce = ByteArray(12).also(reader::get)
        val plaintextLength = reader.int
        if (headerVaultId != vaultId ||
            headerGenerationId != generationId ||
            plaintextLength !in 64..SyncOperationCodec.MAXIMUM_OPERATION_BYTES ||
            envelope.size != HEADER_BYTES + plaintextLength + TAG_BYTES
        ) {
            invalid()
        }
        val plaintext = try {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(
                Cipher.DECRYPT_MODE,
                SecretKeySpec(syncKey, "AES"),
                GCMParameterSpec(TAG_BYTES * 8, nonce),
            )
            cipher.updateAAD(header)
            cipher.doFinal(envelope, HEADER_BYTES, envelope.size - HEADER_BYTES)
        } catch (exception: Exception) {
            throw ProtocolException(
                "GitHub.InvalidRemoteObject",
                "The GitHub object failed authentication.",
                exception,
            )
        } finally {
            header.fill(0)
            nonce.fill(0)
        }
        return try {
            SyncOperationCodec.decode(plaintext).also {
                if (it.id != objectId) invalid()
            }
        } finally {
            plaintext.fill(0)
        }
    }

    private fun createHeader(
        repositoryId: Long,
        vaultId: UUID,
        generationId: UUID,
        objectId: UUID,
        nonce: ByteArray,
        plaintextLength: Int,
    ): ByteArray =
        ByteBuffer.allocate(HEADER_BYTES)
            .order(ByteOrder.LITTLE_ENDIAN)
            .put(MAGIC)
            .putShort(1)
            .putShort(0)
            .putLong(repositoryId)
            .put(DotNetGuid.toByteArray(vaultId))
            .put(DotNetGuid.toByteArray(generationId))
            .put(DotNetGuid.toByteArray(objectId))
            .put(nonce)
            .putInt(plaintextLength)
            .array()

    private fun createNonce(
        repositoryId: Long,
        vaultId: UUID,
        generationId: UUID,
        objectId: UUID,
        syncKey: ByteArray,
    ): ByteArray {
        val input = ByteBuffer.allocate(56)
            .order(ByteOrder.LITTLE_ENDIAN)
            .putLong(repositoryId)
            .put(DotNetGuid.toByteArray(vaultId))
            .put(DotNetGuid.toByteArray(generationId))
            .put(DotNetGuid.toByteArray(objectId))
            .array()
        var digest: ByteArray? = null
        return try {
            val mac = Mac.getInstance("HmacSHA256")
            mac.init(SecretKeySpec(syncKey, "HmacSHA256"))
            val calculated = mac.doFinal(input)
            digest = calculated
            calculated.copyOfRange(0, 12)
        } finally {
            input.fill(0)
            digest?.fill(0)
        }
    }

    private fun readGuid(reader: ByteBuffer): UUID {
        val bytes = ByteArray(16).also(reader::get)
        return DotNetGuid.fromByteArray(bytes)
    }

    private fun invalid(): Nothing =
        throw ProtocolException(
            "GitHub.InvalidRemoteObject",
            "The GitHub object is invalid.",
        )
}
