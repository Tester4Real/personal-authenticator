package com.tester4real.personalauthenticator.vault

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.nio.charset.StandardCharsets

object PinEnvelopeCodec {
    private val MAGIC = "PAVPIN01".toByteArray(StandardCharsets.US_ASCII)
    private const val MAXIMUM_BYTES = 4_096

    fun encode(envelope: PinEnvelope): ByteArray {
        val output = ByteArrayOutputStream()
        DataOutputStream(output).use { writer ->
            writer.write(MAGIC)
            writer.writeInt(PinEnvelopeCrypto.FORMAT_VERSION)
            writer.writeLong(envelope.generation)
            writer.writeInt(envelope.memoryKiB)
            writer.writeInt(envelope.iterations)
            writer.writeInt(envelope.parallelism)
            writeBytes(writer, envelope.pinSalt)
            writeBytes(writer, envelope.argonSalt)
            writeBytes(writer, envelope.nonce)
            writeBytes(writer, envelope.ciphertextAndTag)
        }
        return output.toByteArray()
    }

    fun decode(bytes: ByteArray): PinEnvelope {
        if (bytes.size !in 64..MAXIMUM_BYTES) {
            invalid()
        }
        try {
            DataInputStream(ByteArrayInputStream(bytes)).use { reader ->
                val magic = ByteArray(MAGIC.size)
                reader.readFully(magic)
                if (!magic.contentEquals(MAGIC)) {
                    invalid()
                }
                if (reader.readInt() != PinEnvelopeCrypto.FORMAT_VERSION) {
                    invalid()
                }
                val result = PinEnvelope(
                    generation = reader.readLong(),
                    memoryKiB = reader.readInt(),
                    iterations = reader.readInt(),
                    parallelism = reader.readInt(),
                    pinSalt = readBytes(reader, PinEnvelopeCrypto.SALT_BYTES),
                    argonSalt = readBytes(reader, PinEnvelopeCrypto.SALT_BYTES),
                    nonce = readBytes(reader, PinEnvelopeCrypto.NONCE_BYTES),
                    ciphertextAndTag = readBytes(
                        reader,
                        PinEnvelopeCrypto.KEY_BYTES * 2 +
                            PinEnvelopeCrypto.TAG_BYTES,
                    ),
                )
                if (reader.available() != 0) {
                    invalid()
                }
                return result
            }
        } catch (exception: VaultSecurityException) {
            throw exception
        } catch (exception: Exception) {
            throw VaultSecurityException(
                "Vault.EnvelopeInvalid",
                "The PIN key envelope is malformed.",
                exception,
            )
        }
    }

    private fun writeBytes(writer: DataOutputStream, bytes: ByteArray) {
        writer.writeInt(bytes.size)
        writer.write(bytes)
    }

    private fun readBytes(reader: DataInputStream, expectedLength: Int): ByteArray {
        val length = reader.readInt()
        if (length != expectedLength || length > reader.available()) {
            invalid()
        }
        return ByteArray(length).also(reader::readFully)
    }

    private fun invalid(): Nothing =
        throw VaultSecurityException(
            "Vault.EnvelopeInvalid",
            "The PIN key envelope is malformed.",
        )
}
