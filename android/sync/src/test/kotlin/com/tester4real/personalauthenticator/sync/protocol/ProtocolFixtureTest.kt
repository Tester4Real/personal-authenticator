package com.tester4real.personalauthenticator.sync.protocol

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Test
import java.io.File
import java.util.Base64
import java.util.UUID

class ProtocolFixtureTest {
    @Test
    fun dotNetGuidBytesOrderingAndTicks_matchWindowsVectors() {
        val value = UUID.fromString("00112233-4455-6677-8899-aabbccddeeff")
        assertEquals(
            "33221100554477668899aabbccddeeff",
            DotNetGuid.toByteArray(value).toHex(),
        )
        assertEquals(value, DotNetGuid.fromByteArray(DotNetGuid.toByteArray(value)))

        val values = listOf(
            "00112234-4455-6677-8899-aabbccddeeff",
            "10112233-4455-6677-8899-aabbccddeeff",
            "00112233-4456-6677-8899-aabbccddeeff",
            "00112233-4455-6677-8899-aabbccddeeff",
        ).map(UUID::fromString)
        assertEquals(
            listOf(
                "00112233-4455-6677-8899-aabbccddeeff",
                "00112233-4456-6677-8899-aabbccddeeff",
                "00112234-4455-6677-8899-aabbccddeeff",
                "10112233-4455-6677-8899-aabbccddeeff",
            ),
            values.sortedWith(DotNetGuid.comparator).map(UUID::toString),
        )
        assertEquals(
            639_029_198_450_006_789L,
            DotNetTicks.fromInstant(
                java.time.Instant.parse("2026-01-02T03:04:05.000678900Z"),
            ),
        )
    }

    @Test
    fun allWindowsOperationsAndEncryptedObjects_roundTripByteForByte() {
        val root = fixtureRoot()
        val operationFiles = File(root, "operations")
            .listFiles { file -> file.extension == "bin" }!!
            .sortedBy { it.name }
        val objectFiles = File(root, "objects")
            .listFiles { file -> file.extension == "pao" }!!
            .sortedBy { it.name }
        assertEquals(12, operationFiles.size)
        assertEquals(12, objectFiles.size)
        val key = Base64.getDecoder().decode(
            "S6Q4wewRXz5xThouBxUPpyeHMLO+N/w6htFeUk6UlWA=",
        )
        try {
            operationFiles.zip(objectFiles).forEachIndexed {
                    index,
                    (operationFile, objectFile),
                ->
                val operationBytes = operationFile.readBytes()
                val envelopeBytes = objectFile.readBytes()
                val operation = SyncOperationCodec.decode(operationBytes)
                assertEquals(index, operation.kind.ordinal)
                assertArrayEquals(
                    operationBytes,
                    SyncOperationCodec.encode(operation),
                )
                val decrypted = GitHubObjectEnvelope.decrypt(
                    envelopeBytes,
                    REPOSITORY_ID,
                    VAULT_ID,
                    GENERATION_ID,
                    key,
                )
                assertEquals(operation.id, decrypted.id)
                assertArrayEquals(
                    operationBytes,
                    SyncOperationCodec.encode(decrypted),
                )
                assertArrayEquals(
                    envelopeBytes,
                    GitHubObjectEnvelope.encrypt(
                        REPOSITORY_ID,
                        VAULT_ID,
                        GENERATION_ID,
                        operation,
                        key,
                    ),
                )
            }
        } finally {
            key.fill(0)
        }
    }

    private fun fixtureRoot(): File {
        val workingDirectory = checkNotNull(System.getProperty("user.dir"))
        var current: File? = File(workingDirectory).absoluteFile
        while (current != null) {
            val candidate = File(current, "protocol-fixtures/v1")
            if (candidate.isDirectory) {
                return candidate
            }
            current = current.parentFile
        }
        throw IllegalStateException("Could not locate protocol-fixtures/v1.")
    }

    private fun ByteArray.toHex(): String =
        joinToString(separator = "") { "%02x".format(it) }

    companion object {
        private const val REPOSITORY_ID = 1_234_567_890_123L
        private val VAULT_ID =
            UUID.fromString("00112233-4455-6677-8899-aabbccddeeff")
        private val GENERATION_ID =
            UUID.fromString("10213243-5465-7687-98a9-bacbdcedfe0f")
    }
}
