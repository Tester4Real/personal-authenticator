package com.tester4real.personalauthenticator.vault

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Test
import java.nio.CharBuffer
import java.nio.charset.StandardCharsets
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

class PinEnvelopeCryptoTest {
    private val crypto = PinEnvelopeCrypto(FakePinHmac())

    @Test
    fun pinBoundaries_areStrictlyNumericAndFourToEightDigits() {
        listOf("1234", "123456", "12345678").forEach {
            PinPolicy.validate(it.toCharArray())
        }
        listOf("123", "123456789", "12a4", "１２３４").forEach { value ->
            assertThrows(IllegalArgumentException::class.java) {
                PinPolicy.validate(value.toCharArray())
            }
        }
    }

    @Test
    fun envelope_roundTripsWithoutStoringAPinVerifier() {
        val pin = "24681357".toCharArray()
        val envelope = crypto.create(pin)
        val encoded = PinEnvelopeCodec.encode(envelope)
        val reopened = PinEnvelopeCodec.decode(encoded)
        crypto.unwrap(reopened, pin).use { keys ->
            assertEquals(PinEnvelopeCrypto.KEY_BYTES, keys.copyVaultRootKey().size)
            assertEquals(
                PinEnvelopeCrypto.KEY_BYTES,
                keys.copySqlCipherPassphrase().size,
            )
        }
        val pinBytes = "24681357".encodeToByteArray()
        try {
            assertFalse(encoded.containsSubsequence(pinBytes))
        } finally {
            pin.fill('\u0000')
            pinBytes.fill(0)
            encoded.fill(0)
        }
    }

    @Test
    fun wrongPinAndTampering_failWithoutReturningKeys() {
        val pin = "8642".toCharArray()
        val envelope = crypto.create(pin)
        val wrong = "8643".toCharArray()
        assertThrows(VaultSecurityException::class.java) {
            crypto.unwrap(envelope, wrong)
        }
        val tampered = envelope.copy(
            ciphertextAndTag = envelope.ciphertextAndTag.copyOf().also {
                it[it.lastIndex] = (it.last().toInt() xor 0x80).toByte()
            },
        )
        assertThrows(VaultSecurityException::class.java) {
            crypto.unwrap(tampered, pin)
        }
        pin.fill('\u0000')
        wrong.fill('\u0000')
    }

    @Test
    fun pinChange_rewrapsTheSameDatabaseAndRootKeys() {
        val currentPin = "1357".toCharArray()
        val replacementPin = "97531".toCharArray()
        val originalEnvelope = crypto.create(currentPin, generation = 4)
        crypto.unwrap(originalEnvelope, currentPin).use { original ->
            val replacementEnvelope = crypto.rewrap(
                original,
                replacementPin,
                generation = 5,
            )
            crypto.unwrap(replacementEnvelope, replacementPin).use { reopened ->
                assertArrayEquals(
                    original.copySqlCipherPassphrase(),
                    reopened.copySqlCipherPassphrase(),
                )
                assertArrayEquals(
                    original.copyVaultRootKey(),
                    reopened.copyVaultRootKey(),
                )
            }
        }
        currentPin.fill('\u0000')
        replacementPin.fill('\u0000')
    }

    private class FakePinHmac : PinHmac {
        private val key = ByteArray(32) { index -> (index + 1).toByte() }

        override fun calculate(pin: CharArray, pinSalt: ByteArray): ByteArray {
            val buffer = StandardCharsets.UTF_8.newEncoder()
                .encode(CharBuffer.wrap(pin))
            val bytes = ByteArray(buffer.remaining())
            buffer.get(bytes)
            return try {
                val mac = Mac.getInstance("HmacSHA256")
                mac.init(SecretKeySpec(key, "HmacSHA256"))
                mac.update(pinSalt)
                mac.doFinal(bytes)
            } finally {
                bytes.fill(0)
            }
        }
    }

    private fun ByteArray.containsSubsequence(value: ByteArray): Boolean =
        indices.any { start ->
            start + value.size <= size &&
                value.indices.all { offset -> this[start + offset] == value[offset] }
        }
}
