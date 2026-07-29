package com.tester4real.personalauthenticator.vault

import org.bouncycastle.crypto.generators.Argon2BytesGenerator
import org.bouncycastle.crypto.params.Argon2Parameters
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.GeneralSecurityException
import java.security.SecureRandom
import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

class PinEnvelopeCrypto(
    private val pinHmac: PinHmac,
    private val secureRandom: SecureRandom = SecureRandom(),
) {
    fun create(pin: CharArray, generation: Long = 1): PinEnvelope {
        PinPolicy.validate(pin)
        require(generation > 0)
        val sqlCipherPassphrase = ByteArray(KEY_BYTES).also(secureRandom::nextBytes)
        val vaultRootKey = ByteArray(KEY_BYTES).also(secureRandom::nextBytes)
        return try {
            wrap(pin, generation, sqlCipherPassphrase, vaultRootKey)
        } finally {
            sqlCipherPassphrase.fill(0)
            vaultRootKey.fill(0)
        }
    }

    fun rewrap(
        current: UnwrappedVaultKeys,
        replacementPin: CharArray,
        generation: Long,
    ): PinEnvelope {
        val sqlCipherPassphrase = current.copySqlCipherPassphrase()
        val vaultRootKey = current.copyVaultRootKey()
        return try {
            wrap(
                replacementPin,
                generation,
                sqlCipherPassphrase,
                vaultRootKey,
            )
        } finally {
            sqlCipherPassphrase.fill(0)
            vaultRootKey.fill(0)
        }
    }

    fun unwrap(envelope: PinEnvelope, pin: CharArray): UnwrappedVaultKeys {
        PinPolicy.validate(pin)
        validateEnvelope(envelope)
        val hmac = pinHmac.calculate(pin, envelope.pinSalt)
        val wrappingKey = deriveWrappingKey(
            hmac,
            envelope.argonSalt,
            envelope.memoryKiB,
            envelope.iterations,
            envelope.parallelism,
        )
        val plaintext = try {
            val cipher = Cipher.getInstance(AES_GCM)
            cipher.init(
                Cipher.DECRYPT_MODE,
                SecretKeySpec(wrappingKey, "AES"),
                GCMParameterSpec(TAG_BITS, envelope.nonce),
            )
            cipher.updateAAD(createAad(envelope))
            cipher.doFinal(envelope.ciphertextAndTag)
        } catch (exception: AEADBadTagException) {
            throw VaultSecurityException(
                "Vault.PinInvalid",
                "The PIN is incorrect or the key envelope is damaged.",
                exception,
            )
        } catch (exception: GeneralSecurityException) {
            throw VaultSecurityException(
                "Vault.EnvelopeInvalid",
                "The PIN key envelope could not be opened.",
                exception,
            )
        } finally {
            hmac.fill(0)
            wrappingKey.fill(0)
        }
        if (plaintext.size != KEY_BYTES * 2) {
            plaintext.fill(0)
            throw VaultSecurityException(
                "Vault.EnvelopeInvalid",
                "The PIN key envelope contains an invalid key payload.",
            )
        }
        val sqlCipherPassphrase = plaintext.copyOfRange(0, KEY_BYTES)
        val vaultRootKey = plaintext.copyOfRange(KEY_BYTES, KEY_BYTES * 2)
        return try {
            UnwrappedVaultKeys(sqlCipherPassphrase, vaultRootKey)
        } finally {
            sqlCipherPassphrase.fill(0)
            vaultRootKey.fill(0)
            plaintext.fill(0)
        }
    }

    private fun wrap(
        pin: CharArray,
        generation: Long,
        sqlCipherPassphrase: ByteArray,
        vaultRootKey: ByteArray,
    ): PinEnvelope {
        PinPolicy.validate(pin)
        require(generation > 0)
        require(sqlCipherPassphrase.size == KEY_BYTES)
        require(vaultRootKey.size == KEY_BYTES)
        val pinSalt = ByteArray(SALT_BYTES).also(secureRandom::nextBytes)
        val argonSalt = ByteArray(SALT_BYTES).also(secureRandom::nextBytes)
        val nonce = ByteArray(NONCE_BYTES).also(secureRandom::nextBytes)
        val hmac = pinHmac.calculate(pin, pinSalt)
        val wrappingKey = deriveWrappingKey(
            hmac,
            argonSalt,
            MEMORY_KIB,
            ITERATIONS,
            PARALLELISM,
        )
        val plaintext = sqlCipherPassphrase + vaultRootKey
        val provisional = PinEnvelope(
            generation,
            MEMORY_KIB,
            ITERATIONS,
            PARALLELISM,
            pinSalt,
            argonSalt,
            nonce,
            ByteArray(0),
        )
        return try {
            val cipher = Cipher.getInstance(AES_GCM)
            cipher.init(
                Cipher.ENCRYPT_MODE,
                SecretKeySpec(wrappingKey, "AES"),
                GCMParameterSpec(TAG_BITS, nonce),
            )
            cipher.updateAAD(createAad(provisional))
            provisional.copy(ciphertextAndTag = cipher.doFinal(plaintext))
        } finally {
            hmac.fill(0)
            wrappingKey.fill(0)
            plaintext.fill(0)
        }
    }

    private fun deriveWrappingKey(
        hmac: ByteArray,
        salt: ByteArray,
        memoryKiB: Int,
        iterations: Int,
        parallelism: Int,
    ): ByteArray {
        val parameters = Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
            .withVersion(Argon2Parameters.ARGON2_VERSION_13)
            .withSalt(salt)
            .withMemoryAsKB(memoryKiB)
            .withIterations(iterations)
            .withParallelism(parallelism)
            .build()
        val result = ByteArray(KEY_BYTES)
        Argon2BytesGenerator().apply { init(parameters) }
            .generateBytes(hmac, result)
        return result
    }

    private fun createAad(envelope: PinEnvelope): ByteArray =
        ByteBuffer.allocate(8 + 4 * 4 + SALT_BYTES * 2)
            .order(ByteOrder.LITTLE_ENDIAN)
            .putLong(envelope.generation)
            .putInt(FORMAT_VERSION)
            .putInt(envelope.memoryKiB)
            .putInt(envelope.iterations)
            .putInt(envelope.parallelism)
            .put(envelope.pinSalt)
            .put(envelope.argonSalt)
            .array()

    private fun validateEnvelope(envelope: PinEnvelope) {
        if (envelope.generation <= 0 ||
            envelope.memoryKiB != MEMORY_KIB ||
            envelope.iterations != ITERATIONS ||
            envelope.parallelism != PARALLELISM ||
            envelope.pinSalt.size != SALT_BYTES ||
            envelope.argonSalt.size != SALT_BYTES ||
            envelope.nonce.size != NONCE_BYTES ||
            envelope.ciphertextAndTag.size != KEY_BYTES * 2 + TAG_BYTES
        ) {
            throw VaultSecurityException(
                "Vault.EnvelopeInvalid",
                "The PIN key envelope has invalid parameters.",
            )
        }
    }

    companion object {
        const val FORMAT_VERSION = 1
        const val MEMORY_KIB = 64 * 1_024
        const val ITERATIONS = 3
        const val PARALLELISM = 2
        const val KEY_BYTES = 32
        const val SALT_BYTES = 32
        const val NONCE_BYTES = 12
        const val TAG_BYTES = 16
        private const val TAG_BITS = TAG_BYTES * 8
        private const val AES_GCM = "AES/GCM/NoPadding"
    }
}
