package com.tester4real.personalauthenticator.vault

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.nio.CharBuffer
import java.nio.charset.StandardCharsets
import java.security.KeyStore
import javax.crypto.KeyGenerator
import javax.crypto.Mac
import javax.crypto.SecretKey

class AndroidKeystorePinHmac(
    private val keyAlias: String = DEFAULT_ALIAS,
) : PinHmac {
    override fun calculate(pin: CharArray, pinSalt: ByteArray): ByteArray {
        PinPolicy.validate(pin)
        require(pinSalt.size == PinEnvelopeCrypto.SALT_BYTES)
        val encoded = StandardCharsets.UTF_8.newEncoder().encode(CharBuffer.wrap(pin))
        val pinBytes = ByteArray(encoded.remaining())
        encoded.get(pinBytes)
        return try {
            val mac = Mac.getInstance(KeyProperties.KEY_ALGORITHM_HMAC_SHA256)
            mac.init(loadOrCreateKey())
            mac.update(CONTEXT)
            mac.update(pinSalt)
            mac.doFinal(pinBytes)
        } catch (exception: Exception) {
            throw VaultSecurityException(
                "Vault.KeystoreUnavailable",
                "The Android Keystore PIN key is unavailable.",
                exception,
            )
        } finally {
            pinBytes.fill(0)
        }
    }

    private fun loadOrCreateKey(): SecretKey {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        val existing = keyStore.getKey(keyAlias, null)
        if (existing is SecretKey) {
            return existing
        }
        val generator = KeyGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_HMAC_SHA256,
            ANDROID_KEYSTORE,
        )
        generator.init(
            KeyGenParameterSpec.Builder(
                keyAlias,
                KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY,
            )
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setKeySize(256)
                .setUserAuthenticationRequired(false)
                .build(),
        )
        return generator.generateKey()
    }

    companion object {
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        private const val DEFAULT_ALIAS = "personal-authenticator-pin-hmac-v1"
        private val CONTEXT =
            "PersonalAuthenticator.Android.PinHmac.v1\u0000".encodeToByteArray()
    }
}
