package com.tester4real.personalauthenticator.vault

import android.content.Context
import android.os.SystemClock
import com.tester4real.personalauthenticator.vault.db.PersonalAuthenticatorDatabase
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.withContext
import java.io.Closeable
import javax.inject.Inject
import javax.inject.Singleton

sealed interface VaultSessionState {
    data object NeedsSetup : VaultSessionState
    data object Locked : VaultSessionState
    data object Unlocked : VaultSessionState
}

@Singleton
class VaultSessionManager @Inject constructor(
    @ApplicationContext context: Context,
) : Closeable {
    private val envelopeStore = AtomicPinEnvelopeStore(context)
    private val throttle = PinAttemptThrottle(context)
    private val envelopeCrypto = PinEnvelopeCrypto(AndroidKeystorePinHmac())
    private val mutableState = MutableStateFlow<VaultSessionState>(
        if (envelopeStore.exists()) {
            VaultSessionState.Locked
        } else {
            VaultSessionState.NeedsSetup
        },
    )
    private var database: PersonalAuthenticatorDatabase? = null
    private var keys: UnwrappedVaultKeys? = null

    val state: StateFlow<VaultSessionState> = mutableState.asStateFlow()

    suspend fun setup(pin: CharArray, confirmation: CharArray) {
        check(mutableState.value == VaultSessionState.NeedsSetup)
        PinPolicy.validate(pin)
        require(pin.contentEquals(confirmation)) { "PINs do not match." }
        val envelope = withContext(Dispatchers.Default) {
            envelopeCrypto.create(pin)
        }
        envelopeStore.writeAndActivate(envelope) { reopened ->
            runCatching {
                envelopeCrypto.unwrap(reopened, pin).use { }
            }.isSuccess
        }
        unlockEnvelope(envelope, pin)
        throttle.registerSuccess()
    }

    suspend fun unlock(pin: CharArray) {
        check(mutableState.value == VaultSessionState.Locked)
        PinPolicy.validate(pin)
        val wallClock = System.currentTimeMillis()
        val elapsed = SystemClock.elapsedRealtime()
        val remaining = throttle.remainingDelayMillis(wallClock, elapsed)
        if (remaining > 0) {
            throw VaultSecurityException(
                "Vault.PinDelayed",
                "Try again in ${(remaining + 999) / 1_000} seconds.",
            )
        }

        var opened: UnwrappedVaultKeys? = null
        for (candidate in envelopeStore.loadCandidates()) {
            opened = runCatching {
                withContext(Dispatchers.Default) {
                    envelopeCrypto.unwrap(candidate, pin)
                }
            }.getOrNull()
            if (opened != null) {
                break
            }
        }
        if (opened == null) {
            val delay = throttle.registerFailure(wallClock, elapsed)
            throw VaultSecurityException(
                "Vault.PinInvalid",
                "Incorrect PIN. Try again in ${delay / 1_000} seconds.",
            )
        }
        activate(opened)
        throttle.registerSuccess()
    }

    @Synchronized
    fun lock() {
        database?.close()
        database = null
        keys?.close()
        keys = null
        if (envelopeStore.exists()) {
            mutableState.value = VaultSessionState.Locked
        }
    }

    @Synchronized
    fun requireDatabase(): PersonalAuthenticatorDatabase =
        database ?: throw VaultSecurityException(
            "Vault.Locked",
            "Unlock the vault first.",
        )

    override fun close() {
        lock()
    }

    private suspend fun unlockEnvelope(
        envelope: PinEnvelope,
        pin: CharArray,
    ) {
        val opened = withContext(Dispatchers.Default) {
            envelopeCrypto.unwrap(envelope, pin)
        }
        activate(opened)
    }

    private suspend fun activate(opened: UnwrappedVaultKeys) {
        val passphrase = opened.copySqlCipherPassphrase()
        val openedDatabase = try {
            withContext(Dispatchers.IO) {
                PersonalAuthenticatorDatabase.open(
                    applicationContext,
                    passphrase,
                ).also { database ->
                    database.openHelper.writableDatabase
                    database.verifyIntegrity()
                }
            }
        } catch (exception: Exception) {
            opened.close()
            throw VaultSecurityException(
                "Vault.DatabaseInvalid",
                "The encrypted vault could not be opened safely.",
                exception,
            )
        } finally {
            passphrase.fill(0)
        }
        synchronized(this) {
            database?.close()
            keys?.close()
            database = openedDatabase
            keys = opened
            mutableState.value = VaultSessionState.Unlocked
        }
    }

    private val applicationContext = context.applicationContext
}
