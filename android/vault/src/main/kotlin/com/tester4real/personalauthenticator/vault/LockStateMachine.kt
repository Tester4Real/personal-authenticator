package com.tester4real.personalauthenticator.vault

class LockStateMachine(
    private val backgroundLockDelayMillis: Long = 30_000,
) {
    var isLocked: Boolean = true
        private set

    private var backgroundedAtElapsedMillis: Long? = null

    fun authenticated() {
        isLocked = false
        backgroundedAtElapsedMillis = null
    }

    fun processStarted() {
        lock()
    }

    fun screenTurnedOff() {
        lock()
    }

    fun lockNow() {
        lock()
    }

    fun movedToBackground(elapsedRealtimeMillis: Long) {
        if (!isLocked) {
            backgroundedAtElapsedMillis = elapsedRealtimeMillis
        }
    }

    fun movedToForeground(elapsedRealtimeMillis: Long) {
        val backgroundedAt = backgroundedAtElapsedMillis
        backgroundedAtElapsedMillis = null
        if (!isLocked &&
            backgroundedAt != null &&
            elapsedRealtimeMillis - backgroundedAt >=
            backgroundLockDelayMillis
        ) {
            lock()
        }
    }

    private fun lock() {
        isLocked = true
        backgroundedAtElapsedMillis = null
    }
}
