package com.tester4real.personalauthenticator.vault

import android.content.Context
import android.util.AtomicFile
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.File

class PinAttemptThrottle(context: Context) {
    private val stateFile = AtomicFile(
        File(context.noBackupFilesDir, "pin-attempts.bin"),
    )

    fun remainingDelayMillis(
        wallClockMillis: Long,
        elapsedRealtimeMillis: Long,
    ): Long {
        val state = readState()
        val wallRemaining = state.nextAllowedWallClockMillis - wallClockMillis
        val elapsedRemaining = if (
            elapsedRealtimeMillis >= state.failureElapsedRealtimeMillis
        ) {
            state.nextAllowedElapsedRealtimeMillis - elapsedRealtimeMillis
        } else {
            0
        }
        return maxOf(0, wallRemaining, elapsedRemaining)
    }

    fun registerFailure(
        wallClockMillis: Long,
        elapsedRealtimeMillis: Long,
    ): Long {
        val previous = readState()
        val count = (previous.failureCount + 1).coerceAtMost(31)
        val delay = (
            BASE_DELAY_MILLIS shl (count - 1).coerceAtMost(18)
        ).coerceAtMost(MAXIMUM_DELAY_MILLIS)
        writeState(
            State(
                failureCount = count,
                failureElapsedRealtimeMillis = elapsedRealtimeMillis,
                nextAllowedWallClockMillis = wallClockMillis + delay,
                nextAllowedElapsedRealtimeMillis =
                    elapsedRealtimeMillis + delay,
            ),
        )
        return delay
    }

    fun registerSuccess() {
        writeState(State())
    }

    private fun readState(): State {
        if (!stateFile.baseFile.exists()) {
            return State()
        }
        return runCatching {
            DataInputStream(stateFile.openRead()).use { reader ->
                if (reader.readInt() != FORMAT_VERSION) {
                    return@runCatching State()
                }
                State(
                    failureCount = reader.readInt().coerceIn(0, 31),
                    failureElapsedRealtimeMillis = reader.readLong(),
                    nextAllowedWallClockMillis = reader.readLong(),
                    nextAllowedElapsedRealtimeMillis = reader.readLong(),
                )
            }
        }.getOrDefault(State())
    }

    private fun writeState(state: State) {
        val output = stateFile.startWrite()
        try {
            val writer = DataOutputStream(output)
            writer.writeInt(FORMAT_VERSION)
            writer.writeInt(state.failureCount)
            writer.writeLong(state.failureElapsedRealtimeMillis)
            writer.writeLong(state.nextAllowedWallClockMillis)
            writer.writeLong(state.nextAllowedElapsedRealtimeMillis)
            writer.flush()
            stateFile.finishWrite(output)
        } catch (exception: Exception) {
            stateFile.failWrite(output)
            throw exception
        }
    }

    private data class State(
        val failureCount: Int = 0,
        val failureElapsedRealtimeMillis: Long = 0,
        val nextAllowedWallClockMillis: Long = 0,
        val nextAllowedElapsedRealtimeMillis: Long = 0,
    )

    companion object {
        private const val FORMAT_VERSION = 1
        private const val BASE_DELAY_MILLIS = 1_000L
        private const val MAXIMUM_DELAY_MILLIS = 5 * 60 * 1_000L
    }
}
