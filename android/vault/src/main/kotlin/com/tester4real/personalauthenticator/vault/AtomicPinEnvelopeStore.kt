package com.tester4real.personalauthenticator.vault

import android.content.Context
import android.util.AtomicFile
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.File
import java.nio.charset.StandardCharsets

class AtomicPinEnvelopeStore(context: Context) {
    private val directory = File(context.noBackupFilesDir, DIRECTORY_NAME)
    private val slotA = AtomicFile(File(directory, SLOT_A_FILE))
    private val slotB = AtomicFile(File(directory, SLOT_B_FILE))
    private val activePointer = AtomicFile(File(directory, ACTIVE_FILE))

    fun exists(): Boolean = slotA.baseFile.exists() || slotB.baseFile.exists()

    fun loadCandidates(): List<PinEnvelope> {
        val pointer = readPointer()
        val slots = if (pointer?.slot == Slot.B) {
            listOf(slotB, slotA)
        } else {
            listOf(slotA, slotB)
        }
        return slots.mapNotNull { file ->
            if (!file.baseFile.exists()) {
                null
            } else {
                runCatching {
                    PinEnvelopeCodec.decode(file.readFully())
                }.getOrNull()
            }
        }.sortedWith(
            compareByDescending<PinEnvelope> {
                it.generation == pointer?.generation
            }.thenByDescending { it.generation },
        )
    }

    fun writeAndActivate(
        envelope: PinEnvelope,
        verify: (PinEnvelope) -> Boolean,
    ) {
        directory.mkdirs()
        val current = readPointer()
        val targetSlot = if (current?.slot == Slot.A) Slot.B else Slot.A
        val targetFile = if (targetSlot == Slot.A) slotA else slotB
        writeAtomic(targetFile, PinEnvelopeCodec.encode(envelope))
        val reopened = PinEnvelopeCodec.decode(targetFile.readFully())
        if (reopened.generation != envelope.generation || !verify(reopened)) {
            throw VaultSecurityException(
                "Vault.EnvelopeVerificationFailed",
                "The replacement PIN envelope could not be verified.",
            )
        }
        writePointer(Pointer(targetSlot, envelope.generation))
    }

    private fun readPointer(): Pointer? {
        if (!activePointer.baseFile.exists()) {
            return null
        }
        return runCatching {
            DataInputStream(activePointer.openRead()).use { reader ->
                val magic = ByteArray(POINTER_MAGIC.size)
                reader.readFully(magic)
                if (!magic.contentEquals(POINTER_MAGIC)) {
                    return@runCatching null
                }
                val slot = when (reader.readByte().toInt()) {
                    0 -> Slot.A
                    1 -> Slot.B
                    else -> return@runCatching null
                }
                val generation = reader.readLong()
                if (generation <= 0 || reader.available() != 0) {
                    null
                } else {
                    Pointer(slot, generation)
                }
            }
        }.getOrNull()
    }

    private fun writePointer(pointer: Pointer) {
        val output = activePointer.startWrite()
        try {
            val writer = DataOutputStream(output)
            writer.write(POINTER_MAGIC)
            writer.writeByte(if (pointer.slot == Slot.A) 0 else 1)
            writer.writeLong(pointer.generation)
            writer.flush()
            activePointer.finishWrite(output)
        } catch (exception: Exception) {
            activePointer.failWrite(output)
            throw exception
        }
    }

    private fun writeAtomic(file: AtomicFile, bytes: ByteArray) {
        val output = file.startWrite()
        try {
            output.write(bytes)
            file.finishWrite(output)
        } catch (exception: Exception) {
            file.failWrite(output)
            throw exception
        } finally {
            bytes.fill(0)
        }
    }

    private enum class Slot {
        A,
        B,
    }

    private data class Pointer(
        val slot: Slot,
        val generation: Long,
    )

    companion object {
        private const val DIRECTORY_NAME = "pin-envelope"
        private const val SLOT_A_FILE = "slot-a.bin"
        private const val SLOT_B_FILE = "slot-b.bin"
        private const val ACTIVE_FILE = "active.bin"
        private val POINTER_MAGIC =
            "PAVACT01".toByteArray(StandardCharsets.US_ASCII)
    }
}
