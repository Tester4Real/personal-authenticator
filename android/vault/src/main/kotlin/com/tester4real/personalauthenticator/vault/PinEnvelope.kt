package com.tester4real.personalauthenticator.vault

data class PinEnvelope(
    val generation: Long,
    val memoryKiB: Int,
    val iterations: Int,
    val parallelism: Int,
    val pinSalt: ByteArray,
    val argonSalt: ByteArray,
    val nonce: ByteArray,
    val ciphertextAndTag: ByteArray,
)
