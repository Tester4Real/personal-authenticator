package com.tester4real.personalauthenticator.vault

fun interface PinHmac {
    fun calculate(pin: CharArray, pinSalt: ByteArray): ByteArray
}
