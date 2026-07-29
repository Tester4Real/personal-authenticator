package com.tester4real.personalauthenticator.vault

object PinPolicy {
    const val MINIMUM_LENGTH = 4
    const val MAXIMUM_LENGTH = 8

    fun validate(pin: CharArray) {
        require(pin.size in MINIMUM_LENGTH..MAXIMUM_LENGTH) {
            "PIN must contain 4 to 8 digits."
        }
        require(pin.all { it in '0'..'9' }) {
            "PIN must contain digits only."
        }
    }
}
