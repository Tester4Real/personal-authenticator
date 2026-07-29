package com.tester4real.personalauthenticator.domain

data class TotpParameters(
    val algorithm: TotpAlgorithm = TotpAlgorithm.SHA1,
    val digits: Int = 6,
    val periodSeconds: Int = 30,
) {
    init {
        require(digits == 6 || digits == 8) {
            "TOTP codes must contain 6 or 8 digits."
        }
        require(periodSeconds in 15..300) {
            "The TOTP period must be between 15 and 300 seconds."
        }
    }
}
