package com.tester4real.personalauthenticator.domain

enum class TotpAlgorithm(
    internal val macName: String,
) {
    SHA1("HmacSHA1"),
    SHA256("HmacSHA256"),
    SHA512("HmacSHA512"),
}
