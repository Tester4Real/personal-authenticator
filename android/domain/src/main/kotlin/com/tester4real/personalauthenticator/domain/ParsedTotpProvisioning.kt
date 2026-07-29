package com.tester4real.personalauthenticator.domain

import java.io.Closeable

class ParsedTotpProvisioning(
    val issuer: String,
    val accountName: String,
    secret: ByteArray,
    val parameters: TotpParameters,
) : Closeable {
    private val ownedSecret = secret.copyOf()
    private var closed = false

    init {
        require(issuer.isNotBlank() && issuer.length <= 256)
        require(accountName.isNotBlank() && accountName.length <= 256)
        require(secret.size in 10..128)
    }

    fun copySecret(): ByteArray {
        check(!closed) { "Provisioning data has been cleared." }
        return ownedSecret.copyOf()
    }

    fun maskedSecretSuffix(): String {
        check(!closed) { "Provisioning data has been cleared." }
        val encoded = Base32.encode(ownedSecret)
        return "••••${encoded.takeLast(4)}"
    }

    override fun close() {
        if (!closed) {
            ownedSecret.fill(0)
            closed = true
        }
    }
}
