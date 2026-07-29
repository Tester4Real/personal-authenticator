package com.tester4real.personalauthenticator.vault

import java.io.Closeable

class UnwrappedVaultKeys(
    sqlCipherPassphrase: ByteArray,
    vaultRootKey: ByteArray,
) : Closeable {
    private val ownedSqlCipherPassphrase = sqlCipherPassphrase.copyOf()
    private val ownedVaultRootKey = vaultRootKey.copyOf()
    private var closed = false

    fun copySqlCipherPassphrase(): ByteArray {
        check(!closed)
        return ownedSqlCipherPassphrase.copyOf()
    }

    fun copyVaultRootKey(): ByteArray {
        check(!closed)
        return ownedVaultRootKey.copyOf()
    }

    override fun close() {
        if (!closed) {
            ownedSqlCipherPassphrase.fill(0)
            ownedVaultRootKey.fill(0)
            closed = true
        }
    }
}
