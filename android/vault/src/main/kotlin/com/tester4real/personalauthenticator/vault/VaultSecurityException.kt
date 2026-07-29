package com.tester4real.personalauthenticator.vault

class VaultSecurityException(
    val errorCode: String,
    message: String,
    cause: Throwable? = null,
) : SecurityException(message, cause)
