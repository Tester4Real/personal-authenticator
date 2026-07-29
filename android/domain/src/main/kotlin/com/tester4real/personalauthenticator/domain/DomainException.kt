package com.tester4real.personalauthenticator.domain

class DomainException(
    val errorCode: String,
    message: String,
    cause: Throwable? = null,
) : IllegalArgumentException(message, cause)
