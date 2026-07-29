package com.tester4real.personalauthenticator.domain

import java.security.MessageDigest
import java.text.Normalizer
import java.util.Locale
import java.util.UUID

data class DuplicateAccountView(
    val id: UUID,
    val issuer: String,
    val accountName: String,
    val secret: ByteArray,
)

enum class DuplicateMatchKind {
    NONE,
    EXACT,
    SAME_LABEL_DIFFERENT_SECRET,
}

data class DuplicateMatch(
    val kind: DuplicateMatchKind,
    val accountId: UUID? = null,
)

object DuplicateDetector {
    fun find(
        candidateIssuer: String,
        candidateAccountName: String,
        candidateSecret: ByteArray,
        existing: Iterable<DuplicateAccountView>,
    ): DuplicateMatch {
        val issuer = normalize(candidateIssuer)
        val accountName = normalize(candidateAccountName)
        var sameLabel: UUID? = null
        existing.forEach { account ->
            if (normalize(account.issuer) == issuer &&
                normalize(account.accountName) == accountName
            ) {
                if (MessageDigest.isEqual(account.secret, candidateSecret)) {
                    return DuplicateMatch(
                        DuplicateMatchKind.EXACT,
                        account.id,
                    )
                }
                sameLabel = sameLabel ?: account.id
            }
        }
        return if (sameLabel != null) {
            DuplicateMatch(
                DuplicateMatchKind.SAME_LABEL_DIFFERENT_SECRET,
                sameLabel,
            )
        } else {
            DuplicateMatch(DuplicateMatchKind.NONE)
        }
    }

    private fun normalize(value: String): String =
        Normalizer.normalize(value.trim(), Normalizer.Form.NFKC)
            .uppercase(Locale.ROOT)
}
