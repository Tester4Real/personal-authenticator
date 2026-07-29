package com.tester4real.personalauthenticator.domain

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Test

class OtpAuthUriParserTest {
    private val parser = OtpAuthUriParser()

    @Test
    fun googleStyleUri_readsDefaults() {
        parser.parse(
            "otpauth://totp/Example:alice%40example.com" +
                "?secret=$RFC_SHA1_SECRET&issuer=Example",
        ).use { parsed ->
            assertEquals("Example", parsed.issuer)
            assertEquals("alice@example.com", parsed.accountName)
            assertEquals(TotpAlgorithm.SHA1, parsed.parameters.algorithm)
            assertEquals(6, parsed.parameters.digits)
            assertEquals(30, parsed.parameters.periodSeconds)
            assertFalse(parsed.maskedSecretSuffix().contains(RFC_SHA1_SECRET))
        }
    }

    @Test
    fun encodedUnicodeAndColonParts_areDecodedWithoutChangingSeparator() {
        parser.parse(
            "otpauth://totp/Example%3ATeam:alice%3Aprimary" +
                "?secret=$RFC_SHA1_SECRET&issuer=Example%3ATeam",
        ).use { parsed ->
            assertEquals("Example:Team", parsed.issuer)
            assertEquals("alice:primary", parsed.accountName)
        }
        parser.parse(
            "otpauth://totp/%D8%AE%D8%AF%D9%85%D8%A9:" +
                "%D9%85%D8%B3%D8%AA%D8%AE%D8%AF%D9%85" +
                "?secret=$RFC_SHA1_SECRET" +
                "&issuer=%D8%AE%D8%AF%D9%85%D8%A9",
        ).use { parsed ->
            assertEquals("خدمة", parsed.issuer)
            assertEquals("مستخدم", parsed.accountName)
        }
    }

    @Test
    fun manualLowercaseWhitespaceSecret_isAccepted() {
        parser.parseManual(
            "Example",
            "alice",
            "gezd gnbv gy3t qojq gezd gnbv gy3t qojq",
            TotpAlgorithm.SHA1,
            6,
            30,
        ).use { parsed ->
            val secret = parsed.copySecret()
            try {
                assertEquals(20, secret.size)
            } finally {
                secret.fill(0)
            }
        }
    }

    @Test
    fun invalidAndUnsupportedUris_areRejected() {
        val invalid = listOf(
            "https://example.com",
            "otpauth://hotp/Example:account?secret=$RFC_SHA1_SECRET",
            "otpauth://totp/?secret=$RFC_SHA1_SECRET",
            "otpauth://totp/Example:account?issuer=Example",
            "otpauth://totp/Example:account?secret=not-base32!!!&issuer=Example",
            "otpauth://totp/Example:account?secret=$RFC_SHA1_SECRET&digits=7",
            "otpauth://totp/Example:account?secret=$RFC_SHA1_SECRET&period=5",
            "otpauth://totp/Example:account?secret=$RFC_SHA1_SECRET&algorithm=MD5",
            "otpauth://totp/Example:account?secret=$RFC_SHA1_SECRET&counter=1",
            "otpauth://user@totp/Example:account?secret=$RFC_SHA1_SECRET",
            "otpauth://totp:123/Example:account?secret=$RFC_SHA1_SECRET",
            "otpauth://totp/Example:account?secret=$RFC_SHA1_SECRET#fragment",
        )
        invalid.forEach { uri ->
            assertThrows(DomainException::class.java) {
                parser.parse(uri)
            }
        }
    }

    @Test
    fun duplicateUnknownMismatchAndMalformedEncoding_areRejected() {
        val invalid = listOf(
            "otpauth://totp/Example:account?secret=$RFC_SHA1_SECRET" +
                "&secret=$RFC_SHA1_SECRET&issuer=Example",
            "otpauth://totp/Example:account?secret=$RFC_SHA1_SECRET" +
                "&issuer=Different",
            "otpauth://totp/Example:account?secret=$RFC_SHA1_SECRET" +
                "&issuer=Example&algorithm=",
            "otpauth://totp/Example:account?secret=$RFC_SHA1_SECRET" +
                "&issuer=Example&digits=",
            "otpauth://totp/Example:account?secret=$RFC_SHA1_SECRET" +
                "&issuer=Example&period=",
        )
        invalid.forEach { uri ->
            assertThrows(DomainException::class.java) {
                parser.parse(uri)
            }
        }
        listOf("%", "%2", "%GG", "%2G").forEach { malformed ->
            val exception = assertThrows(DomainException::class.java) {
                parser.parse(
                    "otpauth://totp/Example$malformed:account" +
                        "?secret=$RFC_SHA1_SECRET&issuer=Example",
                )
            }
            assertEquals("ProvisioningUri.InvalidEncoding", exception.errorCode)
        }
    }

    @Test
    fun payloadLongerThan4096Characters_isRejected() {
        val oversized = "otpauth://totp/" +
            "a".repeat(OtpAuthUriParser.MAXIMUM_PAYLOAD_LENGTH)
        assertThrows(DomainException::class.java) {
            parser.parse(oversized)
        }
    }

    companion object {
        private const val RFC_SHA1_SECRET =
            "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
    }
}
