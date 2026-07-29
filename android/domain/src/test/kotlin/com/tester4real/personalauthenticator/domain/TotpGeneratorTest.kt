package com.tester4real.personalauthenticator.domain

import org.junit.Assert.assertEquals
import org.junit.Test

class TotpGeneratorTest {
    @Test
    fun rfc6238Vectors_matchSha1Sha256AndSha512() {
        val timestamps = longArrayOf(
            59,
            1_111_111_109,
            1_111_111_111,
            1_234_567_890,
            2_000_000_000,
            20_000_000_000,
        )
        assertVectors(
            "12345678901234567890".encodeToByteArray(),
            TotpAlgorithm.SHA1,
            timestamps,
            arrayOf(
                "94287082",
                "07081804",
                "14050471",
                "89005924",
                "69279037",
                "65353130",
            ),
        )
        assertVectors(
            "12345678901234567890123456789012".encodeToByteArray(),
            TotpAlgorithm.SHA256,
            timestamps,
            arrayOf(
                "46119246",
                "68084774",
                "67062674",
                "91819424",
                "90698825",
                "77737706",
            ),
        )
        assertVectors(
            "1234567890123456789012345678901234567890123456789012345678901234"
                .encodeToByteArray(),
            TotpAlgorithm.SHA512,
            timestamps,
            arrayOf(
                "90693936",
                "25091201",
                "99943326",
                "93441116",
                "38618901",
                "47863826",
            ),
        )
    }

    private fun assertVectors(
        secret: ByteArray,
        algorithm: TotpAlgorithm,
        timestamps: LongArray,
        expected: Array<String>,
    ) {
        try {
            timestamps.zip(expected).forEach { (timestamp, code) ->
                assertEquals(
                    code,
                    TotpGenerator.generate(
                        secret,
                        timestamp,
                        TotpParameters(algorithm, digits = 8, periodSeconds = 30),
                    ),
                )
            }
        } finally {
            secret.fill(0)
        }
    }
}
