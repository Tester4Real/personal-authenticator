package com.tester4real.personalauthenticator.domain

import java.nio.ByteBuffer
import java.util.Locale
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

object TotpGenerator {
    fun generate(
        secret: ByteArray,
        epochSeconds: Long,
        parameters: TotpParameters = TotpParameters(),
    ): String {
        require(secret.size in 10..128)
        require(epochSeconds >= 0)
        val counter = epochSeconds / parameters.periodSeconds
        val counterBytes = ByteBuffer.allocate(java.lang.Long.BYTES)
            .putLong(counter)
            .array()
        val digest = try {
            val mac = Mac.getInstance(parameters.algorithm.macName)
            mac.init(SecretKeySpec(secret, parameters.algorithm.macName))
            mac.doFinal(counterBytes)
        } finally {
            counterBytes.fill(0)
        }
        try {
            val offset = digest.last().toInt() and 0x0f
            val binary = ((digest[offset].toInt() and 0x7f) shl 24) or
                ((digest[offset + 1].toInt() and 0xff) shl 16) or
                ((digest[offset + 2].toInt() and 0xff) shl 8) or
                (digest[offset + 3].toInt() and 0xff)
            val modulus = if (parameters.digits == 6) 1_000_000 else 100_000_000
            return String.format(
                Locale.ROOT,
                "%0${parameters.digits}d",
                binary % modulus,
            )
        } finally {
            digest.fill(0)
        }
    }

    fun step(epochSeconds: Long, periodSeconds: Int): Long =
        epochSeconds / periodSeconds

    fun secondsRemaining(epochSeconds: Long, periodSeconds: Int): Int {
        val elapsed = Math.floorMod(epochSeconds, periodSeconds.toLong()).toInt()
        return periodSeconds - elapsed
    }
}
