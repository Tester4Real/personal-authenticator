package com.tester4real.personalauthenticator.domain

object Base32 {
    private const val ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

    fun decode(value: String): ByteArray {
        val normalized = buildString(value.length) {
            value.forEach { character ->
                if (!character.isWhitespace()) {
                    append(character.uppercaseChar())
                }
            }
        }
        if (normalized.length !in 16..208) {
            invalid("The Base32 secret has an invalid length.")
        }

        val firstPadding = normalized.indexOf('=')
        val dataLength = if (firstPadding >= 0) firstPadding else normalized.length
        if (firstPadding >= 0) {
            if (normalized.substring(firstPadding).any { it != '=' } ||
                normalized.length % 8 != 0
            ) {
                invalidBase32()
            }
        }

        val output = ByteArray((dataLength * 5) / 8)
        var outputIndex = 0
        var accumulator = 0
        var availableBits = 0
        for (index in 0 until dataLength) {
            val digit = ALPHABET.indexOf(normalized[index])
            if (digit < 0) {
                output.fill(0)
                invalidBase32()
            }
            accumulator = (accumulator shl 5) or digit
            availableBits += 5
            if (availableBits >= 8) {
                availableBits -= 8
                output[outputIndex++] =
                    ((accumulator shr availableBits) and 0xff).toByte()
                accumulator = accumulator and ((1 shl availableBits) - 1)
            }
        }

        if (availableBits > 0 && accumulator != 0) {
            output.fill(0)
            invalidBase32()
        }
        if (outputIndex != output.size || output.size !in 10..128) {
            output.fill(0)
            invalid("The decoded secret has an unsafe length.")
        }
        return output
    }

    fun encode(bytes: ByteArray): String {
        if (bytes.isEmpty()) {
            return ""
        }
        val result = StringBuilder((bytes.size * 8 + 4) / 5)
        var accumulator = 0
        var availableBits = 0
        bytes.forEach { byte ->
            accumulator = (accumulator shl 8) or (byte.toInt() and 0xff)
            availableBits += 8
            while (availableBits >= 5) {
                availableBits -= 5
                result.append(ALPHABET[(accumulator shr availableBits) and 31])
                accumulator = accumulator and ((1 shl availableBits) - 1)
            }
        }
        if (availableBits > 0) {
            result.append(ALPHABET[(accumulator shl (5 - availableBits)) and 31])
        }
        return result.toString()
    }

    private fun invalidBase32(): Nothing =
        throw DomainException(
            "ProvisioningUri.InvalidBase32",
            "The secret is not valid Base32.",
        )

    private fun invalid(message: String): Nothing =
        throw DomainException("ProvisioningUri.Invalid", message)
}
