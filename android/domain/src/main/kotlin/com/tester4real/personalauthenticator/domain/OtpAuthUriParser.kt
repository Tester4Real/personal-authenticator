package com.tester4real.personalauthenticator.domain

import java.io.ByteArrayOutputStream
import java.net.URI
import java.net.URISyntaxException
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets
import java.util.Locale

class OtpAuthUriParser {
    fun parse(provisioningUri: String): ParsedTotpProvisioning {
        if (provisioningUri.isBlank()) {
            invalid("The setup URI is empty.")
        }
        if (provisioningUri.length > MAXIMUM_PAYLOAD_LENGTH) {
            invalid("The setup URI is too long.")
        }
        validatePercentEncoding(provisioningUri)

        val uri = try {
            URI(provisioningUri)
        } catch (exception: URISyntaxException) {
            throw DomainException(
                "ProvisioningUri.Invalid",
                "The setup URI is malformed.",
                exception,
            )
        }
        if (!uri.isAbsolute || !uri.scheme.equals("otpauth", ignoreCase = true)) {
            invalid("Only otpauth setup URIs are supported.")
        }
        if (!uri.host.equals("totp", ignoreCase = true)) {
            invalid("Only TOTP accounts are supported.")
        }
        if (uri.rawFragment != null || uri.rawUserInfo != null || uri.port != -1) {
            invalid("The setup URI contains unsupported components.")
        }

        val encodedLabel = uri.rawPath.orEmpty().trimStart('/')
        if (encodedLabel.isBlank()) {
            invalid("The account label is empty.")
        }
        val query = parseQuery(uri.rawQuery.orEmpty())
        val unsupported = query.keys.firstOrNull { it !in SUPPORTED_PARAMETERS }
        if (unsupported != null) {
            invalid("The setup URI contains the unsupported '$unsupported' parameter.")
        }
        val encodedSecret = query["secret"]
        if (encodedSecret.isNullOrBlank()) {
            invalid("The setup URI does not contain a secret.")
        }

        val (labelIssuer, accountName) = parseEncodedLabel(encodedLabel)
        val queryIssuer = query["issuer"]?.let {
            decodeComponent(it, "issuer").trim()
        }
        if (queryIssuer != null && queryIssuer.isBlank()) {
            invalid("The issuer is empty.")
        }
        if (labelIssuer != null &&
            queryIssuer != null &&
            labelIssuer != queryIssuer
        ) {
            invalid(
                "The issuer in the label does not match the issuer parameter.",
            )
        }

        val issuer = queryIssuer ?: labelIssuer ?: "Other"
        val parameters = TotpParameters(
            algorithm = parseAlgorithm(query["algorithm"]),
            digits = parseNumber(query["digits"], 6, "digits"),
            periodSeconds = parseNumber(query["period"], 30, "period"),
        )
        val secret = Base32.decode(encodedSecret)
        return try {
            ParsedTotpProvisioning(
                issuer = issuer,
                accountName = accountName,
                secret = secret,
                parameters = parameters,
            )
        } finally {
            secret.fill(0)
        }
    }

    fun parseManual(
        issuer: String,
        accountName: String,
        base32Secret: String,
        algorithm: TotpAlgorithm,
        digits: Int,
        periodSeconds: Int,
    ): ParsedTotpProvisioning {
        if (issuer.isBlank() || issuer.length > 256) {
            invalid("Issuer must contain 1 to 256 characters.")
        }
        if (accountName.isBlank() || accountName.length > 256) {
            invalid("Account name must contain 1 to 256 characters.")
        }
        val parameters = try {
            TotpParameters(algorithm, digits, periodSeconds)
        } catch (exception: IllegalArgumentException) {
            throw DomainException(
                "ProvisioningUri.Invalid",
                exception.message ?: "The TOTP parameters are invalid.",
                exception,
            )
        }
        val secret = Base32.decode(base32Secret)
        return try {
            ParsedTotpProvisioning(
                issuer.trim(),
                accountName.trim(),
                secret,
                parameters,
            )
        } finally {
            secret.fill(0)
        }
    }

    private fun parseQuery(rawQuery: String): Map<String, String> {
        if (rawQuery.isEmpty()) {
            return emptyMap()
        }
        val result = linkedMapOf<String, String>()
        rawQuery.split('&').forEach { pair ->
            val equalsIndex = pair.indexOf('=')
            if (equalsIndex <= 0) {
                invalid("The setup URI contains a malformed parameter.")
            }
            val key = decodeComponent(
                pair.substring(0, equalsIndex),
                "parameter name",
            ).lowercase(Locale.ROOT)
            val value = pair.substring(equalsIndex + 1)
            if (result.putIfAbsent(key, value) != null) {
                invalid(
                    "The setup URI contains the '$key' parameter more than once.",
                )
            }
        }
        return result
    }

    private fun parseEncodedLabel(encodedLabel: String): Pair<String?, String> {
        val literalSeparator = encodedLabel.indexOf(':')
        if (literalSeparator < 0) {
            return parseDecodedLabel(
                decodeComponent(encodedLabel, "label").trim(),
            )
        }
        val issuer = decodeComponent(
            encodedLabel.substring(0, literalSeparator),
            "issuer",
        )
        val accountName = decodeComponent(
            encodedLabel.substring(literalSeparator + 1),
            "account name",
        )
        return validateLabelPart(issuer, "issuer") to
            validateLabelPart(accountName, "account name")
    }

    private fun parseDecodedLabel(label: String): Pair<String?, String> {
        val separator = label.indexOf(':')
        if (separator < 0) {
            return null to validateLabelPart(label, "account name")
        }
        return validateLabelPart(label.substring(0, separator), "issuer") to
            validateLabelPart(label.substring(separator + 1), "account name")
    }

    private fun validateLabelPart(value: String, name: String): String {
        val trimmed = value.trim()
        if (trimmed.isBlank() || trimmed.length > 256) {
            invalid("The $name is empty or too long.")
        }
        return trimmed
    }

    private fun decodeComponent(value: String, name: String): String {
        val bytes = ByteArrayOutputStream(value.length)
        var index = 0
        while (index < value.length) {
            val character = value[index]
            if (character == '%') {
                bytes.write(
                    value.substring(index + 1, index + 3).toInt(16),
                )
                index += 3
                continue
            }
            val encoded = character.toString().toByteArray(StandardCharsets.UTF_8)
            bytes.write(encoded)
            encoded.fill(0)
            index++
        }
        val decodedBytes = bytes.toByteArray()
        return try {
            StandardCharsets.UTF_8
                .newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)
                .decode(ByteBuffer.wrap(decodedBytes))
                .toString()
        } catch (exception: CharacterCodingException) {
            throw DomainException(
                "ProvisioningUri.InvalidEncoding",
                "The $name contains invalid percent encoding.",
                exception,
            )
        } finally {
            decodedBytes.fill(0)
        }
    }

    private fun validatePercentEncoding(value: String) {
        var index = 0
        while (index < value.length) {
            if (value[index] == '%') {
                if (index + 2 >= value.length ||
                    !value[index + 1].isAsciiHexDigit() ||
                    !value[index + 2].isAsciiHexDigit()
                ) {
                    throw DomainException(
                        "ProvisioningUri.InvalidEncoding",
                        "The setup URI contains invalid percent encoding.",
                    )
                }
                index += 3
            } else {
                index++
            }
        }
    }

    private fun parseAlgorithm(value: String?): TotpAlgorithm =
        when (value?.uppercase(Locale.ROOT)) {
            null -> TotpAlgorithm.SHA1
            "" -> invalid("The TOTP algorithm value is empty.")
            "SHA1" -> TotpAlgorithm.SHA1
            "SHA256" -> TotpAlgorithm.SHA256
            "SHA512" -> TotpAlgorithm.SHA512
            else -> invalid("The TOTP algorithm is not supported.")
        }

    private fun parseNumber(
        value: String?,
        defaultValue: Int,
        name: String,
    ): Int {
        if (value == null) {
            return defaultValue
        }
        if (value.isEmpty()) {
            invalid("The TOTP $name value is empty.")
        }
        val decoded = decodeComponent(value, name)
        if (decoded.isEmpty() || decoded.any { it !in '0'..'9' }) {
            invalid("The TOTP $name value is invalid.")
        }
        val number = decoded.toIntOrNull()
            ?: invalid("The TOTP $name value is invalid.")
        if (name == "digits" && number != 6 && number != 8) {
            invalid("TOTP codes must contain 6 or 8 digits.")
        }
        if (name == "period" && number !in 15..300) {
            invalid("The TOTP period must be between 15 and 300 seconds.")
        }
        return number
    }

    private fun Char.isAsciiHexDigit(): Boolean =
        this in '0'..'9' || this in 'A'..'F' || this in 'a'..'f'

    private fun invalid(message: String): Nothing =
        throw DomainException("ProvisioningUri.Invalid", message)

    companion object {
        const val MAXIMUM_PAYLOAD_LENGTH = 4_096

        private val SUPPORTED_PARAMETERS = setOf(
            "secret",
            "issuer",
            "algorithm",
            "digits",
            "period",
        )
    }
}
