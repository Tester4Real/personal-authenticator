using OtpNet;
using PersonalAuthenticator.Core.Abstractions;
using PersonalAuthenticator.Core.Domain;
using PersonalAuthenticator.Core.Exceptions;

namespace PersonalAuthenticator.Core.Services;

public sealed class ProvisioningUriParser : IProvisioningUriParser
{
    public const int MaximumPayloadLength = 4096;
    private static readonly HashSet<string> SupportedParameters = new(StringComparer.OrdinalIgnoreCase)
    {
        "secret",
        "issuer",
        "algorithm",
        "digits",
        "period",
    };

    public ParsedTotpProvisioning Parse(string provisioningUri)
    {
        if (string.IsNullOrWhiteSpace(provisioningUri))
        {
            throw Invalid("The setup URI is empty.");
        }

        if (provisioningUri.Length > MaximumPayloadLength)
        {
            throw Invalid("The setup URI is too long.");
        }

        ValidatePercentEncoding(provisioningUri);

        if (!Uri.TryCreate(provisioningUri, UriKind.Absolute, out Uri? uri))
        {
            throw Invalid("The setup URI is malformed.");
        }

        if (!string.Equals(uri.Scheme, "otpauth", StringComparison.OrdinalIgnoreCase))
        {
            throw Invalid("Only otpauth setup URIs are supported.");
        }

        if (!string.Equals(uri.Host, "totp", StringComparison.OrdinalIgnoreCase))
        {
            throw Invalid("Only TOTP accounts are supported.");
        }

        if (!string.IsNullOrEmpty(uri.Fragment) || !string.IsNullOrEmpty(uri.UserInfo) || !uri.IsDefaultPort)
        {
            throw Invalid("The setup URI contains unsupported components.");
        }

        string label = DecodeComponent(uri.AbsolutePath.TrimStart('/'), "label").Trim();
        if (string.IsNullOrWhiteSpace(label))
        {
            throw Invalid("The account label is empty.");
        }

        Dictionary<string, string> query = ParseQuery(uri.Query);
        EnsureSupportedParameters(query.Keys);

        if (!query.TryGetValue("secret", out string? encodedSecret) || string.IsNullOrWhiteSpace(encodedSecret))
        {
            throw Invalid("The setup URI does not contain a secret.");
        }

        (string? labelIssuer, string accountName) = ParseLabel(label);
        string? queryIssuer = query.TryGetValue("issuer", out string? value)
            ? DecodeComponent(value, "issuer").Trim()
            : null;

        if (queryIssuer is not null && string.IsNullOrWhiteSpace(queryIssuer))
        {
            throw Invalid("The issuer is empty.");
        }

        if (labelIssuer is not null &&
            queryIssuer is not null &&
            !string.Equals(labelIssuer, queryIssuer, StringComparison.Ordinal))
        {
            throw Invalid("The issuer in the label does not match the issuer parameter.");
        }

        string issuer = queryIssuer ?? labelIssuer ?? "Other";
        TotpAlgorithm algorithm = ParseAlgorithm(query.GetValueOrDefault("algorithm"));
        int digits = ParseNumber(query.GetValueOrDefault("digits"), 6, "digits");
        int period = ParseNumber(query.GetValueOrDefault("period"), 30, "period");
        byte[] secret = DecodeSecret(encodedSecret);

        try
        {
            return new ParsedTotpProvisioning(issuer, accountName, secret, algorithm, digits, period);
        }
        finally
        {
            System.Security.Cryptography.CryptographicOperations.ZeroMemory(secret);
        }
    }

    public ParsedTotpProvisioning ParseManual(
        string issuer,
        string accountName,
        string base32Secret,
        TotpAlgorithm algorithm,
        int digits,
        int period)
    {
        if (string.IsNullOrWhiteSpace(issuer) || issuer.Length > 256)
        {
            throw Invalid("Issuer must contain 1 to 256 characters.");
        }

        if (string.IsNullOrWhiteSpace(accountName) || accountName.Length > 256)
        {
            throw Invalid("Account name must contain 1 to 256 characters.");
        }

        ValidateDigitsAndPeriod(digits, period);
        byte[] secret = DecodeSecret(base32Secret);
        try
        {
            return new ParsedTotpProvisioning(
                issuer.Trim(),
                accountName.Trim(),
                secret,
                algorithm,
                digits,
                period);
        }
        finally
        {
            System.Security.Cryptography.CryptographicOperations.ZeroMemory(secret);
        }
    }

    private static Dictionary<string, string> ParseQuery(string queryText)
    {
        var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        string text = queryText.TrimStart('?');
        if (string.IsNullOrEmpty(text))
        {
            return result;
        }

        foreach (string pair in text.Split('&', StringSplitOptions.None))
        {
            int equalsIndex = pair.IndexOf('=');
            if (equalsIndex <= 0)
            {
                throw Invalid("The setup URI contains a malformed parameter.");
            }

            string key = DecodeComponent(pair[..equalsIndex], "parameter name");
            string value = pair[(equalsIndex + 1)..];
            if (!result.TryAdd(key, value))
            {
                throw Invalid($"The setup URI contains the '{key}' parameter more than once.");
            }
        }

        return result;
    }

    private static void EnsureSupportedParameters(IEnumerable<string> keys)
    {
        string? unsupported = keys.FirstOrDefault(key => !SupportedParameters.Contains(key));
        if (unsupported is not null)
        {
            throw Invalid($"The setup URI contains the unsupported '{unsupported}' parameter.");
        }
    }

    private static (string? Issuer, string AccountName) ParseLabel(string label)
    {
        int separatorIndex = label.IndexOf(':');
        if (separatorIndex < 0)
        {
            return (null, ValidateLabelPart(label, "account name"));
        }

        string issuer = ValidateLabelPart(label[..separatorIndex], "issuer");
        string accountName = ValidateLabelPart(label[(separatorIndex + 1)..], "account name");
        return (issuer, accountName);
    }

    private static string ValidateLabelPart(string value, string name)
    {
        string trimmed = value.Trim();
        if (string.IsNullOrWhiteSpace(trimmed) || trimmed.Length > 256)
        {
            throw Invalid($"The {name} is empty or too long.");
        }

        return trimmed;
    }

    private static string DecodeComponent(string value, string name)
    {
        try
        {
            return Uri.UnescapeDataString(value);
        }
        catch (UriFormatException exception)
        {
            throw new SafeApplicationException(
                "ProvisioningUri.InvalidEncoding",
                $"The {name} contains invalid percent encoding.",
                exception);
        }
    }

    private static void ValidatePercentEncoding(string value)
    {
        for (int index = 0; index < value.Length; index++)
        {
            if (value[index] != '%')
            {
                continue;
            }

            if (index + 2 >= value.Length ||
                !IsAsciiHexDigit(value[index + 1]) ||
                !IsAsciiHexDigit(value[index + 2]))
            {
                throw new SafeApplicationException(
                    "ProvisioningUri.InvalidEncoding",
                    "The setup URI contains invalid percent encoding.");
            }

            index += 2;
        }
    }

    private static bool IsAsciiHexDigit(char value) =>
        value is >= '0' and <= '9' or >= 'A' and <= 'F' or >= 'a' and <= 'f';

    private static TotpAlgorithm ParseAlgorithm(string? value) =>
        value?.ToUpperInvariant() switch
        {
            null => TotpAlgorithm.Sha1,
            "" => throw Invalid("The TOTP algorithm value is empty."),
            "SHA1" => TotpAlgorithm.Sha1,
            "SHA256" => TotpAlgorithm.Sha256,
            "SHA512" => TotpAlgorithm.Sha512,
            _ => throw Invalid("The TOTP algorithm is not supported."),
        };

    private static int ParseNumber(string? value, int defaultValue, string name)
    {
        if (value is null)
        {
            return defaultValue;
        }

        if (value.Length == 0)
        {
            throw Invalid($"The TOTP {name} value is empty.");
        }

        string decoded = DecodeComponent(value, name);
        if (!int.TryParse(decoded, System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out int result))
        {
            throw Invalid($"The TOTP {name} value is invalid.");
        }

        if (name == "digits" && result is not (6 or 8))
        {
            throw Invalid("TOTP codes must contain 6 or 8 digits.");
        }

        if (name == "period" && result is < 15 or > 300)
        {
            throw Invalid("The TOTP period must be between 15 and 300 seconds.");
        }

        return result;
    }

    private static void ValidateDigitsAndPeriod(int digits, int period)
    {
        if (digits is not (6 or 8))
        {
            throw Invalid("TOTP codes must contain 6 or 8 digits.");
        }

        if (period is < 15 or > 300)
        {
            throw Invalid("The TOTP period must be between 15 and 300 seconds.");
        }
    }

    private static byte[] DecodeSecret(string encodedSecret)
    {
        string normalized = string.Concat(encodedSecret.Where(character => !char.IsWhiteSpace(character))).ToUpperInvariant();
        if (normalized.Length is < 16 or > 208)
        {
            throw Invalid("The Base32 secret has an invalid length.");
        }

        try
        {
            byte[] decoded = Base32Encoding.ToBytes(normalized);
            if (decoded.Length is < 10 or > 128)
            {
                System.Security.Cryptography.CryptographicOperations.ZeroMemory(decoded);
                throw Invalid("The decoded secret has an unsafe length.");
            }

            return decoded;
        }
        catch (ArgumentException exception)
        {
            throw new SafeApplicationException(
                "ProvisioningUri.InvalidBase32",
                "The secret is not valid Base32.",
                exception);
        }
    }

    private static SafeApplicationException Invalid(string message) =>
        new("ProvisioningUri.Invalid", message);
}
