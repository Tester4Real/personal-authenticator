using PersonalAuthenticator.Core.Domain;
using PersonalAuthenticator.Core.Exceptions;
using PersonalAuthenticator.Core.Services;

namespace PersonalAuthenticator.Core.Tests;

public sealed class ProvisioningUriParserTests
{
    private const string RfcSha1Secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
    private readonly ProvisioningUriParser _parser = new();

    [Fact]
    public void Parse_GoogleStyleUri_ReadsDefaults()
    {
        using ParsedTotpProvisioning parsed = _parser.Parse(
            $"otpauth://totp/Example:alice%40example.com?secret={RfcSha1Secret}&issuer=Example");

        Assert.Equal("Example", parsed.Issuer);
        Assert.Equal("alice@example.com", parsed.AccountName);
        Assert.Equal(TotpAlgorithm.Sha1, parsed.Algorithm);
        Assert.Equal(6, parsed.Digits);
        Assert.Equal(30, parsed.Period);
        Assert.DoesNotContain(RfcSha1Secret, parsed.MaskedSecretSuffix, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("SHA256", TotpAlgorithm.Sha256)]
    [InlineData("SHA512", TotpAlgorithm.Sha512)]
    public void Parse_SupportedAlgorithm_ReadsValue(string text, TotpAlgorithm expected)
    {
        using ParsedTotpProvisioning parsed = _parser.Parse(
            $"otpauth://totp/Example:account?secret={RfcSha1Secret}&issuer=Example&algorithm={text}&digits=8&period=45");

        Assert.Equal(expected, parsed.Algorithm);
        Assert.Equal(8, parsed.Digits);
        Assert.Equal(45, parsed.Period);
    }

    [Fact]
    public void Parse_PercentEncodedUnicodeLabel_DecodesValue()
    {
        using ParsedTotpProvisioning parsed = _parser.Parse(
            $"otpauth://totp/%D8%AE%D8%AF%D9%85%D8%A9:%D9%85%D8%B3%D8%AA%D8%AE%D8%AF%D9%85?secret={RfcSha1Secret}&issuer=%D8%AE%D8%AF%D9%85%D8%A9");

        Assert.Equal("خدمة", parsed.Issuer);
        Assert.Equal("مستخدم", parsed.AccountName);
    }

    [Fact]
    public void Parse_EncodedColonInsideLabelParts_DoesNotConfuseTheSeparator()
    {
        using ParsedTotpProvisioning parsed = _parser.Parse(
            $"otpauth://totp/Example%3ATeam:alice%3Aprimary?secret={RfcSha1Secret}&issuer=Example%3ATeam");

        Assert.Equal("Example:Team", parsed.Issuer);
        Assert.Equal("alice:primary", parsed.AccountName);
    }

    [Fact]
    public void ParseManual_LowercaseAndWhitespaceSecret_IsAccepted()
    {
        using ParsedTotpProvisioning parsed = _parser.ParseManual(
            "Example",
            "account",
            "gezd gnbv\n gy3tqojq gezdgnbvgy3tqojq",
            TotpAlgorithm.Sha1,
            6,
            30);

        using TotpAccount account = parsed.CreateAccount();
        Assert.Equal(20, account.Secret.Length);
    }

    [Theory]
    [InlineData("https://example.com")]
    [InlineData("otpauth://hotp/Example:account?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")]
    [InlineData("otpauth://totp/?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")]
    [InlineData("otpauth://totp/Example:account?issuer=Example")]
    [InlineData("otpauth://totp/Example:account?secret=not-base32!!!&issuer=Example")]
    [InlineData("otpauth://totp/Example:account?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&digits=7")]
    [InlineData("otpauth://totp/Example:account?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&period=5")]
    [InlineData("otpauth://totp/Example:account?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&algorithm=MD5")]
    public void Parse_InvalidInput_ThrowsSafeException(string uri)
    {
        Assert.Throws<SafeApplicationException>(() => _parser.Parse(uri));
    }

    [Fact]
    public void Parse_DuplicateParameter_IsRejected()
    {
        string uri =
            $"otpauth://totp/Example:account?secret={RfcSha1Secret}&secret={RfcSha1Secret}&issuer=Example";

        SafeApplicationException exception = Assert.Throws<SafeApplicationException>(() => _parser.Parse(uri));
        Assert.Contains("more than once", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Parse_IssuerMismatch_IsRejected()
    {
        string uri = $"otpauth://totp/Example:account?secret={RfcSha1Secret}&issuer=Different";

        SafeApplicationException exception = Assert.Throws<SafeApplicationException>(() => _parser.Parse(uri));
        Assert.Contains("does not match", exception.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("algorithm")]
    [InlineData("digits")]
    [InlineData("period")]
    public void Parse_PresentButEmptyTotpParameter_IsRejected(string parameter)
    {
        string uri =
            $"otpauth://totp/Example:account?secret={RfcSha1Secret}&issuer=Example&{parameter}=";

        SafeApplicationException exception = Assert.Throws<SafeApplicationException>(() => _parser.Parse(uri));

        Assert.Equal("ProvisioningUri.Invalid", exception.ErrorCode);
        Assert.Contains("empty", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData("%")]
    [InlineData("%2")]
    [InlineData("%GG")]
    [InlineData("%2G")]
    public void Parse_MalformedRawPercentEncoding_IsRejected(string malformedEncoding)
    {
        string uri =
            $"otpauth://totp/Example{malformedEncoding}:account?secret={RfcSha1Secret}&issuer=Example";

        SafeApplicationException exception = Assert.Throws<SafeApplicationException>(() => _parser.Parse(uri));

        Assert.Equal("ProvisioningUri.InvalidEncoding", exception.ErrorCode);
    }

    [Fact]
    public void Parse_OversizedPayload_IsRejected()
    {
        string uri = "otpauth://totp/" + new string('a', ProvisioningUriParser.MaximumPayloadLength);

        Assert.Throws<SafeApplicationException>(() => _parser.Parse(uri));
    }
}
