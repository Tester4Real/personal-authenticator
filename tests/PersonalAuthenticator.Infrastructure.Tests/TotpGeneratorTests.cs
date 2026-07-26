using System.Text;
using PersonalAuthenticator.Core.Domain;
using PersonalAuthenticator.Infrastructure.Otp;

namespace PersonalAuthenticator.Infrastructure.Tests;

public sealed class TotpGeneratorTests
{
    private readonly OtpNetTotpGenerator _generator = new();

    public static TheoryData<long, string, string, string> RfcVectors =>
        new()
        {
            { 59, "94287082", "46119246", "90693936" },
            { 1_111_111_109, "07081804", "68084774", "25091201" },
            { 1_111_111_111, "14050471", "67062674", "99943326" },
            { 1_234_567_890, "89005924", "91819424", "93441116" },
            { 2_000_000_000, "69279037", "90698825", "38618901" },
            { 20_000_000_000, "65353130", "77737706", "47863826" },
        };

    [Theory]
    [MemberData(nameof(RfcVectors))]
    public void Generate_Rfc6238Vectors_Match(
        long unixTime,
        string expectedSha1,
        string expectedSha256,
        string expectedSha512)
    {
        DateTimeOffset timestamp = DateTimeOffset.FromUnixTimeSeconds(unixTime);
        using TotpAccount sha1 = Create("12345678901234567890", TotpAlgorithm.Sha1, 8);
        using TotpAccount sha256 = Create("12345678901234567890123456789012", TotpAlgorithm.Sha256, 8);
        using TotpAccount sha512 = Create(
            "1234567890123456789012345678901234567890123456789012345678901234",
            TotpAlgorithm.Sha512,
            8);

        Assert.Equal(expectedSha1, _generator.Generate(sha1, timestamp));
        Assert.Equal(expectedSha256, _generator.Generate(sha256, timestamp));
        Assert.Equal(expectedSha512, _generator.Generate(sha512, timestamp));
    }

    [Fact]
    public void Countdown_HandlesStepBoundary()
    {
        using TotpAccount account = Create("12345678901234567890", TotpAlgorithm.Sha1, 6);

        Assert.Equal(1, _generator.GetSecondsRemaining(account, DateTimeOffset.FromUnixTimeSeconds(29)));
        Assert.Equal(30, _generator.GetSecondsRemaining(account, DateTimeOffset.FromUnixTimeSeconds(30)));
        Assert.Equal(0, _generator.GetTimeStep(account, DateTimeOffset.FromUnixTimeSeconds(29)));
        Assert.Equal(1, _generator.GetTimeStep(account, DateTimeOffset.FromUnixTimeSeconds(30)));
        Assert.Equal(6, _generator.Generate(account, DateTimeOffset.FromUnixTimeSeconds(59)).Length);
    }

    private static TotpAccount Create(string secret, TotpAlgorithm algorithm, int digits) =>
        new(Guid.NewGuid(), "RFC", "vector", Encoding.ASCII.GetBytes(secret), algorithm, digits);
}
