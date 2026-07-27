using PersonalAuthenticator.Core.Domain;
using PersonalAuthenticator.Core.Security;

namespace PersonalAuthenticator.Core.Tests;

public sealed class DuplicateDetectorTests
{
    [Fact]
    public void SameNormalisedFieldsAndSecret_AreDuplicates()
    {
        byte[] secret = Enumerable.Range(1, 20).Select(value => (byte)value).ToArray();
        using var left = new TotpAccount(Guid.NewGuid(), "Example", "User", secret);
        using var right = new TotpAccount(Guid.NewGuid(), "ｅｘａｍｐｌｅ", "user", secret);
        using var detector = new DuplicateDetector();

        Assert.True(detector.AreLikelyDuplicates(left, right));
    }

    [Fact]
    public void AmbiguousFieldBoundaries_AreNotDuplicates()
    {
        byte[] secret = Enumerable.Range(1, 20).Select(value => (byte)value).ToArray();
        using var left = new TotpAccount(Guid.NewGuid(), "A", "BC", secret);
        using var right = new TotpAccount(Guid.NewGuid(), "AB", "C", secret);
        using var detector = new DuplicateDetector();

        Assert.False(detector.AreLikelyDuplicates(left, right));
    }

    [Fact]
    public void SameIdentityWithDifferentSecret_IsClassifiedAsSecretChange()
    {
        using var left = new TotpAccount(
            Guid.NewGuid(),
            "Example",
            "alice",
            Enumerable.Range(1, 20).Select(value => (byte)value).ToArray());
        using var right = new TotpAccount(
            Guid.NewGuid(),
            " example ",
            "ALICE",
            Enumerable.Range(21, 20).Select(value => (byte)value).ToArray());
        using var detector = new DuplicateDetector();

        Assert.Equal(
            DuplicateMatchKind.SameAccountDifferentSecret,
            detector.Classify(left, right));
        Assert.False(detector.AreLikelyDuplicates(left, right));
    }

    [Fact]
    public void SameSecretWithDifferentTotpParameters_IsClassifiedAsSecretChange()
    {
        byte[] secret = Enumerable.Range(1, 20).Select(value => (byte)value).ToArray();
        using var left = new TotpAccount(Guid.NewGuid(), "Example", "alice", secret);
        using var right = new TotpAccount(
            Guid.NewGuid(),
            "Example",
            "alice",
            secret,
            TotpAlgorithm.Sha256,
            8,
            60);
        using var detector = new DuplicateDetector();

        Assert.Equal(
            DuplicateMatchKind.SameAccountDifferentSecret,
            detector.Classify(left, right));
    }
}
