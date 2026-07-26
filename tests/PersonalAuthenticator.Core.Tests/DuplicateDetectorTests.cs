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
}
