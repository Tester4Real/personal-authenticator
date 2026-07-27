using PersonalAuthenticator.Core.Domain;

namespace PersonalAuthenticator.Core.Tests;

public sealed class V2DomainModelTests
{
    [Fact]
    public void Account_NormalizesDisplayAndTimes()
    {
        Guid accountId = Guid.NewGuid();
        Guid versionId = Guid.NewGuid();
        DateTimeOffset created = new(2026, 1, 1, 2, 0, 0, TimeSpan.FromHours(2));
        DateTimeOffset updated = created.AddHours(1);

        var account = new VaultAccountV2(
            accountId,
            " Example ",
            " alice ",
            versionId,
            favourite: true,
            sortOrder: 3,
            created,
            updated);

        Assert.Equal(accountId, account.Id);
        Assert.Equal("Example", account.Issuer);
        Assert.Equal("alice", account.AccountName);
        Assert.Equal(versionId, account.ActiveSecretVersionId);
        Assert.True(account.Favourite);
        Assert.Equal(3, account.SortOrder);
        Assert.Equal(TimeSpan.Zero, account.CreatedAtUtc.Offset);
        Assert.Equal(TimeSpan.Zero, account.UpdatedAtUtc.Offset);
    }

    [Fact]
    public void SecretVersion_OwnsSecretAndRequiresOtpAuthUri()
    {
        byte[] secret = Enumerable.Range(1, 20).Select(value => (byte)value).ToArray();
        var version = new SecretVersionV2(
            Guid.NewGuid(),
            Guid.NewGuid(),
            secret,
            TotpAlgorithm.Sha256,
            8,
            60,
            "otpauth://totp/Example%3Aalice?secret=AEBAGBAFAYDQQCIKBMGA2DQPCAIREEYU&issuer=Example&algorithm=SHA256&digits=8&period=60",
            ProvisioningUriOrigin.CanonicalGenerated);

        Assert.Equal(secret, version.Secret.ToArray());
        Assert.Equal(SecretVersionState.Active, version.State);

        version.Dispose();
        Assert.Throws<ObjectDisposedException>(() => version.Secret.ToArray());
    }

    [Fact]
    public void SecretVersion_RetiredStateRequiresRetirementTime()
    {
        Assert.Throws<ArgumentException>(
            () => new SecretVersionV2(
                Guid.NewGuid(),
                Guid.NewGuid(),
                Enumerable.Range(1, 20).Select(value => (byte)value).ToArray(),
                TotpAlgorithm.Sha1,
                6,
                30,
                "otpauth://totp/Example%3Aalice?secret=AEBAGBAFAYDQQCIKBMGA2DQPCAIREEYU",
                ProvisioningUriOrigin.CanonicalGenerated,
                SecretVersionState.Retired));
    }
}
