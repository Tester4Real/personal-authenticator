using System.Text;
using PersonalAuthenticator.Core.Domain;
using PersonalAuthenticator.Core.Exceptions;
using PersonalAuthenticator.Infrastructure.Serialization;

namespace PersonalAuthenticator.Infrastructure.Tests;

public sealed class VaultJsonSerializerTests
{
    [Fact]
    public void Serialize_KnownAccount_MatchesFrozenV1Payload()
    {
        using var account = new TotpAccount(
            Guid.Parse("f3a1d235-a58d-4401-a4f8-75d7cfc8513c"),
            "Example",
            "alice",
            Enumerable.Range(1, 20).Select(value => (byte)value).ToArray(),
            TotpAlgorithm.Sha256,
            digits: 8,
            period: 60,
            favourite: true,
            sortOrder: 2,
            createdAtUtc: new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero),
            updatedAtUtc: new DateTimeOffset(2026, 1, 2, 3, 4, 5, TimeSpan.Zero));

        byte[] payload = VaultJsonSerializer.Serialize([account]);

        Assert.Equal(
            """
            {"formatVersion":1,"accounts":[{"id":"f3a1d235-a58d-4401-a4f8-75d7cfc8513c","issuer":"Example","accountName":"alice","secretBytes":"AQIDBAUGBwgJCgsMDQ4PEBESExQ=","algorithm":1,"digits":8,"period":60,"favourite":true,"sortOrder":2,"createdAtUtc":"2026-01-01T00:00:00+00:00","updatedAtUtc":"2026-01-02T03:04:05+00:00"}]}
            """,
            Encoding.UTF8.GetString(payload));
    }

    [Fact]
    public void Deserialize_FrozenV1Payload_RestoresEveryField()
    {
        byte[] payload = Encoding.UTF8.GetBytes(
            """
            {"formatVersion":1,"accounts":[{"id":"f3a1d235-a58d-4401-a4f8-75d7cfc8513c","issuer":"Example","accountName":"alice","secretBytes":"AQIDBAUGBwgJCgsMDQ4PEBESExQ=","algorithm":1,"digits":8,"period":60,"favourite":true,"sortOrder":2,"createdAtUtc":"2026-01-01T00:00:00+00:00","updatedAtUtc":"2026-01-02T03:04:05+00:00"}]}
            """);

        IReadOnlyList<TotpAccount> accounts = VaultJsonSerializer.Deserialize(payload);

        TotpAccount account = Assert.Single(accounts);
        try
        {
            Assert.Equal(Guid.Parse("f3a1d235-a58d-4401-a4f8-75d7cfc8513c"), account.Id);
            Assert.Equal("Example", account.Issuer);
            Assert.Equal("alice", account.AccountName);
            Assert.Equal(Enumerable.Range(1, 20).Select(value => (byte)value), account.Secret.ToArray());
            Assert.Equal(TotpAlgorithm.Sha256, account.Algorithm);
            Assert.Equal(8, account.Digits);
            Assert.Equal(60, account.Period);
            Assert.True(account.Favourite);
            Assert.Equal(2, account.SortOrder);
            Assert.Equal(new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero), account.CreatedAtUtc);
            Assert.Equal(new DateTimeOffset(2026, 1, 2, 3, 4, 5, TimeSpan.Zero), account.UpdatedAtUtc);
        }
        finally
        {
            account.Dispose();
        }
    }

    [Fact]
    public void Deserialize_UndefinedAlgorithm_IsRejected()
    {
        byte[] payload = Encoding.UTF8.GetBytes(
            """
            {
              "formatVersion": 1,
              "accounts": [
                {
                  "id": "f3a1d235-a58d-4401-a4f8-75d7cfc8513c",
                  "issuer": "Example",
                  "accountName": "alice",
                  "secretBytes": "AAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                  "algorithm": 999,
                  "digits": 6,
                  "period": 30,
                  "favourite": false,
                  "sortOrder": 0,
                  "createdAtUtc": "2026-01-01T00:00:00+00:00",
                  "updatedAtUtc": "2026-01-01T00:00:00+00:00"
                }
              ]
            }
            """);

        SafeApplicationException exception = Assert.Throws<SafeApplicationException>(
            () => VaultJsonSerializer.Deserialize(payload));

        Assert.Equal("Vault.InvalidAccount", exception.ErrorCode);
    }
}
