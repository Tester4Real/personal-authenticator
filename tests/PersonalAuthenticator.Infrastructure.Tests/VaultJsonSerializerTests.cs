using System.Text;
using PersonalAuthenticator.Core.Exceptions;
using PersonalAuthenticator.Infrastructure.Serialization;

namespace PersonalAuthenticator.Infrastructure.Tests;

public sealed class VaultJsonSerializerTests
{
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
