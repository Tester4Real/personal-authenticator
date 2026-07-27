using System.Security.Cryptography;
using PersonalAuthenticator.Core.Domain;
using PersonalAuthenticator.Core.Exceptions;

namespace PersonalAuthenticator.Infrastructure.Storage;

internal static class VaultAccountVerifier
{
    public static void VerifyEquivalent(
        IReadOnlyCollection<TotpAccount> expected,
        IReadOnlyCollection<TotpAccount> actual)
    {
        if (expected.Count != actual.Count)
        {
            throw VerificationFailed();
        }

        Dictionary<Guid, TotpAccount> actualById;
        try
        {
            actualById = actual.ToDictionary(account => account.Id);
        }
        catch (ArgumentException exception)
        {
            throw new SafeApplicationException(
                "VaultMigration.VerificationFailed",
                "The migrated vault contains duplicate identifiers.",
                exception);
        }

        foreach (TotpAccount source in expected)
        {
            if (!actualById.TryGetValue(source.Id, out TotpAccount? migrated) ||
                !string.Equals(source.Issuer, migrated.Issuer, StringComparison.Ordinal) ||
                !string.Equals(
                    source.AccountName,
                    migrated.AccountName,
                    StringComparison.Ordinal) ||
                source.Algorithm != migrated.Algorithm ||
                source.Digits != migrated.Digits ||
                source.Period != migrated.Period ||
                source.Favourite != migrated.Favourite ||
                source.SortOrder != migrated.SortOrder ||
                source.CreatedAtUtc != migrated.CreatedAtUtc ||
                source.UpdatedAtUtc != migrated.UpdatedAtUtc ||
                !CryptographicOperations.FixedTimeEquals(source.Secret, migrated.Secret))
            {
                throw VerificationFailed();
            }
        }
    }

    private static SafeApplicationException VerificationFailed() =>
        new(
            "VaultMigration.VerificationFailed",
            "The migrated vault did not match the verified source vault.");
}
