namespace PersonalAuthenticator.Infrastructure.Storage;

internal sealed record ActiveVaultPointer(
    ActiveVaultMode Mode,
    string StoreFileName,
    string? LegacySourceSha256,
    DateTimeOffset ActivatedAtUtc);
