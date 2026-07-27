namespace PersonalAuthenticator.Core.Domain;

public sealed record SecretVersionSummary(
    Guid Id,
    SecretVersionState State,
    TotpAlgorithm Algorithm,
    int Digits,
    int Period,
    DateTimeOffset CreatedAtUtc,
    DateTimeOffset? RetiredAtUtc);
