namespace PersonalAuthenticator.Core.Domain;

public sealed record ArchivedAccountSummary(
    Guid Id,
    string Issuer,
    string AccountName,
    DateTimeOffset ArchivedAtUtc);
