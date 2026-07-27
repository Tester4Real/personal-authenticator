namespace PersonalAuthenticator.Core.Domain;

public sealed record DuplicateAccountMatch(Guid ExistingAccountId, DuplicateMatchKind Kind);
