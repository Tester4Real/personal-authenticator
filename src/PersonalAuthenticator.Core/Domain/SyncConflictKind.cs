namespace PersonalAuthenticator.Core.Domain;

public enum SyncConflictKind
{
    Metadata = 0,
    SecretAdded = 1,
    ActiveSecret = 2,
    RestoreVersusPurge = 3,
    DuplicateDecision = 4,
}
