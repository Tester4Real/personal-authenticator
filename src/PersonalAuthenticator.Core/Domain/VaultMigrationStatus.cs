namespace PersonalAuthenticator.Core.Domain;

public enum VaultMigrationStatus
{
    NotRequired,
    ChoiceRequired,
    UsingLegacyV1,
    UsingLocalV2,
}
