namespace PersonalAuthenticator.Core.Domain;

public enum VaultMigrationChoice
{
    UpgradeToV2,
    ContinueUsingV1,
    Cancel,
}
