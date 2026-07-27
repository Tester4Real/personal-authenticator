namespace PersonalAuthenticator.Core.Domain;

public enum SyncConflictResolution
{
    KeepA = 0,
    KeepB = 1,
    KeepBoth = 2,
    SeparateAccounts = 3,
}
