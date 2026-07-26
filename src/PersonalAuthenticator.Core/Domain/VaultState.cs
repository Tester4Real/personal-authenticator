namespace PersonalAuthenticator.Core.Domain;

public enum VaultState
{
    Uninitialised,
    Locked,
    Unlocking,
    Unlocked,
    Locking,
    Faulted,
}
