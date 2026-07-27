namespace PersonalAuthenticator.Core.Domain;

public enum SecretVersionState
{
    Active = 0,
    Candidate = 1,
    Retired = 2,
}
