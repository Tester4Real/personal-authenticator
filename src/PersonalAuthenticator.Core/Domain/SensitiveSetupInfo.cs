namespace PersonalAuthenticator.Core.Domain;

public sealed record SensitiveSetupInfo(
    Guid AccountId,
    string Issuer,
    string AccountName,
    string ProvisioningUri);
