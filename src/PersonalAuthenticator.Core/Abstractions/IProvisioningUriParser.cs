using PersonalAuthenticator.Core.Domain;

namespace PersonalAuthenticator.Core.Abstractions;

public interface IProvisioningUriParser
{
    ParsedTotpProvisioning Parse(string provisioningUri);

    ParsedTotpProvisioning ParseManual(
        string issuer,
        string accountName,
        string base32Secret,
        TotpAlgorithm algorithm,
        int digits,
        int period);
}
