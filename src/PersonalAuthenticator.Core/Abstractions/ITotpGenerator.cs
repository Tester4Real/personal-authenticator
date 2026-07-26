using PersonalAuthenticator.Core.Domain;

namespace PersonalAuthenticator.Core.Abstractions;

public interface ITotpGenerator
{
    string Generate(TotpAccount account, DateTimeOffset timestamp);

    int GetSecondsRemaining(TotpAccount account, DateTimeOffset timestamp);

    long GetTimeStep(TotpAccount account, DateTimeOffset timestamp);
}
