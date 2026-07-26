using PersonalAuthenticator.Core.Abstractions;
using Windows.Security.Credentials.UI;

namespace PersonalAuthenticator.Infrastructure.Windows;

public sealed class WindowsUserVerificationService : IUserVerificationService
{
    public async Task<UserVerificationAvailability> GetAvailabilityAsync()
    {
        UserConsentVerifierAvailability availability = await UserConsentVerifier.CheckAvailabilityAsync();
        return availability switch
        {
            UserConsentVerifierAvailability.Available => UserVerificationAvailability.Available,
            UserConsentVerifierAvailability.DeviceNotPresent => UserVerificationAvailability.DeviceNotPresent,
            UserConsentVerifierAvailability.NotConfiguredForUser => UserVerificationAvailability.NotConfigured,
            UserConsentVerifierAvailability.DisabledByPolicy => UserVerificationAvailability.DisabledByPolicy,
            _ => UserVerificationAvailability.Unavailable,
        };
    }

    public async Task<bool> RequestAsync(string message, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (await GetAvailabilityAsync() != UserVerificationAvailability.Available)
        {
            return true;
        }

        UserConsentVerificationResult result = await UserConsentVerifier.RequestVerificationAsync(message);
        cancellationToken.ThrowIfCancellationRequested();
        return result == UserConsentVerificationResult.Verified;
    }
}
