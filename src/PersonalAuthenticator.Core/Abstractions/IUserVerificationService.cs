namespace PersonalAuthenticator.Core.Abstractions;

public enum UserVerificationAvailability
{
    Available,
    DeviceNotPresent,
    NotConfigured,
    DisabledByPolicy,
    Unavailable,
}

public interface IUserVerificationService
{
    Task<UserVerificationAvailability> GetAvailabilityAsync();

    Task<bool> RequestAsync(string message, CancellationToken cancellationToken);
}
