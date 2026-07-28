namespace PersonalAuthenticator.Core.Domain;

public sealed record AuthorisedDeviceInfo(
    Guid DeviceId,
    string DisplayName,
    bool IsCurrent,
    bool IsRevoked,
    DateTimeOffset FirstSeenAtUtc,
    DateTimeOffset LastSeenAtUtc,
    long HighestSequence,
    DateTimeOffset? RevokedAtUtc,
    long? RevokedAfterSequence);
