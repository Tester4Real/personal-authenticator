namespace PersonalAuthenticator.Infrastructure.Sync;

internal sealed record SyncDeviceActivity(
    Guid DeviceId,
    DateTimeOffset FirstSeenAtUtc,
    DateTimeOffset LastSeenAtUtc,
    long HighestSequence);
