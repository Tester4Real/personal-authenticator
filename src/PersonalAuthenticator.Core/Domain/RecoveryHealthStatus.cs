namespace PersonalAuthenticator.Core.Domain;

public sealed record RecoveryHealthStatus(
    bool HasVerifiedRecovery,
    bool IsOutdated,
    long ChangesSinceVerifiedRecovery,
    DateTimeOffset? LastVerifiedAtUtc,
    RecoverySlot? LastVerifiedSlot,
    string? LastVerifiedFilePath)
{
    public static RecoveryHealthStatus Missing { get; } =
        new(false, true, 0, null, null, null);
}
