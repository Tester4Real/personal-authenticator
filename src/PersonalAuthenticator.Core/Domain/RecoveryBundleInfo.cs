namespace PersonalAuthenticator.Core.Domain;

public sealed record RecoveryBundleInfo(
    RecoverySlot Slot,
    string FilePath,
    DateTimeOffset CreatedAtUtc,
    DateTimeOffset VerifiedAtUtc,
    long ChangeSequence,
    int AccountCount,
    int SecretVersionCount,
    int HistoryEntryCount);
