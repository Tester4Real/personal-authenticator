namespace PersonalAuthenticator.Infrastructure.Security;

internal enum SecurityCheckpoint
{
    AfterPendingEpochPersisted,
    AfterReplacementVaultWritten,
    AfterReplacementVaultVerified,
    AfterRecoveryRotated,
    BeforeEpochActivation,
    AfterPurgePendingPersisted,
}
