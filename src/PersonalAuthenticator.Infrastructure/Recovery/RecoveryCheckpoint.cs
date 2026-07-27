namespace PersonalAuthenticator.Infrastructure.Recovery;

internal enum RecoveryCheckpoint
{
    BeforeSlotWrite,
    AfterSlotWriteBeforeVerification,
    AfterVerificationBeforeActivation,
    AfterActivationBeforeHealthUpdate,
    BeforeRecoveredVaultWrite,
    AfterRecoveredVaultVerificationBeforeActivation,
}
