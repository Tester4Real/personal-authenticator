namespace PersonalAuthenticator.Infrastructure.Sync;

internal enum LocalSyncCheckpoint
{
    BeforeObjectWrite,
    AfterObjectWriteBeforeVerification,
    BeforeObjectRead,
}
