namespace PersonalAuthenticator.Infrastructure.Sync;

internal enum SyncOperationKind
{
    AccountAdded = 0,
    IssuerChanged = 1,
    AccountNameChanged = 2,
    FavouriteChanged = 3,
    SortOrderChanged = 4,
    ArchiveChanged = 5,
    SecretAdded = 6,
    ActiveSecretChanged = 7,
    HistoryAdded = 8,
    DuplicateDecision = 9,
    Purged = 10,
    ConflictResolved = 11,
}
