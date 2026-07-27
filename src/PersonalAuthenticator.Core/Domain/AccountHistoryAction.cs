namespace PersonalAuthenticator.Core.Domain;

public enum AccountHistoryAction
{
    Migrated,
    Added,
    DisplayUpdated,
    FavouriteChanged,
    Reordered,
    Archived,
    Restored,
    SecretCandidateAdded,
    SecretActivated,
    DuplicateAddedSeparately,
    Imported,
}
