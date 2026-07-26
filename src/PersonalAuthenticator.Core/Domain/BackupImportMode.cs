namespace PersonalAuthenticator.Core.Domain;

public enum BackupImportMode
{
    Merge,
    MergeReplaceDuplicates,
    MergeAddDuplicates,
    Replace,
}
