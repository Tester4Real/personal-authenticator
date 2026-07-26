using PersonalAuthenticator.Core.Domain;

namespace PersonalAuthenticator.Core.Abstractions;

public interface IBackupService
{
    Task ExportAsync(
        string path,
        ReadOnlyMemory<char> password,
        IReadOnlyCollection<TotpAccount> accounts,
        bool overwriteExisting,
        CancellationToken cancellationToken);

    Task<IReadOnlyList<TotpAccount>> ImportAsync(
        string path,
        ReadOnlyMemory<char> password,
        CancellationToken cancellationToken);
}
