using PersonalAuthenticator.Core.Domain;

namespace PersonalAuthenticator.Core.Abstractions;

public interface IAppSettingsStore
{
    Task<AppSettings> LoadAsync(CancellationToken cancellationToken);

    Task SaveAsync(AppSettings settings, CancellationToken cancellationToken);
}
