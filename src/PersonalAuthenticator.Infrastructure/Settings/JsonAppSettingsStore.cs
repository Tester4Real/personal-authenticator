using System.Text.Json;
using PersonalAuthenticator.Core.Abstractions;
using PersonalAuthenticator.Core.Domain;
using PersonalAuthenticator.Core.Exceptions;
using PersonalAuthenticator.Infrastructure.Storage;

namespace PersonalAuthenticator.Infrastructure.Settings;

public sealed class JsonAppSettingsStore : IAppSettingsStore
{
    private static readonly JsonSerializerOptions Options = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = true,
    };

    private readonly string _path;

    public JsonAppSettingsStore(string? baseDirectory = null)
    {
        string directory = baseDirectory ??
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "PersonalAuthenticator");
        _path = Path.Combine(directory, "settings.json");
    }

    public async Task<AppSettings> LoadAsync(CancellationToken cancellationToken)
    {
        if (!File.Exists(_path))
        {
            return new AppSettings();
        }

        try
        {
            await using FileStream stream = File.OpenRead(_path);
            AppSettings? settings = await JsonSerializer.DeserializeAsync<AppSettings>(stream, Options, cancellationToken);
            return Validate(settings ?? new AppSettings());
        }
        catch (JsonException exception)
        {
            throw new SafeApplicationException("Settings.Invalid", "Application settings are corrupt.", exception);
        }
    }

    public async Task SaveAsync(AppSettings settings, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(settings);
        byte[] json = JsonSerializer.SerializeToUtf8Bytes(Validate(settings), Options);
        await AtomicFile.WriteAsync(
            _path,
            json,
            retainPrevious: false,
            overwriteExisting: true,
            cancellationToken);
    }

    private static AppSettings Validate(AppSettings settings)
    {
        if (settings.AutomaticLockMinutes is < 0 or > 1440)
        {
            throw new SafeApplicationException("Settings.InvalidAutoLock", "The automatic locking interval is invalid.");
        }

        if (settings.ClipboardClearSeconds is < 5 or > 300)
        {
            throw new SafeApplicationException("Settings.InvalidClipboardDelay", "The clipboard clearing delay is invalid.");
        }

        return settings;
    }
}
