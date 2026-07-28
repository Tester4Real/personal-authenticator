using System.Security.Cryptography;
using System.Text.Json;
using PersonalAuthenticator.Core.Exceptions;
using PersonalAuthenticator.Infrastructure.Storage;

namespace PersonalAuthenticator.Infrastructure.Security;

internal sealed class SecurityStateStore
{
    private static readonly byte[] Entropy =
        SHA256.HashData("Personal Authenticator security epochs v1"u8);
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        MaxDepth = 16,
    };
    private readonly string _path;

    public SecurityStateStore(string path) => _path = Path.GetFullPath(path);

    public async Task<SecurityState> LoadAsync(
        CancellationToken cancellationToken)
    {
        if (!File.Exists(_path))
        {
            return new SecurityState();
        }

        byte[] envelope = [];
        byte[] plaintext = [];
        try
        {
            envelope = await File.ReadAllBytesAsync(_path, cancellationToken);
            if (envelope.Length is < 32 or > 4 * 1024 * 1024)
            {
                throw InvalidState();
            }

            plaintext = ProtectedData.Unprotect(
                envelope,
                Entropy,
                DataProtectionScope.CurrentUser);
            SecurityState? state =
                JsonSerializer.Deserialize<SecurityState>(plaintext, JsonOptions);
            Validate(state);
            return state!;
        }
        catch (SafeApplicationException)
        {
            throw;
        }
        catch (Exception exception) when (
            exception is IOException or
                CryptographicException or
                JsonException or
                ArgumentException)
        {
            throw new SafeApplicationException(
                "Security.StateUnavailable",
                "The protected device and key-epoch state is unavailable.",
                exception);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(envelope);
            CryptographicOperations.ZeroMemory(plaintext);
        }
    }

    public async Task SaveAsync(
        SecurityState state,
        CancellationToken cancellationToken)
    {
        Validate(state);
        byte[] plaintext = JsonSerializer.SerializeToUtf8Bytes(state, JsonOptions);
        byte[] envelope = [];
        try
        {
            envelope = ProtectedData.Protect(
                plaintext,
                Entropy,
                DataProtectionScope.CurrentUser);
            await AtomicFile.WriteAsync(
                _path,
                envelope,
                retainPrevious: true,
                overwriteExisting: true,
                cancellationToken);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext);
            CryptographicOperations.ZeroMemory(envelope);
        }
    }

    private static void Validate(SecurityState? state)
    {
        if (state is null ||
            state.ActiveEpoch < 1 ||
            state.PendingEpoch is < 1 ||
            state.Devices.Count > 10_000 ||
            state.Devices.Any(pair =>
                pair.Key == Guid.Empty ||
                pair.Value.DisplayName.Length is < 1 or > 80 ||
                pair.Value.HighestSequence < 0 ||
                pair.Value.RevokedAfterSequence is < 0))
        {
            throw InvalidState();
        }
    }

    private static SafeApplicationException InvalidState() =>
        new(
            "Security.StateInvalid",
            "The protected device and key-epoch state is invalid.");
}

internal sealed class SecurityState
{
    public int ActiveEpoch { get; set; } = 1;

    public int? PendingEpoch { get; set; }

    public Guid? PurgeAccountId { get; set; }

    public string? LastFailure { get; set; }

    public Dictionary<Guid, SecurityDeviceState> Devices { get; set; } = [];
}

internal sealed class SecurityDeviceState
{
    public string DisplayName { get; set; } = "Windows device";

    public DateTimeOffset FirstSeenAtUtc { get; set; }

    public DateTimeOffset LastSeenAtUtc { get; set; }

    public long HighestSequence { get; set; }

    public DateTimeOffset? RevokedAtUtc { get; set; }

    public long? RevokedAfterSequence { get; set; }
}
