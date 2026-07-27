using System.Security.Cryptography;
using System.Text.Json;
using PersonalAuthenticator.Core.Domain;
using PersonalAuthenticator.Core.Exceptions;
using PersonalAuthenticator.Infrastructure.Storage;

namespace PersonalAuthenticator.Infrastructure.Recovery;

internal sealed class RecoveryHealthStore
{
    private static readonly byte[] Entropy =
        SHA256.HashData("Personal Authenticator recovery health v1"u8);
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        MaxDepth = 8,
    };
    private readonly string _statePath;

    public RecoveryHealthStore(string statePath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(statePath);
        _statePath = Path.GetFullPath(statePath);
    }

    public async Task<RecoveryVerificationState?> LoadAsync(
        CancellationToken cancellationToken)
    {
        if (!File.Exists(_statePath))
        {
            return null;
        }

        byte[] protectedBytes = [];
        byte[] plaintext = [];
        try
        {
            protectedBytes = await File.ReadAllBytesAsync(_statePath, cancellationToken);
            if (protectedBytes.Length is < 16 or > 64 * 1024)
            {
                throw InvalidState();
            }

            plaintext = ProtectedData.Unprotect(
                protectedBytes,
                Entropy,
                DataProtectionScope.CurrentUser);
            RecoveryVerificationState? state =
                JsonSerializer.Deserialize<RecoveryVerificationState>(plaintext, JsonOptions);
            Validate(state);
            return state;
        }
        catch (SafeApplicationException)
        {
            throw;
        }
        catch (Exception exception) when (
            exception is IOException or CryptographicException or JsonException)
        {
            throw new SafeApplicationException(
                "Recovery.HealthInvalid",
                "Recovery health information is unavailable or corrupt.",
                exception);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(protectedBytes);
            CryptographicOperations.ZeroMemory(plaintext);
        }
    }

    public async Task SaveAsync(
        RecoveryVerificationState state,
        CancellationToken cancellationToken)
    {
        Validate(state);
        byte[] plaintext = JsonSerializer.SerializeToUtf8Bytes(state, JsonOptions);
        byte[] protectedBytes = [];
        try
        {
            protectedBytes = ProtectedData.Protect(
                plaintext,
                Entropy,
                DataProtectionScope.CurrentUser);
            await AtomicFile.WriteAsync(
                _statePath,
                protectedBytes,
                retainPrevious: true,
                overwriteExisting: true,
                cancellationToken);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext);
            CryptographicOperations.ZeroMemory(protectedBytes);
        }
    }

    private static void Validate(RecoveryVerificationState? state)
    {
        if (state is null ||
            !Enum.IsDefined(state.Slot) ||
            state.VerifiedSequence < 0 ||
            state.VerifiedAtUtc == default ||
            string.IsNullOrWhiteSpace(state.BundleSha256) ||
            state.BundleSha256.Length != 64 ||
            !state.BundleSha256.All(Uri.IsHexDigit) ||
            string.IsNullOrWhiteSpace(state.FilePath) ||
            state.FilePath.Length > 1024 ||
            !Path.IsPathFullyQualified(state.FilePath))
        {
            throw InvalidState();
        }
    }

    private static SafeApplicationException InvalidState() =>
        new(
            "Recovery.HealthInvalid",
            "Recovery health information is unavailable or corrupt.");
}

internal sealed record RecoveryVerificationState(
    RecoverySlot Slot,
    string FilePath,
    long VerifiedSequence,
    DateTimeOffset VerifiedAtUtc,
    string BundleSha256);
