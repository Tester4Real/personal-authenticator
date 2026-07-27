using System.Security.Cryptography;
using System.Text;
using PersonalAuthenticator.Core.Exceptions;
using PersonalAuthenticator.Infrastructure.Storage;

namespace PersonalAuthenticator.Infrastructure.GitHub;

internal sealed class GitHubCredentialStore
{
    private static readonly byte[] Entropy =
        SHA256.HashData("Personal Authenticator GitHub token v1"u8);
    private readonly string _path;

    public GitHubCredentialStore(string path) => _path = Path.GetFullPath(path);

    public bool Exists => File.Exists(_path);

    public async Task SaveAsync(
        ReadOnlyMemory<char> token,
        CancellationToken cancellationToken)
    {
        char[] characters = token.ToArray();
        byte[] plaintext = Encoding.UTF8.GetBytes(characters);
        byte[] protectedBytes = [];
        try
        {
            if (characters.Length is < 20 or > 1024 ||
                characters.Any(char.IsWhiteSpace))
            {
                throw new SafeApplicationException(
                    "GitHub.InvalidToken",
                    "Enter a valid fine-grained GitHub repository token.");
            }

            protectedBytes = ProtectedData.Protect(
                plaintext,
                Entropy,
                DataProtectionScope.CurrentUser);
            await AtomicFile.WriteAsync(
                _path,
                protectedBytes,
                retainPrevious: false,
                overwriteExisting: true,
                cancellationToken);
        }
        finally
        {
            Array.Clear(characters);
            CryptographicOperations.ZeroMemory(plaintext);
            CryptographicOperations.ZeroMemory(protectedBytes);
        }
    }

    public async Task<char[]> LoadAsync(CancellationToken cancellationToken)
    {
        byte[] protectedBytes = [];
        byte[] plaintext = [];
        try
        {
            protectedBytes = await File.ReadAllBytesAsync(_path, cancellationToken);
            if (protectedBytes.Length is < 32 or > 8192)
            {
                throw InvalidCredential();
            }

            plaintext = ProtectedData.Unprotect(
                protectedBytes,
                Entropy,
                DataProtectionScope.CurrentUser);
            return new UTF8Encoding(false, true).GetChars(plaintext);
        }
        catch (Exception exception) when (
            exception is IOException or
                CryptographicException or
                DecoderFallbackException)
        {
            throw new SafeApplicationException(
                "GitHub.CredentialUnavailable",
                "The stored GitHub credential is unavailable or invalid.",
                exception);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(protectedBytes);
            CryptographicOperations.ZeroMemory(plaintext);
        }
    }

    public void Delete()
    {
        if (File.Exists(_path))
        {
            File.Delete(_path);
        }
    }

    private static SafeApplicationException InvalidCredential() =>
        new(
            "GitHub.CredentialUnavailable",
            "The stored GitHub credential is unavailable or invalid.");
}
