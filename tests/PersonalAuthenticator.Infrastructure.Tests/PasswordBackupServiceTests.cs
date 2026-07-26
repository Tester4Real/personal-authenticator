using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Logging.Abstractions;
using PersonalAuthenticator.Core.Domain;
using PersonalAuthenticator.Core.Exceptions;
using PersonalAuthenticator.Infrastructure.Backup;

namespace PersonalAuthenticator.Infrastructure.Tests;

public sealed class PasswordBackupServiceTests : IDisposable
{
    private const string Password = "correct horse battery staple";
    private readonly string _directory = Path.Combine(Path.GetTempPath(), $"pa-backup-tests-{Guid.NewGuid():N}");
    private readonly PasswordBackupService _service =
        new(NullLogger<PasswordBackupService>.Instance, iterations: 100_000);

    [Fact]
    public async Task ExportImport_RoundTripsWithoutPlaintextMetadata()
    {
        Directory.CreateDirectory(_directory);
        string path = Path.Combine(_directory, "roundtrip.pab");
        byte[] secret = RandomNumberGenerator.GetBytes(20);
        using var account = new TotpAccount(Guid.NewGuid(), "SecretIssuerMarker", "user@example.com", secret);

        await _service.ExportAsync(
            path,
            Password.AsMemory(),
            [account],
            overwriteExisting: false,
            TestContext.Current.CancellationToken);
        byte[] exported = await File.ReadAllBytesAsync(path, TestContext.Current.CancellationToken);
        Assert.False(exported.AsSpan().IndexOf(secret) >= 0);
        Assert.DoesNotContain(Encoding.UTF8.GetBytes("SecretIssuerMarker"), exported);
        Assert.DoesNotContain(Encoding.UTF8.GetBytes("user@example.com"), exported);

        IReadOnlyList<TotpAccount> imported = await _service.ImportAsync(
            path,
            Password.AsMemory(),
            TestContext.Current.CancellationToken);
        try
        {
            TotpAccount restored = Assert.Single(imported);
            Assert.Equal(secret, restored.Secret.ToArray());
            Assert.Equal("SecretIssuerMarker", restored.Issuer);
        }
        finally
        {
            foreach (TotpAccount item in imported)
            {
                item.Dispose();
            }
        }
    }

    [Fact]
    public async Task WrongPassword_IsRejectedWithoutSensitiveMessage()
    {
        Directory.CreateDirectory(_directory);
        string path = Path.Combine(_directory, "wrong-password.pab");
        using var account = new TotpAccount(Guid.NewGuid(), "Example", "user", RandomNumberGenerator.GetBytes(20));
        await _service.ExportAsync(
            path,
            Password.AsMemory(),
            [account],
            overwriteExisting: false,
            TestContext.Current.CancellationToken);

        SafeApplicationException exception = await Assert.ThrowsAsync<SafeApplicationException>(
            () => _service.ImportAsync(
                path,
                "another valid password".AsMemory(),
                TestContext.Current.CancellationToken));

        Assert.Equal("Backup.AuthenticationFailed", exception.ErrorCode);
        Assert.DoesNotContain(Password, exception.ToString(), StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(-1)]
    [InlineData(-17)]
    public async Task ModifiedCiphertextOrTag_IsRejected(int offsetFromEnd)
    {
        Directory.CreateDirectory(_directory);
        string path = Path.Combine(_directory, $"tampered-{offsetFromEnd}.pab");
        using var account = new TotpAccount(Guid.NewGuid(), "Example", "user", RandomNumberGenerator.GetBytes(20));
        await _service.ExportAsync(
            path,
            Password.AsMemory(),
            [account],
            overwriteExisting: false,
            TestContext.Current.CancellationToken);
        byte[] bytes = await File.ReadAllBytesAsync(path, TestContext.Current.CancellationToken);
        bytes[bytes.Length + offsetFromEnd] ^= 0x01;
        await File.WriteAllBytesAsync(path, bytes, TestContext.Current.CancellationToken);

        await Assert.ThrowsAsync<SafeApplicationException>(
            () => _service.ImportAsync(path, Password.AsMemory(), TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task RepeatedExports_UseDifferentSaltAndNonce()
    {
        Directory.CreateDirectory(_directory);
        using var account = new TotpAccount(Guid.NewGuid(), "Example", "user", RandomNumberGenerator.GetBytes(20));
        string firstPath = Path.Combine(_directory, "first.pab");
        string secondPath = Path.Combine(_directory, "second.pab");
        await _service.ExportAsync(
            firstPath,
            Password.AsMemory(),
            [account],
            overwriteExisting: false,
            TestContext.Current.CancellationToken);
        await _service.ExportAsync(
            secondPath,
            Password.AsMemory(),
            [account],
            overwriteExisting: false,
            TestContext.Current.CancellationToken);
        byte[] first = await File.ReadAllBytesAsync(firstPath, TestContext.Current.CancellationToken);
        byte[] second = await File.ReadAllBytesAsync(secondPath, TestContext.Current.CancellationToken);

        Assert.NotEqual(first.AsSpan(24, 28).ToArray(), second.AsSpan(24, 28).ToArray());
        Assert.NotEqual(first, second);
    }

    [Fact]
    public async Task TruncatedFile_IsRejected()
    {
        Directory.CreateDirectory(_directory);
        string path = Path.Combine(_directory, "truncated.pab");
        await File.WriteAllBytesAsync(path, "PABKUP01"u8.ToArray(), TestContext.Current.CancellationToken);

        await Assert.ThrowsAsync<SafeApplicationException>(
            () => _service.ImportAsync(path, Password.AsMemory(), TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task ModifiedAuthenticatedHeader_IsRejected()
    {
        Directory.CreateDirectory(_directory);
        string path = Path.Combine(_directory, "tampered-header.pab");
        using var account = new TotpAccount(Guid.NewGuid(), "Example", "user", RandomNumberGenerator.GetBytes(20));
        await _service.ExportAsync(
            path,
            Password.AsMemory(),
            [account],
            overwriteExisting: false,
            TestContext.Current.CancellationToken);
        byte[] bytes = await File.ReadAllBytesAsync(path, TestContext.Current.CancellationToken);
        bytes[24] ^= 0x01;
        await File.WriteAllBytesAsync(path, bytes, TestContext.Current.CancellationToken);

        SafeApplicationException exception = await Assert.ThrowsAsync<SafeApplicationException>(
            () => _service.ImportAsync(path, Password.AsMemory(), TestContext.Current.CancellationToken));

        Assert.Equal("Backup.AuthenticationFailed", exception.ErrorCode);
    }

    [Fact]
    public async Task InvalidFormatVersion_IsRejected()
    {
        Directory.CreateDirectory(_directory);
        string path = Path.Combine(_directory, "invalid-version.pab");
        using var account = new TotpAccount(Guid.NewGuid(), "Example", "user", RandomNumberGenerator.GetBytes(20));
        await _service.ExportAsync(
            path,
            Password.AsMemory(),
            [account],
            overwriteExisting: false,
            TestContext.Current.CancellationToken);
        byte[] bytes = await File.ReadAllBytesAsync(path, TestContext.Current.CancellationToken);
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(8, 2), 2);
        await File.WriteAllBytesAsync(path, bytes, TestContext.Current.CancellationToken);

        SafeApplicationException exception = await Assert.ThrowsAsync<SafeApplicationException>(
            () => _service.ImportAsync(path, Password.AsMemory(), TestContext.Current.CancellationToken));

        Assert.Equal("Backup.UnsupportedVersion", exception.ErrorCode);
    }

    [Fact]
    public async Task ExistingFile_RequiresExplicitOverwrite()
    {
        Directory.CreateDirectory(_directory);
        string path = Path.Combine(_directory, "existing.pab");
        await File.WriteAllTextAsync(path, "existing backup", TestContext.Current.CancellationToken);
        using var account = new TotpAccount(Guid.NewGuid(), "Example", "user", RandomNumberGenerator.GetBytes(20));

        SafeApplicationException exception = await Assert.ThrowsAsync<SafeApplicationException>(
            () => _service.ExportAsync(
                path,
                Password.AsMemory(),
                [account],
                overwriteExisting: false,
                TestContext.Current.CancellationToken));

        Assert.Equal("Backup.FileExists", exception.ErrorCode);
        Assert.Equal("existing backup", await File.ReadAllTextAsync(path, TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task ConfirmedOverwrite_ReplacesExistingFileAtomically()
    {
        Directory.CreateDirectory(_directory);
        string path = Path.Combine(_directory, "replace.pab");
        await File.WriteAllTextAsync(path, "existing backup", TestContext.Current.CancellationToken);
        await File.WriteAllTextAsync(path + ".previous", "unrelated file", TestContext.Current.CancellationToken);
        using var account = new TotpAccount(Guid.NewGuid(), "Example", "user", RandomNumberGenerator.GetBytes(20));

        await _service.ExportAsync(
            path,
            Password.AsMemory(),
            [account],
            overwriteExisting: true,
            TestContext.Current.CancellationToken);

        byte[] bytes = await File.ReadAllBytesAsync(path, TestContext.Current.CancellationToken);
        Assert.True(bytes.AsSpan().StartsWith("PABKUP01"u8));
        Assert.Equal(
            "unrelated file",
            await File.ReadAllTextAsync(path + ".previous", TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task CancelledOverwrite_PreservesExistingFile()
    {
        Directory.CreateDirectory(_directory);
        string path = Path.Combine(_directory, "cancelled-replace.pab");
        await File.WriteAllTextAsync(path, "existing backup", TestContext.Current.CancellationToken);
        using var account = new TotpAccount(Guid.NewGuid(), "Example", "user", RandomNumberGenerator.GetBytes(20));
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => _service.ExportAsync(
                path,
                Password.AsMemory(),
                [account],
                overwriteExisting: true,
                cancellation.Token));

        Assert.Equal("existing backup", await File.ReadAllTextAsync(path, TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task OversizedDeclaredCiphertext_IsRejectedAsSafeFormatError()
    {
        Directory.CreateDirectory(_directory);
        string path = Path.Combine(_directory, "oversized-length.pab");
        byte[] envelope = new byte[68];
        "PABKUP01"u8.CopyTo(envelope);
        BinaryPrimitives.WriteUInt16LittleEndian(envelope.AsSpan(8, 2), 1);
        envelope[10] = 1;
        BinaryPrimitives.WriteInt32LittleEndian(envelope.AsSpan(12, 4), 100_000);
        envelope[16] = 16;
        envelope[17] = 12;
        envelope[18] = 16;
        BinaryPrimitives.WriteInt32LittleEndian(envelope.AsSpan(20, 4), int.MaxValue);
        await File.WriteAllBytesAsync(path, envelope, TestContext.Current.CancellationToken);

        SafeApplicationException exception = await Assert.ThrowsAsync<SafeApplicationException>(
            () => _service.ImportAsync(path, Password.AsMemory(), TestContext.Current.CancellationToken));

        Assert.Equal("Backup.InvalidLength", exception.ErrorCode);
    }

    public void Dispose()
    {
        if (Directory.Exists(_directory))
        {
            Directory.Delete(_directory, recursive: true);
        }
    }
}
