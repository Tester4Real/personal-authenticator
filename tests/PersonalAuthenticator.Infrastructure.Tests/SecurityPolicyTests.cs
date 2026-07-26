using System.Security.Cryptography;
using Microsoft.Extensions.Logging;
using PersonalAuthenticator.Core.Domain;
using PersonalAuthenticator.Core.Exceptions;
using PersonalAuthenticator.Infrastructure.Backup;
using PersonalAuthenticator.Infrastructure.Logging;

namespace PersonalAuthenticator.Infrastructure.Tests;

public sealed class SecurityPolicyTests
{
    [Theory]
    [InlineData("otpauth://totp/example")]
    [InlineData("{\"secret\":\"example\"}")]
    [InlineData("backupPassword=value")]
    [InlineData("derivedKey=bytes")]
    [InlineData("clipboardContent=123456")]
    public void SensitiveMarker_IsDetected(string value)
    {
        Assert.True(SensitiveDataPolicy.ContainsForbiddenMarker(value));
    }

    [Fact]
    public void SafeOperationalMessage_IsAllowed()
    {
        Assert.False(SensitiveDataPolicy.ContainsForbiddenMarker(
            "Vault write failed with IOException. CorrelationId=abc123"));
    }

    [Fact]
    public async Task ActualBackupLogs_ExcludeUriSecretAndOtp()
    {
        const string provisioningUri =
            "otpauth://totp/SensitiveIssuer:123456?secret=JBSWY3DPEHPK3PXP&issuer=SensitiveIssuer";
        const string secretMarker = "JBSWY3DPEHPK3PXP";
        const string otpMarker = "123456";
        string directory = Path.Combine(Path.GetTempPath(), $"pa-log-tests-{Guid.NewGuid():N}");
        string path = Path.Combine(directory, "logging.pab");
        Directory.CreateDirectory(directory);
        var logger = new CapturingLogger<PasswordBackupService>();
        var service = new PasswordBackupService(logger, iterations: 100_000);
        using var account = new TotpAccount(
            Guid.NewGuid(),
            provisioningUri,
            otpMarker,
            RandomNumberGenerator.GetBytes(20));

        try
        {
            await service.ExportAsync(
                path,
                "correct horse battery staple".AsMemory(),
                [account],
                overwriteExisting: false,
                TestContext.Current.CancellationToken);
            await Assert.ThrowsAsync<SafeApplicationException>(
                () => service.ImportAsync(
                    path,
                    "different valid password".AsMemory(),
                    TestContext.Current.CancellationToken));

            string combined = string.Join(Environment.NewLine, logger.Messages);
            Assert.DoesNotContain(provisioningUri, combined, StringComparison.Ordinal);
            Assert.DoesNotContain(secretMarker, combined, StringComparison.Ordinal);
            Assert.DoesNotContain(otpMarker, combined, StringComparison.Ordinal);
            Assert.All(logger.Messages, message =>
                Assert.False(SensitiveDataPolicy.ContainsForbiddenMarker(message)));
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    private sealed class CapturingLogger<T> : ILogger<T>
    {
        public List<string> Messages { get; } = [];

        public IDisposable? BeginScope<TState>(TState state)
            where TState : notnull =>
            null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(
            LogLevel logLevel,
            EventId eventId,
            TState state,
            Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            Messages.Add(formatter(state, exception));
            if (exception is not null)
            {
                Messages.Add(exception.ToString());
            }
        }
    }
}
