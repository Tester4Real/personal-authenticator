using Microsoft.Extensions.Logging;

namespace PersonalAuthenticator.Infrastructure.Logging;

internal static partial class InfrastructureLog
{
    [LoggerMessage(EventId = 1001, Level = LogLevel.Error, Message = "Vault read failed with {ErrorType}.")]
    public static partial void VaultReadFailed(ILogger logger, Exception exception, string errorType);

    [LoggerMessage(EventId = 1002, Level = LogLevel.Warning, Message = "Vault decryption failed with {ErrorType}.")]
    public static partial void VaultDecryptionFailed(ILogger logger, string errorType);

    [LoggerMessage(EventId = 1003, Level = LogLevel.Information, Message = "Encrypted vault saved. AccountCount={AccountCount}.")]
    public static partial void VaultSaved(ILogger logger, int accountCount);

    [LoggerMessage(EventId = 1004, Level = LogLevel.Error, Message = "Vault write failed with {ErrorType}.")]
    public static partial void VaultWriteFailed(ILogger logger, Exception exception, string errorType);

    [LoggerMessage(EventId = 2001, Level = LogLevel.Information, Message = "Encrypted portable backup exported. AccountCount={AccountCount}.")]
    public static partial void BackupExported(ILogger logger, int accountCount);

    [LoggerMessage(EventId = 2002, Level = LogLevel.Warning, Message = "Portable backup authentication failed with {ErrorType}.")]
    public static partial void BackupAuthenticationFailed(ILogger logger, string errorType);

    [LoggerMessage(EventId = 3001, Level = LogLevel.Warning, Message = "Clipboard write failed with {ErrorType}.")]
    public static partial void ClipboardWriteFailed(ILogger logger, string errorType);

    [LoggerMessage(EventId = 3002, Level = LogLevel.Information, Message = "Clipboard code owned by this app was cleared.")]
    public static partial void ClipboardCleared(ILogger logger);

    [LoggerMessage(EventId = 3003, Level = LogLevel.Warning, Message = "Conditional clipboard clear failed with {ErrorType}.")]
    public static partial void ClipboardClearFailed(ILogger logger, string errorType);
}
