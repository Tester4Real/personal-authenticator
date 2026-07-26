using Microsoft.Extensions.Logging;

namespace PersonalAuthenticator.App;

internal static partial class AppLog
{
    [LoggerMessage(EventId = 9001, Level = LogLevel.Error, Message = "Unhandled UI error. ErrorType={ErrorType}.")]
    public static partial void UnhandledUiError(ILogger logger, string errorType);
}
