namespace PersonalAuthenticator.Infrastructure.Logging;

public static class SensitiveDataPolicy
{
    private static readonly string[] ForbiddenMarkers =
    [
        "otpauth://",
        "\"secret\"",
        "backupPassword",
        "derivedKey",
        "clipboardContent",
    ];

    public static bool ContainsForbiddenMarker(string? value) =>
        value is not null &&
        ForbiddenMarkers.Any(marker => value.Contains(marker, StringComparison.OrdinalIgnoreCase));

    public static string SafeErrorType(Exception exception)
    {
        ArgumentNullException.ThrowIfNull(exception);
        return exception.GetType().Name;
    }
}
