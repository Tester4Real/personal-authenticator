namespace PersonalAuthenticator.Core.Domain;

public enum AppTheme
{
    System,
    Light,
    Dark,
}

public sealed record AppSettings
{
    public AppTheme Theme { get; init; } = AppTheme.System;

    public int AutomaticLockMinutes { get; init; } = 5;

    public bool LockWhenMinimised { get; init; } = true;

    public bool LockWhenWindowsLocks { get; init; } = true;

    public bool HideCodesByDefault { get; init; }

    public int ClipboardClearSeconds { get; init; } = 30;

    public bool RequireVerificationForCodes { get; init; }

    public bool StartUnlocked { get; init; }
}
