using Microsoft.Win32;
using PersonalAuthenticator.Core.Abstractions;

namespace PersonalAuthenticator.Infrastructure.Windows;

public sealed class WindowsSessionLockMonitor : IAutomaticLockMonitor
{
    private bool _started;
    private bool _disposed;

    public event EventHandler? LockRequested;

    public void Start()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (_started)
        {
            return;
        }

        SystemEvents.SessionSwitch += OnSessionSwitch;
        SystemEvents.PowerModeChanged += OnPowerModeChanged;
        _started = true;
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        if (_started)
        {
            SystemEvents.SessionSwitch -= OnSessionSwitch;
            SystemEvents.PowerModeChanged -= OnPowerModeChanged;
        }

        _disposed = true;
    }

    private void OnSessionSwitch(object sender, SessionSwitchEventArgs args)
    {
        if (args.Reason == SessionSwitchReason.SessionLock)
        {
            LockRequested?.Invoke(this, EventArgs.Empty);
        }
    }

    private void OnPowerModeChanged(object sender, PowerModeChangedEventArgs args)
    {
        if (args.Mode == PowerModes.Suspend)
        {
            LockRequested?.Invoke(this, EventArgs.Empty);
        }
    }
}
