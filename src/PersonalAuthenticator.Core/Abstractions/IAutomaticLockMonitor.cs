namespace PersonalAuthenticator.Core.Abstractions;

public interface IAutomaticLockMonitor : IDisposable
{
    event EventHandler? LockRequested;

    void Start();
}
