using PersonalAuthenticator.Core.Abstractions;

namespace PersonalAuthenticator.Core.Services;

public sealed class SystemClock : IClock
{
    public DateTimeOffset UtcNow => DateTimeOffset.UtcNow;
}
