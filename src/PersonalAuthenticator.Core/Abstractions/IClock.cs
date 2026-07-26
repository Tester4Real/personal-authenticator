namespace PersonalAuthenticator.Core.Abstractions;

public interface IClock
{
    DateTimeOffset UtcNow { get; }
}
