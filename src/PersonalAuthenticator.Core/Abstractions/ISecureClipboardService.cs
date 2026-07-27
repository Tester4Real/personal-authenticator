namespace PersonalAuthenticator.Core.Abstractions;

public interface ISecureClipboardService : IAsyncDisposable
{
    Task CopyCodeAsync(string code, TimeSpan clearAfter, CancellationToken cancellationToken);

    Task CopySensitiveTextAsync(
        string text,
        TimeSpan clearAfter,
        CancellationToken cancellationToken);

    Task CancelPendingClearAsync();
}
