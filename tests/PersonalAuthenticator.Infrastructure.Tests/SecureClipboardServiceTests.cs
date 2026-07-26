using Microsoft.Extensions.Logging.Abstractions;
using PersonalAuthenticator.Infrastructure.Clipboard;

namespace PersonalAuthenticator.Infrastructure.Tests;

public sealed class SecureClipboardServiceTests
{
    [Fact]
    public async Task CallerCancellation_DoesNotCancelAutomaticClear()
    {
        var clipboard = new FakeClipboardAdapter();
        await using var service = new SecureClipboardService(
            NullLogger<SecureClipboardService>.Instance,
            clipboard);
        using var callerCancellation = new CancellationTokenSource();

        await service.CopyCodeAsync(
            "123456",
            TimeSpan.FromMilliseconds(20),
            callerCancellation.Token);
        callerCancellation.Cancel();
        await Task.Delay(200, TestContext.Current.CancellationToken);

        Assert.Null(clipboard.Content);
        Assert.Equal(1, clipboard.ClearCount);
    }

    [Fact]
    public async Task CancelPendingClear_ClearsOwnedCodeImmediately()
    {
        var clipboard = new FakeClipboardAdapter();
        await using var service = new SecureClipboardService(
            NullLogger<SecureClipboardService>.Instance,
            clipboard);
        await service.CopyCodeAsync(
            "123456",
            TimeSpan.FromMinutes(1),
            TestContext.Current.CancellationToken);

        await service.CancelPendingClearAsync();

        Assert.Null(clipboard.Content);
        Assert.Equal(1, clipboard.ClearCount);
    }

    [Fact]
    public async Task CancelPendingClear_DoesNotEraseSameCodeWithDifferentOwner()
    {
        var clipboard = new FakeClipboardAdapter();
        await using var service = new SecureClipboardService(
            NullLogger<SecureClipboardService>.Instance,
            clipboard);
        await service.CopyCodeAsync(
            "123456",
            TimeSpan.FromMinutes(1),
            TestContext.Current.CancellationToken);
        clipboard.Content = new OwnedClipboardContent("123456", "DIFFERENT-OWNER");

        await service.CancelPendingClearAsync();

        Assert.NotNull(clipboard.Content);
        Assert.Equal(0, clipboard.ClearCount);
    }

    private sealed class FakeClipboardAdapter : IClipboardAdapter
    {
        public OwnedClipboardContent? Content { get; set; }

        public int ClearCount { get; private set; }

        public void SetOwnedCode(string code, string ownershipMarker) =>
            Content = new OwnedClipboardContent(code, ownershipMarker);

        public Task<OwnedClipboardContent?> ReadOwnedContentAsync() =>
            Task.FromResult(Content);

        public void Clear()
        {
            Content = null;
            ClearCount++;
        }
    }
}
