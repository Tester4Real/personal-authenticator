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
        await clipboard.Cleared.Task.WaitAsync(TestContext.Current.CancellationToken);

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

    [Fact]
    public async Task NaturalClear_ReleasesPendingOwnershipState()
    {
        var clipboard = new FakeClipboardAdapter();
        await using var service = new SecureClipboardService(
            NullLogger<SecureClipboardService>.Instance,
            clipboard);

        await service.CopyCodeAsync(
            "123456",
            TimeSpan.Zero,
            TestContext.Current.CancellationToken);
        await clipboard.Cleared.Task.WaitAsync(TestContext.Current.CancellationToken);
        int readsAfterNaturalClear = clipboard.ReadCount;

        await service.CancelPendingClearAsync();

        Assert.Equal(1, clipboard.ClearCount);
        Assert.Equal(readsAfterNaturalClear, clipboard.ReadCount);
    }

    [Fact]
    public async Task NewCopy_AfterNaturalClearOwnsIndependentPendingClear()
    {
        var clipboard = new FakeClipboardAdapter();
        await using var service = new SecureClipboardService(
            NullLogger<SecureClipboardService>.Instance,
            clipboard);

        await service.CopyCodeAsync(
            "123456",
            TimeSpan.Zero,
            TestContext.Current.CancellationToken);
        await clipboard.Cleared.Task.WaitAsync(TestContext.Current.CancellationToken);

        await service.CopyCodeAsync(
            "654321",
            TimeSpan.FromMinutes(1),
            TestContext.Current.CancellationToken);
        await service.CancelPendingClearAsync();

        Assert.Null(clipboard.Content);
        Assert.Equal(2, clipboard.ClearCount);
        Assert.Equal(2, clipboard.ReadCount);
    }

    [Fact]
    public async Task SensitiveText_IsConditionallyClearedLikeACode()
    {
        var clipboard = new FakeClipboardAdapter();
        await using var service = new SecureClipboardService(
            NullLogger<SecureClipboardService>.Instance,
            clipboard);
        const string setupUri =
            "otpauth://totp/Example:user?secret=JBSWY3DPEHPK3PXP&issuer=Example";

        await service.CopySensitiveTextAsync(
            setupUri,
            TimeSpan.Zero,
            TestContext.Current.CancellationToken);
        await clipboard.Cleared.Task.WaitAsync(TestContext.Current.CancellationToken);

        Assert.Null(clipboard.Content);
        Assert.Equal(1, clipboard.ClearCount);
    }

    [Fact]
    public async Task SensitiveText_RejectsClipboardTimeoutLongerThanOneMinute()
    {
        var clipboard = new FakeClipboardAdapter();
        await using var service = new SecureClipboardService(
            NullLogger<SecureClipboardService>.Instance,
            clipboard);

        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(
            () => service.CopySensitiveTextAsync(
                "otpauth://totp/Example:user?secret=JBSWY3DPEHPK3PXP",
                TimeSpan.FromSeconds(61),
                TestContext.Current.CancellationToken));
        Assert.Null(clipboard.Content);
    }

    [Fact]
    public async Task DisposeAsync_ClearsOwnedCodeAndRejectsLaterCopies()
    {
        var clipboard = new FakeClipboardAdapter();
        var service = new SecureClipboardService(
            NullLogger<SecureClipboardService>.Instance,
            clipboard);
        await service.CopyCodeAsync(
            "123456",
            TimeSpan.FromMinutes(1),
            TestContext.Current.CancellationToken);

        await service.DisposeAsync();

        Assert.Null(clipboard.Content);
        Assert.Equal(1, clipboard.ClearCount);
        await Assert.ThrowsAsync<ObjectDisposedException>(
            () => service.CopyCodeAsync(
                "654321",
                TimeSpan.FromMinutes(1),
                TestContext.Current.CancellationToken));
    }

    private sealed class FakeClipboardAdapter : IClipboardAdapter
    {
        public OwnedClipboardContent? Content { get; set; }

        public int ClearCount { get; private set; }

        public int ReadCount { get; private set; }

        public TaskCompletionSource Cleared { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        public void SetOwnedText(string text, string ownershipMarker) =>
            Content = new OwnedClipboardContent(text, ownershipMarker);

        public Task<OwnedClipboardContent?> ReadOwnedContentAsync()
        {
            ReadCount++;
            return Task.FromResult(Content);
        }

        public void Clear()
        {
            Content = null;
            ClearCount++;
            Cleared.TrySetResult();
        }
    }
}
