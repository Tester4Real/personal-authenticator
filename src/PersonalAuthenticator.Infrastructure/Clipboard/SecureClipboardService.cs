using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Microsoft.Extensions.Logging;
using PersonalAuthenticator.Core.Abstractions;
using PersonalAuthenticator.Core.Exceptions;
using PersonalAuthenticator.Infrastructure.Logging;

namespace PersonalAuthenticator.Infrastructure.Clipboard;

public sealed class SecureClipboardService : ISecureClipboardService
{
    private readonly ILogger<SecureClipboardService> _logger;
    private readonly IClipboardAdapter _clipboard;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private PendingClear? _pendingClear;
    private bool _disposed;

    public SecureClipboardService(ILogger<SecureClipboardService> logger)
        : this(logger, new WindowsClipboardAdapter())
    {
    }

    internal SecureClipboardService(
        ILogger<SecureClipboardService> logger,
        IClipboardAdapter clipboard)
    {
        _logger = logger;
        _clipboard = clipboard;
    }

    public async Task CopyCodeAsync(string code, TimeSpan clearAfter, CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed), this);
        if (code.Length is not (6 or 8) || code.Any(character => !char.IsAsciiDigit(character)))
        {
            throw new ArgumentException("Only a current one-time code may be copied.", nameof(code));
        }

        ArgumentOutOfRangeException.ThrowIfLessThan(clearAfter, TimeSpan.Zero);

        await _gate.WaitAsync(cancellationToken);
        try
        {
            ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed), this);
            cancellationToken.ThrowIfCancellationRequested();
            await CancelPendingClearCoreAsync(clearOwnedClipboard: true);
            string ownershipMarker = Convert.ToHexString(RandomNumberGenerator.GetBytes(16));

            try
            {
                _clipboard.SetOwnedCode(code, ownershipMarker);
            }
            catch (Exception exception)
            {
                InfrastructureLog.ClipboardWriteFailed(_logger, exception.GetType().Name);
                throw new SafeApplicationException("Clipboard.WriteFailed", "The code could not be copied.", exception);
            }

            var pendingClear = new PendingClear(code, ownershipMarker);
            Interlocked.Exchange(ref _pendingClear, pendingClear);
            pendingClear.Task = ClearConditionallyAfterDelayAsync(pendingClear, clearAfter);
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task CancelPendingClearAsync()
    {
        if (Volatile.Read(ref _disposed))
        {
            return;
        }

        await _gate.WaitAsync();
        try
        {
            if (Volatile.Read(ref _disposed))
            {
                return;
            }

            await CancelPendingClearCoreAsync(clearOwnedClipboard: true);
        }
        finally
        {
            _gate.Release();
        }
    }

    public async ValueTask DisposeAsync()
    {
        if (Volatile.Read(ref _disposed))
        {
            return;
        }

        await _gate.WaitAsync();
        try
        {
            if (Volatile.Read(ref _disposed))
            {
                return;
            }

            Volatile.Write(ref _disposed, true);
            await CancelPendingClearCoreAsync(clearOwnedClipboard: true);
        }
        finally
        {
            _gate.Release();
        }
    }

    private async Task ClearConditionallyAfterDelayAsync(
        PendingClear pendingClear,
        TimeSpan delay)
    {
        try
        {
            await Task.Delay(delay, pendingClear.Cancellation.Token);
            await ClearIfOwnedAsync(pendingClear.Code, pendingClear.OwnershipMarker);
        }
        catch (OperationCanceledException) when (pendingClear.Cancellation.IsCancellationRequested)
        {
        }
        catch (Exception exception)
        {
            InfrastructureLog.ClipboardClearFailed(_logger, exception.GetType().Name);
        }
        finally
        {
            PendingClear? released = Interlocked.CompareExchange(
                ref _pendingClear,
                null,
                pendingClear);
            if (ReferenceEquals(released, pendingClear))
            {
                pendingClear.Dispose();
            }
        }
    }

    private async Task CancelPendingClearCoreAsync(bool clearOwnedClipboard)
    {
        PendingClear? pendingClear = Interlocked.Exchange(ref _pendingClear, null);
        if (pendingClear is null)
        {
            return;
        }

        await pendingClear.Cancellation.CancelAsync();
        try
        {
            await pendingClear.Task;
        }
        finally
        {
            pendingClear.Dispose();
        }

        if (clearOwnedClipboard)
        {
            await ClearIfOwnedAsync(pendingClear.Code, pendingClear.OwnershipMarker);
        }
    }

    private async Task ClearIfOwnedAsync(string expectedCode, string expectedOwnershipMarker)
    {
        try
        {
            OwnedClipboardContent? current = await _clipboard.ReadOwnedContentAsync();
            if (current is null ||
                !string.Equals(current.Code, expectedCode, StringComparison.Ordinal) ||
                !string.Equals(current.OwnershipMarker, expectedOwnershipMarker, StringComparison.Ordinal))
            {
                return;
            }

            _clipboard.Clear();
            InfrastructureLog.ClipboardCleared(_logger);
        }
        catch (COMException exception)
        {
            InfrastructureLog.ClipboardClearFailed(_logger, exception.GetType().Name);
        }
    }

    private sealed class PendingClear(
        string code,
        string ownershipMarker) : IDisposable
    {
        private int _disposed;

        public string Code { get; } = code;

        public string OwnershipMarker { get; } = ownershipMarker;

        public CancellationTokenSource Cancellation { get; } = new();

        public Task Task { get; set; } = Task.CompletedTask;

        public void Dispose()
        {
            if (Interlocked.Exchange(ref _disposed, 1) == 0)
            {
                Cancellation.Dispose();
            }
        }
    }
}
