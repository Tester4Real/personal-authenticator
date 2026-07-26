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
    private CancellationTokenSource? _pendingClear;
    private Task _pendingTask = Task.CompletedTask;
    private string? _pendingCode;
    private string? _pendingOwnershipMarker;
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
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (code.Length is not (6 or 8) || code.Any(character => !char.IsAsciiDigit(character)))
        {
            throw new ArgumentException("Only a current one-time code may be copied.", nameof(code));
        }

        ArgumentOutOfRangeException.ThrowIfLessThan(clearAfter, TimeSpan.Zero);

        await _gate.WaitAsync(cancellationToken);
        try
        {
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

            _pendingCode = code;
            _pendingOwnershipMarker = ownershipMarker;
            _pendingClear = new CancellationTokenSource();
            _pendingTask = ClearConditionallyAfterDelayAsync(
                code,
                ownershipMarker,
                clearAfter,
                _pendingClear.Token);
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task CancelPendingClearAsync()
    {
        if (_disposed)
        {
            return;
        }

        await _gate.WaitAsync();
        try
        {
            await CancelPendingClearCoreAsync(clearOwnedClipboard: true);
        }
        finally
        {
            _gate.Release();
        }
    }

    public async ValueTask DisposeAsync()
    {
        if (_disposed)
        {
            return;
        }

        await CancelPendingClearAsync();
        _disposed = true;
        _gate.Dispose();
    }

    private async Task ClearConditionallyAfterDelayAsync(
        string expectedCode,
        string expectedOwnershipMarker,
        TimeSpan delay,
        CancellationToken cancellationToken)
    {
        try
        {
            await Task.Delay(delay, cancellationToken);
            await ClearIfOwnedAsync(expectedCode, expectedOwnershipMarker);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
        }
        catch (Exception exception)
        {
            InfrastructureLog.ClipboardClearFailed(_logger, exception.GetType().Name);
        }
    }

    private async Task CancelPendingClearCoreAsync(bool clearOwnedClipboard)
    {
        CancellationTokenSource? source = _pendingClear;
        Task pendingTask = _pendingTask;
        string? expectedCode = _pendingCode;
        string? expectedOwnershipMarker = _pendingOwnershipMarker;
        _pendingClear = null;
        _pendingTask = Task.CompletedTask;
        _pendingCode = null;
        _pendingOwnershipMarker = null;
        if (source is not null)
        {
            await source.CancelAsync();
            try
            {
                await pendingTask;
            }
            finally
            {
                source.Dispose();
            }
        }

        if (clearOwnedClipboard &&
            expectedCode is not null &&
            expectedOwnershipMarker is not null)
        {
            await ClearIfOwnedAsync(expectedCode, expectedOwnershipMarker);
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
}
