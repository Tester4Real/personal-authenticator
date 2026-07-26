using System.Security.Cryptography;

namespace PersonalAuthenticator.Core.Security;

public sealed class SensitiveBuffer : IDisposable
{
    private byte[]? _buffer;

    public SensitiveBuffer(ReadOnlySpan<byte> value)
    {
        if (value.IsEmpty)
        {
            throw new ArgumentException("Sensitive value cannot be empty.", nameof(value));
        }

        _buffer = value.ToArray();
    }

    public int Length => GetBuffer().Length;

    public ReadOnlySpan<byte> AsSpan() => GetBuffer();

    public byte[] Copy() => GetBuffer().ToArray();

    public void Dispose()
    {
        byte[]? buffer = Interlocked.Exchange(ref _buffer, null);
        if (buffer is not null)
        {
            CryptographicOperations.ZeroMemory(buffer);
        }
    }

    private byte[] GetBuffer() =>
        _buffer ?? throw new ObjectDisposedException(nameof(SensitiveBuffer));
}
