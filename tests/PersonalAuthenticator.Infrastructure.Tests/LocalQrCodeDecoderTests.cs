using PersonalAuthenticator.Core.Exceptions;
using PersonalAuthenticator.Infrastructure.Qr;

namespace PersonalAuthenticator.Infrastructure.Tests;

public sealed class LocalQrCodeDecoderTests
{
    private const long MaximumInputBytes = 20 * 1024 * 1024;

    [Fact]
    public async Task DecodeAsync_NonSeekableOversizedInput_IsRejectedAfterBoundedRead()
    {
        using var imageStream = new GeneratedNonSeekableStream(MaximumInputBytes * 10);
        var decoder = new LocalQrCodeDecoder();

        SafeApplicationException exception = await Assert.ThrowsAsync<SafeApplicationException>(
            () => decoder.DecodeAsync(imageStream, TestContext.Current.CancellationToken));

        Assert.Equal("Qr.ImageTooLarge", exception.ErrorCode);
        Assert.Equal(MaximumInputBytes + 1, imageStream.BytesRead);
    }

    private sealed class GeneratedNonSeekableStream(long length) : Stream
    {
        private long _remaining = length;

        public long BytesRead { get; private set; }

        public override bool CanRead => true;

        public override bool CanSeek => false;

        public override bool CanWrite => false;

        public override long Length => throw new NotSupportedException();

        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override void Flush()
        {
        }

        public override int Read(byte[] buffer, int offset, int count) =>
            ReadCore(buffer.AsSpan(offset, count));

        public override ValueTask<int> ReadAsync(
            Memory<byte> buffer,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return ValueTask.FromResult(ReadCore(buffer.Span));
        }

        public override long Seek(long offset, SeekOrigin origin) =>
            throw new NotSupportedException();

        public override void SetLength(long value) =>
            throw new NotSupportedException();

        public override void Write(byte[] buffer, int offset, int count) =>
            throw new NotSupportedException();

        private int ReadCore(Span<byte> buffer)
        {
            int bytesToRead = (int)Math.Min(buffer.Length, _remaining);
            buffer[..bytesToRead].Clear();
            _remaining -= bytesToRead;
            BytesRead += bytesToRead;
            return bytesToRead;
        }
    }
}
