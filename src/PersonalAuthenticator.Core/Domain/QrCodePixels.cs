using System.Security.Cryptography;

namespace PersonalAuthenticator.Core.Domain;

public sealed class QrCodePixels : IDisposable
{
    private byte[]? _pixels;

    public QrCodePixels(int width, int height, byte[] pixels)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(width);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(height);
        ArgumentNullException.ThrowIfNull(pixels);
        if (pixels.Length != checked(width * height * 4))
        {
            throw new ArgumentException(
                "QR pixel data must contain one BGRA value per pixel.",
                nameof(pixels));
        }

        Width = width;
        Height = height;
        _pixels = pixels;
    }

    public int Width { get; }

    public int Height { get; }

    public ReadOnlyMemory<byte> Pixels =>
        _pixels ??
        throw new ObjectDisposedException(nameof(QrCodePixels));

    public void Dispose()
    {
        byte[]? pixels = Interlocked.Exchange(ref _pixels, null);
        if (pixels is not null)
        {
            CryptographicOperations.ZeroMemory(pixels);
        }
    }
}
