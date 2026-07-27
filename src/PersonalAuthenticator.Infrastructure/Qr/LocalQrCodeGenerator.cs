using PersonalAuthenticator.Core.Abstractions;
using PersonalAuthenticator.Core.Domain;
using ZXing;
using ZXing.Common;

namespace PersonalAuthenticator.Infrastructure.Qr;

public sealed class LocalQrCodeGenerator : IQrCodeGenerator
{
    public QrCodePixels Generate(string payload, int size)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(payload);
        if (payload.Length > 4096)
        {
            throw new ArgumentOutOfRangeException(
                nameof(payload),
                "QR payloads cannot exceed 4096 characters.");
        }

        if (size is < 128 or > 1024)
        {
            throw new ArgumentOutOfRangeException(
                nameof(size),
                "QR dimensions must be between 128 and 1024 pixels.");
        }

        var writer = new BarcodeWriterPixelData
        {
            Format = BarcodeFormat.QR_CODE,
            Options = new EncodingOptions
            {
                Height = size,
                Width = size,
                Margin = 2,
                PureBarcode = true,
            },
        };
        var pixels = writer.Write(payload);
        return new QrCodePixels(pixels.Width, pixels.Height, pixels.Pixels);
    }
}
