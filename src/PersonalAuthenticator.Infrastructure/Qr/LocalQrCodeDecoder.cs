using System.Buffers;
using System.Runtime.InteropServices.WindowsRuntime;
using PersonalAuthenticator.Core.Abstractions;
using PersonalAuthenticator.Core.Exceptions;
using Windows.Graphics.Imaging;
using ZXing;
using ZXing.Common;
using ZXing.Multi.QrCode;

namespace PersonalAuthenticator.Infrastructure.Qr;

public sealed class LocalQrCodeDecoder : IQrCodeDecoder
{
    private const long MaximumInputBytes = 20 * 1024 * 1024;
    private const uint MaximumDimension = 4096;
    private const ulong MaximumPixels = 16_777_216;
    private const int MaximumPayloadCharacters = 4096;

    public async Task<string> DecodeAsync(Stream imageStream, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(imageStream);
        if (!imageStream.CanRead)
        {
            throw new SafeApplicationException("Qr.InvalidStream", "The selected image cannot be read.");
        }

        if (imageStream.CanSeek && imageStream.Length > MaximumInputBytes)
        {
            throw new SafeApplicationException("Qr.ImageTooLarge", "The selected image is too large.");
        }

        cancellationToken.ThrowIfCancellationRequested();
        using MemoryStream? bufferedInput = await BufferNonSeekableInputAsync(
            imageStream,
            cancellationToken).ConfigureAwait(false);
        Stream decoderInput = bufferedInput ?? imageStream;
        using global::Windows.Storage.Streams.IRandomAccessStream randomAccessStream = decoderInput.AsRandomAccessStream();
        BitmapDecoder decoder;
        try
        {
            decoder = await BitmapDecoder.CreateAsync(randomAccessStream)
                .AsTask(cancellationToken)
                .ConfigureAwait(false);
        }
        catch (Exception exception) when (exception is ArgumentException or InvalidOperationException)
        {
            throw new SafeApplicationException("Qr.UnsupportedImage", "The selected file is not a supported image.", exception);
        }

        if (decoder.PixelWidth is 0 or > MaximumDimension ||
            decoder.PixelHeight is 0 or > MaximumDimension ||
            (ulong)decoder.PixelWidth * decoder.PixelHeight > MaximumPixels)
        {
            throw new SafeApplicationException("Qr.ImageTooLarge", "The image dimensions are too large.");
        }

        cancellationToken.ThrowIfCancellationRequested();
        PixelDataProvider pixels = await decoder.GetPixelDataAsync(
                BitmapPixelFormat.Rgba8,
                BitmapAlphaMode.Ignore,
                new BitmapTransform(),
                ExifOrientationMode.RespectExifOrientation,
                ColorManagementMode.DoNotColorManage)
            .AsTask(cancellationToken)
            .ConfigureAwait(false);
        byte[] pixelBytes = pixels.DetachPixelData();
        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            var source = new RGBLuminanceSource(
                pixelBytes,
                checked((int)decoder.PixelWidth),
                checked((int)decoder.PixelHeight),
                RGBLuminanceSource.BitmapFormat.RGBA32);
            var binaryBitmap = new BinaryBitmap(new HybridBinarizer(source));
            var reader = new QRCodeMultiReader();
            Result[]? results = reader.decodeMultiple(
                binaryBitmap,
                new Dictionary<DecodeHintType, object>
                {
                    [DecodeHintType.TRY_HARDER] = true,
                    [DecodeHintType.CHARACTER_SET] = "UTF-8",
                });
            cancellationToken.ThrowIfCancellationRequested();

            if (results is null || results.Length == 0)
            {
                throw new SafeApplicationException("Qr.NotFound", "No QR code was found in the image.");
            }

            if (results.Length != 1)
            {
                throw new SafeApplicationException("Qr.MultipleCodes", "The image contains multiple QR codes.");
            }

            string text = results[0].Text;
            if (string.IsNullOrWhiteSpace(text) || text.Length > MaximumPayloadCharacters)
            {
                throw new SafeApplicationException("Qr.InvalidPayload", "The QR code payload is empty or too long.");
            }

            return text;
        }
        finally
        {
            System.Security.Cryptography.CryptographicOperations.ZeroMemory(pixelBytes);
        }
    }

    private static async Task<MemoryStream?> BufferNonSeekableInputAsync(
        Stream imageStream,
        CancellationToken cancellationToken)
    {
        if (imageStream.CanSeek)
        {
            return null;
        }

        var bufferedInput = new MemoryStream();
        byte[] copyBuffer = ArrayPool<byte>.Shared.Rent(81_920);
        try
        {
            while (true)
            {
                int readSize = (int)Math.Min(
                    copyBuffer.Length,
                    (MaximumInputBytes - bufferedInput.Length) + 1);
                int bytesRead = await imageStream.ReadAsync(
                    copyBuffer.AsMemory(0, readSize),
                    cancellationToken).ConfigureAwait(false);
                if (bytesRead == 0)
                {
                    bufferedInput.Position = 0;
                    return bufferedInput;
                }

                if (bufferedInput.Length + bytesRead > MaximumInputBytes)
                {
                    throw new SafeApplicationException("Qr.ImageTooLarge", "The selected image is too large.");
                }

                bufferedInput.Write(copyBuffer, 0, bytesRead);
            }
        }
        catch
        {
            bufferedInput.Dispose();
            throw;
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(copyBuffer, clearArray: true);
        }
    }
}
