using PersonalAuthenticator.Infrastructure.Qr;

namespace PersonalAuthenticator.Infrastructure.Tests;

public sealed class LocalQrCodeGeneratorTests
{
    [Fact]
    public void Generate_CreatesLocalBgraQrPixels()
    {
        var generator = new LocalQrCodeGenerator();

        using var qr = generator.Generate(
            "otpauth://totp/Example:user?secret=JBSWY3DPEHPK3PXP&issuer=Example",
            256);

        Assert.Equal(256, qr.Width);
        Assert.Equal(256, qr.Height);
        Assert.Equal(256 * 256 * 4, qr.Pixels.Length);
        Assert.Contains((byte)0, qr.Pixels.Span.ToArray());
        Assert.Contains((byte)255, qr.Pixels.Span.ToArray());
    }

    [Theory]
    [InlineData(127)]
    [InlineData(1025)]
    public void Generate_RejectsUnsafeDimensions(int size)
    {
        var generator = new LocalQrCodeGenerator();

        Assert.Throws<ArgumentOutOfRangeException>(
            () => generator.Generate("safe payload", size));
    }
}
