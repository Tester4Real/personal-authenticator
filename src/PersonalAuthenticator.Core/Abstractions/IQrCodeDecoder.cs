namespace PersonalAuthenticator.Core.Abstractions;

public interface IQrCodeDecoder
{
    Task<string> DecodeAsync(Stream imageStream, CancellationToken cancellationToken);
}
