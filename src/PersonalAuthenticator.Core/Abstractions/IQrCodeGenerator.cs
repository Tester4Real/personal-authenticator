using PersonalAuthenticator.Core.Domain;

namespace PersonalAuthenticator.Core.Abstractions;

public interface IQrCodeGenerator
{
    QrCodePixels Generate(string payload, int size);
}
