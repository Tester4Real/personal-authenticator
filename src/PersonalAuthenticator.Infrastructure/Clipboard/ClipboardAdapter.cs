using Windows.ApplicationModel.DataTransfer;
using WindowsClipboard = Windows.ApplicationModel.DataTransfer.Clipboard;

namespace PersonalAuthenticator.Infrastructure.Clipboard;

internal interface IClipboardAdapter
{
    void SetOwnedCode(string code, string ownershipMarker);

    Task<OwnedClipboardContent?> ReadOwnedContentAsync();

    void Clear();
}

internal sealed record OwnedClipboardContent(string Code, string OwnershipMarker);

internal sealed class WindowsClipboardAdapter : IClipboardAdapter
{
    private const string OwnershipFormat = "application/x-personal-authenticator-owner";

    public void SetOwnedCode(string code, string ownershipMarker)
    {
        var package = new DataPackage();
        package.SetText(code);
        package.SetData(OwnershipFormat, ownershipMarker);
        var options = new ClipboardContentOptions
        {
            IsAllowedInHistory = false,
            IsRoamable = false,
        };

        WindowsClipboard.SetContentWithOptions(package, options);
        WindowsClipboard.Flush();
    }

    public async Task<OwnedClipboardContent?> ReadOwnedContentAsync()
    {
        DataPackageView content = WindowsClipboard.GetContent();
        if (!content.Contains(StandardDataFormats.Text) || !content.Contains(OwnershipFormat))
        {
            return null;
        }

        string code = await content.GetTextAsync();
        object markerValue = await content.GetDataAsync(OwnershipFormat);
        return markerValue is string ownershipMarker
            ? new OwnedClipboardContent(code, ownershipMarker)
            : null;
    }

    public void Clear() => WindowsClipboard.Clear();
}
