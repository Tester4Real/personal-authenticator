using Windows.ApplicationModel.DataTransfer;
using WindowsClipboard = Windows.ApplicationModel.DataTransfer.Clipboard;

namespace PersonalAuthenticator.Infrastructure.Clipboard;

internal interface IClipboardAdapter
{
    void SetOwnedText(string text, string ownershipMarker);

    Task<OwnedClipboardContent?> ReadOwnedContentAsync();

    void Clear();
}

internal sealed record OwnedClipboardContent(string Text, string OwnershipMarker);

internal sealed class WindowsClipboardAdapter : IClipboardAdapter
{
    private const string OwnershipFormat = "application/x-personal-authenticator-owner";

    public void SetOwnedText(string text, string ownershipMarker)
    {
        var package = new DataPackage();
        package.SetText(text);
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

        string text = await content.GetTextAsync();
        object markerValue = await content.GetDataAsync(OwnershipFormat);
        return markerValue is string ownershipMarker
            ? new OwnedClipboardContent(text, ownershipMarker)
            : null;
    }

    public void Clear() => WindowsClipboard.Clear();
}
