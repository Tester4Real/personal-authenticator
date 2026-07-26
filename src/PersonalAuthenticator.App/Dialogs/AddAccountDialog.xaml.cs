using System.Runtime.InteropServices.WindowsRuntime;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using PersonalAuthenticator.Core.Abstractions;
using PersonalAuthenticator.Core.Domain;
using PersonalAuthenticator.Core.Exceptions;
using Windows.ApplicationModel.DataTransfer;
using Windows.Storage.Pickers;
using Windows.Storage.Streams;
using WindowsClipboard = Windows.ApplicationModel.DataTransfer.Clipboard;

namespace PersonalAuthenticator.App.Dialogs;

public sealed partial class AddAccountDialog : ContentDialog
{
    private readonly IProvisioningUriParser _parser;
    private readonly IQrCodeDecoder _qrDecoder;
    private readonly nint _windowHandle;
    private ParsedTotpProvisioning? _qrProvisioning;

    public AddAccountDialog(
        IProvisioningUriParser parser,
        IQrCodeDecoder qrDecoder,
        nint windowHandle)
    {
        InitializeComponent();
        _parser = parser;
        _qrDecoder = qrDecoder;
        _windowHandle = windowHandle;
    }

    public ParsedTotpProvisioning? Result { get; private set; }

    public ParsedTotpProvisioning? TakeResult()
    {
        ParsedTotpProvisioning? result = Result;
        Result = null;
        if (ReferenceEquals(result, _qrProvisioning))
        {
            _qrProvisioning = null;
        }

        _qrProvisioning?.Dispose();
        _qrProvisioning = null;
        return result;
    }

    private void Dialog_PrimaryButtonClick(ContentDialog sender, ContentDialogButtonClickEventArgs args)
    {
        try
        {
            Result = ImportTabs.SelectedIndex switch
            {
                0 => _parser.Parse(UriBox.Text),
                1 => _qrProvisioning ?? throw new SafeApplicationException(
                    "Qr.NotSelected",
                    "Choose or paste a QR image first."),
                2 => _parser.ParseManual(
                    IssuerBox.Text,
                    AccountNameBox.Text,
                    SecretBox.Password,
                    AlgorithmBox.SelectedIndex switch
                    {
                        1 => TotpAlgorithm.Sha256,
                        2 => TotpAlgorithm.Sha512,
                        _ => TotpAlgorithm.Sha1,
                    },
                    DigitsBox.SelectedIndex == 1 ? 8 : 6,
                    checked((int)PeriodBox.Value)),
                _ => throw new InvalidOperationException("Unknown import method."),
            };
        }
        catch (Exception exception) when (exception is SafeApplicationException or ArgumentException or OverflowException)
        {
            args.Cancel = true;
            ShowQrStatus(exception.Message, isError: true);
        }
        finally
        {
            SecretBox.Password = string.Empty;
        }
    }

    private async void ChooseImage_Click(object sender, RoutedEventArgs args)
    {
        var picker = new FileOpenPicker();
        WinRT.Interop.InitializeWithWindow.Initialize(picker, _windowHandle);
        picker.FileTypeFilter.Add(".png");
        picker.FileTypeFilter.Add(".jpg");
        picker.FileTypeFilter.Add(".jpeg");
        Windows.Storage.StorageFile? file = await picker.PickSingleFileAsync();
        if (file is null)
        {
            return;
        }

        try
        {
            await using Stream stream = await file.OpenStreamForReadAsync();
            await DecodeQrAsync(stream);
        }
        catch (Exception exception)
        {
            ShowQrStatus(
                exception is SafeApplicationException ? exception.Message : "The QR image could not be decoded.",
                isError: true);
        }
    }

    private async void PasteImage_Click(object sender, RoutedEventArgs args)
    {
        try
        {
            DataPackageView content = WindowsClipboard.GetContent();
            if (!content.Contains(StandardDataFormats.Bitmap))
            {
                throw new SafeApplicationException("Qr.ClipboardMissing", "The clipboard does not contain an image.");
            }

            RandomAccessStreamReference reference = await content.GetBitmapAsync();
            using IRandomAccessStreamWithContentType randomAccessStream = await reference.OpenReadAsync();
            await using Stream stream = randomAccessStream.AsStreamForRead();
            await DecodeQrAsync(stream);
        }
        catch (Exception exception)
        {
            ShowQrStatus(
                exception is SafeApplicationException ? exception.Message : "The clipboard image could not be decoded.",
                isError: true);
        }
    }

    private async Task DecodeQrAsync(Stream stream)
    {
        string payload = await _qrDecoder.DecodeAsync(stream, CancellationToken.None);
        ParsedTotpProvisioning parsed = _parser.Parse(payload);
        _qrProvisioning?.Dispose();
        _qrProvisioning = parsed;
        ShowQrStatus(
            $"Ready to preview {parsed.Issuer} — {parsed.AccountName}. Secret {parsed.MaskedSecretSuffix}.",
            isError: false);
    }

    private void ShowQrStatus(string message, bool isError)
    {
        ValidationStatus.Message = message;
        ValidationStatus.Severity = isError ? InfoBarSeverity.Error : InfoBarSeverity.Success;
        ValidationStatus.IsOpen = true;
    }
}
