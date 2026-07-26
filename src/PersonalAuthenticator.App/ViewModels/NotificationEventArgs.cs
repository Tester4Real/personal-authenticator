namespace PersonalAuthenticator.App.ViewModels;

public sealed class NotificationEventArgs : EventArgs
{
    public NotificationEventArgs(string title, string message, bool isError = false)
    {
        Title = title;
        Message = message;
        IsError = isError;
    }

    public string Title { get; }

    public string Message { get; }

    public bool IsError { get; }
}
