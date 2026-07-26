namespace PersonalAuthenticator.Core.Exceptions;

public class SafeApplicationException : Exception
{
    public SafeApplicationException(string errorCode, string safeMessage)
        : base(safeMessage)
    {
        ErrorCode = errorCode;
    }

    public SafeApplicationException(string errorCode, string safeMessage, Exception innerException)
        : base(safeMessage, innerException)
    {
        ErrorCode = errorCode;
    }

    public string ErrorCode { get; }
}
