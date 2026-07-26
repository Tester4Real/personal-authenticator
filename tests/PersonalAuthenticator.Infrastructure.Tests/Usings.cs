global using Xunit;

internal static class TestContext
{
    public static TestExecutionContext Current { get; } = new();

    internal sealed class TestExecutionContext
    {
        private readonly CancellationToken _cancellationToken = CancellationToken.None;

        public CancellationToken CancellationToken => _cancellationToken;
    }
}
