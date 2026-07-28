using PersonalAuthenticator.Infrastructure.GitHub;

namespace PersonalAuthenticator.Infrastructure.Tests;

public sealed class Phase6LiveGitHubTests
{
    [Fact]
    [Trait("Category", "LiveGitHub")]
    public async Task ExplicitReleaseEnvironment_CanVerifyTemporaryPrivateRepository()
    {
        if (!string.Equals(
                Environment.GetEnvironmentVariable("PA_GITHUB_LIVE_TEST"),
                "1",
                StringComparison.Ordinal))
        {
            return;
        }

        string owner = Require("PA_GITHUB_LIVE_OWNER");
        string repository = Require("PA_GITHUB_LIVE_REPOSITORY");
        string branch = Require("PA_GITHUB_LIVE_BRANCH");
        char[] token = Require("PA_GITHUB_LIVE_TOKEN").ToCharArray();
        try
        {
            var factory = new HttpGitHubApiClientFactory();
            await using IGitHubApiClient client = factory.Create(token);
            _ = await client.GetUserAsync(TestContext.Current.CancellationToken);
            GitHubRepositoryInfo info = await client.GetRepositoryAsync(
                owner,
                repository,
                TestContext.Current.CancellationToken);
            Assert.True(info.IsPrivate);
            Assert.Equal("contents:write", info.Permissions);
            _ = await client.ListFilesAsync(
                owner,
                repository,
                branch,
                $".pa-live-{Guid.NewGuid():N}",
                TestContext.Current.CancellationToken);
        }
        finally
        {
            Array.Clear(token);
        }
    }

    private static string Require(string name) =>
        Environment.GetEnvironmentVariable(name) ??
        throw new InvalidOperationException(
            $"The opt-in live GitHub test requires {name}.");
}
