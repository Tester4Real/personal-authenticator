using System.Security.Cryptography;
using PersonalAuthenticator.Infrastructure.GitHub;
using PersonalAuthenticator.Infrastructure.Sync;

namespace PersonalAuthenticator.Infrastructure.Tests;

public sealed class ProtocolFixtureConformanceTests
{
    [Fact]
    public async Task WindowsProtocolV1_ConsumesCheckedInFixturesByteForByte()
    {
        string fixtureRoot = FindFixtureRoot();
        using ProtocolFixtureSet expected =
            await ProtocolFixtureFactory.BuildAsync(
                TestContext.Current.CancellationToken);

        foreach ((string relativePath, byte[] expectedBytes) in expected.Files)
        {
            string path = Path.Combine(
                fixtureRoot,
                relativePath.Replace('/', Path.DirectorySeparatorChar));
            Assert.True(File.Exists(path), $"Missing fixture: {relativePath}");
            byte[] actualBytes = await File.ReadAllBytesAsync(
                path,
                TestContext.Current.CancellationToken);
            try
            {
                Assert.Equal(expectedBytes, actualBytes);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(actualBytes);
            }
        }

        string[] operationFiles =
            Directory.GetFiles(
                Path.Combine(fixtureRoot, "operations"),
                "*.bin",
                SearchOption.TopDirectoryOnly);
        string[] envelopeFiles =
            Directory.GetFiles(
                Path.Combine(fixtureRoot, "objects"),
                "*.pao",
                SearchOption.TopDirectoryOnly);
        Assert.Equal(12, operationFiles.Length);
        Assert.Equal(12, envelopeFiles.Length);

        using GitHubSyncConfiguration configuration =
            ProtocolFixtureFactory.CreateConfiguration(expected.SyncKey);
        foreach (string operationPath in operationFiles.Order())
        {
            byte[] bytes = await File.ReadAllBytesAsync(
                operationPath,
                TestContext.Current.CancellationToken);
            try
            {
                using SyncOperation operation =
                    SyncOperationSerializer.Deserialize(bytes);
                byte[] roundTrip = SyncOperationSerializer.Serialize(operation);
                try
                {
                    Assert.Equal(bytes, roundTrip);
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(roundTrip);
                }

                string index = Path.GetFileName(operationPath)[..2];
                string envelopePath = envelopeFiles.Single(
                    path => Path.GetFileName(path).StartsWith(
                        index + "-",
                        StringComparison.Ordinal));
                byte[] envelope = await File.ReadAllBytesAsync(
                    envelopePath,
                    TestContext.Current.CancellationToken);
                try
                {
                    using SyncOperation decrypted =
                        GitHubRemoteProtocol.DecryptOperation(
                            configuration,
                            envelope);
                    Assert.Equal(operation.Id, decrypted.Id);
                    Assert.Equal(operation.Kind, decrypted.Kind);
                    byte[] decryptedBytes =
                        SyncOperationSerializer.Serialize(decrypted);
                    try
                    {
                        Assert.Equal(bytes, decryptedBytes);
                    }
                    finally
                    {
                        CryptographicOperations.ZeroMemory(decryptedBytes);
                    }
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(envelope);
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(bytes);
            }
        }
    }

    private static string FindFixtureRoot()
    {
        DirectoryInfo? current = new(AppContext.BaseDirectory);
        while (current is not null)
        {
            string solution = Path.Combine(
                current.FullName,
                "PersonalAuthenticator.sln");
            if (File.Exists(solution))
            {
                return Path.Combine(
                    current.FullName,
                    "protocol-fixtures",
                    "v1");
            }

            current = current.Parent;
        }

        throw new DirectoryNotFoundException(
            "Could not locate protocol-fixtures/v1 from the test output directory.");
    }
}
