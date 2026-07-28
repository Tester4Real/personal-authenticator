using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using PersonalAuthenticator.Core.Exceptions;

namespace PersonalAuthenticator.Infrastructure.GitHub;

internal sealed class HttpGitHubApiClientFactory : IGitHubApiClientFactory
{
    public IGitHubApiClient Create(ReadOnlyMemory<char> token) =>
        new HttpGitHubApiClient(token);
}

internal sealed class HttpGitHubApiClient : IGitHubApiClient
{
    private const int MaximumResponseBytes = 32 * 1024 * 1024;
    private readonly HttpClient _client;

    public DateTimeOffset? RateLimitResetsAtUtc { get; private set; }

    public HttpGitHubApiClient(ReadOnlyMemory<char> token)
    {
        _client = new HttpClient
        {
            BaseAddress = new Uri("https://api.github.com/"),
            Timeout = TimeSpan.FromSeconds(30),
            MaxResponseContentBufferSize = MaximumResponseBytes,
        };
        _client.DefaultRequestHeaders.Accept.Add(
            new MediaTypeWithQualityHeaderValue("application/vnd.github+json"));
        _client.DefaultRequestHeaders.UserAgent.ParseAdd(
            "PersonalAuthenticator-Windows/2");
        _client.DefaultRequestHeaders.Add("X-GitHub-Api-Version", "2022-11-28");
        _client.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", new string(token.Span));
    }

    public async Task<GitHubUserInfo> GetUserAsync(
        CancellationToken cancellationToken)
    {
        using JsonDocument document = await GetJsonAsync(
            "user",
            cancellationToken);
        return new GitHubUserInfo(
            document.RootElement.GetProperty("id").GetInt64(),
            document.RootElement.GetProperty("login").GetString() ??
                throw InvalidResponse());
    }

    public async Task<GitHubRepositoryInfo> GetRepositoryAsync(
        string owner,
        string repository,
        CancellationToken cancellationToken)
    {
        using JsonDocument document = await GetJsonAsync(
            $"repos/{Escape(owner)}/{Escape(repository)}",
            cancellationToken);
        JsonElement root = document.RootElement;
        JsonElement permissions = root.GetProperty("permissions");
        return new GitHubRepositoryInfo(
            root.GetProperty("id").GetInt64(),
            root.GetProperty("owner").GetProperty("login").GetString() ??
                throw InvalidResponse(),
            root.GetProperty("name").GetString() ?? throw InvalidResponse(),
            root.GetProperty("private").GetBoolean(),
            permissions.TryGetProperty("push", out JsonElement push) &&
            push.GetBoolean()
                ? "contents:write"
                : permissions.TryGetProperty("pull", out JsonElement pull) &&
                  pull.GetBoolean()
                    ? "contents:read"
                    : "none");
    }

    public async Task<GitHubRemoteFile?> GetFileAsync(
        string owner,
        string repository,
        string path,
        string branch,
        string? etag,
        CancellationToken cancellationToken)
    {
        using HttpResponseMessage response = await SendAsync(
            () =>
            {
                var request = new HttpRequestMessage(
                    HttpMethod.Get,
                    $"repos/{Escape(owner)}/{Escape(repository)}/contents/{EscapePath(path)}?ref={Uri.EscapeDataString(branch)}");
                if (!string.IsNullOrWhiteSpace(etag))
                {
                    request.Headers.IfNoneMatch.ParseAdd(etag);
                }

                return request;
            },
            allowNotFound: true,
            cancellationToken);
        if (response.StatusCode == HttpStatusCode.NotFound)
        {
            return null;
        }

        using JsonDocument document = await ReadJsonAsync(response, cancellationToken);
        string encoded = document.RootElement.GetProperty("content").GetString() ??
            throw InvalidResponse();
        byte[] content;
        try
        {
            content = Convert.FromBase64String(
                encoded.Replace("\n", string.Empty, StringComparison.Ordinal));
        }
        catch (FormatException exception)
        {
            throw new SafeApplicationException(
                "GitHub.InvalidResponse",
                "GitHub returned malformed repository content.",
                exception);
        }

        return new GitHubRemoteFile(
            content,
            document.RootElement.GetProperty("sha").GetString() ??
                throw InvalidResponse(),
            response.Headers.ETag?.Tag);
    }

    public async Task<IReadOnlyList<GitHubRemoteEntry>> ListFilesAsync(
        string owner,
        string repository,
        string branch,
        string pathPrefix,
        CancellationToken cancellationToken)
    {
        using JsonDocument document = await GetJsonAsync(
            $"repos/{Escape(owner)}/{Escape(repository)}/git/trees/{Uri.EscapeDataString(branch)}?recursive=1",
            cancellationToken);
        if (document.RootElement.TryGetProperty("truncated", out JsonElement truncated) &&
            truncated.GetBoolean())
        {
            return await ListFilesByBoundedTraversalAsync(
                owner,
                repository,
                branch,
                pathPrefix,
                cancellationToken);
        }

        return ReadMatchingBlobs(document.RootElement, pathPrefix);
    }

    private async Task<IReadOnlyList<GitHubRemoteEntry>>
        ListFilesByBoundedTraversalAsync(
            string owner,
            string repository,
            string branch,
            string pathPrefix,
            CancellationToken cancellationToken)
    {
        const int maximumTrees = 10_000;
        const int maximumDepth = 64;
        var result = new List<GitHubRemoteEntry>();
        var pending = new Queue<(string Prefix, string Tree, int Depth)>();
        var visited = new HashSet<string>(StringComparer.Ordinal);
        pending.Enqueue((string.Empty, branch, 0));
        while (pending.Count > 0)
        {
            cancellationToken.ThrowIfCancellationRequested();
            (string prefix, string tree, int depth) = pending.Dequeue();
            if (depth > maximumDepth ||
                visited.Count >= maximumTrees ||
                !visited.Add(tree))
            {
                throw RemoteTreeTooLarge();
            }

            using JsonDocument document = await GetJsonAsync(
                $"repos/{Escape(owner)}/{Escape(repository)}/git/trees/{Escape(tree)}",
                cancellationToken);
            if (document.RootElement.TryGetProperty(
                    "truncated",
                    out JsonElement truncated) &&
                truncated.GetBoolean())
            {
                throw RemoteTreeTooLarge();
            }

            foreach (JsonElement item in
                     document.RootElement.GetProperty("tree").EnumerateArray())
            {
                string name = item.GetProperty("path").GetString() ??
                    throw InvalidResponse();
                if (name.Length is < 1 or > 255 ||
                    name is "." or ".." ||
                    name.Contains('/') ||
                    name.Contains('\\'))
                {
                    throw new SafeApplicationException(
                        "GitHub.InvalidRemotePath",
                        "The GitHub tree contains an invalid path component.");
                }

                string path = prefix.Length == 0 ? name : $"{prefix}/{name}";
                if (path.Length > 1024)
                {
                    throw RemoteTreeTooLarge();
                }

                string type = item.GetProperty("type").GetString() ??
                    throw InvalidResponse();
                if (type == "tree" && PathsMayIntersect(path, pathPrefix))
                {
                    pending.Enqueue(
                        (path,
                         item.GetProperty("sha").GetString() ??
                         throw InvalidResponse(),
                         depth + 1));
                }
                else if (type == "blob" &&
                         path.StartsWith(
                             pathPrefix + "/",
                             StringComparison.Ordinal))
                {
                    if (result.Count >= 100_000)
                    {
                        throw RemoteTreeTooLarge();
                    }

                    result.Add(
                        new GitHubRemoteEntry(
                            path,
                            item.GetProperty("sha").GetString() ??
                            throw InvalidResponse(),
                            item.TryGetProperty("size", out JsonElement size)
                                ? size.GetInt64()
                                : 0));
                }
            }
        }

        return result;
    }

    private static List<GitHubRemoteEntry> ReadMatchingBlobs(
        JsonElement root,
        string pathPrefix)
    {
        var result = new List<GitHubRemoteEntry>();
        foreach (JsonElement item in root.GetProperty("tree").EnumerateArray())
        {
            string? path = item.GetProperty("path").GetString();
            if (path is null ||
                !path.StartsWith(pathPrefix + "/", StringComparison.Ordinal) ||
                item.GetProperty("type").GetString() != "blob")
            {
                continue;
            }

            if (result.Count >= 100_000)
            {
                throw new SafeApplicationException(
                    "GitHub.RemoteTooLarge",
                    "The GitHub sync repository contains too many objects.");
            }

            result.Add(
                new GitHubRemoteEntry(
                    path,
                    item.GetProperty("sha").GetString() ?? throw InvalidResponse(),
                    item.TryGetProperty("size", out JsonElement size)
                        ? size.GetInt64()
                        : 0));
        }

        return result;
    }

    private static bool PathsMayIntersect(string path, string target) =>
        target.Equals(path, StringComparison.Ordinal) ||
        target.StartsWith(path + "/", StringComparison.Ordinal) ||
        path.StartsWith(target + "/", StringComparison.Ordinal);

    private static SafeApplicationException RemoteTreeTooLarge() =>
        new(
            "GitHub.RemoteTooLarge",
            "The GitHub sync tree exceeds safe traversal limits. Nothing was partially applied.");

    public async Task<GitHubPutResult> PutFileAsync(
        string owner,
        string repository,
        string path,
        string branch,
        ReadOnlyMemory<byte> content,
        string? existingSha,
        CancellationToken cancellationToken)
    {
        var body = new
        {
            message = "Update encrypted authenticator sync object",
            content = Convert.ToBase64String(content.Span),
            branch,
            sha = existingSha,
        };
        using HttpResponseMessage response = await SendAsync(
            () => new HttpRequestMessage(
                HttpMethod.Put,
                $"repos/{Escape(owner)}/{Escape(repository)}/contents/{EscapePath(path)}")
            {
                Content = JsonContent.Create(body),
            },
            allowNotFound: false,
            cancellationToken);
        using JsonDocument document = await ReadJsonAsync(response, cancellationToken);
        return new GitHubPutResult(
            document.RootElement.GetProperty("content").GetProperty("sha").GetString() ??
                throw InvalidResponse(),
            document.RootElement.GetProperty("commit").GetProperty("sha").GetString() ??
                throw InvalidResponse());
    }

    public async Task<string> GetBranchHeadAsync(
        string owner,
        string repository,
        string branch,
        CancellationToken cancellationToken)
    {
        using JsonDocument document = await GetJsonAsync(
            $"repos/{Escape(owner)}/{Escape(repository)}/git/ref/heads/{EscapePath(branch)}",
            cancellationToken);
        return document.RootElement.GetProperty("object").GetProperty("sha").GetString() ??
            throw InvalidResponse();
    }

    public async Task<bool> IsAncestorAsync(
        string owner,
        string repository,
        string ancestor,
        string descendant,
        CancellationToken cancellationToken)
    {
        using JsonDocument document = await GetJsonAsync(
            $"repos/{Escape(owner)}/{Escape(repository)}/compare/{Escape(ancestor)}...{Escape(descendant)}",
            cancellationToken);
        string? status = document.RootElement.GetProperty("status").GetString();
        return status is "ahead" or "identical";
    }

    public ValueTask DisposeAsync()
    {
        _client.Dispose();
        return ValueTask.CompletedTask;
    }

    private async Task<JsonDocument> GetJsonAsync(
        string path,
        CancellationToken cancellationToken)
    {
        using HttpResponseMessage response = await SendAsync(
            () => new HttpRequestMessage(HttpMethod.Get, path),
            allowNotFound: false,
            cancellationToken);
        return await ReadJsonAsync(response, cancellationToken);
    }

    private async Task<HttpResponseMessage> SendAsync(
        Func<HttpRequestMessage> requestFactory,
        bool allowNotFound,
        CancellationToken cancellationToken)
    {
        for (int attempt = 0; ; attempt++)
        {
            HttpRequestMessage request = requestFactory();
            HttpResponseMessage response;
            try
            {
                response = await _client.SendAsync(
                    request,
                    HttpCompletionOption.ResponseHeadersRead,
                    cancellationToken);
            }
            catch (HttpRequestException exception)
            {
                request.Dispose();
                throw new SafeApplicationException(
                    "GitHub.NetworkUnavailable",
                    "GitHub could not be reached. Local changes remain queued.",
                    exception);
            }

            request.Dispose();
            CaptureRateLimit(response);
            if (response.IsSuccessStatusCode ||
                (allowNotFound && response.StatusCode == HttpStatusCode.NotFound))
            {
                return response;
            }

            if (response.StatusCode == HttpStatusCode.Unauthorized)
            {
                response.Dispose();
                throw new SafeApplicationException(
                    "GitHub.AuthenticationFailed",
                    "The GitHub token is invalid, expired, or revoked.");
            }

            if (response.StatusCode == HttpStatusCode.NotFound)
            {
                response.Dispose();
                throw new SafeApplicationException(
                    "GitHub.NotFoundOrInaccessible",
                    "GitHub returned 404. The private repository may be inaccessible, renamed, transferred, deleted, or hidden by token permissions.");
            }

            bool rateLimited =
                response.StatusCode is HttpStatusCode.Forbidden or
                    HttpStatusCode.TooManyRequests &&
                (response.Headers.TryGetValues(
                     "X-RateLimit-Remaining",
                     out IEnumerable<string>? remainingValues) &&
                 remainingValues.Contains("0", StringComparer.Ordinal) ||
                 response.StatusCode == HttpStatusCode.TooManyRequests);
            bool retryable = response.StatusCode is
                HttpStatusCode.RequestTimeout or
                HttpStatusCode.Conflict or
                HttpStatusCode.TooManyRequests ||
                (int)response.StatusCode >= 500;
            if (!retryable || attempt >= 4)
            {
                string code = rateLimited
                    ? "GitHub.RateLimited"
                    : response.StatusCode == HttpStatusCode.Forbidden
                        ? "GitHub.PermissionDenied"
                        : "GitHub.RequestFailed";
                string message = rateLimited
                    ? "GitHub rate limits are active. Local changes remain queued until the reset time."
                    : response.StatusCode == HttpStatusCode.Forbidden
                        ? "The GitHub token lacks Contents read/write permission."
                        : "GitHub rejected the sync request. Local changes remain queued.";
                response.Dispose();
                throw new SafeApplicationException(code, message);
            }

            TimeSpan delay = response.Headers.RetryAfter?.Delta ??
                TimeSpan.FromMilliseconds(
                    Math.Min(30_000, 500 * (1 << attempt)) +
                    Random.Shared.Next(100, 750));
            response.Dispose();
            await Task.Delay(delay, cancellationToken);
        }
    }

    private void CaptureRateLimit(HttpResponseMessage response)
    {
        if (!response.Headers.TryGetValues(
                "X-RateLimit-Reset",
                out IEnumerable<string>? values) ||
            !long.TryParse(values.FirstOrDefault(), out long seconds))
        {
            return;
        }

        try
        {
            RateLimitResetsAtUtc =
                DateTimeOffset.FromUnixTimeSeconds(seconds);
        }
        catch (ArgumentOutOfRangeException)
        {
            RateLimitResetsAtUtc = null;
        }
    }

    private static async Task<JsonDocument> ReadJsonAsync(
        HttpResponseMessage response,
        CancellationToken cancellationToken)
    {
        if (response.Content.Headers.ContentLength > MaximumResponseBytes)
        {
            throw InvalidResponse();
        }

        await using Stream stream =
            await response.Content.ReadAsStreamAsync(cancellationToken);
        try
        {
            return await JsonDocument.ParseAsync(
                stream,
                new JsonDocumentOptions { MaxDepth = 32 },
                cancellationToken);
        }
        catch (JsonException exception)
        {
            throw new SafeApplicationException(
                "GitHub.InvalidResponse",
                "GitHub returned a malformed response.",
                exception);
        }
    }

    private static string Escape(string value) => Uri.EscapeDataString(value);

    private static string EscapePath(string value) =>
        string.Join('/', value.Split('/').Select(Uri.EscapeDataString));

    private static SafeApplicationException InvalidResponse() =>
        new("GitHub.InvalidResponse", "GitHub returned an incomplete response.");
}
