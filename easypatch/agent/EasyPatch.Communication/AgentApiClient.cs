using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;
using EasyPatch.Contracts.Agent;
using EasyPatch.Contracts.Json;
using EasyPatch.Contracts.Security;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace EasyPatch.Communication;

/// <summary>A credential ID plus the private key that signs for it. The key is owned by the caller.</summary>
public sealed record SigningCredential(string CredentialId, ECDsa Key);

/// <summary>Supplies the credential used to sign the next request (c_… once active, r_… while pending approval).</summary>
public interface ISigningCredentialProvider
{
    /// <summary>Returns the current signing credential, or null when the agent has no identity yet.</summary>
    SigningCredential? GetSigningCredential();
}

/// <summary>
/// Typed HTTPS client for the EasyPatch agent protocol. Every request except enroll is signed with
/// <see cref="RequestSigner"/>. The <see cref="HttpClient"/> (and its BaseAddress / TLS / proxy settings)
/// is supplied by the composition root; this class never weakens TLS validation.
/// </summary>
public sealed class AgentApiClient
{
    private const string JsonMediaType = "application/json";

    private static readonly HashSet<string> FatalAuthCodes = new(StringComparer.Ordinal)
    {
        AgentErrorCodes.CredentialRevoked,
        AgentErrorCodes.CredentialExpired,
        AgentErrorCodes.UnknownCredential,
        AgentErrorCodes.EndpointRevoked,
    };

    private readonly HttpClient _http;
    private readonly ISigningCredentialProvider _credentials;
    private readonly ServerClock _clock;
    private readonly string _userAgent;
    private readonly ILogger _logger;
    private readonly Lock _signingLock = new();

    public AgentApiClient(
        HttpClient httpClient,
        ISigningCredentialProvider credentials,
        ServerClock clock,
        string agentVersion,
        ILogger<AgentApiClient>? logger = null)
    {
        ArgumentNullException.ThrowIfNull(httpClient);
        ArgumentNullException.ThrowIfNull(credentials);
        ArgumentNullException.ThrowIfNull(clock);
        ArgumentException.ThrowIfNullOrEmpty(agentVersion);
        if (httpClient.BaseAddress is null)
        {
            throw new ArgumentException("HttpClient.BaseAddress must be set to the EasyPatch server URL.", nameof(httpClient));
        }

        _http = httpClient;
        _credentials = credentials;
        _clock = clock;
        _userAgent = $"EasyPatchAgent/{agentVersion}";
        _logger = (ILogger?)logger ?? NullLogger.Instance;
    }

    public ServerClock Clock => _clock;

    public Uri BaseAddress => _http.BaseAddress!;

    // ------------------------------------------------------------------ enrollment

    public async Task<EnrollResponse> EnrollAsync(EnrollRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        var response = await SendAsync<EnrollResponse>(AgentRoutes.Enroll, Serialize(request), signed: false, cancellationToken);
        _clock.Observe(response.ServerTime);
        return response;
    }

    public async Task<EnrollResponse> GetEnrollmentStatusAsync(CancellationToken cancellationToken = default)
    {
        var response = await SendAsync<EnrollResponse>(AgentRoutes.EnrollmentStatus, Serialize(new { }), signed: true, cancellationToken);
        _clock.Observe(response.ServerTime);
        return response;
    }

    // ------------------------------------------------------------------ steady state

    public async Task<CheckInResponse> CheckInAsync(CheckInRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        var response = await SendCheckInAsync(Serialize(request), cancellationToken);
        if (response.ServerTime != default)
        {
            _clock.Observe(response.ServerTime);
        }

        return response;
    }

    /// <summary>
    /// Deserializes the check-in response one job at a time, so a job this agent version cannot understand (for
    /// example a job type added in a newer server) is skipped instead of breaking every check-in.
    /// </summary>
    private async Task<CheckInResponse> SendCheckInAsync(byte[] body, CancellationToken cancellationToken)
    {
        using var response = await SendCoreAsync(AgentRoutes.CheckIn, body, signed: true, cancellationToken);
        JsonObject root;
        try
        {
            var bytes = await response.Content.ReadAsByteArrayAsync(cancellationToken);
            root = JsonNode.Parse(bytes, new JsonNodeOptions { PropertyNameCaseInsensitive = true }) as JsonObject
                ?? throw new AgentTransientException("Malformed check-in response.", response.StatusCode, null, null);
        }
        catch (JsonException ex)
        {
            throw new AgentTransientException("Malformed check-in response.", response.StatusCode, null, null, ex);
        }

        var jobsKey = root.Select(p => p.Key).FirstOrDefault(k => string.Equals(k, "jobs", StringComparison.OrdinalIgnoreCase));
        var jobNodes = jobsKey is not null && root[jobsKey] is JsonArray array ? array.ToList() : [];
        if (jobsKey is not null)
        {
            root.Remove(jobsKey);
        }

        CheckInResponse result;
        try
        {
            result = root.Deserialize<CheckInResponse>(ContractJson.Options)
                ?? throw new AgentTransientException("Empty check-in response.", response.StatusCode, null, null);
        }
        catch (JsonException ex)
        {
            throw new AgentTransientException("Malformed check-in response.", response.StatusCode, null, null, ex);
        }

        var jobs = new List<AgentJob>(jobNodes.Count);
        foreach (var node in jobNodes)
        {
            try
            {
                if (node?.Deserialize<AgentJob>(ContractJson.Options) is { } job)
                {
                    jobs.Add(job);
                }
            }
            catch (JsonException ex)
            {
                var id = node is JsonObject obj && obj.FirstOrDefault(p => string.Equals(p.Key, "jobId", StringComparison.OrdinalIgnoreCase)).Value is { } idNode
                    ? idNode.ToJsonString()
                    : "(unknown)";
                _logger.LogWarning("Ignoring job {JobId} that this agent version cannot read (upgrade the agent): {Message}", id, ex.Message);
            }
        }

        return result with { Jobs = jobs };
    }

    public Task SendInventoryAsync(InventoryReport report, CancellationToken cancellationToken = default) =>
        PostRawAsync(AgentRoutes.Inventory, Serialize(report), cancellationToken);

    public Task SendScanResultsAsync(ScanResultReport report, CancellationToken cancellationToken = default) =>
        PostRawAsync(AgentRoutes.ScanResults, Serialize(report), cancellationToken);

    public Task SendHistoryAsync(HistoryReport report, CancellationToken cancellationToken = default) =>
        PostRawAsync(AgentRoutes.History, Serialize(report), cancellationToken);

    public Task<JobAckResponse> AcknowledgeJobAsync(Guid jobId, CancellationToken cancellationToken = default) =>
        SendAsync<JobAckResponse>(AgentRoutes.JobAck(jobId), Serialize(new { }), signed: true, cancellationToken);

    public Task SendJobStatusAsync(Guid jobId, JobStatusReport report, CancellationToken cancellationToken = default) =>
        PostRawAsync(AgentRoutes.JobStatus(jobId), Serialize(report), cancellationToken);

    public Task<RotateCredentialResponse> RotateCredentialAsync(RotateCredentialRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        return SendAsync<RotateCredentialResponse>(AgentRoutes.RotateCredential, Serialize(request), signed: true, cancellationToken);
    }

    public Task UnenrollAsync(UnenrollRequest request, CancellationToken cancellationToken = default) =>
        PostRawAsync(AgentRoutes.Unenroll, Serialize(request), cancellationToken);

    /// <summary>Posts an already-serialized JSON body to a signed route (used by the durable outbox).</summary>
    public async Task PostRawAsync(string route, byte[] jsonBody, CancellationToken cancellationToken = default)
    {
        using var response = await SendCoreAsync(route, jsonBody, signed: true, cancellationToken);
    }

    public static byte[] Serialize<T>(T value) => JsonSerializer.SerializeToUtf8Bytes(value, ContractJson.Options);

    /// <summary>Downloads an agent package from this server's package downloads into <paramref name="destination"/>.</summary>
    /// <remarks>Not signed: the download is public, and the caller trusts the bytes only after checking them against a
    /// release signature it verified itself. The URL is always on this server; only the file name comes from the job.</remarks>
    /// <exception cref="AgentTransientException">Network failure, timeout or server error; worth retrying.</exception>
    /// <exception cref="AgentRejectedException">The server does not have the package.</exception>
    /// <exception cref="InvalidDataException">The server sent more than <paramref name="maxBytes"/>.</exception>
    public Task DownloadAgentPackageAsync(string fileName, Stream destination, long maxBytes, TimeSpan timeout,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(fileName);
        return DownloadAsync("downloads/agent/", fileName, destination, maxBytes, "its release signature says", timeout, cancellationToken);
    }

    /// <summary>Downloads a file of the pinned winget release from this server's copy (see <c>WingetDistribution</c>).</summary>
    /// <remarks>Not signed, like agent packages: the caller trusts the bytes only after checking the pinned SHA-256.</remarks>
    /// <exception cref="AgentTransientException">Network failure, timeout or server error (503 while the server is still
    /// fetching its copy); worth retrying.</exception>
    public Task DownloadWingetFileAsync(string fileName, Stream destination, long maxBytes, TimeSpan timeout,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(fileName);
        return DownloadAsync(WingetDistribution.ServerRoute, fileName, destination, maxBytes, "the pinned release says", timeout, cancellationToken);
    }

    private async Task DownloadAsync(string prefix, string fileName, Stream destination, long maxBytes, string limitSource, TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(destination);
        var route = prefix + Uri.EscapeDataString(fileName);
        using var timeoutSource = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeoutSource.CancelAfter(timeout);
        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, route);
            request.Headers.TryAddWithoutValidation("User-Agent", _userAgent);
            using var response = await _http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, timeoutSource.Token);
            if (!response.IsSuccessStatusCode)
            {
                var status = response.StatusCode;
                var message = $"Downloading {fileName} failed with HTTP {(int)status}.";
                throw status is HttpStatusCode.RequestTimeout or HttpStatusCode.TooManyRequests || (int)status >= 500
                    ? new AgentTransientException(message, status, null, GetRetryAfter(response))
                    : new AgentRejectedException(message, status, null);
            }

            if (response.Content.Headers.ContentLength > maxBytes)
            {
                throw new InvalidDataException($"{fileName} is larger than {limitSource}.");
            }

            await using var source = await response.Content.ReadAsStreamAsync(timeoutSource.Token);
            var buffer = new byte[81920];
            long total = 0;
            int read;
            while ((read = await source.ReadAsync(buffer, timeoutSource.Token)) > 0)
            {
                total += read;
                if (total > maxBytes)
                {
                    throw new InvalidDataException($"{fileName} is larger than {limitSource}.");
                }

                await destination.WriteAsync(buffer.AsMemory(0, read), timeoutSource.Token);
            }

            _logger.LogDebug("GET {Route} -> {Bytes} bytes", route, total);
        }
        catch (OperationCanceledException ex) when (!cancellationToken.IsCancellationRequested)
        {
            throw new AgentTransientException($"Downloading {fileName} timed out.", null, null, null, ex);
        }
        catch (HttpRequestException ex)
        {
            throw new AgentTransientException($"Could not download {fileName}: {ex.Message}", null, null, null, ex);
        }
        catch (IOException ex)
        {
            throw new AgentTransientException($"The download of {fileName} was interrupted: {ex.Message}", null, null, null, ex);
        }
    }

    // ------------------------------------------------------------------ core

    private async Task<T> SendAsync<T>(string route, byte[] body, bool signed, CancellationToken cancellationToken)
    {
        using var response = await SendCoreAsync(route, body, signed, cancellationToken);
        try
        {
            var stream = await response.Content.ReadAsStreamAsync(cancellationToken);
            await using (stream)
            {
                var value = await JsonSerializer.DeserializeAsync<T>(stream, ContractJson.Options, cancellationToken);
                return value ?? throw new AgentTransientException($"Empty response body from {route}.", response.StatusCode, null, null);
            }
        }
        catch (JsonException ex)
        {
            throw new AgentTransientException($"Malformed response from {route}.", response.StatusCode, null, null, ex);
        }
    }

    /// <summary>Sends the request; returns a successful response or throws a typed exception.
    /// A single automatic retry happens after a clock_skew rejection (once the offset has been corrected).</summary>
    private async Task<HttpResponseMessage> SendCoreAsync(string route, byte[] body, bool signed, CancellationToken cancellationToken)
    {
        for (var attempt = 0; ; attempt++)
        {
            var response = await SendOnceAsync(route, body, signed, cancellationToken);
            if (response.IsSuccessStatusCode)
            {
                return response;
            }

            using (response)
            {
                var problem = await ReadProblemAsync(response, cancellationToken);
                if (problem.ServerTime is { } serverTime)
                {
                    _clock.Observe(serverTime);
                }

                if (problem.Code == AgentErrorCodes.ClockSkew && attempt == 0)
                {
                    _logger.LogWarning("Server reported clock skew on {Route}; corrected offset is {Offset}. Retrying once.", route, _clock.Offset);
                    continue;
                }

                throw MapError(route, response, problem);
            }
        }
    }

    private async Task<HttpResponseMessage> SendOnceAsync(string route, byte[] body, bool signed, CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, route);
        var content = new ByteArrayContent(body);
        content.Headers.ContentType = new MediaTypeHeaderValue(JsonMediaType) { CharSet = "utf-8" };
        request.Content = content;
        request.Headers.TryAddWithoutValidation("User-Agent", _userAgent);
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue(JsonMediaType));

        if (signed)
        {
            var credential = _credentials.GetSigningCredential()
                ?? throw new AgentAuthException("The agent has no credential; enrollment is required.", null, AgentErrorCodes.UnknownCredential, isFatal: true);
            var target = new Uri(_http.BaseAddress!, route);
            SignedRequestHeaders headers;
            lock (_signingLock)
            {
                // ECDsa instances are not guaranteed to be safe for concurrent use.
                headers = RequestSigner.Sign(credential.Key, credential.CredentialId, "POST", target.PathAndQuery, body, _clock.Now);
            }

            request.Headers.TryAddWithoutValidation(AgentAuthHeaders.Credential, headers.CredentialId);
            request.Headers.TryAddWithoutValidation(AgentAuthHeaders.Timestamp, headers.Timestamp.ToString(CultureInfo.InvariantCulture));
            request.Headers.TryAddWithoutValidation(AgentAuthHeaders.Nonce, headers.Nonce);
            request.Headers.TryAddWithoutValidation(AgentAuthHeaders.ContentSha256, headers.ContentSha256);
            request.Headers.TryAddWithoutValidation(AgentAuthHeaders.Signature, headers.Signature);
        }

        HttpResponseMessage response;
        try
        {
            response = await _http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (OperationCanceledException ex)
        {
            throw new AgentTransientException($"Request to {route} timed out.", null, null, null, ex);
        }
        catch (HttpRequestException ex)
        {
            throw new AgentTransientException($"Could not reach the EasyPatch server ({route}): {ex.Message}", null, null, null, ex);
        }
        catch (IOException ex)
        {
            throw new AgentTransientException($"Connection to the EasyPatch server failed ({route}): {ex.Message}", null, null, null, ex);
        }

        if (response.Headers.Date is { } date)
        {
            _clock.Observe(date);
        }

        _logger.LogDebug("POST {Route} -> {StatusCode}", route, (int)response.StatusCode);
        return response;
    }

    private static AgentApiException MapError(string route, HttpResponseMessage response, Problem problem)
    {
        var status = response.StatusCode;
        var detail = problem.Detail ?? problem.Title ?? response.ReasonPhrase ?? status.ToString();
        var message = $"{route} failed with HTTP {(int)status}{(problem.Code is null ? "" : $" ({problem.Code})")}: {detail}";

        if (status is HttpStatusCode.RequestTimeout or HttpStatusCode.TooManyRequests || (int)status >= 500)
        {
            return new AgentTransientException(message, status, problem.Code, GetRetryAfter(response));
        }

        if (status is HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden &&
            problem.Code is not (AgentErrorCodes.EnrollmentInvalid or AgentErrorCodes.EnrollmentRejected))
        {
            var fatal = problem.Code is not null && FatalAuthCodes.Contains(problem.Code);
            return new AgentAuthException(message, status, problem.Code, fatal);
        }

        return new AgentRejectedException(message, status, problem.Code);
    }

    private static TimeSpan? GetRetryAfter(HttpResponseMessage response)
    {
        var retry = response.Headers.RetryAfter;
        if (retry?.Delta is { } delta)
        {
            return delta;
        }

        if (retry?.Date is { } date)
        {
            var wait = date - DateTimeOffset.UtcNow;
            return wait > TimeSpan.Zero ? wait : TimeSpan.Zero;
        }

        return null;
    }

    private static async Task<Problem> ReadProblemAsync(HttpResponseMessage response, CancellationToken cancellationToken)
    {
        try
        {
            var bytes = await response.Content.ReadAsByteArrayAsync(cancellationToken);
            if (bytes.Length == 0 || bytes.Length > 64 * 1024)
            {
                return default;
            }

            using var doc = JsonDocument.Parse(bytes);
            if (doc.RootElement.ValueKind != JsonValueKind.Object)
            {
                return default;
            }

            var root = doc.RootElement;
            DateTimeOffset? serverTime = null;
            if (root.TryGetProperty("serverTime", out var st) && st.ValueKind == JsonValueKind.String && st.TryGetDateTimeOffset(out var parsed))
            {
                serverTime = parsed;
            }

            return new Problem(GetString(root, "code"), GetString(root, "title"), GetString(root, "detail"), serverTime);
        }
        catch (JsonException)
        {
            return default;
        }
        catch (HttpRequestException)
        {
            return default;
        }
    }

    private static string? GetString(JsonElement element, string name) =>
        element.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String ? value.GetString() : null;

    private readonly record struct Problem(string? Code, string? Title, string? Detail, DateTimeOffset? ServerTime);
}
