using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using EasyPatch.Contracts;
using EasyPatch.Contracts.Agent;
using EasyPatch.Contracts.Json;
using EasyPatch.Contracts.Security;

namespace EasyPatch.Agent.Tests.Infrastructure;

/// <summary>
/// In-memory implementation of the server side of the agent protocol, used as the HttpMessageHandler of the agent's
/// HttpClient. It verifies every signature exactly like the real server must (canonical string, body hash, clock
/// window, single-use nonce), so tests fail if the agent signs anything incorrectly.
/// </summary>
public sealed class FakeAgentServer : HttpMessageHandler
{
    public static readonly Uri BaseAddress = new("https://easypatch.test/");

    private readonly Lock _lock = new();
    private readonly TimeProvider _time;
    private readonly HashSet<string> _seenNonces = new(StringComparer.Ordinal);
    private int _counter;

    public FakeAgentServer(TimeProvider time)
    {
        _time = time;
    }

    // ------------------------------------------------------------------ configuration

    public HashSet<string> ValidTokens { get; } = new(StringComparer.Ordinal);

    public HashSet<string> DeploymentCodes { get; } = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Server clock relative to the agent's TimeProvider.</summary>
    public TimeSpan ClockOffset { get; set; }

    /// <summary>When true every request fails as if the network were down.</summary>
    public bool NetworkDown { get; set; }

    /// <summary>Requests to fail with 503 before serving normally again.</summary>
    public int FailNextRequests { get; set; }

    /// <summary>Optional per-request override (route, body) → response; return null to handle normally.</summary>
    public Func<string, byte[], HttpResponseMessage?>? Override { get; set; }

    /// <summary>Lets a test rewrite the raw check-in JSON (e.g. to add a job type from a newer server).</summary>
    public Action<JsonObject>? CheckInMutator { get; set; }

    public bool RotateOnNextCheckIn { get; set; }

    public AgentConfig Config { get; set; } = new();

    /// <summary>Agent packages served at <c>GET downloads/agent/{fileName}</c> (anonymous, like the real server).</summary>
    public Dictionary<string, byte[]> Packages { get; } = new(StringComparer.Ordinal);

    /// <summary>The server's copy of the winget release at <c>GET downloads/winget/{fileName}</c>; a missing file gets
    /// 503 (the real server is then fetching its copy).</summary>
    public Dictionary<string, byte[]> WingetFiles { get; } = new(StringComparer.Ordinal);

    // ------------------------------------------------------------------ observed traffic

    public List<string> Requests { get; } = [];

    public List<EnrollRequest> EnrollRequests { get; } = [];

    public List<CheckInRequest> CheckIns { get; } = [];

    public List<ScanResultReport> ScanReports { get; } = [];

    public List<InventoryReport> InventoryReports { get; } = [];

    public List<HistoryReport> HistoryReports { get; } = [];

    public List<Guid> Acks { get; } = [];

    public Dictionary<Guid, List<JobStatusReport>> JobStatuses { get; } = [];

    public List<string> Unenrolled { get; } = [];

    public Dictionary<string, ServerCredential> Credentials { get; } = new(StringComparer.Ordinal);

    public Dictionary<string, PendingRequest> PendingRequests { get; } = new(StringComparer.Ordinal);

    public Dictionary<Guid, ServerJob> Jobs { get; } = [];

    public int RejectedSignatures { get; private set; }

    public DateTimeOffset Now => _time.GetUtcNow() + ClockOffset;

    // ------------------------------------------------------------------ admin actions

    public ServerJob EnqueueJob(AgentJob job)
    {
        lock (_lock)
        {
            var serverJob = new ServerJob(job);
            Jobs[job.JobId] = serverJob;
            return serverJob;
        }
    }

    public void CancelJob(Guid jobId)
    {
        lock (_lock)
        {
            Jobs[jobId].CancelRequested = true;
        }
    }

    public void Approve(string requestId) => SetRequestState(requestId, EnrollmentState.Active);

    public void Reject(string requestId) => SetRequestState(requestId, EnrollmentState.Rejected);

    public void Expire(string requestId) => SetRequestState(requestId, EnrollmentState.Expired);

    public void Revoke(string credentialId)
    {
        lock (_lock)
        {
            Credentials[credentialId].Revoked = true;
        }
    }

    public IReadOnlyList<JobStatusReport> StatusesFor(Guid jobId)
    {
        lock (_lock)
        {
            return JobStatuses.TryGetValue(jobId, out var list) ? list.ToList() : [];
        }
    }

    // ------------------------------------------------------------------ handler

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        if (NetworkDown)
        {
            throw new HttpRequestException("Simulated network outage.");
        }

        var body = request.Content is null ? [] : await request.Content.ReadAsByteArrayAsync(cancellationToken);
        var route = request.RequestUri!.AbsolutePath.TrimStart('/');
        lock (_lock)
        {
            Requests.Add(route);
            if (FailNextRequests > 0)
            {
                FailNextRequests--;
                return Problem(HttpStatusCode.ServiceUnavailable, null, "Simulated outage.");
            }

            if (Override?.Invoke(route, body) is { } overridden)
            {
                return overridden;
            }

            if (request.Method == HttpMethod.Get && route.StartsWith(WingetDistribution.ServerRoute, StringComparison.Ordinal))
            {
                if (WingetFiles.TryGetValue(Uri.UnescapeDataString(route[WingetDistribution.ServerRoute.Length..]), out var file))
                {
                    return new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(file) };
                }

                var preparing = new HttpResponseMessage(HttpStatusCode.ServiceUnavailable);
                preparing.Headers.RetryAfter = new System.Net.Http.Headers.RetryConditionHeaderValue(TimeSpan.FromMinutes(15));
                return preparing;
            }

            if (request.Method == HttpMethod.Get && route.StartsWith("downloads/agent/", StringComparison.Ordinal))
            {
                return Packages.TryGetValue(Uri.UnescapeDataString(route["downloads/agent/".Length..]), out var package)
                    ? new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(package) }
                    : new HttpResponseMessage(HttpStatusCode.NotFound);
            }

            if (request.Method != HttpMethod.Post)
            {
                return Problem(HttpStatusCode.MethodNotAllowed, null, "POST only.");
            }

            return route == AgentRoutes.Enroll ? HandleEnroll(body) : HandleSigned(request, route, body);
        }
    }

    private HttpResponseMessage HandleEnroll(byte[] body)
    {
        var enroll = Read<EnrollRequest>(body);
        EnrollRequests.Add(enroll);
        if (!AgentKeys.TryParsePublicKey(enroll.PublicKey, out var spki))
        {
            return Problem(HttpStatusCode.BadRequest, AgentErrorCodes.ValidationFailed, "Bad public key.");
        }

        var fingerprint = AgentKeys.Fingerprint(spki);
        if (enroll.EnrollmentToken is { } token)
        {
            if (!ValidTokens.Contains(token))
            {
                return Problem(HttpStatusCode.Unauthorized, AgentErrorCodes.EnrollmentInvalid, "Invalid enrollment token.");
            }

            var credential = CreateCredential(spki, Guid.NewGuid());
            return Json(new EnrollResponse
            {
                State = EnrollmentState.Active,
                CredentialId = credential.Id,
                EndpointId = credential.EndpointId,
                OrganizationId = Guid.Empty,
                CredentialExpiresAt = Now.AddDays(90),
                Config = Config,
                KeyFingerprint = fingerprint,
                ServerTime = Now,
            });
        }

        if (enroll.DeploymentCode is { } code && DeploymentCodes.Contains(code))
        {
            var existing = PendingRequests.Values.FirstOrDefault(p => p.Fingerprint == fingerprint);
            var pending = existing ?? new PendingRequest($"r_{Next()}", spki, fingerprint);
            PendingRequests[pending.Id] = pending;
            return Json(new EnrollResponse
            {
                State = EnrollmentState.PendingApproval,
                CredentialId = pending.Id,
                KeyFingerprint = fingerprint,
                ServerTime = Now,
            });
        }

        return Problem(HttpStatusCode.Unauthorized, AgentErrorCodes.EnrollmentInvalid, "Invalid enrollment credential.");
    }

    private HttpResponseMessage HandleSigned(HttpRequestMessage request, string route, byte[] body)
    {
        var authError = Authenticate(request, route, body, out var credentialId);
        if (authError is not null)
        {
            return authError;
        }

        if (credentialId.StartsWith("r_", StringComparison.Ordinal))
        {
            return HandleEnrollmentStatus(credentialId);
        }

        var credential = Credentials[credentialId];
        if (route == AgentRoutes.CheckIn)
        {
            return HandleCheckIn(Read<CheckInRequest>(body));
        }

        if (route == AgentRoutes.ScanResults)
        {
            ScanReports.Add(Read<ScanResultReport>(body));
            return Accepted();
        }

        if (route == AgentRoutes.Inventory)
        {
            InventoryReports.Add(Read<InventoryReport>(body));
            return Accepted();
        }

        if (route == AgentRoutes.History)
        {
            HistoryReports.Add(Read<HistoryReport>(body));
            return Accepted();
        }

        if (route == AgentRoutes.RotateCredential)
        {
            var rotate = Read<RotateCredentialRequest>(body);
            if (!AgentKeys.TryParsePublicKey(rotate.PublicKey, out var spki))
            {
                return Problem(HttpStatusCode.BadRequest, AgentErrorCodes.ValidationFailed, "Bad public key.");
            }

            var replacement = CreateCredential(spki, credential.EndpointId);
            return Json(new RotateCredentialResponse
            {
                CredentialId = replacement.Id,
                ExpiresAt = Now.AddDays(90),
                KeyFingerprint = AgentKeys.Fingerprint(spki),
            });
        }

        if (route == AgentRoutes.Unenroll)
        {
            Unenrolled.Add(credentialId);
            credential.Revoked = true;
            return Accepted();
        }

        var parts = route.Split('/');
        if (parts.Length == 6 && parts[3] == "jobs" && Guid.TryParse(parts[4], out var jobId))
        {
            if (!Jobs.TryGetValue(jobId, out var job))
            {
                return Problem(HttpStatusCode.NotFound, AgentErrorCodes.JobNotFound, "Unknown job.");
            }

            if (parts[5] == "ack")
            {
                Acks.Add(jobId);
                if (job.CancelRequested)
                {
                    job.Status = JobStatus.Cancelled;
                    return Json(new JobAckResponse { Accepted = false, Reason = "The job was cancelled." });
                }

                job.Status = JobStatus.Acknowledged;
                return Json(new JobAckResponse { Accepted = true });
            }

            if (parts[5] == "status")
            {
                var report = Read<JobStatusReport>(body);
                if (!JobStatuses.TryGetValue(jobId, out var list))
                {
                    JobStatuses[jobId] = list = [];
                }

                if (list.Count == 0 || report.Sequence > list[^1].Sequence)
                {
                    list.Add(report);
                    job.Status = report.Status;
                }

                return Accepted();
            }
        }

        return Problem(HttpStatusCode.NotFound, null, $"No route {route}.");
    }

    private HttpResponseMessage HandleEnrollmentStatus(string requestId)
    {
        var pending = PendingRequests[requestId];
        switch (pending.State)
        {
            case EnrollmentState.Active:
                pending.Credential ??= CreateCredential(pending.PublicKey, Guid.NewGuid());
                return Json(new EnrollResponse
                {
                    State = EnrollmentState.Active,
                    CredentialId = pending.Credential.Id,
                    EndpointId = pending.Credential.EndpointId,
                    CredentialExpiresAt = Now.AddDays(90),
                    Config = Config,
                    KeyFingerprint = pending.Fingerprint,
                    ServerTime = Now,
                });
            default:
                return Json(new EnrollResponse
                {
                    State = pending.State,
                    CredentialId = requestId,
                    KeyFingerprint = pending.Fingerprint,
                    ServerTime = Now,
                });
        }
    }

    private HttpResponseMessage HandleCheckIn(CheckInRequest checkIn)
    {
        CheckIns.Add(checkIn);
        var deliver = new List<AgentJob>();
        foreach (var job in Jobs.Values)
        {
            if (job.Status == JobStatus.Queued ||
                (job.Status.IsInFlight() && !checkIn.ActiveJobIds.Contains(job.Job.JobId) && !job.CancelRequested))
            {
                job.Status = JobStatus.Delivered;
                job.Deliveries++;
                deliver.Add(job.Job);
            }
        }

        var cancels = Jobs.Values.Where(j => j.CancelRequested && checkIn.ActiveJobIds.Contains(j.Job.JobId)).Select(j => j.Job.JobId).ToList();
        var response = new CheckInResponse
        {
            ServerTime = Now,
            Config = Config,
            Jobs = deliver,
            CancelJobIds = cancels,
            RotateCredential = RotateOnNextCheckIn,
        };
        RotateOnNextCheckIn = false;

        if (CheckInMutator is null)
        {
            return Json(response);
        }

        var node = JsonSerializer.SerializeToNode(response, ContractJson.Options)!.AsObject();
        CheckInMutator(node);
        return Raw(HttpStatusCode.OK, node.ToJsonString());
    }

    private HttpResponseMessage? Authenticate(HttpRequestMessage request, string route, byte[] body, out string credentialId)
    {
        credentialId = Header(request, AgentAuthHeaders.Credential) ?? string.Empty;
        var timestampText = Header(request, AgentAuthHeaders.Timestamp);
        var nonce = Header(request, AgentAuthHeaders.Nonce);
        var contentHash = Header(request, AgentAuthHeaders.ContentSha256);
        var signature = Header(request, AgentAuthHeaders.Signature);
        if (credentialId.Length == 0 || timestampText is null || nonce is null || contentHash is null || signature is null ||
            !long.TryParse(timestampText, out var timestamp))
        {
            RejectedSignatures++;
            return Problem(HttpStatusCode.Unauthorized, AgentErrorCodes.InvalidSignature, "Missing authentication headers.");
        }

        byte[] spki;
        if (credentialId.StartsWith("r_", StringComparison.Ordinal))
        {
            if (route != AgentRoutes.EnrollmentStatus || !PendingRequests.TryGetValue(credentialId, out var pending))
            {
                return Problem(HttpStatusCode.Unauthorized, AgentErrorCodes.UnknownCredential, "Unknown request.");
            }

            spki = pending.PublicKey;
        }
        else
        {
            if (!Credentials.TryGetValue(credentialId, out var credential) || route == AgentRoutes.EnrollmentStatus)
            {
                return Problem(HttpStatusCode.Unauthorized, AgentErrorCodes.UnknownCredential, "Unknown credential.");
            }

            if (credential.Revoked)
            {
                return Problem(HttpStatusCode.Unauthorized, AgentErrorCodes.CredentialRevoked, "Credential revoked.");
            }

            spki = credential.PublicKey;
        }

        var skew = DateTimeOffset.FromUnixTimeSeconds(timestamp) - Now;
        if (skew.Duration() > RequestSigner.AllowedClockSkew)
        {
            return Problem(HttpStatusCode.Unauthorized, AgentErrorCodes.ClockSkew, "Clock skew.");
        }

        if (!RequestSigner.IsValidNonce(nonce) || !_seenNonces.Add(nonce))
        {
            return Problem(HttpStatusCode.Unauthorized, AgentErrorCodes.ReplayedNonce, "Nonce replayed.");
        }

        var canonical = RequestSigner.BuildCanonicalString("POST", request.RequestUri!.PathAndQuery, timestamp, nonce, contentHash, credentialId);
        using var key = AgentKeys.ImportPublicKey(spki);
        if (!string.Equals(RequestSigner.ComputeContentHash(body), contentHash, StringComparison.Ordinal) ||
            !RequestSigner.Verify(key, canonical, signature))
        {
            RejectedSignatures++;
            return Problem(HttpStatusCode.Unauthorized, AgentErrorCodes.InvalidSignature, "Bad signature.");
        }

        return null;
    }

    private ServerCredential CreateCredential(byte[] spki, Guid endpointId)
    {
        var credential = new ServerCredential($"c_{Next()}", spki, endpointId);
        Credentials[credential.Id] = credential;
        return credential;
    }

    private void SetRequestState(string requestId, EnrollmentState state)
    {
        lock (_lock)
        {
            PendingRequests[requestId].State = state;
        }
    }

    private string Next() => Interlocked.Increment(ref _counter).ToString("D4", System.Globalization.CultureInfo.InvariantCulture) +
                             Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(4));

    private static string? Header(HttpRequestMessage request, string name) =>
        request.Headers.TryGetValues(name, out var values) ? values.FirstOrDefault() : null;

    private static T Read<T>(byte[] body) => JsonSerializer.Deserialize<T>(body, ContractJson.Options)!;

    private HttpResponseMessage Json<T>(T value) =>
        Raw(HttpStatusCode.OK, JsonSerializer.Serialize(value, ContractJson.Options));

    private HttpResponseMessage Accepted() => Raw(HttpStatusCode.Accepted, "{}");

    private HttpResponseMessage Raw(HttpStatusCode status, string json)
    {
        var response = new HttpResponseMessage(status)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json"),
        };
        response.Headers.Date = Now;
        return response;
    }

    public HttpResponseMessage Problem(HttpStatusCode status, string? code, string detail)
    {
        var problem = new JsonObject
        {
            ["title"] = status.ToString(),
            ["status"] = (int)status,
            ["detail"] = detail,
            ["serverTime"] = Now.ToString("O", System.Globalization.CultureInfo.InvariantCulture),
        };
        if (code is not null)
        {
            problem["code"] = code;
        }

        var response = new HttpResponseMessage(status)
        {
            Content = new StringContent(problem.ToJsonString(), Encoding.UTF8, "application/problem+json"),
        };
        response.Headers.Date = Now;
        return response;
    }
}

public sealed class ServerCredential(string id, byte[] publicKey, Guid endpointId)
{
    public string Id { get; } = id;
    public byte[] PublicKey { get; } = publicKey;
    public Guid EndpointId { get; } = endpointId;
    public bool Revoked { get; set; }
}

public sealed class PendingRequest(string id, byte[] publicKey, string fingerprint)
{
    public string Id { get; } = id;
    public byte[] PublicKey { get; } = publicKey;
    public string Fingerprint { get; } = fingerprint;
    public EnrollmentState State { get; set; } = EnrollmentState.PendingApproval;
    public ServerCredential? Credential { get; set; }
}

public sealed class ServerJob(AgentJob job)
{
    public AgentJob Job { get; } = job;
    public JobStatus Status { get; set; } = JobStatus.Queued;
    public bool CancelRequested { get; set; }
    public int Deliveries { get; set; }
}
