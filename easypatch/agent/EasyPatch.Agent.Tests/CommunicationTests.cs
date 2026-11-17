using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using EasyPatch.Agent.Core.State;
using EasyPatch.Agent.Tests.Infrastructure;
using EasyPatch.Communication;
using EasyPatch.Contracts;
using EasyPatch.Contracts.Agent;
using EasyPatch.Contracts.Security;
using Xunit;

namespace EasyPatch.Agent.Tests;

public sealed class CommunicationTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    [Fact]
    public async Task Signed_requests_bind_method_path_body_time_nonce_and_credential()
    {
        var time = new ManualTimeProvider(DateTimeOffset.UnixEpoch.AddYears(56));
        using var key = AgentKeys.Generate();
        var capture = new CapturingHandler();
        using var http = new HttpClient(capture) { BaseAddress = new Uri("https://patch.example.com/easypatch/") };
        var client = new AgentApiClient(http, new StaticCredential("c_abc", key), new ServerClock(time, TimeSpan.Zero), "1.2.3");

        await client.CheckInAsync(new CheckInRequest { AgentVersion = "1.2.3" }, Ct);

        var request = capture.Last!;
        Assert.Equal("/easypatch/api/v1/agents/check-in", request.Uri.PathAndQuery);
        Assert.Equal("c_abc", request.Headers[AgentAuthHeaders.Credential]);
        Assert.Equal(time.GetUtcNow().ToUnixTimeSeconds().ToString(System.Globalization.CultureInfo.InvariantCulture), request.Headers[AgentAuthHeaders.Timestamp]);
        Assert.True(RequestSigner.IsValidNonce(request.Headers[AgentAuthHeaders.Nonce]));
        Assert.Equal(RequestSigner.ComputeContentHash(request.Body), request.Headers[AgentAuthHeaders.ContentSha256]);
        Assert.StartsWith("EasyPatchAgent/1.2.3", request.UserAgent, StringComparison.Ordinal);

        var canonical = RequestSigner.BuildCanonicalString("POST", request.Uri.PathAndQuery, long.Parse(request.Headers[AgentAuthHeaders.Timestamp], System.Globalization.CultureInfo.InvariantCulture),
            request.Headers[AgentAuthHeaders.Nonce], request.Headers[AgentAuthHeaders.ContentSha256], "c_abc");
        Assert.True(RequestSigner.Verify(key, canonical, request.Headers[AgentAuthHeaders.Signature]));

        // Any change to the signed material invalidates the signature.
        var tamperedPath = canonical.Replace("/check-in", "/inventory", StringComparison.Ordinal);
        Assert.False(RequestSigner.Verify(key, tamperedPath, request.Headers[AgentAuthHeaders.Signature]));
        using var otherKey = AgentKeys.Generate();
        Assert.False(RequestSigner.Verify(otherKey, canonical, request.Headers[AgentAuthHeaders.Signature]));

        // Nonces are never reused.
        await client.CheckInAsync(new CheckInRequest { AgentVersion = "1.2.3" }, Ct);
        Assert.NotEqual(request.Headers[AgentAuthHeaders.Nonce], capture.Last!.Headers[AgentAuthHeaders.Nonce]);
    }

    [Fact]
    public async Task Clock_skew_rejection_corrects_the_offset_and_retries_once()
    {
        using var h = new AgentHarness();
        await h.EnrollWithTokenAsync();
        h.Server.ClockOffset = TimeSpan.FromMinutes(20);
        var before = h.Server.Requests.Count;

        Assert.NotNull(await h.Runtime.CheckInOnceAsync(Ct));

        Assert.InRange(h.Runtime.Clock.Offset.TotalMinutes, 19.9, 20.1);
        Assert.InRange(h.Runtime.State.Read(s => s.ServerClockOffsetSeconds), 1190, 1210);
        Assert.Equal(2, h.Server.Requests.Skip(before).Count(r => r == AgentRoutes.CheckIn));
        Assert.Single(h.Server.CheckIns);

        // The corrected offset is persisted and used after a restart.
        var restarted = h.Restart();
        Assert.NotNull(await restarted.CheckInOnceAsync(Ct));
        Assert.Equal(2, h.Server.CheckIns.Count);
    }

    [Fact]
    public async Task Revoked_credential_suspends_the_agent_and_discards_queued_reports()
    {
        using var h = new AgentHarness();
        await h.EnrollWithTokenAsync();
        await h.Runtime.RunScanAsync(ScanTrigger.Scheduled, Ct);
        Assert.True(h.Runtime.Outbox.Count > 0);
        h.Server.Revoke(h.Runtime.State.Read(s => s.CredentialId)!);

        var error = await Assert.ThrowsAsync<AgentAuthException>(() => h.Runtime.CheckInOnceAsync(Ct));

        Assert.True(error.IsFatal);
        Assert.Equal(AgentErrorCodes.CredentialRevoked, error.ErrorCode);
        Assert.Equal(AgentEnrollmentStatus.Revoked, h.Runtime.State.Read(s => s.Status));
        Assert.Equal(0, h.Runtime.Outbox.Count);
        Assert.Null(await h.Runtime.CheckInOnceAsync(Ct)); // no further authenticated traffic
    }

    [Fact]
    public async Task Revoked_agent_reenrolls_only_with_a_new_enrollment_credential()
    {
        using var h = new AgentHarness();
        await h.EnrollWithTokenAsync();
        var oldFingerprint = h.Runtime.State.Read(s => s.KeyFingerprint);
        h.Server.Revoke(h.Runtime.State.Read(s => s.CredentialId)!);
        await Assert.ThrowsAsync<AgentAuthException>(() => h.Runtime.CheckInOnceAsync(Ct));

        Assert.Equal(Core.Enrollment.EnrollmentOutcome.NotConfigured, await h.Runtime.EnsureEnrolledAsync(Ct));

        h.Bootstrap.EnrollmentToken = AgentHarness.Token;
        Assert.Equal(Core.Enrollment.EnrollmentOutcome.Active, await h.Runtime.EnsureEnrolledAsync(Ct));
        Assert.NotEqual(oldFingerprint, h.Runtime.State.Read(s => s.KeyFingerprint));
    }

    [Theory]
    [InlineData(HttpStatusCode.ServiceUnavailable)]
    [InlineData(HttpStatusCode.InternalServerError)]
    [InlineData(HttpStatusCode.TooManyRequests)]
    public async Task Server_errors_are_transient(HttpStatusCode status)
    {
        using var h = new AgentHarness();
        await h.EnrollWithTokenAsync();
        h.Server.Override = (route, _) =>
        {
            if (route != AgentRoutes.CheckIn)
            {
                return null;
            }

            var response = h.Server.Problem(status, status == HttpStatusCode.TooManyRequests ? AgentErrorCodes.RateLimited : null, "busy");
            response.Headers.RetryAfter = new System.Net.Http.Headers.RetryConditionHeaderValue(TimeSpan.FromSeconds(120));
            return response;
        };

        var error = await Assert.ThrowsAsync<AgentTransientException>(() => h.Runtime.CheckInOnceAsync(Ct));
        Assert.Equal(status, error.StatusCode);
        Assert.Equal(TimeSpan.FromSeconds(120), error.RetryAfter);
        Assert.Equal(AgentEnrollmentStatus.Active, h.Runtime.State.Read(s => s.Status));
    }

    [Fact]
    public async Task Malformed_responses_are_transient_not_success()
    {
        using var h = new AgentHarness();
        await h.EnrollWithTokenAsync();
        h.Server.Override = (route, _) => route == AgentRoutes.CheckIn
            ? new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent("<html>proxy login</html>", Encoding.UTF8, "text/html") }
            : null;

        await Assert.ThrowsAsync<AgentTransientException>(() => h.Runtime.CheckInOnceAsync(Ct));
        Assert.Null(h.Runtime.State.Read(s => s.LastCheckInAt));
    }

    [Fact]
    public async Task Check_in_skips_jobs_this_agent_version_cannot_read()
    {
        using var h = new AgentHarness();
        await h.EnrollWithTokenAsync();
        var known = AgentHarness.SimpleJob(JobType.UpdateScan);
        h.Server.EnqueueJob(known);
        h.Server.CheckInMutator = root =>
        {
            root["jobs"]!.AsArray().Add(new JsonObject
            {
                ["jobId"] = Guid.NewGuid().ToString(),
                ["type"] = "SomethingFromTheFuture",
                ["expiresAt"] = "2027-01-01T00:00:00Z",
            });
        };

        var response = await h.Runtime.CheckInOnceAsync(Ct);

        Assert.NotNull(response);
        Assert.Equal(known.JobId, Assert.Single(response.Jobs).JobId);
        Assert.Contains(known.JobId, h.Server.Acks);
    }

    [Fact]
    public async Task Check_in_reports_reboot_state_and_held_jobs()
    {
        using var h = new AgentHarness();
        await h.EnrollWithTokenAsync();
        h.RebootDetector.Status = new Core.Abstractions.RebootStatus(true, ["Component Based Servicing (RebootPending)"]);
        var job = AgentHarness.SimpleJob(JobType.UpdateScan);
        await h.DeliverAsync(job);

        await h.Runtime.CheckInOnceAsync(Ct);

        var last = h.Server.CheckIns[^1];
        Assert.True(last.RebootPending);
        Assert.Contains("Component Based Servicing (RebootPending)", last.RebootReasons);
        Assert.Contains(job.JobId, last.ActiveJobIds);
        Assert.Equal(h.BootTime.Boot, last.LastBootAt);
        Assert.Equal(1, h.Server.Jobs[job.JobId].Deliveries); // held, so not re-delivered
        Assert.Null(last.RebootDetails);
    }

    [Fact]
    public async Task Check_in_reports_what_the_restart_is_for_only_while_one_is_pending()
    {
        using var h = new AgentHarness();
        await h.EnrollWithTokenAsync();
        var update = Guid.NewGuid();
        var details = new RebootDetails
        {
            WindowsUpdateIds = [update],
            FileOperations = [new PendingFileOperation { Action = PendingFileOperation.Replace, Path = @"C:\Program Files\Contoso\contoso.dll" }],
            FileOperationCount = 1,
        };
        h.RebootDetector.Status = new Core.Abstractions.RebootStatus(true, ["Windows Update (RebootRequired)"], details);

        await h.Runtime.CheckInOnceAsync(Ct);
        var pending = h.Server.CheckIns[^1];
        Assert.Equal([update], pending.RebootDetails!.WindowsUpdateIds);
        Assert.Equal(@"C:\Program Files\Contoso\contoso.dll", Assert.Single(pending.RebootDetails.FileOperations).Path);

        h.RebootDetector.Status = Core.Abstractions.RebootStatus.None;
        await h.Runtime.CheckInOnceAsync(Ct);
        Assert.Null(h.Server.CheckIns[^1].RebootDetails);
    }

    [Fact]
    public void Server_url_normalization_requires_https_and_rejects_credentials()
    {
        Assert.Equal(new Uri("https://patch.example.com/base/"), Core.Runtime.ApiClientAccessor.NormalizeServerUrl("https://patch.example.com/base", requireHttps: true));
        Assert.Throws<ArgumentException>(() => Core.Runtime.ApiClientAccessor.NormalizeServerUrl("http://patch.example.com", requireHttps: true));
        Assert.Throws<ArgumentException>(() => Core.Runtime.ApiClientAccessor.NormalizeServerUrl("https://user:pw@patch.example.com", requireHttps: true));
        Assert.Throws<ArgumentException>(() => Core.Runtime.ApiClientAccessor.NormalizeServerUrl("https://patch.example.com/?x=1", requireHttps: true));
        Assert.Throws<ArgumentException>(() => Core.Runtime.ApiClientAccessor.NormalizeServerUrl("patch.example.com", requireHttps: true));
    }

    [Fact]
    public void Server_clock_ignores_small_differences_and_tracks_large_ones()
    {
        var time = new ManualTimeProvider(DateTimeOffset.UnixEpoch.AddYears(56));
        var clock = new ServerClock(time, TimeSpan.Zero);

        clock.Observe(time.GetUtcNow().AddSeconds(2));
        Assert.Equal(TimeSpan.Zero, clock.Offset);

        clock.Observe(time.GetUtcNow().AddMinutes(-7));
        Assert.Equal(TimeSpan.FromMinutes(-7), clock.Offset);
        Assert.Equal(time.GetUtcNow().AddMinutes(-7), clock.Now);
    }

    private sealed class StaticCredential(string id, ECDsa key) : ISigningCredentialProvider
    {
        public SigningCredential? GetSigningCredential() => new(id, key);
    }

    private sealed record CapturedRequest(Uri Uri, Dictionary<string, string> Headers, byte[] Body, string UserAgent);

    private sealed class CapturingHandler : HttpMessageHandler
    {
        public CapturedRequest? Last { get; private set; }

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var headers = request.Headers.Where(h => h.Key.StartsWith("X-EasyPatch-", StringComparison.Ordinal))
                .ToDictionary(h => h.Key, h => h.Value.First(), StringComparer.Ordinal);
            var body = await request.Content!.ReadAsByteArrayAsync(cancellationToken);
            Last = new CapturedRequest(request.RequestUri!, headers, body, request.Headers.UserAgent.ToString());
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("""{"config":{},"jobs":[]}""", Encoding.UTF8, "application/json"),
            };
        }
    }
}
