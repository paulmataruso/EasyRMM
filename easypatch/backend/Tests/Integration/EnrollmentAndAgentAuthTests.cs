using System.Net;
using System.Net.Http.Json;
using EasyPatch.Api.Contracts;
using EasyPatch.Contracts;
using EasyPatch.Contracts.Agent;
using EasyPatch.Contracts.Security;
using EasyPatch.Core.Entities;
using EasyPatch.Infrastructure.Security;
using Microsoft.EntityFrameworkCore;
using Xunit;

namespace EasyPatch.Tests.Integration;

public sealed class EnrollmentTests(PostgresFixture postgres) : IntegrationTest(postgres)
{
    private static async Task<EnrollResponse> ReadEnrollAsync(HttpResponseMessage response)
    {
        await AdminSession.EnsureAsync(response, HttpStatusCode.OK);
        return (await response.Content.ReadFromJsonAsync<EnrollResponse>(TestJson.Options))!;
    }

    [Fact]
    public async Task Tokens_are_use_limited_expire_and_can_be_revoked_and_are_stored_hashed()
    {
        var root = await SuperAdminAsync();
        var (org, site) = await CreateOrgAsync(root);

        var single = await CreateTokenAsync(root, org.Id, site.Id, maxUses: 1);
        Assert.StartsWith("ept_", single, StringComparison.Ordinal);
        using (var first = await NewAgent().EnrollAsync(single, null, "PC-1"))
        {
            Assert.Equal(EnrollmentState.Active, (await ReadEnrollAsync(first)).State);
        }

        using (var reused = await NewAgent().EnrollAsync(single, null, "PC-2"))
        {
            Assert.Equal(HttpStatusCode.Unauthorized, reused.StatusCode);
            Assert.Equal(AgentErrorCodes.EnrollmentInvalid, await AdminSession.ProblemCodeAsync(reused));
        }

        var expiring = await CreateTokenAsync(root, org.Id, site.Id, hours: 1);
        Clock.Advance(TimeSpan.FromMinutes(61));
        root = await LoginAsync("root", DefaultPassword, root.MfaSecret); // the session idled out meanwhile
        using (var expired = await NewAgent().EnrollAsync(expiring, null, "PC-3"))
        {
            Assert.Equal(HttpStatusCode.Unauthorized, expired.StatusCode);
        }

        var revocable = await root.SendAsync<List<CreatedTokenDto>>(HttpMethod.Post, "/api/v1/enrollment-tokens",
            new CreateTokensRequest(org.Id, site.Id, "to revoke", 24, 10, 1), HttpStatusCode.OK);
        await root.ExpectAsync(HttpMethod.Post, $"/api/v1/enrollment-tokens/{revocable[0].Token.Id}/revoke", null, HttpStatusCode.NoContent);
        using (var revoked = await NewAgent().EnrollAsync(revocable[0].PlaintextToken, null, "PC-4"))
        {
            Assert.Equal(HttpStatusCode.Unauthorized, revoked.StatusCode);
        }

        var hashes = await WithDbAsync(db => db.EnrollmentTokens.Select(t => t.TokenHash).ToListAsync());
        Assert.DoesNotContain(single, hashes);
        Assert.Contains(SecureTokens.Hash(single), hashes);
        Assert.DoesNotContain(revocable[0].PlaintextToken, revocable[0].Token.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Tokenless_deployment_code_enrollment_waits_for_administrator_approval()
    {
        var root = await SuperAdminAsync();
        var (org, site) = await CreateOrgAsync(root);
        var code = await root.SendAsync<DeploymentCodeDto>(HttpMethod.Post, "/api/v1/deployment-codes",
            new CreateDeploymentCodeRequest(org.Id, site.Id, "RMM rollout", 30, null, null), HttpStatusCode.Created);

        var agent = NewAgent();
        var pending = await ReadEnrollAsync(await agent.EnrollAsync(null, code.Code, "RMM-PC1"));
        Assert.Equal(EnrollmentState.PendingApproval, pending.State);
        Assert.StartsWith("r_", pending.CredentialId, StringComparison.Ordinal);
        Assert.Null(pending.EndpointId);
        agent.CredentialId = pending.CredentialId;

        // A pending request can only poll its status: no check-in, no reports.
        using (var checkIn = await agent.PostAsync(AgentRoutes.CheckIn, new CheckInRequest { AgentVersion = "1.0.0" }))
        {
            Assert.Equal(HttpStatusCode.Forbidden, checkIn.StatusCode);
        }

        using (var poll = await agent.PostAsync(AgentRoutes.EnrollmentStatus, new { }))
        {
            Assert.Equal(EnrollmentState.PendingApproval, (await ReadEnrollAsync(poll)).State);
        }

        var requests = await root.GetAsync<PagedResult<EnrollmentRequestDto>>("/api/v1/enrollment-requests");
        var request = Assert.Single(requests.Items);
        Assert.Equal("RMM-PC1", request.Hostname);
        Assert.Equal(pending.KeyFingerprint, request.KeyFingerprint); // admin compares this with the agent's local fingerprint
        Assert.Equal(0, await WithDbAsync(db => db.Endpoints.CountAsync()));

        await root.SendAsync<object>(HttpMethod.Post, $"/api/v1/enrollment-requests/{request.Id}/approve", new ApproveRequest(null, null), HttpStatusCode.OK);

        EnrollResponse active;
        using (var poll = await agent.PostAsync(AgentRoutes.EnrollmentStatus, new { }))
        {
            active = await ReadEnrollAsync(poll);
        }

        Assert.Equal(EnrollmentState.Active, active.State);
        Assert.StartsWith("c_", active.CredentialId, StringComparison.Ordinal);
        agent.CredentialId = active.CredentialId;
        agent.EndpointId = active.EndpointId!.Value;
        await agent.CheckInAsync();

        var endpoint = await root.GetAsync<EndpointDetailDto>($"/api/v1/endpoints/{agent.EndpointId}");
        Assert.Equal(site.Id, endpoint.Summary.SiteId);
        Assert.Contains("enrollment_request.approve", await WithDbAsync(db => db.AuditLogs.Select(a => a.Action).ToListAsync()));
    }

    [Fact]
    public async Task Rejected_requests_never_become_endpoints()
    {
        var root = await SuperAdminAsync();
        var (org, _) = await CreateOrgAsync(root);
        var code = await root.SendAsync<DeploymentCodeDto>(HttpMethod.Post, "/api/v1/deployment-codes",
            new CreateDeploymentCodeRequest(org.Id, null, "RMM", 30, null, null), HttpStatusCode.Created);
        var agent = NewAgent();
        agent.CredentialId = (await ReadEnrollAsync(await agent.EnrollAsync(null, code.Code, "UNKNOWN-PC"))).CredentialId;

        var request = (await root.GetAsync<PagedResult<EnrollmentRequestDto>>("/api/v1/enrollment-requests")).Items.Single();
        await root.ExpectAsync(HttpMethod.Post, $"/api/v1/enrollment-requests/{request.Id}/reject", new RejectRequest("Not one of ours"), HttpStatusCode.NoContent);
        await root.ExpectAsync(HttpMethod.Post, $"/api/v1/enrollment-requests/{request.Id}/approve", new ApproveRequest(null, null), HttpStatusCode.Conflict,
            "invalid_state");

        using var poll = await agent.PostAsync(AgentRoutes.EnrollmentStatus, new { });
        var status = await ReadEnrollAsync(poll);
        Assert.Equal(EnrollmentState.Rejected, status.State);
        Assert.Equal("Not one of ours", status.Message);
        Assert.Equal(0, await WithDbAsync(db => db.Endpoints.CountAsync()));
    }

    [Fact]
    public async Task Deployment_codes_can_be_restricted_to_source_networks_and_revoked()
    {
        var root = await SuperAdminAsync();
        var (org, _) = await CreateOrgAsync(root);
        var restricted = await root.SendAsync<DeploymentCodeDto>(HttpMethod.Post, "/api/v1/deployment-codes",
            new CreateDeploymentCodeRequest(org.Id, null, "Branch only", 30, ["203.0.113.0/24"], null), HttpStatusCode.Created);
        using (var outside = await NewAgent().EnrollAsync(null, restricted.Code, "PC-X"))
        {
            Assert.Equal(HttpStatusCode.Unauthorized, outside.StatusCode); // the test server's client address is not in 203.0.113.0/24
        }

        var open = await root.SendAsync<DeploymentCodeDto>(HttpMethod.Post, "/api/v1/deployment-codes",
            new CreateDeploymentCodeRequest(org.Id, null, "Anywhere", 30, null, null), HttpStatusCode.Created);
        await root.ExpectAsync(HttpMethod.Post, $"/api/v1/deployment-codes/{open.Id}/revoke", null, HttpStatusCode.NoContent);
        using var revoked = await NewAgent().EnrollAsync(null, open.Code, "PC-Y");
        Assert.Equal(HttpStatusCode.Unauthorized, revoked.StatusCode);
    }
}

public sealed class AgentAuthenticationTests(PostgresFixture postgres) : IntegrationTest(postgres)
{
    private async Task<(AdminSession Root, SignedAgent Agent)> EnrolledAsync()
    {
        var root = await SuperAdminAsync();
        var (org, site) = await CreateOrgAsync(root);
        return (root, await EnrollAgentAsync(root, org.Id, site.Id, "SIGNED-PC"));
    }

    private static async Task ExpectRejectedAsync(HttpResponseMessage response, string code)
    {
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal(code, await AdminSession.ProblemCodeAsync(response));
        response.Dispose();
    }

    [Fact]
    public async Task Unsigned_tampered_replayed_and_skewed_requests_are_rejected()
    {
        var (_, agent) = await EnrolledAsync();
        await agent.CheckInAsync();

        var http = NewHttpClient();
        await ExpectRejectedAsync(await http.PostAsJsonAsync(new Uri("/" + AgentRoutes.CheckIn, UriKind.Relative),
            new CheckInRequest { AgentVersion = "1.0.0" }, TestJson.Options), AgentErrorCodes.InvalidSignature);

        // Body changed after signing.
        await ExpectRejectedAsync(await agent.PostAsync(AgentRoutes.CheckIn, new CheckInRequest { AgentVersion = "1.0.0" },
            tamper: r => r.Content = JsonContent.Create(new CheckInRequest { AgentVersion = "9.9.9" }, options: TestJson.Options)), AgentErrorCodes.InvalidSignature);

        // Signature for a different path.
        await ExpectRejectedAsync(await agent.PostAsync(AgentRoutes.CheckIn, new CheckInRequest { AgentVersion = "1.0.0" },
            tamper: r => r.RequestUri = new Uri("/" + AgentRoutes.Inventory, UriKind.Relative)), AgentErrorCodes.InvalidSignature);

        // Replay of a nonce that was already accepted.
        using (var ok = await agent.PostAsync(AgentRoutes.CheckIn, new CheckInRequest { AgentVersion = "1.0.0" }))
        {
            Assert.Equal(HttpStatusCode.OK, ok.StatusCode);
        }

        await ExpectRejectedAsync(await agent.PostAsync(AgentRoutes.CheckIn, new CheckInRequest { AgentVersion = "1.0.0" }, nonce: agent.LastNonce),
            AgentErrorCodes.ReplayedNonce);

        // Clock skew: the response carries serverTime so the agent can correct its offset.
        using var skewed = await agent.PostAsync(AgentRoutes.CheckIn, new CheckInRequest { AgentVersion = "1.0.0" }, at: Clock.GetUtcNow().AddMinutes(-6));
        Assert.Equal(HttpStatusCode.Unauthorized, skewed.StatusCode);
        var body = await skewed.Content.ReadAsStringAsync();
        Assert.Contains(AgentErrorCodes.ClockSkew, body, StringComparison.Ordinal);
        Assert.Contains("serverTime", body, StringComparison.Ordinal);

        // A key that was never registered.
        using var impostor = NewAgent();
        impostor.CredentialId = agent.CredentialId;
        await ExpectRejectedAsync(await impostor.PostAsync(AgentRoutes.CheckIn, new CheckInRequest { AgentVersion = "1.0.0" }), AgentErrorCodes.InvalidSignature);

        // Credentials are stored as public keys only.
        var stored = await WithDbAsync(db => db.AgentCredentials.AsNoTracking().SingleAsync());
        Assert.Equal(AgentKeys.ExportPublicKey(agent.Key), stored.PublicKey);
    }

    [Fact]
    public async Task Revoked_endpoints_and_rotated_credentials_lose_access()
    {
        var (root, agent) = await EnrolledAsync();

        // Rotation: the new key is registered with a request signed by the old one; the old credential stops working.
        using var newKey = AgentKeys.Generate();
        RotateCredentialResponse rotated;
        using (var response = await agent.PostAsync(AgentRoutes.RotateCredential,
                   new RotateCredentialRequest { PublicKey = Convert.ToBase64String(AgentKeys.ExportPublicKey(newKey)) }))
        {
            await AdminSession.EnsureAsync(response, HttpStatusCode.OK);
            rotated = (await response.Content.ReadFromJsonAsync<RotateCredentialResponse>(TestJson.Options))!;
        }

        // In-flight requests signed with the old key keep working for a short grace period, then the old credential expires.
        await agent.CheckInAsync();
        var renewed = new SignedAgent(NewHttpClient(), Clock) { CredentialId = rotated.CredentialId, EndpointId = agent.EndpointId };
        renewed.Key.ImportECPrivateKey(newKey.ExportECPrivateKey(), out _);
        await renewed.CheckInAsync();

        Clock.Advance(TimeSpan.FromMinutes(61));
        await ExpectRejectedAsync(await agent.PostAsync(AgentRoutes.CheckIn, new CheckInRequest { AgentVersion = "1.0.0" }), AgentErrorCodes.CredentialExpired);
        await renewed.CheckInAsync();

        root = await LoginAsync("root", DefaultPassword, root.MfaSecret); // the admin session idled out meanwhile
        await root.ExpectAsync(HttpMethod.Post, $"/api/v1/endpoints/{agent.EndpointId}/revoke", new RevokeEndpointRequest("Stolen laptop"), HttpStatusCode.OK);
        using var afterRevoke = await renewed.PostAsync(AgentRoutes.CheckIn, new CheckInRequest { AgentVersion = "1.0.0" });
        Assert.Equal(HttpStatusCode.Unauthorized, afterRevoke.StatusCode);
        Assert.Contains(await AdminSession.ProblemCodeAsync(afterRevoke), new[] { AgentErrorCodes.CredentialRevoked, AgentErrorCodes.EndpointRevoked });
        renewed.Dispose();
    }

    [Fact]
    public async Task Agents_cannot_report_for_jobs_of_other_endpoints()
    {
        var root = await SuperAdminAsync();
        var (org, site) = await CreateOrgAsync(root);
        var a = await EnrollAgentAsync(root, org.Id, site.Id, "PC-A");
        var b = await EnrollAgentAsync(root, org.Id, site.Id, "PC-B");
        var job = await root.SendAsync<JobSummaryDto>(HttpMethod.Post, $"/api/v1/endpoints/{a.EndpointId}/scan", null, HttpStatusCode.Accepted);

        using var foreign = await b.PostAsync($"api/v1/agents/jobs/{job.Id}/status",
            new JobStatusReport { Sequence = 1, Status = JobStatus.Completed });
        Assert.Equal(HttpStatusCode.NotFound, foreign.StatusCode);
        using var foreignAck = await b.PostAsync($"api/v1/agents/jobs/{job.Id}/ack", new { });
        Assert.Equal(HttpStatusCode.NotFound, foreignAck.StatusCode);
        Assert.Equal(JobStatus.Queued, (await root.GetAsync<JobDetailDto>($"/api/v1/jobs/{job.Id}")).Summary.Status);
    }
}
