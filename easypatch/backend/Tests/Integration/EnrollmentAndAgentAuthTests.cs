using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Nodes;
using EasyPatch.Api.Contracts;
using EasyPatch.Contracts;
using EasyPatch.Contracts.Agent;
using EasyPatch.Contracts.Security;
using EasyPatch.Infrastructure.Security;
using Microsoft.EntityFrameworkCore;
using Xunit;

namespace EasyPatch.Tests.Integration;

public sealed class EnrollmentTests(PostgresFixture postgres) : IntegrationTest(postgres)
{
    private static async Task<EnrollResponse> ReadEnrollAsync(HttpResponseMessage response)
    {
        await AdminClient.EnsureAsync(response, HttpStatusCode.OK);
        return (await response.Content.ReadFromJsonAsync<EnrollResponse>(TestJson.Options))!;
    }

    [Fact]
    public async Task Tokens_are_use_limited_expire_and_can_be_revoked_and_are_stored_hashed()
    {
        var root = SuperAdmin();
        var (org, site) = await CreateOrgAsync(root);

        var single = await CreateTokenAsync(root, org.Id, site.Id, maxUses: 1);
        Assert.StartsWith("ept_", single, StringComparison.Ordinal);
        using (var first = await NewAgent().EnrollAsync(single, "PC-1"))
        {
            Assert.Equal(EnrollmentState.Active, (await ReadEnrollAsync(first)).State);
        }

        using (var reused = await NewAgent().EnrollAsync(single, "PC-2"))
        {
            Assert.Equal(HttpStatusCode.Unauthorized, reused.StatusCode);
            Assert.Equal(AgentErrorCodes.EnrollmentInvalid, await AdminClient.ProblemCodeAsync(reused));
        }

        var expiring = await CreateTokenAsync(root, org.Id, site.Id, hours: 1);
        Clock.Advance(TimeSpan.FromMinutes(61));
        using (var expired = await NewAgent().EnrollAsync(expiring, "PC-3"))
        {
            Assert.Equal(HttpStatusCode.Unauthorized, expired.StatusCode);
        }

        var revocable = await root.SendAsync<List<CreatedTokenDto>>(HttpMethod.Post, "/api/v1/enrollment-tokens",
            new CreateTokensRequest(org.Id, site.Id, "to revoke", 24, 10, 1), HttpStatusCode.OK);
        await root.ExpectAsync(HttpMethod.Post, $"/api/v1/enrollment-tokens/{revocable[0].Token.Id}/revoke", null, HttpStatusCode.NoContent);
        using (var revoked = await NewAgent().EnrollAsync(revocable[0].PlaintextToken, "PC-4"))
        {
            Assert.Equal(HttpStatusCode.Unauthorized, revoked.StatusCode);
        }

        var hashes = await WithDbAsync(db => db.EnrollmentTokens.Select(t => t.TokenHash).ToListAsync());
        Assert.DoesNotContain(single, hashes);
        Assert.Contains(SecureTokens.Hash(single), hashes);
        Assert.DoesNotContain(revocable[0].PlaintextToken, revocable[0].Token.ToString(), StringComparison.Ordinal);
    }

    /// <summary>The enroll request of an agent from before ADR-0048. <paramref name="deploymentCode"/>: the
    /// <c>deploymentCode</c> member, absent when <paramref name="sendsDeploymentCode"/> is false.</summary>
    private static JsonObject OlderAgentEnroll(SignedAgent agent, string hostname, string? token, string? deploymentCode,
        bool sendsDeploymentCode = true)
    {
        var body = new JsonObject
        {
            ["enrollmentToken"] = token,
            ["publicKey"] = agent.PublicKeyBase64,
            ["agentVersion"] = "1.8.0",
            ["device"] = JsonSerializer.SerializeToNode(SignedAgent.Device(hostname), TestJson.Options),
        };
        if (sendsDeploymentCode)
        {
            body["deploymentCode"] = deploymentCode;
        }

        return body;
    }

    [Fact]
    public async Task Older_agents_enroll_with_a_token_whatever_they_send_as_deployment_code_when_it_is_empty()
    {
        var root = SuperAdmin();
        var (org, site) = await CreateOrgAsync(root);
        var token = await CreateTokenAsync(root, org.Id, site.Id, maxUses: 3);

        foreach (var (hostname, sends, code) in new[] { ("OLD-PC1", true, (string?)null), ("OLD-PC2", false, null), ("OLD-PC3", true, "") })
        {
            var agent = NewAgent();
            var json = OlderAgentEnroll(agent, hostname, token, code, sends);
            Assert.Equal(sends, json.ToJsonString().Contains("\"deploymentCode\"", StringComparison.Ordinal));
            using var response = await agent.EnrollAsJsonAsync(json);
            var enrolled = await ReadEnrollAsync(response);
            Assert.Equal(EnrollmentState.Active, enrolled.State);
            Assert.StartsWith("c_", enrolled.CredentialId, StringComparison.Ordinal);
            agent.CredentialId = enrolled.CredentialId;
            agent.EndpointId = enrolled.EndpointId!.Value;
            await agent.CheckInAsync();
        }

        Assert.Equal(3, await WithDbAsync(db => db.Endpoints.CountAsync(e => e.SiteId == site.Id)));
    }

    [Fact]
    public async Task A_deployment_code_is_refused_clearly_and_uses_no_token()
    {
        var root = SuperAdmin();
        var (org, site) = await CreateOrgAsync(root);
        var token = await CreateTokenAsync(root, org.Id, site.Id, maxUses: 1);
        var agent = NewAgent();

        // A code alone, and a code beside a valid token: both refused, the token left unused.
        foreach (var withToken in new[] { (string?)null, token })
        {
            using var response = await agent.EnrollAsJsonAsync(OlderAgentEnroll(agent, "RMM-PC1", withToken, "EPD-ABCDEFGHJKMNPQRS"));
            Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
            Assert.Equal(AgentErrorCodes.DeploymentCodesRetired, await AdminClient.ProblemCodeAsync(response));
            Assert.Contains("enrollment token", await response.Content.ReadAsStringAsync(), StringComparison.Ordinal);
        }

        Assert.Equal(0, await WithDbAsync(db => db.Endpoints.CountAsync()));
        Assert.Equal(0, await WithDbAsync(db => db.EnrollmentTokens.Select(t => t.UseCount).SingleAsync()));

        // Neither a code nor a token.
        using var neither = await agent.EnrollAsJsonAsync(OlderAgentEnroll(agent, "RMM-PC1", null, null));
        Assert.Equal(HttpStatusCode.BadRequest, neither.StatusCode);
        Assert.Equal(AgentErrorCodes.EnrollmentInvalid, await AdminClient.ProblemCodeAsync(neither));
    }

    [Fact]
    public async Task An_older_agent_still_waiting_for_approval_is_told_its_request_is_unknown()
    {
        // Such an agent signs with the r_ ID of its enrollment request; the engine keeps none any more.
        var agent = NewAgent();
        agent.CredentialId = "r_" + RequestSigner.Base64UrlEncode(System.Security.Cryptography.RandomNumberGenerator.GetBytes(16));
        using (var poll = await agent.PostAsync("api/v1/agents/enrollment/status", new { }))
        {
            Assert.Equal(HttpStatusCode.Unauthorized, poll.StatusCode);
            Assert.Equal(AgentErrorCodes.UnknownCredential, await AdminClient.ProblemCodeAsync(poll));
        }

        using var checkIn = await agent.PostAsync(AgentRoutes.CheckIn, new CheckInRequest { AgentVersion = "1.8.0" });
        Assert.Equal(HttpStatusCode.Unauthorized, checkIn.StatusCode);
        Assert.Equal(AgentErrorCodes.UnknownCredential, await AdminClient.ProblemCodeAsync(checkIn));
    }
}

public sealed class AgentAuthenticationTests(PostgresFixture postgres) : IntegrationTest(postgres)
{
    private async Task<(AdminClient Root, SignedAgent Agent)> EnrolledAsync()
    {
        var root = SuperAdmin();
        var (org, site) = await CreateOrgAsync(root);
        return (root, await EnrollAgentAsync(root, org.Id, site.Id, "SIGNED-PC"));
    }

    private static async Task ExpectRejectedAsync(HttpResponseMessage response, string code)
    {
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal(code, await AdminClient.ProblemCodeAsync(response));
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
            await AdminClient.EnsureAsync(response, HttpStatusCode.OK);
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

        await root.ExpectAsync(HttpMethod.Post, $"/api/v1/endpoints/{agent.EndpointId}/revoke", new RevokeEndpointRequest("Stolen laptop"), HttpStatusCode.OK);
        using var afterRevoke = await renewed.PostAsync(AgentRoutes.CheckIn, new CheckInRequest { AgentVersion = "1.0.0" });
        Assert.Equal(HttpStatusCode.Unauthorized, afterRevoke.StatusCode);
        Assert.Contains(await AdminClient.ProblemCodeAsync(afterRevoke), new[] { AgentErrorCodes.CredentialRevoked, AgentErrorCodes.EndpointRevoked });
        renewed.Dispose();
    }

    [Fact]
    public async Task Agents_cannot_report_for_jobs_of_other_endpoints()
    {
        var root = SuperAdmin();
        var (org, site) = await CreateOrgAsync(root);
        var a = await EnrollAgentAsync(root, org.Id, site.Id, "PC-A");
        var b = await EnrollAgentAsync(root, org.Id, site.Id, "PC-B");
        var job = await ScanAsync(root, a.EndpointId);

        using var foreign = await b.PostAsync($"api/v1/agents/jobs/{job}/status",
            new JobStatusReport { Sequence = 1, Status = JobStatus.Completed });
        Assert.Equal(HttpStatusCode.NotFound, foreign.StatusCode);
        using var foreignAck = await b.PostAsync($"api/v1/agents/jobs/{job}/ack", new { });
        Assert.Equal(HttpStatusCode.NotFound, foreignAck.StatusCode);
        Assert.Equal(JobStatus.Queued, (await root.GetAsync<JobDetailDto>($"/api/v1/jobs/{job}")).Summary.Status);
    }
}
