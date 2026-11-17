using System.Net;
using System.Net.Http.Headers;
using EasyPatch.Api.Contracts;
using EasyPatch.Core.Entities;
using Microsoft.EntityFrameworkCore;
using Xunit;

namespace EasyPatch.Tests.Integration;

/// <summary>API tokens: bearer credentials for scripts and integrations with a fixed role and organization scope.</summary>
public sealed class ApiTokenTests(PostgresFixture postgres) : IntegrationTest(postgres)
{
    private AdminSession root = null!;

    public override async ValueTask InitializeAsync()
    {
        await base.InitializeAsync();
        root = await SuperAdminAsync();
    }

    private Task<CreateApiTokenResponse> CreateAsync(string name, UserRole role, int days = 90, params Guid[] organizations) =>
        root.SendAsync<CreateApiTokenResponse>(HttpMethod.Post, "/api/v1/api-tokens", new CreateApiTokenRequest(name, role, organizations, days),
            HttpStatusCode.Created);

    /// <summary>A client that sends only the bearer token: no cookies, no CSRF header.</summary>
    private AdminSession TokenClient(string secret)
    {
        var browser = new BrowserHandler();
        var http = NewHttpClient(browser);
        http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", secret);
        return new AdminSession(http, browser, "token", string.Empty);
    }

    [Fact]
    public async Task A_token_acts_with_its_role_and_organizations_only()
    {
        var (contoso, contosoSite) = await CreateOrgAsync(root, "Contoso");
        var (fabrikam, fabrikamSite) = await CreateOrgAsync(root, "Fabrikam");
        var contosoAgent = await EnrollAgentAsync(root, contoso.Id, contosoSite.Id, "CONTOSO-PC1");
        var fabrikamAgent = await EnrollAgentAsync(root, fabrikam.Id, fabrikamSite.Id, "FABRIKAM-PC1");

        var created = await CreateAsync("Contoso report", UserRole.ReadOnly, 90, contoso.Id);
        Assert.StartsWith("ept_", created.Secret, StringComparison.Ordinal);
        Assert.Equal((created.Secret[..12], "Active", false, contoso.Id), (created.Token.Prefix, created.Token.Status, created.Token.AllOrganizations,
            Assert.Single(created.Token.OrganizationIds)));

        // Only a hash is stored, and the secret is in no audit record.
        var stored = await WithDbAsync(db => db.ApiTokens.AsNoTracking().SingleAsync(t => t.Id == created.Token.Id));
        Assert.NotEqual(created.Secret, stored.TokenHash);
        var audit = await WithDbAsync(db => db.AuditLogs.AsNoTracking().Where(a => a.Action == "api_token.create").Select(a => a.Details).SingleAsync());
        Assert.DoesNotContain(created.Secret, audit!, StringComparison.Ordinal);

        var reader = TokenClient(created.Secret);
        var endpoints = await reader.GetAsync<PagedResult<EndpointSummaryDto>>("/api/v1/endpoints");
        Assert.Equal([contosoAgent.EndpointId], endpoints.Items.Select(e => e.Id));
        await reader.ExpectAsync(HttpMethod.Get, $"/api/v1/endpoints/{fabrikamAgent.EndpointId}", null, HttpStatusCode.NotFound);
        await reader.ExpectAsync(HttpMethod.Post, $"/api/v1/endpoints/{contosoAgent.EndpointId}/scan", null, HttpStatusCode.Forbidden, "forbidden");

        // Never users, tokens, server settings, or the signed-in user's own account.
        await reader.ExpectAsync(HttpMethod.Get, "/api/v1/users", null, HttpStatusCode.Forbidden);
        await reader.ExpectAsync(HttpMethod.Get, "/api/v1/api-tokens", null, HttpStatusCode.Forbidden);
        await reader.ExpectAsync(HttpMethod.Get, "/api/v1/auth/me", null, HttpStatusCode.Unauthorized);
        await reader.ExpectAsync(HttpMethod.Get, "/api/v1/auth/sessions", null, HttpStatusCode.Unauthorized);

        // An operator token for every organization runs jobs without a CSRF token, and is audited by name.
        var automation = TokenClient((await CreateAsync("Automation", UserRole.Admin)).Secret);
        await automation.ExpectAsync(HttpMethod.Post, $"/api/v1/endpoints/{fabrikamAgent.EndpointId}/scan", null, HttpStatusCode.Accepted);
        var job = await WithDbAsync(db => db.Jobs.AsNoTracking().SingleAsync(j => j.EndpointId == fabrikamAgent.EndpointId && j.Type == Contracts.JobType.UpdateScan));
        Assert.Equal(("token:Automation", (Guid?)null), (job.RequestedBy, job.RequestedByUserId));
        await automation.SendAsync<PolicyDto>(HttpMethod.Put, $"/api/v1/organizations/{fabrikam.Id}/policy",
            new PolicyRequest(null, null, null, null, null, null, null, null, null, null, null, null, null, null), HttpStatusCode.OK);
        var entry = await WithDbAsync(db => db.AuditLogs.AsNoTracking().SingleAsync(a => a.Action == "policy.update"));
        Assert.Equal(("token:Automation", (Guid?)null), (entry.Username, entry.UserId));
        await automation.ExpectAsync(HttpMethod.Post, "/api/v1/api-tokens", new CreateApiTokenRequest("Escalate", UserRole.Admin, null, 30),
            HttpStatusCode.Forbidden);
        await automation.ExpectAsync(HttpMethod.Put, "/api/v1/settings", new Core.Domain.ServerSettings(), HttpStatusCode.Forbidden);

        // Validation.
        await root.ExpectAsync(HttpMethod.Post, "/api/v1/api-tokens", new CreateApiTokenRequest("Root", UserRole.SuperAdmin, null, 30),
            HttpStatusCode.BadRequest);
        await root.ExpectAsync(HttpMethod.Post, "/api/v1/api-tokens", new CreateApiTokenRequest("Forever", UserRole.ReadOnly, null, 366),
            HttpStatusCode.BadRequest);
        await root.ExpectAsync(HttpMethod.Post, "/api/v1/api-tokens", new CreateApiTokenRequest("", UserRole.ReadOnly, null, 30),
            HttpStatusCode.BadRequest);
        await root.ExpectAsync(HttpMethod.Post, "/api/v1/api-tokens", new CreateApiTokenRequest("automation", UserRole.ReadOnly, null, 30),
            HttpStatusCode.Conflict, "name_taken");
        await root.ExpectAsync(HttpMethod.Post, "/api/v1/api-tokens", new CreateApiTokenRequest("Ghost", UserRole.ReadOnly, [Guid.NewGuid()], 30),
            HttpStatusCode.NotFound);

        var list = await root.GetAsync<List<ApiTokenDto>>("/api/v1/api-tokens");
        Assert.Equal(["Automation", "Contoso report"], list.Select(t => t.Name));
        Assert.All(list, t => Assert.NotNull(t.LastUsedAt));
    }

    [Fact]
    public async Task Revoked_expired_and_unknown_tokens_are_rejected()
    {
        var created = await CreateAsync("Sync", UserRole.ReadOnly, 1);
        var client = TokenClient(created.Secret);
        await client.GetAsync<List<OrganizationSummaryDto>>("/api/v1/organizations");

        await root.SendAsync<ApiTokenDto>(HttpMethod.Post, $"/api/v1/api-tokens/{created.Token.Id}/revoke", null, HttpStatusCode.OK);
        await client.ExpectAsync(HttpMethod.Get, "/api/v1/organizations", null, HttpStatusCode.Unauthorized, "unauthenticated");

        // The name is free again once the token is revoked; a token stops working when it expires.
        var renewed = await CreateAsync("Sync", UserRole.ReadOnly, 1);
        var second = TokenClient(renewed.Secret);
        await second.GetAsync<List<OrganizationSummaryDto>>("/api/v1/organizations");
        Clock.Advance(TimeSpan.FromDays(1) + TimeSpan.FromSeconds(1));
        await second.ExpectAsync(HttpMethod.Get, "/api/v1/organizations", null, HttpStatusCode.Unauthorized);
        root = await LoginAsync("root", DefaultPassword, root.MfaSecret); // the session idled out meanwhile
        var statuses = (await root.GetAsync<List<ApiTokenDto>>("/api/v1/api-tokens")).Select(t => t.Status).Order();
        Assert.Equal(["Expired", "Revoked"], statuses);

        await TokenClient("ept_" + new string('A', 43)).ExpectAsync(HttpMethod.Get, "/api/v1/organizations", null, HttpStatusCode.Unauthorized);
        await TokenClient("not-a-token").ExpectAsync(HttpMethod.Get, "/api/v1/organizations", null, HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task A_session_request_ignores_a_bearer_token()
    {
        var (org, site) = await CreateOrgAsync(root);
        var agent = await EnrollAgentAsync(root, org.Id, site.Id, "PC-1");
        var admin = await CreateAsync("Automation", UserRole.Admin);
        var viewer = await CreateAndLoginAsync("viewer1", UserRole.ReadOnly);

        // The read-only user's session decides; the operator token does not add to it.
        viewer.Http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", admin.Secret);
        await viewer.ExpectAsync(HttpMethod.Post, $"/api/v1/endpoints/{agent.EndpointId}/scan", null, HttpStatusCode.Forbidden);

        // Session requests still need the CSRF token even with a bearer header.
        root.Browser.SkipCsrf = true;
        root.Http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", admin.Secret);
        await root.ExpectAsync(HttpMethod.Post, $"/api/v1/endpoints/{agent.EndpointId}/scan", null, HttpStatusCode.Forbidden, "csrf_failed");
    }
}
