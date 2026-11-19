using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;
using EasyPatch.Api.Contracts;
using EasyPatch.Core.Entities;
using EasyPatch.Infrastructure.Services;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace EasyPatch.Tests.Integration;

/// <summary>
/// API tokens: bearer credentials for scripts and integrations with a fixed role and organization scope, made on the server with
/// <c>create-api-token</c> (EasyRMM's contract test and connector still use them).
/// </summary>
public sealed class ApiTokenTests(PostgresFixture postgres) : IntegrationTest(postgres)
{
    private AdminClient root = null!;

    public override async ValueTask InitializeAsync()
    {
        await base.InitializeAsync();
        root = SuperAdmin();
    }

    /// <summary>Makes a token as <c>create-api-token</c> does.</summary>
    private Task<(ApiToken Token, string Secret)> CreateAsync(string name, UserRole role, int days = 90, params Guid[] organizations) =>
        WithScopeAsync(sp => sp.GetRequiredService<ApiTokenService>().CreateAsync(name, role, organizations, days));

    /// <summary>A client that sends only the bearer token.</summary>
    private AdminClient TokenClient(string secret)
    {
        var http = NewHttpClient();
        http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", secret);
        return new AdminClient(http, "token");
    }

    [Fact]
    public async Task A_token_acts_with_its_role_and_organizations_only()
    {
        var (contoso, contosoSite) = await CreateOrgAsync(root, "Contoso");
        var (fabrikam, fabrikamSite) = await CreateOrgAsync(root, "Fabrikam");
        var contosoAgent = await EnrollAgentAsync(root, contoso.Id, contosoSite.Id, "CONTOSO-PC1");
        var fabrikamAgent = await EnrollAgentAsync(root, fabrikam.Id, fabrikamSite.Id, "FABRIKAM-PC1");

        var (token, secret) = await CreateAsync("Contoso report", UserRole.ReadOnly, 90, contoso.Id);
        Assert.StartsWith("ept_", secret, StringComparison.Ordinal);
        Assert.Equal((secret[..12], false, contoso.Id), (token.Prefix, token.AllOrganizations, Assert.Single(token.OrganizationIds)));

        // Only a hash is stored, and the secret is in no audit record.
        var stored = await WithDbAsync(db => db.ApiTokens.AsNoTracking().SingleAsync(t => t.Id == token.Id));
        Assert.NotEqual(secret, stored.TokenHash);
        var audit = await WithDbAsync(db => db.AuditLogs.AsNoTracking().Where(a => a.Action == "api_token.create").Select(a => a.Details).SingleAsync());
        Assert.DoesNotContain(secret, audit!, StringComparison.Ordinal);

        var reader = TokenClient(secret);
        var endpoints = await reader.GetAsync<PagedResult<EndpointSummaryDto>>("/api/v1/endpoints");
        Assert.Equal([contosoAgent.EndpointId], endpoints.Items.Select(e => e.Id));
        await reader.ExpectAsync(HttpMethod.Get, $"/api/v1/endpoints/{fabrikamAgent.EndpointId}", null, HttpStatusCode.NotFound);
        await reader.ExpectAsync(HttpMethod.Post, $"/api/v1/endpoints/{contosoAgent.EndpointId}/scan", null, HttpStatusCode.Forbidden, "forbidden");

        // An operator token for every organization runs jobs, and is audited by name.
        var automation = TokenClient((await CreateAsync("Automation", UserRole.Admin)).Secret);
        await automation.ExpectAsync(HttpMethod.Post, $"/api/v1/endpoints/{fabrikamAgent.EndpointId}/scan", null, HttpStatusCode.Accepted);
        var job = await WithDbAsync(db => db.Jobs.AsNoTracking().SingleAsync(j => j.EndpointId == fabrikamAgent.EndpointId && j.Type == Contracts.JobType.UpdateScan));
        Assert.Equal(("token:Automation", (Guid?)null), (job.RequestedBy, job.RequestedByUserId));
        await automation.SendAsync<PolicyDto>(HttpMethod.Put, $"/api/v1/organizations/{fabrikam.Id}/policy",
            new PolicyRequest(null, null, null, null, null, null, null, null, null, null, null, null, null, null), HttpStatusCode.OK);
        var entry = await WithDbAsync(db => db.AuditLogs.AsNoTracking().SingleAsync(a => a.Action == "policy.update"));
        Assert.Equal(("token:Automation", (Guid?)null), (entry.Username, entry.UserId));

        // Never server settings: a token is never a super administrator.
        await automation.ExpectAsync(HttpMethod.Put, "/api/v1/settings", new Core.Domain.ServerSettings(), HttpStatusCode.Forbidden);
        var refused = await Assert.ThrowsAsync<AppException>(() => CreateAsync("Root", UserRole.SuperAdmin));
        Assert.Equal("invalid_role", refused.Code);

        // Names are unique among active tokens, ignoring case, and organizations must exist.
        Assert.Equal("name_taken", (await Assert.ThrowsAsync<AppException>(() => CreateAsync("automation", UserRole.ReadOnly))).Code);
        Assert.Equal(404, (await Assert.ThrowsAsync<AppException>(() => CreateAsync("Ghost", UserRole.ReadOnly, 30, Guid.NewGuid()))).StatusCode);

        // Each token records its last use.
        Assert.All(await WithDbAsync(db => db.ApiTokens.AsNoTracking().ToListAsync()), t => Assert.NotNull(t.LastUsedAt));
    }

    [Fact]
    public async Task Revoked_expired_and_unknown_tokens_are_rejected()
    {
        var (token, secret) = await CreateAsync("Sync", UserRole.ReadOnly, 1);
        var client = TokenClient(secret);
        await client.GetAsync<List<OrganizationSummaryDto>>("/api/v1/organizations");

        await WithDbAsync(db => db.ApiTokens.Where(t => t.Id == token.Id).ExecuteUpdateAsync(s => s.SetProperty(t => t.RevokedAt, Clock.GetUtcNow())));
        await client.ExpectAsync(HttpMethod.Get, "/api/v1/organizations", null, HttpStatusCode.Unauthorized, "unauthenticated");

        // The name is free again once the token is revoked; a token stops working when it expires.
        var second = TokenClient((await CreateAsync("Sync", UserRole.ReadOnly, 1)).Secret);
        await second.GetAsync<List<OrganizationSummaryDto>>("/api/v1/organizations");
        Clock.Advance(TimeSpan.FromDays(1) + TimeSpan.FromSeconds(1));
        await second.ExpectAsync(HttpMethod.Get, "/api/v1/organizations", null, HttpStatusCode.Unauthorized);

        await TokenClient("ept_" + new string('A', 43)).ExpectAsync(HttpMethod.Get, "/api/v1/organizations", null, HttpStatusCode.Unauthorized);
        await TokenClient("not-a-token").ExpectAsync(HttpMethod.Get, "/api/v1/organizations", null, HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task A_request_with_a_statement_ignores_a_bearer_token()
    {
        var (org, site) = await CreateOrgAsync(root);
        var agent = await EnrollAgentAsync(root, org.Id, site.Id, "PC-1");
        var operatorToken = await CreateAsync("Automation", UserRole.Admin);

        // The read-only statement decides; the operator token does not add to it.
        var viewer = Admin("viewer1", UserRole.ReadOnly);
        viewer.Http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", operatorToken.Secret);
        await viewer.ExpectAsync(HttpMethod.Post, $"/api/v1/endpoints/{agent.EndpointId}/scan", null, HttpStatusCode.Forbidden);
        Assert.Empty(await WithDbAsync(db => db.Jobs.AsNoTracking().Where(j => j.EndpointId == agent.EndpointId).ToListAsync()));
    }

    [Fact]
    public async Task An_integration_names_the_person_it_acts_for()
    {
        var info = await root.GetAsync<ServerInfoDto>("/api/v1/server-info");
        Assert.Equal(["scheduled-installs", "on-behalf-of"], info.Capabilities);

        var (org, site) = await CreateOrgAsync(root);
        var agent = await EnrollAgentAsync(root, org.Id, site.Id, "PC-1");
        var secret = (await CreateAsync("EasyRMM", UserRole.Admin)).Secret;
        var rmm = TokenClient(secret);
        rmm.Http.DefaultRequestHeaders.Add("X-EasyPatch-On-Behalf-Of", "  alice@example.com ");

        // The job says who asked for it, and so does the audit record; the token alone decides what is allowed.
        await rmm.ExpectAsync(HttpMethod.Post, $"/api/v1/endpoints/{agent.EndpointId}/scan", null, HttpStatusCode.Accepted);
        var scan = await WithDbAsync(db => db.Jobs.AsNoTracking().SingleAsync(j => j.EndpointId == agent.EndpointId));
        Assert.Equal(("token:EasyRMM for alice@example.com", (Guid?)null), (scan.RequestedBy, scan.RequestedByUserId));
        var created = await WithDbAsync(db => db.AuditLogs.AsNoTracking().SingleAsync(a => a.Action == "job.create"));
        Assert.Equal("token:EasyRMM", created.Username);
        using (var details = JsonDocument.Parse(created.Details!))
        {
            Assert.Equal("alice@example.com", details.RootElement.GetProperty("onBehalfOf").GetString());
            Assert.Equal("UpdateScan", details.RootElement.GetProperty("type").GetString());
        }

        // Excluding an update works with a token (it used to fail with 401) and records no user.
        var update = Guid.NewGuid();
        await rmm.ExpectAsync(HttpMethod.Post, $"/api/v1/endpoints/{agent.EndpointId}/exclusions", new ExclusionRequest(update, "Breaks the payroll app"),
            HttpStatusCode.NoContent);
        var exclusion = await WithDbAsync(db => db.UpdateExclusions.AsNoTracking().SingleAsync());
        Assert.Equal((update, (Guid?)null), (exclusion.UpdateGuid, exclusion.CreatedByUserId));
        var excluded = await WithDbAsync(db => db.AuditLogs.AsNoTracking().SingleAsync(a => a.Action == "endpoint.update_excluded"));
        using (var details = JsonDocument.Parse(excluded.Details!))
        {
            Assert.Equal("alice@example.com", details.RootElement.GetProperty("onBehalfOf").GetString());
            Assert.Equal("Breaks the payroll app", details.RootElement.GetProperty("reason").GetString());
        }

        await rmm.ExpectAsync(HttpMethod.Delete, $"/api/v1/endpoints/{agent.EndpointId}/exclusions/{update}", null, HttpStatusCode.NoContent);
        var included = await WithDbAsync(db => db.AuditLogs.AsNoTracking().SingleAsync(a => a.Action == "endpoint.update_included"));
        Assert.Contains("alice@example.com", included.Details!, StringComparison.Ordinal);

        // A value that is not one line of printable text, or is too long, is ignored, and so is the header beside a statement.
        var tab = TokenClient(secret);
        Assert.True(tab.Http.DefaultRequestHeaders.TryAddWithoutValidation("X-EasyPatch-On-Behalf-Of", "alice\tbob"));
        await tab.ExpectAsync(HttpMethod.Post, $"/api/v1/endpoints/{agent.EndpointId}/inventory-refresh", null, HttpStatusCode.Accepted);
        var refresh = await WithDbAsync(db => db.Jobs.AsNoTracking().SingleAsync(j => j.Type == Contracts.JobType.InventoryRefresh));
        Assert.Equal("token:EasyRMM", refresh.RequestedBy);

        var longName = TokenClient(secret);
        longName.Http.DefaultRequestHeaders.Add("X-EasyPatch-On-Behalf-Of", new string('a', 255));
        await longName.ExpectAsync(HttpMethod.Post, $"/api/v1/endpoints/{agent.EndpointId}/exclusions", new ExclusionRequest(Guid.NewGuid(), null),
            HttpStatusCode.NoContent);
        root.Http.DefaultRequestHeaders.Add("X-EasyPatch-On-Behalf-Of", "mallory@example.com");
        await root.ExpectAsync(HttpMethod.Post, $"/api/v1/endpoints/{agent.EndpointId}/exclusions", new ExclusionRequest(Guid.NewGuid(), null),
            HttpStatusCode.NoContent);
        var exclusions = await WithDbAsync(db => db.AuditLogs.AsNoTracking().Where(a => a.Action == "endpoint.update_excluded").OrderBy(a => a.Id)
            .Select(a => new { a.Username, a.Details }).ToListAsync());
        Assert.Equal(["token:EasyRMM", "token:EasyRMM", root.Actor], exclusions.Select(e => e.Username));
        Assert.All(exclusions.Skip(1), e => Assert.DoesNotContain("onBehalfOf", e.Details!, StringComparison.Ordinal));
    }
}
