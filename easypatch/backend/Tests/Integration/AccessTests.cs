using System.Net;
using System.Net.Http.Headers;
using EasyPatch.Api.Contracts;
using EasyPatch.Contracts;
using EasyPatch.Core.Entities;
using EasyPatch.Infrastructure.Maintenance;
using EasyPatch.Infrastructure.Security;
using Microsoft.EntityFrameworkCore;
using Xunit;

namespace EasyPatch.Tests.Integration;

/// <summary>Who may call the administrator API, and with which role: EasyRMM's statements, and nothing else.</summary>
public sealed class AccessTests(PostgresFixture postgres) : IntegrationTest(postgres)
{
    /// <summary>An API token as a standalone EasyPatch stored it, in an imported database: the engine accepts none.</summary>
    private async Task<string> StoredApiTokenAsync(string name, UserRole role)
    {
        var secret = SecureTokens.Create("ept_");
        var now = Clock.GetUtcNow();
        await WithDbAsync(async db =>
        {
            db.ApiTokens.Add(new ApiToken
            {
                Name = name, Prefix = secret[..12], TokenHash = SecureTokens.Hash(secret), Role = role, AllOrganizations = true,
                CreatedAt = now, ExpiresAt = now.AddDays(30),
            });
            await db.SaveChangesAsync();
        });
        return secret;
    }

    [Fact]
    public async Task API_tokens_are_refused_even_one_a_standalone_EasyPatch_made()
    {
        var root = SuperAdmin();
        var (org, site) = await CreateOrgAsync(root);
        var agent = await EnrollAgentAsync(root, org.Id, site.Id, "PC-1");
        var stored = await StoredApiTokenAsync("Automation", UserRole.Admin);

        foreach (var secret in new[] { stored, "ept_" + new string('A', 43), "not-a-token" })
        {
            var http = NewHttpClient();
            http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", secret);
            foreach (var (method, url) in new[] { (HttpMethod.Get, "/api/v1/organizations"), (HttpMethod.Post, "/api/v1/endpoints/bulk/scan") })
            {
                using var request = new HttpRequestMessage(method, new Uri(url, UriKind.Relative));
                if (method == HttpMethod.Post)
                {
                    request.Content = System.Net.Http.Json.JsonContent.Create(new BulkEndpointsRequest([agent.EndpointId], false));
                }

                using var response = await http.SendAsync(request);
                Assert.Equal((url, HttpStatusCode.Unauthorized), (url, response.StatusCode));
                Assert.Equal("unauthenticated", await AdminClient.ProblemCodeAsync(response));
            }
        }

        // The answer says where to go instead.
        var bearer = NewHttpClient();
        bearer.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", stored);
        using (var response = await bearer.GetAsync(new Uri("/api/v1/organizations", UriKind.Relative)))
        {
            Assert.Contains("Call through EasyRMM", await response.Content.ReadAsStringAsync(), StringComparison.Ordinal);
        }

        Assert.Empty(await WithDbAsync(db => db.Jobs.AsNoTracking().Where(j => j.EndpointId == agent.EndpointId).ToListAsync()));
        Assert.All(await WithDbAsync(db => db.ApiTokens.AsNoTracking().ToListAsync()), t => Assert.Null(t.LastUsedAt));
    }

    [Fact]
    public async Task A_statement_decides_whatever_bearer_token_comes_with_it()
    {
        var root = SuperAdmin();
        var (org, site) = await CreateOrgAsync(root);
        var agent = await EnrollAgentAsync(root, org.Id, site.Id, "PC-1");

        // A read-only statement with an operator token of an imported database beside it: still read-only.
        var viewer = Admin("viewer1", UserRole.ReadOnly);
        viewer.Http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", await StoredApiTokenAsync("Automation", UserRole.Admin));
        await viewer.GetAsync<PagedResult<EndpointSummaryDto>>("/api/v1/endpoints");
        await viewer.ExpectAsync(HttpMethod.Post, "/api/v1/endpoints/bulk/scan", new BulkEndpointsRequest([agent.EndpointId], false), HttpStatusCode.Forbidden,
            "forbidden");
        Assert.Empty(await WithDbAsync(db => db.Jobs.AsNoTracking().Where(j => j.EndpointId == agent.EndpointId).ToListAsync()));
    }

    [Fact]
    public async Task A_statement_names_who_acted_and_on_behalf_of_is_ignored()
    {
        var root = SuperAdmin();
        var info = await root.GetAsync<ServerInfoDto>("/api/v1/server-info");
        Assert.Equal(["scheduled-installs"], info.Capabilities);

        var (org, site) = await CreateOrgAsync(root);
        var agent = await EnrollAgentAsync(root, org.Id, site.Id, "PC-1");

        // X-EasyPatch-On-Behalf-Of went with API tokens: the statement names the person, and the header changes nothing.
        var technician = Admin("alice@example.com", UserRole.Admin, [org.Id]);
        technician.Http.DefaultRequestHeaders.Add("X-EasyPatch-On-Behalf-Of", "mallory@example.com");
        await ScanAsync(technician, agent.EndpointId);
        var scan = await WithDbAsync(db => db.Jobs.AsNoTracking().SingleAsync(j => j.EndpointId == agent.EndpointId));
        Assert.Equal((technician.Actor, (Guid?)null), (scan.RequestedBy, scan.RequestedByUserId));

        // Excluding an update, and including it again, work with a statement and record no user.
        var update = Guid.NewGuid();
        await technician.ExpectAsync(HttpMethod.Post, $"/api/v1/endpoints/{agent.EndpointId}/exclusions",
            new ExclusionRequest(update, "Breaks the payroll app"), HttpStatusCode.NoContent);
        var exclusion = await WithDbAsync(db => db.UpdateExclusions.AsNoTracking().SingleAsync());
        Assert.Equal((update, (Guid?)null), (exclusion.UpdateGuid, exclusion.CreatedByUserId));
        await technician.ExpectAsync(HttpMethod.Delete, $"/api/v1/endpoints/{agent.EndpointId}/exclusions/{update}", null, HttpStatusCode.NoContent);

        var entries = await WithDbAsync(db => db.AuditLogs.AsNoTracking()
            .Where(a => a.Action == "job.create" || a.Action == "endpoint.update_excluded" || a.Action == "endpoint.update_included")
            .Select(a => new { a.Action, a.Username, a.Details }).ToListAsync());
        Assert.Equal(3, entries.Count);
        Assert.All(entries, e => Assert.Equal((e.Action, technician.Actor), (e.Action, e.Username)));
        Assert.All(entries, e => Assert.DoesNotContain("mallory", e.Details ?? "", StringComparison.Ordinal));
        Assert.All(entries, e => Assert.DoesNotContain("onBehalfOf", e.Details ?? "", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Anonymous_requests_are_rejected()
    {
        var http = NewHttpClient();
        foreach (var (method, url) in new[] { (HttpMethod.Get, "/api/v1/organizations"), (HttpMethod.Get, "/api/v1/endpoints"),
                     (HttpMethod.Put, "/api/v1/settings"), (HttpMethod.Get, "/api/openapi/v1.json") })
        {
            using var request = new HttpRequestMessage(method, new Uri(url, UriKind.Relative));
            if (method != HttpMethod.Get)
            {
                request.Content = System.Net.Http.Json.JsonContent.Create(new Core.Domain.ServerSettings());
            }

            using var response = await http.SendAsync(request);
            Assert.Equal((url, HttpStatusCode.Unauthorized), (url, response.StatusCode));
            Assert.Equal("unauthenticated", await AdminClient.ProblemCodeAsync(response));
        }
    }

    [Fact]
    public async Task Read_only_callers_can_view_but_not_change_anything()
    {
        var root = SuperAdmin();
        var (org, site) = await CreateOrgAsync(root);
        var viewer = Admin("viewer1", UserRole.ReadOnly);

        await viewer.GetAsync<List<OrganizationSummaryDto>>("/api/v1/organizations");
        await viewer.GetAsync<PagedResult<EndpointSummaryDto>>("/api/v1/endpoints");
        await viewer.ExpectAsync(HttpMethod.Post, "/api/v1/organizations", new OrganizationRequest("X", null, null, null, null, null), HttpStatusCode.Forbidden, "forbidden");
        await viewer.ExpectAsync(HttpMethod.Post, $"/api/v1/organizations/{org.Id}/sites", new SiteRequest("Branch", null, null, null), HttpStatusCode.Forbidden);
        await viewer.ExpectAsync(HttpMethod.Post, "/api/v1/enrollment-tokens", new CreateTokensRequest(org.Id, site.Id, null, 24, 1, 1), HttpStatusCode.Forbidden);
        await viewer.ExpectAsync(HttpMethod.Get, "/api/v1/enrollment-tokens", null, HttpStatusCode.Forbidden);
        await viewer.ExpectAsync(HttpMethod.Get, "/api/v1/audit-logs", null, HttpStatusCode.Forbidden);

        // Admins manage endpoints but not server settings.
        var admin = Admin("admin1", UserRole.Admin);
        await admin.GetAsync<List<EnrollmentTokenDto>>("/api/v1/enrollment-tokens");
        await admin.ExpectAsync(HttpMethod.Put, "/api/v1/settings", new Core.Domain.ServerSettings(), HttpStatusCode.Forbidden);
    }
}

public sealed class TenantIsolationTests(PostgresFixture postgres) : IntegrationTest(postgres)
{
    [Fact]
    public async Task Callers_restricted_to_an_organization_cannot_see_or_touch_another()
    {
        var root = SuperAdmin();
        var (contoso, contosoSite) = await CreateOrgAsync(root, "Contoso");
        var (fabrikam, fabrikamSite) = await CreateOrgAsync(root, "Fabrikam");
        var contosoAgent = await EnrollAgentAsync(root, contoso.Id, contosoSite.Id, "CONTOSO-PC1");
        var fabrikamAgent = await EnrollAgentAsync(root, fabrikam.Id, fabrikamSite.Id, "FABRIKAM-PC1");

        var tech = Admin("contoso-tech", UserRole.Admin, [contoso.Id]);

        var orgs = await tech.GetAsync<List<OrganizationSummaryDto>>("/api/v1/organizations");
        Assert.Equal([contoso.Id], orgs.Select(o => o.Id));
        var endpoints = await tech.GetAsync<PagedResult<EndpointSummaryDto>>("/api/v1/endpoints");
        Assert.Equal([contosoAgent.EndpointId], endpoints.Items.Select(e => e.Id));

        // Everything about the other tenant answers 404 (no existence oracle).
        await tech.ExpectAsync(HttpMethod.Get, $"/api/v1/organizations/{fabrikam.Id}", null, HttpStatusCode.NotFound);
        await tech.ExpectAsync(HttpMethod.Get, $"/api/v1/sites/{fabrikamSite.Id}", null, HttpStatusCode.NotFound);
        await tech.ExpectAsync(HttpMethod.Get, $"/api/v1/endpoints/{fabrikamAgent.EndpointId}", null, HttpStatusCode.NotFound);
        await tech.ExpectAsync(HttpMethod.Post, $"/api/v1/endpoints/{fabrikamAgent.EndpointId}/install-updates",
            new InstallUpdatesRequest(InstallMode.AllEligible, null, false), HttpStatusCode.NotFound);
        await tech.ExpectAsync(HttpMethod.Post, "/api/v1/enrollment-tokens", new CreateTokensRequest(fabrikam.Id, null, null, 24, 1, 1), HttpStatusCode.NotFound);
        await tech.ExpectAsync(HttpMethod.Post, "/api/v1/organizations", new OrganizationRequest("Mine", null, null, null, null, null), HttpStatusCode.Forbidden);

        // Bulk operations silently scope to the caller's tenants.
        var bulk = await tech.SendAsync<BulkResultDto>(HttpMethod.Post, "/api/v1/endpoints/bulk/scan",
            new BulkEndpointsRequest([contosoAgent.EndpointId, fabrikamAgent.EndpointId], false), HttpStatusCode.OK);
        Assert.Equal(1, bulk.Succeeded);
        Assert.Equal("not_found", bulk.Results.Single(r => r.EndpointId == fabrikamAgent.EndpointId).ErrorCode);

        var jobs = await tech.GetAsync<PagedResult<JobSummaryDto>>("/api/v1/jobs");
        Assert.All(jobs.Items, j => Assert.Equal(contoso.Id, j.OrganizationId));
        await RunMaintenanceAsync<ComplianceSnapshotTask>();
        Assert.Equal(2, Assert.Single(await root.GetAsync<List<ComplianceTrendPoint>>("/api/v1/reports/compliance/trend")).TotalEndpoints);
        Assert.Equal(1, Assert.Single(await tech.GetAsync<List<ComplianceTrendPoint>>("/api/v1/reports/compliance/trend")).TotalEndpoints);
        Assert.Empty(await tech.GetAsync<List<ComplianceTrendPoint>>($"/api/v1/reports/compliance/trend?organizationId={fabrikam.Id}"));
        var audit = await tech.GetAsync<PagedResult<AuditLogDto>>("/api/v1/audit-logs");
        Assert.All(audit.Items, a => Assert.Equal(contoso.Id, a.OrganizationId));
    }

    [Fact]
    public async Task A_statement_naming_only_an_organization_that_is_not_there_never_widens_access()
    {
        var root = SuperAdmin();
        var (fabrikam, fabrikamSite) = await CreateOrgAsync(root, "Fabrikam");
        var fabrikamAgent = await EnrollAgentAsync(root, fabrikam.Id, fabrikamSite.Id, "FABRIKAM-PC1");
        var tech = Admin("gone-tech", UserRole.Admin, [Guid.NewGuid()]);

        Assert.Empty(await tech.GetAsync<List<OrganizationSummaryDto>>("/api/v1/organizations"));
        Assert.Empty((await tech.GetAsync<PagedResult<EndpointSummaryDto>>("/api/v1/endpoints")).Items);
        await tech.ExpectAsync(HttpMethod.Get, $"/api/v1/organizations/{fabrikam.Id}", null, HttpStatusCode.NotFound);
        await tech.ExpectAsync(HttpMethod.Get, $"/api/v1/endpoints/{fabrikamAgent.EndpointId}", null, HttpStatusCode.NotFound);
        Assert.Equal("not_found", (await BulkOneAsync(tech, "scan", new BulkEndpointsRequest([fabrikamAgent.EndpointId], false))).ErrorCode);
        await tech.ExpectAsync(HttpMethod.Post, "/api/v1/organizations", new OrganizationRequest("Mine", null, null, null, null, null),
            HttpStatusCode.Forbidden);
    }

    [Fact]
    public async Task Every_organization_only_when_the_statement_says_so()
    {
        var root = SuperAdmin();
        var (contoso, _) = await CreateOrgAsync(root, "Contoso");
        var (fabrikam, _) = await CreateOrgAsync(root, "Fabrikam");

        Assert.Equal(new[] { contoso.Id, fabrikam.Id }.Order(),
            (await Admin("ops", UserRole.Admin).GetAsync<List<OrganizationSummaryDto>>("/api/v1/organizations")).Select(o => o.Id).Order());
        Assert.Equal([contoso.Id],
            (await Admin("ops", UserRole.Admin, [contoso.Id]).GetAsync<List<OrganizationSummaryDto>>("/api/v1/organizations")).Select(o => o.Id));

        // An empty list is no organization, never every one, whatever the role.
        Assert.Empty(await Admin("ops", UserRole.Admin, []).GetAsync<List<OrganizationSummaryDto>>("/api/v1/organizations"));
        Assert.Empty(await Admin("root", UserRole.SuperAdmin, []).GetAsync<List<OrganizationSummaryDto>>("/api/v1/organizations"));
    }
}
