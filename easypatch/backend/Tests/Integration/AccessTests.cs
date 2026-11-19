using System.Net;
using EasyPatch.Api.Contracts;
using EasyPatch.Contracts;
using EasyPatch.Core.Entities;
using Xunit;

namespace EasyPatch.Tests.Integration;

/// <summary>Who may call the administrator API, and with which role: EasyRMM's statements (and API tokens, ApiTokenTests).</summary>
public sealed class AccessTests(PostgresFixture postgres) : IntegrationTest(postgres)
{
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
        await tech.ExpectAsync(HttpMethod.Post, $"/api/v1/endpoints/{fabrikamAgent.EndpointId}/scan", null, HttpStatusCode.NotFound);
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
        var report = await tech.GetAsync<ComplianceReportDto>("/api/v1/reports/compliance");
        Assert.All(report.Rows, r => Assert.Equal("Contoso", r.OrganizationName));
        var audit = await tech.GetAsync<PagedResult<AuditLogDto>>("/api/v1/audit-logs");
        Assert.All(audit.Items, a => Assert.Equal(contoso.Id, a.OrganizationId));
    }

    [Fact]
    public async Task Deleting_a_restricted_callers_organization_never_widens_their_access()
    {
        var root = SuperAdmin();
        var (contoso, _) = await CreateOrgAsync(root, "Contoso");
        var (fabrikam, fabrikamSite) = await CreateOrgAsync(root, "Fabrikam");
        var fabrikamAgent = await EnrollAgentAsync(root, fabrikam.Id, fabrikamSite.Id, "FABRIKAM-PC1");
        var tech = Admin("contoso-tech", UserRole.Admin, [contoso.Id]);

        // An Admin may delete their own organization while it has no endpoints. Statements that still name it then reach nothing.
        await tech.ExpectAsync(HttpMethod.Delete, $"/api/v1/organizations/{contoso.Id}", null, HttpStatusCode.NoContent);

        Assert.Empty(await tech.GetAsync<List<OrganizationSummaryDto>>("/api/v1/organizations"));
        Assert.Empty((await tech.GetAsync<PagedResult<EndpointSummaryDto>>("/api/v1/endpoints")).Items);
        await tech.ExpectAsync(HttpMethod.Get, $"/api/v1/organizations/{fabrikam.Id}", null, HttpStatusCode.NotFound);
        await tech.ExpectAsync(HttpMethod.Get, $"/api/v1/endpoints/{fabrikamAgent.EndpointId}", null, HttpStatusCode.NotFound);
        await tech.ExpectAsync(HttpMethod.Post, $"/api/v1/endpoints/{fabrikamAgent.EndpointId}/scan", null, HttpStatusCode.NotFound);
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
