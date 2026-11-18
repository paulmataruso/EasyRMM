using System.Net;
using EasyPatch.Api.Contracts;
using EasyPatch.Api.Security;
using EasyPatch.Core.Entities;
using EasyPatch.Tests.Unit;
using Microsoft.EntityFrameworkCore;
using Xunit;

namespace EasyPatch.Tests.Integration;

/// <summary>Signs every request it sends with a statement from "EasyRMM", made for that request.</summary>
internal sealed class EasyRmmSigner(Func<DateTimeOffset> now, string role, object orgs, string subject, string name) : DelegatingHandler
{
    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var claims = EasyRmmTestSigner.Claims(request.Method.Method, request.RequestUri!.PathAndQuery, now(), orgs, role);
        (claims["sub"], claims["name"]) = (subject, name);
        request.Headers.Add(EasyRmmAuthenticationHandler.HeaderName, EasyRmmTestSigner.Sign(claims));
        return base.SendAsync(request, cancellationToken);
    }
}

/// <summary>
/// EasyPatch as EasyRMM's patching engine: EasyRMM's statements act with the role and organizations each call names, through
/// EasyPatch's own checks, without users, sessions or CSRF tokens, and are refused for any other request.
/// </summary>
public sealed class EasyRmmGatewayTests(PostgresFixture postgres) : IntegrationTest(postgres)
{
    private const string Jane = "6f1c2a52-3e0d-4b8a-9d55-0b6f1e8c2a10";
    private AdminSession root = null!;

    protected override IReadOnlyDictionary<string, string?>? Settings => new Dictionary<string, string?>
    {
        [EasyRmmGateway.KeySetting] = Convert.ToBase64String(EasyRmmTestSigner.Key),
    };

    public override async ValueTask InitializeAsync()
    {
        await base.InitializeAsync();
        root = await SuperAdminAsync();
    }

    /// <summary>A client whose every request carries a statement, and nothing else: no cookies, no CSRF token.</summary>
    private AdminSession EasyRmm(string role, object orgs, string subject = Jane, string name = "jane@example.com", TimeSpan? age = null)
    {
        var browser = new BrowserHandler();
        var http = NewHttpClient(browser, new EasyRmmSigner(() => Clock.GetUtcNow() - (age ?? TimeSpan.Zero), role, orgs, subject, name));
        return new AdminSession(http, browser, "easyrmm", string.Empty);
    }

    [Fact]
    public async Task A_statement_acts_with_the_role_and_organizations_it_names()
    {
        var (contoso, contosoSite) = await CreateOrgAsync(root, "Contoso");
        var (fabrikam, fabrikamSite) = await CreateOrgAsync(root, "Fabrikam");
        var contosoPc = await EnrollAgentAsync(root, contoso.Id, contosoSite.Id, "CONTOSO-PC1");
        var fabrikamPc = await EnrollAgentAsync(root, fabrikam.Id, fabrikamSite.Id, "FABRIKAM-PC1");

        // A technician's call for Contoso: Contoso's endpoint only, and a scan without a CSRF token, audited as EasyRMM's user.
        var technician = EasyRmm("Admin", new[] { contoso.Id.ToString() });
        var endpoints = await technician.GetAsync<PagedResult<EndpointSummaryDto>>("/api/v1/endpoints");
        Assert.Equal([contosoPc.EndpointId], endpoints.Items.Select(e => e.Id));
        await technician.ExpectAsync(HttpMethod.Get, $"/api/v1/endpoints/{fabrikamPc.EndpointId}", null, HttpStatusCode.NotFound);
        await technician.ExpectAsync(HttpMethod.Post, $"/api/v1/endpoints/{fabrikamPc.EndpointId}/scan", null, HttpStatusCode.NotFound);
        await technician.ExpectAsync(HttpMethod.Post, $"/api/v1/endpoints/{contosoPc.EndpointId}/scan", null, HttpStatusCode.Accepted);
        var job = await WithDbAsync(db => db.Jobs.AsNoTracking().SingleAsync(j => j.EndpointId == contosoPc.EndpointId && j.Type == Contracts.JobType.UpdateScan));
        Assert.Equal(("easyrmm:jane@example.com", (Guid?)null), (job.RequestedBy, job.RequestedByUserId));

        // No user row was created for it.
        Assert.Equal(1, await WithDbAsync(db => db.Users.CountAsync()));

        // Read-only: reads, never acts.
        var viewer = EasyRmm("ReadOnly", "*");
        Assert.Equal(2, (await viewer.GetAsync<PagedResult<EndpointSummaryDto>>("/api/v1/endpoints")).Items.Count);
        await viewer.ExpectAsync(HttpMethod.Post, $"/api/v1/endpoints/{contosoPc.EndpointId}/scan", null, HttpStatusCode.Forbidden, "forbidden");

        // A role never widens the organizations: a super administrator's call for Contoso sees Contoso only.
        var scoped = EasyRmm("SuperAdmin", new[] { contoso.Id.ToString() });
        Assert.Equal([contoso.Id], (await scoped.GetAsync<List<OrganizationSummaryDto>>("/api/v1/organizations")).Select(o => o.Id));
        var nothing = EasyRmm("SuperAdmin", Array.Empty<string>());
        Assert.Empty(await nothing.GetAsync<List<OrganizationSummaryDto>>("/api/v1/organizations"));

        // EasyRMM's own work: server settings, which need a super administrator and record no user.
        var service = EasyRmm("SuperAdmin", "*", EasyRmmStatement.ServiceSubject, "EasyRMM");
        await service.SendAsync<Core.Domain.ServerSettings>(HttpMethod.Put, "/api/v1/settings", new Core.Domain.ServerSettings(), HttpStatusCode.OK);
        var entry = await WithDbAsync(db => db.AuditLogs.AsNoTracking().SingleAsync(a => a.Action == "settings.update"));
        Assert.Equal(("easyrmm:EasyRMM", (Guid?)null), (entry.Username, entry.UserId));
        await technician.ExpectAsync(HttpMethod.Put, "/api/v1/settings", new Core.Domain.ServerSettings(), HttpStatusCode.Forbidden);

        // Never the signed-in user's own account: those routes take a session only.
        await service.ExpectAsync(HttpMethod.Get, "/api/v1/auth/me", null, HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task A_statement_is_refused_for_any_other_request_and_once_it_has_expired()
    {
        var (contoso, contosoSite) = await CreateOrgAsync(root, "Contoso");
        var pc = await EnrollAgentAsync(root, contoso.Id, contosoSite.Id, "CONTOSO-PC1");
        var scan = $"/api/v1/endpoints/{pc.EndpointId}/scan";

        // Made for one request, sent with another: the same route for another endpoint.
        var claims = EasyRmmTestSigner.Claims("POST", scan, Clock.GetUtcNow());
        using (var request = new HttpRequestMessage(HttpMethod.Post, $"/api/v1/endpoints/{Guid.NewGuid()}/scan"))
        {
            request.Headers.Add(EasyRmmAuthenticationHandler.HeaderName, EasyRmmTestSigner.Sign(claims));
            using var response = await NewHttpClient().SendAsync(request);
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        }

        // Signed a minute ago.
        await EasyRmm("Admin", "*", age: TimeSpan.FromMinutes(1)).ExpectAsync(HttpMethod.Post, scan, null, HttpStatusCode.Unauthorized, "unauthenticated");

        // A request with a statement is judged by it alone: a valid session alongside a bad statement does not help.
        using (var request = new HttpRequestMessage(HttpMethod.Get, new Uri("/api/v1/endpoints", UriKind.Relative)))
        {
            request.Headers.Add(EasyRmmAuthenticationHandler.HeaderName, "not.a.statement");
            using var response = await root.Http.SendAsync(request);
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        }

        Assert.Empty(await WithDbAsync(db => db.Jobs.AsNoTracking().Where(j => j.EndpointId == pc.EndpointId).ToListAsync()));
    }
}

/// <summary>A server that is not an EasyRMM server's engine accepts no statement, however it is signed.</summary>
public sealed class EasyRmmGatewayOffTests(PostgresFixture postgres) : IntegrationTest(postgres)
{
    [Fact]
    public async Task Without_the_gateway_key_no_statement_is_accepted()
    {
        var http = NewHttpClient(new EasyRmmSigner(() => Clock.GetUtcNow(), "SuperAdmin", "*", EasyRmmStatement.ServiceSubject, "EasyRMM"));
        using var response = await http.GetAsync(new Uri("/api/v1/organizations", UriKind.Relative));
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }
}
