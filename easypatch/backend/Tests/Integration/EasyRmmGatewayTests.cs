using System.Net;
using System.Net.Http.Headers;
using EasyPatch.Api.Contracts;
using EasyPatch.Api.Security;
using EasyPatch.Contracts.Agent;
using EasyPatch.Core.Entities;
using EasyPatch.Infrastructure.Security;
using EasyPatch.Tests.Unit;
using Microsoft.EntityFrameworkCore;
using Xunit;

namespace EasyPatch.Tests.Integration;

/// <summary>
/// EasyPatch as EasyRMM's patching engine: EasyRMM's statements act with the role and organizations each call names, through
/// EasyPatch's own checks, without users, sessions or CSRF tokens, and are refused for any other request.
/// </summary>
public sealed class EasyRmmGatewayTests(PostgresFixture postgres) : IntegrationTest(postgres)
{
    private const string Jane = "6f1c2a52-3e0d-4b8a-9d55-0b6f1e8c2a10";
    private AdminClient root = null!;

    public override async ValueTask InitializeAsync()
    {
        await base.InitializeAsync();
        root = SuperAdmin();
    }

    /// <summary>A client whose every request carries a statement, and nothing else: no cookies, no CSRF token.</summary>
    private AdminClient EasyRmm(string role, object orgs, string subject = Jane, string name = "jane@example.com", TimeSpan? age = null) =>
        new(NewHttpClient(new EasyRmmSigner(() => Clock.GetUtcNow() - (age ?? TimeSpan.Zero), role, orgs, subject, name)), name);

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
        Assert.Equal("not_found", (await BulkOneAsync(technician, "scan", new BulkEndpointsRequest([fabrikamPc.EndpointId], false))).ErrorCode);
        await ScanAsync(technician, contosoPc.EndpointId);
        var job = await WithDbAsync(db => db.Jobs.AsNoTracking().SingleAsync(j => j.EndpointId == contosoPc.EndpointId && j.Type == Contracts.JobType.UpdateScan));
        Assert.Equal(("easyrmm:jane@example.com", (Guid?)null), (job.RequestedBy, job.RequestedByUserId));

        // No user row was created for it, or for anyone else.
        Assert.False(await WithDbAsync(db => db.Users.AnyAsync()));

        // Read-only: reads, never acts.
        var viewer = EasyRmm("ReadOnly", "*");
        Assert.Equal(2, (await viewer.GetAsync<PagedResult<EndpointSummaryDto>>("/api/v1/endpoints")).Items.Count);
        await viewer.ExpectAsync(HttpMethod.Post, "/api/v1/endpoints/bulk/scan", new BulkEndpointsRequest([contosoPc.EndpointId], false),
            HttpStatusCode.Forbidden, "forbidden");

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
    }

    [Fact]
    public async Task The_longest_name_a_statement_carries_is_recorded_whole_wherever_the_engine_says_who_acted()
    {
        var (contoso, contosoSite) = await CreateOrgAsync(root, "Contoso");
        var pc = await EnrollAgentAsync(root, contoso.Id, contosoSite.Id, "CONTOSO-PC1");
        await pc.CheckInAsync();
        var update = JobQueueTests.SecurityUpdate("KB5060003");
        var now = Clock.GetUtcNow();
        using (var scan = await pc.PostAsync(AgentRoutes.ScanResults, new ScanResultReport
        {
            ScanId = Guid.NewGuid(), Trigger = Contracts.ScanTrigger.Scheduled, StartedAt = now.AddMinutes(-1), CompletedAt = now, Succeeded = true,
            Source = new UpdateSourceInfo { Type = Contracts.UpdateSourceType.WindowsUpdate }, Missing = [update], Installed = [],
        }))
        {
            await AdminClient.EnsureAsync(scan, HttpStatusCode.NoContent);
        }

        // An email address as long as EasyRMM allows (254 characters), the longest name a statement may carry.
        var name = new string('j', 242) + "@example.com";
        Assert.Equal(254, name.Length);
        var actor = "easyrmm:" + name;
        var admin = EasyRmm("Admin", new[] { contoso.Id.ToString() }, name: name);

        // A job, its audit entry, a hold, a monthly report and an acknowledged alert all name the person whole.
        await ScanAsync(admin, pc.EndpointId);
        var job = await WithDbAsync(db => db.Jobs.AsNoTracking().SingleAsync(j => j.EndpointId == pc.EndpointId && j.Type == Contracts.JobType.UpdateScan));
        Assert.Equal(actor, job.RequestedBy);

        var hold = await admin.SendAsync<UpdateHoldDto>(HttpMethod.Post, $"/api/v1/updates/{update.UpdateGuid}/holds",
            new CreateUpdateHoldRequest(contoso.Id, "Testing"), HttpStatusCode.Created);
        Assert.Equal(actor, await WithDbAsync(db => db.UpdateHolds.AsNoTracking().Where(h => h.Id == hold.Id).Select(h => h.CreatedBy).SingleAsync()));
        Assert.Contains(await WithDbAsync(db => db.AuditLogs.AsNoTracking().Select(a => a.Username).ToListAsync()), u => u == actor);

        var today = DateOnly.FromDateTime(now.UtcDateTime);
        var report = await admin.SendAsync<MonthlyReportDto>(HttpMethod.Post, "/api/v1/monthly-reports",
            new GenerateReportRequest(contoso.Id, today.Year, today.Month), HttpStatusCode.Created);
        Assert.Equal(actor, report.GeneratedBy);

        var alert = new Alert
        {
            Id = Guid.NewGuid(), RuleType = AlertRuleType.EndpointOffline, OrganizationId = contoso.Id, EndpointId = pc.EndpointId,
            DedupeKey = "long-name", Status = AlertStatus.Open, Severity = AlertSeverity.Warning, Title = "CONTOSO-PC1 is offline",
            OpenedAt = now, LastSeenAt = now,
        };
        await WithDbAsync(async db => { db.Alerts.Add(alert); await db.SaveChangesAsync(); });
        var ack = await admin.SendAsync<AcknowledgeAlertsResult>(HttpMethod.Post, "/api/v1/alerts/acknowledge",
            new AcknowledgeAlertsRequest([alert.Id]), HttpStatusCode.OK);
        Assert.Equal(1, ack.Acknowledged);
        Assert.Equal(actor, await WithDbAsync(db => db.Alerts.AsNoTracking().Where(a => a.Id == alert.Id).Select(a => a.AcknowledgedBy).SingleAsync()));
    }

    [Fact]
    public async Task A_statement_is_refused_for_any_other_request_and_once_it_has_expired()
    {
        var (contoso, contosoSite) = await CreateOrgAsync(root, "Contoso");
        var pc = await EnrollAgentAsync(root, contoso.Id, contosoSite.Id, "CONTOSO-PC1");
        var uninstall = $"/api/v1/endpoints/{pc.EndpointId}/uninstall-agent";

        // Made for one request, sent with another: the same route for another endpoint.
        var claims = EasyRmmTestSigner.Claims("POST", uninstall, Clock.GetUtcNow());
        using (var request = new HttpRequestMessage(HttpMethod.Post, $"/api/v1/endpoints/{Guid.NewGuid()}/uninstall-agent"))
        {
            request.Headers.Add(EasyRmmAuthenticationHandler.HeaderName, EasyRmmTestSigner.Sign(claims));
            using var response = await NewHttpClient().SendAsync(request);
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        }

        // Signed a minute ago.
        await EasyRmm("Admin", "*", age: TimeSpan.FromMinutes(1)).ExpectAsync(HttpMethod.Post, uninstall, null, HttpStatusCode.Unauthorized, "unauthenticated");

        // A request with a statement is judged by it alone: an API token alongside a bad statement does not help, even one stored
        // in an imported database (AccessTests: no API token is accepted on its own either).
        var secret = SecureTokens.Create("ept_");
        await WithDbAsync(async db =>
        {
            db.ApiTokens.Add(new ApiToken
            {
                Name = "Automation", Prefix = secret[..12], TokenHash = SecureTokens.Hash(secret), Role = UserRole.Admin, AllOrganizations = true,
                CreatedAt = Clock.GetUtcNow(), ExpiresAt = Clock.GetUtcNow().AddDays(30),
            });
            await db.SaveChangesAsync();
        });
        using (var request = new HttpRequestMessage(HttpMethod.Post, new Uri(uninstall, UriKind.Relative)))
        {
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", secret);
            request.Headers.Add(EasyRmmAuthenticationHandler.HeaderName, "not.a.statement");
            using var response = await NewHttpClient().SendAsync(request);
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        }

        // Nor does a second, valid statement: a request carries exactly one.
        using (var request = new HttpRequestMessage(HttpMethod.Post, new Uri(uninstall, UriKind.Relative)))
        {
            request.Headers.Add(EasyRmmAuthenticationHandler.HeaderName, EasyRmmTestSigner.Sign(EasyRmmTestSigner.Claims("POST", uninstall, Clock.GetUtcNow())));
            using var response = await root.Http.SendAsync(request);
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        }

        Assert.Empty(await WithDbAsync(db => db.Jobs.AsNoTracking().Where(j => j.EndpointId == pc.EndpointId).ToListAsync()));
    }
}

/// <summary>A server that is not an EasyRMM server's engine accepts no statement, however it is signed.</summary>
public sealed class EasyRmmGatewayOffTests(PostgresFixture postgres) : IntegrationTest(postgres)
{
    protected override IReadOnlyDictionary<string, string?>? Settings => new Dictionary<string, string?>
    {
        [EasyRmmGateway.KeySetting] = "",
    };

    [Fact]
    public async Task Without_the_gateway_key_no_statement_is_accepted()
    {
        var http = NewHttpClient(new EasyRmmSigner(() => Clock.GetUtcNow(), "SuperAdmin", "*", EasyRmmStatement.ServiceSubject, "EasyRMM"));
        using var response = await http.GetAsync(new Uri("/api/v1/organizations", UriKind.Relative));
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }
}
