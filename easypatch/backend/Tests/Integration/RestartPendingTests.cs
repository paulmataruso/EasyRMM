using System.Net;
using EasyPatch.Api.Contracts;
using EasyPatch.Contracts;
using EasyPatch.Contracts.Agent;
using EasyPatch.Core.Entities;
using Microsoft.EntityFrameworkCore;
using Xunit;

namespace EasyPatch.Tests.Integration;

/// <summary>"Restart all that need it" for an organization or a site.</summary>
public sealed class RestartPendingTests(PostgresFixture postgres) : IntegrationTest(postgres)
{
    private AdminSession root = null!;
    private OrganizationDto org = null!;
    private SiteDto hq = null!;
    private SiteDto branch = null!;
    private OrganizationDto other = null!;
    private SiteDto otherSite = null!;

    public override async ValueTask InitializeAsync()
    {
        await base.InitializeAsync();
        root = await SuperAdminAsync();
        (org, hq) = await CreateOrgAsync(root);
        branch = await root.SendAsync<SiteDto>(HttpMethod.Post, $"/api/v1/organizations/{org.Id}/sites", new SiteRequest("Branch", null, null, null),
            HttpStatusCode.Created);
        (other, otherSite) = await CreateOrgAsync(root, "Fabrikam");
    }

    private string Url => $"/api/v1/organizations/{org.Id}/restart-pending";

    private static CheckInRequest Capable(bool rebootPending) => new()
    {
        AgentVersion = "1.1.0",
        RebootPending = rebootPending,
        ActiveJobIds = [],
        Capabilities = AgentCapabilities.All,
        Sessions = new UserSessionInfo { SignedInUsers = 1, TrayConnected = 1 },
    };

    // The request asks for an unconditional restart; the server makes it conditional.
    private static RestartRequest Restart() => new(RestartMode.Countdown, RestartCondition.Always, 10, null, null, null, false);

    [Fact]
    public async Task Lists_and_restarts_only_the_confirmed_endpoints_that_still_need_a_restart()
    {
        var server = await EnrollAgentAsync(root, org.Id, hq.Id, "SRV-HQ");
        var pc = await EnrollAgentAsync(root, org.Id, branch.Id, "PC-BRANCH");
        var clean = await EnrollAgentAsync(root, org.Id, hq.Id, "PC-CLEAN");
        var legacy = await EnrollAgentAsync(root, org.Id, hq.Id, "PC-LEGACY");
        var foreign = await EnrollAgentAsync(root, other.Id, otherSite.Id, "PC-FABRIKAM");
        await server.CheckInAsync(Capable(true));
        await pc.CheckInAsync(Capable(true));
        await clean.CheckInAsync(Capable(false));
        await legacy.CheckInAsync(rebootPending: true); // agent 1.0.0: no restart jobs
        await foreign.CheckInAsync(Capable(true));
        await WithDbAsync(db => db.Endpoints.Where(e => e.Id == server.EndpointId)
            .ExecuteUpdateAsync(s => s.SetProperty(e => e.OsProductType, "DomainController")));

        var all = await root.GetAsync<RestartPendingDto>(Url);
        Assert.Equal(3, all.Total);
        Assert.Equal(["PC-BRANCH", "PC-LEGACY", "SRV-HQ"], all.Endpoints.Select(e => e.Hostname));
        Assert.True(all.Endpoints.Single(e => e.Hostname == "SRV-HQ").IsServer);
        Assert.False(all.Endpoints.Single(e => e.Hostname == "PC-BRANCH").IsServer);
        Assert.False(all.Endpoints.Single(e => e.Hostname == "PC-LEGACY").CanRestart);
        Assert.True(all.Endpoints.Single(e => e.Hostname == "SRV-HQ").CanRestart);
        Assert.Equal("Branch", all.Endpoints.Single(e => e.Hostname == "PC-BRANCH").SiteName);

        var hqOnly = await root.GetAsync<RestartPendingDto>($"{Url}?siteId={hq.Id}");
        Assert.Equal(["PC-LEGACY", "SRV-HQ"], hqOnly.Endpoints.Select(e => e.Hostname));

        var detail = await root.GetAsync<OrganizationDto>($"/api/v1/organizations/{org.Id}");
        Assert.Equal(2, detail.Sites.Single(s => s.Id == hq.Id).RebootPendingCount);
        Assert.Equal(1, detail.Sites.Single(s => s.Id == branch.Id).RebootPendingCount);

        // After the list was shown the branch PC restarted on its own; the request also names a clean endpoint and another
        // organization's endpoint. Only the server is restarted.
        await pc.CheckInAsync(Capable(false));
        var result = await root.SendAsync<BulkResultDto>(HttpMethod.Post, Url,
            new RestartPendingRequest(null, [server.EndpointId, pc.EndpointId, legacy.EndpointId, foreign.EndpointId, clean.EndpointId], Restart()),
            HttpStatusCode.OK);
        Assert.Equal(1, result.Succeeded);
        Assert.Equal(4, result.Failed);
        BulkItemResult Item(SignedAgent a) => result.Results.Single(r => r.EndpointId == a.EndpointId);
        Assert.True(Item(server).Success);
        Assert.Equal("no_restart_pending", Item(pc).ErrorCode);
        Assert.Equal("no_restart_pending", Item(clean).ErrorCode);
        Assert.Equal("agent_upgrade_required", Item(legacy).ErrorCode);
        Assert.Equal("out_of_scope", Item(foreign).ErrorCode);
        Assert.Null(Item(foreign).Hostname); // nothing about other organizations' endpoints

        var job = await WithDbAsync(db => db.Jobs.AsNoTracking().SingleAsync(j => j.Type == JobType.Restart));
        Assert.Equal(server.EndpointId, job.EndpointId);
        var delivered = Assert.Single((await server.CheckInAsync(Capable(true))).Jobs);
        Assert.Equal(RestartCondition.OnlyIfPending, delivered.Restart!.Condition);
        Assert.Equal(RestartMode.Countdown, delivered.Restart.Mode);

        // A site's request covers only that site.
        await pc.CheckInAsync(Capable(true));
        var scoped = await root.SendAsync<BulkResultDto>(HttpMethod.Post, Url, new RestartPendingRequest(hq.Id, [pc.EndpointId], Restart()),
            HttpStatusCode.OK);
        Assert.Equal("out_of_scope", Assert.Single(scoped.Results).ErrorCode);
        Assert.Equal(1, await WithDbAsync(db => db.Jobs.CountAsync(j => j.Type == JobType.Restart)));
    }

    [Fact]
    public async Task Requests_are_validated_and_limited_to_the_users_organizations_and_operators()
    {
        var pc = await EnrollAgentAsync(root, org.Id, hq.Id, "PC-1");
        await pc.CheckInAsync(Capable(true));
        var request = new RestartPendingRequest(null, [pc.EndpointId], Restart());

        await root.ExpectAsync(HttpMethod.Post, Url, request with { EndpointIds = [] }, HttpStatusCode.BadRequest, "validation_failed");
        await root.ExpectAsync(HttpMethod.Get, $"{Url}?siteId={otherSite.Id}", null, HttpStatusCode.NotFound);
        await root.ExpectAsync(HttpMethod.Post, Url, request with { SiteId = otherSite.Id }, HttpStatusCode.NotFound);

        var viewer = await CreateAndLoginAsync("viewer", UserRole.ReadOnly);
        Assert.Equal(1, (await viewer.GetAsync<RestartPendingDto>(Url)).Total);
        await viewer.ExpectAsync(HttpMethod.Post, Url, request, HttpStatusCode.Forbidden);

        var otherAdmin = await CreateAndLoginAsync("fabrikam-admin", UserRole.Admin, other.Id);
        await otherAdmin.ExpectAsync(HttpMethod.Get, Url, null, HttpStatusCode.NotFound);
        await otherAdmin.ExpectAsync(HttpMethod.Post, Url, request, HttpStatusCode.NotFound);
        await otherAdmin.ExpectAsync(HttpMethod.Post, $"/api/v1/organizations/{other.Id}/restart-pending", request, HttpStatusCode.OK);

        Assert.Equal(0, await WithDbAsync(db => db.Jobs.CountAsync()));
    }
}
