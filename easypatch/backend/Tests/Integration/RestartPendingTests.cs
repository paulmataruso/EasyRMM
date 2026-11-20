using System.Net;
using EasyPatch.Api.Contracts;
using EasyPatch.Contracts;
using EasyPatch.Contracts.Agent;
using EasyPatch.Core.Entities;
using Microsoft.EntityFrameworkCore;
using Xunit;

namespace EasyPatch.Tests.Integration;

/// <summary>"Restart all that need it" for an organization or a site: EasyRMM reads the list, then restarts through
/// <c>bulk/restart</c>.</summary>
public sealed class RestartPendingTests(PostgresFixture postgres) : IntegrationTest(postgres)
{
    private AdminClient root = null!;
    private OrganizationDto org = null!;
    private SiteDto hq = null!;
    private SiteDto branch = null!;
    private OrganizationDto other = null!;
    private SiteDto otherSite = null!;

    public override async ValueTask InitializeAsync()
    {
        await base.InitializeAsync();
        root = SuperAdmin();
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

    [Fact]
    public async Task Lists_only_the_confirmed_endpoints_that_still_need_a_restart()
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

        // After the list was shown the branch PC restarted on its own: it is no longer listed.
        await pc.CheckInAsync(Capable(false));
        Assert.Equal(["PC-LEGACY", "SRV-HQ"], (await root.GetAsync<RestartPendingDto>(Url)).Endpoints.Select(e => e.Hostname));

        // The server is restarted only if a restart is still pending when its agent gets the job.
        var restart = await BulkOneAsync(root, "restart", new BulkRestartRequest([server.EndpointId],
            new RestartRequest(RestartMode.Countdown, RestartCondition.OnlyIfPending, 10, null, null, null, false)));
        Assert.True(restart.Success, restart.Message);
        var job = await WithDbAsync(db => db.Jobs.AsNoTracking().SingleAsync(j => j.Type == JobType.Restart));
        Assert.Equal(server.EndpointId, job.EndpointId);
        var delivered = Assert.Single((await server.CheckInAsync(Capable(true))).Jobs);
        Assert.Equal(RestartCondition.OnlyIfPending, delivered.Restart!.Condition);
        Assert.Equal(RestartMode.Countdown, delivered.Restart.Mode);
    }

    [Fact]
    public async Task The_list_is_limited_to_the_users_organizations()
    {
        var pc = await EnrollAgentAsync(root, org.Id, hq.Id, "PC-1");
        await pc.CheckInAsync(Capable(true));

        await root.ExpectAsync(HttpMethod.Get, $"{Url}?siteId={otherSite.Id}", null, HttpStatusCode.NotFound);

        var viewer = Admin("viewer", UserRole.ReadOnly);
        Assert.Equal(1, (await viewer.GetAsync<RestartPendingDto>(Url)).Total);

        var otherAdmin = Admin("fabrikam-admin", UserRole.Admin, [other.Id]);
        await otherAdmin.ExpectAsync(HttpMethod.Get, Url, null, HttpStatusCode.NotFound);
        Assert.Equal(0, (await otherAdmin.GetAsync<RestartPendingDto>($"/api/v1/organizations/{other.Id}/restart-pending")).Total);

        Assert.Equal(0, await WithDbAsync(db => db.Jobs.CountAsync()));
    }
}
