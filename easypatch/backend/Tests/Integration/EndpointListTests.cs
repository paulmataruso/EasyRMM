using EasyPatch.Api.Contracts;
using Microsoft.EntityFrameworkCore;
using Xunit;

namespace EasyPatch.Tests.Integration;

/// <summary>The endpoint list, which EasyRMM pages through.</summary>
public sealed class EndpointListTests(PostgresFixture postgres) : IntegrationTest(postgres)
{
    [Fact]
    public async Task Agent_versions_sort_as_versions_in_both_directions_and_across_pages()
    {
        var root = SuperAdmin();
        var (org, site) = await CreateOrgAsync(root);
        // Hostnames in neither the versions' order nor their text order (as text, 1.10.0 comes before 1.2.3 and 1.9.0).
        (string Host, string? Version)[] endpoints =
        [
            ("PC-A", "2.0.0"), ("PC-B", "1.10.0"), ("PC-C", null), ("PC-D", "1.9.0"), ("PC-E", "1.10.0-rc.1"), ("PC-F", "1.2.3"),
            ("PC-G", "unknown"), ("PC-H", "1.10.0"),
        ];
        foreach (var (host, version) in endpoints)
        {
            var agent = await EnrollAgentAsync(root, org.Id, site.Id, host);
            await WithDbAsync(db => db.Endpoints.Where(e => e.Id == agent.EndpointId)
                .ExecuteUpdateAsync(s => s.SetProperty(e => e.AgentVersion, version), TestContext.Current.CancellationToken));
        }

        // No version, then text that is not a version, then by version with the pre-release before its release; the two 1.10.0
        // endpoints by hostname, on two pages.
        Assert.Equal(["PC-C", "PC-G", "PC-F", "PC-D", "PC-E", "PC-B", "PC-H", "PC-A"], await HostnamesAsync(root, "asc"));
        // The exact reverse, but endpoints with the same version stay in hostname order.
        Assert.Equal(["PC-A", "PC-B", "PC-H", "PC-E", "PC-D", "PC-F", "PC-G", "PC-C"], await HostnamesAsync(root, "desc"));
    }

    /// <summary>The whole list sorted by agent version, read three endpoints a page.</summary>
    private static async Task<List<string>> HostnamesAsync(AdminClient admin, string dir)
    {
        var hostnames = new List<string>();
        for (var page = 1; page <= 3; page++)
        {
            var result = await admin.GetAsync<PagedResult<EndpointSummaryDto>>($"/api/v1/endpoints?sort=agentVersion&dir={dir}&page={page}&pageSize=3");
            Assert.Equal(8, result.TotalCount);
            hostnames.AddRange(result.Items.Select(e => e.Hostname));
        }

        return hostnames;
    }
}
