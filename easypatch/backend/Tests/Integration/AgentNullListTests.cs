using System.Net;
using System.Text.Json;
using System.Text.Json.Nodes;
using EasyPatch.Api.Contracts;
using EasyPatch.Contracts;
using EasyPatch.Contracts.Agent;
using EasyPatch.Contracts.Policy;
using Xunit;

namespace EasyPatch.Tests.Integration;

/// <summary>
/// An agent request that sends <c>null</c> for a list, at the top of the body or inside an object it holds, is refused with 400
/// <c>validation_failed</c> naming the list. Each test sends a request once per list, with that list null, then unchanged.
/// </summary>
public sealed class AgentNullListTests(PostgresFixture postgres) : IntegrationTest(postgres)
{
    private AdminClient root = null!;
    private SignedAgent agent = null!;

    public override async ValueTask InitializeAsync()
    {
        await base.InitializeAsync();
        root = SuperAdmin();
        var (org, site) = await CreateOrgAsync(root);
        agent = await EnrollAgentAsync(root, org.Id, site.Id, "PC-LISTS");
    }

    private static RebootDetails Details() => new()
    {
        WindowsUpdateIds = [Guid.NewGuid()],
        ServicingPackages = ["Package_for_KB5044284"],
        FileOperations = [new PendingFileOperation { Action = PendingFileOperation.Replace, Path = @"C:\Windows\System32\example.dll" }],
        FileOperationCount = 1,
    };

    private static ScanResultReport Scan(ReportedUpdate missing) => new()
    {
        ScanId = Guid.NewGuid(),
        Trigger = ScanTrigger.Scheduled,
        Succeeded = true,
        Source = new UpdateSourceInfo { Type = UpdateSourceType.WindowsUpdate },
        Missing = [missing],
    };

    [Fact]
    public async Task A_check_in_with_a_null_list_is_refused()
    {
        var request = new CheckInRequest
        {
            AgentVersion = "1.11.1",
            RebootPending = true,
            RebootReasons = ["WindowsUpdate"],
            RebootDetails = Details(),
            Capabilities = [AgentCapabilities.Restart],
            WindowsUpdatePolicy = new WindowsUpdatePolicyReport
            {
                Groups =
                [
                    new WindowsUpdatePolicyGroupStatus
                    {
                        Group = WindowsUpdatePolicyGroup.QualityUpdates, State = WindowsUpdatePolicyState.Conflict, ConflictingValues = ["DeferQualityUpdates"],
                    },
                ],
            },
            ReleaseKeyIds = [AgentRelease.KeyId(agent.Key)],
        };

        await RefusesEachNullListAsync(AgentRoutes.CheckIn, request,
            "rebootReasons", "rebootDetails.windowsUpdateIds", "rebootDetails.servicingPackages", "rebootDetails.fileOperations", "activeJobIds",
            "capabilities", "windowsUpdatePolicy.groups", "windowsUpdatePolicy.groups[0].conflictingValues", "releaseKeyIds");
        await agent.CheckInAsync(request);
    }

    [Fact]
    public async Task An_inventory_with_a_null_list_is_refused()
    {
        var report = new InventoryReport
        {
            Hostname = "PC-LISTS",
            AgentVersion = "1.11.1",
            EsuLicenseDetected = true,
            EsuLicenseNames = ["Windows 10 ESU Year 1"],
            RebootPending = true,
            RebootReasons = ["WindowsUpdate"],
            RebootDetails = Details(),
        };

        await RefusesEachNullListAsync(AgentRoutes.Inventory, report,
            "esuLicenseNames", "rebootReasons", "rebootDetails.windowsUpdateIds", "rebootDetails.servicingPackages", "rebootDetails.fileOperations");
        await AcceptsAsync(AgentRoutes.Inventory, report, HttpStatusCode.NoContent);
    }

    [Fact]
    public async Task A_scan_with_a_null_list_is_refused_also_inside_an_update()
    {
        var report = Scan(JobQueueTests.SecurityUpdate("KB5046617") with
        {
            SupersededUpdateGuids = [Guid.NewGuid()],
            Package = new PackageUpdateInfo { Name = "openssl", Architecture = "amd64", Version = "3.0.17-1~deb12u3", Advisories = ["DSA-5900-1"] },
        });

        await RefusesEachNullListAsync(AgentRoutes.ScanResults, report,
            "missing", "missing[0].kbNumbers", "missing[0].categories", "missing[0].supersededUpdateGuids", "missing[0].package.advisories",
            "missing[0].package.cves", "installed");

        // One refusal names at most 20 lists.
        var many = JsonSerializer.SerializeToNode(report with { Missing = Enumerable.Repeat(report.Missing[0], 30).ToList() }, TestJson.Options)!;
        foreach (var update in many["missing"]!.AsArray())
        {
            update!["kbNumbers"] = null;
        }

        using (var response = await agent.PostAsync(AgentRoutes.ScanResults, many))
        {
            await AdminClient.EnsureAsync(response, HttpStatusCode.BadRequest);
            using var problem = JsonDocument.Parse(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
            Assert.Equal(20, problem.RootElement.GetProperty("errors").EnumerateObject().Count());
        }

        await AcceptsAsync(AgentRoutes.ScanResults, report, HttpStatusCode.NoContent);
    }

    [Fact]
    public async Task An_update_history_with_a_null_list_is_refused()
    {
        var report = new HistoryReport
        {
            Entries = [new HistoryEntryReport { Title = "2026-11 Security Update (KB5046617)", KbNumber = "5046617", Operation = "Installation", ResultCode = 2 }],
        };

        await RefusesEachNullListAsync(AgentRoutes.History, report, "entries");
        await AcceptsAsync(AgentRoutes.History, report, HttpStatusCode.NoContent);
    }

    [Fact]
    public async Task A_job_report_with_a_null_list_is_refused()
    {
        var update = JobQueueTests.SecurityUpdate("KB5046617");
        await AcceptsAsync(AgentRoutes.ScanResults, Scan(update), HttpStatusCode.NoContent);
        var job = await root.SendAsync<JobSummaryDto>(HttpMethod.Post, $"/api/v1/endpoints/{agent.EndpointId}/install-updates",
            new InstallUpdatesRequest(InstallMode.Selected, [update.UpdateGuid], false), HttpStatusCode.Accepted);
        Assert.Equal(job.Id, Assert.Single((await agent.CheckInAsync()).Jobs).JobId);
        await AcceptsAsync(AgentRoutes.JobAck(job.Id), new { }, HttpStatusCode.OK);
        var report = new JobStatusReport
        {
            Sequence = 1,
            Status = JobStatus.Running,
            Items = [new JobItemReport { UpdateGuid = update.UpdateGuid, RevisionNumber = update.RevisionNumber, Title = update.Title, Status = JobItemStatus.Installing }],
        };

        await RefusesEachNullListAsync(AgentRoutes.JobStatus(job.Id), report, "items");
        await AcceptsAsync(AgentRoutes.JobStatus(job.Id), report, HttpStatusCode.NoContent);
    }

    /// <summary>
    /// Sends <paramref name="request"/> once for each of its lists with that list null, and expects each refused naming it.
    /// <paramref name="lists"/> must be every list the request holds, so a list added to the contract later fails this test until
    /// it is named here.
    /// </summary>
    private async Task RefusesEachNullListAsync(string route, object request, params string[] lists)
    {
        var json = JsonSerializer.SerializeToNode(request, request.GetType(), TestJson.Options)!.AsObject();
        Assert.Equal(lists.Order(StringComparer.Ordinal), Lists(json).Select(l => l.Path).Order(StringComparer.Ordinal));
        foreach (var path in lists)
        {
            var body = json.DeepClone().AsObject();
            var (_, owner, name) = Lists(body).Single(l => l.Path == path);
            owner[name] = null;
            using var response = await agent.PostAsync(route, body);
            var text = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
            Assert.True(response.StatusCode == HttpStatusCode.BadRequest, $"{path}: {(int)response.StatusCode} {text}");
            using var problem = JsonDocument.Parse(text);
            Assert.Equal(AgentErrorCodes.ValidationFailed, problem.RootElement.GetProperty("code").GetString());
            Assert.Equal($"{path}: Must be a list (empty when there is nothing to report), not null.", problem.RootElement.GetProperty("detail").GetString());
            Assert.Equal(path, Assert.Single(problem.RootElement.GetProperty("errors").EnumerateObject()).Name);
        }
    }

    private async Task AcceptsAsync(string route, object request, HttpStatusCode expected)
    {
        using var response = await agent.PostAsync(route, request);
        await AdminClient.EnsureAsync(response, expected);
    }

    /// <summary>The lists in a JSON body by path (<c>missing</c>, <c>missing[0].kbNumbers</c>), with the object that holds each.</summary>
    private static IEnumerable<(string Path, JsonObject Owner, string Name)> Lists(JsonObject json, string prefix = "")
    {
        foreach (var (name, value) in json)
        {
            if (value is JsonObject child)
            {
                foreach (var list in Lists(child, $"{prefix}{name}."))
                {
                    yield return list;
                }
            }
            else if (value is JsonArray array)
            {
                yield return (prefix + name, json, name);
                for (var i = 0; i < array.Count; i++)
                {
                    if (array[i] is JsonObject item)
                    {
                        foreach (var list in Lists(item, $"{prefix}{name}[{i}]."))
                        {
                            yield return list;
                        }
                    }
                }
            }
        }
    }
}
