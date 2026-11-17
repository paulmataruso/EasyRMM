using EasyPatch.Agent.Tests.Infrastructure;
using EasyPatch.Contracts;
using EasyPatch.Contracts.Agent;
using Xunit;

namespace EasyPatch.Agent.Tests;

/// <summary>Download jobs: download what the maintenance window's installation would install, ahead of the window, and install
/// nothing.</summary>
public sealed class DownloadUpdatesTests
{
    private static AgentJob DownloadJob(DateTimeOffset windowStart, InstallFilterOptions? filter = null) =>
        AgentHarness.InstallJob(filter, notAfter: windowStart) with { Type = JobType.DownloadUpdates, Trigger = JobTrigger.Scheduled };

    [Fact]
    public async Task Downloads_what_the_window_would_install_and_installs_nothing()
    {
        using var h = new AgentHarness();
        await h.EnrollWithTokenAsync();
        await h.Runtime.CheckInOnceAsync(TestContext.Current.CancellationToken);
        Assert.Contains(AgentCapabilities.DownloadUpdates, h.Server.CheckIns[^1].Capabilities);
        var first = h.AddSecurityUpdate("KB5003001");
        var cached = h.AddSecurityUpdate("KB5003002");
        cached.Downloaded = true;
        var broken = h.AddSecurityUpdate("KB5003003");
        broken.DownloadHResult = unchecked((int)0x80240022);
        var excluded = h.AddSecurityUpdate("KB5003004");
        var job = DownloadJob(h.Time.GetUtcNow().AddHours(4), AgentHarness.DefaultFilter with { ExcludedKbs = ["5003004"] });

        await h.DeliverAsync(job);
        await h.RunJobsAndFlushAsync();

        Assert.Equal([$"download:{first.Guid}", $"download:{broken.Guid}"], h.WindowsUpdate.Operations.Where(o => o.StartsWith("download:", StringComparison.Ordinal)));
        Assert.DoesNotContain(h.WindowsUpdate.Operations, o => o.StartsWith("install:", StringComparison.Ordinal));
        var final = h.Server.StatusesFor(job.JobId)[^1];
        Assert.Equal((JobStatus.Completed, false), (final.Status, final.RebootRequired));
        Assert.Equal("Downloaded 2 of 3 update(s) for the maintenance window; 1 failed.", final.Message);
        Assert.Equal((3, 2, 1), (final.Result!.Planned, final.Result.Succeeded, final.Result.Failed));
        Assert.Equal(JobItemStatus.Downloaded, final.Items.Single(i => i.UpdateGuid == first.Guid).Status);
        Assert.Equal(JobItemStatus.Downloaded, final.Items.Single(i => i.UpdateGuid == cached.Guid).Status);
        Assert.Equal((JobItemStatus.Failed, "0x80240022"), (final.Items.Single(i => i.UpdateGuid == broken.Guid).Status, final.Items.Single(i => i.UpdateGuid == broken.Guid).ErrorCode));
        Assert.Equal(SkipReasons.Excluded, final.Items.Single(i => i.UpdateGuid == excluded.Guid).SkipReason);

        // Nothing changed for the users or Windows: no notification, no verification scan.
        Assert.Empty(h.Users.Notices);
        Assert.DoesNotContain(h.Server.ScanReports, s => s.JobId == job.JobId);

        // The installation in the window does not download them again.
        var install = AgentHarness.InstallJob(AgentHarness.DefaultFilter with { ExcludedKbs = ["5003004"] });
        broken.DownloadHResult = null;
        await h.DeliverAsync(install);
        await h.RunJobsAndFlushAsync();
        Assert.Equal(1, h.WindowsUpdate.Operations.Count(o => o == $"download:{first.Guid}"));
        Assert.Equal(1, h.WindowsUpdate.InstallCount(first.Guid));
        Assert.Equal(JobStatus.Completed, h.Server.StatusesFor(install.JobId)[^1].Status);
    }

    [Fact]
    public async Task A_download_job_stops_when_the_maintenance_window_starts()
    {
        using var h = new AgentHarness();
        await h.EnrollWithTokenAsync();
        var first = h.AddSecurityUpdate("KB5003011");
        var second = h.AddSecurityUpdate("KB5003012");
        first.DownloadProgress = [50, 100];
        var start = h.Time.GetUtcNow().AddMinutes(30);
        h.WindowsUpdate.BeforeProgress = (_, _) => h.Time.Advance(TimeSpan.FromMinutes(20)); // the first download takes 40 minutes
        var job = DownloadJob(start);

        await h.DeliverAsync(job);
        await h.RunJobsAndFlushAsync();

        Assert.Equal([$"download:{first.Guid}"], h.WindowsUpdate.Operations.Where(o => o.StartsWith("download:", StringComparison.Ordinal)));
        var final = h.Server.StatusesFor(job.JobId)[^1];
        Assert.Equal(JobStatus.Completed, final.Status);
        var skipped = final.Items.Single(i => i.UpdateGuid == second.Guid);
        Assert.Equal((JobItemStatus.Skipped, SkipReasons.WindowStarted), (skipped.Status, skipped.SkipReason));

        // Received after the window started: nothing is downloaded.
        var late = DownloadJob(h.Time.GetUtcNow().AddMinutes(-1));
        await h.DeliverAsync(late);
        await h.RunJobsAndFlushAsync();
        var cancelled = h.Server.StatusesFor(late.JobId)[^1];
        Assert.Equal((JobStatus.Cancelled, "maintenance_window_started"), (cancelled.Status, cancelled.ErrorCode));
        Assert.Single(h.WindowsUpdate.Operations, o => o.StartsWith("download:", StringComparison.Ordinal));
    }
}
