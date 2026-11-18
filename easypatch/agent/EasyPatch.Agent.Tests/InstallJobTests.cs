using EasyPatch.Agent.Core.State;
using EasyPatch.Agent.Tests.Infrastructure;
using EasyPatch.Contracts;
using EasyPatch.Contracts.Agent;
using EasyPatch.Contracts.Updates;
using Xunit;

namespace EasyPatch.Agent.Tests;

public sealed class InstallJobTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    [Fact]
    public async Task Installs_only_policy_approved_updates_in_servicing_order()
    {
        using var h = new AgentHarness();
        await h.EnrollWithTokenAsync();
        var security = h.AddSecurityUpdate("KB5001001");
        var cumulative = h.AddCumulativeUpdate("KB5001002");
        var ssu = h.AddServicingStackUpdate("KB5001003");
        var driver = h.WindowsUpdate.Add("Intel - Display - 31.0.101.5000", MicrosoftClassifications.Drivers, isDriver: true);
        var optional = h.WindowsUpdate.Add("2026-11 Cumulative Update Preview for Windows 11 (KB5001004)", MicrosoftClassifications.Updates, "KB5001004", browseOnly: true);
        var excluded = h.AddSecurityUpdate("KB5001005");
        var feature = h.WindowsUpdate.Add("Feature update to Windows 11, version 25H2", MicrosoftClassifications.Upgrades);
        var job = AgentHarness.InstallJob(AgentHarness.DefaultFilter with { ExcludedKbs = ["5001005"] });

        await h.DeliverAsync(job);
        await h.RunJobsAndFlushAsync();

        // Order: servicing stack, cumulative, then other security updates.
        var installs = h.WindowsUpdate.Operations.Where(o => o.StartsWith("install:", StringComparison.Ordinal)).ToList();
        Assert.Equal(new[] { $"install:{ssu.Guid}", $"install:{cumulative.Guid}", $"install:{security.Guid}" }, installs);
        Assert.Equal(0, h.WindowsUpdate.InstallCount(driver.Guid));
        Assert.Equal(0, h.WindowsUpdate.InstallCount(optional.Guid));
        Assert.Equal(0, h.WindowsUpdate.InstallCount(excluded.Guid));
        Assert.Equal(0, h.WindowsUpdate.InstallCount(feature.Guid));

        var reports = h.Server.StatusesFor(job.JobId);
        Assert.True(reports.Zip(reports.Skip(1)).All(p => p.Second.Sequence > p.First.Sequence), "sequences must increase");
        var final = reports[^1];
        Assert.Equal(JobStatus.Completed, final.Status);
        Assert.NotNull(final.Result);
        Assert.Equal(3, final.Result.Planned);
        Assert.Equal(3, final.Result.Succeeded);
        Assert.Equal(0, final.Result.Failed);
        Assert.True(final.RebootRequired); // the cumulative update needs a restart
        Assert.True(final.Result.RebootRequired);

        var excludedItem = Assert.Single(final.Items, i => i.UpdateGuid == excluded.Guid);
        Assert.Equal(JobItemStatus.Skipped, excludedItem.Status);
        Assert.Equal(SkipReasons.Excluded, excludedItem.SkipReason);
        Assert.DoesNotContain(final.Items, i => i.UpdateGuid == driver.Guid); // policy-filtered noise is not reported

        var cumulativeItem = Assert.Single(final.Items, i => i.UpdateGuid == cumulative.Guid);
        Assert.Equal(JobItemStatus.Succeeded, cumulativeItem.Status);
        Assert.True(cumulativeItem.RebootRequired);
        Assert.Equal("KB5001002", cumulativeItem.KbNumber);
        Assert.Equal(UpdateCategory.Cumulative, cumulativeItem.Category);

        // A verification scan is sent and linked to the job.
        var verification = Assert.Single(h.Server.ScanReports, s => s.Trigger == ScanTrigger.PostInstall);
        Assert.Equal(job.JobId, verification.JobId);
        Assert.Equal(verification.ScanId, final.Result.PostInstallScanId);
        Assert.Contains(verification.Missing, m => m.UpdateGuid == cumulative.Guid && m.RebootRequired);

        Assert.Empty(h.Runtime.State.Read(s => s.Jobs));
        Assert.Equal(0, h.WindowsUpdate.OpenHandles);
    }

    [Fact]
    public async Task Download_and_install_percentages_are_reported_at_most_every_ten_seconds()
    {
        using var h = new AgentHarness();
        await h.EnrollWithTokenAsync();
        var first = h.AddSecurityUpdate("KB5001011");
        var second = h.AddSecurityUpdate("KB5001012");
        first.DownloadProgress = [0, 20, 40, 60, 100];
        first.InstallProgress = [0, 50, 100];
        h.WindowsUpdate.BeforeProgress = (operation, percent) =>
        {
            // 20% and 40% arrive within ten seconds of each other: only 20% is sent; 60% comes 12 s later.
            h.Time.Advance(percent == 40 ? TimeSpan.FromSeconds(4) : TimeSpan.FromSeconds(12));
        };
        var job = AgentHarness.InstallJob();

        await h.DeliverAsync(job);
        await h.RunJobsAndFlushAsync();

        var reports = h.Server.StatusesFor(job.JobId);
        var downloading = reports.Where(r => r.Phase == "Downloading" && r.Message!.Contains("KB5001011", StringComparison.Ordinal))
            .Select(r => r.Items.Single(i => i.UpdateGuid == first.Guid).DownloadPercent).ToList();
        Assert.Equal(new int?[] { null, 20, 60, 100 }, downloading);
        var installing = reports.Where(r => r.Phase == "Installing" && r.Message!.Contains("KB5001011", StringComparison.Ordinal))
            .Select(r => (r.Items.Single(i => i.UpdateGuid == first.Guid).InstallPercent, r.Percent)).ToList();
        Assert.Equal([(null, 27), (50, 38), (100, 50), (100, 50)], installing); // started, 50%, 100%, installed

        // The job percentage moves through the first update's half of 5-95% and never goes backwards.
        var percents = reports.Where(r => r.Percent is not null).Select(r => r.Percent!.Value).ToList();
        Assert.True(percents.Zip(percents.Skip(1)).All(p => p.Second >= p.First), string.Join(",", percents));
        Assert.Contains(reports, r => r.Phase == "Downloading" && r.Message == "Downloading KB5001011 (1 of 2): 60%.");

        // An update source without percentages leaves them empty until the update is done.
        var final = reports[^1];
        Assert.Equal(JobStatus.Completed, final.Status);
        var secondItem = final.Items.Single(i => i.UpdateGuid == second.Guid);
        Assert.Equal(100, secondItem.DownloadPercent);
        Assert.Equal(100, secondItem.InstallPercent);
        Assert.DoesNotContain(reports, r => r.Items.Any(i => i.UpdateGuid == second.Guid && i.Status == JobItemStatus.Installing && i.InstallPercent is not null));
    }

    [Fact]
    public async Task Partial_failure_reports_the_real_hresult_per_update()
    {
        using var h = new AgentHarness();
        await h.EnrollWithTokenAsync();
        var good = h.AddSecurityUpdate("KB5002001");
        var bad = h.AddSecurityUpdate("KB5002002");
        bad.InstallHResult = unchecked((int)0x80070643);
        var job = AgentHarness.InstallJob();

        await h.DeliverAsync(job);
        await h.RunJobsAndFlushAsync();

        var final = h.Server.StatusesFor(job.JobId)[^1];
        Assert.Equal(JobStatus.Completed, final.Status); // partial success is not a job failure
        Assert.Equal(1, final.Result!.Succeeded);
        Assert.Equal(1, final.Result.Failed);
        var failed = Assert.Single(final.Items, i => i.UpdateGuid == bad.Guid);
        Assert.Equal(JobItemStatus.Failed, failed.Status);
        Assert.Equal("0x80070643", failed.ErrorCode);
        Assert.Equal(UpdateOperationResultCodes.Failed, failed.ResultCode);
        Assert.False(string.IsNullOrWhiteSpace(failed.ErrorMessage));
        Assert.Equal(JobItemStatus.Succeeded, Assert.Single(final.Items, i => i.UpdateGuid == good.Guid).Status);
    }

    [Fact]
    public async Task All_updates_failing_fails_the_job_with_the_first_error()
    {
        using var h = new AgentHarness();
        await h.EnrollWithTokenAsync();
        var update = h.AddSecurityUpdate("KB5003001");
        update.DownloadHResult = unchecked((int)0x80244022);
        var job = AgentHarness.InstallJob();

        await h.DeliverAsync(job);
        await h.RunJobsAndFlushAsync();

        var final = h.Server.StatusesFor(job.JobId)[^1];
        Assert.Equal(JobStatus.Failed, final.Status);
        Assert.Equal("0x80244022", final.ErrorCode);
        Assert.Equal(0, h.WindowsUpdate.InstallCount(update.Guid)); // a failed download is never "installed"
    }

    [Fact]
    public async Task Nothing_to_install_completes_without_claiming_installs()
    {
        using var h = new AgentHarness();
        await h.EnrollWithTokenAsync();
        h.WindowsUpdate.Add("Intel - Display", MicrosoftClassifications.Drivers, isDriver: true);
        var job = AgentHarness.InstallJob();

        await h.DeliverAsync(job);
        await h.RunJobsAndFlushAsync();

        var final = h.Server.StatusesFor(job.JobId)[^1];
        Assert.Equal(JobStatus.Completed, final.Status);
        Assert.Equal(0, final.Result!.Planned);
        Assert.Equal(0, final.Result.Succeeded);
        Assert.DoesNotContain(h.WindowsUpdate.Operations, o => o.StartsWith("install:", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Pending_restart_parks_the_job_until_the_computer_restarts()
    {
        using var h = new AgentHarness();
        await h.EnrollWithTokenAsync();
        var update = h.AddSecurityUpdate("KB5004001");
        h.WindowsUpdate.RebootRequiredBeforeInstallation = true;
        var job = AgentHarness.InstallJob();

        await h.DeliverAsync(job);
        await h.RunJobsAndFlushAsync();

        Assert.Equal(JobStatus.WaitingForReboot, h.Server.StatusesFor(job.JobId)[^1].Status);
        Assert.Equal(JobRunState.WaitingForReboot, h.Runtime.State.Read(s => s.FindJob(job.JobId)!.RunState));
        Assert.Equal(0, h.WindowsUpdate.InstallCount(update.Guid));

        // Same boot: nothing to do, and the job is still reported as held so the server does not re-deliver it.
        Assert.False(await h.Runtime.ProcessNextJobAsync(Ct));
        await h.Runtime.CheckInOnceAsync(Ct);
        Assert.Contains(job.JobId, h.Server.CheckIns[^1].ActiveJobIds);
        Assert.Equal(1, h.Server.Jobs[job.JobId].Deliveries);

        // An install job never restarts the computer itself; once someone does, the job resumes.
        var runtime = h.Reboot();
        Assert.True(await runtime.ProcessNextJobAsync(Ct));
        Assert.True(await runtime.FlushOutboxAsync(Ct));

        Assert.Equal(1, h.WindowsUpdate.InstallCount(update.Guid));
        Assert.Equal(JobStatus.Completed, h.Server.StatusesFor(job.JobId)[^1].Status);
        Assert.Empty(runtime.State.Read(s => s.Jobs));
    }

    [Fact]
    public async Task Restart_required_after_a_failure_parks_remaining_updates()
    {
        using var h = new AgentHarness();
        await h.EnrollWithTokenAsync();
        var first = h.AddServicingStackUpdate("KB5005001");
        var second = h.AddSecurityUpdate("KB5005002");
        first.InstallHResult = unchecked((int)0x8024200B);
        h.WindowsUpdate.BeforeInstall = (update, _) =>
        {
            if (update == first)
            {
                h.WindowsUpdate.RebootRequiredBeforeInstallation = true;
            }

            return Task.CompletedTask;
        };
        var job = AgentHarness.InstallJob();

        await h.DeliverAsync(job);
        await h.RunJobsAndFlushAsync();

        var waiting = h.Server.StatusesFor(job.JobId)[^1];
        Assert.Equal(JobStatus.WaitingForReboot, waiting.Status);
        Assert.Equal(0, h.WindowsUpdate.InstallCount(second.Guid));

        first.InstallHResult = null; // succeeds after the restart
        h.WindowsUpdate.BeforeInstall = null;
        var runtime = h.Reboot();
        await h.RunJobsAndFlushAsync();

        var final = h.Server.StatusesFor(job.JobId)[^1];
        Assert.Equal(JobStatus.Completed, final.Status);
        Assert.Equal(2, final.Result!.Succeeded);
        Assert.Equal(2, h.WindowsUpdate.InstallCount(first.Guid));
        Assert.Equal(1, h.WindowsUpdate.InstallCount(second.Guid));
        Assert.Empty(runtime.State.Read(s => s.Jobs));
    }

    [Fact]
    public async Task Job_waiting_too_long_for_a_restart_fails()
    {
        using var h = new AgentHarness();
        await h.EnrollWithTokenAsync();
        h.AddSecurityUpdate("KB5006001");
        h.WindowsUpdate.RebootRequiredBeforeInstallation = true;
        var job = AgentHarness.InstallJob();
        await h.DeliverAsync(job);
        await h.RunJobsAndFlushAsync();

        h.Time.Advance(TimeSpan.FromDays(31));
        await h.RunJobsAndFlushAsync();

        var final = h.Server.StatusesFor(job.JobId)[^1];
        Assert.Equal(JobStatus.Failed, final.Status);
        Assert.Equal("reboot_not_performed", final.ErrorCode);
        Assert.Empty(h.Runtime.State.Read(s => s.Jobs));
    }

    [Fact]
    public async Task Cancellation_before_start_reports_cancelled_and_installs_nothing()
    {
        using var h = new AgentHarness();
        await h.EnrollWithTokenAsync();
        var update = h.AddSecurityUpdate("KB5007001");
        var job = AgentHarness.InstallJob();
        await h.DeliverAsync(job);

        h.Server.CancelJob(job.JobId);
        await h.Runtime.CheckInOnceAsync(Ct);
        await h.RunJobsAndFlushAsync();

        Assert.Equal(JobStatus.Cancelled, Assert.Single(h.Server.StatusesFor(job.JobId)).Status);
        Assert.Equal(0, h.WindowsUpdate.InstallCount(update.Guid));
        Assert.Empty(h.Runtime.State.Read(s => s.Jobs));
    }

    [Fact]
    public async Task Cancellation_during_install_stops_before_the_next_update()
    {
        using var h = new AgentHarness();
        await h.EnrollWithTokenAsync();
        var first = h.AddServicingStackUpdate("KB5008001");
        var second = h.AddSecurityUpdate("KB5008002");
        var job = AgentHarness.InstallJob();
        h.WindowsUpdate.BeforeInstall = (_, _) =>
        {
            // An administrator cancels while the first install is running (delivered by a concurrent check-in).
            h.Runtime.State.Update(s => s.FindJob(job.JobId)!.CancelRequested = true);
            return Task.CompletedTask;
        };

        await h.DeliverAsync(job);
        await h.RunJobsAndFlushAsync();

        var final = h.Server.StatusesFor(job.JobId)[^1];
        Assert.Equal(JobStatus.Cancelled, final.Status);
        Assert.Equal(1, h.WindowsUpdate.InstallCount(first.Guid)); // an in-progress install is never interrupted
        Assert.Equal(0, h.WindowsUpdate.InstallCount(second.Guid));
        Assert.Equal(JobItemStatus.Cancelled, Assert.Single(final.Items, i => i.UpdateGuid == second.Guid).Status);
        Assert.Equal(JobItemStatus.Succeeded, Assert.Single(final.Items, i => i.UpdateGuid == first.Guid).Status);
    }

    [Fact]
    public async Task Closed_maintenance_window_prevents_a_late_start()
    {
        using var h = new AgentHarness();
        await h.EnrollWithTokenAsync();
        var update = h.AddSecurityUpdate("KB5009001");
        var job = AgentHarness.InstallJob(notAfter: h.Time.GetUtcNow().AddMinutes(-1));

        await h.DeliverAsync(job);
        await h.RunJobsAndFlushAsync();

        var final = Assert.Single(h.Server.StatusesFor(job.JobId));
        Assert.Equal(JobStatus.Cancelled, final.Status);
        Assert.Equal("maintenance_window_closed", final.ErrorCode);
        Assert.Equal(0, h.WindowsUpdate.InstallCount(update.Guid));
    }

    [Fact]
    public async Task Maintenance_window_closing_mid_job_skips_remaining_updates()
    {
        using var h = new AgentHarness();
        await h.EnrollWithTokenAsync();
        var first = h.AddServicingStackUpdate("KB5010001");
        var second = h.AddSecurityUpdate("KB5010002");
        var job = AgentHarness.InstallJob(notAfter: h.Time.GetUtcNow().AddMinutes(30));
        h.WindowsUpdate.BeforeInstall = (_, _) =>
        {
            h.Time.Advance(TimeSpan.FromMinutes(45)); // a long install runs past the window
            return Task.CompletedTask;
        };

        await h.DeliverAsync(job);
        await h.RunJobsAndFlushAsync();

        var final = h.Server.StatusesFor(job.JobId)[^1];
        Assert.Equal(JobStatus.Completed, final.Status);
        Assert.Equal(1, h.WindowsUpdate.InstallCount(first.Guid));
        Assert.Equal(0, h.WindowsUpdate.InstallCount(second.Guid));
        var skipped = Assert.Single(final.Items, i => i.UpdateGuid == second.Guid);
        Assert.Equal(JobItemStatus.Skipped, skipped.Status);
        Assert.Equal(SkipReasons.MaintenanceWindowClosed, skipped.SkipReason);
    }

    [Fact]
    public async Task Service_stop_mid_job_resumes_without_reinstalling()
    {
        using var h = new AgentHarness();
        await h.EnrollWithTokenAsync();
        var first = h.AddServicingStackUpdate("KB5011001");
        var second = h.AddSecurityUpdate("KB5011002");
        var job = AgentHarness.InstallJob();
        await h.DeliverAsync(job);

        using var stop = new CancellationTokenSource();
        h.WindowsUpdate.BeforeInstall = (update, _) =>
        {
            if (update == second)
            {
                stop.Cancel(); // the service is stopped while the second update is about to install
            }

            return Task.CompletedTask;
        };
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => h.Runtime.ProcessNextJobAsync(stop.Token));
        Assert.Equal(JobRunState.Running, h.Runtime.State.Read(s => s.FindJob(job.JobId)!.RunState));

        h.WindowsUpdate.BeforeInstall = null;
        var runtime = h.Restart();
        await h.RunJobsAndFlushAsync();

        Assert.Equal(1, h.WindowsUpdate.InstallCount(first.Guid));
        Assert.Equal(1, h.WindowsUpdate.InstallCount(second.Guid));
        var final = h.Server.StatusesFor(job.JobId)[^1];
        Assert.Equal(JobStatus.Completed, final.Status);
        Assert.Equal(JobItemStatus.Succeeded, Assert.Single(final.Items, i => i.UpdateGuid == first.Guid).Status);
        Assert.Equal(JobItemStatus.Succeeded, Assert.Single(final.Items, i => i.UpdateGuid == second.Guid).Status);
        Assert.Empty(runtime.State.Read(s => s.Jobs));
    }

    [Fact]
    public async Task Repeatedly_interrupted_job_is_abandoned_instead_of_crash_looping()
    {
        using var h = new AgentHarness();
        await h.EnrollWithTokenAsync();
        var update = h.AddSecurityUpdate("KB5012001");
        var job = AgentHarness.InstallJob();
        await h.DeliverAsync(job);
        h.Runtime.State.Update(s =>
        {
            var record = s.FindJob(job.JobId)!;
            record.Attempts = h.Options.MaxJobAttempts;
            record.RunState = JobRunState.Running;
        });

        await h.RunJobsAndFlushAsync();

        var final = h.Server.StatusesFor(job.JobId)[^1];
        Assert.Equal(JobStatus.Failed, final.Status);
        Assert.Equal("agent_interrupted", final.ErrorCode);
        Assert.Equal(0, h.WindowsUpdate.InstallCount(update.Guid));
    }

    [Fact]
    public async Task Selected_mode_reports_installed_and_unknown_updates_honestly()
    {
        using var h = new AgentHarness();
        await h.EnrollWithTokenAsync();
        var wanted = h.WindowsUpdate.Add("Some Update", MicrosoftClassifications.Updates, "KB5013001"); // category not in policy
        var notWanted = h.AddSecurityUpdate("KB5013002");
        var alreadyInstalled = h.WindowsUpdate.Add("Installed Update", MicrosoftClassifications.SecurityUpdates, "KB5013003", installed: true);
        var unknown = Guid.NewGuid();
        var job = AgentHarness.InstallJob(mode: InstallMode.Selected, selected: [wanted.Guid, alreadyInstalled.Guid, unknown]);

        await h.DeliverAsync(job);
        await h.RunJobsAndFlushAsync();

        Assert.Equal(1, h.WindowsUpdate.InstallCount(wanted.Guid)); // explicit selection overrides category policy
        Assert.Equal(0, h.WindowsUpdate.InstallCount(notWanted.Guid));
        var final = h.Server.StatusesFor(job.JobId)[^1];
        Assert.Equal(JobItemStatus.Succeeded, Assert.Single(final.Items, i => i.UpdateGuid == wanted.Guid).Status);
        var installed = Assert.Single(final.Items, i => i.UpdateGuid == alreadyInstalled.Guid);
        Assert.Equal(SkipReasons.AlreadyInstalled, installed.SkipReason);
        var missing = Assert.Single(final.Items, i => i.UpdateGuid == unknown);
        Assert.Equal(SkipReasons.NotApplicable, missing.SkipReason);
        Assert.DoesNotContain(final.Items, i => i.UpdateGuid == notWanted.Guid);
    }

    [Fact]
    public async Task Updates_needing_user_input_are_skipped()
    {
        using var h = new AgentHarness();
        await h.EnrollWithTokenAsync();
        var interactive = h.AddSecurityUpdate("KB5014001");
        h.WindowsUpdate.Updates.Remove(interactive);
        var replaced = new FakeUpdate { Metadata = interactive.Metadata with { CanRequestUserInput = true } };
        h.WindowsUpdate.Updates.Add(replaced);
        var job = AgentHarness.InstallJob();

        await h.DeliverAsync(job);
        await h.RunJobsAndFlushAsync();

        var item = Assert.Single(h.Server.StatusesFor(job.JobId)[^1].Items);
        Assert.Equal(SkipReasons.RequiresUserInput, item.SkipReason);
        Assert.Equal(0, h.WindowsUpdate.InstallCount(replaced.Guid));
    }

    [Fact]
    public async Task Unsupported_job_is_reported_failed_and_never_executed()
    {
        using var h = new AgentHarness();
        await h.EnrollWithTokenAsync();
        var job = AgentHarness.SimpleJob(JobType.InstallUpdates); // no payload
        h.Server.EnqueueJob(job);

        await h.Runtime.CheckInOnceAsync(Ct);
        await h.RunJobsAndFlushAsync();

        Assert.DoesNotContain(job.JobId, h.Server.Acks);
        var final = Assert.Single(h.Server.StatusesFor(job.JobId));
        Assert.Equal(JobStatus.Failed, final.Status);
        Assert.Equal("unsupported_job", final.ErrorCode);
        Assert.Equal(0, h.WindowsUpdate.Scans);
    }

    [Fact]
    public async Task Expired_unstarted_job_is_reported_and_dropped()
    {
        using var h = new AgentHarness();
        await h.EnrollWithTokenAsync();
        var update = h.AddSecurityUpdate("KB5015001");
        var job = AgentHarness.InstallJob(expiresAt: h.Time.GetUtcNow().AddHours(1));
        await h.DeliverAsync(job);

        h.Time.Advance(TimeSpan.FromHours(2));
        Assert.False(await h.Runtime.ProcessNextJobAsync(Ct));
        Assert.True(await h.Runtime.FlushOutboxAsync(Ct));

        Assert.Empty(h.Runtime.State.Read(s => s.Jobs));
        Assert.Equal(0, h.WindowsUpdate.InstallCount(update.Guid));
        var final = Assert.Single(h.Server.StatusesFor(job.JobId));
        Assert.Equal(JobStatus.Expired, final.Status);
    }

    [Fact]
    public async Task Scan_job_reports_results_linked_to_the_job()
    {
        using var h = new AgentHarness();
        await h.EnrollWithTokenAsync();
        h.AddSecurityUpdate("KB5016001");
        h.WindowsUpdate.Add("Installed", MicrosoftClassifications.SecurityUpdates, "KB5016002", installed: true);
        var job = AgentHarness.SimpleJob(JobType.UpdateScan);

        await h.DeliverAsync(job);
        await h.RunJobsAndFlushAsync();

        var scan = Assert.Single(h.Server.ScanReports);
        Assert.Equal(job.JobId, scan.JobId);
        Assert.Equal(ScanTrigger.Job, scan.Trigger);
        Assert.True(scan.Succeeded);
        Assert.Single(scan.Missing);
        Assert.Single(scan.Installed);
        Assert.Null(scan.Installed[0].Description);
        Assert.Equal(JobStatus.Completed, h.Server.StatusesFor(job.JobId)[^1].Status);
    }

    [Fact]
    public async Task Failed_scan_is_reported_as_a_failure_with_its_hresult()
    {
        using var h = new AgentHarness();
        await h.EnrollWithTokenAsync();
        h.WindowsUpdate.ScanException = new Core.Abstractions.WindowsUpdateException("Search failed.", unchecked((int)0x8024402C));
        var job = AgentHarness.SimpleJob(JobType.UpdateScan);

        await h.DeliverAsync(job);
        await h.RunJobsAndFlushAsync();

        var scan = Assert.Single(h.Server.ScanReports);
        Assert.False(scan.Succeeded);
        Assert.Equal("0x8024402C", scan.ErrorCode);
        Assert.Empty(scan.Missing);
        var final = h.Server.StatusesFor(job.JobId)[^1];
        Assert.Equal(JobStatus.Failed, final.Status);
        Assert.Equal("0x8024402C", final.ErrorCode);
    }

    [Fact]
    public async Task Inventory_job_sends_inventory_with_reboot_state()
    {
        using var h = new AgentHarness();
        await h.EnrollWithTokenAsync();
        h.RebootDetector.Status = new Core.Abstractions.RebootStatus(true, ["Windows Update (RebootRequired)"]);
        var job = AgentHarness.SimpleJob(JobType.InventoryRefresh);

        await h.DeliverAsync(job);
        await h.RunJobsAndFlushAsync();

        var inventory = Assert.Single(h.Server.InventoryReports);
        Assert.Equal("TEST-PC", inventory.Hostname);
        Assert.True(inventory.RebootPending);
        Assert.Equal(UpdateSourceType.WindowsUpdate, inventory.UpdateSource!.Type);
        Assert.Equal(JobStatus.Completed, h.Server.StatusesFor(job.JobId)[^1].Status);
    }

    [Theory]
    [InlineData(UpdateCategory.ServicingStack, UpdateCategory.Cumulative)]
    [InlineData(UpdateCategory.Cumulative, UpdateCategory.Security)]
    [InlineData(UpdateCategory.Security, UpdateCategory.Definition)]
    [InlineData(UpdateCategory.Driver, UpdateCategory.Feature)]
    public void Install_priority_orders_servicing_stack_first_and_feature_updates_last(UpdateCategory earlier, UpdateCategory later) =>
        Assert.True(Core.Jobs.InstallUpdatesHandler.Priority(earlier) < Core.Jobs.InstallUpdatesHandler.Priority(later));

    private static class UpdateOperationResultCodes
    {
        public const int Failed = Core.Abstractions.UpdateOperationResult.Failed;
    }
}
