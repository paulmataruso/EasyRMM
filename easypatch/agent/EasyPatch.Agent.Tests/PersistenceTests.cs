using System.Net;
using EasyPatch.Agent.Core.Logging;
using EasyPatch.Agent.Core.Outbox;
using EasyPatch.Agent.Core.State;
using EasyPatch.Agent.Core.Util;
using EasyPatch.Agent.Tests.Infrastructure;
using EasyPatch.Contracts;
using EasyPatch.Contracts.Agent;
using Xunit;

namespace EasyPatch.Agent.Tests;

public sealed class PersistenceTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "easypatch-agent-tests", Guid.NewGuid().ToString("N"));

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    public void Dispose()
    {
        if (Directory.Exists(_dir))
        {
            Directory.Delete(_dir, recursive: true);
        }
    }

    // ------------------------------------------------------------------ outbox

    [Fact]
    public async Task Reports_queued_during_an_outage_are_delivered_once_after_restart()
    {
        using var h = new AgentHarness();
        await h.EnrollWithTokenAsync();
        h.AddSecurityUpdate("KB5020001");
        h.Server.NetworkDown = true;

        var scanId = await h.Runtime.RunScanAsync(ScanTrigger.Scheduled, Ct);
        await h.Runtime.SendInventoryAsync(Ct);
        Assert.False(await h.Runtime.FlushOutboxAsync(Ct));
        Assert.Equal(2, h.Runtime.Outbox.Count);

        var runtime = h.Restart();
        h.Server.NetworkDown = false;
        Assert.True(await runtime.FlushOutboxAsync(Ct));
        Assert.True(await runtime.FlushOutboxAsync(Ct));

        var scan = Assert.Single(h.Server.ScanReports);
        Assert.Equal(scanId, scan.ScanId);
        Assert.Single(h.Server.InventoryReports);
        Assert.Equal(0, runtime.Outbox.Count);
    }

    [Fact]
    public async Task Job_reports_are_delivered_in_order_after_transient_failures()
    {
        using var h = new AgentHarness();
        await h.EnrollWithTokenAsync();
        h.AddSecurityUpdate("KB5021001");
        var job = AgentHarness.InstallJob();
        await h.DeliverAsync(job);

        while (await h.Runtime.ProcessNextJobAsync(Ct))
        {
        }

        h.Server.FailNextRequests = 2;
        Assert.False(await h.Runtime.FlushOutboxAsync(Ct));
        Assert.False(await h.Runtime.FlushOutboxAsync(Ct));
        Assert.True(await h.Runtime.FlushOutboxAsync(Ct));

        var reports = h.Server.StatusesFor(job.JobId);
        Assert.Equal(reports.Select(r => r.Sequence).Order(), reports.Select(r => r.Sequence));
        Assert.Equal(JobStatus.Completed, reports[^1].Status);
    }

    [Fact]
    public async Task Undelivered_job_status_keeps_the_job_held_in_check_ins()
    {
        using var h = new AgentHarness();
        await h.EnrollWithTokenAsync();
        var job = AgentHarness.SimpleJob(JobType.UpdateScan);
        await h.DeliverAsync(job);
        while (await h.Runtime.ProcessNextJobAsync(Ct))
        {
        }

        Assert.Empty(h.Runtime.State.Read(s => s.Jobs)); // finished locally...
        h.Server.Override = (route, _) => route.Contains("/jobs/", StringComparison.Ordinal) ? h.Server.Problem(HttpStatusCode.BadGateway, null, "down") : null;
        await h.Runtime.CheckInOnceAsync(Ct);

        // ...but its final report is not delivered yet, so the server must not re-deliver the job.
        Assert.Contains(job.JobId, h.Server.CheckIns[^1].ActiveJobIds);
        Assert.Equal(1, h.Server.Jobs[job.JobId].Deliveries);

        h.Server.Override = null;
        await h.Runtime.CheckInOnceAsync(Ct);
        Assert.DoesNotContain(job.JobId, h.Server.CheckIns[^1].ActiveJobIds);
        Assert.Equal(JobStatus.Completed, h.Server.Jobs[job.JobId].Status);
    }

    [Fact]
    public async Task Permanently_rejected_report_is_dropped_so_later_reports_flow()
    {
        using var h = new AgentHarness();
        await h.EnrollWithTokenAsync();
        await h.Runtime.RunScanAsync(ScanTrigger.Scheduled, Ct);
        await h.Runtime.SendInventoryAsync(Ct);
        h.Server.Override = (route, _) => route == AgentRoutes.ScanResults
            ? h.Server.Problem(HttpStatusCode.UnprocessableEntity, AgentErrorCodes.ValidationFailed, "bad")
            : null;

        Assert.True(await h.Runtime.FlushOutboxAsync(Ct));

        Assert.Empty(h.Server.ScanReports);
        Assert.Single(h.Server.InventoryReports);
    }

    [Fact]
    public void Outbox_stays_bounded_and_never_drops_job_status()
    {
        using var outbox = new ReportOutbox(_dir, maxItems: 10);
        var jobId = Guid.NewGuid();
        for (var i = 1; i <= 5; i++)
        {
            outbox.EnqueueJobStatus(jobId, new JobStatusReport { Sequence = i, Status = JobStatus.Running });
        }

        for (var i = 0; i < 30; i++)
        {
            outbox.EnqueueScanResults(new ScanResultReport { ScanId = Guid.NewGuid(), Trigger = ScanTrigger.Scheduled, Succeeded = true });
            outbox.EnqueueInventory(new InventoryReport { Hostname = "PC", AgentVersion = "1" });
        }

        var items = outbox.Peek();
        Assert.True(items.Count <= 10, $"outbox holds {items.Count} items");
        Assert.Equal(5, items.Count(i => i.Kind == OutboxKind.JobStatus));
        Assert.Contains(items, i => i.Kind == OutboxKind.ScanResults);
        Assert.Equal(items.Select(i => i.Sequence).Order(), items.Select(i => i.Sequence));
    }

    [Fact]
    public void Outbox_sequence_continues_after_restart()
    {
        long last;
        using (var outbox = new ReportOutbox(_dir))
        {
            outbox.EnqueueInventory(new InventoryReport { Hostname = "PC", AgentVersion = "1" });
            outbox.EnqueueInventory(new InventoryReport { Hostname = "PC", AgentVersion = "1" });
            last = outbox.Peek()[^1].Sequence;
        }

        using var reopened = new ReportOutbox(_dir);
        reopened.EnqueueInventory(new InventoryReport { Hostname = "PC", AgentVersion = "1" });
        Assert.True(reopened.Peek()[^1].Sequence > last);
        Assert.Equal(3, reopened.Count);
    }

    // ------------------------------------------------------------------ state

    [Fact]
    public void State_is_persisted_atomically_and_reloaded()
    {
        var store = new AgentStateStore(_dir);
        var jobId = Guid.NewGuid();
        store.Update(s =>
        {
            s.Status = AgentEnrollmentStatus.Active;
            s.CredentialId = "c_123";
            s.Jobs.Add(new JobRecord { Job = AgentHarness.SimpleJob(JobType.UpdateScan) with { JobId = jobId }, RunState = JobRunState.Acknowledged, NextSequence = 7 });
        });

        var reloaded = new AgentStateStore(_dir).Snapshot();
        Assert.Equal(AgentEnrollmentStatus.Active, reloaded.Status);
        Assert.Equal("c_123", reloaded.CredentialId);
        var job = Assert.Single(reloaded.Jobs);
        Assert.Equal(jobId, job.Job.JobId);
        Assert.Equal(7, job.NextSequence);
        Assert.Empty(Directory.GetFiles(Path.Combine(_dir, "state"), "*.tmp"));
    }

    [Fact]
    public void Snapshot_is_a_copy()
    {
        var store = new AgentStateStore(_dir);
        var snapshot = store.Snapshot();
        snapshot.CredentialId = "c_mutated";
        Assert.Null(store.Read(s => s.CredentialId));
    }

    [Fact]
    public void Corrupt_state_is_quarantined_not_silently_overwritten()
    {
        var stateDir = Path.Combine(_dir, "state");
        Directory.CreateDirectory(stateDir);
        File.WriteAllText(Path.Combine(stateDir, "agent-state.json"), "{ this is not json");

        var store = new AgentStateStore(_dir);

        Assert.Equal(AgentEnrollmentStatus.NotEnrolled, store.Read(s => s.Status));
        Assert.Single(Directory.GetFiles(stateDir, "agent-state.json.corrupt-*"));
    }

    [Fact]
    public void Atomic_write_replaces_content_and_cleans_temporary_files()
    {
        Directory.CreateDirectory(_dir);
        var path = Path.Combine(_dir, "file.json");
        AtomicFile.WriteAllBytes(path, "one"u8);
        AtomicFile.WriteAllBytes(path, "two"u8);
        File.WriteAllText(Path.Combine(_dir, ".file.json.deadbeef.tmp"), "orphan");

        AtomicFile.CleanupTemporaryFiles(_dir);

        Assert.Equal("two"u8.ToArray(), AtomicFile.TryReadAllBytes(path));
        Assert.Null(AtomicFile.TryReadAllBytes(Path.Combine(_dir, "missing.json")));
        Assert.Equal(new[] { "file.json" }, Directory.GetFiles(_dir).Select(f => Path.GetFileName(f)));
    }

    // ------------------------------------------------------------------ backoff

    [Fact]
    public void Backoff_grows_exponentially_with_full_jitter_up_to_the_cap()
    {
        var backoff = new ExponentialBackoff(TimeSpan.FromSeconds(5), TimeSpan.FromMinutes(15), new Random(42));
        var ceilings = new List<TimeSpan>();
        for (var i = 0; i < 12; i++)
        {
            ceilings.Add(backoff.CurrentCeiling);
            var delay = backoff.NextDelay();
            Assert.InRange(delay, TimeSpan.FromSeconds(1), ceilings[^1] < TimeSpan.FromSeconds(1) ? TimeSpan.FromSeconds(1) : ceilings[^1]);
        }

        Assert.Equal(TimeSpan.FromSeconds(5), ceilings[0]);
        Assert.Equal(TimeSpan.FromSeconds(10), ceilings[1]);
        Assert.Equal(TimeSpan.FromSeconds(40), ceilings[3]);
        Assert.Equal(TimeSpan.FromMinutes(15), ceilings[^1]);

        backoff.Reset();
        Assert.Equal(TimeSpan.FromSeconds(5), backoff.CurrentCeiling);
    }

    [Fact]
    public void Backoff_honours_server_retry_after_within_the_cap()
    {
        var backoff = new ExponentialBackoff(TimeSpan.FromSeconds(5), TimeSpan.FromMinutes(15), new Random(1));
        Assert.True(backoff.NextDelay(TimeSpan.FromMinutes(2)) >= TimeSpan.FromMinutes(2));
        Assert.Equal(TimeSpan.FromMinutes(15), backoff.NextDelay(TimeSpan.FromHours(5)));
    }

    [Fact]
    public void Jitter_stays_within_the_requested_band()
    {
        var random = new Random(7);
        for (var i = 0; i < 1000; i++)
        {
            Assert.InRange(Jitter.Apply(TimeSpan.FromSeconds(60), 10, random), TimeSpan.FromSeconds(54), TimeSpan.FromSeconds(66));
            Assert.InRange(Jitter.Between(TimeSpan.FromSeconds(30), TimeSpan.FromMinutes(3), random), TimeSpan.FromSeconds(30), TimeSpan.FromMinutes(3));
        }
    }

    // ------------------------------------------------------------------ logging

    [Theory]
    [InlineData("enrolling with token=ept_abcdefghijklmnop", "ept_abcdefghijklmnop")]
    [InlineData("EnrollmentToken: ept_SECRETSECRET123", "SECRETSECRET123")]
    [InlineData("value ept_0123456789abcdefXYZ in text", "0123456789abcdefXYZ")]
    [InlineData("-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49\n-----END PRIVATE KEY-----", "MIGHAgEAMBMGByqGSM49")]
    [InlineData("signature=MEUCIQDabc+/=", "MEUCIQDabc")]
    public void Log_redactor_removes_secrets(string message, string secret)
    {
        var redacted = LogRedactor.Redact(message);
        Assert.DoesNotContain(secret, redacted, StringComparison.Ordinal);
    }

    [Fact]
    public void Log_redactor_keeps_ordinary_messages()
    {
        const string message = "Job 3f2a installed KB5044284 (restart required).";
        Assert.Equal(message, LogRedactor.Redact(message));
    }

    [Fact]
    public void Rolling_file_logger_writes_redacted_lines_and_rotates()
    {
        var logDir = Path.Combine(_dir, "logs");
        using (var provider = new RollingFileLoggerProvider(new RollingFileLoggerOptions { Directory = logDir, MaxFileBytes = 2048, RetainedFiles = 2 }))
        {
            var logger = provider.CreateLogger("EasyPatch.Test");
            for (var i = 0; i < 200; i++)
            {
                Microsoft.Extensions.Logging.LoggerExtensions.LogInformation(logger, "line {Index} token=ept_shouldnotappear123", i);
            }
        }

        var files = Directory.GetFiles(logDir).Select(f => Path.GetFileName(f)).Order().ToList();
        Assert.Contains("agent.log", files);
        Assert.Contains("agent.1.log", files);
        Assert.DoesNotContain("agent.3.log", files);
        var text = string.Concat(Directory.GetFiles(logDir).Select(File.ReadAllText));
        Assert.Contains("line 199", text, StringComparison.Ordinal);
        Assert.DoesNotContain("shouldnotappear", text, StringComparison.Ordinal);
    }
}
