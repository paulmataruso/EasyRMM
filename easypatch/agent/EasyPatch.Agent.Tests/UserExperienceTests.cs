using EasyPatch.Agent.Core.Abstractions;
using EasyPatch.Agent.Core.Runtime;
using EasyPatch.Agent.Core.State;
using EasyPatch.Agent.Tests.Infrastructure;
using EasyPatch.Contracts;
using EasyPatch.Contracts.Agent;
using Xunit;

namespace EasyPatch.Agent.Tests;

/// <summary>Restart jobs, messages to signed-in users and what the agent tells the tray and the server about them.</summary>
public sealed class UserExperienceTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private static JobStatusReport Last(AgentHarness h, Guid jobId) => h.Server.StatusesFor(jobId)[^1];

    private static JobRunState? RunState(AgentHarness h, Guid jobId) => h.Runtime.State.Read(s => s.FindJob(jobId)?.RunState);

    [Fact]
    public async Task With_nobody_signed_in_the_restart_happens_at_once_and_completes_only_after_the_boot_time_changes()
    {
        using var h = new AgentHarness();
        await h.EnrollWithTokenAsync();
        h.Users.SignedInUsers = 0;
        var job = AgentHarness.RestartJob(RestartMode.PromptWithDeadline);

        await h.DeliverAsync(job);
        await h.RunJobsAndFlushAsync();

        Assert.Equal([TimeSpan.Zero], h.SystemRestart.Requests);
        Assert.Equal(JobRunState.WaitingForReboot, RunState(h, job.JobId));
        var restarting = Last(h, job.JobId);
        Assert.Equal(JobStatus.Running, restarting.Status); // never "completed" before Windows actually restarted
        Assert.Equal("Restarting", restarting.Phase);
        Assert.Contains("No one was signed in", restarting.Message, StringComparison.Ordinal);
        Assert.Equal("Restarting", h.Runtime.CurrentActivity);

        h.Reboot();
        await h.RunJobsAndFlushAsync();

        Assert.Equal(JobStatus.Completed, Last(h, job.JobId).Status);
        Assert.Empty(h.Runtime.State.Read(s => s.Jobs));
        Assert.Single(h.SystemRestart.Requests); // not restarted again after the reboot
    }

    [Fact]
    public async Task A_countdown_cannot_be_postponed_and_restarts_when_it_ends()
    {
        using var h = new AgentHarness();
        await h.EnrollWithTokenAsync();
        var job = AgentHarness.RestartJob(RestartMode.Countdown, countdownMinutes: 5);

        await h.DeliverAsync(job);
        await h.RunJobsAndFlushAsync();

        var prompt = h.Users.CurrentPrompt!;
        Assert.Equal(job.JobId, prompt.JobId);
        Assert.Equal(RestartPromptKind.Countdown, prompt.Kind);
        Assert.Equal(h.Time.GetUtcNow().AddMinutes(5), prompt.RestartAt);
        Assert.Empty(prompt.PostponeOptions);

        h.Users.Answer(job.JobId, restartNow: false, postponeMinutes: 60);
        await h.TickAsync(TimeSpan.FromMinutes(4));
        Assert.Empty(h.SystemRestart.Requests);
        Assert.Equal(0, h.Runtime.State.Read(s => s.FindJob(job.JobId)!.Restart!.Postponements));

        await h.TickAsync(TimeSpan.FromMinutes(1));
        Assert.Equal([TimeSpan.Zero], h.SystemRestart.Requests);
        Assert.Null(h.Users.CurrentPrompt); // the prompt is removed once Windows is restarting
    }

    [Fact]
    public async Task Users_can_postpone_within_the_deadline_and_a_final_countdown_starts_at_the_deadline()
    {
        using var h = new AgentHarness();
        await h.EnrollWithTokenAsync();
        var job = AgentHarness.RestartJob(RestartMode.PromptWithDeadline, deadlineMinutes: 120);
        var start = h.Time.GetUtcNow();

        await h.DeliverAsync(job);
        await h.RunJobsAndFlushAsync();

        var prompt = h.Users.CurrentPrompt!;
        Assert.Equal(RestartPromptKind.Prompt, prompt.Kind);
        Assert.Equal(start.AddMinutes(120), prompt.Deadline);
        Assert.Equal([60], prompt.PostponeOptions); // 4 hours and 1 day would pass the deadline
        Assert.Equal(JobRunState.WaitingForUser, RunState(h, job.JobId));
        Assert.Equal("Waiting to restart", h.Runtime.CurrentActivity);

        // A postponement that was not offered is ignored; an offered one is accepted.
        h.Users.Answer(job.JobId, restartNow: false, postponeMinutes: 240);
        await h.TickAsync();
        Assert.Equal(RestartPromptKind.Prompt, h.Users.CurrentPrompt!.Kind);
        h.Users.Answer(job.JobId, restartNow: false, postponeMinutes: 60);
        await h.TickAsync();
        Assert.Equal(RestartPromptKind.Postponed, h.Users.CurrentPrompt!.Kind);
        Assert.Equal(start.AddMinutes(60), h.Users.CurrentPrompt.PostponedUntil);
        Assert.Contains(h.Server.StatusesFor(job.JobId), r => r.Phase == "Postponed");

        // An answer for another job is never applied to this one.
        h.Users.Answer(Guid.NewGuid(), restartNow: true);
        await h.TickAsync(TimeSpan.FromMinutes(61));
        Assert.Empty(h.SystemRestart.Requests);
        Assert.Equal(RestartPromptKind.Prompt, h.Users.CurrentPrompt!.Kind); // the postponement ended

        await h.TickAsync(TimeSpan.FromMinutes(60));
        var countdown = h.Users.CurrentPrompt!;
        Assert.Equal(RestartPromptKind.Countdown, countdown.Kind);
        Assert.Equal(h.Time.GetUtcNow().AddMinutes(RestartPayload.FinalCountdownMinutes), countdown.RestartAt);
        Assert.Empty(countdown.PostponeOptions);
        Assert.Empty(h.SystemRestart.Requests);

        await h.TickAsync(TimeSpan.FromMinutes(RestartPayload.FinalCountdownMinutes));
        Assert.Equal([TimeSpan.Zero], h.SystemRestart.Requests);
        Assert.Contains("countdown ended", Last(h, job.JobId).Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Restart_now_from_the_tray_restarts_at_once()
    {
        using var h = new AgentHarness();
        await h.EnrollWithTokenAsync();
        var job = AgentHarness.RestartJob(RestartMode.PromptNoDeadline);
        await h.DeliverAsync(job);
        await h.RunJobsAndFlushAsync();
        Assert.Equal([60, 240, 1440], h.Users.CurrentPrompt!.PostponeOptions);

        h.Users.Answer(job.JobId, restartNow: true);
        await h.TickAsync();

        Assert.Equal([TimeSpan.Zero], h.SystemRestart.Requests);
        Assert.Contains("chose to restart now", Last(h, job.JobId).Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Without_a_tray_windows_warns_the_users_for_the_rest_of_the_countdown()
    {
        using var h = new AgentHarness();
        await h.EnrollWithTokenAsync();
        h.Users.TrayConnected = 0;
        var job = AgentHarness.RestartJob(RestartMode.Countdown, countdownMinutes: 10);

        await h.DeliverAsync(job);
        await h.RunJobsAndFlushAsync();

        Assert.Equal([TimeSpan.FromMinutes(10)], h.SystemRestart.Requests);
        Assert.Contains("the operating system warned the signed-in users", Last(h, job.JobId).Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_prompt_without_a_deadline_never_restarts_on_its_own_and_gives_up_after_seven_days()
    {
        using var h = new AgentHarness();
        await h.EnrollWithTokenAsync();
        h.Users.TrayConnected = 0; // no tray: a prompt without a deadline keeps waiting rather than restart
        var job = AgentHarness.RestartJob(RestartMode.PromptNoDeadline);
        await h.DeliverAsync(job);
        await h.RunJobsAndFlushAsync();
        var reports = h.Server.StatusesFor(job.JobId).Count;

        await h.TickAsync(TimeSpan.FromHours(2));
        Assert.True(h.Server.StatusesFor(job.JobId).Count > reports, "a heartbeat keeps the server from timing the job out");
        Assert.Contains("tray is not running", Last(h, job.JobId).Message, StringComparison.Ordinal);

        await h.TickAsync(TimeSpan.FromDays(7));
        Assert.Empty(h.SystemRestart.Requests);
        var failed = Last(h, job.JobId);
        Assert.Equal(JobStatus.Failed, failed.Status);
        Assert.Equal("restart_not_performed", failed.ErrorCode);
        Assert.Empty(h.Runtime.State.Read(s => s.Jobs));
    }

    [Fact]
    public async Task Only_if_pending_does_nothing_when_windows_does_not_need_a_restart()
    {
        using var h = new AgentHarness();
        await h.EnrollWithTokenAsync();
        var job = AgentHarness.RestartJob(RestartMode.Immediate, condition: RestartCondition.OnlyIfPending);

        await h.DeliverAsync(job);
        await h.RunJobsAndFlushAsync();

        Assert.Empty(h.SystemRestart.Requests);
        var final = Last(h, job.JobId);
        Assert.Equal(JobStatus.Completed, final.Status);
        Assert.Contains("No restart was needed", final.Message, StringComparison.Ordinal);

        h.RebootDetector.Status = new RebootStatus(true, ["Windows Update (RebootRequired)"]);
        var second = AgentHarness.RestartJob(RestartMode.Immediate, condition: RestartCondition.OnlyIfPending);
        await h.DeliverAsync(second);
        await h.RunJobsAndFlushAsync();
        Assert.Equal([TimeSpan.Zero], h.SystemRestart.Requests);
    }

    [Fact]
    public async Task A_restart_windows_did_not_perform_fails_after_the_timeout()
    {
        using var h = new AgentHarness();
        await h.EnrollWithTokenAsync();
        var job = AgentHarness.RestartJob(RestartMode.Immediate);
        await h.DeliverAsync(job);
        await h.RunJobsAndFlushAsync();
        Assert.Single(h.SystemRestart.Requests);

        await h.TickAsync(TimeSpan.FromMinutes(29));
        Assert.Equal(JobStatus.Running, Last(h, job.JobId).Status);
        await h.TickAsync(TimeSpan.FromMinutes(2));

        var failed = Last(h, job.JobId);
        Assert.Equal(JobStatus.Failed, failed.Status);
        Assert.Equal("restart_not_performed", failed.ErrorCode);
        Assert.Single(h.SystemRestart.Requests); // never retried on its own
    }

    [Fact]
    public async Task Windows_refusing_the_restart_fails_the_job()
    {
        using var h = new AgentHarness();
        await h.EnrollWithTokenAsync();
        h.SystemRestart.Failure = new InvalidOperationException("A required privilege is not held by the client.");
        var job = AgentHarness.RestartJob(RestartMode.Immediate);

        await h.DeliverAsync(job);
        await h.RunJobsAndFlushAsync();

        var failed = Last(h, job.JobId);
        Assert.Equal(JobStatus.Failed, failed.Status);
        Assert.Equal("restart_failed", failed.ErrorCode);
        Assert.Contains("privilege", failed.ErrorMessage, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_restart_someone_else_performed_while_waiting_completes_the_job()
    {
        using var h = new AgentHarness();
        await h.EnrollWithTokenAsync();
        var job = AgentHarness.RestartJob(RestartMode.PromptNoDeadline);
        await h.DeliverAsync(job);
        await h.RunJobsAndFlushAsync();

        h.Reboot();
        await h.RunJobsAndFlushAsync();

        Assert.Empty(h.SystemRestart.Requests);
        var final = Last(h, job.JobId);
        Assert.Equal(JobStatus.Completed, final.Status);
        Assert.Contains("before EasyPatch restarted it", final.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_waiting_restart_survives_a_service_restart_and_the_prompt_is_shown_again()
    {
        using var h = new AgentHarness();
        await h.EnrollWithTokenAsync();
        var job = AgentHarness.RestartJob(RestartMode.PromptWithDeadline, deadlineMinutes: 600);
        await h.DeliverAsync(job);
        await h.RunJobsAndFlushAsync();
        var deadline = h.Users.CurrentPrompt!.Deadline;

        h.Restart();
        h.Users.Prompts.Clear();
        await h.RunJobsAndFlushAsync();

        Assert.Equal(job.JobId, h.Users.CurrentPrompt!.JobId);
        Assert.Equal(deadline, h.Users.CurrentPrompt.Deadline); // the deadline does not move
        Assert.Equal(JobRunState.WaitingForUser, RunState(h, job.JobId));
        Assert.Empty(h.SystemRestart.Requests);
    }

    [Fact]
    public async Task Cancelling_a_waiting_restart_removes_the_prompt_and_aborts_a_windows_restart_in_progress()
    {
        using var h = new AgentHarness();
        await h.EnrollWithTokenAsync();
        var waiting = AgentHarness.RestartJob(RestartMode.PromptNoDeadline);
        await h.DeliverAsync(waiting);
        await h.RunJobsAndFlushAsync();
        Assert.NotNull(h.Users.CurrentPrompt);

        h.Server.CancelJob(waiting.JobId);
        await h.Runtime.CheckInOnceAsync(Ct);
        await h.RunJobsAndFlushAsync();

        Assert.Equal(JobStatus.Cancelled, Last(h, waiting.JobId).Status);
        Assert.Null(h.Users.CurrentPrompt);
        Assert.Equal(0, h.SystemRestart.Aborts);
        Assert.Empty(h.Runtime.State.Read(s => s.Jobs));

        // Without a tray Windows' own grace period runs; cancelling aborts it.
        h.Users.TrayConnected = 0;
        var issued = AgentHarness.RestartJob(RestartMode.Countdown, countdownMinutes: 15);
        await h.DeliverAsync(issued);
        await h.RunJobsAndFlushAsync();
        Assert.Equal([TimeSpan.FromMinutes(15)], h.SystemRestart.Requests);

        h.Server.CancelJob(issued.JobId);
        await h.Runtime.CheckInOnceAsync(Ct);
        await h.RunJobsAndFlushAsync();
        Assert.Equal(1, h.SystemRestart.Aborts);
        Assert.Equal(JobStatus.Cancelled, Last(h, issued.JobId).Status);
    }

    [Fact]
    public async Task Cancelling_after_windows_started_restarting_is_refused()
    {
        using var h = new AgentHarness();
        await h.EnrollWithTokenAsync();
        h.SystemRestart.AbortSucceeds = false;
        var job = AgentHarness.RestartJob(RestartMode.Immediate);
        await h.DeliverAsync(job);
        await h.RunJobsAndFlushAsync();

        h.Server.CancelJob(job.JobId);
        await h.Runtime.CheckInOnceAsync(Ct);
        await h.RunJobsAndFlushAsync();

        Assert.NotEqual(JobStatus.Cancelled, Last(h, job.JobId).Status);
        Assert.Equal(JobRunState.WaitingForReboot, RunState(h, job.JobId));
    }

    [Fact]
    public async Task Messages_are_shown_in_every_tray_and_fail_when_nobody_can_see_them()
    {
        using var h = new AgentHarness();
        await h.EnrollWithTokenAsync();
        h.Users.TrayConnected = 2;
        var at = h.Time.GetUtcNow().AddHours(2);
        var message = AgentHarness.MessageJob(UserMessagePreset.RestartScheduled, at);

        await h.DeliverAsync(message); // shown during the check-in, not after other jobs
        await h.Runtime.FlushOutboxAsync(Ct);

        var notice = Assert.Single(h.Users.Notices);
        Assert.Equal(UserMessagePreset.RestartScheduled, notice.Preset);
        Assert.Equal(at, notice.ScheduledAt);
        var delivered = Last(h, message.JobId);
        Assert.Equal(JobStatus.Completed, delivered.Status);
        Assert.Contains("2 signed-in session(s)", delivered.Message, StringComparison.Ordinal);

        h.Users.TrayConnected = 0;
        var unseen = AgentHarness.MessageJob(UserMessagePreset.SaveYourWork);
        await h.DeliverAsync(unseen);
        await h.Runtime.FlushOutboxAsync(Ct);
        var failed = Last(h, unseen.JobId);
        Assert.Equal(JobStatus.Failed, failed.Status);
        Assert.Equal("no_recipients", failed.ErrorCode);
        Assert.Contains("tray was not running", failed.ErrorMessage, StringComparison.Ordinal);

        h.Users.SignedInUsers = 0;
        var nobody = AgentHarness.MessageJob(UserMessagePreset.SaveYourWork);
        await h.DeliverAsync(nobody);
        await h.Runtime.FlushOutboxAsync(Ct);
        Assert.Contains("No one was signed in", Last(h, nobody.JobId).ErrorMessage, StringComparison.Ordinal);
        Assert.Empty(h.Runtime.State.Read(s => s.Jobs));
    }

    [Fact]
    public async Task Install_notices_follow_the_policy()
    {
        using var h = new AgentHarness();
        await h.EnrollWithTokenAsync();
        h.AddCumulativeUpdate("KB5009001");
        h.AddSecurityUpdate("KB5009002");

        await h.DeliverAsync(AgentHarness.InstallJob());
        await h.RunJobsAndFlushAsync();
        Assert.Equal([UserMessagePreset.UpdatesInstalling, UserMessagePreset.RestartRequired], h.Users.Notices.Select(n => n.Preset));

        h.Users.Notices.Clear();
        h.Server.Config = new AgentConfig { UserExperience = new UserExperienceConfig { InstallNotifications = false } };
        h.AddSecurityUpdate("KB5009003");
        await h.DeliverAsync(AgentHarness.InstallJob());
        await h.RunJobsAndFlushAsync();
        Assert.Empty(h.Users.Notices);
    }

    [Fact]
    public async Task Check_ins_report_capabilities_and_sessions_and_the_tray_shows_last_contact()
    {
        using var h = new AgentHarness();
        await h.EnrollWithTokenAsync();
        h.Users.SignedInUsers = 3;
        h.Users.TrayConnected = 2;
        h.Server.Config = new AgentConfig { UserExperience = new UserExperienceConfig { TrayIcon = false } };

        await h.Runtime.CheckInOnceAsync(Ct);

        var checkIn = h.Server.CheckIns[^1];
        // Self-update also needs a release key built in (AgentUpdateTests); this harness has none, no winget service and no update remover.
        Assert.Equal(AgentCapabilities.All.Where(c => c is not AgentCapabilities.SelfUpdate and not AgentCapabilities.ApplicationUpdates
                and not AgentCapabilities.UninstallUpdates).Order(StringComparer.Ordinal),
            checkIn.Capabilities.Order(StringComparer.Ordinal));
        Assert.Equal(3, checkIn.Sessions!.SignedInUsers);
        Assert.Equal(2, checkIn.Sessions.TrayConnected);
        var status = h.Users.Status!;
        Assert.Equal(h.Time.GetUtcNow(), status.LastContactAt);
        Assert.False(status.ShowIcon);
        Assert.Equal("Idle", status.Activity);
    }

    [Fact]
    public async Task Users_can_ask_for_a_check_in_but_not_more_than_every_30_seconds()
    {
        using var h = new AgentHarness();
        Assert.False(h.Runtime.HandleUserRequest(UserRequestKind.CheckIn, 2).Accepted); // not enrolled
        await h.EnrollWithTokenAsync();

        Assert.True(h.Runtime.HandleUserRequest(UserRequestKind.CheckIn, 2).Accepted);
        Assert.True(h.Runtime.CheckInRequested);
        Assert.True(h.Users.Status!.CheckInRequested);
        Assert.True(h.Runtime.HandleUserRequest(UserRequestKind.CheckIn, 3).Accepted); // already on its way

        await h.Runtime.CheckInOnceAsync(Ct);
        Assert.False(h.Runtime.CheckInRequested);
        Assert.False(h.Users.Status!.CheckInRequested);
        Assert.Equal(TrayConnection.Connected, h.Users.Status.Connection);
        Assert.Equal("easypatch.test", h.Users.Status.ServerHost);

        var tooSoon = h.Runtime.HandleUserRequest(UserRequestKind.CheckIn, 2);
        Assert.False(tooSoon.Accepted);
        Assert.Contains("30 seconds", tooSoon.Message, StringComparison.Ordinal);
        Assert.False(h.Runtime.CheckInRequested);

        h.Time.Advance(AgentRuntime.UserCheckInInterval);
        Assert.True(h.Runtime.HandleUserRequest(UserRequestKind.CheckIn, 2).Accepted);
    }

    [Fact]
    public async Task Users_can_check_for_updates_which_scans_without_installing_and_is_rate_limited()
    {
        using var h = new AgentHarness();
        await h.EnrollWithTokenAsync();
        var update = h.AddSecurityUpdate("KB5009001");

        Assert.Null(await h.Runtime.RunRequestedUpdateCheckAsync(Ct)); // nothing requested
        Assert.True(h.Runtime.HandleUserRequest(UserRequestKind.CheckForUpdates, 2).Accepted);
        Assert.True(h.Users.Status!.UpdateCheckRequested);
        Assert.True(h.Runtime.HandleUserRequest(UserRequestKind.CheckForUpdates, 4).Accepted); // already waiting

        var scanId = await h.Runtime.RunRequestedUpdateCheckAsync(Ct);
        Assert.NotNull(scanId);
        Assert.Null(await h.Runtime.RunRequestedUpdateCheckAsync(Ct)); // ran once
        var status = h.Users.Status!;
        Assert.False(status.UpdateCheckRequested);
        Assert.Equal(1, status.UpdatesAvailable);
        Assert.Equal(h.Time.GetUtcNow(), status.LastScanAt);
        Assert.Null(status.LastScanError);
        Assert.Equal("Idle", status.Activity);
        Assert.False(update.Installed);
        Assert.DoesNotContain(h.WindowsUpdate.Operations, o => o.StartsWith("install", StringComparison.Ordinal) || o.StartsWith("download", StringComparison.Ordinal));
        Assert.True(await h.Runtime.FlushOutboxAsync(Ct));
        Assert.Equal(ScanTrigger.User, Assert.Single(h.Server.ScanReports, r => r.ScanId == scanId).Trigger);

        var tooSoon = h.Runtime.HandleUserRequest(UserRequestKind.CheckForUpdates, 2);
        Assert.False(tooSoon.Accepted);
        Assert.Contains("5 minutes", tooSoon.Message, StringComparison.Ordinal);

        // A failed check is shown with its reason; the previous count stays.
        h.Time.Advance(AgentRuntime.UserUpdateCheckInterval);
        h.WindowsUpdate.ScanException = new InvalidOperationException("The service is not available.") { HResult = unchecked((int)0x8024402C) };
        Assert.True(h.Runtime.HandleUserRequest(UserRequestKind.CheckForUpdates, 2).Accepted);
        await h.Runtime.RunRequestedUpdateCheckAsync(Ct);
        status = h.Users.Status!;
        Assert.NotNull(status.LastScanError);
        Assert.Equal(1, status.UpdatesAvailable);
        Assert.False(status.UpdateCheckRequested);
    }

    [Fact]
    public async Task The_tray_status_shows_the_last_installation()
    {
        using var h = new AgentHarness();
        await h.EnrollWithTokenAsync();
        h.AddSecurityUpdate("KB5009002");
        h.AddSecurityUpdate("KB5009003");
        await h.DeliverAsync(AgentHarness.InstallJob());
        await h.RunJobsAndFlushAsync();
        await h.Runtime.CheckInOnceAsync(Ct);

        var status = h.Users.Status!;
        Assert.Equal(2, status.LastInstallCount);
        Assert.Equal(h.Time.GetUtcNow(), status.LastInstallAt);
        Assert.Equal(0, status.UpdatesAvailable); // the verification scan after installing
        Assert.Equal(h.Options.AgentVersion, status.AgentVersion);
    }

    [Fact]
    public async Task Invalid_restart_jobs_are_rejected_without_restarting()
    {
        using var h = new AgentHarness();
        await h.EnrollWithTokenAsync();
        var job = AgentHarness.RestartJob(RestartMode.Countdown, countdownMinutes: 0);

        h.Server.EnqueueJob(job);
        await h.Runtime.CheckInOnceAsync(Ct);
        await h.RunJobsAndFlushAsync();

        Assert.DoesNotContain(job.JobId, h.Server.Acks);
        Assert.Equal(JobStatus.Failed, Last(h, job.JobId).Status);
        Assert.Empty(h.SystemRestart.Requests);
    }
}
