using System.Globalization;
using EasyPatch.Agent.Core.Abstractions;
using EasyPatch.Agent.Core.Enrollment;
using EasyPatch.Agent.Core.State;
using EasyPatch.Contracts;
using EasyPatch.Contracts.Agent;
using Microsoft.Extensions.Logging;

namespace EasyPatch.Agent.Core.Jobs;

/// <summary>
/// Restart jobs. A restart is only ever started for an administrator's restart job (manual or from a restart
/// schedule). The job waits for the signed-in users according to its mode without blocking other work, and is
/// completed only when the boot time shows that the computer actually restarted.
/// </summary>
/// <remarks>
/// <list type="bullet">
/// <item>Nobody signed in: restart at once, whatever the mode.</item>
/// <item>Immediate: restart at once.</item>
/// <item>Countdown: the tray counts down; users can only restart sooner.</item>
/// <item>PromptWithDeadline: users may restart now or postpone (never past the deadline); at the deadline a final
/// countdown starts.</item>
/// <item>PromptNoDeadline: users decide; the job gives up after <see cref="MaxWait"/>.</item>
/// </list>
/// When users are signed in but no tray is connected, countdowns and deadlines use Windows' own restart warning
/// (a grace period) so nobody loses work without notice; prompts without a deadline keep waiting for a tray.
/// </remarks>
public sealed class RestartHandler
{
    /// <summary>Windows must restart within this time (after the grace period) or the job fails.</summary>
    public static readonly TimeSpan RestartTimeout = TimeSpan.FromMinutes(30);

    /// <summary>The longest a restart job waits for users.</summary>
    public static readonly TimeSpan MaxWait = TimeSpan.FromMinutes(RestartPayload.MaxDeadlineMinutes);

    /// <summary>Progress is re-reported at this interval while waiting, so the server does not time the job out
    /// (its running-job timeout is at least one hour).</summary>
    public static readonly TimeSpan HeartbeatInterval = TimeSpan.FromMinutes(30);

    private const string WindowsMessage = "Your IT team is restarting this computer. Please save your work.";

    private readonly AgentPlatform _platform;
    private readonly AgentStateStore _state;
    private readonly JobReporter _reporter;
    private readonly AgentRuntimeOptions _options;
    private readonly TimeProvider _time;
    private readonly ILogger _logger;
    private string? _publishedPrompt = "";

    public RestartHandler(AgentPlatform platform, AgentStateStore state, JobReporter reporter, AgentRuntimeOptions options, TimeProvider time,
        ILogger<RestartHandler> logger)
    {
        _platform = platform;
        _state = state;
        _reporter = reporter;
        _options = options;
        _time = time;
        _logger = logger;
    }

    /// <summary>Short description for the tray and check-ins while a restart is pending, otherwise null.</summary>
    public string? Activity => _state.Read(s => s.Jobs.Find(j => j.Job.Type == JobType.Restart && j.Restart is not null) is { } r
        ? r.RunState == JobRunState.WaitingForReboot ? "Restarting" : "Waiting to restart"
        : null);

    public async Task StartAsync(Guid jobId, CancellationToken cancellationToken)
    {
        var job = _state.Read(s => s.FindJob(jobId)?.Job);
        if (job?.Restart is not { } payload || _platform.SystemRestart is null)
        {
            return;
        }

        if (payload.Condition == RestartCondition.OnlyIfPending)
        {
            RebootStatus reboot;
            try
            {
                reboot = await _platform.RebootDetector.DetectAsync(cancellationToken);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                _logger.LogWarning(ex, "Restart job {JobId}: could not check whether a restart is pending.", jobId);
                Finish(jobId, JobStatus.Failed, "Could not check whether the computer needs a restart, so it was not restarted.", "reboot_detection_failed");
                return;
            }

            if (!reboot.Pending)
            {
                Finish(jobId, JobStatus.Completed, "No restart was needed: no restart was pending.");
                return;
            }
        }

        var now = _time.GetUtcNow();
        var progress = new RestartProgress
        {
            StartedAt = now,
            BootTimeAtStart = _platform.BootTime.GetLastBootTime(),
            LastHeartbeatAt = now,
        };
        switch (payload.Mode)
        {
            case RestartMode.Immediate:
                progress.RestartAt = now;
                break;
            case RestartMode.Countdown:
                progress.RestartAt = now.AddMinutes(payload.CountdownMinutes);
                break;
            case RestartMode.PromptWithDeadline:
                progress.Deadline = now.AddMinutes(payload.DeadlineMinutes);
                break;
        }

        _state.Update(s =>
        {
            var r = s.FindJob(jobId);
            if (r is not null)
            {
                r.RunState = JobRunState.WaitingForUser;
                r.StartedAt ??= now;
                r.Restart = progress;
            }
        });
        _logger.LogInformation("Restart job {JobId} started ({Mode}).", jobId, payload.Mode);
        _reporter.Report(jobId, JobStatus.Running, "WaitingForUser", null, Describe(payload, progress, now));
        Tick();
    }

    /// <summary>Advances every restart job: user answers, countdowns, deadlines, verification after the restart.</summary>
    public void Tick()
    {
        var jobs = _state.Read(s => s.Jobs
            .Where(j => j.Job.Type == JobType.Restart && j.Restart is not null && j.RunState is JobRunState.WaitingForUser or JobRunState.WaitingForReboot)
            .Select(j => j.Job.JobId).ToList());
        var responses = SafeTakeResponses();
        RestartPrompt? prompt = null;
        foreach (var jobId in jobs)
        {
            var current = TickJob(jobId, responses.Where(r => r.JobId == jobId).ToList());
            prompt ??= current;
        }

        Publish(prompt);
    }

    /// <summary>Handles an administrator's cancellation. Returns false when Windows is already restarting.</summary>
    public bool TryCancel(Guid jobId)
    {
        var record = _state.Read(s => s.FindJob(jobId) is { } r ? new { r.RunState, Issued = r.Restart?.IssuedAt is not null } : null);
        if (record is null)
        {
            return true;
        }

        if (record.Issued)
        {
            if (_platform.SystemRestart?.TryAbort() != true)
            {
                _logger.LogWarning("Restart job {JobId}: cancellation arrived after the restart had started.", jobId);
                return false;
            }

            _logger.LogInformation("Restart job {JobId}: the pending Windows restart was aborted.", jobId);
        }

        return true;
    }

    /// <summary>Re-publishes the prompt after jobs were added or removed (e.g. cancelled).</summary>
    public void Refresh() => Tick();

    private RestartPrompt? TickJob(Guid jobId, List<RestartPromptResponse> responses)
    {
        var snapshot = _state.Read(s => s.FindJob(jobId) is { } r ? (r.RunState, r.Job.Restart, Progress: Clone(r.Restart!)) : default);
        if (snapshot.Restart is not { } payload)
        {
            return null;
        }

        var p = snapshot.Progress;
        var now = _time.GetUtcNow();
        var boot = _platform.BootTime.GetLastBootTime();

        if (snapshot.RunState == JobRunState.WaitingForReboot)
        {
            var issuedBoot = _state.Read(s => s.FindJob(jobId)?.WaitingBootTime) ?? p.BootTimeAtStart;
            if (Restarted(issuedBoot, boot))
            {
                Finish(jobId, JobStatus.Completed, $"The computer restarted at {boot.UtcDateTime.ToString("u", CultureInfo.InvariantCulture)}.");
            }
            else if (p.IssuedAt is { } issued && now - issued > p.GracePeriod + RestartTimeout)
            {
                Finish(jobId, JobStatus.Failed,
                    $"The computer did not restart within {(int)(p.GracePeriod + RestartTimeout).TotalMinutes} minutes of the request. A user or an application may have cancelled it.",
                    "restart_not_performed");
            }

            return null;
        }

        // Someone else restarted the computer while we were waiting: the job's purpose is fulfilled.
        if (Restarted(p.BootTimeAtStart, boot))
        {
            Finish(jobId, JobStatus.Completed, $"The computer was restarted at {boot.UtcDateTime.ToString("u", CultureInfo.InvariantCulture)} before EasyPatch restarted it.");
            return null;
        }

        UserSessionInfo sessions;
        try
        {
            sessions = _platform.Users.GetSessions();
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Could not enumerate signed-in users.");
            sessions = new UserSessionInfo { SignedInUsers = 1 }; // assume someone is there rather than restart without warning
        }

        foreach (var response in responses)
        {
            if (response.RestartNow)
            {
                Issue(jobId, TimeSpan.Zero, "A signed-in user chose to restart now.");
                return null;
            }

            var options = PostponeOptions(payload, p, now);
            if (response.PostponeMinutes is { } minutes && options.Contains(minutes) && p.RestartAt is null)
            {
                p.PostponedUntil = now.AddMinutes(minutes);
                p.Postponements++;
                Save(jobId, p);
                _reporter.Report(jobId, JobStatus.Running, "Postponed", null,
                    $"A signed-in user postponed the restart until {p.PostponedUntil.Value.UtcDateTime.ToString("u", CultureInfo.InvariantCulture)}.");
                _logger.LogInformation("Restart job {JobId} postponed by a user for {Minutes} minutes.", jobId, minutes);
            }
        }

        if (sessions.SignedInUsers == 0)
        {
            Issue(jobId, TimeSpan.Zero, "No one was signed in.");
            return null;
        }

        if (payload.Mode == RestartMode.PromptWithDeadline && p.RestartAt is null && p.Deadline is { } deadline && now >= deadline)
        {
            p.RestartAt = now.AddMinutes(RestartPayload.FinalCountdownMinutes);
            Save(jobId, p);
            _reporter.Report(jobId, JobStatus.Running, "Countdown", null,
                $"The deadline was reached; the computer restarts in {RestartPayload.FinalCountdownMinutes} minutes.");
        }

        if (p.RestartAt is { } restartAt)
        {
            if (now >= restartAt)
            {
                Issue(jobId, TimeSpan.Zero,
                    payload.Mode == RestartMode.Immediate ? "Restart requested by an administrator." : "The countdown ended.");
                return null;
            }

            if (sessions.TrayConnected == 0)
            {
                // No tray can show the countdown: let Windows warn the users for the remaining time instead.
                Issue(jobId, restartAt - now, "The EasyPatch tray is not running, so the operating system warned the signed-in users.");
                return null;
            }
        }

        if (now - p.StartedAt > MaxWait)
        {
            Finish(jobId, JobStatus.Failed,
                $"No signed-in user restarted the computer within {MaxWait.TotalDays:0} days.", "restart_not_performed");
            return null;
        }

        if (p.LastHeartbeatAt is not { } beat || now - beat >= HeartbeatInterval)
        {
            p.LastHeartbeatAt = now;
            Save(jobId, p);
            _reporter.Report(jobId, JobStatus.Running, "WaitingForUser", null,
                Describe(payload, p, now) + (sessions.TrayConnected == 0 ? " The EasyPatch tray is not running for the signed-in users." : string.Empty));
        }

        return new RestartPrompt
        {
            JobId = jobId,
            Kind = p.RestartAt is not null ? RestartPromptKind.Countdown
                : p.PostponedUntil is { } until && until > now ? RestartPromptKind.Postponed
                : RestartPromptKind.Prompt,
            Deadline = p.Deadline,
            RestartAt = p.RestartAt,
            PostponedUntil = p.PostponedUntil is { } u && u > now ? u : null,
            PostponeOptions = p.RestartAt is null ? PostponeOptions(payload, p, now) : [],
        };
    }

    private static IReadOnlyList<int> PostponeOptions(RestartPayload payload, RestartProgress p, DateTimeOffset now) => payload.Mode switch
    {
        RestartMode.PromptWithDeadline => RestartPayload.PostponeOptions(p.Deadline - now),
        RestartMode.PromptNoDeadline => RestartPayload.PostponeOptions(null),
        _ => [],
    };

    private void Issue(Guid jobId, TimeSpan grace, string reason)
    {
        var now = _time.GetUtcNow();
        var boot = _platform.BootTime.GetLastBootTime();
        _state.Update(s =>
        {
            var r = s.FindJob(jobId);
            if (r?.Restart is not null)
            {
                r.RunState = JobRunState.WaitingForReboot;
                r.WaitingBootTime = boot;
                r.WaitingSince = now;
                r.Restart.IssuedAt = now;
                r.Restart.GracePeriod = grace;
            }
        });

        var when = grace > TimeSpan.Zero ? $" in {Math.Max(1, (int)Math.Round(grace.TotalMinutes))} minute(s)" : string.Empty;
        _reporter.Report(jobId, JobStatus.Running, "Restarting", null, $"{reason} Restarting the computer{when}.");
        _logger.LogWarning(AgentEventIds.RestartStarted, "Restart job {JobId}: restarting the computer{When}. {Reason}", jobId, when, reason);
        Publish(null);
        try
        {
            _platform.SystemRestart!.Restart(grace, WindowsMessage);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Restart job {JobId}: the restart was refused.", jobId);
            Finish(jobId, JobStatus.Failed, $"The operating system refused to restart: {ex.Message}", "restart_failed");
        }
    }

    private void Finish(Guid jobId, JobStatus status, string message, string? errorCode = null)
    {
        _reporter.Report(jobId, status, status == JobStatus.Completed ? "Completed" : "Failed", 100, message,
            errorCode: errorCode, errorMessage: errorCode is null ? null : message);
        _state.Update(s => s.Jobs.RemoveAll(j => j.Job.JobId == jobId));
        _logger.LogInformation("Restart job {JobId} finished: {Status}. {Message}", jobId, status, message);
    }

    private void Save(Guid jobId, RestartProgress progress) => _state.Update(s =>
    {
        var r = s.FindJob(jobId);
        if (r is not null)
        {
            r.Restart = progress;
        }
    });

    private bool Restarted(DateTimeOffset before, DateTimeOffset now) => (now - before).Duration() > _options.BootTimeTolerance;

    private IReadOnlyList<RestartPromptResponse> SafeTakeResponses()
    {
        try
        {
            return _platform.Users.TakeResponses();
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Could not read answers from the tray.");
            return [];
        }
    }

    private void Publish(RestartPrompt? prompt)
    {
        var key = prompt is null
            ? null
            : $"{prompt.JobId}|{prompt.Kind}|{prompt.Deadline:O}|{prompt.RestartAt:O}|{prompt.PostponedUntil:O}|{string.Join(',', prompt.PostponeOptions)}";
        if (key == _publishedPrompt)
        {
            return;
        }

        try
        {
            _platform.Users.SetRestartPrompt(prompt);
            _publishedPrompt = key;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Could not update the restart prompt.");
        }
    }

    private static string Describe(RestartPayload payload, RestartProgress p, DateTimeOffset now) => payload.Mode switch
    {
        RestartMode.Immediate => "Restarting now.",
        RestartMode.Countdown => $"Restarting after a {payload.CountdownMinutes}-minute countdown.",
        RestartMode.PromptWithDeadline when p.RestartAt is not null => "Deadline reached; final countdown running.",
        RestartMode.PromptWithDeadline =>
            $"Waiting for a signed-in user to restart; the computer restarts automatically at {p.Deadline!.Value.UtcDateTime.ToString("u", CultureInfo.InvariantCulture)}.",
        _ => p.PostponedUntil is { } until && until > now
            ? $"Postponed by a user until {until.UtcDateTime.ToString("u", CultureInfo.InvariantCulture)}."
            : "Waiting for a signed-in user to restart.",
    };

    private static RestartProgress Clone(RestartProgress p) => new()
    {
        StartedAt = p.StartedAt,
        BootTimeAtStart = p.BootTimeAtStart,
        Deadline = p.Deadline,
        RestartAt = p.RestartAt,
        PostponedUntil = p.PostponedUntil,
        Postponements = p.Postponements,
        IssuedAt = p.IssuedAt,
        GracePeriod = p.GracePeriod,
        LastHeartbeatAt = p.LastHeartbeatAt,
    };
}

/// <summary>Messages to signed-in users: preset message jobs and the automatic install notices.</summary>
public sealed class UserNotifier
{
    private readonly AgentPlatform _platform;
    private readonly AgentStateStore _state;
    private readonly ILogger _logger;

    public UserNotifier(AgentPlatform platform, AgentStateStore state, ILogger<UserNotifier> logger)
    {
        _platform = platform;
        _state = state;
        _logger = logger;
    }

    /// <summary>Shows a message in every connected tray. Returns how many sessions it reached.</summary>
    public int Notify(UserNotice notice)
    {
        try
        {
            return _platform.Users.Notify(notice);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Could not show a message to signed-in users.");
            return 0;
        }
    }

    /// <summary>"Updates are installing", once per install job, when install notifications are enabled.</summary>
    public void InstallStarting(Guid jobId)
    {
        var send = _state.Update(s =>
        {
            var r = s.FindJob(jobId);
            if (r is null || r.UsersNotified || !s.Config.UserExperience.InstallNotifications)
            {
                return false;
            }

            r.UsersNotified = true;
            return true;
        });
        if (send)
        {
            Notify(new UserNotice { Preset = UserMessagePreset.UpdatesInstalling });
        }
    }

    /// <summary>"Updates installed" or "Restart required" after an install that installed something.</summary>
    public void InstallFinished(int succeeded, bool rebootRequired)
    {
        if (succeeded > 0 && _state.Read(s => s.Config.UserExperience.InstallNotifications))
        {
            Notify(new UserNotice { Preset = rebootRequired ? UserMessagePreset.RestartRequired : UserMessagePreset.UpdatesInstalled });
        }
    }
}
