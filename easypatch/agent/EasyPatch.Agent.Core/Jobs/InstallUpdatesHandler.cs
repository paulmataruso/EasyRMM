using EasyPatch.Agent.Core.Abstractions;
using EasyPatch.Agent.Core.Scanning;
using EasyPatch.Agent.Core.State;
using EasyPatch.Contracts;
using EasyPatch.Contracts.Agent;
using EasyPatch.Contracts.Updates;
using Microsoft.Extensions.Logging;

namespace EasyPatch.Agent.Core.Jobs;

public enum JobOutcome
{
    /// <summary>A final status was reported; the job can be forgotten.</summary>
    Finished,

    /// <summary>Parked until the computer restarts.</summary>
    WaitingForReboot,
}

/// <summary>
/// Executes InstallUpdates jobs with the platform's update service (the Windows Update Agent; apt or dnf on Linux, which
/// install the whole set in one transaction). Idempotent: every run starts with a fresh scan, so re-running after a
/// crash, service restart or reboot never reinstalls what is already installed.
/// </summary>
public sealed class InstallUpdatesHandler
{
    /// <summary>Skip reasons worth showing to administrators for "install all" jobs (policy filtering is not noise-free otherwise).</summary>
    private static readonly HashSet<string> ReportedSkipReasons = new(StringComparer.Ordinal)
    {
        SkipReasons.Excluded,
        SkipReasons.RequiresUserInput,
        SkipReasons.EulaNotAccepted,
    };

    /// <summary>Progress percentages within one update are sent to the server at most this often.</summary>
    internal static readonly TimeSpan ProgressReportInterval = TimeSpan.FromSeconds(10);

    private readonly AgentPlatform _platform;
    private readonly AgentStateStore _state;
    private readonly JobReporter _reporter;
    private readonly ScanService _scans;
    private readonly UserNotifier _notifier;
    private readonly TimeProvider _time;
    private readonly ILogger _logger;

    public InstallUpdatesHandler(
        AgentPlatform platform,
        AgentStateStore state,
        JobReporter reporter,
        ScanService scans,
        UserNotifier notifier,
        TimeProvider time,
        ILogger<InstallUpdatesHandler> logger)
    {
        _platform = platform;
        _state = state;
        _reporter = reporter;
        _scans = scans;
        _notifier = notifier;
        _time = time;
        _logger = logger;
    }

    /// <summary>Current human-readable activity (e.g. "Installing KB5044284").</summary>
    public string? Activity { get; private set; }

    public async Task<JobOutcome> ExecuteAsync(JobRecord record, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(record);
        var job = record.Job;
        if (job.Type == JobType.DownloadUpdates)
        {
            return await DownloadOnlyAsync(record, cancellationToken);
        }

        var jobId = job.JobId;
        var payload = job.Install ?? throw new InvalidOperationException("The install job has no payload.");
        var previous = record.Items.ToDictionary(i => i.UpdateGuid);
        var wu = _platform.Updates;

        try
        {
            if (record.WaitingBootTime is not null)
            {
                _logger.LogInformation("Resuming job {JobId} after the computer restarted.", jobId);
                _state.Update(s =>
                {
                    var r = s.FindJob(jobId);
                    if (r is not null)
                    {
                        r.WaitingBootTime = null;
                        r.WaitingSince = null;
                    }
                });
            }

            var anyStarted = previous.Values.Any(i => i.Status is JobItemStatus.Succeeded or JobItemStatus.Failed or JobItemStatus.Installing);
            if (payload.NotAfter is { } notAfter && _time.GetUtcNow() > notAfter && !anyStarted)
            {
                _logger.LogWarning("Job {JobId}: the maintenance window closed before installation started.", jobId);
                _reporter.Report(jobId, JobStatus.Cancelled, "NotStarted", 100,
                    "The maintenance window closed before installation could start.",
                    errorCode: "maintenance_window_closed",
                    errorMessage: "The maintenance window closed before installation could start.");
                return JobOutcome.Finished;
            }

            Activity = "Scanning for updates";
            _reporter.Report(jobId, JobStatus.Running, "Scanning", 0, $"Checking {wu.Name} for applicable updates.", previous.Values.ToList());

            if (await wu.IsRebootRequiredBeforeInstallationAsync(cancellationToken))
            {
                return EnterWaitingForReboot(jobId, "Windows requires a restart before updates can be installed.", previous.Values.ToList());
            }

            using var scan = await wu.ScanAsync(includeInstalled: payload.Mode == InstallMode.Selected, cancellationToken);
            var plan = BuildPlan(scan, payload, previous);
            var items = plan.Items;
            _logger.LogInformation("Job {JobId}: {Count} update(s) to install, {Skipped} skipped.",
                jobId, plan.ToInstall.Count, items.Count(i => i.Status == JobItemStatus.Skipped));

            if (wu is IBatchUpdateService batch && plan.ToInstall.Count > 0)
            {
                return await ExecuteBatchAsync(jobId, payload, plan, batch, cancellationToken);
            }

            var cancelled = false;
            for (var index = 0; index < plan.ToInstall.Count; index++)
            {
                var candidate = plan.ToInstall[index];
                var guid = candidate.Update.UpdateGuid;
                var label = Label(candidate.Update);

                if (IsCancelRequested(jobId))
                {
                    cancelled = true;
                    MarkRemaining(items, plan.ToInstall, index, JobItemStatus.Cancelled, SkipReasons.Cancelled);
                    break;
                }

                if (payload.NotAfter is { } windowEnd && _time.GetUtcNow() > windowEnd)
                {
                    MarkRemaining(items, plan.ToInstall, index, JobItemStatus.Skipped, SkipReasons.MaintenanceWindowClosed);
                    _logger.LogWarning("Job {JobId}: maintenance window closed; {Remaining} update(s) not started.", jobId, plan.ToInstall.Count - index);
                    break;
                }

                // Each update gets an equal share of 5-95%: the first half while it downloads, the second while it installs.
                var count = plan.ToInstall.Count;
                var position = $"{index + 1} of {count}";
                int JobPercent(double phase, int itemPercent) => 5 + (int)(90.0 * (index + phase + itemPercent / 200.0) / count);
                var basePercent = JobPercent(0, 0);
                var startedAt = _time.GetUtcNow();
                _notifier.InstallStarting(jobId);

                // ---- download
                if (!candidate.Update.IsDownloaded)
                {
                    Activity = $"Downloading {label}";
                    Set(items, guid, i => i with { Status = JobItemStatus.Downloading, StartedAt = startedAt, ErrorCode = null, ErrorMessage = null, DownloadPercent = null });
                    _reporter.Report(jobId, JobStatus.Running, "Downloading", basePercent, $"Downloading {label} ({position}).", items);

                    var downloadProgress = ItemProgress(jobId, items, guid, installing: false, label, position,
                        percent => JobPercent(0, percent), cancellationToken);
                    var download = await RunOperationAsync(() => wu.DownloadAsync(candidate.Handle, downloadProgress, cancellationToken));
                    if (!download.IsSuccess)
                    {
                        Fail(items, guid, download, "Download failed");
                        _reporter.Report(jobId, JobStatus.Running, "Downloading", basePercent, $"Download of {label} failed.", items);
                        continue;
                    }
                }

                Set(items, guid, i => i with { Status = JobItemStatus.Downloaded, StartedAt = i.StartedAt ?? startedAt, DownloadPercent = 100 });

                // ---- install
                Activity = $"Installing {label}";
                Set(items, guid, i => i with { Status = JobItemStatus.Installing, InstallPercent = null });
                _reporter.Report(jobId, JobStatus.Running, "Installing", JobPercent(0.5, 0), $"Installing {label} ({position}).", items);

                var installProgress = ItemProgress(jobId, items, guid, installing: true, label, position,
                    percent => JobPercent(0.5, percent), cancellationToken);
                var install = await RunOperationAsync(() => wu.InstallAsync(candidate.Handle, payload.Filter.AcceptEulas, installProgress, cancellationToken));
                if (install.IsSuccess)
                {
                    Set(items, guid, i => i with
                    {
                        Status = JobItemStatus.Succeeded,
                        InstallPercent = 100,
                        ResultCode = install.ResultCode,
                        RebootRequired = install.RebootRequired,
                        ErrorCode = install.ResultCode == UpdateOperationResult.SucceededWithErrors ? WindowsUpdateErrors.Format(install.HResult) : null,
                        ErrorMessage = install.ResultCode == UpdateOperationResult.SucceededWithErrors ? "Installed with errors: " + WindowsUpdateErrors.Describe(install.HResult) : null,
                        CompletedAt = _time.GetUtcNow(),
                    });
                    _logger.LogInformation("Job {JobId}: installed {Update}{Reboot}.", jobId, label, install.RebootRequired ? " (restart required)" : string.Empty);
                }
                else
                {
                    Fail(items, guid, install, "Installation failed");
                }

                _reporter.Report(jobId, JobStatus.Running, "Installing", JobPercent(1, 0),
                    install.IsSuccess ? $"Installed {label}." : $"Installation of {label} failed.", items);

                if (!install.IsSuccess && index < plan.ToInstall.Count - 1 &&
                    await wu.IsRebootRequiredBeforeInstallationAsync(cancellationToken))
                {
                    return EnterWaitingForReboot(jobId, "A restart is required before the remaining updates can be installed.", items);
                }
            }

            // ---- verify with a fresh scan so the server reconciles real state
            Activity = "Verifying installation";
            _reporter.Report(jobId, JobStatus.Running, "Verifying", 96, "Running a post-installation scan.", items);
            var verification = await _scans.RunScanAsync(ScanTrigger.PostInstall, jobId, gateHeld: true, cancellationToken);

            return Finish(jobId, items, plan.ToInstall.Count, cancelled, verification?.ScanId);
        }
        finally
        {
            Activity = null;
        }
    }

    /// <summary>
    /// Download job: downloads what the installation in the next maintenance window would install, and installs nothing. Windows
    /// Update keeps the downloads, and the installation then skips downloading them. No restart check, no message to users and
    /// no post-installation scan: the only change on the computer is the Windows Update download cache.
    /// </summary>
    private async Task<JobOutcome> DownloadOnlyAsync(JobRecord record, CancellationToken cancellationToken)
    {
        var jobId = record.Job.JobId;
        var payload = record.Job.Install ?? throw new InvalidOperationException("The download job has no payload.");
        var previous = record.Items.ToDictionary(i => i.UpdateGuid);
        var wu = _platform.Updates;
        try
        {
            if (payload.NotAfter is { } windowStart && _time.GetUtcNow() > windowStart)
            {
                const string late = "The maintenance window started before the download could begin. The installation downloads the updates.";
                _reporter.Report(jobId, JobStatus.Cancelled, "NotStarted", 100, late, errorCode: "maintenance_window_started", errorMessage: late);
                return JobOutcome.Finished;
            }

            if (wu is IBatchUpdateService || !wu.KeepsDownloads)
            {
                const string unsupported = "Downloading updates ahead of the maintenance window is only available with Windows Update.";
                _reporter.Report(jobId, JobStatus.Failed, "NotStarted", 100, unsupported, errorCode: "not_supported", errorMessage: unsupported);
                return JobOutcome.Finished;
            }

            Activity = "Scanning for updates";
            _reporter.Report(jobId, JobStatus.Running, "Scanning", 0, $"Checking {wu.Name} for applicable updates.", previous.Values.ToList());
            using var scan = await wu.ScanAsync(includeInstalled: payload.Mode == InstallMode.Selected, cancellationToken);
            var plan = BuildPlan(scan, payload, previous);
            var items = plan.Items;
            var count = plan.ToInstall.Count;
            var cancelled = false;
            _logger.LogInformation("Job {JobId}: {Count} update(s) to download before the maintenance window.", jobId, count);

            for (var index = 0; index < count; index++)
            {
                var candidate = plan.ToInstall[index];
                var guid = candidate.Update.UpdateGuid;
                var label = Label(candidate.Update);
                if (IsCancelRequested(jobId))
                {
                    cancelled = true;
                    MarkRemaining(items, plan.ToInstall, index, JobItemStatus.Cancelled, SkipReasons.Cancelled);
                    break;
                }

                if (payload.NotAfter is { } start && _time.GetUtcNow() > start)
                {
                    MarkRemaining(items, plan.ToInstall, index, JobItemStatus.Skipped, SkipReasons.WindowStarted);
                    _logger.LogInformation("Job {JobId}: the maintenance window started; {Remaining} update(s) not downloaded in advance.", jobId, count - index);
                    break;
                }

                var startedAt = _time.GetUtcNow();
                if (candidate.Update.IsDownloaded)
                {
                    Set(items, guid, i => i with { Status = JobItemStatus.Downloaded, DownloadPercent = 100, StartedAt = i.StartedAt ?? startedAt, CompletedAt = startedAt });
                    continue;
                }

                var position = $"{index + 1} of {count}";
                int JobPercent(int itemPercent) => 5 + (int)(90.0 * (index + itemPercent / 100.0) / count);
                Activity = $"Downloading {label}";
                Set(items, guid, i => i with { Status = JobItemStatus.Downloading, StartedAt = startedAt, ErrorCode = null, ErrorMessage = null, DownloadPercent = null });
                _reporter.Report(jobId, JobStatus.Running, "Downloading", JobPercent(0), $"Downloading {label} ({position}) before the maintenance window.", items);
                var progress = ItemProgress(jobId, items, guid, installing: false, label, position, JobPercent, cancellationToken);
                var download = await RunOperationAsync(() => wu.DownloadAsync(candidate.Handle, progress, cancellationToken));
                if (download.IsSuccess)
                {
                    Set(items, guid, i => i with { Status = JobItemStatus.Downloaded, DownloadPercent = 100, CompletedAt = _time.GetUtcNow() });
                }
                else
                {
                    Fail(items, guid, download, "Download failed");
                }

                _reporter.Report(jobId, JobStatus.Running, "Downloading", JobPercent(100),
                    download.IsSuccess ? $"Downloaded {label}." : $"Download of {label} failed.", items);
            }

            var downloaded = items.Count(i => i.Status == JobItemStatus.Downloaded);
            var failed = items.Count(i => i.Status == JobItemStatus.Failed);
            var status = cancelled ? JobStatus.Cancelled : count > 0 && downloaded == 0 && failed > 0 ? JobStatus.Failed : JobStatus.Completed;
            var message = count == 0
                ? "No updates needed to be downloaded."
                : $"Downloaded {downloaded} of {count} update(s) for the maintenance window" + (failed > 0 ? $"; {failed} failed" : string.Empty) +
                  (cancelled ? "; cancelled" : string.Empty) + ".";
            var firstFailure = items.FirstOrDefault(i => i.Status == JobItemStatus.Failed);
            _reporter.Report(jobId, status, "Completed", 100, message, items,
                errorCode: status == JobStatus.Failed ? firstFailure?.ErrorCode : null,
                errorMessage: status == JobStatus.Failed ? firstFailure?.ErrorMessage : null,
                result: new JobResultSummary
                {
                    Planned = count,
                    Succeeded = downloaded,
                    Failed = failed,
                    Skipped = items.Count(i => i.Status is JobItemStatus.Skipped or JobItemStatus.Cancelled),
                });
            _logger.LogInformation("Job {JobId} finished: {Status}. {Message}", jobId, status, message);
            return JobOutcome.Finished;
        }
        finally
        {
            Activity = null;
        }
    }

    /// <summary>Downloads, then installs, every planned update in one package-manager transaction each (apt, dnf).</summary>
    private async Task<JobOutcome> ExecuteBatchAsync(Guid jobId, InstallUpdatesPayload payload, Plan plan, IBatchUpdateService batch,
        CancellationToken cancellationToken)
    {
        var items = plan.Items;
        var pending = plan.ToInstall.ToList();
        var total = pending.Count;
        var cancelled = false;

        bool StopBeforeNextPhase()
        {
            if (IsCancelRequested(jobId))
            {
                cancelled = true;
                MarkRemaining(items, pending, 0, JobItemStatus.Cancelled, SkipReasons.Cancelled);
                return true;
            }

            if (payload.NotAfter is { } windowEnd && _time.GetUtcNow() > windowEnd)
            {
                MarkRemaining(items, pending, 0, JobItemStatus.Skipped, SkipReasons.MaintenanceWindowClosed);
                _logger.LogWarning("Job {JobId}: maintenance window closed; {Remaining} update(s) not started.", jobId, pending.Count);
                return true;
            }

            return false;
        }

        var wu = _platform.Updates;
        if (!StopBeforeNextPhase())
        {
            _notifier.InstallStarting(jobId);
            var startedAt = _time.GetUtcNow();

            // ---- download (one transaction)
            Activity = $"Downloading {total} update(s)";
            foreach (var candidate in pending)
            {
                Set(items, candidate.Update.UpdateGuid, i => i with { Status = JobItemStatus.Downloading, StartedAt = startedAt, ErrorCode = null, ErrorMessage = null });
            }

            _reporter.Report(jobId, JobStatus.Running, "Downloading", 5, $"Downloading {total} update(s) with {wu.Name}.", items);
            var downloads = await RunBatchAsync(() => batch.DownloadAsync(pending.Select(c => c.Handle).ToList(), cancellationToken), pending.Count);
            var downloaded = new List<UpdateCandidate>();
            for (var i = 0; i < pending.Count; i++)
            {
                var guid = pending[i].Update.UpdateGuid;
                if (downloads[i].IsSuccess)
                {
                    Set(items, guid, item => item with { Status = JobItemStatus.Downloaded, DownloadPercent = 100 });
                    downloaded.Add(pending[i]);
                }
                else
                {
                    Fail(items, guid, downloads[i], "Download failed");
                }
            }

            pending = downloaded;
            _reporter.Report(jobId, JobStatus.Running, "Downloading", 30, $"Downloaded {pending.Count} of {total} update(s).", items);

            // ---- install (one transaction; the package manager retries failures one by one and confirms every version)
            if (pending.Count > 0 && !StopBeforeNextPhase())
            {
                Activity = $"Installing {pending.Count} update(s)";
                foreach (var candidate in pending)
                {
                    Set(items, candidate.Update.UpdateGuid, i => i with { Status = JobItemStatus.Installing });
                }

                _reporter.Report(jobId, JobStatus.Running, "Installing", 35, $"Installing {pending.Count} update(s) with {wu.Name}.", items);
                var lastReport = _time.GetUtcNow();
                var progress = new SynchronousProgress<BatchInstallProgress>(p =>
                {
                    Activity = $"Installing updates ({p.Completed} of {p.Total})";
                    var now = _time.GetUtcNow();
                    if (now - lastReport >= TimeSpan.FromSeconds(15) || p.Completed == p.Total)
                    {
                        lastReport = now;
                        _reporter.Report(jobId, JobStatus.Running, "Installing", 35 + (int)(60.0 * p.Completed / Math.Max(1, p.Total)),
                            $"Installing updates: {p.Completed} of {p.Total} done{(p.Current is null ? "" : $" ({p.Current})")}.", items);
                    }
                });
                var installs = await RunBatchAsync(() => batch.InstallAsync(pending.Select(c => c.Handle).ToList(), progress, cancellationToken), pending.Count);
                for (var i = 0; i < pending.Count; i++)
                {
                    var guid = pending[i].Update.UpdateGuid;
                    var result = installs[i];
                    if (result.IsSuccess)
                    {
                        Set(items, guid, item => item with
                        {
                            Status = JobItemStatus.Succeeded,
                            ResultCode = result.ResultCode,
                            RebootRequired = result.RebootRequired,
                            ErrorCode = null,
                            ErrorMessage = null,
                            CompletedAt = _time.GetUtcNow(),
                        });
                    }
                    else
                    {
                        Fail(items, guid, result, "Installation failed");
                    }
                }

                _logger.LogInformation("Job {JobId}: {Succeeded} of {Count} update(s) installed with {Name}.",
                    jobId, installs.Count(r => r.IsSuccess), pending.Count, wu.Name);
            }
        }

        Activity = "Verifying installation";
        _reporter.Report(jobId, JobStatus.Running, "Verifying", 96, "Running a post-installation scan.", items);
        var verification = await _scans.RunScanAsync(ScanTrigger.PostInstall, jobId, gateHeld: true, cancellationToken);
        return Finish(jobId, items, total, cancelled, verification?.ScanId);
    }

    /// <summary>Runs a batch operation; an exception fails every update in it (an exception never means success).</summary>
    private static async Task<IReadOnlyList<UpdateOperationResult>> RunBatchAsync(Func<Task<IReadOnlyList<UpdateOperationResult>>> operation, int count)
    {
        IReadOnlyList<UpdateOperationResult> results;
        try
        {
            results = await operation();
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            var failed = new UpdateOperationResult(UpdateOperationResult.Failed, ex.HResult, false) { ErrorCode = "package_manager_failed", Message = ex.Message };
            return Enumerable.Repeat(failed, count).ToList();
        }

        if (results.Count != count)
        {
            var failed = new UpdateOperationResult(UpdateOperationResult.Failed, 0, false)
            {
                ErrorCode = "package_manager_failed",
                Message = "The package manager returned an unexpected number of results.",
            };
            return Enumerable.Repeat(failed, count).ToList();
        }

        return results;
    }

    /// <summary>
    /// Progress of one update: every percentage updates the item and the activity shown in the tray, and a report goes to
    /// the server when the percentage changed and <see cref="ProgressReportInterval"/> has passed since the last one. 0% is
    /// not shown (Windows Update reports it before it knows how far along an update is).
    /// </summary>
    private SynchronousProgress<int> ItemProgress(Guid jobId, List<JobItemReport> items, Guid guid, bool installing, string label, string position,
        Func<int, int> jobPercent, CancellationToken cancellationToken)
    {
        var phase = installing ? "Installing" : "Downloading";
        var lastReport = _time.GetUtcNow();
        var lastPercent = 0;
        return new SynchronousProgress<int>(value =>
        {
            var percent = Math.Clamp(value, 0, 100);
            if (cancellationToken.IsCancellationRequested || percent == 0 || percent == lastPercent)
            {
                return; // the job is no longer waiting for this operation, or nothing changed
            }

            lastPercent = percent;
            Activity = $"{phase} {label} ({percent}%)";
            Set(items, guid, i => installing ? i with { InstallPercent = percent } : i with { DownloadPercent = percent });
            var now = _time.GetUtcNow();
            if (now - lastReport >= ProgressReportInterval)
            {
                lastReport = now;
                _reporter.Report(jobId, JobStatus.Running, phase, jobPercent(percent), $"{phase} {label} ({position}): {percent}%.", items);
            }
        });
    }

    /// <summary>Invokes the callback on the reporting thread (unlike <see cref="Progress{T}"/>, which posts to the thread pool).</summary>
    private sealed class SynchronousProgress<T>(Action<T> handler) : IProgress<T>
    {
        public void Report(T value) => handler(value);
    }

    private JobOutcome Finish(Guid jobId, List<JobItemReport> items, int planned, bool cancelled, Guid? scanId)
    {
        var succeeded = items.Count(i => i.Status == JobItemStatus.Succeeded);
        var failed = items.Count(i => i.Status == JobItemStatus.Failed);
        var skipped = items.Count(i => i.Status is JobItemStatus.Skipped or JobItemStatus.Cancelled);
        var rebootRequired = items.Any(i => i.Status == JobItemStatus.Succeeded && i.RebootRequired);
        var summary = new JobResultSummary
        {
            Planned = planned,
            Succeeded = succeeded,
            Failed = failed,
            Skipped = skipped,
            RebootRequired = rebootRequired,
            PostInstallScanId = scanId,
        };

        var status = cancelled
            ? JobStatus.Cancelled
            : planned > 0 && succeeded == 0 && failed > 0 ? JobStatus.Failed : JobStatus.Completed;

        var message = planned == 0
            ? "No updates needed to be installed."
            : $"Installed {succeeded} of {planned} update(s)" + (failed > 0 ? $"; {failed} failed" : string.Empty) + (cancelled ? "; cancelled" : string.Empty) + ".";
        if (rebootRequired)
        {
            message += " A restart is required to complete installation.";
        }

        if (succeeded > 0)
        {
            var finishedAt = _time.GetUtcNow();
            _state.Update(s =>
            {
                s.LastInstallAt = finishedAt;
                s.LastInstallCount = succeeded;
            });
        }

        _notifier.InstallFinished(succeeded, rebootRequired);
        var firstFailure = items.FirstOrDefault(i => i.Status == JobItemStatus.Failed);
        _reporter.Report(jobId, status, "Completed", 100, message, items,
            errorCode: status == JobStatus.Failed ? firstFailure?.ErrorCode : null,
            errorMessage: status == JobStatus.Failed ? firstFailure?.ErrorMessage : null,
            rebootRequired: rebootRequired,
            result: summary);
        _logger.LogInformation("Job {JobId} finished: {Status}. {Message}", jobId, status, message);
        return JobOutcome.Finished;
    }

    private JobOutcome EnterWaitingForReboot(Guid jobId, string message, IReadOnlyList<JobItemReport> items)
    {
        var bootTime = _platform.BootTime.GetLastBootTime();
        var now = _time.GetUtcNow();
        _state.Update(s =>
        {
            var r = s.FindJob(jobId);
            if (r is not null)
            {
                r.RunState = JobRunState.WaitingForReboot;
                r.WaitingBootTime = bootTime;
                r.WaitingSince ??= now;
            }
        });
        _reporter.Report(jobId, JobStatus.WaitingForReboot, "WaitingForReboot", null, message, items, rebootRequired: true);
        _logger.LogWarning("Job {JobId} is waiting for a restart: {Message} The agent restarts the computer only for an administrator's restart job.", jobId, message);
        return JobOutcome.WaitingForReboot;
    }

    private static Plan BuildPlan(UpdateScanResult scan, InstallUpdatesPayload payload, Dictionary<Guid, JobItemReport> previous)
    {
        var items = new List<JobItemReport>();
        var toInstall = new List<UpdateCandidate>();
        var seen = new HashSet<Guid>();

        foreach (var candidate in scan.Missing)
        {
            var update = candidate.Update;
            if (!seen.Add(update.UpdateGuid))
            {
                continue;
            }

            var decision = InstallFilter.Evaluate(update, payload);
            previous.TryGetValue(update.UpdateGuid, out var earlier);
            if (decision.Install)
            {
                toInstall.Add(candidate);
                items.Add(NewItem(update, decision.Category, JobItemStatus.Pending, null));
                continue;
            }

            if (earlier is { Status: JobItemStatus.Succeeded })
            {
                // Installed by an earlier run of this job (now pending reboot / installed): keep the real result.
                items.Add(earlier);
                continue;
            }

            var selected = payload.Mode == InstallMode.Selected && payload.SelectedUpdateGuids.Contains(update.UpdateGuid);
            if (selected || (decision.SkipReason is not null && ReportedSkipReasons.Contains(decision.SkipReason)))
            {
                items.Add(NewItem(update, decision.Category, JobItemStatus.Skipped, decision.SkipReason));
            }
        }

        if (payload.Mode == InstallMode.Selected)
        {
            foreach (var guid in payload.SelectedUpdateGuids.Distinct())
            {
                if (!seen.Add(guid))
                {
                    continue;
                }

                previous.TryGetValue(guid, out var earlier);
                if (earlier is { Status: JobItemStatus.Succeeded })
                {
                    items.Add(earlier);
                    continue;
                }

                var installed = scan.Installed.FirstOrDefault(u => u.UpdateGuid == guid);
                items.Add(installed is not null
                    ? NewItem(installed, UpdateClassifier.Classify(installed), JobItemStatus.Skipped, SkipReasons.AlreadyInstalled)
                    : new JobItemReport
                    {
                        UpdateGuid = guid,
                        Title = earlier?.Title ?? $"Update {guid}",
                        KbNumber = earlier?.KbNumber,
                        Category = earlier?.Category ?? UpdateCategory.Other,
                        Status = JobItemStatus.Skipped,
                        SkipReason = SkipReasons.NotApplicable,
                    });
            }
        }

        // Successful results from an earlier run whose updates no longer appear at all (installed and superseded).
        foreach (var earlier in previous.Values.Where(p => p.Status == JobItemStatus.Succeeded && !seen.Contains(p.UpdateGuid)))
        {
            items.Add(earlier);
        }

        toInstall.Sort((a, b) => Priority(UpdateClassifier.Classify(a.Update)).CompareTo(Priority(UpdateClassifier.Classify(b.Update))));
        var order = toInstall.Select((c, i) => (c.Update.UpdateGuid, i)).ToDictionary(x => x.UpdateGuid, x => x.i);
        items.Sort((a, b) => Rank(a).CompareTo(Rank(b)));
        return new Plan(toInstall, items);

        int Rank(JobItemReport item) => order.TryGetValue(item.UpdateGuid, out var position) ? position : int.MaxValue;
    }

    /// <summary>Servicing stack first (Microsoft requirement), then quality/security, definitions, drivers, feature updates last.</summary>
    internal static int Priority(UpdateCategory category) => category switch
    {
        UpdateCategory.ServicingStack => 0,
        UpdateCategory.Cumulative => 1,
        UpdateCategory.Security => 2,
        UpdateCategory.Critical => 3,
        UpdateCategory.DotNet => 4,
        UpdateCategory.Other => 5,
        UpdateCategory.Definition => 6,
        UpdateCategory.Driver => 7,
        UpdateCategory.Feature => 8,
        _ => 9,
    };

    private static JobItemReport NewItem(ReportedUpdate update, UpdateCategory category, JobItemStatus status, string? skipReason) => new()
    {
        UpdateGuid = update.UpdateGuid,
        RevisionNumber = update.RevisionNumber,
        Title = update.Title,
        KbNumber = update.KbNumbers.Select(KbNumber.Normalize).FirstOrDefault(k => k is not null),
        Category = category,
        Status = status,
        SkipReason = skipReason,
    };

    private static string Label(ReportedUpdate update) =>
        update.KbNumbers.Select(KbNumber.Normalize).FirstOrDefault(k => k is not null) ?? update.Title;

    private static void Set(List<JobItemReport> items, Guid guid, Func<JobItemReport, JobItemReport> change)
    {
        var index = items.FindIndex(i => i.UpdateGuid == guid);
        if (index >= 0)
        {
            items[index] = change(items[index]);
        }
    }

    private void Fail(List<JobItemReport> items, Guid guid, UpdateOperationResult result, string what)
    {
        string code;
        string description;
        if (result.ErrorCode is not null || result.Message is not null)
        {
            code = result.ErrorCode ?? "install_failed";
            description = result.Message ?? code;
        }
        else
        {
            var hresult = result.HResult != 0 ? result.HResult : unchecked((int)0x80240FFF);
            code = WindowsUpdateErrors.Format(hresult);
            description = WindowsUpdateErrors.Describe(hresult);
        }

        Set(items, guid, i => i with
        {
            Status = JobItemStatus.Failed,
            ResultCode = result.ResultCode,
            ErrorCode = code.Length > 32 ? code[..32] : code,
            ErrorMessage = $"{what}: {description}",
            CompletedAt = _time.GetUtcNow(),
        });
        _logger.LogWarning("Update {UpdateGuid}: {What} with {Code} — {Description}", guid, what, code, description);
    }

    private static void MarkRemaining(List<JobItemReport> items, List<UpdateCandidate> toInstall, int fromIndex, JobItemStatus status, string reason)
    {
        for (var i = fromIndex; i < toInstall.Count; i++)
        {
            Set(items, toInstall[i].Update.UpdateGuid, item => item with { Status = status, SkipReason = reason });
        }
    }

    /// <summary>Converts an exception from a WUA call into a failed result (an exception never means success).</summary>
    private static async Task<UpdateOperationResult> RunOperationAsync(Func<Task<UpdateOperationResult>> operation)
    {
        try
        {
            return await operation();
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return new UpdateOperationResult(UpdateOperationResult.Failed, ex.HResult, false);
        }
    }

    private bool IsCancelRequested(Guid jobId) => _state.Read(s => s.FindJob(jobId)?.CancelRequested ?? false);

    private sealed record Plan(List<UpdateCandidate> ToInstall, List<JobItemReport> Items);
}
