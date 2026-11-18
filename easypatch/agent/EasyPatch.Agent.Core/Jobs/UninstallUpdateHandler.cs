using EasyPatch.Agent.Core.Abstractions;
using EasyPatch.Agent.Core.Enrollment;
using EasyPatch.Agent.Core.Removal;
using EasyPatch.Agent.Core.Scanning;
using EasyPatch.Agent.Core.State;
using EasyPatch.Contracts;
using EasyPatch.Contracts.Agent;
using Microsoft.Extensions.Logging;

namespace EasyPatch.Agent.Core.Jobs;

/// <summary>
/// Uninstall-update jobs: removes the one update named in the job with <see cref="IUpdateRemover"/>, then scans so the server
/// sees the real state. The computer is never restarted; when Windows needs a restart to finish the removal the job says so, and
/// restarting stays an administrator's decision.
/// </summary>
public sealed class UninstallUpdateHandler
{
    private readonly AgentPlatform _platform;
    private readonly JobReporter _reporter;
    private readonly ScanService _scans;
    private readonly TimeProvider _time;
    private readonly ILogger _logger;

    public UninstallUpdateHandler(AgentPlatform platform, JobReporter reporter, ScanService scans, TimeProvider time, ILogger<UninstallUpdateHandler> logger)
    {
        _platform = platform;
        _reporter = reporter;
        _scans = scans;
        _time = time;
        _logger = logger;
    }

    public bool CanRemove => _platform.UpdateRemover is not null;

    public async Task<JobOutcome> ExecuteAsync(JobRecord record, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(record);
        var jobId = record.Job.JobId;
        var payload = record.Job.UninstallUpdate;
        var remover = _platform.UpdateRemover;
        if (remover is null || payload is null || !UninstallUpdatePayload.IsValid(payload))
        {
            const string message = "This agent cannot remove updates, or the job does not name a valid update.";
            _reporter.Report(jobId, JobStatus.Failed, "Failed", null, message, errorCode: "uninstall_update_not_supported", errorMessage: message);
            return JobOutcome.Finished;
        }

        if (record.CancelRequested)
        {
            _reporter.Report(jobId, JobStatus.Cancelled, "Cancelled", null, "Removal cancelled by an administrator before it started.");
            return JobOutcome.Finished;
        }

        var label = payload.KbNumber is { } kb && !payload.Title.Contains("KB" + kb, StringComparison.OrdinalIgnoreCase)
            ? $"{payload.Title} (KB{kb})"
            : payload.Title;

        var startedAt = _time.GetUtcNow();
        var item = new JobItemReport
        {
            UpdateGuid = payload.UpdateGuid,
            Title = payload.Title,
            KbNumber = payload.KbNumber is { } digits ? "KB" + digits : null,
            Category = payload.Category,
            Status = JobItemStatus.Installing,
            StartedAt = startedAt,
        };
        _reporter.Report(jobId, JobStatus.Running, "Removing", 10, $"Removing {label}.", [item]);
        _logger.LogInformation("Job {JobId}: removing {Update} for an administrator.", jobId, label);

        UpdateRemovalResult result;
        try
        {
            result = await remover.RemoveAsync(payload, cancellationToken);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            result = new UpdateRemovalResult(UpdateRemovalStatus.Failed, $"{label} could not be removed: {ex.Message}", ErrorCode: "update_removal_failed");
        }

        var completedAt = _time.GetUtcNow();
        item = result.Status switch
        {
            UpdateRemovalStatus.Removed => item with
            {
                Status = JobItemStatus.Succeeded,
                RebootRequired = result.RebootRequired,
                ErrorCode = result.ErrorCode,
                ErrorMessage = result.ErrorCode is null ? null : result.Message,
                CompletedAt = completedAt,
            },
            UpdateRemovalStatus.NotInstalled => item with { Status = JobItemStatus.Skipped, SkipReason = SkipReasons.NotInstalled, CompletedAt = completedAt },
            _ => item with
            {
                Status = JobItemStatus.Failed,
                ErrorCode = result.ErrorCode ?? "update_removal_failed",
                ErrorMessage = result.Message,
                CompletedAt = completedAt,
            },
        };

        if (result.Status == UpdateRemovalStatus.Removed)
        {
            _logger.LogWarning(AgentEventIds.UpdateRemoved, "Job {JobId}: {Message}", jobId, result.Message);
        }
        else if (result.Status != UpdateRemovalStatus.NotInstalled)
        {
            _logger.LogWarning(AgentEventIds.UpdateRemovalFailed, "Job {JobId}: {Message}", jobId, result.Message);
        }

        // ---- verify with a fresh scan so the server reconciles real state
        _reporter.Report(jobId, JobStatus.Running, "Verifying", 90, "Running a scan after the removal.", [item]);
        var verification = await _scans.RunScanAsync(ScanTrigger.PostInstall, jobId, gateHeld: true, cancellationToken);

        var removed = result.Status == UpdateRemovalStatus.Removed;
        var summary = new JobResultSummary
        {
            Planned = 1,
            Succeeded = removed ? 1 : 0,
            Failed = item.Status == JobItemStatus.Failed ? 1 : 0,
            Skipped = item.Status == JobItemStatus.Skipped ? 1 : 0,
            RebootRequired = removed && result.RebootRequired,
            PostInstallScanId = verification?.ScanId,
        };
        var failed = item.Status == JobItemStatus.Failed;
        _reporter.Report(jobId, failed ? JobStatus.Failed : JobStatus.Completed, "Completed", 100, result.Message, [item],
            errorCode: failed ? item.ErrorCode : null,
            errorMessage: failed ? result.Message : null,
            rebootRequired: summary.RebootRequired,
            result: summary);
        return JobOutcome.Finished;
    }
}
