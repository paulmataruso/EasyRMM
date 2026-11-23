using EasyPatch.Agent.Core.State;
using EasyPatch.Contracts;
using EasyPatch.Contracts.Agent;
using Microsoft.Extensions.Logging;

namespace EasyPatch.Agent.Core.Jobs;

/// <summary>
/// RepairCompanion and CollectLogs jobs (ADR-0069). A job names a target and a step from fixed lists; the handler maps them to
/// <see cref="Companion.ICompanionRepair"/>, which does the one thing and returns what it did with redacted log lines for the job's
/// diagnostics. A payload that is not on the lists is refused, never run.
/// </summary>
public sealed class CompanionJobHandler
{
    private readonly Companion.ICompanionRepair? _repair;
    private readonly JobReporter _reporter;
    private readonly ILogger _logger;

    public CompanionJobHandler(Companion.ICompanionRepair? repair, JobReporter reporter, ILogger<CompanionJobHandler> logger)
    {
        _repair = repair;
        _reporter = reporter;
        _logger = logger;
    }

    public bool CanRun => _repair is not null;

    public async Task<JobOutcome> ExecuteAsync(JobRecord record, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(record);
        var jobId = record.Job.JobId;
        var payload = record.Job.RepairCompanion;
        var collect = record.Job.Type == JobType.CollectLogs;
        if (_repair is null || (!collect && !RepairCompanionPayload.IsValid(payload)))
        {
            const string message = "This agent cannot do that, or the job does not name a target and step it knows.";
            _reporter.Report(jobId, JobStatus.Failed, "Failed", null, message, errorCode: Companion.CompanionErrors.NotSupported, errorMessage: message);
            return JobOutcome.Finished;
        }

        if (record.CancelRequested)
        {
            _reporter.Report(jobId, JobStatus.Cancelled, "Cancelled", null, "Cancelled by an administrator before it started.");
            return JobOutcome.Finished;
        }

        var phase = collect ? "Collecting" : payload!.Step == CompanionSteps.Repair ? "Repairing" : "Restarting";
        _reporter.Report(jobId, JobStatus.Running, phase, 10, phase + " for EasyRMM.");
        _logger.LogWarning("Job {JobId}: {Phase} {Target} for EasyRMM.", jobId, phase, collect ? "the agents' logs" : payload!.Target + " " + payload.Step);

        Companion.CompanionOutcome outcome;
        try
        {
            outcome = collect ? await _repair.CollectLogsAsync(cancellationToken)
                : payload!.Step == CompanionSteps.Repair ? await _repair.RepairEasyRmmAgentAsync(payload.ExpectedSha256!, cancellationToken)
                : await _repair.RestartAsync(payload.Target, cancellationToken);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.LogError(ex, "Job {JobId} failed.", jobId);
            outcome = new Companion.CompanionOutcome(false, "The step failed: " + ex.Message, "agent_error");
        }

        var message2 = outcome.Message.Length <= JobDiagnostics.MaxMessageLength ? outcome.Message : outcome.Message[..JobDiagnostics.MaxMessageLength];
        _reporter.Report(jobId, outcome.Succeeded ? JobStatus.Completed : JobStatus.Failed, outcome.Succeeded ? "Completed" : "Failed", 100, message2,
            errorCode: outcome.Succeeded ? null : outcome.ErrorCode ?? "agent_error", errorMessage: outcome.Succeeded ? null : message2, diagnostics: outcome.Diagnostics);
        return JobOutcome.Finished;
    }
}
