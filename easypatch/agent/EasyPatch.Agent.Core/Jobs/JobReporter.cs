using EasyPatch.Agent.Core.Outbox;
using EasyPatch.Agent.Core.State;
using EasyPatch.Contracts;
using EasyPatch.Contracts.Agent;

namespace EasyPatch.Agent.Core.Jobs;

/// <summary>
/// Persists the next sequence number and queues a status report for a job. The sequence is saved before the
/// report is queued, so it is strictly increasing even across crashes (gaps are allowed, repeats are not).
/// </summary>
public sealed class JobReporter
{
    private readonly AgentStateStore _state;
    private readonly ReportOutbox _outbox;

    public JobReporter(AgentStateStore state, ReportOutbox outbox)
    {
        _state = state;
        _outbox = outbox;
    }

    public JobStatusReport Report(
        Guid jobId,
        JobStatus status,
        string? phase,
        int? percent = null,
        string? message = null,
        IReadOnlyList<JobItemReport>? items = null,
        string? errorCode = null,
        string? errorMessage = null,
        bool rebootRequired = false,
        JobResultSummary? result = null)
    {
        var itemList = items?.ToList();
        var sequence = _state.Update(s =>
        {
            var record = s.FindJob(jobId) ?? throw new InvalidOperationException($"Job {jobId} is not held by the agent.");
            var next = record.NextSequence;
            record.NextSequence = next + 1;
            record.Phase = phase;
            if (itemList is not null)
            {
                record.Items = itemList;
            }

            return next;
        });

        var report = new JobStatusReport
        {
            Sequence = sequence,
            Status = status,
            Phase = phase,
            Percent = percent is null ? null : Math.Clamp(percent.Value, 0, 100),
            Message = message,
            ErrorCode = errorCode,
            ErrorMessage = errorMessage,
            RebootRequired = rebootRequired,
            Items = itemList ?? [],
            Result = result,
        };
        _outbox.EnqueueJobStatus(jobId, report);
        return report;
    }
}
