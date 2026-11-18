using EasyPatch.Contracts;

namespace EasyPatch.Core.Domain;

public static class JobTransitions
{
    /// <summary>Statuses a job occupies while the endpoint is working on it (blocks delivery of another job).</summary>
    public static readonly JobStatus[] ActiveOnAgent = [JobStatus.Delivered, JobStatus.Acknowledged, JobStatus.Running];

    /// <summary>Statuses covered by the duplicate-job guard.</summary>
    public static readonly JobStatus[] DedupeStatuses =
        [JobStatus.Queued, JobStatus.Delivered, JobStatus.Acknowledged, JobStatus.Running, JobStatus.WaitingForReboot];

    /// <summary>Whether an agent status report may move a job from <paramref name="from"/> to <paramref name="to"/>.</summary>
    public static bool AgentMayTransition(JobStatus from, JobStatus to, bool timedOut)
    {
        if (to is JobStatus.Queued or JobStatus.Delivered or JobStatus.Acknowledged)
        {
            return false;
        }

        // The agent reports Expired when a job's deadline (or maintenance window) passed before it could start.
        if (to is JobStatus.Expired)
        {
            return from is JobStatus.Delivered or JobStatus.Acknowledged or JobStatus.Running;
        }

        return from switch
        {
            JobStatus.Delivered or JobStatus.Acknowledged or JobStatus.Running or JobStatus.WaitingForReboot => true,
            // A job the server timed out may still receive the agent's genuine late result.
            JobStatus.Failed when timedOut => true,
            _ => false,
        };
    }

    public static bool AdminMayCancel(JobStatus status) =>
        status is JobStatus.Queued or JobStatus.Delivered or JobStatus.Acknowledged or JobStatus.Running or JobStatus.WaitingForReboot;
}
