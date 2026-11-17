using EasyPatch.Core.Entities;

namespace EasyPatch.Core.Domain;

/// <summary>One update reported by a scan, already mapped to a catalog row.</summary>
/// <param name="FleetFirstSeenAt">When any endpoint first reported this update (start of its rollout delay).</param>
/// <param name="LineKey">Linux: package line (see <see cref="UpdateRequirement.LineKey(Update?)"/>); a newer version
/// replaces older outstanding versions of the same line.</param>
public sealed record ReconcileItem(Guid UpdateGuid, Guid UpdateId, bool RebootRequired, IReadOnlyList<Guid> Supersedes,
    DateTimeOffset? FleetFirstSeenAt = null, string? LineKey = null);

public sealed record ReconcileResult(IReadOnlyList<EndpointUpdate> Added, int Changed);

/// <summary>
/// Applies a scan snapshot to an endpoint's update states. Pure logic (no I/O) so it can be unit tested.
/// Rules (docs/architecture.md, "Update state model"):
/// * Installed list → Installed (the only path to Installed).
/// * Missing with WUA RebootRequired → PendingReboot.
/// * Missing and superseded by another reported update → Superseded.
/// * Missing after a reported-successful install (PendingVerification) → Reoffered (Windows offers it again although the
///   installation succeeded); it stays Reoffered while the same revision is offered, and becomes Missing again when a new
///   revision is offered. Never Installed and never Failed by this rule.
/// * Missing and previously Failed → stays Failed (error kept); otherwise Missing.
/// * Excluded overrides Missing/Failed/Superseded.
/// * Rows absent from both lists: Installed stays Installed (WUA drops old installed updates from results);
///   other rows become Superseded (if superseded) or NotApplicable.
/// </summary>
public static class UpdateReconciler
{
    public const string ReofferedCode = "reoffered";

    public const string ReofferedMessage =
        "Windows reported the installation as successful, but Windows Update still offers this update. This is a Windows " +
        "Update detection problem (often seen with Windows Security platform updates such as KB5007651). EasyPatch does not " +
        "install it again automatically; select it to install it anyway.";

    public static ReconcileResult Reconcile(
        Guid endpointId,
        IDictionary<Guid, EndpointUpdate> existing,
        IReadOnlyList<ReconcileItem> missing,
        IReadOnlyList<ReconcileItem> installed,
        Func<Guid, bool> isExcluded,
        Func<Guid, Guid, bool> isRequired,
        Guid scanId,
        DateTimeOffset now,
        Func<EndpointUpdate, bool>? keepWhenUnreported = null)
    {
        ArgumentNullException.ThrowIfNull(existing);
        ArgumentNullException.ThrowIfNull(missing);
        ArgumentNullException.ThrowIfNull(installed);
        ArgumentNullException.ThrowIfNull(isExcluded);
        ArgumentNullException.ThrowIfNull(isRequired);

        var added = new List<EndpointUpdate>();
        var changed = 0;
        var superseded = missing.Concat(installed).SelectMany(i => i.Supersedes).ToHashSet();
        var seen = new HashSet<Guid>();

        // Outstanding rows before this scan (their state is changed below): a new update that replaces one of them inherits
        // the start of its rollout delay.
        var outstanding = existing.Values
            .Where(r => r.State is EndpointUpdateState.Missing or EndpointUpdateState.Failed or EndpointUpdateState.Superseded)
            .ToList();

        DateTimeOffset DelayBasis(ReconcileItem item)
        {
            var basis = item.FleetFirstSeenAt is { } seen && seen < now ? seen : now;
            foreach (var previous in outstanding)
            {
                var replaced = item.Supersedes.Contains(previous.UpdateGuid) ||
                               (item.LineKey is not null && item.LineKey == UpdateRequirement.LineKey(previous.Update));
                var previousBasis = previous.DelayBasisAt ?? previous.FirstDetectedAt;
                if (replaced && previousBasis < basis)
                {
                    basis = previousBasis;
                }
            }

            return basis;
        }

        EndpointUpdate GetOrAdd(ReconcileItem item, EndpointUpdateState initial)
        {
            if (!existing.TryGetValue(item.UpdateGuid, out var row))
            {
                row = new EndpointUpdate
                {
                    Id = Guid.CreateVersion7(now),
                    EndpointId = endpointId,
                    UpdateGuid = item.UpdateGuid,
                    UpdateId = item.UpdateId,
                    State = initial,
                    FirstDetectedAt = now,
                    LastDetectedAt = now,
                    StateChangedAt = now,
                    DelayBasisAt = DelayBasis(item),
                };
                existing[item.UpdateGuid] = row;
                added.Add(row);
            }
            else
            {
                row.DelayBasisAt ??= DelayBasis(item);
            }

            row.UpdateId = item.UpdateId;
            row.LastDetectedAt = now;
            row.LastScanId = scanId;
            return row;
        }

        void SetState(EndpointUpdate row, EndpointUpdateState state)
        {
            if (row.State != state)
            {
                row.State = state;
                row.StateChangedAt = now;
                changed++;
            }
        }

        foreach (var item in installed)
        {
            if (!seen.Add(item.UpdateGuid))
            {
                continue;
            }

            var row = GetOrAdd(item, EndpointUpdateState.Installed);
            if (row.State != EndpointUpdateState.Installed)
            {
                row.InstalledAt ??= now;
            }

            SetState(row, EndpointUpdateState.Installed);
            row.ErrorCode = null;
            row.ErrorMessage = null;
            row.IsExcluded = isExcluded(item.UpdateGuid);
            row.IsRequired = isRequired(item.UpdateGuid, item.UpdateId);
        }

        foreach (var item in missing)
        {
            if (!seen.Add(item.UpdateGuid))
            {
                continue;
            }

            var newRevision = existing.TryGetValue(item.UpdateGuid, out var before) && before.UpdateId != item.UpdateId;
            var row = GetOrAdd(item, EndpointUpdateState.Missing);
            var excluded = isExcluded(item.UpdateGuid);
            row.IsExcluded = excluded;
            row.IsRequired = isRequired(item.UpdateGuid, item.UpdateId);

            EndpointUpdateState next;
            if (item.RebootRequired)
            {
                next = EndpointUpdateState.PendingReboot;
                row.ErrorCode = null;
                row.ErrorMessage = null;
            }
            else if (excluded)
            {
                next = EndpointUpdateState.Excluded;
            }
            else if (superseded.Contains(item.UpdateGuid))
            {
                next = EndpointUpdateState.Superseded;
            }
            else if (row.State == EndpointUpdateState.PendingVerification ||
                     (row.State == EndpointUpdateState.Reoffered && !newRevision))
            {
                next = EndpointUpdateState.Reoffered;
                row.ErrorCode = ReofferedCode;
                row.ErrorMessage = ReofferedMessage;
            }
            else if (row.State == EndpointUpdateState.Failed && row.FailedAttempts > 0)
            {
                next = EndpointUpdateState.Failed;
            }
            else
            {
                next = EndpointUpdateState.Missing;
                if (row.ErrorCode == ReofferedCode)
                {
                    row.ErrorCode = null; // a new revision is offered: it may install correctly
                    row.ErrorMessage = null;
                }
            }

            SetState(row, next);
        }

        foreach (var row in existing.Values)
        {
            // keepWhenUnreported: rows the scan could not see (e.g. application updates when the winget part failed).
            if (seen.Contains(row.UpdateGuid) || keepWhenUnreported?.Invoke(row) == true)
            {
                continue;
            }

            switch (row.State)
            {
                case EndpointUpdateState.Installed:
                case EndpointUpdateState.NotApplicable:
                    break;
                case EndpointUpdateState.Superseded:
                    break;
                default:
                    SetState(row, superseded.Contains(row.UpdateGuid)
                        ? EndpointUpdateState.Superseded
                        : EndpointUpdateState.NotApplicable);
                    break;
            }
        }

        return new ReconcileResult(added, changed);
    }

    /// <summary>Applies a final per-update install outcome reported by the agent.</summary>
    public static void ApplyInstallOutcome(
        EndpointUpdate row, bool succeeded, bool rebootRequired, string? errorCode, string? errorMessage, Guid jobId, DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(row);
        row.LastJobId = jobId;
        row.LastAttemptAt = now;
        var next = succeeded
            ? (rebootRequired ? EndpointUpdateState.PendingReboot : EndpointUpdateState.PendingVerification)
            : EndpointUpdateState.Failed;
        if (succeeded)
        {
            row.ErrorCode = null;
            row.ErrorMessage = null;
            row.FailedAttempts = 0;
        }
        else
        {
            row.ErrorCode = errorCode;
            row.ErrorMessage = errorMessage;
            row.FailedAttempts++;
        }

        if (row.State != next)
        {
            row.State = next;
            row.StateChangedAt = now;
        }
    }

    /// <summary>States that count as "not installed yet" for compliance (when the update is required).</summary>
    public static bool IsOutstanding(EndpointUpdateState state) =>
        state is EndpointUpdateState.Missing or EndpointUpdateState.Failed or EndpointUpdateState.PendingVerification;
}
