using EasyPatch.Core.Entities;

namespace EasyPatch.Core.Domain;

public readonly record struct UpdateCounts(
    int MissingRequired, int MissingTotal, int Failed, int Installed, int PendingReboot, int MissingDeferred = 0, int KnownExploitedMissing = 0);

/// <summary>
/// Patch compliance rules (documented in docs/compliance.md):
/// 1. NeverScanned — no successful scan yet.
/// 2. ScanStale — last successful scan older than the policy's ScanStaleAfterHours.
/// 3. FailedUpdates — at least one required update failed to install.
/// 4. MissingUpdates — at least one required update is missing (or awaiting verification).
/// 5. RebootRequired — Windows reports a pending restart, or an installed update awaits a restart.
/// 6. Compliant — none of the above.
/// Excluded, superseded, not-applicable and not-required (drivers/feature/optional unless enabled) updates never count,
/// nor do updates still inside their rollout delay (counted separately as deferred), nor updates Windows offers again
/// after a successful installation (Reoffered; they still count as known-exploited when they are).
/// Offline status is tracked separately and does not change compliance by itself.
/// </summary>
public static class ComplianceCalculator
{
    public static UpdateCounts Count(IEnumerable<EndpointUpdate> updates)
    {
        ArgumentNullException.ThrowIfNull(updates);
        int missingRequired = 0, missingTotal = 0, failed = 0, installed = 0, pendingReboot = 0, deferred = 0, knownExploited = 0;
        foreach (var u in updates)
        {
            if (u.KnownExploited && (u.IsRequired || u.DeferredUntil is not null) &&
                u.State is EndpointUpdateState.Missing or EndpointUpdateState.PendingVerification or EndpointUpdateState.Failed
                    or EndpointUpdateState.Reoffered)
            {
                knownExploited++;
            }

            switch (u.State)
            {
                case EndpointUpdateState.Installed:
                    installed++;
                    break;
                case EndpointUpdateState.PendingReboot:
                    pendingReboot++;
                    break;
                case EndpointUpdateState.Missing:
                case EndpointUpdateState.PendingVerification:
                    missingTotal++;
                    if (u.IsRequired)
                    {
                        missingRequired++;
                    }
                    else if (u.DeferredUntil is not null)
                    {
                        deferred++;
                    }

                    break;
                case EndpointUpdateState.Failed:
                    missingTotal++;
                    if (u.IsRequired)
                    {
                        missingRequired++;
                        failed++;
                    }
                    else if (u.DeferredUntil is not null)
                    {
                        deferred++;
                    }

                    break;
            }
        }

        return new UpdateCounts(missingRequired, missingTotal, failed, installed, pendingReboot, deferred, knownExploited);
    }

    public static ComplianceStatus Evaluate(
        DateTimeOffset? lastSuccessfulScan, bool rebootPending, UpdateCounts counts, int scanStaleAfterHours, DateTimeOffset now)
    {
        if (lastSuccessfulScan is null)
        {
            return ComplianceStatus.NeverScanned;
        }

        if (now - lastSuccessfulScan.Value > TimeSpan.FromHours(scanStaleAfterHours))
        {
            return ComplianceStatus.ScanStale;
        }

        if (counts.Failed > 0)
        {
            return ComplianceStatus.FailedUpdates;
        }

        if (counts.MissingRequired > 0)
        {
            return ComplianceStatus.MissingUpdates;
        }

        if (rebootPending || counts.PendingReboot > 0)
        {
            return ComplianceStatus.RebootRequired;
        }

        return ComplianceStatus.Compliant;
    }

    /// <summary>Fleet compliance percentage: compliant endpoints / active endpoints (0 when there are none).</summary>
    public static double Percentage(int compliant, int total) =>
        total == 0 ? 0 : Math.Round(100.0 * compliant / total, 1);
}
