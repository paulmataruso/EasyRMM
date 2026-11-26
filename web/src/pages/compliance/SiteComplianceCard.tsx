import { Link } from "react-router";
import { useApi } from "../../api/hooks";
import type { ComplianceSettings, ComplianceSummary } from "../../api/types";
import { useAuth } from "../../auth/AuthContext";
import { Card, Spinner } from "../../components/ui";
import { formatRelative } from "../../lib/format";

/**
 * The site's result card (ADR-0078, section 7): counts of the site's computers' stored results, with a link to the
 * organization's tab. It reads stored results and never starts a job. Hidden where the module is off or the viewer may not see it.
 */
export function SiteComplianceCard({ organizationId, siteId }: { organizationId: string; siteId: string }) {
  const { canAt } = useAuth();
  const may = canAt("compliance.view", { organizationId, siteId });
  const settings = useApi<ComplianceSettings>(may ? `/organizations/${organizationId}/compliance/settings` : null, undefined, { staleTime: 60_000 });
  const on = may && settings.data?.enabled === true;
  const summary = useApi<ComplianceSummary>(on ? `/sites/${siteId}/compliance/summary` : null, undefined, { refetchInterval: 60_000 });
  if (!on) return null;
  const s = summary.data;
  return (
    <Card title="Compliance" actions={<Link to={`/organizations/${organizationId}?tab=compliance`} className="text-sm text-accent underline">Details</Link>}>
      {!s ? (
        <Spinner />
      ) : s.devices === 0 ? (
        <p className="text-sm text-muted">No scan has read the computers here yet.</p>
      ) : (
        <>
          <dl className="grid grid-cols-3 gap-3 text-sm">
            <div>
              <dt className="text-xs text-muted">Meet</dt>
              <dd className="text-lg font-semibold tabular-nums">{s.meets}</dd>
            </div>
            <div>
              <dt className="text-xs text-muted">Do not meet</dt>
              <dd className="text-lg font-semibold tabular-nums">{s.doesNotMeet}</dd>
            </div>
            <div>
              <dt className="text-xs text-muted">Cannot tell</dt>
              <dd className="text-lg font-semibold tabular-nums">{s.cannotTell + s.stale}</dd>
            </div>
          </dl>
          <p className="mt-2 text-xs text-muted">
            {s.failingDevices} of {s.devices} computers have a control that does not meet. Last scan {s.lastScan ? formatRelative(s.lastScan) : "none yet"}.
          </p>
        </>
      )}
    </Card>
  );
}
