import { Link } from "react-router";
import { useApi } from "../../../../../api/hooks";
import { useAuth } from "../../../../../auth/AuthContext";
import { Card, StatTile } from "../../../../../components/ui";
import type { GpoSummary } from "./types";

/**
 * The Group Policy card of the organization Overview (ADR-0083 section 8): each domain's GPO count, GPOs linked nowhere and
 * GPOs never saved, and the requests waiting for a second person. It reads stored results and never sends a job. It
 * says what it cannot see: changes made outside EasyRMM are not tracked.
 */
export function GpoCard({ organizationId }: { organizationId: string }) {
  const { canAt } = useAuth();
  const allowed = canAt("gpo.view", { organizationId });
  const data = useApi<GpoSummary>(allowed ? `/organizations/${organizationId}/gpo/summary` : null, undefined, { refetchInterval: 60_000 });
  if (!allowed || data.error || !data.data || !data.data.enabled || data.data.domains.length === 0) return null;
  const d = data.data;
  return (
    <Card title="Group Policy">
      <div className="flex flex-col gap-5">
        {d.domains.map((x) => (
          <section key={x.domain} aria-label={x.domain} className="flex flex-col gap-3">
            <h3 className="text-sm font-semibold">
              <Link to={`/devices/${x.deviceId}?tab=roles`} className="text-accent hover:underline">{x.domain}</Link>
            </h3>
            <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
              <StatTile label="GPOs" value={String(x.gpoCount)} />
              <StatTile label="Linked nowhere" value={x.unlinked === null ? "—" : String(x.unlinked)} />
              <StatTile label="No settings" value={String(x.empty)} hint="never saved" />
              <StatTile label="Waiting for approval" value={String(d.pendingApprovals)} />
            </div>
          </section>
        ))}
        <p className="text-xs text-muted">Changes made outside EasyRMM, in the Group Policy Management Console, are not detected here; the directory&apos;s own audit log has them.</p>
      </div>
    </Card>
  );
}
