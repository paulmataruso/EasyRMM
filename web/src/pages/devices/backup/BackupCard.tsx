import { Link } from "react-router";
import { useApi } from "../../../api/hooks";
import type { BackupFleet } from "../../../api/types";
import { useAuth } from "../../../auth/AuthContext";
import { Badge, Card, StatTile, type Tone } from "../../../components/ui";
import { formatRelative } from "../../../lib/format";

const STATE: Record<string, { label: string; tone: Tone }> = {
  ok: { label: "Backed up", tone: "ok" },
  stale: { label: "Over a day ago", tone: "neutral" },
  failed: { label: "Failed", tone: "danger" },
  overdue: { label: "Overdue", tone: "warn" },
  not_configured: { label: "Not configured", tone: "warn" },
  not_installed: { label: "Not installed", tone: "neutral" },
  no_data: { label: "Not read yet", tone: "neutral" },
};

/**
 * The Backup card of the organization and site pages (ADR-0077, section 4): counts of servers by their last backup and
 * a table of them. It reads stored results and never sends a job to a computer. It shows only where the viewer holds
 * backup.view, and says nothing where the module is off.
 */
export function BackupCard({ level, id, organizationId }: { level: "organization" | "site"; id: string; organizationId?: string }) {
  const { canAt } = useAuth();
  const scope = level === "site" ? { organizationId: organizationId ?? "", siteId: id } : { organizationId: id };
  const allowed = canAt("backup.view", scope);
  const fleet = useApi<BackupFleet>(allowed ? `/${level === "site" ? "sites" : "organizations"}/${id}/backup` : null, undefined, {
    refetchInterval: 60_000,
  });
  if (!allowed || fleet.error || !fleet.data || !fleet.data.enabled) return null;
  const c = fleet.data.counts;
  return (
    <Card title="Windows Backup" padded={false}>
      {fleet.data.devices.length === 0 ? (
        <p className="p-4 text-sm text-muted">No Windows computer here reports backup yet.</p>
      ) : (
        <>
          <div className="grid grid-cols-2 gap-3 p-4 sm:grid-cols-4">
            <StatTile label="Backed up" value={String(c.backedUp)} hint="in the last 24 hours" />
            <StatTile label="Failed" value={String(c.failed)} />
            <StatTile label="Overdue" value={String(c.overdue)} hint="no success in 2 days" />
            <StatTile label="Not configured" value={String(c.notConfigured)} />
          </div>
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left text-xs text-muted">
                <th className="px-4 py-2 font-medium">Computer</th>
                <th className="px-4 py-2 font-medium">State</th>
                <th className="px-4 py-2 font-medium">Last success</th>
                <th className="px-4 py-2 font-medium">Alerts</th>
              </tr>
            </thead>
            <tbody>
              {fleet.data.devices.map((d) => {
                const s = STATE[d.state] ?? STATE.no_data!;
                return (
                  <tr key={d.deviceId} className="border-t border-border">
                    <td className="px-4 py-2">
                      <Link to={`/devices/${d.deviceId}?tab=backup`} className="text-accent hover:underline">
                        {d.name}
                      </Link>
                    </td>
                    <td className="px-4 py-2">
                      <Badge tone={s.tone}>{s.label}</Badge>
                    </td>
                    <td className="px-4 py-2">{d.lastSuccess ? formatRelative(d.lastSuccess) : "Never"}</td>
                    <td className="px-4 py-2">{d.openAlerts || "—"}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </>
      )}
    </Card>
  );
}
