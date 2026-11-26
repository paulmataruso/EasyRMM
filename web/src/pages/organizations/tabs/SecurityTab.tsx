import { Link } from "react-router";
import { useApi } from "../../../api/hooks";
import { useAuth } from "../../../auth/AuthContext";
import { Badge, Card, ErrorState, KeyValueList, Spinner, TableWrap } from "../../../components/ui";
import { formatRelative } from "../../../lib/format";
import type { DefenderFleet, FleetRow } from "../../devices/security/types";
import type { LevelTabProps } from "../levelTabs";

function fleetPath(level: "organization" | "site", id: string): string {
  return `/${level === "site" ? "sites" : "organizations"}/${id}/defender/fleet`;
}

/**
 * The Security card of a site's or an organization's Overview (ADR-0074 section 6): counts from what is stored, never a
 * job. A page that cannot see Defender (no `defender.view`, or no computer with the role where the module is on) shows
 * nothing.
 */
export function SecurityCard({ level, id, organizationId }: { level: "organization" | "site"; id: string; organizationId: string }) {
  const { canAt } = useAuth();
  const can = canAt("defender.view", level === "site" ? { organizationId, siteId: id } : { organizationId: id });
  const fleet = useApi<DefenderFleet>(can ? fleetPath(level, id) : null);
  if (!can || fleet.isPending || fleet.isError || !fleet.data || fleet.data.items.length === 0) return null;
  const f = fleet.data;
  const tab = `${level === "site" ? "/sites/" : "/organizations/"}${id}?tab=security`;
  return (
    <Card title="Security" actions={<Link to={tab} className="text-sm text-accent underline">Details</Link>}>
      <KeyValueList
        items={[
          ["Protected", <Badge key="p" tone="ok">{f.protected}</Badge>],
          ["Not protected", <Badge key="n" tone={f.notProtected > 0 ? "danger" : "neutral"}>{f.notProtected}</Badge>],
          ["Signatures old", <Badge key="s" tone={f.signaturesOld > 0 ? "warn" : "neutral"}>{f.signaturesOld}</Badge>],
          ["Threats in 30 days", <Badge key="t" tone={f.threats30Days > 0 ? "danger" : "neutral"}>{f.threats30Days}</Badge>],
          ...(f.unknown > 0 ? ([["Not read yet or passive", f.unknown]] as [string, number][]) : []),
        ]}
      />
    </Card>
  );
}

function protection(r: FleetRow): { label: string; tone: "ok" | "danger" | "neutral" } {
  if (r.runningMode && r.runningMode !== "Normal" && r.runningMode !== "EDR Block Mode") return { label: r.runningMode, tone: "neutral" };
  if (r.realTimeProtection === null) return { label: "Not read yet", tone: "neutral" };
  return r.realTimeProtection ? { label: "Protected", tone: "ok" } : { label: "Real-time protection off", tone: "danger" };
}

const days = (n: number | null) => (n === null ? "Never" : n === 0 ? "Today" : n === 1 ? "1 day ago" : `${n} days ago`);

/** The organization's and the site's Security tab: one row per computer with Defender, from what is stored. */
export function SecurityTab({ level, id }: LevelTabProps) {
  const org = level === "organization" || level === "site";
  const fleet = useApi<DefenderFleet>(org ? fleetPath(level as "organization" | "site", id) : null);
  if (fleet.isPending) return <Spinner />;
  if (fleet.isError) return <ErrorState error={fleet.error} onRetry={() => void fleet.refetch()} />;
  const rows = fleet.data?.items ?? [];
  return (
    <Card title="Microsoft Defender" padded={false}>
      {rows.length === 0 ? (
        <p className="p-4 text-sm text-muted">No computer here reports Microsoft Defender, or the module is off. The table reads what is stored; it sends nothing to the computers.</p>
      ) : (
        <TableWrap className="rounded-none border-0">
          <table className="table-base">
            <thead>
              <tr>
                <th>Computer</th>
                {level === "organization" && <th>Site</th>}
                <th>State</th>
                <th>Signatures</th>
                <th>Last quick scan</th>
                <th className="text-right">Open alerts</th>
                <th className="text-right">Threats (30 days)</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((r) => {
                const p = protection(r);
                return (
                  <tr key={r.deviceId}>
                    <td className="font-medium">
                      <Link to={`/devices/${r.deviceId}?tab=security`} className="hover:text-accent hover:underline">
                        {r.name}
                      </Link>
                    </td>
                    {level === "organization" && <td className="text-muted">{r.siteName}</td>}
                    <td>
                      <Badge tone={p.tone}>{p.label}</Badge>
                    </td>
                    <td className="text-muted">{days(r.signatureAgeDays)}</td>
                    <td className="text-muted">{days(r.quickScanAgeDays)}</td>
                    <td className="text-right">{r.openAlerts}</td>
                    <td className="text-right">{r.threats30Days}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
          <p className="p-3 text-xs text-muted">Read from what was last stored{rows[0]?.readAt ? ` (${formatRelative(rows[0].readAt)})` : ""}; nothing is sent to the computers.</p>
        </TableWrap>
      )}
    </Card>
  );
}
