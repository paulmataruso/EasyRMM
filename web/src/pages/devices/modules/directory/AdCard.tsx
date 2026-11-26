import { Link } from "react-router";
import { useApi, useApiMutation } from "../../../../api/hooks";
import { api } from "../../../../api/client";
import { useAuth } from "../../../../auth/AuthContext";
import { Badge, Card, InlineError, Select, StatTile, type Tone } from "../../../../components/ui";
import type { AdDomains } from "./types";

const WHY: Record<string, string> = {
  pinned: "pinned",
  pdc: "holds the PDC emulator role",
  heartbeat: "most recent heartbeat",
  heartbeat_unknown: "most recent heartbeat (health not read yet)",
  heartbeat_unhealthy: "the only one up, though its health checks fail",
  none_qualifies: "none is online and writable",
};
const WORST: Record<string, { label: string; tone: Tone }> = {
  ok: { label: "Healthy", tone: "ok" },
  not_applicable: { label: "Healthy", tone: "ok" },
  warning: { label: "Warning", tone: "warn" },
  critical: { label: "Critical", tone: "danger" },
  unknown: { label: "Unknown", tone: "neutral" },
  could_not_run: { label: "Unknown", tone: "neutral" },
};

/**
 * The Directory card of the organization page (ADR-0075 section 8): each domain with the controller its changes go
 * through, the health of that controller and who may pin another one. It reads stored results and never sends a job.
 */
export function AdCard({ organizationId }: { organizationId: string }) {
  const { canAt } = useAuth();
  const allowed = canAt("ad.view", { organizationId });
  const path = `/organizations/${organizationId}/ad/domains`;
  const data = useApi<AdDomains>(allowed ? path : null, undefined, { refetchInterval: 60_000 });
  const pin = useApiMutation((v: { sid: string; deviceId: string | null }) => api.put(`${path}/${v.sid}/preferred`, { deviceId: v.deviceId }), { invalidate: [path] });
  if (!allowed || data.error || !data.data || !data.data.enabled || data.data.domains.length === 0) return null;
  const canPin = canAt("ad.manage", { organizationId });
  return (
    <Card title="Active Directory">
      <div className="flex flex-col gap-6">
        {data.data.domains.map((d) => {
          const chosen = d.controllers.find((c) => c.deviceId === d.chosen);
          const w = WORST[d.worst] ?? WORST.unknown!;
          return (
            <section key={d.sid} aria-label={d.name} className="flex flex-col gap-3">
              <h3 className="text-sm font-semibold">{d.name}</h3>
              <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
                <StatTile label="Health" value={chosen ? w.label : "—"} hint={chosen ? chosen.name : "no controller"} />
                <StatTile label="Locked out" value={d.lockedOut === null ? "—" : String(d.lockedOut)} />
                <StatTile label="Replication failures" value={d.replicationFailures === null ? "—" : String(d.replicationFailures)} />
                <StatTile label="Controllers" value={String(d.controllers.length)} />
              </div>
              <p className="text-sm">
                Changes go through{" "}
                {chosen ? (
                  <Link to={`/devices/${chosen.deviceId}?tab=roles`} className="text-accent hover:underline">
                    {chosen.name}
                  </Link>
                ) : (
                  "no controller"
                )}{" "}
                <Badge tone="neutral">{WHY[d.why] ?? d.why}</Badge>
              </p>
              {canPin && (
                <label className="text-xs text-muted">
                  Preferred controller
                  <Select
                    value={d.pinned ?? ""}
                    onChange={(e) => pin.mutate({ sid: d.sid, deviceId: e.target.value || null })}
                    aria-label={`Preferred controller for ${d.name}`}
                    className="mt-1 max-w-xs"
                  >
                    <option value="">Automatic</option>
                    {d.controllers.filter((c) => !c.readOnly).map((c) => (
                      <option key={c.deviceId} value={c.deviceId}>
                        {c.name}
                        {c.online ? "" : " (offline)"}
                      </option>
                    ))}
                  </Select>
                </label>
              )}
              <InlineError error={pin.error} />
            </section>
          );
        })}
      </div>
    </Card>
  );
}
