import { useState } from "react";
import { Link } from "react-router";
import { useApi } from "../../../api/hooks";
import type { HardeningFleet, HardeningFleetDevice, HardeningState } from "../../../api/types";
import { Badge, Card, EmptyState, ErrorState, Segmented, Spinner, StatTile, TableWrap } from "../../../components/ui";
import { formatDateTime, formatRelative } from "../../../lib/format";
import { summarize } from "../../devices/hardeningText";
import { GUARD_STATES, needsAttention, windowsModule } from "../../hardening/windowsText";
import type { LevelTabProps } from "../levelTabs";

type Filter = "all" | "attention" | "unchecked";

const FLEET_STATES: [HardeningState, string][] = [
  ["in_place", "In place"],
  ["partly", "Partly"],
  ["not_in_place", "Not in place"],
  ["managed_elsewhere", "Managed elsewhere"],
  ["half_applied", "Half applied"],
  ["failed", "Failed"],
];

const attention = (d: HardeningFleetDevice) => Object.entries(d.states).some(([s, n]) => (n ?? 0) > 0 && needsAttention(s as HardeningState));

/**
 * The Hardening tab of an organization, a site or a group (ADR-0054, W3; ADR-0072): the Windows computers there, each
 * with what its last check found, and each module's states summed. A computer's own page has the detail and the
 * apply and undo. The server shows only the computers the viewer can see.
 */
export function HardeningTab({ level, id }: LevelTabProps) {
  const [filter, setFilter] = useState<Filter>("all");
  const param = level === "organization" ? "organizationId" : level === "site" ? "siteId" : "groupId";
  const fleet = useApi<HardeningFleet>("/hardening/windows/fleet", { [param]: id }, { refetchInterval: 60_000 });
  if (fleet.isPending) return <Spinner />;
  if (fleet.isError) return <ErrorState error={fleet.error} onRetry={() => void fleet.refetch()} />;
  const f = fleet.data;
  if (f.devices.length === 0) {
    return (
      <Card>
        <EmptyState title="No Windows computers here">Hardening covers Windows computers with the EasyRMM agent. None are in this {level}.</EmptyState>
      </Card>
    );
  }
  const unchecked = f.devices.filter((d) => d.checkedAt === null).length;
  const needing = f.devices.filter(attention).length;
  const waiting = f.devices.filter((d) => d.guard === "armed").length;
  const shown = f.devices.filter((d) => (filter === "attention" ? attention(d) : filter === "unchecked" ? d.checkedAt === null : true));
  return (
    <div className="flex flex-col gap-5">
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <StatTile label="Windows computers" value={f.devices.length} hint={f.truncated ? "The first 500" : undefined} />
        <StatTile label="Need attention" value={needing} />
        <StatTile label="Not checked yet" value={unchecked} />
        <StatTile label="Changes waiting to be kept" value={waiting} hint={waiting > 0 ? "The computer undoes them unless the agent confirms" : undefined} />
      </div>

      <Card title="Modules" padded={false}>
        {f.modules.length === 0 ? (
          <p className="px-4 py-3 text-sm text-muted">No module has been checked yet.</p>
        ) : (
          <TableWrap className="rounded-none border-0">
            <table className="w-full text-left text-sm" aria-label="Modules across the computers">
              <thead>
                <tr className="text-xs text-muted">
                  <th className="px-4 py-2 font-medium">Module</th>
                  {FLEET_STATES.map(([s, label]) => (
                    <th key={s} className="px-2 py-2 text-right font-medium">
                      {label}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody className="divide-y divide-line">
                {f.modules.map((m) => (
                  <tr key={m.module}>
                    <td className="px-4 py-2 font-medium">{windowsModule(m.module).name}</td>
                    {FLEET_STATES.map(([s]) => (
                      <td key={s} className="px-2 py-2 text-right tabular-nums">
                        {m.states[s] ? m.states[s] : <span className="text-subtle">0</span>}
                      </td>
                    ))}
                  </tr>
                ))}
              </tbody>
            </table>
          </TableWrap>
        )}
      </Card>

      <Card
        title="Computers"
        padded={false}
        actions={
          <Segmented
            label="Show"
            value={filter}
            onChange={setFilter}
            options={[
              { value: "all", label: "All" },
              { value: "attention", label: "Needs attention" },
              { value: "unchecked", label: "Not checked" },
            ]}
          />
        }
      >
        <TableWrap className="rounded-none border-0">
          <table className="w-full text-left text-sm" aria-label="Windows computers">
            <thead>
              <tr className="text-xs text-muted">
                <th className="px-4 py-2 font-medium">Computer</th>
                <th className="px-2 py-2 font-medium">Findings</th>
                <th className="px-2 py-2 font-medium">Change</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-line">
              {shown.map((d) => {
                const s = d.checkedAt ? summarize({ checkedAt: d.checkedAt, states: d.states }) : null;
                const g = d.guard ? GUARD_STATES[d.guard] : null;
                return (
                  <tr key={d.id}>
                    <td className="px-4 py-2">
                      <Link to={`/devices/${d.id}?tab=hardening`} className="font-medium text-accent hover:underline">
                        {d.name}
                      </Link>
                      <span className="block text-xs text-muted">
                        {d.siteName}
                        {d.groupName ? ` / ${d.groupName}` : ""}
                      </span>
                    </td>
                    <td className="px-2 py-2">
                      {s && d.checkedAt ? (
                        <>
                          <Badge tone={s.tone} title={s.title} className="tabular-nums">
                            {s.label}
                          </Badge>
                          <span className="block text-xs text-muted" title={formatDateTime(d.checkedAt)}>
                            {formatRelative(d.checkedAt)}
                          </span>
                        </>
                      ) : (
                        <span className="text-muted">Not checked</span>
                      )}
                    </td>
                    <td className="px-2 py-2">
                      {g ? (
                        <Badge tone={g.tone} title={g.title}>
                          {g.label}
                        </Badge>
                      ) : (
                        <span className="text-subtle">—</span>
                      )}
                    </td>
                  </tr>
                );
              })}
              {shown.length === 0 && (
                <tr>
                  <td colSpan={3} className="px-4 py-3 text-muted">
                    No computer matches.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </TableWrap>
      </Card>
    </div>
  );
}
