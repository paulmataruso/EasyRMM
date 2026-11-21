// A device's disks with their health (ADR-0065): the Hardware tab's Disks card, a disk's panel, and the Devices list's
// column.
import { useId, useState, type ReactNode } from "react";
import { Link } from "react-router";
import type { UseQueryResult } from "@tanstack/react-query";
import { useApi, useList } from "../../api/hooks";
import type { Device, Disk, DiskAlert, DiskHealth, DiskHealthDetail } from "../../api/types";
import { Dialog } from "../../components/Dialog";
import { Badge, Card, Dot, EmptyState, ErrorState, KeyValueList, Mono, Spinner, TableWrap } from "../../components/ui";
import { formatDateTime, formatRelative, formatSize } from "../../lib/format";
import { CHECK_NAMES, SeverityBadge } from "../alerts/alertText";
import {
  ATTRIBUTES,
  deviceDiskHealth,
  diskShown,
  factText,
  firmwareText,
  formatDay,
  historyColumns,
  PROTOCOLS,
  ROUTES,
  stateText,
  stateWords,
} from "./diskHealthText";

const DISK_KINDS: Record<Disk["kind"], string> = { "": "Unknown", ssd: "SSD", hdd: "Hard disk", nvme: "NVMe SSD" };

const dash = <span className="text-muted">—</span>;

/** One row of the Disks card: an inventory disk, its health, or both. */
export interface DiskRow {
  inv?: Disk;
  health?: DiskHealth;
}

/** A disk's identity as the server makes it (easyrmm_disk_key): its model and serial, or its name without a serial. */
const identity = (d: Pick<Disk, "name" | "model" | "serial">) => (d.serial ? `disk\n${d.model}\n${d.serial}` : `name\n${d.name}`);

/**
 * The inventory's disks, each with its health, then the disks only the health report lists; missing disks below the
 * present ones (ADR-0065, "Disks that disappear").
 */
export function diskRows(inventory: Disk[], health: DiskHealth[]): DiskRow[] {
  const byIdentity = new Map(health.map((h) => [identity(h), h]));
  const matched = new Set<DiskHealth>();
  const rows: DiskRow[] = inventory.map((inv) => {
    const h = byIdentity.get(identity(inv));
    if (h) matched.add(h);
    return { inv, health: h };
  });
  for (const h of health) if (!matched.has(h)) rows.push({ health: h });
  return [...rows.filter((r) => !r.health?.missingSince), ...rows.filter((r) => r.health?.missingSince)];
}

/** A disk's state in words, with a dot in its tone: "Failing, last read 2 May 14:30", what made it so, and any note. */
export function DiskState({ disk, className }: { disk: DiskHealth; className?: string }) {
  const s = diskShown(disk);
  return (
    <div className={className}>
      <p className="flex items-start gap-1.5">
        <span className="pt-1.5">
          <Dot tone={s.tone} />
        </span>
        <span>
          <span className="font-medium">{s.head}</span>
          {s.rest}
        </span>
      </p>
      {s.detail && <p className="text-xs text-muted">{s.detail}</p>}
      {s.note && <p className="text-xs text-muted">{s.note}</p>}
      {s.asOf && <p className="text-xs text-muted">{s.asOf}</p>}
    </div>
  );
}

/** A fact's or a day's state in a word or two, with a dot in its tone. */
function StateMark({ state, reason }: { state: string; reason?: string }) {
  return (
    <span className="inline-flex items-baseline gap-1.5">
      <Dot tone={stateWords(state).tone} />
      <span>{stateText(state, reason)}</span>
    </span>
  );
}

function FirmwareCell({ disk }: { disk?: Disk }) {
  const text = firmwareText(disk?.firmware);
  if (text === null) return dash;
  if (disk?.firmware?.state === "read") return <Mono>{text}</Mono>;
  return <span className="text-muted">{text}</span>;
}

/** The Hardware tab's Disks card: the inventory's disks with their firmware and health; a disk opens its panel. */
export function DisksCard({ device, disks }: { device: Pick<Device, "id" | "agent">; disks: Disk[] }) {
  const health = useList<DiskHealth>(`/devices/${device.id}/disks`, undefined, { refetchInterval: 60_000 });
  const [open, setOpen] = useState<DiskRow | null>(null);
  const rows = diskRows(disks, health.items);
  const reported = health.items.length > 0;

  const healthCell = (r: DiskRow) => {
    if (r.health) return <DiskState disk={r.health} className="min-w-52" />;
    if (health.isPending) return <span className="text-muted">Loading…</span>;
    if (health.isError) return dash;
    return (
      <span className="text-muted" title={reported ? "The agent's disk health report does not list this disk." : undefined}>
        Not reported
      </span>
    );
  };

  return (
    <Card title="Disks" padded={false}>
      {rows.length === 0 ? (
        <EmptyState title="No disks reported" compact>
          Containers and some virtual machines do not show their disks to the agent.
        </EmptyState>
      ) : (
        <TableWrap className="rounded-none border-0">
          <table className="table-base">
            <thead>
              <tr>
                <th scope="col">Disk</th>
                <th scope="col">Model</th>
                <th scope="col" className="hidden md:table-cell">
                  Type
                </th>
                <th scope="col" className="hidden text-right md:table-cell">
                  Size
                </th>
                <th scope="col" className="hidden lg:table-cell">
                  Serial number
                </th>
                <th scope="col" className="hidden sm:table-cell">
                  Firmware
                </th>
                <th scope="col">Health</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((r) => {
                const name = r.inv?.name ?? r.health?.name ?? "";
                const model = r.inv?.model ?? r.health?.model ?? "";
                const serial = r.inv?.serial ?? r.health?.serial ?? "";
                return (
                  <tr key={r.health?.key ?? `inv-${name}`}>
                    <td className="font-medium whitespace-nowrap">
                      {r.health ? (
                        <button
                          type="button"
                          className="rounded-sm font-medium text-accent hover:underline"
                          aria-haspopup="dialog"
                          onClick={() => setOpen(r)}
                        >
                          {name}
                        </button>
                      ) : (
                        name
                      )}
                      {r.inv?.removable && <Badge className="ml-2">Removable</Badge>}
                      {r.health?.missingSince && (
                        <Badge tone="warn" className="ml-2">
                          Missing
                        </Badge>
                      )}
                    </td>
                    <td>{model || dash}</td>
                    <td className="hidden whitespace-nowrap md:table-cell">{r.inv ? (DISK_KINDS[r.inv.kind] ?? r.inv.kind) : dash}</td>
                    <td className="hidden text-right whitespace-nowrap tabular-nums md:table-cell">{r.inv ? formatSize(r.inv.sizeBytes) : dash}</td>
                    <td className="hidden lg:table-cell">{serial ? <Mono>{serial}</Mono> : dash}</td>
                    <td className="hidden sm:table-cell">
                      <FirmwareCell disk={r.inv} />
                    </td>
                    <td>{healthCell(r)}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </TableWrap>
      )}
      {health.isError ? (
        <div className="border-t border-line">
          <ErrorState error={health.error} onRetry={() => void health.refetch()} compact />
        </div>
      ) : (
        !health.isPending && (
          <p className="border-t border-line px-4 py-2.5 text-xs text-muted">
            {reported
              ? "The agent reads each disk's health every 30 minutes. Select a disk for its facts, its last 30 days and its alerts."
              : `Disk health not reported: ${device.agent ? `this device's agent, version ${device.agent.version}, has` : "this device has"} sent none. An agent that reads disk health reports it a few minutes after it starts, then every 30 minutes.`}
          </p>
        )
      )}
      <DiskPanel deviceId={device.id} row={open} onClose={() => setOpen(null)} />
    </Card>
  );
}

/** A disk's panel: every fact with its state and reason, the ATA attributes, the last 30 days and its open alerts. */
export function DiskPanel({ deviceId, row, onClose }: { deviceId: string; row: DiskRow | null; onClose: () => void }) {
  const key = row?.health?.key ?? null;
  const detail = useApi<DiskHealthDetail>(key ? `/devices/${deviceId}/disks/${encodeURIComponent(key)}` : null, undefined, { refetchInterval: 60_000 });
  // The list's disk shows at once; the panel's own read adds its history and alerts, and is the newer once it arrives.
  const d: DiskHealth | undefined = key ? (detail.data ?? row?.health) : undefined;
  return (
    <Dialog open={d !== undefined} onClose={onClose} title={d?.name ?? ""} description={d?.model || undefined} size="lg">
      {d && <DiskPanelBody deviceId={deviceId} disk={d} firmware={row?.inv} detail={detail} />}
    </Dialog>
  );
}

function DiskPanelBody({ deviceId, disk: d, firmware, detail }: {
  deviceId: string;
  disk: DiskHealth;
  firmware?: Disk;
  detail: UseQueryResult<DiskHealthDetail>;
}) {
  const factsId = useId();
  const attributesId = useId();
  const historyId = useId();
  const alertsId = useId();
  const fw = firmwareText(firmware?.firmware);
  return (
    <div className="flex flex-col gap-5">
      <DiskState disk={d} />
      <KeyValueList
        narrow
        items={[
          ["Serial number", d.serial ? <Mono key="s">{d.serial}</Mono> : <span className="text-muted">None reported</span>],
          ...(fw !== null ? [["Firmware", firmware?.firmware?.state === "read" ? <Mono key="f">{fw}</Mono> : fw] as [string, ReactNode]] : []),
          ["Read with", d.protocol ? [PROTOCOLS[d.protocol] ?? d.protocol, ROUTES[d.route] ?? d.route].filter(Boolean).join(", ") : <span className="text-muted">Not read</span>],
          ["Facts as of", d.factsAt ? formatDateTime(d.factsAt) : <span className="text-muted">Never read</span>],
          [
            "Latest reading",
            <span key="l">
              {stateText(d.latest.state, d.latest.reason)}, <span title={formatDateTime(d.latest.receivedAt)}>{formatRelative(d.latest.receivedAt)}</span>
              {d.latest.detail && <span className="block text-xs text-muted">{d.latest.detail}</span>}
            </span>,
          ],
          ...(d.unstable
            ? [["Identified by", "Its name: the disk reports no serial number, so its history starts again if its name changes."] as [string, string]]
            : []),
        ]}
      />

      <section aria-labelledby={factsId} className="flex flex-col gap-2">
        <h3 id={factsId} className="text-sm font-semibold">
          Facts
        </h3>
        {d.facts.length === 0 ? (
          <p className="text-sm text-muted">No facts read yet.</p>
        ) : (
          <TableWrap>
            <table className="table-base" aria-labelledby={factsId}>
              <thead>
                <tr>
                  <th scope="col">Fact</th>
                  <th scope="col">Value</th>
                  <th scope="col">State</th>
                </tr>
              </thead>
              <tbody>
                {d.facts.map((f) => {
                  const t = factText(f);
                  return (
                    <tr key={f.name}>
                      <td>{t.label}</td>
                      <td className="tabular-nums">{t.value}</td>
                      <td>
                        <StateMark state={f.state} reason={f.reason} />
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </TableWrap>
        )}
      </section>

      {d.attributes.length > 0 && (
        <section aria-labelledby={attributesId} className="flex flex-col gap-2">
          <h3 id={attributesId} className="text-sm font-semibold">
            SMART attributes
          </h3>
          <TableWrap>
            <table className="table-base" aria-labelledby={attributesId}>
              <thead>
                <tr>
                  <th scope="col" className="text-right">
                    ID
                  </th>
                  <th scope="col">Attribute</th>
                  <th scope="col">Type</th>
                  <th scope="col" className="text-right">
                    Value
                  </th>
                  <th scope="col" className="text-right">
                    Worst
                  </th>
                  <th scope="col" className="text-right">
                    Threshold
                  </th>
                  <th scope="col" className="text-right">
                    Raw
                  </th>
                  <th scope="col">State</th>
                </tr>
              </thead>
              <tbody>
                {d.attributes.map((a) => (
                  <tr key={a.id}>
                    <td className="text-right tabular-nums">{a.id}</td>
                    <td>{ATTRIBUTES[a.id] ?? <span className="text-muted">The maker's own</span>}</td>
                    <td className="whitespace-nowrap">{a.preFail ? "Pre-fail" : "Old age"}</td>
                    <td className="text-right tabular-nums">{a.value}</td>
                    <td className="text-right tabular-nums">{a.worst}</td>
                    <td className="text-right tabular-nums">{a.threshold ?? dash}</td>
                    <td className="text-right font-mono text-xs tabular-nums">{a.raw}</td>
                    <td className="whitespace-nowrap">
                      <StateMark state={a.state} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </TableWrap>
        </section>
      )}

      <section aria-labelledby={historyId} className="flex flex-col gap-2">
        <h3 id={historyId} className="text-sm font-semibold">
          Last 30 days
        </h3>
        {/* A later read that fails keeps what the last one showed. */}
        {detail.data ? (
          detail.data.history.length === 0 ? (
            <p className="text-sm text-muted">No readings in the last 30 days.</p>
          ) : (
            <HistoryTable labelledBy={historyId} days={detail.data.history} />
          )
        ) : detail.isError ? (
          <ErrorState error={detail.error} onRetry={() => void detail.refetch()} compact />
        ) : (
          <Spinner />
        )}
      </section>

      {detail.data && detail.data.alerts !== null && (
        <section aria-labelledby={alertsId} className="flex flex-col gap-2">
          <div className="flex items-baseline justify-between gap-2">
            <h3 id={alertsId} className="text-sm font-semibold">
              Open alerts
            </h3>
            <Link to={`/alerts?deviceId=${deviceId}&status=all`} className="text-xs text-accent hover:underline">
              The device's alerts
            </Link>
          </div>
          {detail.data.alerts.length === 0 ? (
            <p className="text-sm text-muted">No open alerts on this disk.</p>
          ) : (
            <ul className="divide-y divide-line rounded-lg border border-line">
              {detail.data.alerts.map((a) => (
                <DiskAlertItem key={a.id} alert={a} />
              ))}
            </ul>
          )}
        </section>
      )}
    </div>
  );
}

function HistoryTable({ days, labelledBy }: { days: DiskHealthDetail["history"]; labelledBy: string }) {
  const columns = historyColumns(days);
  return (
    <TableWrap>
      <table className="table-base" aria-labelledby={labelledBy}>
        <thead>
          <tr>
            <th scope="col">Day (UTC)</th>
            <th scope="col">Worst state</th>
            {columns.map((c) => (
              <th key={c.key} scope="col" className="text-right">
                {c.label}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {days.map((day) => (
            <tr key={day.day}>
              <td className="whitespace-nowrap">{formatDay(day.day)}</td>
              <td className="whitespace-nowrap">
                <StateMark state={day.state} />
              </td>
              {columns.map((c) => {
                const v = day[c.key];
                return (
                  <td key={c.key} className="text-right tabular-nums">
                    {v === null ? dash : c.value(v)}
                  </td>
                );
              })}
            </tr>
          ))}
        </tbody>
      </table>
    </TableWrap>
  );
}

function DiskAlertItem({ alert: a }: { alert: DiskAlert }) {
  const check = Object.hasOwn(CHECK_NAMES, a.checkName) ? CHECK_NAMES[a.checkName as keyof typeof CHECK_NAMES] : a.checkName;
  return (
    <li className="flex items-start justify-between gap-3 px-3 py-2.5 text-sm">
      <span className="min-w-0">
        <span className="block font-medium">{a.name}</span>
        <span className="block text-xs text-muted">
          {check}
          {a.detail && <> · {a.detail}</>}
        </span>
        <span className="block text-xs text-muted">
          <span title={formatDateTime(a.openedAt)}>Opened {formatRelative(a.openedAt)}</span>
          {a.status === "acknowledged" && " · acknowledged"}
        </span>
      </span>
      <SeverityBadge severity={a.severity} />
    </li>
  );
}

/** The Devices list's disk health column: the device's label, with every disk counted in its title. */
export function DiskHealthCell({ device }: { device: Pick<Device, "diskHealth"> }) {
  const h = deviceDiskHealth(device.diskHealth);
  if (!device.diskHealth) {
    return (
      <span className="text-muted" title={h.title}>
        {h.label}
      </span>
    );
  }
  return (
    <Badge tone={h.tone} title={h.title}>
      {h.label}
    </Badge>
  );
}
