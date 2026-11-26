import { useState } from "react";
import { Plus } from "lucide-react";
import type {
  Device,
  DhcpLease,
  DhcpLeaseList,
  DhcpOption,
  DhcpReservation,
  DhcpScope,
  DhcpScopeList,
  DhcpStatus,
} from "../../../../../api/types";
import { useAuth } from "../../../../../auth/AuthContext";
import { Alert, Badge, Button, Card, EmptyState, InlineError, KeyValueList, Mono, Segmented, TableWrap } from "../../../../../components/ui";
import { UsageMeter } from "../../../../../components/Meter";
import { ModuleTab } from "../../ModuleTab";
import { failureText, useWinmodChange, useWinmodRead } from "../../winmod";
import {
  ActivateDialog,
  CreateScopeDialog,
  DangerScopeDialog,
  EditScopeDialog,
  OptionDialog,
  RangeDialog,
  ReservationDialog,
  SimpleConfirm,
} from "./DhcpDialogs";
import { leaseText, rangeText } from "./dhcpText";

type Dialog =
  | { kind: "createScope" }
  | { kind: "editScope"; scope: DhcpScope }
  | { kind: "activate"; scope: DhcpScope }
  | { kind: "deactivate" | "remove"; scope: DhcpScope }
  | { kind: "exclusionAdd"; scope: DhcpScope }
  | { kind: "exclusionRemove"; scope: DhcpScope; start: string; end: string }
  | { kind: "reservation"; scope: DhcpScope; reservation: DhcpReservation | null }
  | { kind: "reservationRemove"; scope: DhcpScope; reservation: DhcpReservation }
  | { kind: "option"; level: string }
  | { kind: "leaseRemove" | "leaseToReservation"; scope: DhcpScope; lease: DhcpLease };

type Panel = "reservations" | "exclusions" | "options" | "leases";

const AUTHORIZE =
  "Add-DhcpServerInDC -DnsName <this server's name> -IPAddress <its address>";

/** The DHCP Server module (ADR-0076, section 5): the server's state, its scopes and what a scope holds. */
export function DhcpView({ device }: { device: Device }) {
  const { canAt } = useAuth();
  const at = { organizationId: device.organizationId, siteId: device.siteId };
  const manage = canAt("dhcp.manage", at);
  const [started, setStarted] = useState(false);
  const [scopeId, setScopeId] = useState<string | null>(null);
  const [panel, setPanel] = useState<Panel>("reservations");
  const [offset, setOffset] = useState(0);
  const [dialog, setDialog] = useState<Dialog | null>(null);
  const status = useWinmodRead<DhcpStatus>(device.id, "dhcp.status", {}, started);
  const scopes = useWinmodRead<DhcpScopeList>(device.id, "dhcp.scope_list", {}, started);
  const sel = scopeId ?? "";
  const on = (p: Panel) => started && scopeId !== null && panel === p;
  const reservations = useWinmodRead<{ reservations: DhcpReservation[] }>(device.id, "dhcp.reservation_list", { scopeId: sel }, on("reservations"));
  const exclusions = useWinmodRead<{ exclusions: { startRange: string; endRange: string }[] }>(device.id, "dhcp.exclusion_list", { scopeId: sel }, on("exclusions"));
  const options = useWinmodRead<{ options: DhcpOption[] }>(device.id, "dhcp.option_list", scopeId ? { scopeId } : {}, started && panel === "options");
  // Leases name devices and people: only those who may change DHCP see them, and they are not kept.
  const leases = useWinmodRead<DhcpLeaseList>(device.id, "dhcp.lease_list", { scopeId: sel, offset }, on("leases") && manage);
  const change = useWinmodChange(device.id, "dhcp");

  const reads = [status, scopes, ...(scopeId ? [reservations, exclusions, leases] : [])].filter((r) => r.fetchStatus !== "idle" || r.data);
  const refresh = () => {
    if (!started) setStarted(true);
    else reads.forEach((r) => void r.refetch());
  };
  const failure = reads.map((r) => r.data?.failure).find(Boolean);
  const lost = reads.map((r) => r.data?.lost).find(Boolean);
  const st = status.data?.data ?? null;
  const list = scopes.data?.data ?? null;
  const scope = list?.scopes.find((s) => s.scopeId === scopeId) ?? null;
  const open = (d: Dialog) => {
    change.reset();
    setDialog(d);
  };
  const close = () => setDialog(null);
  const select = (id: string) => {
    setScopeId(id);
    setOffset(0);
  };

  return (
    <ModuleTab
      name="DHCP Server"
      asOf={st ? (status.data?.finishedAt ?? null) : null}
      onRefresh={refresh}
      refreshing={reads.some((r) => r.isFetching)}
      unavailable={failure ? failureText(failure) : (lost ?? undefined)}
    >
      <InlineError error={status.error ?? scopes.error} />
      {st && (
        <Card title="Server">
          <KeyValueList
            items={[
              ["Service", <Badge key="s" tone={st.serviceState === "running" ? "ok" : st.serviceState === "stopped" ? "danger" : "warn"}>{st.serviceState}</Badge>],
              ["Scopes", `${st.scopeCount} (${st.activeScopeCount} active)`],
              ["Authorized in Active Directory", st.domainJoined === false ? "Not needed (not in a domain)" : st.authorized === null ? "—" : st.authorized ? "Yes" : "No"],
              ["Listening on", st.bindings.filter((b) => b.enabled).map((b) => b.address).join(", ") || "—"],
              ["Conflict detection", st.conflictDetectionAttempts === null ? "—" : st.conflictDetectionAttempts === 0 ? "Off" : `${st.conflictDetectionAttempts} attempts`],
            ]}
          />
          {st.authorized === false && (
            <Alert tone="warn" className="mt-3" title="Not authorized in Active Directory">
              A DHCP server in a domain does not serve clients until an administrator authorizes it. Authorization needs rights this console does not hold, so run, as one:
              <Mono className="mt-1 block break-all">{AUTHORIZE}</Mono>
            </Alert>
          )}
        </Card>
      )}
      {list && (
        <Card
          title="Scopes"
          padded={false}
          actions={manage && <Button size="sm" icon={<Plus className="size-3.5" aria-hidden />} onClick={() => open({ kind: "createScope" })}>Add scope</Button>}
        >
          {list.scopes.length === 0 ? (
            <EmptyState compact title="No scopes">This server has no IPv4 scopes yet.</EmptyState>
          ) : (
            <TableWrap className="rounded-none border-0">
              <table className="table-base">
                <thead>
                  <tr>
                    <th scope="col">Scope</th>
                    <th scope="col" className="hidden md:table-cell">Range</th>
                    <th scope="col">State</th>
                    <th scope="col" className="min-w-32">In use</th>
                    <th scope="col"><span className="sr-only">Actions</span></th>
                  </tr>
                </thead>
                <tbody>
                  {list.scopes.map((s) => (
                    <tr key={s.scopeId} aria-selected={s.scopeId === scopeId}>
                      <td><span className="font-medium">{s.name || s.scopeId}</span> <Mono className="text-muted">{s.scopeId}</Mono></td>
                      <td className="hidden md:table-cell">{rangeText(s)} <span className="text-muted">({leaseText(s.leaseDurationSeconds)})</span></td>
                      <td><Badge tone={s.state === "Active" ? "ok" : "neutral"}>{s.state === "Active" ? "Active" : "Inactive"}</Badge></td>
                      <td><UsageMeter label={`${s.scopeId} in use`} hideLabel percent={s.percentageInUse} detail={`${s.inUse} of ${s.inUse + s.free}`} /></td>
                      <td className="text-right whitespace-nowrap">
                        <Button size="sm" variant="ghost" onClick={() => select(s.scopeId)}>Open</Button>
                        {manage && <Button size="sm" variant="ghost" onClick={() => open({ kind: "editScope", scope: s })}>Edit</Button>}
                        {manage && (s.state === "Active" ? (
                          <Button size="sm" variant="danger-ghost" onClick={() => open({ kind: "deactivate", scope: s })}>Deactivate</Button>
                        ) : (
                          <Button size="sm" variant="ghost" onClick={() => open({ kind: "activate", scope: s })}>Activate</Button>
                        ))}
                        {manage && <Button size="sm" variant="danger-ghost" onClick={() => open({ kind: "remove", scope: s })}>Remove</Button>}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </TableWrap>
          )}
        </Card>
      )}
      {scope && (
        <Card
          title={`Scope ${scope.scopeId}`}
          actions={
            <Segmented
              label="Show"
              value={panel}
              onChange={setPanel}
              options={[
                { value: "reservations", label: "Reservations" },
                { value: "exclusions", label: "Exclusions" },
                { value: "options", label: "Options" },
                ...(manage ? [{ value: "leases" as const, label: "Leases" }] : []),
              ]}
            />
          }
        >
          {panel === "reservations" && (
            <Rows
              empty="No reservations."
              head={["Address", "Hardware address", "Name"]}
              rows={(reservations.data?.data?.reservations ?? []).map((r) => ({
                key: r.ipAddress,
                cells: [r.ipAddress, r.clientId, r.name || "—"],
                actions: manage && (
                  <>
                    <Button size="sm" variant="ghost" onClick={() => open({ kind: "reservation", scope, reservation: r })}>Edit</Button>
                    <Button size="sm" variant="danger-ghost" onClick={() => open({ kind: "reservationRemove", scope, reservation: r })}>Remove</Button>
                  </>
                ),
              }))}
              loaded={!!reservations.data?.data}
              add={manage ? <Button size="sm" onClick={() => open({ kind: "reservation", scope, reservation: null })}>Add reservation</Button> : null}
            />
          )}
          {panel === "exclusions" && (
            <Rows
              empty="No excluded ranges."
              head={["From", "To"]}
              rows={(exclusions.data?.data?.exclusions ?? []).map((x) => ({
                key: x.startRange,
                cells: [x.startRange, x.endRange],
                actions: manage && <Button size="sm" variant="danger-ghost" onClick={() => open({ kind: "exclusionRemove", scope, start: x.startRange, end: x.endRange })}>Remove</Button>,
              }))}
              loaded={!!exclusions.data?.data}
              add={manage ? <Button size="sm" onClick={() => open({ kind: "exclusionAdd", scope })}>Exclude a range</Button> : null}
            />
          )}
          {panel === "options" && (
            <Rows
              empty="This scope sets no options of its own."
              head={["Option", "Name", "Value"]}
              rows={(options.data?.data?.options ?? []).map((o) => ({ key: String(o.optionId), cells: [String(o.optionId), o.name, o.value.join(", ")], actions: null }))}
              loaded={!!options.data?.data}
              add={manage ? <Button size="sm" onClick={() => open({ kind: "option", level: scope.scopeId })}>Set an option</Button> : null}
            />
          )}
          {panel === "leases" && manage && (
            <>
              <p className="mb-2 text-xs text-muted">Leases name devices and sometimes people, so they are read when you ask and kept for 15 minutes.</p>
              <Rows
                empty="No leases."
                head={["Address", "Hardware address", "Host name", "State"]}
                rows={(leases.data?.data?.leases ?? []).map((l) => ({
                  key: l.ipAddress,
                  cells: [l.ipAddress, l.clientId, l.hostName || "—", l.state],
                  actions: (
                    <>
                      <Button size="sm" variant="ghost" onClick={() => open({ kind: "leaseToReservation", scope, lease: l })}>Reserve</Button>
                      <Button size="sm" variant="danger-ghost" onClick={() => open({ kind: "leaseRemove", scope, lease: l })}>Remove</Button>
                    </>
                  ),
                }))}
                loaded={!!leases.data?.data}
                add={null}
              />
              {leases.data?.data && (
                <div className="mt-2 flex items-center justify-between text-xs text-muted">
                  <span>{leases.data.data.offset + 1}–{leases.data.data.offset + leases.data.data.leases.length} of {leases.data.data.total}</span>
                  <span className="flex gap-2">
                    <Button size="sm" disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - 100))}>Previous</Button>
                    <Button size="sm" disabled={leases.data.data.next === null} onClick={() => leases.data?.data?.next != null && setOffset(leases.data.data.next)}>Next</Button>
                  </span>
                </div>
              )}
            </>
          )}
        </Card>
      )}
      {dialog?.kind === "createScope" && <CreateScopeDialog change={change} onClose={close} />}
      {dialog?.kind === "editScope" && <EditScopeDialog scope={dialog.scope} change={change} onClose={close} />}
      {dialog?.kind === "activate" && <ActivateDialog scope={dialog.scope} change={change} onClose={close} />}
      {(dialog?.kind === "deactivate" || dialog?.kind === "remove") && <DangerScopeDialog kind={dialog.kind} scope={dialog.scope} change={change} onClose={() => { if (dialog.kind === "remove" && scopeId === dialog.scope.scopeId) setScopeId(null); close(); }} />}
      {dialog?.kind === "exclusionAdd" && <RangeDialog scope={dialog.scope} change={change} onClose={close} />}
      {dialog?.kind === "exclusionRemove" && (
        <SimpleConfirm title="Remove excluded range" label="Remove" action="dhcp.exclusion_remove" params={{ scopeId: dialog.scope.scopeId, startRange: dialog.start, endRange: dialog.end }} change={change} onClose={close}>
          The addresses {dialog.start} to {dialog.end} will be offered to clients again.
        </SimpleConfirm>
      )}
      {dialog?.kind === "reservation" && <ReservationDialog scope={dialog.scope} reservation={dialog.reservation} change={change} onClose={close} />}
      {dialog?.kind === "reservationRemove" && (
        <SimpleConfirm title="Remove reservation" label="Remove" action="dhcp.reservation_remove" params={{ scopeId: dialog.scope.scopeId, ipAddress: dialog.reservation.ipAddress }} change={change} onClose={close}>
          {dialog.reservation.ipAddress} will no longer be kept for {dialog.reservation.clientId}. A client that holds it keeps the lease until it expires.
        </SimpleConfirm>
      )}
      {dialog?.kind === "option" && <OptionDialog level={dialog.level} change={change} onClose={close} />}
      {dialog?.kind === "leaseRemove" && (
        <SimpleConfirm title="Remove lease" label="Remove lease" action="dhcp.lease_remove" params={{ scopeId: dialog.scope.scopeId, ipAddress: dialog.lease.ipAddress }} change={change} onClose={close}>
          {dialog.lease.ipAddress} is freed; the client asks for an address again.
        </SimpleConfirm>
      )}
      {dialog?.kind === "leaseToReservation" && (
        <SimpleConfirm title="Reserve this address" label="Make reservation" action="dhcp.lease_to_reservation" params={{ scopeId: dialog.scope.scopeId, ipAddress: dialog.lease.ipAddress }} change={change} onClose={close}>
          {dialog.lease.ipAddress} will be kept for {dialog.lease.clientId}.
        </SimpleConfirm>
      )}
    </ModuleTab>
  );
}

function Rows({ head, rows, empty, loaded, add }: {
  head: string[];
  rows: { key: string; cells: string[]; actions: React.ReactNode }[];
  empty: string;
  loaded: boolean;
  add: React.ReactNode;
}) {
  if (!loaded) return <p className="text-sm text-muted">Reading…</p>;
  return (
    <div className="flex flex-col gap-3">
      {rows.length === 0 ? (
        <p className="text-sm text-muted">{empty}</p>
      ) : (
        <TableWrap>
          <table className="table-base">
            <thead>
              <tr>
                {head.map((h) => (
                  <th key={h} scope="col">{h}</th>
                ))}
                <th scope="col"><span className="sr-only">Actions</span></th>
              </tr>
            </thead>
            <tbody>
              {rows.map((r) => (
                <tr key={r.key}>
                  {r.cells.map((c, i) => (
                    <td key={i} className="break-all">{c}</td>
                  ))}
                  <td className="text-right whitespace-nowrap">{r.actions}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </TableWrap>
      )}
      {add && <div>{add}</div>}
    </div>
  );
}
