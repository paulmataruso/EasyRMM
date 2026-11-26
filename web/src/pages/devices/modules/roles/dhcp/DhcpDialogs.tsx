import { useState } from "react";
import type { DhcpReservation, DhcpScope } from "../../../../../api/types";
import { ConfirmDialog, Dialog } from "../../../../../components/Dialog";
import { Alert, Button, InlineError, SelectField, TextField } from "../../../../../components/ui";
import { confirmText, useWinmodChange } from "../../winmod";
import { isIPv4, isMac, optionAction, OPTIONS } from "./dhcpText";

type Change = ReturnType<typeof useWinmodChange>;

function Actions({ change, onClose, label, disabled, danger }: { change: Change; onClose: () => void; label: string; disabled?: boolean; danger?: boolean }) {
  return (
    <>
      <InlineError error={change.error} />
      <div className="flex justify-end gap-2 pt-1">
        <Button onClick={onClose} disabled={change.isPending}>Cancel</Button>
        <Button type="submit" variant={danger ? "danger" : "primary"} loading={change.isPending} disabled={disabled}>{label}</Button>
      </div>
    </>
  );
}

export function CreateScopeDialog({ change, onClose }: { change: Change; onClose: () => void }) {
  const [f, setF] = useState({ name: "", startRange: "", endRange: "", subnetMask: "255.255.255.0", leaseHours: "8" });
  const set = (k: keyof typeof f) => (e: { target: { value: string } }) => setF({ ...f, [k]: e.target.value });
  const hours = Number(f.leaseHours);
  const ok = f.name.trim() && isIPv4(f.startRange) && isIPv4(f.endRange) && isIPv4(f.subnetMask) && Number.isInteger(hours) && hours >= 1 && hours <= 8760;
  return (
    <Dialog open onClose={onClose} title="Create DHCP scope" description="The scope is created inactive and serves nothing until you activate it.">
      <form
        className="flex flex-col gap-3"
        onSubmit={(e) => {
          e.preventDefault();
          change.mutate({ action: "dhcp.scope_create", params: { ...f, name: f.name.trim(), leaseHours: hours } }, { onSuccess: onClose });
        }}
      >
        <TextField label="Name" value={f.name} onChange={set("name")} required />
        <TextField label="First address" value={f.startRange} onChange={set("startRange")} required />
        <TextField label="Last address" value={f.endRange} onChange={set("endRange")} required />
        <TextField label="Subnet mask" value={f.subnetMask} onChange={set("subnetMask")} required />
        <TextField label="Lease time (hours)" value={f.leaseHours} onChange={set("leaseHours")} inputMode="numeric" />
        <Actions change={change} onClose={onClose} label="Create scope" disabled={!ok} />
      </form>
    </Dialog>
  );
}

export function EditScopeDialog({ scope, change, onClose }: { scope: DhcpScope; change: Change; onClose: () => void }) {
  const [name, setName] = useState(scope.name);
  const [description, setDescription] = useState(scope.description);
  const [hours, setHours] = useState(String(Math.max(1, Math.round(scope.leaseDurationSeconds / 3600))));
  const h = Number(hours);
  return (
    <Dialog open onClose={onClose} title="Change DHCP scope" description={scope.scopeId}>
      <form
        className="flex flex-col gap-3"
        onSubmit={(e) => {
          e.preventDefault();
          change.mutate({ action: "dhcp.scope_set", params: { scopeId: scope.scopeId, name: name.trim(), description, leaseHours: h } }, { onSuccess: onClose });
        }}
      >
        <TextField label="Name" value={name} onChange={(e) => setName(e.target.value)} required />
        <TextField label="Description" value={description} onChange={(e) => setDescription(e.target.value)} />
        <TextField label="Lease time (hours)" value={hours} onChange={(e) => setHours(e.target.value)} inputMode="numeric" hint="The address range cannot be changed here." />
        <Actions change={change} onClose={onClose} label="Save" disabled={!name.trim() || !Number.isInteger(h) || h < 1 || h > 8760} />
      </form>
    </Dialog>
  );
}

export function ActivateDialog({ scope, change, onClose }: { scope: DhcpScope; change: Change; onClose: () => void }) {
  return (
    <ConfirmDialog
      open
      onClose={onClose}
      title="Activate DHCP scope"
      confirmLabel="Activate"
      loading={change.isPending}
      error={change.error}
      onConfirm={() => change.mutate({ action: "dhcp.scope_activate", params: { scopeId: scope.scopeId } }, { onSuccess: onClose })}
    >
      Scope <strong>{scope.scopeId}</strong> ({scope.name}) will start leasing {scope.startRange} to {scope.endRange} to clients on its network.
    </ConfirmDialog>
  );
}

/** Tier 3, both: confirmed by typing the scope, and a second factor. */
export function DangerScopeDialog({ kind, scope, change, onClose }: { kind: "deactivate" | "remove"; scope: DhcpScope; change: Change; onClose: () => void }) {
  const action = kind === "remove" ? "dhcp.scope_remove" : "dhcp.scope_deactivate";
  return (
    <ConfirmDialog
      open
      onClose={onClose}
      title={kind === "remove" ? "Remove DHCP scope" : "Deactivate DHCP scope"}
      confirmLabel={kind === "remove" ? "Remove scope" : "Deactivate"}
      tone="danger"
      confirmText={scope.scopeId}
      loading={change.isPending}
      error={change.error}
      onConfirm={() => change.mutate({ action, params: { scopeId: scope.scopeId }, confirm: confirmText(action, scope.scopeId) }, { onSuccess: onClose })}
    >
      {kind === "remove"
        ? `This removes scope ${scope.scopeId} (${scope.name}) with its leases, reservations and options. ${scope.inUse} addresses are in use. A scope in a failover relationship is refused.`
        : `Scope ${scope.scopeId} (${scope.name}) stops leasing to every client on its network; ${scope.inUse} addresses are in use and those clients cannot renew.`}{" "}
      It needs a second factor.
    </ConfirmDialog>
  );
}

export function RangeDialog({ scope, change, onClose }: { scope: DhcpScope; change: Change; onClose: () => void }) {
  const [start, setStart] = useState("");
  const [end, setEnd] = useState("");
  return (
    <Dialog open onClose={onClose} title="Exclude a range" description={`${scope.scopeId} serves ${scope.startRange} – ${scope.endRange}`}>
      <form
        className="flex flex-col gap-3"
        onSubmit={(e) => {
          e.preventDefault();
          change.mutate({ action: "dhcp.exclusion_add", params: { scopeId: scope.scopeId, startRange: start.trim(), endRange: end.trim() } }, { onSuccess: onClose });
        }}
      >
        <TextField label="First address" value={start} onChange={(e) => setStart(e.target.value)} required />
        <TextField label="Last address" value={end} onChange={(e) => setEnd(e.target.value)} required />
        <Actions change={change} onClose={onClose} label="Exclude" disabled={!isIPv4(start) || !isIPv4(end)} />
      </form>
    </Dialog>
  );
}

export function ReservationDialog({ scope, reservation, change, onClose }: { scope: DhcpScope; reservation: DhcpReservation | null; change: Change; onClose: () => void }) {
  const editing = reservation !== null;
  const [ip, setIp] = useState(reservation?.ipAddress ?? "");
  const [mac, setMac] = useState(reservation?.clientId ?? "");
  const [name, setName] = useState(reservation?.name ?? "");
  return (
    <Dialog open onClose={onClose} title={editing ? "Change reservation" : "Add reservation"} description={`Scope ${scope.scopeId}`}>
      <form
        className="flex flex-col gap-3"
        onSubmit={(e) => {
          e.preventDefault();
          change.mutate(
            { action: editing ? "dhcp.reservation_set" : "dhcp.reservation_add", params: { scopeId: scope.scopeId, ipAddress: ip.trim(), clientId: mac.trim(), ...(name.trim() ? { name: name.trim() } : {}) } },
            { onSuccess: onClose },
          );
        }}
      >
        <TextField label="IP address" value={ip} onChange={(e) => setIp(e.target.value)} disabled={editing} required />
        <TextField label="Hardware address" value={mac} onChange={(e) => setMac(e.target.value)} hint="Such as 00-11-22-33-44-55" required />
        <TextField label="Name" value={name} onChange={(e) => setName(e.target.value)} />
        <Actions change={change} onClose={onClose} label={editing ? "Save" : "Add reservation"} disabled={!isIPv4(ip) || !isMac(mac)} />
      </form>
    </Dialog>
  );
}

/** Removing a reservation, an exclusion or a lease: one confirmation each, tier 2. */
export function SimpleConfirm({ title, label, children, action, params, change, onClose }: {
  title: string;
  label: string;
  children: React.ReactNode;
  action: string;
  params: Record<string, unknown>;
  change: Change;
  onClose: () => void;
}) {
  return (
    <ConfirmDialog
      open
      onClose={onClose}
      title={title}
      confirmLabel={label}
      tone={action.endsWith("_to_reservation") ? "primary" : "danger"}
      loading={change.isPending}
      error={change.error}
      onConfirm={() => change.mutate({ action, params }, { onSuccess: onClose })}
    >
      {children}
    </ConfirmDialog>
  );
}

/** Sets an option; 3 and 6 are a tier 3 action of their own, confirmed by typing the level. */
export function OptionDialog({ level, change, onClose }: { level: string; change: Change; onClose: () => void }) {
  const [id, setId] = useState<number>(15);
  const [value, setValue] = useState("");
  const opt = OPTIONS.find((o) => o.id === id)!;
  const [typed, setTyped] = useState("");
  const action = optionAction(id);
  return (
    <Dialog open onClose={onClose} title="Set a DHCP option" description={level === "server" ? "For every scope that does not set its own" : `Scope ${level}`}>
      <form
        className="flex flex-col gap-3"
        onSubmit={(e) => {
          e.preventDefault();
          change.mutate(
            { action, params: { scopeId: level, optionId: id, value: value.trim() }, ...(opt.network ? { confirm: confirmText(action, level) } : {}) },
            { onSuccess: onClose },
          );
        }}
      >
        <SelectField label="Option" value={String(id)} onChange={(e) => setId(Number(e.target.value))}>
          {OPTIONS.map((o) => (
            <option key={o.id} value={o.id}>{o.id} · {o.label}</option>
          ))}
        </SelectField>
        <TextField label="Value" value={value} onChange={(e) => setValue(e.target.value)} hint={opt.hint} required />
        {opt.network && (
          <Alert tone="warn" title="Every client receives this">
            Clients use the new {opt.id === 3 ? "gateway" : "DNS servers"} when they next renew; a wrong value cuts them off. Type <strong>{level}</strong> to confirm. It needs a second factor.
            <TextField label="Level" value={typed} onChange={(e) => setTyped(e.target.value)} autoComplete="off" />
          </Alert>
        )}
        <Actions change={change} onClose={onClose} label="Set option" danger={opt.network} disabled={!value.trim() || (opt.network && typed.trim() !== level)} />
      </form>
    </Dialog>
  );
}
