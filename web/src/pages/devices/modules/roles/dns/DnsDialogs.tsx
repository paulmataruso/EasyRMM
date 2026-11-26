import { useState, type FormEvent } from "react";
import type { DnsRecord, DnsZone } from "../../../../../api/types";
import { ConfirmDialog, Dialog } from "../../../../../components/Dialog";
import { Alert, Button, InlineError, SelectField, TextField } from "../../../../../components/ui";
import { confirmText, useWinmodChange } from "../../winmod";
import { DATA_HINT, isProtectedRecord, RECORD_TYPES, relName } from "./dnsText";

type Change = ReturnType<typeof useWinmodChange>;

/** Adds a record, or (with `record`) changes its data and TTL; the name and type are what identify it. */
export function RecordDialog({
  zone,
  record,
  change,
  onClose,
}: {
  zone: string;
  record: DnsRecord | null;
  change: Change;
  onClose: () => void;
}) {
  const editing = record !== null;
  const [name, setName] = useState(record?.name ?? "");
  const [type, setType] = useState(record?.type ?? "A");
  const [data, setData] = useState(record?.data ?? "");
  const [ttl, setTtl] = useState(record ? String(record.ttl) : "3600");
  const rel = relName(zone, name.trim());
  const protectedName = rel !== "" && isProtectedRecord(zone, rel);
  const ttlNum = Number(ttl);
  const ttlOk = Number.isInteger(ttlNum) && ttlNum >= 1 && ttlNum <= 604800;

  function submit(e: FormEvent) {
    e.preventDefault();
    const base = { zone, name: name.trim(), type };
    change.mutate(
      editing
        ? { action: "dns.record_set", params: { ...base, data: record.data, newData: data.trim(), newTtl: ttlNum } }
        : { action: "dns.record_add", params: { ...base, data: data.trim(), ttl: ttlNum } },
      { onSuccess: onClose },
    );
  }

  return (
    <Dialog
      open
      onClose={onClose}
      title={editing ? "Change DNS record" : "Add DNS record"}
      description={`Zone ${zone}`}
    >
      <form onSubmit={submit} className="flex flex-col gap-3">
        <TextField label="Name" value={name} onChange={(e) => setName(e.target.value)} disabled={editing} hint="Relative to the zone; @ is the zone itself." required />
        <SelectField label="Type" value={type} onChange={(e) => setType(e.target.value)} disabled={editing}>
          {RECORD_TYPES.map((t) => (
            <option key={t}>{t}</option>
          ))}
        </SelectField>
        <TextField label="Data" value={data} onChange={(e) => setData(e.target.value)} hint={DATA_HINT[type]} required />
        <TextField label="TTL (seconds)" value={ttl} onChange={(e) => setTtl(e.target.value)} inputMode="numeric" error={ttlOk ? undefined : "Use 1 to 604800."} />
        {protectedName && (
          <Alert tone="warn">This name helps computers find domain controllers. Active Directory maintains it, and the server refuses to change it.</Alert>
        )}
        <InlineError error={change.error} />
        <div className="flex justify-end gap-2 pt-1">
          <Button onClick={onClose} disabled={change.isPending}>Cancel</Button>
          <Button type="submit" variant="primary" loading={change.isPending} disabled={!name.trim() || !data.trim() || !ttlOk || protectedName}>
            {editing ? "Save" : "Add record"}
          </Button>
        </div>
      </form>
    </Dialog>
  );
}

export function RemoveRecordDialog({ zone, record, change, onClose }: { zone: string; record: DnsRecord; change: Change; onClose: () => void }) {
  return (
    <ConfirmDialog
      open
      onClose={onClose}
      title="Remove DNS record"
      confirmLabel="Remove record"
      tone="danger"
      loading={change.isPending}
      error={change.error}
      onConfirm={() =>
        change.mutate(
          { action: "dns.record_remove", params: { zone, name: record.name, type: record.type, data: record.data } },
          { onSuccess: onClose },
        )
      }
    >
      Remove the {record.type} record <strong>{record.name}</strong> ({record.data}) from {zone}? Computers that cached it keep the answer until its TTL ends.
    </ConfirmDialog>
  );
}

/** Tier 3: every record of a name, confirmed by typing the name; the console asks for the second factor. */
export function RemoveAllDialog({ zone, name, change, onClose }: { zone: string; name: string; change: Change; onClose: () => void }) {
  return (
    <ConfirmDialog
      open
      onClose={onClose}
      title="Remove every record of this name"
      confirmLabel="Remove all"
      tone="danger"
      confirmText={name}
      loading={change.isPending}
      error={change.error}
      onConfirm={() =>
        change.mutate(
          { action: "dns.record_remove_all", params: { zone, name }, confirm: confirmText("dns.record_remove_all", name) },
          { onSuccess: onClose },
        )
      }
    >
      This removes every record named <strong>{name}</strong> in {zone}, of every type. It needs a second factor.
    </ConfirmDialog>
  );
}

const STORAGE = [
  ["file", "File (this server only)"],
  ["ad_domain", "Active Directory, all domain controllers in the domain"],
  ["ad_forest", "Active Directory, all domain controllers in the forest"],
  ["ad_legacy", "Active Directory, all domain controllers (legacy scope)"],
] as const;

export function CreateZoneDialog({ change, onClose }: { change: Change; onClose: () => void }) {
  const [zone, setZone] = useState("");
  const [storageKind, setStorage] = useState<string>("file");
  const [update, setUpdate] = useState("None");
  const secureOk = storageKind !== "file";
  return (
    <Dialog open onClose={onClose} title="Create DNS zone" description="A primary zone. Reverse zones end in .in-addr.arpa.">
      <form
        className="flex flex-col gap-3"
        onSubmit={(e) => {
          e.preventDefault();
          change.mutate(
            { action: "dns.zone_create", params: { zone: zone.trim(), storage: storageKind, dynamicUpdate: secureOk ? update : "None" } },
            { onSuccess: onClose },
          );
        }}
      >
        <TextField label="Zone name" value={zone} onChange={(e) => setZone(e.target.value)} required />
        <SelectField label="Stored in" value={storageKind} onChange={(e) => setStorage(e.target.value)}>
          {STORAGE.map(([v, l]) => (
            <option key={v} value={v}>{l}</option>
          ))}
        </SelectField>
        <SelectField label="Dynamic updates" value={secureOk ? update : "None"} onChange={(e) => setUpdate(e.target.value)} disabled={!secureOk} hint={secureOk ? undefined : "Secure updates need an Active Directory zone."}>
          <option value="None">None</option>
          <option value="Secure">Secure only</option>
        </SelectField>
        <InlineError error={change.error} />
        <div className="flex justify-end gap-2 pt-1">
          <Button onClick={onClose} disabled={change.isPending}>Cancel</Button>
          <Button type="submit" variant="primary" loading={change.isPending} disabled={!zone.trim()}>Create zone</Button>
        </div>
      </form>
    </Dialog>
  );
}

export function RemoveZoneDialog({ zone, change, onClose }: { zone: DnsZone; change: Change; onClose: () => void }) {
  return (
    <ConfirmDialog
      open
      onClose={onClose}
      title="Remove DNS zone"
      confirmLabel="Remove zone"
      tone="danger"
      confirmText={zone.name}
      loading={change.isPending}
      error={change.error}
      onConfirm={() =>
        change.mutate({ action: "dns.zone_remove", params: { zone: zone.name }, confirm: confirmText("dns.zone_remove", zone.name) }, { onSuccess: onClose })
      }
    >
      This deletes the zone <strong>{zone.name}</strong> and every record in it.
      {zone.adIntegrated && " It is stored in Active Directory, so the other domain controllers in its scope receive the deletion and it cannot be undone from this server."}{" "}
      It needs a second factor.
    </ConfirmDialog>
  );
}

/** Dynamic updates: none or secure here; allowing unauthenticated updates is its own, confirmed, action. */
export function UpdateDialog({ zone, change, onClose }: { zone: DnsZone; change: Change; onClose: () => void }) {
  const [mode, setMode] = useState(zone.dynamicUpdate === "Secure" ? "Secure" : zone.dynamicUpdate === "None" ? "None" : "NonsecureAndSecure");
  const [typed, setTyped] = useState("");
  const open = mode === "NonsecureAndSecure";
  const unchanged = mode === zone.dynamicUpdate;
  const blocked = unchanged || (open && typed.trim() !== zone.name) || (zone.adIntegrated && mode === "None") || (!zone.adIntegrated && mode === "Secure");
  return (
    <Dialog open onClose={onClose} title="Dynamic updates" description={zone.name}>
      <form
        className="flex flex-col gap-3"
        onSubmit={(e) => {
          e.preventDefault();
          change.mutate(
            open
              ? { action: "dns.zone_allow_nonsecure", params: { zone: zone.name }, confirm: confirmText("dns.zone_allow_nonsecure", zone.name) }
              : { action: "dns.zone_set_update", params: { zone: zone.name, mode } },
            { onSuccess: onClose },
          );
        }}
      >
        <SelectField label="Who may register names" value={mode} onChange={(e) => setMode(e.target.value)}>
          <option value="None" disabled={zone.adIntegrated}>No one (records are added by hand)</option>
          <option value="Secure" disabled={!zone.adIntegrated}>Domain members only (secure)</option>
          <option value="NonsecureAndSecure">Anyone, without authentication</option>
        </SelectField>
        {zone.adIntegrated && <p className="text-xs text-muted">Turning updates off in an Active Directory zone would stop domain computers registering their names, so it is not offered.</p>}
        {open && (
          <Alert tone="warn" title="Unauthenticated updates">
            Any computer that can reach this server could add or replace records in this zone. Type <strong>{zone.name}</strong> to allow it. It needs a second factor.
            <TextField label="Zone name" value={typed} onChange={(e) => setTyped(e.target.value)} autoComplete="off" />
          </Alert>
        )}
        <InlineError error={change.error} />
        <div className="flex justify-end gap-2 pt-1">
          <Button onClick={onClose} disabled={change.isPending}>Cancel</Button>
          <Button type="submit" variant={open ? "danger" : "primary"} loading={change.isPending} disabled={blocked}>Save</Button>
        </div>
      </form>
    </Dialog>
  );
}
