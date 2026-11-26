import { useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { api } from "../../../../../api/client";
import type { Device } from "../../../../../api/types";
import { Dialog } from "../../../../../components/Dialog";
import { Alert, Button, InlineError, SelectField, TextField, TextareaField } from "../../../../../components/ui";
import { confirmText, runWinmod, failureText } from "../../winmod";
import { GpoChangeDialog } from "./GpoChange";
import { MODULE, STATUS_LABEL } from "./gpoText";
import type { Gpo, GpoBackup, GpoDetail, LinkTarget, Trustee } from "./types";

type Close = { onClose: () => void };
type Base = { device: Device } & Close;

/** The versions a GPO was read at: the change refuses if they have moved. */
const expect = (g: Gpo) => ({ expectComputerVersion: g.computer.directory, expectUserVersion: g.user.directory });
const dflt = (g: Gpo) => (g.default ? g.name : undefined);

export function CreateGpoDialog({ device, onClose }: Base) {
  const [name, setName] = useState("");
  const [comment, setComment] = useState("");
  return (
    <GpoChangeDialog device={device} title="Create a GPO" label="Create" valid={name.trim().length > 0} onClose={onClose}
      op={{ action: "gpo_create", params: { newName: name.trim(), comment: comment.trim() || undefined }, subject: name.trim() }}>
      <TextField label="Name" value={name} onChange={(e) => setName(e.target.value)} required />
      <TextField label="Comment" value={comment} onChange={(e) => setComment(e.target.value)} />
    </GpoChangeDialog>
  );
}

export function CopyGpoDialog({ device, gpo, onClose }: Base & { gpo: Gpo }) {
  const [name, setName] = useState(`${gpo.name} (copy)`);
  return (
    <GpoChangeDialog device={device} title={`Copy ${gpo.name}`} label="Copy" valid={name.trim().length > 0} onClose={onClose}
      op={{ action: "gpo_copy", params: { id: gpo.id, newName: name.trim(), ...expect(gpo) }, subject: gpo.name }}>
      <TextField label="Name of the copy" value={name} onChange={(e) => setName(e.target.value)} required />
      <p className="text-xs text-muted">The copy has the settings, not the links. It is not linked anywhere until you link it.</p>
    </GpoChangeDialog>
  );
}

export function RenameGpoDialog({ device, gpo, onClose }: Base & { gpo: Gpo }) {
  const [name, setName] = useState(gpo.name);
  return (
    <GpoChangeDialog device={device} title={`Rename ${gpo.name}`} label="Rename" valid={name.trim().length > 0 && name.trim() !== gpo.name} onClose={onClose}
      op={{ action: "gpo_rename", params: { id: gpo.id, newName: name.trim(), ...expect(gpo) }, subject: gpo.name }}>
      <TextField label="New name" value={name} onChange={(e) => setName(e.target.value)} required />
    </GpoChangeDialog>
  );
}

export function DeleteGpoDialog({ device, gpo, onClose }: Base & { gpo: Gpo }) {
  return (
    <GpoChangeDialog device={device} title={`Delete ${gpo.name}`} label="Delete GPO" danger onClose={onClose}
      op={{ action: "gpo_delete", params: { id: gpo.id, name: gpo.name, ...expect(gpo) }, confirmSubject: gpo.name, subject: gpo.name }}>
      <Alert tone="warn">
        {gpo.linkCount > 0 ? `It is linked in ${gpo.linkCount} place${gpo.linkCount === 1 ? "" : "s"}, and deleting it removes those links. ` : ""}A backup is kept, and the Backups list restores it.
      </Alert>
    </GpoChangeDialog>
  );
}

export function StatusDialog({ device, gpo, onClose }: Base & { gpo: Gpo }) {
  const [status, setStatus] = useState<Gpo["status"]>(gpo.status);
  return (
    <GpoChangeDialog device={device} title={`Which parts of ${gpo.name} apply`} label="Save" valid={status !== gpo.status} onClose={onClose}
      op={{ action: "gpo_status", params: { id: gpo.id, status, ...expect(gpo) }, subject: gpo.name }} defaultName={dflt(gpo)}>
      <SelectField label="Status" value={status} onChange={(e) => setStatus(e.target.value as Gpo["status"])}>
        {(Object.keys(STATUS_LABEL) as Gpo["status"][]).map((s) => (
          <option key={s} value={s}>{STATUS_LABEL[s]}</option>
        ))}
      </SelectField>
      <p className="text-xs text-muted">Disabling the part a GPO does not use makes computers process it faster.</p>
    </GpoChangeDialog>
  );
}

export function WmiDialog({ device, gpo, filters, onClose }: Base & { gpo: Gpo; filters: string[] }) {
  const [filter, setFilter] = useState(gpo.wmiFilter);
  return (
    <GpoChangeDialog device={device} title={`WMI filter of ${gpo.name}`} label="Save" valid={filter !== gpo.wmiFilter} onClose={onClose}
      op={{ action: "wmi_set", params: { id: gpo.id, filter, ...expect(gpo) }, subject: gpo.name }} defaultName={dflt(gpo)}>
      <SelectField label="WMI filter" value={filter} onChange={(e) => setFilter(e.target.value)}>
        <option value="">None</option>
        {filters.map((f) => (
          <option key={f} value={f}>{f}</option>
        ))}
      </SelectField>
    </GpoChangeDialog>
  );
}

export function SecurityAddDialog({ device, gpo, onClose }: Base & { gpo: Gpo }) {
  const [sid, setSid] = useState("");
  const ok = /^S-1-\d{1,10}(-\d{1,10}){1,15}$/.test(sid.trim());
  return (
    <GpoChangeDialog device={device} title={`Add to the security filtering of ${gpo.name}`} label="Add" valid={ok} onClose={onClose}
      op={{ action: "sec_filter_add", params: { id: gpo.id, trustee: sid.trim(), ...expect(gpo) }, subject: gpo.name }} defaultName={dflt(gpo)}>
      <TextField label="Security identifier (SID) of a user, group or computer" value={sid} onChange={(e) => setSid(e.target.value)} placeholder="S-1-5-21-…" required
        hint="The principal gets Read and Apply group policy. Find a SID in the Directory view." />
    </GpoChangeDialog>
  );
}

export function SecurityRemoveDialog({ device, gpo, trustee, onClose }: Base & { gpo: Gpo; trustee: Trustee }) {
  const [keepRead, setKeepRead] = useState(true);
  return (
    <GpoChangeDialog device={device} title={`Remove ${trustee.name} from the security filtering`} label="Remove" danger onClose={onClose}
      op={{ action: "sec_filter_remove", params: { id: gpo.id, name: gpo.name, trustee: trustee.sid, keepRead, ...expect(gpo) }, confirmSubject: gpo.name, subject: gpo.name }}
      defaultName={dflt(gpo)}>
      <label className="flex items-center gap-2 text-sm">
        <input type="checkbox" checked={keepRead} onChange={(e) => setKeepRead(e.target.checked)} /> Keep Read, so the computer can still fetch the GPO (recommended)
      </label>
      <p className="text-xs text-muted">The change is refused when it would leave nobody with Read or Apply: the GPO would stop applying.</p>
    </GpoChangeDialog>
  );
}

export function BackupNowDialog({ device, gpo, onClose }: Base & { gpo: Gpo }) {
  return (
    <GpoChangeDialog device={device} title={`Back up ${gpo.name}`} label="Back up" onClose={onClose} op={{ action: "gpo_backup", params: { id: gpo.id }, subject: gpo.name }}>
      <p className="text-sm">The backup is kept on the server and restored from the Backups list.</p>
    </GpoChangeDialog>
  );
}

export function LinkAddDialog({ device, gpo, targets, onClose }: Base & { gpo: Gpo; targets: LinkTarget[] }) {
  const [target, setTarget] = useState("");
  const [enforced, setEnforced] = useState(false);
  const [enabled, setEnabled] = useState(true);
  return (
    <GpoChangeDialog device={device} title={`Link ${gpo.name}`} label="Link" valid={target.trim().length > 0} onClose={onClose}
      op={{ action: "link_add", params: { id: gpo.id, target: target.trim(), enabled, enforced, ...expect(gpo) }, subject: `${gpo.name} to ${target.trim()}` }} defaultName={dflt(gpo)}>
      <TextField label="Link to (distinguished name)" value={target} onChange={(e) => setTarget(e.target.value)} list="gpo-targets" required placeholder="OU=Workstations,DC=corp,DC=test" />
      <datalist id="gpo-targets">
        {targets.map((t) => (
          <option key={t.dn} value={t.dn} />
        ))}
      </datalist>
      <label className="flex items-center gap-2 text-sm"><input type="checkbox" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} /> Link enabled</label>
      <label className="flex items-center gap-2 text-sm"><input type="checkbox" checked={enforced} onChange={(e) => setEnforced(e.target.checked)} /> Enforced</label>
    </GpoChangeDialog>
  );
}

export function LinkRemoveDialog({ device, gpo, target, onClose }: Base & { gpo: Gpo; target: string }) {
  return (
    <GpoChangeDialog device={device} title={`Remove the link of ${gpo.name}`} label="Remove link" danger onClose={onClose}
      op={{ action: "link_remove", params: { id: gpo.id, name: gpo.name, target, ...expect(gpo) }, confirmSubject: gpo.name, subject: `${gpo.name} from ${target}` }}>
      <p className="text-sm">Computers and users under <strong>{target}</strong> stop receiving this GPO.</p>
    </GpoChangeDialog>
  );
}

export type LinkEdit = "order" | "enabled" | "enforced";
export function LinkEditDialog({ device, gpo, target, kind, current, onClose }: Base & { gpo: Gpo; target: string; kind: LinkEdit; current: { order: number; enabled: boolean; enforced: boolean } }) {
  const [order, setOrder] = useState(String(current.order));
  const [flag, setFlag] = useState(kind === "enabled" ? !current.enabled : !current.enforced);
  const n = Number(order);
  const params =
    kind === "order" ? { order: n } : kind === "enabled" ? { enabled: flag } : { enforced: flag };
  const titles = { order: "Change the order of the link", enabled: "Enable or disable the link", enforced: "Enforce or release the link" };
  return (
    <GpoChangeDialog device={device} title={titles[kind]} description={target} label="Save" valid={kind !== "order" || (Number.isInteger(n) && n >= 1 && n <= 999)} onClose={onClose}
      op={{ action: `link_${kind}`, params: { id: gpo.id, target, ...params, ...expect(gpo) }, subject: `${gpo.name} at ${target}` }} defaultName={dflt(gpo)}>
      {kind === "order" ? (
        <TextField label="Order (1 is applied last and wins)" value={order} onChange={(e) => setOrder(e.target.value)} inputMode="numeric" />
      ) : (
        <label className="flex items-center gap-2 text-sm">
          <input type="checkbox" checked={flag} onChange={(e) => setFlag(e.target.checked)} /> {kind === "enabled" ? "Link enabled" : "Enforced"}
        </label>
      )}
    </GpoChangeDialog>
  );
}

export function BlockDialog({ device, target, blocked, onClose }: Base & { target: string; blocked: boolean }) {
  return (
    <GpoChangeDialog device={device} title={blocked ? "Allow inheritance" : "Block inheritance"} description={target}
      label={blocked ? "Allow inheritance" : "Block inheritance"} onClose={onClose}
      op={{ action: "inheritance_block", params: { target, blocked: !blocked }, subject: target }}>
      <p className="text-sm">
        {blocked
          ? "GPOs linked above this container apply again, except where they are not enforced and another rule stops them."
          : "GPOs linked above this container stop applying here, unless they are enforced."}
      </p>
    </GpoChangeDialog>
  );
}

/**
 * Restores a backup: the controller cannot take a whole backup in one request, so the console sends it in pieces, each as
 * its own checked step, and then asks for the restore. The server only accepts a backup it holds, by its hash.
 */
export function RestoreDialog({ device, backup, current, onClose }: Base & { backup: GpoBackup; current: Gpo | null }) {
  const client = useQueryClient();
  const [reason, setReason] = useState("");
  const [typed, setTyped] = useState("");
  const [defTyped, setDefTyped] = useState("");
  const [step, setStep] = useState<string | null>(null);
  const [error, setError] = useState<unknown>(null);
  const defaultName = current?.default ? current.name : undefined;
  const name = current?.name ?? backup.gpoName;
  const ok = reason.trim().length >= 10 && typed.trim().toLowerCase() === name.toLowerCase() && (defaultName === undefined || defTyped === defaultName);

  async function go() {
    setError(null);
    try {
      for (let i = 0; i < backup.parts; i++) {
        setStep(`Sending the backup (${i + 1} of ${backup.parts})`);
        const c = await api.get<{ index: number; count: number; chunk: string }>(`/devices/${device.id}/gpo/backups/${backup.id}/chunks/${i}`);
        const out = await runWinmod(device.id, `${MODULE}.gpo_restore_stage`, { backupId: backup.backupId, index: c.index, count: c.count, chunk: c.chunk });
        if (out.failure) throw new Error(failureText(out.failure));
        if (out.lost) throw new Error(out.lost);
      }
      setStep("Restoring");
      const action = `${MODULE}.gpo_restore`;
      const params = {
        id: backup.gpoId, name, backupId: backup.backupId, zipSha256: backup.sha256, parts: backup.parts, reason: reason.trim(),
        ...(current ? expect(current) : {}), ...(defaultName ? { confirmName: defTyped } : {}),
      };
      const out = await runWinmod(device.id, action, params, confirmText(action, name));
      if (out.failure) throw new Error(failureText(out.failure));
      if (out.lost) throw new Error(out.lost);
      await client.invalidateQueries({ predicate: (q) => q.queryKey.includes("gpo") || q.queryKey[0] === "winmod" });
      onClose();
    } catch (e) {
      setError(e);
      setStep(null);
    }
  }

  return (
    <Dialog open onClose={onClose} title={`Restore ${backup.gpoName}`} description={`The backup from ${new Date(backup.createdAt).toLocaleString()}`}>
      <div className="flex flex-col gap-3">
        <Alert tone="warn">
          The GPO&apos;s settings go back to those of the backup. Its links, security filtering and delegation stay as they are. A backup of the
          GPO as it is now is taken first.{current ? "" : " The GPO no longer exists; the restore creates it again."}
        </Alert>
        <TextareaField label="Why" value={reason} onChange={(e) => setReason(e.target.value)} rows={2} maxLength={500} hint="Required, 10 to 500 characters." />
        {defaultName !== undefined && (
          <TextField label={<>This is a Default policy. Type <strong>{defaultName}</strong> in full</>} value={defTyped} onChange={(e) => setDefTyped(e.target.value)} autoComplete="off" />
        )}
        <TextField label={<>Type <strong>{name}</strong> to confirm</>} value={typed} onChange={(e) => setTyped(e.target.value)} autoComplete="off" />
        {step && <p role="status" className="text-sm text-muted">{step}…</p>}
        <InlineError error={error} />
        <div className="flex justify-end gap-2">
          <Button onClick={onClose} disabled={step !== null}>Cancel</Button>
          <Button variant="danger" onClick={() => void go()} loading={step !== null} disabled={!ok}>Restore</Button>
        </div>
      </div>
    </Dialog>
  );
}

export type DetailGpo = GpoDetail;
