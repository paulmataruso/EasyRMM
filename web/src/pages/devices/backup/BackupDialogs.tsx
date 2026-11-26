import { useState, type ReactNode } from "react";
import type { BackupDisk, BackupPrunePreview, BackupStatus, BackupVersion, Device } from "../../../api/types";
import { ConfirmDialog, Dialog } from "../../../components/Dialog";
import { Alert, Button, Field, Select, Spinner, TextField, TextareaField } from "../../../components/ui";
import { formatDateTime, formatSize } from "../../../lib/format";
import { outcomeMessage, useBackupRead, type Outcome } from "./winmod";

// The dialogs of the Backup tab (ADR-0077). Each one is the confirmation of its action; a tier 3 action also asks for
// a second factor, which the API client puts to the person when the server asks.

type Perform = <T>(action: string, params: Record<string, unknown>, confirm: boolean, done: string) => Promise<Outcome<T>>;

interface Base {
  open: boolean;
  onClose: () => void;
  perform: Perform;
}

function Footer({ onClose, busy, label, disabled, tone }: { onClose: () => void; busy: boolean; label: string; disabled?: boolean; tone?: "danger" }) {
  return (
    <div className="flex justify-end gap-2 pt-1">
      <Button onClick={onClose} disabled={busy}>
        Cancel
      </Button>
      <Button type="submit" variant={tone === "danger" ? "danger" : "primary"} loading={busy} disabled={disabled}>
        {label}
      </Button>
    </div>
  );
}

/** Lines of a textarea to the "|"-joined list the action takes (no path holds a "|"). */
const lines = (s: string) => s.split(/\r?\n/).map((l) => l.trim()).filter(Boolean).join("|");

export function PolicyDialog({ open, onClose, st, perform }: Base & { st: BackupStatus | null }) {
  const [times, setTimes] = useState("21:00");
  const [volumes, setVolumes] = useState("");
  const [files, setFiles] = useState("");
  const [exclude, setExclude] = useState("");
  const [systemState, setSystemState] = useState(true);
  const [bareMetal, setBareMetal] = useState(false);
  const [target, setTarget] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const hasTarget = (st?.targets.length ?? 0) > 0;
  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    const params: Record<string, unknown> = { times: times.replace(/\s+/g, ""), systemState, bareMetal };
    if (volumes.trim()) params.volumes = volumes.replace(/\s+/g, "").split(",").filter(Boolean).join("|");
    if (files.trim()) params.files = lines(files);
    if (exclude.trim()) params.exclude = lines(exclude);
    if (!hasTarget && target.trim()) params.targetVolume = target.trim();
    const o = await perform("policy_set", params, true, "The backup policy was saved.");
    setBusy(false);
    if (o.ok) onClose();
    else setError(outcomeMessage(o));
  }
  return (
    <Dialog open={open} onClose={onClose} title="Set the backup policy" size="lg">
      <form onSubmit={(e) => void submit(e)} className="flex flex-col gap-3">
        <Alert tone="warn">This replaces the current policy. The target is kept.</Alert>
        <TextField label="Times of day" hint="24-hour times separated by commas, up to six, such as 21:00,03:30." value={times} onChange={(e) => setTimes(e.target.value)} required />
        <TextField label="Volumes" hint="Drive letters separated by commas, such as C:,D:." value={volumes} onChange={(e) => setVolumes(e.target.value)} />
        <TextareaField label="Folders" hint="One absolute path per line." value={files} onChange={(e) => setFiles(e.target.value)} />
        <TextareaField label="Exclude" hint="One absolute path per line; needs a folder above." value={exclude} onChange={(e) => setExclude(e.target.value)} />
        <label className="flex items-center gap-2 text-sm">
          <input type="checkbox" checked={systemState} onChange={(e) => setSystemState(e.target.checked)} /> Include the system state
        </label>
        <label className="flex items-center gap-2 text-sm">
          <input type="checkbox" checked={bareMetal} onChange={(e) => setBareMetal(e.target.checked)} /> Include bare-metal recovery
        </label>
        {!hasTarget && (
          <TextField label="Target volume" hint="A formatted local volume, such as E:. A network share or a disk can be set after the policy exists." value={target} onChange={(e) => setTarget(e.target.value)} required />
        )}
        {error && <Alert tone="danger">{error}</Alert>}
        <Footer onClose={onClose} busy={busy} label="Save policy" />
      </form>
    </Dialog>
  );
}

export function VolumeDialog({ open, onClose, perform }: Base) {
  const [volume, setVolume] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    const o = await perform("target_volume_set", { volume: volume.trim() }, true, "The backup target was changed.");
    setBusy(false);
    if (o.ok) onClose();
    else setError(outcomeMessage(o));
  }
  return (
    <Dialog open={open} onClose={onClose} title="Back up to a local volume">
      <form onSubmit={(e) => void submit(e)} className="flex flex-col gap-3">
        <TextField label="Volume" hint="A drive letter such as E:, or a volume path. The volume must already be formatted." value={volume} onChange={(e) => setVolume(e.target.value)} required />
        {error && <Alert tone="danger">{error}</Alert>}
        <Footer onClose={onClose} busy={busy} label="Set target" />
      </form>
    </Dialog>
  );
}

export function ShareDialog({ open, onClose, device, perform }: Base & { device: Device }) {
  const [unc, setUnc] = useState(`\\\\server\\backups\\${device.name}`);
  const [user, setUser] = useState("");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    const o = await perform("target_network_set", { unc: unc.trim(), user: user.trim(), password }, true, "The backup target was changed.");
    setBusy(false);
    if (o.ok) {
      setPassword("");
      onClose();
    } else setError(outcomeMessage(o));
  }
  return (
    <Dialog open={open} onClose={() => { setPassword(""); onClose(); }} title="Back up to a network share">
      <form onSubmit={(e) => void submit(e)} className="flex flex-col gap-3" autoComplete="off">
        <Alert tone="warn">
          Windows keeps one backup per computer in a shared folder: the next backup overwrites the last one, and a
          failed run can leave none. Use a sub-folder named for this computer (required below).
        </Alert>
        <TextField label="Share and sub-folder" hint="\\server\share\folder. The sub-folder is required." value={unc} onChange={(e) => setUnc(e.target.value)} required />
        <TextField label="Account" hint="DOMAIN\user or user@domain." value={user} onChange={(e) => setUser(e.target.value)} required autoComplete="off" />
        <TextField label="Password" type="password" hint="Sent once, sealed, and kept only by Windows inside its backup policy. It cannot be read back." value={password} onChange={(e) => setPassword(e.target.value)} required autoComplete="new-password" />
        {error && <Alert tone="danger">{error}</Alert>}
        <Footer onClose={onClose} busy={busy} label="Set target" disabled={!password} />
      </form>
    </Dialog>
  );
}

export function DiskDialog({ open, onClose, device, perform }: Base & { device: Device }) {
  const disks = useBackupRead<{ disks: BackupDisk[] }>(device.id, "disks", {}, open);
  const [pick, setPick] = useState("");
  const [typed, setTyped] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const list = disks.data?.ok ? (disks.data.data?.disks ?? []) : [];
  const chosen = list.find((d) => String(d.number) === pick);
  async function submit(e: React.FormEvent) {
    e.preventDefault();
    if (!chosen) return;
    setBusy(true);
    setError(null);
    const o = await perform("target_disk_set", { diskNumber: chosen.number, diskId: chosen.id }, true, "The backup target was changed.");
    setBusy(false);
    if (o.ok) onClose();
    else setError(outcomeMessage(o));
  }
  return (
    <Dialog open={open} onClose={onClose} title="Back up to a whole disk">
      <form onSubmit={(e) => void submit(e)} className="flex flex-col gap-3">
        <Alert tone="danger">
          Windows formats the disk and permanently erases everything on it. Only choose a disk that holds nothing you
          need. This needs a second factor.
        </Alert>
        {disks.isFetching ? (
          <Spinner />
        ) : (
          <Field label="Disk" htmlFor="backup-disk">
            <Select id="backup-disk" value={pick} onChange={(e) => setPick(e.target.value)}>
              <option value="">Choose a disk</option>
              {list.map((d) => (
                <option key={d.id} value={String(d.number)}>
                  Disk {d.number}: {d.name || "unnamed"} ({formatSize(d.sizeBytes)}){d.hasData ? " - has volumes" : ""}
                </option>
              ))}
            </Select>
          </Field>
        )}
        {disks.data && !disks.data.ok && <Alert tone="warn">{outcomeMessage(disks.data)}</Alert>}
        {chosen && (
          <TextField label={`Type ${device.name} to erase disk ${chosen.number}`} value={typed} onChange={(e) => setTyped(e.target.value)} autoComplete="off" />
        )}
        {error && <Alert tone="danger">{error}</Alert>}
        <Footer onClose={onClose} busy={busy} label="Format and use" tone="danger" disabled={!chosen || typed.trim() !== device.name} />
      </form>
    </Dialog>
  );
}

export function RestoreDialog({ open, onClose, device, perform, canDestroy }: Base & { device: Device; canDestroy: boolean }) {
  const versions = useBackupRead<{ versions: BackupVersion[] }>(device.id, "versions", {}, open);
  const [version, setVersion] = useState("");
  const [source, setSource] = useState("");
  const [target, setTarget] = useState("");
  const [recursive, setRecursive] = useState(true);
  const [overwrite, setOverwrite] = useState(false);
  const [typed, setTyped] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const list = versions.data?.ok ? (versions.data.data?.versions ?? []) : [];
  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    const params: Record<string, unknown> = { version, source: source.trim(), recursive };
    if (!overwrite && target.trim()) params.targetPath = target.trim();
    const o = await perform(
      overwrite ? "restore_files_overwrite" : "restore_files",
      params,
      true,
      "The restore was started. Progress shows in Status.",
    );
    setBusy(false);
    if (o.ok) onClose();
    else setError(outcomeMessage(o));
  }
  return (
    <Dialog open={open} onClose={onClose} title="Restore files" size="lg">
      <form onSubmit={(e) => void submit(e)} className="flex flex-col gap-3">
        {versions.isFetching ? (
          <Spinner />
        ) : (
          <Field label="Backup version" htmlFor="backup-version">
            <Select id="backup-version" value={version} onChange={(e) => setVersion(e.target.value)} required>
              <option value="">Choose a version</option>
              {list.map((v) => (
                <option key={v.id} value={v.id}>
                  {v.time ? formatDateTime(v.time) : v.id}
                  {v.sizeBytes ? ` (${formatSize(v.sizeBytes)})` : ""}
                </option>
              ))}
            </Select>
          </Field>
        )}
        {versions.data && !versions.data.ok && <Alert tone="warn">{outcomeMessage(versions.data)}</Alert>}
        <TextField label="File or folder to restore" hint="The absolute path as it was when backed up, such as D:\Data\report.xlsx. One path at a time." value={source} onChange={(e) => setSource(e.target.value)} required />
        <label className="flex items-center gap-2 text-sm">
          <input type="checkbox" checked={recursive} onChange={(e) => setRecursive(e.target.checked)} /> Include what is inside a folder
        </label>
        {!overwrite && (
          <TextField label="Restore into" hint="Leave empty for a new folder, EasyRMM-Restore, on the system drive. A file that exists keeps its copy: the restored one is renamed." value={target} onChange={(e) => setTarget(e.target.value)} />
        )}
        {canDestroy && (
          <label className="flex items-center gap-2 text-sm">
            <input type="checkbox" checked={overwrite} onChange={(e) => setOverwrite(e.target.checked)} /> Restore over the originals
          </label>
        )}
        {overwrite && (
          <Alert tone="danger">
            Files that exist are overwritten with the backed-up version. This needs a second factor.
            <TextField className="mt-2" label={`Type ${device.name} to confirm`} value={typed} onChange={(e) => setTyped(e.target.value)} autoComplete="off" />
          </Alert>
        )}
        {error && <Alert tone="danger">{error}</Alert>}
        <Footer onClose={onClose} busy={busy} label="Restore" tone={overwrite ? "danger" : undefined} disabled={!version || !source.trim() || (overwrite && typed.trim() !== device.name)} />
      </form>
    </Dialog>
  );
}

export function PruneDialog({ open, onClose, device, perform }: Base & { device: Device }) {
  const [keep, setKeep] = useState("3");
  const [mode, setMode] = useState<"keep" | "oldest">("keep");
  const [preview, setPreview] = useState<BackupPrunePreview | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const params = () => (mode === "keep" ? { keep: Number(keep) } : {});
  async function look() {
    setBusy(true);
    setError(null);
    setPreview(null);
    const o = await perform<BackupPrunePreview>("versions_prune_preview", params(), false, "Preview ready.");
    setBusy(false);
    if (o.ok && o.data) setPreview(o.data);
    else setError(outcomeMessage(o));
  }
  const close = () => {
    setPreview(null);
    onClose();
  };
  const body: ReactNode = (
    <div className="flex flex-col gap-3">
      <Alert tone="danger">Removing backup versions cannot be undone. The last version is never removed.</Alert>
      <Field label="What to remove" htmlFor="prune-mode">
        <Select id="prune-mode" value={mode} onChange={(e) => { setMode(e.target.value as "keep" | "oldest"); setPreview(null); }}>
          <option value="keep">Keep only the newest versions</option>
          <option value="oldest">Remove the oldest version</option>
        </Select>
      </Field>
      {mode === "keep" && (
        <TextField label="Versions to keep" type="number" min={1} max={365} value={keep} onChange={(e) => { setKeep(e.target.value); setPreview(null); }} />
      )}
      <div>
        <Button onClick={() => void look()} loading={busy && !preview}>
          Preview what would be removed
        </Button>
      </div>
      {error && <Alert tone="danger">{error}</Alert>}
      {preview && (
        <p className="text-sm">
          {preview.sets.length === 0
            ? `Nothing to remove (${preview.total} versions).`
            : `${preview.sets.length} of ${preview.total} versions would be removed: ${preview.sets.map((s) => (s.time ? formatDateTime(s.time) : s.id)).join(", ")}.`}
        </p>
      )}
    </div>
  );
  return (
    <ConfirmDialog
      open={open}
      onClose={close}
      title="Remove old backup versions"
      tone="danger"
      confirmLabel="Remove versions"
      confirmText={preview && preview.sets.length > 0 ? device.name : "preview first"}
      loading={busy && !!preview}
      error={undefined}
      onConfirm={() => {
        if (!preview || preview.sets.length === 0) return;
        setBusy(true);
        void perform("versions_prune", { ...params(), expect: preview.sets.length }, true, "The old versions were removed.").then((o) => {
          setBusy(false);
          if (o.ok) close();
          else setError(outcomeMessage(o));
        });
      }}
    >
      {body}
    </ConfirmDialog>
  );
}
