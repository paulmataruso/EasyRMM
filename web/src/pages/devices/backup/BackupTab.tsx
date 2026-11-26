import { useEffect, useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { Play, Square } from "lucide-react";
import { api } from "../../../api/client";
import { useApi } from "../../../api/hooks";
import type {
  BackupJobs,
  BackupSensitive,
  BackupStatus,
  Device,
  DeviceRoles,
} from "../../../api/types";
import { useAuth } from "../../../auth/AuthContext";
import { useToast } from "../../../components/Toast";
import { ConfirmDialog } from "../../../components/Dialog";
import { Alert, Badge, Button, Card, InlineError, KeyValueList, Spinner, type Tone } from "../../../components/ui";
import { formatDateTime, formatRelative, formatSize } from "../../../lib/format";
import { ModuleTab } from "../modules/ModuleTab";
import { SkeletonKeyValue, SkeletonTable } from "../modules/skeletons";
import {
  PolicyDialog,
  PruneDialog,
  RestoreDialog,
  ShareDialog,
  VolumeDialog,
  DiskDialog,
} from "./BackupDialogs";
import { outcomeMessage, runBackup, useBackupRead, type Outcome } from "./winmod";

const KIND_LABEL: Record<string, string> = { volume: "Local volume", disk: "Whole disk", network: "Network share" };

/** A result code of Windows (HRESULT) as Windows writes it. */
export function hresult(v: number | null): string {
  return v === null ? "—" : `0x${(v >>> 0).toString(16).toUpperCase().padStart(8, "0")}`;
}

type Dialog = null | "policy" | "volume" | "share" | "disk" | "restore" | "prune" | "remove" | "stop-restore" | "vss" | "install";

/**
 * The device page's "Backup" tab (ADR-0077). On a server it manages Windows Server Backup. A desktop is not managed:
 * Windows 11's Backup app has no management interface, and the tab says so.
 */
export function BackupTab({ device }: { device: Device }) {
  const { can } = useAuth();
  const toast = useToast();
  const client = useQueryClient();
  const roles = useApi<DeviceRoles>(`/devices/${device.id}/roles`);
  const role = roles.data?.roles.find((r) => r.module === "windows_backup");
  const notInstalled = role?.state === "not_installed";
  const status = useBackupRead<BackupStatus>(device.id, "status", {}, !notInstalled, 30);
  const [dialog, setDialog] = useState<Dialog>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const canManage = can("backup.manage");
  const canDestroy = can("backup.destroy");
  const canSensitive = can("backup.view_sensitive");
  const online = device.online;
  const st = status.data?.ok ? (status.data.data ?? null) : null;
  const desktop = status.data?.ok === false && status.data.code === "not_offered";

  const refresh = () => {
    void client.invalidateQueries({ queryKey: ["winmod", device.id] });
  };

  /** Runs an action, tells the result, and reads the state again. */
  async function perform<T>(action: string, params: Record<string, unknown>, confirm: boolean, done: string): Promise<Outcome<T>> {
    setBusy(action);
    setError(null);
    try {
      const o = await runBackup<T>(device.id, action, { device: device.name, ...params }, confirm ? `windows_backup.${action}:${device.name}` : undefined);
      if (o.ok) {
        toast.success(done);
        refresh();
      } else {
        setError(outcomeMessage(o));
      }
      return o;
    } catch (e) {
      setError(e instanceof Error ? e.message : "The action could not be started.");
      return { ok: false };
    } finally {
      setBusy(null);
    }
  }

  const unavailable = !online ? "This computer is offline. What is shown was read earlier; actions wait until it is back." : undefined;

  if (desktop) return <DesktopCard device={device} />;

  return (
    <ModuleTab
      name="Windows Backup"
      asOf={st ? (status.data?.readAt || null) : null}
      refreshing={status.isFetching}
      loading={status.data === undefined && !notInstalled && !status.error}
      skeleton={
        <>
          <SkeletonKeyValue title="Status" rows={5} />
          <SkeletonKeyValue title="Policy" rows={4} />
          <SkeletonTable title="Backup versions" columns={3} rows={3} />
        </>
      }
      offline={status.offline}
      unavailable={unavailable}
    >
      <InlineError error={status.error} />
      {error && <Alert tone="danger">{error}</Alert>}
      {status.data && !status.data.ok && !desktop && !notInstalled && <Alert tone="warn">{outcomeMessage(status.data)}</Alert>}

      {notInstalled && (
        <Card title="Windows Server Backup is not installed">
          <p className="text-sm text-muted">
            This server does not have the Windows Server Backup feature. Installing it changes the server and needs a
            second factor. A restart may be needed.
          </p>
          <div className="mt-3">
            <Button
              variant="primary"
              disabled={!online || !canDestroy}
              title={!canDestroy ? "Installing a feature needs the backup.destroy permission." : undefined}
              onClick={() => setDialog("install")}
            >
              Install Windows Server Backup
            </Button>
          </div>
        </Card>
      )}
      {st && !st.installed && (
        <Card title="Windows Server Backup is not installed">
          <p className="text-sm text-muted">The feature is missing, so there is nothing to read yet.</p>
        </Card>
      )}

      {st?.installed && (
        <>
          <StatusPanel device={device} st={st} canManage={canManage && online} busy={busy} perform={perform} />
          <PolicyPanel st={st} canManage={canManage && online} canDestroy={canDestroy && online} onDialog={setDialog} />
          <TargetsPanel device={device} st={st} canManage={canManage && online} canDestroy={canDestroy && online} canSensitive={canSensitive} onDialog={setDialog} />
          <VersionsPanel st={st} canManage={canManage && online} canDestroy={canDestroy && online} onDialog={setDialog} />
          <Card title="Not shown here">
            <p className="text-sm text-muted">
              Restoring a volume, the system state or a whole server, and browsing inside a backup, are not offered
              from the console: run them from the recovery console on the server. Windows&apos; backup event log is not
              read yet, so a failure shows when the next status read sees it.
            </p>
          </Card>
        </>
      )}
      {status.isPending && !notInstalled && <Spinner />}

      <PolicyDialog open={dialog === "policy"} onClose={() => setDialog(null)} st={st} perform={perform} />
      <VolumeDialog open={dialog === "volume"} onClose={() => setDialog(null)} perform={perform} />
      <ShareDialog open={dialog === "share"} onClose={() => setDialog(null)} device={device} perform={perform} />
      <DiskDialog open={dialog === "disk"} onClose={() => setDialog(null)} device={device} perform={perform} />
      <RestoreDialog open={dialog === "restore"} onClose={() => setDialog(null)} device={device} perform={perform} canDestroy={canDestroy} />
      <PruneDialog open={dialog === "prune"} onClose={() => setDialog(null)} device={device} perform={perform} />
      <ConfirmDialog
        open={dialog === "remove"}
        onClose={() => setDialog(null)}
        title="Remove the backup policy"
        tone="danger"
        confirmLabel="Remove policy"
        confirmText={device.name}
        loading={busy === "policy_remove"}
        onConfirm={() => void perform("policy_remove", {}, true, "The backup policy was removed.").then(() => setDialog(null))}
      >
        This stops all scheduled backups of this computer. Backups already made are kept. It needs a second factor.
      </ConfirmDialog>
      <ConfirmDialog
        open={dialog === "vss"}
        onClose={() => setDialog(null)}
        title={st?.vssFull ? "Go back to copy backups" : "Make backups full backups"}
        tone="danger"
        confirmLabel="Change"
        confirmText={device.name}
        loading={busy === "vss_full_set"}
        onConfirm={() => void perform("vss_full_set", { enabled: !st?.vssFull }, true, "The backup type was changed.").then(() => setDialog(null))}
      >
        {st?.vssFull
          ? "Copy backups leave other backup products' incremental chains alone."
          : "Microsoft warns that a full backup can break the incremental chain of another backup product that protects this server. A copy backup does not. Change this only if Windows Server Backup is the only backup product here."}
      </ConfirmDialog>
      <ConfirmDialog
        open={dialog === "stop-restore"}
        onClose={() => setDialog(null)}
        title="Stop the restore"
        confirmLabel="Stop restore"
        loading={busy === "stop_recovery"}
        onConfirm={() => void perform("stop_recovery", {}, true, "The restore was stopped.").then(() => setDialog(null))}
      >
        Stopping a restore may leave files partly restored.
      </ConfirmDialog>
      <ConfirmDialog
        open={dialog === "install"}
        onClose={() => setDialog(null)}
        title="Install Windows Server Backup"
        confirmLabel="Install"
        confirmText={device.name}
        loading={busy === "feature_install"}
        onConfirm={() =>
          void perform<{ restartNeeded: boolean }>("feature_install", {}, true, "Windows Server Backup was installed.").then((o) => {
            setDialog(null);
            if (o.ok) {
              void api.post(`/devices/${device.id}/roles/rescan`).catch(() => undefined);
              if (o.data?.restartNeeded) toast.success("The server needs a restart before the feature can be used.");
            }
          })
        }
      >
        This adds a Windows feature to the server. It needs a second factor, and the server may need a restart.
      </ConfirmDialog>
    </ModuleTab>
  );
}

type Perform = <T>(action: string, params: Record<string, unknown>, confirm: boolean, done: string) => Promise<Outcome<T>>;

function stateBadge(st: BackupStatus): { label: string; tone: Tone } {
  if (!st.configured) return { label: "Not configured", tone: "warn" };
  if (st.lastFailure && (!st.lastSuccess || st.lastFailure > st.lastSuccess)) return { label: "Last backup failed", tone: "danger" };
  if (!st.lastSuccess) return { label: "No backup yet", tone: "warn" };
  return { label: "Healthy", tone: "ok" };
}

function StatusPanel({ device, st, canManage, busy, perform }: { device: Device; st: BackupStatus; canManage: boolean; busy: string | null; perform: Perform }) {
  const s = stateBadge(st);
  // Progress is read every 5 seconds while a job runs, and only then (ADR-0077, section 2).
  const [job, setJob] = useState<BackupJobs | null>(null);
  useEffect(() => {
    if (!st.running) {
      setJob(null);
      return;
    }
    let live = true;
    const tick = async () => {
      const o = await runBackup<BackupJobs>(device.id, "job", { previous: 0 }).catch(() => null);
      if (live && o?.ok && o.data) setJob(o.data);
    };
    void tick();
    const t = setInterval(() => void tick(), 5000);
    return () => {
      live = false;
      clearInterval(t);
    };
  }, [st.running, device.id]);
  const running = job?.jobs[0] ?? st.job;
  return (
    <Card
      title="Status"
      actions={
        <div className="flex gap-2">
          <Button
            size="sm"
            variant="primary"
            icon={<Play className="size-3.5" aria-hidden />}
            disabled={!canManage || !st.configured || st.running}
            loading={busy === "run_now"}
            title={!st.configured ? "Set a backup policy first." : st.running ? "A job is running." : undefined}
            onClick={() => void perform("run_now", {}, false, "The backup was started.")}
          >
            Run now
          </Button>
          <Button
            size="sm"
            icon={<Square className="size-3.5" aria-hidden />}
            disabled={!canManage || !st.running}
            loading={busy === "stop"}
            onClick={() => void perform("stop", {}, false, "The backup was stopped.")}
          >
            Stop
          </Button>
        </div>
      }
    >
      <KeyValueList
        items={[
          ["State", <Badge key="s" tone={s.tone}>{s.label}</Badge>],
          ["Last successful backup", st.lastSuccess ? <span title={formatDateTime(st.lastSuccess)}>{formatRelative(st.lastSuccess)}</span> : "Never"],
          [
            "Last failed backup",
            st.lastFailure ? (
              <span key="f" title={formatDateTime(st.lastFailure)}>
                {formatRelative(st.lastFailure)} ({hresult(st.lastResultHR)})
              </span>
            ) : (
              "None"
            ),
          ],
          ["Next backup", st.nextRun ? formatDateTime(st.nextRun) : "Not scheduled"],
          [
            "Running now",
            st.running && running ? `${running.type} ${running.percent === null ? "" : `${running.percent}%`}`.trim() : st.running ? "Yes" : "No",
          ],
        ]}
      />
    </Card>
  );
}

function PolicyPanel({ st, canManage, canDestroy, onDialog }: { st: BackupStatus; canManage: boolean; canDestroy: boolean; onDialog: (d: Dialog) => void }) {
  return (
    <Card
      title="Schedule and items"
      actions={
        <div className="flex gap-2">
          <Button size="sm" disabled={!canManage || st.running} onClick={() => onDialog("policy")}>
            {st.configured ? "Change" : "Set up"}
          </Button>
          <Button size="sm" disabled={!canDestroy || st.running} onClick={() => onDialog("vss")} title="Needs a second factor">
            {st.vssFull ? "Use copy backups" : "Use full backups"}
          </Button>
          <Button size="sm" variant="danger-ghost" disabled={!canDestroy || !st.configured || st.running} onClick={() => onDialog("remove")} title="Needs a second factor">
            Remove policy
          </Button>
        </div>
      }
    >
      {st.configured ? (
        <KeyValueList
          items={[
            ["Times of day", st.schedule.length ? st.schedule.join(", ") : "Not scheduled"],
            ["Volumes", String(st.volumeCount)],
            ["Folders", String(st.fileSpecCount)],
            ["System state", st.systemState ? "Included" : "Not included"],
            ["Bare-metal recovery", st.bareMetal ? "Included" : "Not included"],
            ["Backup type", st.vssFull ? <Badge key="t" tone="warn">Full backup</Badge> : "Copy backup (default)"],
          ]}
        />
      ) : (
        <p className="text-sm text-muted">There is no backup policy on this server. Set one up to schedule backups.</p>
      )}
    </Card>
  );
}

function TargetsPanel({ device, st, canManage, canDestroy, canSensitive, onDialog }: { device: Device; st: BackupStatus; canManage: boolean; canDestroy: boolean; canSensitive: boolean; onDialog: (d: Dialog) => void }) {
  const [show, setShow] = useState(false);
  const detail = useBackupRead<BackupSensitive>(device.id, "sensitive", {}, show && canSensitive);
  return (
    <Card
      title="Targets and space"
      actions={
        <div className="flex gap-2">
          <Button size="sm" disabled={!canManage || !st.configured || st.running} onClick={() => onDialog("volume")}>Local volume</Button>
          <Button size="sm" disabled={!canManage || !st.configured || st.running} onClick={() => onDialog("share")}>Network share</Button>
          <Button size="sm" variant="danger-ghost" disabled={!canDestroy || !st.configured || st.running} onClick={() => onDialog("disk")} title="Formats the disk. Needs a second factor.">
            Whole disk
          </Button>
        </div>
      }
    >
      {st.targets.length === 0 ? (
        <p className="text-sm text-muted">No target is set.</p>
      ) : (
        <ul className="flex flex-col gap-2 text-sm">
          {st.targets.map((t, i) => (
            <li key={i} className="flex flex-wrap items-center gap-2">
              <span className="font-medium">{KIND_LABEL[t.kind] ?? t.kind}</span>
              <Badge tone={t.online ? "ok" : "danger"}>{t.online ? "Online" : "Not found"}</Badge>
              {t.freeBytes !== null && t.totalBytes !== null && (
                <span className="text-muted">
                  {formatSize(t.freeBytes)} free of {formatSize(t.totalBytes)}
                </span>
              )}
              {canSensitive && show && detail.data?.ok && detail.data.data?.targets[i] && (
                <span className="font-mono text-xs">{detail.data.data.targets[i]!.path}</span>
              )}
            </li>
          ))}
        </ul>
      )}
      {canSensitive && st.targets.length > 0 && (
        <div className="mt-3">
          <Button size="sm" variant="ghost" onClick={() => setShow((v) => !v)}>
            {show ? "Hide paths and folders" : "Show paths and folders"}
          </Button>
          {show && detail.data?.ok && detail.data.data && (
            <KeyValueList
              className="mt-2"
              items={[
                ["Included", detail.data.data.include.join(", ") || "—"],
                ["Excluded", detail.data.data.exclude.join(", ") || "—"],
              ]}
            />
          )}
        </div>
      )}
      <p className="mt-3 text-xs text-muted">
        A share keeps one backup per computer: without a sub-folder the next backup overwrites the last, and a failed
        run can leave none. A password set for a share cannot be read back; set it again to change it.
      </p>
    </Card>
  );
}

function VersionsPanel({ st, canManage, canDestroy, onDialog }: { st: BackupStatus; canManage: boolean; canDestroy: boolean; onDialog: (d: Dialog) => void }) {
  return (
    <Card
      title="Versions and restore"
      actions={
        <div className="flex gap-2">
          <Button size="sm" disabled={!canManage || st.running || !st.versionCount} onClick={() => onDialog("restore")}>
            Restore files
          </Button>
          <Button size="sm" variant="danger-ghost" disabled={!canDestroy || st.running || !st.versionCount} onClick={() => onDialog("prune")} title="Needs a second factor">
            Remove old versions
          </Button>
          <Button size="sm" disabled={!canManage || !st.running} onClick={() => onDialog("stop-restore")}>
            Stop a restore
          </Button>
        </div>
      }
    >
      <KeyValueList
        items={[
          ["Versions", st.versionCount === null ? "—" : String(st.versionCount)],
          ["Oldest", st.oldestVersion ? formatDateTime(st.oldestVersion) : "—"],
          ["Newest", st.newestVersion ? formatDateTime(st.newestVersion) : "—"],
        ]}
      />
    </Card>
  );
}

/** A desktop is watched, not managed (ADR-0077): what Windows allows, and what it does not. */
function DesktopCard({ device }: { device: Device }) {
  return (
    <ModuleTab name="Windows Backup" asOf={null}>
      <Card title="What Windows allows on a desktop">
        <div className="flex max-w-2xl flex-col gap-2 text-sm">
          <p>
            <strong>{device.name}</strong> is a desktop. The Windows 11 Backup app, which saves settings and folders to
            OneDrive, has no management interface, so EasyRMM can neither configure nor read it.
          </p>
          <p className="text-muted">
            File History is set up by each user for their own account and cannot be managed from here. The older System
            Image Backup (Backup and Restore, Windows 7) is deprecated by Microsoft; EasyRMM does not manage it, pending
            a test on a real Windows 11 computer.
          </p>
          <p className="text-muted">Servers running Windows Server Backup are managed in full.</p>
        </div>
      </Card>
    </ModuleTab>
  );
}
