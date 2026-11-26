import { useQuery } from "@tanstack/react-query";
import { api } from "../../../api/client";
import type { WinmodResult, WinmodRun } from "../../../api/types";

// Running a Windows Backup action (ADR-0077) and following its run: POST the action, then read the run until it
// ends. A step-up the server asks for is handled by the API client.

const FINISHED = new Set(["succeeded", "failed", "timed_out", "canceled", "expired", "lost"]);
const POLL_MS = 1500;
const GIVE_UP_MS = 4 * 60 * 1000;

export interface Outcome<T> {
  ok: boolean;
  data?: T;
  /** The action's own refusal: busy, module_missing, no_policy, ... */
  code?: string;
  message?: string;
}

/** What each refusal code of the module's scripts says to a person. */
export const BACKUP_FAILURES: Record<string, string> = {
  module_missing: "Windows Server Backup is not installed on this computer.",
  not_offered: "Windows Server Backup is not offered on a desktop.",
  busy: "Windows Server Backup is running another operation. Try again when it has finished.",
  no_policy: "This computer has no backup policy yet. Set the items and the schedule first.",
  no_target: "Name a target volume: this computer has no policy to keep a target from.",
  no_items: "Choose at least one thing to back up.",
  not_running: "Nothing is running.",
  not_a_backup: "The running operation is not a backup.",
  not_a_recovery: "The running operation is a backup, not a restore.",
  disk_changed: "That disk is no longer the one that was chosen. Read the disks again.",
  version_not_found: "That backup version is no longer there. Read the versions again.",
  bad_target: "That restore target is not allowed. Choose another folder.",
  would_leave_none: "That would remove every backup version, which is never done.",
  changed: "The versions changed since the preview. Preview again.",
  unsupported: "This computer cannot install Windows features this way.",
  command_failed: "Windows reported an error.",
};

export function outcomeMessage(o: Outcome<unknown>): string {
  return (o.code && BACKUP_FAILURES[o.code]) || o.message || "The action did not finish.";
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

/** Starts an action on a device and resolves when its run ends. */
export async function runBackup<T>(
  deviceId: string,
  action: string,
  params: Record<string, unknown> = {},
  confirm?: string,
): Promise<Outcome<T>> {
  const run = await api.post<WinmodRun>(`/devices/${deviceId}/winmod/windows_backup.${action}`, {
    params,
    ...(confirm ? { confirm } : {}),
  });
  const until = Date.now() + GIVE_UP_MS;
  for (;;) {
    const r = await api.get<WinmodResult>(`/winmod/runs/${run.runId}`);
    if (r.ok === true) return { ok: true, data: r.data as T };
    if (r.ok === false) return { ok: false, code: r.failure?.code, message: r.failure?.message };
    if (FINISHED.has(r.status)) return { ok: false, message: r.error ?? `The action ended as ${r.status}.` };
    if (Date.now() > until) return { ok: false, message: "The computer did not answer in time." };
    await sleep(POLL_MS);
  }
}

/** A read of the device that runs when the tab opens and again on refresh. */
export function useBackupRead<T>(deviceId: string, action: string, params: Record<string, unknown> = {}, enabled = true) {
  return useQuery<Outcome<T> & { readAt: string }>({
    queryKey: ["backup-read", deviceId, action, JSON.stringify(params)],
    enabled,
    staleTime: 5 * 60 * 1000,
    refetchOnWindowFocus: false,
    queryFn: async () => ({ ...(await runBackup<T>(deviceId, action, params)), readAt: new Date().toISOString() }),
  });
}
