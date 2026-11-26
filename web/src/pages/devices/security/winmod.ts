import { api } from "../../../api/client";
import type { WinmodResult, WinmodRun } from "../../../api/types";
import { RUN_POLL_MS, useWinmodRead } from "../modules/winmod";

const FINISHED = new Set(["succeeded", "failed", "timed_out", "canceled", "expired", "lost"]);

/** Why a module action ended without a result, for people. */
export class ActionFailed extends Error {
  code: string;
  constructor(code: string, message: string) {
    super(message);
    this.code = code;
  }
}

/**
 * Runs one module action on a device and waits for its typed result: the run is started with POST, then followed until
 * it finishes. A refusal by the server (a confirmation, a step-up, a policy) is thrown as the API client throws it; a
 * run that reported a failure is thrown as ActionFailed with the script's own code (`managed_by_policy`,
 * `protected_exclusion`, `ours_not_covered`, ...). `confirm` is the typed confirmation of a change.
 */
export async function runAction<T>(
  deviceId: string,
  action: string,
  params: Record<string, unknown> | undefined,
  confirm?: string,
  options: { pollMs?: number; maxMs?: number } = {},
): Promise<{ data: T; finishedAt: string | null }> {
  const body: Record<string, unknown> = { params: params ?? {} };
  if (confirm) body.confirm = confirm;
  const run = await api.post<WinmodRun>(`/devices/${deviceId}/winmod/defender.${action}`, body);
  const pollMs = options.pollMs ?? RUN_POLL_MS;
  const deadline = Date.now() + (options.maxMs ?? 30 * 60_000);
  for (;;) {
    const r = await api.get<WinmodResult>(`/winmod/runs/${run.runId}`);
    if (r.ok === true) return { data: r.data as T, finishedAt: r.finishedAt };
    if (r.ok === false) throw new ActionFailed(r.failure?.code ?? "failed", r.failure?.message ?? "The action failed.");
    if (FINISHED.has(r.status)) throw new ActionFailed(r.status, r.error ?? `The action ended as ${r.status}.`);
    if (Date.now() > deadline) throw new ActionFailed("timed_out", "The action is still running; check the result later.");
    await new Promise((resolve) => setTimeout(resolve, pollMs));
  }
}

/** The state of a read panel: the last result, when it was read, and whether a new read is on its way. */
export interface Read<T> {
  data: T | null;
  asOf: string | null;
  /** No result yet, stored or new: the panel shows its skeleton. */
  loading: boolean;
  /** A new read is on its way; what is shown is the last result. */
  refreshing: boolean;
  error: Error | null;
  /** Reads again now (after a change this panel made). */
  load: () => void;
}

/**
 * A read action on a device. It runs by itself when the panel opens, shows the stored result at once, and keeps it
 * fresh while the panel is open (the shared module read, ADR-0073 section 5); there is no button for it.
 */
export function useRead<T>(deviceId: string, action: string): Read<T> {
  const q = useWinmodRead<T>(deviceId, `defender.${action}`, {});
  const o = q.data;
  const error = o?.failure ? new ActionFailed(o.failure.code, o.failure.message) : o?.lost && !o.data ? new ActionFailed("lost", o.lost) : q.error instanceof Error ? q.error : null;
  return {
    data: o?.data ?? null,
    asOf: o?.data ? o.finishedAt : null,
    loading: o === undefined && !q.error,
    refreshing: q.isFetching,
    error,
    load: () => void q.refetch(),
  };
}
