import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../../../api/client";
import type { WinmodResult, WinmodRun } from "../../../api/types";

/** How often a run in flight is looked at: fast, because a person is waiting; nothing is polled once it ends. */
export const RUN_POLL_MS = 700;
/** How often an open tab re-asks for its reads. The server answers from its stored result and starts a read only when that is old. */
export const KEEP_FRESH_MS = 30_000;
/** How long a read is followed before the tab says the computer did not answer. */
const READ_GIVE_UP_MS = 3 * 60_000;

// How a module's tab runs its actions (ADR-0073): start one, follow its run until the computer has answered, and
// read the typed result. Shared by the role modules (ADR-0076); Defender's tab does the same by hand.

const FINISHED = new Set(["succeeded", "failed", "timed_out", "canceled", "expired", "lost"]);

/** What a finished action says: its data, or why it did not do what was asked. */
export interface WinmodOutcome<T> {
  data: T | null;
  failure: { code: string; message: string } | null;
  /** The run ended without a result (offline, timed out, expired). */
  lost: string | null;
  finishedAt: string | null;
  /** The computer is not checking in: what is shown is the last result, with its age. */
  offline?: boolean;
}

const wait = (ms: number) => new Promise((r) => setTimeout(r, ms));

/** Starts an action and waits for its result. A destructive action sends its `confirm` text. */
export async function runWinmod<T>(
  deviceId: string,
  action: string,
  params: Record<string, unknown> = {},
  confirm?: string,
  pollMs = RUN_POLL_MS,
): Promise<WinmodOutcome<T>> {
  const run = await api.post<WinmodRun>(`/devices/${deviceId}/winmod/${action}`, confirm ? { params, confirm } : { params });
  for (let i = 0; i < 200; i++) {
    const r = await api.get<WinmodResult>(`/winmod/runs/${run.runId}`);
    if (r.ok !== undefined || FINISHED.has(r.status)) {
      if (r.ok === true) return { data: r.data as T, failure: null, lost: null, finishedAt: r.finishedAt };
      if (r.ok === false) return { data: null, failure: r.failure ?? { code: "failed", message: "The action failed." }, lost: null, finishedAt: r.finishedAt };
      return { data: null, failure: null, lost: r.error ?? `The action ended as ${r.status}.`, finishedAt: r.finishedAt };
    }
    await wait(pollMs);
  }
  throw new Error("The computer did not answer in time.");
}

/** What the server answers a tab's read: the last stored result with its age, and the read it started when that was old. */
export interface ReadSnapshot {
  action: string;
  takenAt: string | null;
  stale: boolean;
  data: unknown;
  refreshing: boolean;
  offline: boolean;
  runId?: string;
}

export const OFFLINE_TEXT = "This computer is not checking in, so it cannot be read now.";

/**
 * Reads a module's state for a tab, with no click (ADR-0073 section 5): the server returns the last stored result at once,
 * with its age, and starts a new read itself when that is older than about two minutes or missing. `onStored` is
 * called with the stored result before the new one is waited for, so the page fills at once; the returned outcome is
 * the new result. Never more than one read per device and action is in flight: the server names the one on its way.
 */
export async function readModule<T>(
  deviceId: string,
  action: string,
  params: Record<string, unknown>,
  opts: { signal?: AbortSignal; onStored?: (o: WinmodOutcome<T>) => void; pollMs?: number; maxAgeSeconds?: number } = {},
): Promise<WinmodOutcome<T>> {
  const snap = await api.post<ReadSnapshot>(`/devices/${deviceId}/winmod-read/${action}`, { params, ...(opts.maxAgeSeconds ? { maxAgeSeconds: opts.maxAgeSeconds } : {}) });
  const stored: WinmodOutcome<T> | null =
    snap.data !== null && snap.data !== undefined ? { data: snap.data as T, failure: null, lost: null, finishedAt: snap.takenAt, offline: snap.offline } : null;
  if (!snap.runId || snap.offline) {
    return stored ?? { data: null, failure: null, lost: snap.offline ? OFFLINE_TEXT : "The computer has not been read yet.", finishedAt: null, offline: snap.offline };
  }
  if (stored) opts.onStored?.(stored);
  const until = Date.now() + READ_GIVE_UP_MS;
  for (;;) {
    if (opts.signal?.aborted) throw new DOMException("The read was stopped.", "AbortError");
    const r = await api.get<WinmodResult>(`/winmod/runs/${snap.runId}`);
    if (r.ok === true) return { data: r.data as T, failure: null, lost: null, finishedAt: r.finishedAt, offline: false };
    if (r.ok === false) return { data: stored?.data ?? null, failure: r.failure ?? { code: "failed", message: "The read failed." }, lost: null, finishedAt: r.finishedAt };
    if (FINISHED.has(r.status)) return { data: stored?.data ?? null, failure: null, lost: r.error ?? `The read ended as ${r.status}.`, finishedAt: r.finishedAt };
    if (Date.now() > until) return { data: stored?.data ?? null, failure: null, lost: "The computer did not answer in time.", finishedAt: null };
    await wait(opts.pollMs ?? RUN_POLL_MS);
  }
}

/** The confirmation text a destructive action takes: "<action>:<subject>". */
export const confirmText = (action: string, subject: string) => `${action}:${subject}`;

/** Messages for the failure codes the role actions share; an action's own message is used otherwise. */
const FAILURES: Record<string, string> = {
  module_missing: "The management tools for this role are not installed on this computer.",
  protected_record: "This record helps computers find domain controllers; Active Directory maintains it and this console does not change it.",
  protected_zone: "This zone holds what Active Directory needs to find its domain controllers; this console does not remove it.",
};

export function failureText(f: { code: string; message: string }): string {
  return FAILURES[f.code] ?? f.message;
}

/**
 * A module read for a tab: the stored result shows at once (with its age), a new read starts by itself when that is old
 * or missing, the new result replaces it as soon as it arrives, and the tab keeps it fresh while it is open. The result
 * stays in the query cache under the device and the action, so a successful change drops it (`useWinmodChange`).
 */
export function useWinmodRead<T>(deviceId: string, action: string, params: Record<string, unknown>, enabled = true, maxAgeSeconds?: number) {
  const client = useQueryClient();
  const key = ["winmod", deviceId, action, params];
  return useQuery<WinmodOutcome<T>>({
    queryKey: key,
    queryFn: ({ signal }) => readModule<T>(deviceId, action, params, { signal, maxAgeSeconds, onStored: (o) => client.setQueryData(key, o) }),
    enabled,
    staleTime: 10_000,
    refetchInterval: KEEP_FRESH_MS,
    refetchOnWindowFocus: true,
    retry: false,
  });
}

/** A change: runs the action, drops the device's cached reads for the module, and throws the failure's text. */
export function useWinmodChange(deviceId: string, module: string) {
  const client = useQueryClient();
  return useMutation<unknown, Error, { action: string; params: Record<string, unknown>; confirm?: string }>({
    mutationFn: async ({ action, params, confirm }) => {
      const out = await runWinmod<unknown>(deviceId, action, params, confirm);
      if (out.failure) throw new Error(failureText(out.failure));
      if (out.lost) throw new Error(out.lost);
      return out.data;
    },
    onSuccess: () => client.invalidateQueries({ queryKey: ["winmod", deviceId], predicate: (q) => String(q.queryKey[2]).startsWith(`${module}.`) }),
  });
}
