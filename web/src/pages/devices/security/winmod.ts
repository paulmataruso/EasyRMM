import { useCallback, useEffect, useRef, useState } from "react";
import { api } from "../../../api/client";
import type { WinmodResult, WinmodRun } from "../../../api/types";

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
  const pollMs = options.pollMs ?? 1500;
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

/** The state of a read panel: nothing until asked, then the result, the time it was read and any failure. */
export interface Read<T> {
  data: T | null;
  asOf: string | null;
  loading: boolean;
  error: Error | null;
  load: () => void;
}

/** A read action on a device, run on request (never on its own: every read is a job on the computer). */
export function useRead<T>(deviceId: string, action: string): Read<T> {
  const [state, setState] = useState<{ data: T | null; asOf: string | null; error: Error | null }>({ data: null, asOf: null, error: null });
  const [loading, setLoading] = useState(false);
  const alive = useRef(true);
  useEffect(() => {
    alive.current = true;
    return () => {
      alive.current = false;
    };
  }, []);
  const load = useCallback(() => {
    setLoading(true);
    runAction<T>(deviceId, action, undefined)
      .then((r) => alive.current && setState({ data: r.data, asOf: r.finishedAt, error: null }))
      .catch((e: Error) => alive.current && setState((s) => ({ ...s, error: e })))
      .finally(() => alive.current && setLoading(false));
  }, [deviceId, action]);
  return { data: state.data, asOf: state.asOf, loading, error: state.error, load };
}
