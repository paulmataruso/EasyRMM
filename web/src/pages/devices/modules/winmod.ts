import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../../../api/client";
import type { WinmodResult, WinmodRun } from "../../../api/types";

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
}

const wait = (ms: number) => new Promise((r) => setTimeout(r, ms));

/** Starts an action and waits for its result. A destructive action sends its `confirm` text. */
export async function runWinmod<T>(
  deviceId: string,
  action: string,
  params: Record<string, unknown> = {},
  confirm?: string,
  pollMs = 1500,
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
 * A read, sent when `enabled` and again by `refetch`. The result stays in the query cache under the device and the
 * action, so a change can drop it with `invalidateWinmod`.
 */
export function useWinmodRead<T>(deviceId: string, action: string, params: Record<string, unknown>, enabled = true) {
  return useQuery({
    queryKey: ["winmod", deviceId, action, params],
    queryFn: () => runWinmod<T>(deviceId, action, params),
    enabled,
    staleTime: 60_000,
    refetchOnWindowFocus: false,
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
