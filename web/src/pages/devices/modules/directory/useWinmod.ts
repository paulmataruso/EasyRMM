import { useCallback } from "react";
import { api } from "../../../../api/client";
import type { WinmodResult, WinmodRun } from "../../../../api/types";

const FINISHED = new Set(["succeeded", "failed", "timed_out", "canceled", "expired", "lost"]);

/** A finished action: its typed result, or why it did not run, and the secrets the server made for it (shown once). */
export interface Finished<T> {
  ok: boolean;
  data?: T;
  /** The script's own typed refusal, or the run's end when it never answered. */
  failure?: { code: string; message: string };
  finishedAt: string | null;
  /** Values the server made for the request, by parameter name. They are in no other answer; do not keep them. */
  generated?: Record<string, string>;
}

const wait = (ms: number) => new Promise((r) => setTimeout(r, ms));

/**
 * Runs one Active Directory action on a controller and follows the run to its result. The step-up (ADR-0055) is asked
 * for by the API client when the server needs it. A refusal by the script (a protected account, a read-only controller)
 * is a `failure`, not a thrown error.
 */
export function useWinmod(deviceId: string) {
  return useCallback(
    async <T,>(action: string, params: Record<string, unknown> = {}, confirm?: string): Promise<Finished<T>> => {
      const run = await api.post<WinmodRun & { generated?: Record<string, string> }>(
        `/devices/${deviceId}/winmod/active_directory.${action}`,
        { params, ...(confirm ? { confirm } : {}) },
      );
      for (let i = 0; i < 150; i++) {
        const r = await api.get<WinmodResult>(`/winmod/runs/${run.runId}`);
        if (r.ok !== undefined || FINISHED.has(r.status)) {
          if (r.ok === true) return { ok: true, data: r.data as T, finishedAt: r.finishedAt, generated: run.generated };
          return {
            ok: false,
            failure: r.failure ?? { code: r.status, message: r.error ?? `The action ended as ${r.status}.` },
            finishedAt: r.finishedAt,
          };
        }
        await wait(1000);
      }
      return { ok: false, failure: { code: "timeout", message: "The controller did not answer in time." }, finishedAt: null };
    },
    [deviceId],
  );
}

/** The confirmation a destructive action asks for: its name and the subject's id. */
export const confirmFor = (action: string, id: string) => `active_directory.${action}:${id}`;
