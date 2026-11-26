import { api, ApiError } from "../../../api/client";
import type { EventlogRequest, EventlogResult, EventlogRun } from "../../../api/types";

/** How often a run is asked about, and how long one is waited for: the run's own limits are 2 minutes queued and 60 seconds running. */
const EVERY_MS = 600;
const GIVE_UP_MS = 190_000;

export interface Started {
  run: EventlogRun;
  result: Promise<EventlogResult>;
}

/**
 * Starts one operation of the event viewer on a device and follows it: the answer is the run to follow and a promise of its
 * result. A run that is still open answers 409 run_open, which is waited out; anything else a person must see is thrown.
 * A signal that aborts stops the following; the server cancels what a newer search from the same person replaces.
 */
export async function startOp(deviceId: string, request: EventlogRequest, signal?: AbortSignal): Promise<Started> {
  const run = await api.post<EventlogRun>(`/devices/${deviceId}/eventlog`, request);
  const result = (async () => {
    const started = Date.now();
    for (;;) {
      if (signal?.aborted) throw new DOMException("aborted", "AbortError");
      try {
        return await api.get<EventlogResult>(`/job-runs/${run.runId}/eventlog`, undefined, signal);
      } catch (e) {
        if (!(e instanceof ApiError) || e.code !== "run_open") throw e;
      }
      if (Date.now() - started > GIVE_UP_MS) throw new Error("The device did not answer in time.");
      await new Promise((r) => setTimeout(r, EVERY_MS));
    }
  })();
  return { run, result };
}

/** Cancels a run that is still open, as when a person leaves the tab; a run that has ended answers an error nobody needs. */
export async function cancelRun(runId: string): Promise<void> {
  try {
    await api.post(`/job-runs/${runId}/cancel`, {});
  } catch {
    // Already finished, or not the person's to cancel: nothing to do.
  }
}
