import { api, ApiError } from "../../../api/client";
import type { RegistryQuery, RegistryResult, RegistryRun } from "../../../api/types";

/** How often a read is asked about, and how long one is waited for: the run's own limits are 2 minutes queued and 60 seconds running. */
const EVERY_MS = 600;
const GIVE_UP_MS = 190_000;

export interface Started {
  run: RegistryRun;
  result: Promise<RegistryResult>;
}

/**
 * Starts one read of a device's registry and follows it: the answer is the run to follow and a promise of its result.
 * A read that is still open answers 409 run_open, which is waited out; anything else a person must see is thrown.
 */
export async function startQuery(deviceId: string, query: RegistryQuery, signal?: AbortSignal): Promise<Started> {
  const run = await api.post<RegistryRun>(`/devices/${deviceId}/registry/query`, query);
  const result = (async () => {
    const started = Date.now();
    for (;;) {
      if (signal?.aborted) throw new DOMException("aborted", "AbortError");
      try {
        return await api.get<RegistryResult>(`/job-runs/${run.runId}/result`, undefined, signal);
      } catch (e) {
        if (!(e instanceof ApiError) || e.code !== "run_open") throw e;
      }
      if (Date.now() - started > GIVE_UP_MS) throw new Error("The device did not answer in time.");
      await new Promise((r) => setTimeout(r, EVERY_MS));
    }
  })();
  return { run, result };
}
