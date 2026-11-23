import { CircleCheck, CircleX, Clock, LoaderCircle, RefreshCw } from "lucide-react";
import { api } from "../../api/client";
import { useApi, useApiMutation } from "../../api/hooks";
import type { Device, List, Repair, RepairStepName, RepairStepState } from "../../api/types";
import { useToast } from "../../components/Toast";
import { Alert, Button, InlineError } from "../../components/ui";
import { formatDateTime, formatRelative } from "../../lib/format";

// Reconnecting a device's remote access (ADR-0069, Part R): the EasyRMM agent restarts MeshAgent and, if that does not
// bring it back, puts its program and settings in place again, keeping its identity. The page shows the steps.

/** A finished repair is shown for this long, so that its outcome is not missed. */
const SHOWN_FOR_MS = 60 * 60 * 1000;

export const STEP_NAMES: Record<RepairStepName, string> = {
  restart: "Restart MeshAgent",
  repair: "Put MeshAgent's program and settings back, keeping its identity",
};

const STEP_STATE: Record<RepairStepState, string> = {
  pending: "Waiting for the EasyRMM agent to check in",
  sent: "Sent to the EasyRMM agent",
  done: "Done",
  failed: "Failed",
};

/** The device's latest repairs, refreshed every 5 seconds while one runs; read by those who may ask for one. */
export function useRepairs(d: Device) {
  return useApi<List<Repair>>(d.canReconnectRemote ? `/devices/${d.id}/repairs` : null, undefined, {
    refetchInterval: (data) => (data?.items[0]?.state === "running" ? 5_000 : false),
  });
}

/** The repair worth showing: the latest, while it runs and for an hour after. */
export function shownRepair(items: Repair[] | undefined, now: number = Date.now()): Repair | null {
  const r = items?.[0];
  if (!r) return null;
  if (r.state === "running") return r;
  const ended = r.endedAt ? new Date(r.endedAt).getTime() : 0;
  return now - ended < SHOWN_FOR_MS ? r : null;
}

/** The device page's button that reconnects remote access. */
export function ReconnectRemoteButton({ device: d }: { device: Device }) {
  const toast = useToast();
  const repairs = useRepairs(d);
  const ask = useApiMutation(() => api.post<Repair>(`/devices/${d.id}/repairs`, { target: "meshagent" }), {
    invalidate: [`/devices/${d.id}/repairs`],
    onSuccess: () => toast.success(`${d.name}'s EasyRMM agent restarts MeshAgent the next time it checks in.`),
  });
  if (!d.canReconnectRemote) return null;
  const running = repairs.data?.items[0]?.state === "running";
  const why = !d.online ? "The device is not checking in, so nothing can be repaired from here." : undefined;
  return (
    <Button
      icon={<RefreshCw className="size-4" aria-hidden />}
      onClick={() => ask.mutate(undefined)}
      loading={ask.isPending}
      disabled={running || !d.online}
      title={running ? "A repair is running." : why}
    >
      Reconnect remote access
    </Button>
  );
}

function StepIcon({ state }: { state: RepairStepState }) {
  switch (state) {
    case "done":
      return <CircleCheck className="size-4 text-ok" aria-hidden />;
    case "failed":
      return <CircleX className="size-4 text-danger" aria-hidden />;
    case "sent":
      return <LoaderCircle className="size-4 animate-spin text-info" aria-hidden />;
    default:
      return <Clock className="size-4 text-muted" aria-hidden />;
  }
}

/** A repair's steps and outcome. */
export function RepairSteps({ repair: r }: { repair: Repair }) {
  return (
    <ol className="mt-1.5 space-y-1">
      {r.steps.map((s) => (
        <li key={s.id} className="flex items-start gap-2">
          <StepIcon state={s.state} />
          <span className="min-w-0">
            <span className="font-medium">{STEP_NAMES[s.step]}</span>
            <span className="text-muted">
              {" "}
              · {STEP_STATE[s.state]}
              {s.doneAt && <>, <span title={formatDateTime(s.doneAt)}>{formatRelative(s.doneAt)}</span></>}
            </span>
            {s.error && <span className="block break-words text-danger">{s.error}</span>}
          </span>
        </li>
      ))}
    </ol>
  );
}

/** The latest repair of remote access, with its steps and how it ended; nothing while there is none to show. */
export function RemoteRepairCard({ device: d }: { device: Device }) {
  const repairs = useRepairs(d);
  const r = shownRepair(repairs.data?.items);
  if (!r) return repairs.isError ? <InlineError error={repairs.error} /> : null;
  const tone = r.state === "running" ? "info" : r.state === "succeeded" ? "ok" : "danger";
  const title =
    r.state === "running"
      ? "Reconnecting remote access"
      : r.state === "succeeded"
        ? "Remote access is connected again"
        : "Remote access did not come back";
  return (
    <Alert tone={tone} className="mb-5" title={title}>
      <span className="block text-muted">
        Started <span title={formatDateTime(r.startedAt)}>{formatRelative(r.startedAt)}</span>
        {r.trigger === "automatic" ? " by EasyRMM" : ""}.
      </span>
      <RepairSteps repair={r} />
      {r.state === "failed" && r.error && <span className="mt-1.5 block break-words">{r.error}</span>}
    </Alert>
  );
}
