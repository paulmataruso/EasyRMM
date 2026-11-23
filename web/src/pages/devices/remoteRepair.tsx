import { CircleCheck, CircleX, Clock, LoaderCircle, RefreshCw, Wrench } from "lucide-react";
import { api } from "../../api/client";
import { useApi, useApiMutation } from "../../api/hooks";
import type { Device, List, Repair, RepairStepName, RepairStepState, RepairTarget } from "../../api/types";
import { useToast } from "../../components/Toast";
import { Alert, Button, InlineError } from "../../components/ui";
import { formatDateTime, formatRelative } from "../../lib/format";

// Repairing a device's agents (ADR-0069, Part R). Reconnecting remote access: the EasyRMM agent restarts MeshAgent and, if
// that does not bring it back, puts its program and settings in place again, keeping its identity. Repairing the patching
// agent: the EasyRMM agent restarts the EasyPatch agent and, if that does not help, reinstalls its package of the same
// version over it, keeping its enrollment. The page shows the steps.

/** A finished repair is shown for this long, so that its outcome is not missed. */
const SHOWN_FOR_MS = 60 * 60 * 1000;

export const STEP_NAMES: Record<RepairTarget, Record<RepairStepName, string>> = {
  meshagent: {
    restart: "Restart MeshAgent",
    repair: "Put MeshAgent's program and settings back, keeping its identity",
  },
  "easypatch-agent": {
    restart: "Restart the EasyPatch agent",
    repair: "Reinstall the EasyPatch agent's package of the same version, keeping its enrollment",
  },
  "easyrmm-agent": {
    restart: "Restart the EasyRMM agent",
    repair: "Put the EasyRMM agent back from its recovery copy",
  },
};

/** What a step's state says, by the agent that carries it out. */
function stepState(carrier: RepairTarget, state: RepairStepState): string {
  const agent = carrier === "easypatch-agent" ? "EasyPatch agent" : "EasyRMM agent";
  switch (state) {
    case "pending":
      return carrier === "easypatch-agent" ? "Waiting for the patching engine" : `Waiting for the ${agent} to check in`;
    case "sent":
      return `Sent to the ${agent}`;
    case "done":
      return "Done";
    default:
      return "Failed";
  }
}

/** The device's latest repairs, refreshed every 5 seconds while one runs; read by those who may ask for one. */
export function useRepairs(d: Device) {
  return useApi<List<Repair>>(d.canReconnectRemote || d.canRepairPatching || d.canRepairEasyRmm ? `/devices/${d.id}/repairs` : null, undefined, {
    refetchInterval: (data) => (data?.items[0]?.state === "running" ? 5_000 : false),
  });
}

/** The latest repair of a target. */
export function latestOf(items: Repair[] | undefined, target: RepairTarget): Repair | undefined {
  return items?.find((r) => r.target === target);
}

/** The repair of a target worth showing: the latest, while it runs and for an hour after. */
export function shownRepair(items: Repair[] | undefined, now: number = Date.now(), target: RepairTarget = "meshagent"): Repair | null {
  const r = latestOf(items, target);
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
  const running = latestOf(repairs.data?.items, "meshagent")?.state === "running";
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

/** The device page's button that repairs the EasyPatch agent. */
export function RepairPatchingButton({ device: d }: { device: Device }) {
  const toast = useToast();
  const repairs = useRepairs(d);
  const ask = useApiMutation(() => api.post<Repair>(`/devices/${d.id}/repairs`, { target: "easypatch-agent" }), {
    invalidate: [`/devices/${d.id}/repairs`],
    onSuccess: () => toast.success(`${d.name}'s EasyRMM agent restarts the EasyPatch agent the next time it checks in.`),
  });
  if (!d.canRepairPatching) return null;
  const running = latestOf(repairs.data?.items, "easypatch-agent")?.state === "running";
  const why = !d.online ? "The device is not checking in, so nothing can be repaired from here." : undefined;
  return (
    <Button
      icon={<Wrench className="size-4" aria-hidden />}
      onClick={() => ask.mutate(undefined)}
      loading={ask.isPending}
      disabled={running || !d.online}
      title={running ? "A repair is running." : why}
    >
      Repair patching agent
    </Button>
  );
}

/** The device page's button that repairs the EasyRMM agent through the EasyPatch agent. */
export function RepairEasyRmmButton({ device: d }: { device: Device }) {
  const toast = useToast();
  const repairs = useRepairs(d);
  const ask = useApiMutation(() => api.post<Repair>(`/devices/${d.id}/repairs`, { target: "easyrmm-agent" }), {
    invalidate: [`/devices/${d.id}/repairs`],
    onSuccess: () => toast.success(`The EasyPatch agent on ${d.name} restarts the EasyRMM agent through the patching engine.`),
  });
  if (!d.canRepairEasyRmm) return null;
  const running = latestOf(repairs.data?.items, "easyrmm-agent")?.state === "running";
  const why = d.online ? "The EasyRMM agent is checking in, so there is nothing to repair through patching." : undefined;
  return (
    <Button
      icon={<Wrench className="size-4" aria-hidden />}
      onClick={() => ask.mutate(undefined)}
      loading={ask.isPending}
      disabled={running || d.online}
      title={running ? "A repair is running." : why}
    >
      Repair EasyRMM agent through patching
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
            <span className="font-medium">{STEP_NAMES[r.target]?.[s.step] ?? s.step}</span>
            <span className="text-muted">
              {" "}
              · {stepState(r.carriedBy, s.state)}
              {s.doneAt && <>, <span title={formatDateTime(s.doneAt)}>{formatRelative(s.doneAt)}</span></>}
            </span>
            {s.error && <span className="block break-words text-danger">{s.error}</span>}
            {s.note && !s.error && <span className="block break-words text-muted">{s.note}</span>}
          </span>
        </li>
      ))}
    </ol>
  );
}

const CARD_TITLES: Record<"meshagent" | "easypatch-agent" | "easyrmm-agent", Record<"running" | "succeeded" | "failed", string>> = {
  "easyrmm-agent": {
    running: "Repairing the EasyRMM agent through patching",
    succeeded: "The EasyRMM agent is checking in again",
    failed: "The EasyRMM agent did not come back",
  },
  meshagent: {
    running: "Reconnecting remote access",
    succeeded: "Remote access is connected again",
    failed: "Remote access did not come back",
  },
  "easypatch-agent": {
    running: "Repairing the patching agent",
    succeeded: "The patching agent is checking in again",
    failed: "The patching agent did not come back",
  },
};

/** The latest repair of an agent, with its steps and how it ended; nothing while there is none to show. */
function RepairCard({ device: d, target }: { device: Device; target: "meshagent" | "easypatch-agent" | "easyrmm-agent" }) {
  const repairs = useRepairs(d);
  const r = shownRepair(repairs.data?.items, Date.now(), target);
  if (!r) return repairs.isError && target === "meshagent" ? <InlineError error={repairs.error} /> : null;
  const tone = r.state === "running" ? "info" : r.state === "succeeded" ? "ok" : "danger";
  return (
    <Alert tone={tone} className="mb-5" title={CARD_TITLES[target][r.state]}>
      <span className="block text-muted">
        Started <span title={formatDateTime(r.startedAt)}>{formatRelative(r.startedAt)}</span>
        {r.trigger === "automatic" ? " by EasyRMM" : ""}.
      </span>
      <RepairSteps repair={r} />
      {r.state === "failed" && r.error && <span className="mt-1.5 block break-words">{r.error}</span>}
    </Alert>
  );
}

/** The latest repair of remote access. */
export function RemoteRepairCard({ device: d }: { device: Device }) {
  return <RepairCard device={d} target="meshagent" />;
}

/** The latest repair of the patching agent. */
export function PatchingRepairCard({ device: d }: { device: Device }) {
  return <RepairCard device={d} target="easypatch-agent" />;
}

/** The latest repair of the EasyRMM agent, through patching. */
export function EasyRmmRepairCard({ device: d }: { device: Device }) {
  return <RepairCard device={d} target="easyrmm-agent" />;
}
