import { useState } from "react";
import { CircleCheck, CircleX, Clock, LoaderCircle, Wrench } from "lucide-react";
import { api } from "../../api/client";
import { useApi, useApiMutation } from "../../api/hooks";
import type { Device, List, Repair, RepairOutcome, RepairPlan, RepairStepName, RepairStepState, RepairTarget } from "../../api/types";
import { Dialog } from "../../components/Dialog";
import { useToast } from "../../components/Toast";
import { Alert, Button, InlineError } from "../../components/ui";
import { formatDateTime, formatRelative } from "../../lib/format";

// Repairing a device's agents (ADR-0069, Part R). One Repair button: the server decides what is down and which running
// agent repairs it. The EasyRMM agent restarts MeshAgent or the EasyPatch agent and, if that does not bring it back, puts
// it in place again keeping its identity; the EasyPatch agent does the same for a silent EasyRMM agent. The page shows
// the steps.

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
  return useApi<List<Repair>>(canRepair(d) ? `/devices/${d.id}/repairs` : null, undefined, {
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

/** True when someone may press Repair here: the device has an EasyRMM agent and the caller may repair some agent of it. */
export function canRepair(d: Device): boolean {
  return d.canReconnectRemote || d.canRepairPatching || d.canRepairEasyRmm;
}

/** The short name of an agent, as the repair plan uses it. */
export const AGENT_NAMES: Record<RepairTarget, string> = {
  "easyrmm-agent": "the EasyRMM agent",
  meshagent: "MeshAgent",
  "easypatch-agent": "the EasyPatch agent",
};

/**
 * The device page's one Repair button (ADR-0069, amended 2026-11-26). The server knows which of the three agents is
 * down and which running agent repairs it; the dialog says what will happen before it asks. A repair that runs
 * already disables the button, since the steps show below.
 */
export function RepairButton({ device: d }: { device: Device }) {
  const [open, setOpen] = useState(false);
  const repairs = useRepairs(d);
  if (!canRepair(d)) return null;
  const running = repairs.data?.items.some((r) => r.state === "running") ?? false;
  return (
    <>
      <Button icon={<Wrench className="size-4" aria-hidden />} onClick={() => setOpen(true)} disabled={running} title={running ? "A repair is running." : undefined}>
        Repair
      </Button>
      {open && <RepairDialog device={d} onClose={() => setOpen(false)} />}
    </>
  );
}

function RepairDialog({ device: d, onClose }: { device: Device; onClose: () => void }) {
  const toast = useToast();
  const plan = useApi<RepairPlan>(`/devices/${d.id}/repair-plan`, undefined, { refetchInterval: false });
  const ask = useApiMutation(() => api.post<RepairOutcome>(`/devices/${d.id}/repairs`, {}), {
    invalidate: [`/devices/${d.id}/repairs`, `/devices/${d.id}/repair-plan`],
    onSuccess: (r) => {
      toast.success(`Repair started on ${d.name}: ${r.repairs.map((x) => AGENT_NAMES[x.target]).join(" and ")}.`);
      onClose();
    },
  });
  const p = plan.data;
  return (
    <Dialog open onClose={onClose} title={`Repair ${d.name}`} description="EasyRMM works out which agent is down and which running agent repairs it.">
      {plan.isPending && <LoaderCircle className="size-5 animate-spin text-muted" aria-label="Loading" />}
      {plan.isError && <InlineError error={plan.error} />}
      {p && (
        <p className={p.refusal ? "text-sm text-muted" : "text-sm"} data-testid="repair-plan">
          {p.summary}
        </p>
      )}
      <InlineError error={ask.error} />
      <div className="mt-4 flex justify-end gap-2 border-t border-line pt-3">
        <Button onClick={onClose} disabled={ask.isPending}>
          {p?.refusal ? "Close" : "Cancel"}
        </Button>
        {p && !p.refusal && (
          <Button variant="primary" loading={ask.isPending} onClick={() => ask.mutate(undefined)}>
            Repair
          </Button>
        )}
      </div>
    </Dialog>
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
