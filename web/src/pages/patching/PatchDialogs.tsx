import { useEffect, useId, useState, type ReactNode } from "react";
import { Link } from "react-router";
import { RotateCcw } from "lucide-react";
import type { UseQueryResult } from "@tanstack/react-query";
import { api, errorMessage } from "../../api/client";
import { useApi, useApiMutation } from "../../api/hooks";
import type { PatchActionInput, PatchActionResult, PatchInstallPreview, PatchJobDetail, PatchJobView, RestartInput, RestartMode, RestartPlan } from "../../api/types";
import { Dialog } from "../../components/Dialog";
import { useToast } from "../../components/Toast";
import { Alert, Badge, Button, ErrorState, Field, InlineError, Input, KeyValueList, Select, Spinner } from "../../components/ui";
import { formatDateTime, formatRelative, formatSize, plural } from "../../lib/format";
import { canRetry, categoryLabel, EasyPatchLink, isActiveJob, jobOutcome, jobTypeLabel, PatchJobBadge, requester, skipReasonText, triggerLabel } from "./patchText";

/** What the patching views refresh after an action. */
export const PATCH_KEYS = ["/patching", "/audit"];

export interface PatchTarget {
  id: string;
  name: string;
}

/** The outcome of a scan or install, said in a toast; devices that did not start are listed in a dialog. */
export function useOutcome() {
  const toast = useToast();
  const [result, setResult] = useState<PatchActionResult | null>(null);
  const report = (verb: string, r: PatchActionResult) => {
    if (r.succeeded > 0) toast.success(`${verb} on ${plural(r.succeeded, "device")}.`);
    if (r.failed > 0) setResult(r);
  };
  const dialog = <ResultDialog result={result} onClose={() => setResult(null)} />;
  return { report, dialog };
}

function ResultDialog({ result, onClose }: { result: PatchActionResult | null; onClose: () => void }) {
  const failed = result?.results.filter((r) => !r.ok) ?? [];
  return (
    <Dialog
      open={result !== null}
      onClose={onClose}
      title={`${plural(failed.length, "device")} did not start`}
      description={result && result.succeeded > 0 ? `${plural(result.succeeded, "other device")} did.` : undefined}
      footer={<Button onClick={onClose}>Close</Button>}
    >
      <ul className="divide-y divide-line rounded-md border border-line">
        {failed.map((r) => (
          <li key={r.deviceId} className="px-3 py-2.5 text-sm">
            <Link to={`/devices/${r.deviceId}?tab=patches`} className="font-medium hover:text-accent">
              {r.deviceName}
            </Link>
            <p className="text-muted">{r.message || "EasyPatch did not say why."}</p>
          </li>
        ))}
      </ul>
    </Dialog>
  );
}

/** Scans devices for updates at once. */
export function useScan() {
  const outcome = useOutcome();
  const scan = useApiMutation((ids: string[]) => api.post<PatchActionResult>("/patching/scan", { deviceIds: ids }), {
    invalidate: PATCH_KEYS,
    onSuccess: (r) => outcome.report("Scan started", r),
  });
  return { scan, dialog: outcome.dialog };
}

/**
 * Has devices' EasyRMM agents install and enroll the EasyPatch agent (ADR-0031), each at its next check-in. EasyRMM
 * leaves devices that already have one alone.
 */
export function AgentInstallDialog({ open, onClose, devices, onDone }: { open: boolean; onClose: () => void; devices: PatchTarget[]; onDone?: () => void }) {
  const outcome = useOutcome();
  const install = useApiMutation((ids: string[]) => api.post<PatchActionResult>("/patching/agent-install", { deviceIds: ids }), {
    invalidate: PATCH_KEYS,
    onSuccess: (r) => {
      outcome.report("EasyPatch agent install requested", r);
      onClose();
      onDone?.();
    },
  });
  useEffect(() => {
    if (open) install.reset();
    // eslint-disable-next-line react-hooks/exhaustive-deps -- reset when the dialog opens, not when the mutation changes
  }, [open]);
  const where = devices.length === 1 ? devices[0]!.name : plural(devices.length, "device");
  return (
    <>
      <Dialog
        open={open}
        onClose={onClose}
        title={`Install the EasyPatch agent on ${where}`}
        description={`At its next check-in, within a minute, ${devices.length === 1 ? "the" : "each"} device's EasyRMM agent downloads the EasyPatch agent from your EasyPatch server, checks it, installs it and enrolls it in the EasyPatch organization linked to the device's organization.`}
        footer={
          <>
            <Button onClick={onClose} disabled={install.isPending}>
              Cancel
            </Button>
            <Button variant="primary" loading={install.isPending} onClick={() => install.mutate(devices.map((d) => d.id))}>
              Install EasyPatch agent
            </Button>
          </>
        }
      >
        <ul className="list-disc space-y-1 pl-5 text-sm text-muted">
          <li>A device that already has an EasyPatch agent is left alone, whichever server it is enrolled with.</li>
          <li>The device joins the EasyPatch site with the same name as its EasyRMM site, or no site when there is none.</li>
          <li>
            Linux devices need systemd and apt-get or dnf. If your EasyPatch server's certificate comes from a private authority, Linux devices need that
            authority in their certificate store; EasyRMM does not change it.
          </li>
        </ul>
        <InlineError error={install.error} />
      </Dialog>
      {outcome.dialog}
    </>
  );
}

/**
 * Stops patching devices (ADR-0040): EasyRMM removes the EasyPatch agent it manages on them and installs none again,
 * automatically or when asked, until patching is allowed again.
 */
export function StopPatchingDialog({ open, onClose, devices }: { open: boolean; onClose: () => void; devices: PatchTarget[] }) {
  const toast = useToast();
  const stop = useApiMutation((ids: string[]) => api.post<PatchActionResult>("/patching/stop", { deviceIds: ids }), {
    invalidate: PATCH_KEYS,
    onSuccess: (r) => {
      const first = r.results[0];
      if (r.failed > 0 && first) toast.error(first.message || "Patching was not stopped.");
      else toast.success(devices.length === 1 && first?.message ? first.message : `Patching stopped on ${plural(r.succeeded, "device")}.`);
      onClose();
    },
  });
  useEffect(() => {
    if (open) stop.reset();
    // eslint-disable-next-line react-hooks/exhaustive-deps -- reset when the dialog opens, not when the mutation changes
  }, [open]);
  const where = devices.length === 1 ? devices[0]!.name : plural(devices.length, "device");
  return (
    <Dialog
      open={open}
      onClose={onClose}
      title={`Stop patching ${where}?`}
      description="For a device that must not be patched, such as a server that may only change in a planned window."
      footer={
        <>
          <Button onClick={onClose} disabled={stop.isPending}>
            Cancel
          </Button>
          <Button variant="danger" loading={stop.isPending} onClick={() => stop.mutate(devices.map((d) => d.id))}>
            Stop patching
          </Button>
        </>
      }
    >
      <ul className="list-disc space-y-1 pl-5 text-sm text-muted">
        <li>EasyRMM has the EasyPatch agent uninstall itself. An agent that cannot is cut off from patching instead.</li>
        <li>EasyRMM installs no EasyPatch agent on the device again, automatically or when asked, until you allow patching again.</li>
        <li>An EasyPatch agent someone installs on the computer by hand is left alone.</li>
      </ul>
      <InlineError error={stop.error} />
    </Dialog>
  );
}

/** Allows patching again on a device it was stopped for. */
export function useAllowPatching() {
  const toast = useToast();
  return useApiMutation((ids: string[]) => api.post<PatchActionResult>("/patching/allow", { deviceIds: ids }), {
    invalidate: PATCH_KEYS,
    onSuccess: (r) => {
      const first = r.results[0];
      if (r.failed > 0) toast.error(first?.message || "Patching was not allowed again.");
      else toast.success(first?.message || "Patching allowed again.");
    },
  });
}

/** A datetime-local value for a time, in the browser's zone. */
function localInput(d: Date): string {
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

/** Tonight at 22:00, or tomorrow's if that has passed. */
function tonight(now = new Date()): Date {
  const d = new Date(now);
  d.setHours(22, 0, 0, 0);
  if (d.getTime() - now.getTime() < 15 * 60_000) d.setDate(d.getDate() + 1);
  return d;
}

/** What an install on one device would do, from its last scan (one-product plan, C1). */
function InstallPreviewList({ q }: { q: UseQueryResult<PatchInstallPreview> }) {
  if (q.isPending) return <Spinner label="Checking what would be installed…" />;
  if (q.isError) {
    return <p className="text-xs text-muted">What would be installed could not be checked ({errorMessage(q.error)}). EasyPatch checks again when it installs.</p>;
  }
  const p = q.data;
  return (
    <div className="space-y-3 text-sm">
      {p.items.length === 0 ? (
        <Alert tone="warn" title="Nothing would be installed">
          {p.skipped.length > 0 ? "Every update is left out, for the reasons below." : "The last scan found no update the policy allows."}
        </Alert>
      ) : (
        <div>
          <p className="font-medium">
            {plural(p.items.length, "update")}
            {p.totalSizeBytes > 0 && <span className="font-normal text-muted">, {formatSize(p.totalSizeBytes)}</span>}
            {p.rebootLikelyCount > 0 && <span className="font-normal text-muted">; {p.rebootLikelyCount.toLocaleString()} likely to need a restart</span>}
          </p>
          <ul className="mt-1 max-h-40 space-y-0.5 overflow-y-auto">
            {p.items.map((u) => (
              <li key={u.updateGuid} className="break-words">
                {u.title}
                <span className="text-xs text-muted">
                  {" "}
                  · {categoryLabel(u.category)}
                  {u.sizeBytes ? ` · ${formatSize(u.sizeBytes)}` : ""}
                </span>
              </li>
            ))}
          </ul>
        </div>
      )}
      {p.skipped.length > 0 && (
        <div>
          <p className="font-medium">Left out ({p.skipped.length.toLocaleString()})</p>
          <ul className="mt-1 max-h-32 space-y-0.5 overflow-y-auto">
            {p.skipped.map((u) => (
              <li key={u.updateGuid} className="break-words">
                {u.title}
                <span className="block text-xs text-muted">{skipReasonText(u.reason)}</span>
              </li>
            ))}
          </ul>
        </div>
      )}
      {p.warnings.length > 0 && (
        <Alert tone="warn">
          {p.warnings.map((w) => (
            <p key={w}>{w}</p>
          ))}
        </Alert>
      )}
      <p className="text-xs text-subtle">
        {p.lastScanAt ? <>From the scan {formatRelative(p.lastScanAt)}. </> : null}
        The agent scans again before installing.
      </p>
    </div>
  );
}

/**
 * Installs updates on devices: every eligible update, or chosen ones on one device. Where EasyPatch can schedule
 * (scheduled-installs), the install can wait for a time. On one device, with preview, it first shows what EasyPatch
 * would install and leave out.
 */
export function InstallDialog({
  open,
  onClose,
  devices,
  updates,
  canSchedule,
  preview = false,
  onDone,
}: {
  open: boolean;
  onClose: () => void;
  devices: PatchTarget[];
  /** Chosen updates (one device only); every eligible update when absent. */
  updates?: { id: string; title: string }[];
  canSchedule: boolean;
  /** Show what the install would do first (one device only). */
  preview?: boolean;
  onDone?: () => void;
}) {
  const outcome = useOutcome();
  const previewing = open && preview && devices.length === 1;
  const pv = useApi<PatchInstallPreview>(
    previewing ? `/patching/devices/${devices[0]!.id}/install-preview` : null,
    updates ? { updateId: updates.map((u) => u.id) } : undefined,
    { staleTime: 0 },
  );
  const [when, setWhen] = useState<"now" | "later">("now");
  const [at, setAt] = useState(() => localInput(tonight()));
  const whenId = useId();
  useEffect(() => {
    if (open) {
      setWhen("now");
      setAt(localInput(tonight()));
    }
  }, [open]);

  const install = useApiMutation((body: PatchActionInput) => api.post<PatchActionResult>("/patching/install", body), {
    invalidate: PATCH_KEYS,
    onSuccess: (r) => {
      outcome.report(when === "later" ? "Install scheduled" : "Install started", r);
      onClose();
      onDone?.();
    },
  });
  useEffect(() => {
    if (open) install.reset();
    // eslint-disable-next-line react-hooks/exhaustive-deps -- reset when the dialog opens, not when the mutation changes
  }, [open]);

  const scheduledAt = when === "later" && at ? new Date(at) : null;
  const badTime = scheduledAt !== null && Number.isNaN(scheduledAt.getTime());
  const what = updates ? plural(updates.length, "chosen update") : "every update its policy allows";
  const where = devices.length === 1 ? devices[0]!.name : plural(devices.length, "device");

  return (
    <>
      <Dialog
        open={open}
        onClose={onClose}
        title={updates ? `Install ${plural(updates.length, "update")} on ${where}` : `Install updates on ${where}`}
        description={`EasyPatch installs ${what}, downloading what it needs. Updates that need a restart finish at the next one, which the device's EasyPatch policy may schedule.`}
        footer={
          <>
            <Button onClick={onClose} disabled={install.isPending}>
              Cancel
            </Button>
            <Button
              variant="primary"
              loading={install.isPending}
              disabled={badTime || (when === "later" && !at)}
              onClick={() =>
                install.mutate({
                  deviceIds: devices.map((d) => d.id),
                  updateIds: updates?.map((u) => u.id),
                  scheduledAt: scheduledAt && !badTime ? scheduledAt.toISOString() : undefined,
                })
              }
            >
              {when === "later" ? "Schedule install" : "Install now"}
            </Button>
          </>
        }
      >
        <div className="space-y-4">
          {previewing && <InstallPreviewList q={pv} />}
          {updates && !previewing && (
            <ul className="max-h-40 list-disc space-y-0.5 overflow-y-auto pl-5 text-sm">
              {updates.map((u) => (
                <li key={u.id} className="break-words">
                  {u.title}
                </li>
              ))}
            </ul>
          )}
          {canSchedule ? (
            <fieldset className="space-y-2" aria-describedby={whenId}>
              <legend className="text-xs font-medium text-muted">When</legend>
              <label className="flex items-center gap-2 text-sm">
                <input type="radio" name="when" checked={when === "now"} onChange={() => setWhen("now")} className="size-4 accent-accent" />
                Now
              </label>
              <label className="flex flex-wrap items-center gap-2 text-sm">
                <input type="radio" name="when" checked={when === "later"} onChange={() => setWhen("later")} className="size-4 accent-accent" />
                At
                <Input
                  type="datetime-local"
                  aria-label="Install at"
                  value={at}
                  min={localInput(new Date())}
                  onChange={(e) => {
                    setAt(e.target.value);
                    setWhen("later");
                  }}
                  className="w-auto"
                />
              </label>
              <p id={whenId} className="text-xs text-subtle">
                Your time zone ({Intl.DateTimeFormat().resolvedOptions().timeZone}). Up to 31 days ahead; the device must be online then.
              </p>
            </fieldset>
          ) : (
            <p className="text-xs text-muted">
              Installs start when each device next checks in with EasyPatch. Installing at a later time needs an EasyPatch server with scheduled installs.
            </p>
          )}
          <InlineError error={install.error} />
        </div>
      </Dialog>
      {outcome.dialog}
    </>
  );
}

export const RESTART_MODES: { value: RestartMode; label: string; hint: string }[] = [
  { value: "Countdown", label: "Count down, then restart", hint: "Signed-in users see the countdown and can only restart sooner." },
  {
    value: "PromptWithDeadline",
    label: "Ask users, with a deadline",
    hint: "Users restart when it suits them or postpone, never past the deadline; then a five-minute countdown.",
  },
  { value: "PromptNoDeadline", label: "Ask users, no deadline", hint: "Users choose when. The restart fails if nobody agrees within 7 days." },
  { value: "Immediate", label: "Restart at once", hint: "No warning, even with users signed in." },
];

export const COUNTDOWNS = [1, 5, 10, 15, 30, 60];
export const DEADLINES = [15, 30, 60, 120, 240, 480, 1440, 3 * 1440, 7 * 1440];
export const EXPIRIES = [15, 30, 60, 120, 240, 480, 1440];

/** "15 minutes", "4 hours", "3 days". */
function minutesText(m: number): string {
  if (m % 1440 === 0) return plural(m / 1440, "day");
  if (m % 60 === 0) return plural(m / 60, "hour");
  return plural(m, "minute");
}

/** At most this many devices restart whether or not a restart is pending (the server says the same). */
const MAX_ALWAYS = 100;

/**
 * Restarts devices (one-product plan, C3): by default only those whose restart is still pending when the job runs,
 * or all of them; after a countdown, by asking the people signed in (with or without a deadline), or at once; now or
 * at a time, waiting a while for devices that are offline. EasyRMM first asks what the restart would do; servers
 * restart only when ticked by name.
 */
export function RestartDialog({
  open,
  onClose,
  devices,
  pendingOnly: initialPendingOnly = true,
  onDone,
}: {
  open: boolean;
  onClose: () => void;
  devices: PatchTarget[];
  /** Start with "only if a restart is pending" ticked; untick it for devices with nothing pending. */
  pendingOnly?: boolean;
  onDone?: () => void;
}) {
  const outcome = useOutcome();
  const [pendingOnly, setPendingOnly] = useState(initialPendingOnly);
  const [mode, setMode] = useState<RestartMode>("Countdown");
  const [countdown, setCountdown] = useState(5);
  const [deadline, setDeadline] = useState(240);
  const [expiry, setExpiry] = useState(120);
  const [when, setWhen] = useState<"now" | "later">("now");
  const [at, setAt] = useState(() => localInput(tonight()));
  const [confirmed, setConfirmed] = useState<Set<string>>(new Set());
  const whenId = useId();
  const modeId = useId();
  const expiryId = useId();
  const plan = useApiMutation((v: { ids: string[]; always: boolean }) =>
    api.post<RestartPlan>("/patching/restart/plan", v.always ? { deviceIds: v.ids, condition: "Always" } : { deviceIds: v.ids }),
  );
  const restart = useApiMutation((body: RestartInput) => api.post<PatchActionResult>("/patching/restart", body), {
    invalidate: PATCH_KEYS,
    onSuccess: (r) => {
      outcome.report(when === "later" ? "Restart scheduled" : "Restart requested", r);
      onClose();
      onDone?.();
    },
  });
  const ids = devices.map((d) => d.id).join(",");
  const replan = (pending: boolean) => {
    setConfirmed(new Set());
    plan.mutate({ ids: ids.split(","), always: !pending });
  };
  useEffect(() => {
    if (!open) return;
    setPendingOnly(initialPendingOnly);
    setMode("Countdown");
    setCountdown(5);
    setDeadline(240);
    setExpiry(120);
    setWhen("now");
    setAt(localInput(tonight()));
    restart.reset();
    replan(initialPendingOnly);
    // eslint-disable-next-line react-hooks/exhaustive-deps -- plan again when the dialog opens, not when the mutations change
  }, [open, ids]);

  const checks = plan.data?.devices ?? [];
  const servers = checks.filter((c) => c.restart && c.server);
  const others = checks.filter((c) => c.restart && !c.server);
  const skipped = checks.filter((c) => !c.restart);
  const chosenServers = servers.filter((c) => confirmed.has(c.deviceId));
  const sending = [...others, ...chosenServers];
  const allServers = servers.length > 0 && chosenServers.length === servers.length;
  const scheduledAt = when === "later" && at ? new Date(at) : null;
  const badTime = scheduledAt !== null && Number.isNaN(scheduledAt.getTime());
  const where = devices.length === 1 ? devices[0]!.name : plural(devices.length, "device");
  const tooMany = !pendingOnly && devices.length > MAX_ALWAYS;
  const tick = (id: string, on: boolean) =>
    setConfirmed((prev) => {
      const next = new Set(prev);
      if (on) next.add(id);
      else next.delete(id);
      return next;
    });
  const modeHint = RESTART_MODES.find((m) => m.value === mode)!.hint;

  return (
    <>
      <Dialog
        open={open}
        onClose={onClose}
        title={`Restart ${where}`}
        description={
          pendingOnly
            ? "Each device restarts only if it still needs a restart when the job runs."
            : "Each device restarts whether or not it needs a restart."
        }
        footer={
          <>
            <Button onClick={onClose} disabled={restart.isPending}>
              Cancel
            </Button>
            <Button
              variant="primary"
              loading={restart.isPending}
              disabled={tooMany || !plan.data || plan.isPending || sending.length === 0 || badTime || (when === "later" && !at)}
              onClick={() =>
                restart.mutate({
                  deviceIds: sending.map((c) => c.deviceId),
                  confirmServers: chosenServers.length > 0 ? chosenServers.map((c) => c.deviceId) : undefined,
                  mode,
                  condition: pendingOnly ? "OnlyIfPending" : "Always",
                  countdownMinutes: mode === "Countdown" ? countdown : undefined,
                  deadlineMinutes: mode === "PromptWithDeadline" ? deadline : undefined,
                  expiresAfterMinutes: expiry,
                  scheduledAt: scheduledAt && !badTime ? scheduledAt.toISOString() : undefined,
                })
              }
            >
              {sending.length === 0
                ? "Restart"
                : when === "later"
                  ? `Schedule restart of ${plural(sending.length, "device")}`
                  : `Restart ${plural(sending.length, "device")}`}
            </Button>
          </>
        }
      >
        <div className="space-y-4">
          <div>
            <label className="flex items-center gap-2 text-sm">
              <input
                type="checkbox"
                checked={pendingOnly}
                onChange={(e) => {
                  setPendingOnly(e.target.checked);
                  if (e.target.checked || devices.length <= MAX_ALWAYS) replan(e.target.checked);
                }}
                className="size-4 accent-accent"
              />
              Only if a restart is pending
            </label>
            <p className="mt-0.5 pl-6 text-xs text-muted">
              {pendingOnly
                ? "Devices that no longer need a restart when the job runs are left alone."
                : `Restarts every device chosen, at most ${MAX_ALWAYS.toLocaleString()} at once.`}
            </p>
          </div>
          {tooMany ? (
            <Alert tone="warn" title={`Choose at most ${MAX_ALWAYS.toLocaleString()} devices`}>
              EasyRMM checks each device before restarting it whether or not a restart is pending. Choose fewer, or restart only where one is pending.
            </Alert>
          ) : plan.isPending || plan.isIdle ? (
            <Spinner />
          ) : plan.isError ? (
            <ErrorState error={plan.error} onRetry={() => replan(pendingOnly)} compact />
          ) : (
            <>
              {servers.length > 0 && (
                <fieldset className="space-y-2">
                  <legend className="mb-1 text-sm font-medium">
                    {plan.data!.serversKnown ? "Servers restart only when you tick them" : "Tick each device to restart"}
                  </legend>
                  <p className="text-xs text-muted">
                    {plan.data!.serversKnown
                      ? "A restart interrupts everyone using the server."
                      : "Your EasyPatch server is older than 1.10.0 and cannot say which devices are servers, so each one waits for your tick."}
                  </p>
                  <ul className="max-h-48 divide-y divide-line overflow-y-auto rounded-md border border-line">
                    {servers.length > 1 && (
                      <li className="px-3 py-2">
                        <label className="flex items-center gap-2 text-sm font-medium">
                          <input
                            type="checkbox"
                            checked={allServers}
                            ref={(el) => {
                              if (el) el.indeterminate = chosenServers.length > 0 && !allServers;
                            }}
                            onChange={(e) => setConfirmed(e.target.checked ? new Set(servers.map((c) => c.deviceId)) : new Set())}
                            className="size-4 accent-accent"
                          />
                          {`All ${servers.length.toLocaleString()}`}
                        </label>
                      </li>
                    )}
                    {servers.map((c) => (
                      <li key={c.deviceId} className="px-3 py-2">
                        <label className="flex items-center gap-2 text-sm">
                          <input
                            type="checkbox"
                            checked={confirmed.has(c.deviceId)}
                            onChange={(e) => tick(c.deviceId, e.target.checked)}
                            className="size-4 accent-accent"
                          />
                          <span className="min-w-0 break-words">Restart {c.deviceName}</span>
                          {!c.online && <span className="ml-auto shrink-0 text-xs text-muted">Offline</span>}
                        </label>
                      </li>
                    ))}
                  </ul>
                </fieldset>
              )}
              {others.length > 0 && (
                <div>
                  <h3 className="mb-1.5 text-xs font-medium text-muted">{servers.length > 0 ? "Also restarts" : "Restarts"}</h3>
                  <ul className="max-h-40 space-y-0.5 overflow-y-auto text-sm">
                    {others.map((c) => (
                      <li key={c.deviceId} className="flex items-baseline gap-2">
                        <span className="min-w-0 break-words">{c.deviceName}</span>
                        {!c.online && <span className="text-xs text-muted">Offline</span>}
                      </li>
                    ))}
                  </ul>
                </div>
              )}
              {skipped.length > 0 && (
                <div>
                  <h3 className="mb-1.5 text-xs font-medium text-muted">{servers.length + others.length > 0 ? "Not restarted" : "Nothing to restart"}</h3>
                  <ul className="max-h-40 divide-y divide-line overflow-y-auto rounded-md border border-line">
                    {skipped.map((c) => (
                      <li key={c.deviceId} className="px-3 py-2 text-sm">
                        <span className="font-medium">{c.deviceName}</span>
                        <p className="text-muted">{c.reason}</p>
                      </li>
                    ))}
                  </ul>
                </div>
              )}
              {servers.length + others.length > 0 && (
                <>
                  <fieldset className="space-y-2" aria-describedby={modeId}>
                    <legend className="text-xs font-medium text-muted">Signed-in users</legend>
                    {RESTART_MODES.map((m) => (
                      <div key={m.value} className="flex flex-wrap items-center gap-x-2 gap-y-1">
                        <label className="flex items-center gap-2 text-sm">
                          <input
                            type="radio"
                            name="restart-mode"
                            checked={mode === m.value}
                            onChange={() => setMode(m.value)}
                            className="size-4 accent-accent"
                          />
                          {m.label}
                        </label>
                        {m.value === "Countdown" && mode === "Countdown" && (
                          <Select aria-label="Countdown" value={countdown} onChange={(e) => setCountdown(Number(e.target.value))} className="w-auto">
                            {COUNTDOWNS.map((n) => (
                              <option key={n} value={n}>
                                {minutesText(n)}
                              </option>
                            ))}
                          </Select>
                        )}
                        {m.value === "PromptWithDeadline" && mode === "PromptWithDeadline" && (
                          <Select aria-label="Deadline" value={deadline} onChange={(e) => setDeadline(Number(e.target.value))} className="w-auto">
                            {DEADLINES.map((n) => (
                              <option key={n} value={n}>
                                within {minutesText(n)}
                              </option>
                            ))}
                          </Select>
                        )}
                      </div>
                    ))}
                    <p id={modeId} className="text-xs text-muted">
                      {modeHint}
                    </p>
                    {mode !== "Immediate" && (
                      <p className="text-xs text-subtle">
                        Nobody signed in: the device restarts at once. Without EasyPatch&apos;s tray icon (Linux, macOS, or Windows where it is not running),
                        users get the system&apos;s shutdown warning, and asking waits for the deadline, or for the icon when there is none.
                      </p>
                    )}
                  </fieldset>
                  <fieldset className="space-y-2" aria-describedby={whenId}>
                    <legend className="text-xs font-medium text-muted">When</legend>
                    <label className="flex items-center gap-2 text-sm">
                      <input type="radio" name="restart-when" checked={when === "now"} onChange={() => setWhen("now")} className="size-4 accent-accent" />
                      Now
                    </label>
                    <label className="flex flex-wrap items-center gap-2 text-sm">
                      <input type="radio" name="restart-when" checked={when === "later"} onChange={() => setWhen("later")} className="size-4 accent-accent" />
                      At
                      <Input
                        type="datetime-local"
                        aria-label="Restart at"
                        value={at}
                        min={localInput(new Date())}
                        onChange={(e) => {
                          setAt(e.target.value);
                          setWhen("later");
                        }}
                        className="w-auto"
                      />
                    </label>
                    <p id={whenId} className="text-xs text-subtle">
                      Your time zone ({Intl.DateTimeFormat().resolvedOptions().timeZone}). Up to 31 days ahead.
                    </p>
                  </fieldset>
                  <Field
                    label="If a device is offline, wait for it"
                    htmlFor={expiryId}
                    hint="If it does not come back in time, EasyPatch drops its restart."
                    className="w-fit"
                  >
                    <Select id={expiryId} value={expiry} onChange={(e) => setExpiry(Number(e.target.value))} className="w-auto">
                      {EXPIRIES.map((n) => (
                        <option key={n} value={n}>
                          {minutesText(n)}
                        </option>
                      ))}
                    </Select>
                  </Field>
                </>
              )}
            </>
          )}
          <InlineError error={restart.error} />
        </div>
      </Dialog>
      {outcome.dialog}
    </>
  );
}

/** How far a running job has got, as the agent reports it. */
function JobProgress({ percent }: { percent: number }) {
  const p = Math.max(0, Math.min(100, percent));
  return (
    <div role="progressbar" aria-label="Progress" aria-valuemin={0} aria-valuemax={100} aria-valuenow={p} className="h-1.5 overflow-hidden rounded-full bg-line">
      <div className="h-full rounded-full bg-accent transition-[width] duration-500 motion-reduce:transition-none" style={{ width: `${p}%` }} />
    </div>
  );
}

/**
 * One EasyPatch job: its updates and what happened, refreshing while it runs; cancellable, or run again once
 * finished, where the caller may. A retry is a new job, which onJob opens.
 */
export function PatchJobDialog({ jobId, onClose, onJob }: { jobId: string | null; onClose: () => void; onJob: (id: string) => void }) {
  const toast = useToast();
  const job = useApi<PatchJobDetail>(jobId ? `/patching/jobs/${jobId}` : null, undefined, {
    refetchInterval: (data) => (data && !isActiveJob(data.summary) ? false : 4_000),
  });
  const cancel = useApiMutation(() => api.post<PatchJobDetail>(`/patching/jobs/${jobId}/cancel`), {
    invalidate: PATCH_KEYS,
    onSuccess: (j) => toast.success(isActiveJob(j.summary) ? "Asked the device to stop." : "Job cancelled."),
  });
  const retry = useApiMutation(() => api.post<PatchJobView>(`/patching/jobs/${jobId}/retry`), {
    invalidate: PATCH_KEYS,
    onSuccess: (j) => {
      toast.success("Retry queued.");
      onJob(j.id);
    },
  });
  useEffect(() => {
    cancel.reset();
    retry.reset();
    // eslint-disable-next-line react-hooks/exhaustive-deps -- reset when another job opens
  }, [jobId]);
  const d = job.data;
  const s = d?.summary;
  const outcome = s ? jobOutcome(s) : "";

  return (
    <Dialog
      open={jobId !== null}
      onClose={onClose}
      size="lg"
      title={s ? `${jobTypeLabel(s.type)} on ${d.deviceName}` : "Patch job"}
      footer={
        <>
          {jobId && (
            <EasyPatchLink to={{ job: jobId }} className="mr-auto text-sm">
              Open in EasyPatch
            </EasyPatchLink>
          )}
          {d?.canManage && s && isActiveJob(s) && !s.cancelRequested && (
            <Button variant="danger-ghost" loading={cancel.isPending} onClick={() => cancel.mutate()}>
              Cancel job
            </Button>
          )}
          {d?.canManage && s && canRetry(s) && (
            <Button icon={<RotateCcw className="size-4" aria-hidden />} loading={retry.isPending} onClick={() => retry.mutate()}>
              Retry
            </Button>
          )}
          <Button onClick={onClose}>Close</Button>
        </>
      }
    >
      {job.isPending ? (
        <Spinner />
      ) : job.isError ? (
        <ErrorState error={job.error} onRetry={() => void job.refetch()} compact />
      ) : (
        s && (
          <div className="space-y-4">
            <InlineError error={cancel.error ?? retry.error} />
            {s.errorMessage && (
              <Alert tone="danger" title="EasyPatch reported an error">
                {s.errorMessage}
                {s.errorCode && <span className="block text-xs text-muted">{s.errorCode}</span>}
              </Alert>
            )}
            {s.cancelRequested && isActiveJob(s) && (
              <Alert tone="info" title="Cancellation requested">
                {d.cancelRequestedAt ? `Asked ${formatRelative(d.cancelRequestedAt)}. ` : ""}The device stops at its next check-in or the next safe point.
              </Alert>
            )}
            {s.timedOut && (
              <Alert tone="warn" title="The job ran out of time">
                The device stopped reporting progress, so EasyPatch gave up on it.
              </Alert>
            )}
            {isActiveJob(s) && s.progressPercent !== null && <JobProgress percent={s.progressPercent} />}
            <KeyValueList
              narrow
              items={[
                ["Status", <PatchJobBadge key="s" job={s} />],
                ...(s.progressMessage && isActiveJob(s) ? [["Now", s.progressMessage] as [string, string]] : []),
                ...(outcome ? [["Result", outcome] as [string, string]] : []),
                ...(d.notBefore ? [["Starts", formatDateTime(d.notBefore)] as [string, string]] : []),
                [
                  "Requested",
                  <span key="r">
                    {formatDateTime(s.createdAt)}{" "}
                    <span className="text-muted">{s.trigger === "Manual" ? `by ${requester(s.requestedBy)}` : triggerLabel(s.trigger).toLowerCase()}</span>
                  </span>,
                ],
                ...(d.retryOfJobId
                  ? [
                      [
                        "Runs again",
                        <button key="retry" type="button" className="rounded-sm text-left text-accent hover:underline" onClick={() => onJob(d.retryOfJobId!)}>
                          The earlier job
                        </button>,
                      ] as [string, ReactNode],
                    ]
                  : []),
                // A queued job waits for its device until then.
                ...(s.status === "Queued" ? [["Gives up at", formatDateTime(s.expiresAt)] as [string, string]] : []),
                ...(d.deliveredAt
                  ? [
                      [
                        "Sent to the device",
                        d.deliveryCount > 1 ? `${formatDateTime(d.deliveredAt)} (${d.deliveryCount.toLocaleString()} times)` : formatDateTime(d.deliveredAt),
                      ] as [string, string],
                    ]
                  : []),
                ...(s.startedAt ? [["Started", formatDateTime(s.startedAt)] as [string, string]] : []),
                ...(s.completedAt ? [["Finished", formatDateTime(s.completedAt)] as [string, string]] : []),
                ...(s.rebootRequired ? [["Restart", "Needed to finish"] as [string, string]] : []),
              ]}
            />
            {d.items.length > 0 && (
              <div>
                <h3 className="mb-1.5 text-xs font-medium text-muted">Updates</h3>
                <ul className="divide-y divide-line rounded-md border border-line">
                  {d.items.map((it) => (
                    <li key={it.updateGuid} className="flex items-start justify-between gap-3 px-3 py-2 text-sm">
                      <span className="min-w-0">
                        <span className="block break-words">{it.title}</span>
                        <span className="text-xs text-muted">
                          {categoryLabel(it.category)}
                          {it.skipReason && ` · ${it.skipReason}`}
                          {it.errorMessage && <span className="text-danger"> · {it.errorMessage}</span>}
                        </span>
                      </span>
                      <Badge tone={it.status === "Succeeded" ? "ok" : it.status === "Failed" ? "danger" : "neutral"}>
                        {it.status}
                        {it.installPercent !== null && it.status === "Installing" ? ` · ${it.installPercent}%` : ""}
                        {it.downloadPercent !== null && it.status === "Downloading" ? ` · ${it.downloadPercent}%` : ""}
                      </Badge>
                    </li>
                  ))}
                </ul>
              </div>
            )}
            {d.events.length > 0 && (
              <div>
                <h3 className="mb-1.5 text-xs font-medium text-muted">Events</h3>
                <ol className="space-y-1 text-sm">
                  {d.events.map((e) => (
                    <li key={e.id} className="flex gap-3">
                      <span className="shrink-0 text-xs whitespace-nowrap text-muted tabular-nums" title={formatDateTime(e.createdAt)}>
                        {formatRelative(e.createdAt)}
                      </span>
                      <span className={e.severity === "Error" ? "text-danger" : e.severity === "Warning" ? "text-warn" : undefined}>{e.message}</span>
                    </li>
                  ))}
                </ol>
              </div>
            )}
          </div>
        )
      )}
    </Dialog>
  );
}
