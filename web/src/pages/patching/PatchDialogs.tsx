import { useEffect, useId, useState, type ReactNode } from "react";
import { Link } from "react-router";
import { RotateCcw } from "lucide-react";
import type { UseQueryResult } from "@tanstack/react-query";
import { api, errorMessage } from "../../api/client";
import { useApi, useApiMutation } from "../../api/hooks";
import type {
  PatchActionInput,
  PatchActionResult,
  PatchAvailablePlan,
  PatchInstallPreview,
  PatchJobDetail,
  PatchJobView,
  PatchRestartAfter,
  PatchTargets,
  RestartInput,
  RestartMode,
  RestartPlan,
} from "../../api/types";
import { Dialog } from "../../components/Dialog";
import { useToast } from "../../components/Toast";
import { Alert, Badge, Button, ErrorState, InlineError, Input, KeyValueList, Spinner } from "../../components/ui";
import { formatDateTime, formatRelative, formatSize, plural } from "../../lib/format";
import { canRetry, categoryLabel, isActiveJob, jobOutcome, jobTypeLabel, PatchJobBadge, requester, skipReasonText, triggerLabel } from "./patchText";
import {
  ExpiryField,
  localInput,
  MAX_ALWAYS,
  MAX_BULK,
  minutesText,
  PlanLists,
  RESTART_MODES,
  RestartModeFields,
  ServerTicks,
  splitPlan,
  tonight,
  useInstallRestart,
} from "./RestartFields";
import { AvailablePlanView, scopeLabel, ScopeSummary, scopeTargets, SkippedList, usePatchScope, usePlatforms, type ScopeTarget } from "./scopeParts";

/** What the patching views refresh after an action. */
export const PATCH_KEYS = ["/patching", "/audit"];

export interface PatchTarget {
  id: string;
  name: string;
}

/**
 * The outcome of a scan, install or restart. On chosen devices it is said in a toast, and devices that did not start
 * are listed in a dialog; on all of an organization or site, a dialog sums it up: the jobs, the restarts to follow, the
 * batches the patching engine did not take, and the devices left out.
 */
export function useOutcome() {
  const toast = useToast();
  const [result, setResult] = useState<{ verb: string; r: PatchActionResult } | null>(null);
  const report = (verb: string, r: PatchActionResult) => {
    if (r.scope || r.batches) {
      setResult({ verb, r });
      return;
    }
    if (r.succeeded > 0) {
      const after = r.restartAfter ? ` ${plural(r.restartAfter, "device")} ${r.restartAfter === 1 ? "is" : "are"} set to restart after the install.` : "";
      toast.success(`${verb} on ${plural(r.succeeded, "device")}.${after}`);
    }
    if (r.failed > 0) setResult({ verb, r });
  };
  const dialog = <ResultDialog result={result} onClose={() => setResult(null)} />;
  return { report, dialog };
}

function ResultDialog({ result, onClose }: { result: { verb: string; r: PatchActionResult } | null; onClose: () => void }) {
  const r = result?.r;
  const failed = r?.results.filter((x) => !x.ok) ?? [];
  const bulk = Boolean(r?.scope || r?.batches);
  const where = r?.scope ? ` in ${scopeLabel(r.scope.organizationName, r.scope.siteName)}` : "";
  const notTaken = r?.batches?.filter((b) => b.error) ?? [];
  return (
    <Dialog
      open={result !== null}
      onClose={onClose}
      title={!bulk ? `${plural(failed.length, "device")} did not start` : r && r.succeeded > 0 ? `${result!.verb}${where}` : `Nothing started${where}`}
      description={!bulk && r && r.succeeded > 0 ? `${plural(r.succeeded, "other device")} did.` : undefined}
      footer={<Button onClick={onClose}>Close</Button>}
    >
      <div className="space-y-4">
        {bulk && r && (
          <>
            <ul className="space-y-0.5 text-sm">
              <li>
                {plural(r.succeeded, "job")} created, one per device{r.failed > 0 ? `; ${plural(r.failed, "device")} did not start` : ""}.
              </li>
              {r.restartAfter !== undefined && (
                <li>
                  {plural(r.restartAfter, "device")} {r.restartAfter === 1 ? "is" : "are"} set to restart after the install.
                </li>
              )}
            </ul>
            {notTaken.length > 0 && (
              <Alert tone="danger" title={`The patching engine did not take ${plural(notTaken.length, "batch", "batches")}`}>
                <ul className="space-y-0.5">
                  {r.batches!.map((b, i) =>
                    b.error ? (
                      <li key={i}>
                        Batch {i + 1} of {r.batches!.length}: {plural(b.devices, "device")} not sent. {b.error}
                      </li>
                    ) : null,
                  )}
                </ul>
                <p className="mt-1 text-xs">Its devices are listed below. Start it again later; devices already started are not affected.</p>
              </Alert>
            )}
            {r.batches && r.batches.length > 1 && notTaken.length === 0 && (
              <p className="text-xs text-muted">Sent in {plural(r.batches.length, "batch", "batches")} of at most {MAX_BULK.toLocaleString()} devices.</p>
            )}
            {r.scope && <SkippedList skipped={r.scope.skipped} intro="Left out, as they stood when it was sent:" />}
          </>
        )}
        {failed.length > 0 && (
          <div>
            {bulk && <h3 className="mb-1.5 text-xs font-medium text-muted">Did not start ({failed.length.toLocaleString()})</h3>}
            <ul className="max-h-72 divide-y divide-line overflow-y-auto rounded-md border border-line">
              {failed.map((x) => (
                <li key={x.deviceId} className="px-3 py-2.5 text-sm">
                  <Link to={`/devices/${x.deviceId}?tab=patches`} className="font-medium hover:text-accent">
                    {x.deviceName}
                  </Link>
                  <p className="text-muted">{x.message || "The patching engine did not say why."}</p>
                </li>
              ))}
            </ul>
          </div>
        )}
      </div>
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
        description={`At its next check-in, within a minute, ${devices.length === 1 ? "the" : "each"} device's EasyRMM agent downloads the EasyPatch agent from the patching engine, checks it, installs it and enrolls it in the device's organization in the engine.`}
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
          <li>The device joins the patching engine site with the same name as its EasyRMM site, or no site when there is none.</li>
          <li>
            Linux devices need systemd and apt-get or dnf. If EasyRMM&apos;s certificate comes from a private authority, Linux devices need that
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

/** What an install on one device would do, from its last scan. */
function InstallPreviewList({ q }: { q: UseQueryResult<PatchInstallPreview> }) {
  if (q.isPending) return <Spinner label="Checking what would be installed…" />;
  if (q.isError) {
    return <p className="text-xs text-muted">What would be installed could not be checked ({errorMessage(q.error)}). The patching engine checks again when it installs.</p>;
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

/** Now, or at a time in the browser's zone, up to 31 days ahead. */
function WhenFields({ when, onWhen, at, onAt, label, note }: {
  when: "now" | "later";
  onWhen: (w: "now" | "later") => void;
  at: string;
  onAt: (v: string) => void;
  /** The time field's name: "Install at", "Restart at". */
  label: string;
  note: string;
}) {
  const id = useId();
  // Unique per dialog: closed dialogs stay in the page, and radios that shared a name would share one choice.
  const name = useId();
  return (
    <fieldset className="space-y-2" aria-describedby={id}>
      <legend className="text-xs font-medium text-muted">When</legend>
      <label className="flex items-center gap-2 text-sm">
        <input type="radio" name={name} checked={when === "now"} onChange={() => onWhen("now")} className="size-4 accent-accent" />
        Now
      </label>
      <label className="flex flex-wrap items-center gap-2 text-sm">
        <input type="radio" name={name} checked={when === "later"} onChange={() => onWhen("later")} className="size-4 accent-accent" />
        At
        <Input
          type="datetime-local"
          aria-label={label}
          value={at}
          min={localInput(new Date())}
          onChange={(e) => {
            onAt(e.target.value);
            onWhen("later");
          }}
          className="w-auto"
        />
      </label>
      <p id={id} className="text-xs text-subtle">
        Your time zone ({Intl.DateTimeFormat().resolvedOptions().timeZone}). {note}
      </p>
    </fieldset>
  );
}

/** What "all available updates" takes in, said once for the choice and the preview. */
const AVAILABLE_TEXT =
  "Security, critical, cumulative, definitions, servicing stack, .NET, drivers, other updates and the application updates the patch policy approves. Updates on hold or excluded on a device are left out. Feature upgrades only when ticked.";

/**
 * Installs updates: on chosen devices, every update their policy allows or chosen ones on one device; or on every
 * device of an organization or site the caller may patch (Patch all), what each policy allows or every available update.
 * Now or at a later time, and, when asked, each device restarts once its install has finished; servers only when
 * ticked by name. On one device, with preview, it first shows what EasyPatch would install and leave out.
 */
export function InstallDialog({
  open,
  onClose,
  devices = [],
  scope,
  preset,
  updates,
  preview = false,
  onDone,
}: {
  open: boolean;
  onClose: () => void;
  /** The chosen devices; or `scope` instead. */
  devices?: PatchTarget[];
  /** Every device of an organization or site the caller may patch, read by the server when the install is sent. */
  scope?: ScopeTarget;
  /** update-now: every available update, now, restarting if the updates need it, on Windows only; each can be changed. */
  preset?: "update-now";
  /** Chosen updates (one device only); every eligible update when absent. */
  updates?: { id: string; title: string }[];
  /** Show what the install would do first (one device only). */
  preview?: boolean;
  onDone?: () => void;
}) {
  const outcome = useOutcome();
  const updateNow = preset === "update-now";
  const previewing = open && preview && !scope && devices.length === 1;
  const pv = useApi<PatchInstallPreview>(
    previewing ? `/patching/devices/${devices[0]!.id}/install-preview` : null,
    updates ? { updateId: updates.map((u) => u.id) } : undefined,
    { staleTime: 0 },
  );
  const sc = usePatchScope(open && scope ? scope : null);
  const plat = usePlatforms(sc.data, open, !updateNow);
  const [what, setWhat] = useState<"policy" | "available">(updateNow ? "available" : "policy");
  const [features, setFeatures] = useState(false);
  const [when, setWhen] = useState<"now" | "later">("now");
  const [at, setAt] = useState(() => localInput(tonight()));
  const whatName = useId();
  useEffect(() => {
    if (open) {
      setWhen("now");
      setAt(localInput(tonight()));
    } else {
      // Back to the start once closed, so opening again checks nothing twice.
      setWhat(updateNow ? "available" : "policy");
      setFeatures(false);
    }
  }, [open, updateNow]);

  const count = scope ? plat.count : devices.length;
  const targets: PatchTargets | null = scope
    ? sc.data && plat.ready && plat.count > 0
      ? scopeTargets(scope, plat.platforms)
      : null
    : { deviceIds: devices.map((d) => d.id) };
  const available = scope !== undefined && what === "available";
  const tooManyAvailable = available && count > MAX_BULK;
  const availKey = open && available && targets && !tooManyAvailable ? JSON.stringify({ ...targets, features }) : "";
  const avail = useApiMutation((body: PatchTargets & { features: boolean }) => api.post<PatchAvailablePlan>("/patching/install/plan", body));
  const checkAvailable = () => {
    if (availKey) avail.mutate(JSON.parse(availKey) as PatchTargets & { features: boolean });
  };
  useEffect(() => {
    if (availKey) checkAvailable();
    else avail.reset();
    // eslint-disable-next-line react-hooks/exhaustive-deps -- check again when what is sent changes
  }, [availKey]);
  const rs = useInstallRestart({ open, targets, count, initial: updateNow ? "OnlyIfPending" : "none" });

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
  const nothing = available && avail.data !== undefined && avail.data.updates === 0 && avail.data.errors.length === 0;
  const blocked =
    badTime ||
    (when === "later" && !at) ||
    !rs.ready ||
    (scope !== undefined && targets === null) ||
    (available && (tooManyAvailable || !avail.isSuccess || nothing));
  const whatText = updates ? plural(updates.length, "chosen update") : "every update its policy allows";
  const where = devices.length === 1 ? devices[0]!.name : plural(devices.length, "device");
  const title = scope
    ? updateNow
      ? `Update all of ${scope.label} now`
      : `Patch all of ${scope.label}`
    : updates
      ? `Install ${plural(updates.length, "update")} on ${where}`
      : `Install updates on ${where}`;
  const reached = !scope || (sc.data !== undefined && sc.data.devices > 0);

  return (
    <>
      <Dialog
        open={open}
        onClose={onClose}
        title={title}
        description={
          scope
            ? "Reaches each device here that you may patch and whose EasyPatch agent EasyRMM has linked. EasyRMM reads the devices when you send this, so devices added since are included."
            : `The patching engine installs ${whatText}, downloading what it needs.`
        }
        footer={
          <>
            <Button onClick={onClose} disabled={install.isPending}>
              Cancel
            </Button>
            <Button
              variant="primary"
              loading={install.isPending}
              disabled={blocked}
              onClick={() =>
                install.mutate({
                  ...(scope ? targets! : { deviceIds: devices.map((d) => d.id) }),
                  updateIds: updates?.map((u) => u.id),
                  updates: scope ? what : undefined,
                  features: available ? features : undefined,
                  scheduledAt: scheduledAt && !badTime ? scheduledAt.toISOString() : undefined,
                  ...rs.body,
                })
              }
            >
              {when === "later" ? "Schedule install" : "Install now"}
            </Button>
          </>
        }
      >
        <div className="space-y-4">
          {scope && <ScopeSummary target={scope} q={sc} plat={plat} verb={when === "later" ? "install at the time set" : "install"} />}
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
          {scope && reached && (
            <fieldset className="space-y-2">
              <legend className="text-xs font-medium text-muted">What</legend>
              <label className="flex items-center gap-2 text-sm">
                <input type="radio" name={whatName} checked={what === "policy"} onChange={() => setWhat("policy")} className="size-4 accent-accent" />
                Updates each device&apos;s policy allows
              </label>
              <label className="flex items-center gap-2 text-sm">
                <input type="radio" name={whatName} checked={what === "available"} onChange={() => setWhat("available")} className="size-4 accent-accent" />
                All available updates
              </label>
              {what === "available" && (
                <div className="space-y-2 pl-6">
                  <p className="text-xs text-muted">{AVAILABLE_TEXT}</p>
                  <label className="flex items-center gap-2 text-sm">
                    <input type="checkbox" checked={features} onChange={(e) => setFeatures(e.target.checked)} className="size-4 accent-accent" />
                    Include feature upgrades (new Windows versions)
                  </label>
                </div>
              )}
            </fieldset>
          )}
          {available &&
            reached &&
            (tooManyAvailable ? (
              <Alert tone="warn" title={`All available updates reaches at most ${MAX_BULK.toLocaleString()} devices at once`}>
                This reaches {plural(count, "device")}. Choose a site or fewer platforms, or install the updates each device&apos;s policy allows.
              </Alert>
            ) : (
              targets && <AvailablePlanView plan={avail} onRetry={checkAvailable} />
            ))}
          {reached && (
            <WhenFields
              when={when}
              onWhen={setWhen}
              at={at}
              onAt={setAt}
              label="Install at"
              note="Up to 31 days ahead; the device must be online then."
            />
          )}
          {reached && (!scope || targets) && rs.element}
          <InlineError error={install.error} />
        </div>
      </Dialog>
      {outcome.dialog}
    </>
  );
}

/**
 * Restarts devices: chosen ones, or every device of an organization or site the caller may patch; by default only those
 * whose restart is still pending when the job runs, or all of them; after a countdown, by asking the people signed in
 * (with or without a deadline), or at once; now or at a time, waiting a while for devices that are offline. EasyRMM
 * first asks what the restart would do; servers restart only when ticked by name, and on all of an organization or site
 * those not ticked are left out.
 */
export function RestartDialog({
  open,
  onClose,
  devices = [],
  scope,
  pendingOnly: initialPendingOnly = true,
  initialWhen = "now",
  onDone,
}: {
  open: boolean;
  onClose: () => void;
  /** The chosen devices; or `scope` instead. */
  devices?: PatchTarget[];
  /** Every device of an organization or site the caller may patch, read by the server when the restart is sent. */
  scope?: ScopeTarget;
  /** Start with "only if a restart is pending" ticked; untick it for devices with nothing pending. */
  pendingOnly?: boolean;
  /** Start with now, or with a time (tonight). */
  initialWhen?: "now" | "later";
  onDone?: () => void;
}) {
  const outcome = useOutcome();
  const sc = usePatchScope(open && scope ? scope : null);
  const plat = usePlatforms(sc.data, open, true);
  const [pendingOnly, setPendingOnly] = useState(initialPendingOnly);
  const [mode, setMode] = useState<RestartMode>("Countdown");
  const [countdown, setCountdown] = useState(5);
  const [deadline, setDeadline] = useState(240);
  const [expiry, setExpiry] = useState(120);
  const [when, setWhen] = useState<"now" | "later">(initialWhen);
  const [at, setAt] = useState(() => localInput(tonight()));
  const [confirmed, setConfirmed] = useState<Set<string>>(new Set());
  const plan = useApiMutation((body: PatchTargets & { condition?: "Always" }) => api.post<RestartPlan>("/patching/restart/plan", body));
  const restart = useApiMutation((body: RestartInput) => api.post<PatchActionResult>("/patching/restart", body), {
    invalidate: PATCH_KEYS,
    onSuccess: (r) => {
      outcome.report(when === "later" ? "Restart scheduled" : "Restart requested", r);
      onClose();
      onDone?.();
    },
  });

  const count = scope ? plat.count : devices.length;
  const targets: PatchTargets | null = scope
    ? sc.data && plat.ready && plat.count > 0
      ? scopeTargets(scope, plat.platforms)
      : null
    : { deviceIds: devices.map((d) => d.id) };
  const key = targets ? JSON.stringify(targets) : "";
  const tooMany = !pendingOnly && count > MAX_ALWAYS;
  const replan = () => {
    if (!key || tooMany) return;
    setConfirmed(new Set());
    const t = JSON.parse(key) as PatchTargets;
    plan.mutate(pendingOnly ? t : { ...t, condition: "Always" });
  };
  // Back to the start once closed, so opening again plans once, with the choices it opens with.
  useEffect(() => {
    if (open) return;
    setPendingOnly(initialPendingOnly);
    setMode("Countdown");
    setCountdown(5);
    setDeadline(240);
    setExpiry(120);
    setWhen(initialWhen);
    setConfirmed(new Set());
    plan.reset();
    // eslint-disable-next-line react-hooks/exhaustive-deps -- back to the defaults when the dialog closes
  }, [open, initialPendingOnly, initialWhen]);
  useEffect(() => {
    if (!open) return;
    setAt(localInput(tonight()));
    restart.reset();
    // eslint-disable-next-line react-hooks/exhaustive-deps -- reset when the dialog opens, not when the mutation changes
  }, [open]);
  useEffect(() => {
    if (open) replan();
    // eslint-disable-next-line react-hooks/exhaustive-deps -- plan again when the devices or the condition change
  }, [open, key, pendingOnly, tooMany]);

  const { servers, others, skipped } = splitPlan(plan.data);
  const chosenServers = servers.filter((c) => confirmed.has(c.deviceId));
  const sending = [...others, ...chosenServers];
  const scheduledAt = when === "later" && at ? new Date(at) : null;
  const badTime = scheduledAt !== null && Number.isNaN(scheduledAt.getTime());
  const where = devices.length === 1 ? devices[0]!.name : plural(devices.length, "device");
  const reached = !scope || (sc.data !== undefined && sc.data.devices > 0);

  return (
    <>
      <Dialog
        open={open}
        onClose={onClose}
        title={scope ? `Restart all of ${scope.label}` : `Restart ${where}`}
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
              disabled={tooMany || !targets || !plan.data || plan.isPending || sending.length === 0 || badTime || (when === "later" && !at)}
              onClick={() =>
                restart.mutate({
                  ...(scope ? targets! : { deviceIds: sending.map((c) => c.deviceId) }),
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
          {scope && <ScopeSummary target={scope} q={sc} plat={plat} verb="can restart" />}
          {reached && (
            <div>
              <label className="flex items-center gap-2 text-sm">
                <input type="checkbox" checked={pendingOnly} onChange={(e) => setPendingOnly(e.target.checked)} className="size-4 accent-accent" />
                Only if a restart is pending
              </label>
              <p className="mt-0.5 pl-6 text-xs text-muted">
                {pendingOnly
                  ? "Devices that no longer need a restart when the job runs are left alone."
                  : `Restarts every device ${scope ? "here" : "chosen"}, at most ${MAX_ALWAYS.toLocaleString()} at once.`}
              </p>
            </div>
          )}
          {!reached || (scope && !targets) ? null : tooMany ? (
            <Alert tone="warn" title={`Choose at most ${MAX_ALWAYS.toLocaleString()} devices`}>
              {scope
                ? `This reaches ${plural(count, "device")}. EasyRMM checks each device before restarting it whether or not a restart is pending. Choose a site or fewer platforms, or restart only where one is pending.`
                : "EasyRMM checks each device before restarting it whether or not a restart is pending. Choose fewer, or restart only where one is pending."}
            </Alert>
          ) : plan.isPending || plan.isIdle ? (
            <Spinner />
          ) : plan.isError ? (
            <ErrorState error={plan.error} onRetry={replan} compact />
          ) : (
            <>
              <ServerTicks
                servers={servers}
                confirmed={confirmed}
                onChange={setConfirmed}
                note={
                  scope
                    ? "A restart interrupts everyone using the server. Servers you leave unticked are left out; the other devices restart."
                    : "A restart interrupts everyone using the server."
                }
              />
              <PlanLists servers={servers} others={others} skipped={skipped} />
              {servers.length + others.length > 0 && (
                <>
                  <RestartModeFields
                    mode={mode}
                    onMode={setMode}
                    countdown={countdown}
                    onCountdown={setCountdown}
                    deadline={deadline}
                    onDeadline={setDeadline}
                  />
                  <WhenFields when={when} onWhen={setWhen} at={at} onAt={setAt} label="Restart at" note="Up to 31 days ahead." />
                  <ExpiryField value={expiry} onChange={setExpiry} />
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

const RESTART_STATES: Record<PatchRestartAfter["state"], { label: string; tone: "info" | "ok" | "neutral" | "danger" }> = {
  waiting: { label: "Waiting for the install to finish", tone: "info" },
  done: { label: "Restart asked for", tone: "ok" },
  skipped: { label: "Not restarted", tone: "neutral" },
  failed: { label: "Restart refused", tone: "danger" },
};

/** The restart asked for with an install: the choice, how users are treated, and what became of it. */
function RestartAfterView({ r, onJob }: { r: PatchRestartAfter; onJob: (id: string) => void }) {
  const mode = RESTART_MODES.find((m) => m.value === r.mode)?.label ?? r.mode;
  const how =
    r.mode === "Countdown" && r.countdownMinutes
      ? `${mode}, after ${minutesText(r.countdownMinutes)}`
      : r.mode === "PromptWithDeadline" && r.deadlineMinutes
        ? `${mode}, within ${minutesText(r.deadlineMinutes)}`
        : mode;
  const state = RESTART_STATES[r.state] ?? { label: r.state, tone: "neutral" as const };
  const link = (id: string, text: string) => (
    <button type="button" className="rounded-sm text-left text-accent hover:underline" onClick={() => onJob(id)}>
      {text}
    </button>
  );
  const items: [string, ReactNode][] = [
    ["Asked for", r.condition === "Always" ? "Restart when done" : "Restart if the updates need it"],
    ["Signed-in users", how],
    ...(r.expiresAfterMinutes ? [["If offline", `Wait ${minutesText(r.expiresAfterMinutes)}`] as [string, ReactNode]] : []),
    ...(r.server ? [["Server", "Ticked by name to restart"] as [string, ReactNode]] : []),
    [
      "State",
      <span key="state" className="flex flex-col items-start gap-0.5">
        <Badge tone={state.tone}>{state.label}</Badge>
        {r.message && <span className="text-muted">{r.message}</span>}
      </span>,
    ],
    ...(r.restartJobId ? [["Restart job", link(r.restartJobId, "The restart after the install")] as [string, ReactNode]] : []),
    ...(r.midwayJobId ? [["Restart to go on", link(r.midwayJobId, "The restart the install waited for")] as [string, ReactNode]] : []),
    ...(r.requestedAt
      ? [["Requested", `${formatDateTime(r.requestedAt)}${r.requestedBy ? ` by ${requester(r.requestedBy)}` : ""}`] as [string, ReactNode]]
      : []),
  ];
  return (
    <section aria-label="Restart after the install">
      <h3 className="mb-1.5 text-xs font-medium text-muted">Restart after the install</h3>
      <KeyValueList narrow items={items} />
    </section>
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
              <Alert tone="danger" title="The patching engine reported an error">
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
                The device stopped reporting progress, so the patching engine gave up on it.
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
                ...(d.restartFor
                  ? [
                      [
                        "Restart after",
                        <button key="for" type="button" className="rounded-sm text-left text-accent hover:underline" onClick={() => onJob(d.restartFor!)}>
                          The install job
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
            {d.restartAfter && <RestartAfterView r={d.restartAfter} onJob={onJob} />}
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
