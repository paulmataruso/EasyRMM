import { useEffect, useState, type ReactNode } from "react";
import { Link } from "react-router";
import { ExternalLink, RotateCcw } from "lucide-react";
import { api } from "../../api/client";
import { useApi, useApiMutation } from "../../api/hooks";
import type { PatchJob, PatchJobDetail, PatchJobFacts, PatchJobItem, PatchJobUpdateFacts, PatchJobView, PatchRestartAfter } from "../../api/types";
import { Dialog } from "../../components/Dialog";
import { useToast } from "../../components/Toast";
import { Alert, Badge, Button, ErrorState, InlineError, KeyValueList, Mono, Spinner } from "../../components/ui";
import { formatDate, formatDateTime, formatDuration, formatRelative, formatSize, plural } from "../../lib/format";
import { platformName } from "../devices/platform";
import { explainCode } from "./hresult";
import {
  canRetry,
  categoryLabel,
  isActiveJob,
  jobOutcome,
  jobTypeLabel,
  PatchJobBadge,
  requester,
  skipReasonText,
  triggerLabel,
  UpdateStateBadge,
} from "./patchText";
import { PATCH_KEYS } from "./PatchDialogs";
import { minutesText, RESTART_MODES } from "./RestartFields";

/** Lists longer than these show their first entries, and a button for the rest. */
export const UPDATES_SHOWN = 25;
export const EVENTS_SHOWN = 20;
export const CVES_SHOWN = 5;

/**
 * One EasyPatch job in full: what it did, how it started, the device it ran on, each of its updates with what the
 * patching engine knows of it, and what happened when; refreshing while it runs. It is cancellable, or run again once
 * finished, where the caller may. A retry is a new job, which onJob opens.
 */
export function PatchJobDialog({ jobId, onClose, onJob }: { jobId: string | null; onClose: () => void; onJob: (id: string) => void }) {
  const toast = useToast();
  // The job's status refreshes every 4 seconds while it runs; what the engine knows of its updates (two lists of the
  // device's updates) is read once per opening, and again only if the job comes to list more updates.
  const job = useApi<PatchJobDetail>(jobId ? `/patching/jobs/${jobId}` : null, undefined, {
    refetchInterval: (data) => (data && !isActiveJob(data.summary) ? false : 4_000),
  });
  const itemCount = job.data?.items.length ?? 0;
  const facts = useApi<PatchJobFacts>(jobId && itemCount > 0 ? `/patching/jobs/${jobId}/facts` : null, undefined, {
    key: ["patching-job-facts", jobId, itemCount],
    staleTime: Infinity,
    gcTime: 0,
    refetchOnWindowFocus: false,
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
        d && (
          <div className="space-y-6">
            <InlineError error={cancel.error ?? retry.error} />
            <JobSummary d={d} />
            <JobOrigin d={d} onJob={onJob} />
            <JobDevice d={d} />
            {d.restartAfter && <RestartAfterView r={d.restartAfter} onJob={onJob} />}
            {d.items.length > 0 && <JobUpdates d={d} facts={facts.data} factsError={facts.error} />}
            <JobTimeline d={d} />
          </div>
        )
      )}
    </Dialog>
  );
}

/** A section of the job, under its heading. */
function Section({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section aria-label={title}>
      <h3 className="mb-2 text-xs font-medium tracking-wide text-muted uppercase">{title}</h3>
      {children}
    </section>
  );
}

/** A button that shows the rest of a long list. */
function ShowAll({ total, what, onClick }: { total: number; what: string; onClick: () => void }) {
  return (
    <button type="button" className="mt-1.5 rounded-sm text-xs text-accent hover:underline" onClick={onClick}>
      Show all {total.toLocaleString()} {what}
    </button>
  );
}

// ---------------------------------------------------------------- summary

/** How long a job took, or has been running. */
function took(s: PatchJob, now = Date.now()): string | null {
  if (!s.startedAt) return null;
  const end = s.completedAt ? Date.parse(s.completedAt) : now;
  return formatDuration((end - Date.parse(s.startedAt)) / 1000);
}

/** The job at a glance: its state, what it did, how long it took, and why it stopped if it did not finish well. */
function JobSummary({ d }: { d: PatchJobDetail }) {
  const s = d.summary;
  const outcome = jobOutcome(s);
  const duration = took(s);
  const active = isActiveJob(s);
  const restart = s.rebootRequired
    ? "Needed to finish"
    : s.type === "InstallUpdates" && s.status === "Completed"
      ? "Not needed"
      : null;
  return (
    <section aria-label="Summary" className="space-y-3">
      {s.errorMessage || s.errorCode ? (
        <Alert tone="danger" title="The patching engine reported an error">
          {s.errorMessage && <span className="block">{s.errorMessage}</span>}
          {s.errorCode && <CodeMeaning code={s.errorCode} />}
        </Alert>
      ) : null}
      {s.cancelRequested && active && (
        <Alert tone="info" title="Cancellation requested">
          {d.cancelRequestedAt ? `Asked ${formatRelative(d.cancelRequestedAt)}. ` : ""}The device stops at its next check-in or the next safe point.
        </Alert>
      )}
      {s.timedOut && (
        <Alert tone="warn" title="The job ran out of time">
          The device stopped reporting progress, so the patching engine gave up on it.
        </Alert>
      )}
      {active && s.progressPercent !== null && <JobProgress percent={s.progressPercent} />}
      <KeyValueList
        narrow
        items={[
          ["Status", <PatchJobBadge key="s" job={s} />],
          ...(s.progressMessage && active ? [["Now", s.progressMessage] as [string, string]] : []),
          ...(outcome ? [["Result", outcome] as [string, string]] : []),
          ...(duration ? [[s.completedAt ? "Took" : "Running for", duration] as [string, string]] : []),
          ...(restart ? [["Restart", restart] as [string, string]] : []),
          ...(d.notBefore ? [["Starts", formatDateTime(d.notBefore)] as [string, string]] : []),
          [
            "Requested",
            <span key="r">
              {formatDateTime(s.createdAt)}{" "}
              <span className="text-muted">{s.trigger === "Manual" ? `by ${requester(s.requestedBy)}` : triggerLabel(s.trigger).toLowerCase()}</span>
            </span>,
          ],
          // A queued job waits for its device until then.
          ...(s.status === "Queued" ? [["Gives up at", formatDateTime(s.expiresAt)] as [string, string]] : []),
        ]}
      />
    </section>
  );
}

function JobLink({ id, text, onJob }: { id: string; text: string; onJob: (id: string) => void }) {
  return (
    <button type="button" className="rounded-sm text-left text-accent hover:underline" onClick={() => onJob(id)}>
      {text}
    </button>
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

/** An error code with what it means: an HRESULT in hex and EasyRMM's explanation, or the code as reported. */
function CodeMeaning({ code }: { code: string }) {
  const e = explainCode(code);
  if (e.kind === "other") {
    return (
      <span className="block text-xs">
        Code <Mono>{e.code}</Mono>
      </span>
    );
  }
  return (
    <span className="block text-xs">
      <Mono>{e.hex}</Mono>{" "}
      {e.kind === "known" ? (
        <>
          {e.meaning}
          {e.advice && <span className="block text-muted">{e.advice}</span>}
        </>
      ) : (
        <span className="text-muted">Unknown code{e.windowsUpdate ? " (a Windows Update error EasyRMM has no explanation for)" : ""}.</span>
      )}
    </span>
  );
}

// ---------------------------------------------------------------- origin

/** EasyRMM's audit actions that start jobs. */
const ORIGIN_ACTIONS: Record<string, string> = {
  "patch.install": "Install",
  "patch.scan": "Scan",
  "patch.restart": "Restart",
  "patch.retry": "Retry",
  "patch.remove_update": "Update removal",
  "patch.agent_update": "EasyPatch agent update",
  "patch.notify": "Message to the user",
  "patch.refresh": "Inventory refresh",
};

function updatesText(updates: string, features: boolean | null): string {
  if (updates === "all eligible") return "Every update the patch policy approves";
  if (updates === "all available") return `Every available update, ${features ? "with" : "without"} feature upgrades`;
  const n = Number(updates);
  return Number.isInteger(n) ? `${plural(n, "chosen update")}` : updates;
}

/** How the job started: who or what asked for it, as part of what, and what it was asked to do. */
function JobOrigin({ d, onJob }: { d: PatchJobDetail; onJob: (id: string) => void }) {
  const s = d.summary;
  const o = d.origin;
  const items: [string, ReactNode][] = [];
  if (o) {
    items.push(["Started by", `${o.system ? "EasyRMM" : requester(o.by)}, ${formatDateTime(o.at)}`]);
    items.push(["As", ORIGIN_ACTIONS[o.action] ?? o.action]);
    if (o.patchAll) {
      items.push([
        "Part of",
        <span key="all">
          A request for every device in {o.patchAll}
          {o.requestId && (
            <span className="block text-xs text-muted">
              Request <Mono>{o.requestId}</Mono>
            </span>
          )}
        </span>,
      ]);
    }
    if (o.updates) items.push(["Updates", updatesText(o.updates, o.featureUpgrades)]);
    if (o.scheduledAt) items.push(["Scheduled for", formatDateTime(o.scheduledAt)]);
  } else if (d.restartFor) {
    items.push(["Started by", "EasyRMM, once the install it follows finished"]);
  } else {
    items.push(["Started", s.trigger === "Manual" ? `By hand, by ${requester(s.requestedBy)}` : triggerLabel(s.trigger)]);
    items.push([
      "Note",
      <span key="n" className="text-muted">
        {s.trigger === "Scheduled"
          ? "The device's patch policy started it in its maintenance window."
          : s.trigger === "System"
            ? "The patching engine started it on its own."
            : "EasyRMM has no record of starting it: it was started in the patching engine itself, or before EasyRMM kept these records."}
      </span>,
    ]);
  }
  if (d.retryOfJobId) items.push(["Retry of", <JobLink key="retry" id={d.retryOfJobId} onJob={onJob} text="The earlier job" />]);
  if (d.restartFor) items.push(["Follows", <JobLink key="for" id={d.restartFor} onJob={onJob} text="The install job" />]);
  return (
    <Section title="How it started">
      <KeyValueList narrow items={items} />
    </Section>
  );
}

// ---------------------------------------------------------------- device

const SUPPORT: Record<string, { label: string; tone: "warn" | "danger" }> = {
  ExtendedSecurityUpdates: { label: "Extended security updates only", tone: "warn" },
  Unsupported: { label: "No more security updates", tone: "danger" },
};

/** The device the job ran on, as EasyRMM and the patching engine know it. */
function JobDevice({ d }: { d: PatchJobDetail }) {
  const dev = d.device;
  const e = dev.endpoint;
  const os = e?.operatingSystem || dev.os;
  const support = e ? SUPPORT[e.osSupportStatus] : undefined;
  const items: [string, ReactNode][] = [
    [
      "Device",
      <span key="d">
        <Link to={`/devices/${d.deviceId}?tab=patches`} className="text-accent hover:underline">
          {d.deviceName}
        </Link>
        <span className="block text-xs text-muted">
          {dev.organizationName} / {dev.siteName}
        </span>
      </span>,
    ],
    [
      "Operating system",
      <span key="os">
        {os || platformName(dev.platform)}
        {e?.osBuild && <span className="text-muted"> (build {e.osBuild})</span>}
        {support && (
          <Badge tone={support.tone} className="ml-2">
            {support.label}
          </Badge>
        )}
      </span>,
    ],
    ["EasyRMM agent", dev.agentVersion ?? <span className="text-muted">None</span>],
  ];
  if (e) {
    items.push([
      "EasyPatch agent",
      <span key="ep">
        {e.agentVersion || <span className="text-muted">Not reported</span>}
        {e.agentOutdated && (
          <Badge tone="warn" className="ml-2">
            Outdated
          </Badge>
        )}
      </span>,
    ]);
    items.push([
      "Patching engine",
      <span key="pe">
        {e.online ? "Online" : "Offline"}
        {e.lastCheckInAt && <span className="text-muted">, last checked in {formatRelative(e.lastCheckInAt)}</span>}
        {e.rebootPending && <span className="block text-xs text-warn">A restart is pending on the device.</span>}
      </span>,
    ]);
  }
  return (
    <Section title="Device">
      <KeyValueList narrow items={items} />
      {!e && <p className="mt-2 text-xs text-muted">The patching engine could not be read, so its view of the device is not shown.</p>}
    </Section>
  );
}

// ---------------------------------------------------------------- restart after the install

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
    ...(r.restartJobId ? [["Restart job", <JobLink key="r" id={r.restartJobId} onJob={onJob} text="The restart after the install" />] as [string, ReactNode]] : []),
    ...(r.midwayJobId ? [["Restart to go on", <JobLink key="m" id={r.midwayJobId} onJob={onJob} text="The restart the install waited for" />] as [string, ReactNode]] : []),
    ...(r.requestedAt
      ? [["Requested", `${formatDateTime(r.requestedAt)}${r.requestedBy ? ` by ${requester(r.requestedBy)}` : ""}`] as [string, ReactNode]]
      : []),
  ];
  return (
    <Section title="Restart after the install">
      <KeyValueList narrow items={items} />
    </Section>
  );
}

// ---------------------------------------------------------------- updates

const ITEM_TONES: Record<string, "ok" | "danger" | "info" | "neutral"> = {
  Succeeded: "ok",
  Failed: "danger",
  Downloading: "info",
  Downloaded: "info",
  Installing: "info",
};

/** Windows Update's result of an update (OperationResultCode), where it says more than the status. */
const RESULT_CODES: Record<number, string> = {
  3: "Installed, with errors",
  5: "Stopped before it finished",
};

/**
 * The job's updates: totals, then each with what the patching engine knows of it (facts, undefined until read;
 * factsError when they could not be).
 */
function JobUpdates({ d, facts, factsError }: { d: PatchJobDetail; facts: PatchJobFacts | undefined; factsError: Error | null }) {
  const [all, setAll] = useState(false);
  const counts = new Map<string, number>();
  for (const it of d.items) counts.set(it.status, (counts.get(it.status) ?? 0) + 1);
  const known = facts ? d.items.map((it) => facts.updateFacts[it.updateGuid]?.sizeBytes ?? null).filter((n): n is number => n !== null) : [];
  const exploited = facts ? d.items.filter((it) => facts.updateFacts[it.updateGuid]?.knownExploited).length : 0;
  const unread = factsError ? factsError.message : (facts?.updateFactsError ?? null);
  const restart = d.items.filter((it) => it.rebootRequired).length;
  const shown = all ? d.items : d.items.slice(0, UPDATES_SHOWN);
  return (
    <Section title="Updates">
      <ul aria-label="Totals" className="mb-2 flex flex-wrap gap-x-4 gap-y-0.5 text-sm text-muted">
        <li>
          <span className="text-fg tabular-nums">{d.items.length.toLocaleString()}</span> in all
        </li>
        {[...counts].map(([status, n]) => (
          <li key={status}>
            {status}: <span className="text-fg tabular-nums">{n.toLocaleString()}</span>
          </li>
        ))}
        {known.length > 0 && (
          <li>
            Size: <span className="text-fg">{formatSize(known.reduce((a, b) => a + b, 0))}</span>
            {known.length < d.items.length && ` (${plural(d.items.length - known.length, "size")} unknown)`}
          </li>
        )}
        {exploited > 0 && <li className="text-danger">{plural(exploited, "update")} fixing exploited flaws</li>}
        {restart > 0 && <li>{plural(restart, "update")} need a restart</li>}
      </ul>
      {unread !== null && (
        <Alert tone="warn" title="The patching engine's details of these updates could not be read" className="mb-2">
          {unread}
        </Alert>
      )}
      <ul className="divide-y divide-line rounded-md border border-line">
        {shown.map((it) => (
          <UpdateRow key={it.updateGuid} it={it} facts={facts?.updateFacts[it.updateGuid]} unread={!facts || unread !== null} />
        ))}
      </ul>
      {!all && d.items.length > UPDATES_SHOWN && <ShowAll total={d.items.length} what="updates" onClick={() => setAll(true)} />}
    </Section>
  );
}

function UpdateRow({ it, facts, unread }: { it: PatchJobItem; facts: PatchJobUpdateFacts | undefined; unread: boolean }) {
  const [allCves, setAllCves] = useState(false);
  const kbs = facts?.kbNumbers.length ? facts.kbNumbers : it.kbNumber ? [it.kbNumber] : [];
  const pkg = facts?.package;
  const cves = facts?.cveIds ?? [];
  const what = [
    ...kbs.map((kb) => (kb.toUpperCase().startsWith("KB") ? kb : `KB${kb}`)),
    ...(pkg ? [`${pkg.name} ${pkg.version}${pkg.installedVersion ? `, from ${pkg.installedVersion}` : ""}`] : []),
    categoryLabel(it.category),
    ...(facts?.msrcSeverity ? [facts.msrcSeverity] : []),
    ...(facts?.sizeBytes != null ? [formatSize(facts.sizeBytes)] : []),
    ...(facts?.releaseDate ? [`released ${formatDate(facts.releaseDate)}`] : []),
  ];
  const result = it.resultCode !== null ? RESULT_CODES[it.resultCode] : undefined;
  const ran = it.startedAt && it.completedAt ? formatDuration((Date.parse(it.completedAt) - Date.parse(it.startedAt)) / 1000) : null;
  return (
    <li className="space-y-1 px-3 py-2 text-sm">
      <div className="flex items-start justify-between gap-3">
        <span className="min-w-0 break-words">{it.title}</span>
        <Badge tone={ITEM_TONES[it.status] ?? "neutral"}>
          {it.status}
          {it.installPercent !== null && it.status === "Installing" ? ` · ${it.installPercent}%` : ""}
          {it.downloadPercent !== null && it.status === "Downloading" ? ` · ${it.downloadPercent}%` : ""}
        </Badge>
      </div>
      <p className="text-xs text-muted">{what.join(" · ")}</p>
      {(cves.length > 0 || facts?.knownExploited) && (
        <p className="flex flex-wrap items-center gap-x-2 gap-y-0.5 text-xs">
          {facts?.knownExploited && (
            <Badge tone="danger">Known exploited{facts.kevDueDate ? `, fix by ${formatDate(facts.kevDueDate)}` : ""}</Badge>
          )}
          {(allCves ? cves : cves.slice(0, CVES_SHOWN)).map((c) => (
            <Mono key={c}>{c}</Mono>
          ))}
          {!allCves && cves.length > CVES_SHOWN && (
            <button type="button" className="rounded-sm text-accent hover:underline" onClick={() => setAllCves(true)}>
              {plural(cves.length - CVES_SHOWN, "more CVE")}
            </button>
          )}
        </p>
      )}
      {pkg && pkg.advisories.length > 0 && <p className="text-xs text-muted">Advisories: {pkg.advisories.join(", ")}</p>}
      {it.skipReason && <p className="text-xs text-muted">Skipped: {skipReasonText(it.skipReason)}</p>}
      {result && <p className="text-xs text-muted">{result}</p>}
      {(it.errorCode || it.errorMessage) && (
        <div className="rounded-md border border-danger/30 px-2 py-1.5 text-xs text-danger">
          {it.errorMessage && <span className="block">{it.errorMessage}</span>}
          {it.errorCode && <CodeMeaning code={it.errorCode} />}
        </div>
      )}
      <p className="text-xs text-subtle">
        {[
          ...(it.rebootRequired ? ["Needs a restart to finish"] : []),
          ...(it.startedAt ? [`Started ${formatDateTime(it.startedAt)}`] : []),
          ...(it.completedAt ? [`finished ${formatDateTime(it.completedAt)}${ran ? ` (${ran})` : ""}`] : []),
        ].join(", ")}
      </p>
      {facts ? (
        <p className="text-xs text-muted">
          On the device now: <UpdateStateBadge state={facts.state} />
        </p>
      ) : (
        !unread && <p className="text-xs text-subtle">The patching engine no longer lists this update for the device.</p>
      )}
      {facts?.supportUrl && (
        <a href={facts.supportUrl} target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-1 text-xs text-accent hover:underline">
          About this update
          <ExternalLink className="size-3" aria-hidden />
        </a>
      )}
    </li>
  );
}

// ---------------------------------------------------------------- timeline

interface Moment {
  at: string;
  text: string;
  tone?: "danger" | "warn";
}

const FINISHED: Record<string, string> = {
  Completed: "Finished",
  Failed: "Failed",
  Cancelled: "Cancelled",
  Expired: "Expired before it could start",
};

/** What happened to the job, in order: EasyRMM's and the engine's times, and the engine's events. */
/** The engine's events the job's own times already show: queued (its creation) and started. */
const REPEATED_EVENTS = new Set(["JobQueued", "JobStarted"]);

function timeline(d: PatchJobDetail): Moment[] {
  const s = d.summary;
  const m: Moment[] = [{ at: s.createdAt, text: s.trigger === "Manual" ? `Requested by ${requester(s.requestedBy)}` : `Requested ${triggerLabel(s.trigger).toLowerCase()}` }];
  if (d.notBefore) m.push({ at: d.notBefore, text: "Not to start before this" });
  if (d.deliveredAt) m.push({ at: d.deliveredAt, text: d.deliveryCount > 1 ? `Sent to the device (${d.deliveryCount.toLocaleString()} times)` : "Sent to the device" });
  if (d.acknowledgedAt) m.push({ at: d.acknowledgedAt, text: "The device accepted it" });
  if (s.startedAt) m.push({ at: s.startedAt, text: "Started" });
  if (d.cancelRequestedAt) m.push({ at: d.cancelRequestedAt, text: "Cancellation asked for" });
  if (d.lastProgressAt && isActiveJob(s)) m.push({ at: d.lastProgressAt, text: "Last progress reported" });
  if (s.completedAt) {
    const failed = s.status === "Failed" || s.status === "Expired";
    m.push({ at: s.completedAt, text: FINISHED[s.status] ?? s.status, tone: failed ? "danger" : undefined });
  }
  // The engine's queued and started events say again what the job's own times above say.
  for (const e of d.events.filter((x) => !REPEATED_EVENTS.has(x.type))) {
    m.push({ at: e.createdAt, text: e.message, tone: e.severity === "Error" ? "danger" : e.severity === "Warning" ? "warn" : undefined });
  }
  return m.sort((a, b) => Date.parse(a.at) - Date.parse(b.at));
}

function JobTimeline({ d }: { d: PatchJobDetail }) {
  const [all, setAll] = useState(false);
  const moments = timeline(d);
  const shown = all ? moments : moments.slice(0, EVENTS_SHOWN);
  return (
    <Section title="Timeline">
      <ol className="space-y-1 border-l border-line pl-3 text-sm">
        {shown.map((x, i) => (
          <li key={i} className="flex gap-3">
            <time dateTime={x.at} className="w-40 shrink-0 text-xs whitespace-nowrap text-muted tabular-nums" title={formatRelative(x.at)}>
              {formatDateTime(x.at)}
            </time>
            <span className={x.tone === "danger" ? "text-danger" : x.tone === "warn" ? "text-warn" : undefined}>{x.text}</span>
          </li>
        ))}
      </ol>
      {!all && moments.length > EVENTS_SHOWN && <ShowAll total={moments.length} what="entries" onClick={() => setAll(true)} />}
    </Section>
  );
}
