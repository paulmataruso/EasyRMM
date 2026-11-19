import { useId, type ReactNode } from "react";
import type { AgentInstall, ComplianceStatus, PatchJob, PatchLink, PatchPolicy, PatchStatus, PatchUpdateState } from "../../api/types";
import { ArrowUpRight } from "lucide-react";
import { useApi } from "../../api/hooks";
import { Badge, Button, buttonClasses, cx, Dot, Field, Select, type Tone } from "../../components/ui";
import { plural } from "../../lib/format";

export const COMPLIANCE: Record<ComplianceStatus, { label: string; tone: Tone; hint: string }> = {
  Compliant: {
    label: "Up to date",
    tone: "ok",
    hint: "Every required update is installed.",
  },
  MissingUpdates: {
    label: "Updates missing",
    tone: "warn",
    hint: "Required updates are not installed yet.",
  },
  FailedUpdates: {
    label: "Updates failed",
    tone: "danger",
    hint: "An update failed to install.",
  },
  RebootRequired: {
    label: "Restart needed",
    tone: "info",
    hint: "Installed updates finish when the device restarts.",
  },
  ScanStale: {
    label: "Scan out of date",
    tone: "neutral",
    hint: "The last scan is older than the policy allows; what is missing may have changed.",
  },
  NeverScanned: {
    label: "Never scanned",
    tone: "neutral",
    hint: "EasyPatch has not scanned this device yet.",
  },
};

/** The compliance filter's choices, worst first. */
export const COMPLIANCE_ORDER: ComplianceStatus[] = ["FailedUpdates", "MissingUpdates", "RebootRequired", "ScanStale", "NeverScanned", "Compliant"];

export function ComplianceBadge({ status }: { status: ComplianceStatus }) {
  const c = COMPLIANCE[status] ?? {
    label: status,
    tone: "neutral" as Tone,
    hint: "",
  };
  return (
    <Badge tone={c.tone} icon={<Dot tone={c.tone} />} title={c.hint}>
      {c.label}
    </Badge>
  );
}

export const LINK_LABELS: Record<PatchLink, string> = {
  linked: "Linked",
  unlinked: "Not linked",
  pending: "Checking",
  none: "No EasyPatch agent",
};

export function LinkBadge({ link, reason }: { link: PatchLink; reason?: string }) {
  const tone: Tone = link === "linked" ? "ok" : link === "unlinked" ? "warn" : "neutral";
  return (
    <Badge tone={tone} title={reason}>
      {LINK_LABELS[link]}
    </Badge>
  );
}

/** Where the EasyPatch agent's install is (ADR-0031), in a few words, with the detail that goes under them. */
export function installText(i: AgentInstall): { tone: Tone; label: string; detail?: string } {
  switch (i.state) {
    case "waiting":
      return { tone: "neutral", label: "EasyPatch agent install waiting", detail: i.note || "Starts at the device's next check-in, within a minute." };
    case "sent":
      return { tone: "info", label: "Installing the EasyPatch agent", detail: "The EasyRMM agent downloads, installs and enrolls it." };
    case "succeeded":
      return { tone: "ok", label: "EasyPatch agent installed", detail: "EasyRMM links the device once its agent reports it, within a few minutes." };
    case "failed":
      return { tone: "danger", label: "EasyPatch agent install failed", detail: i.error };
  }
}

/** The install's state under a device's link badge; nothing once the device is linked. */
export function InstallLine({ install, link }: { install?: AgentInstall; link: PatchLink }) {
  if (!install || link === "linked") return null;
  const t = installText(install);
  return (
    <p className="mt-1 max-w-sm text-xs">
      <span className={t.tone === "danger" ? "font-medium text-danger" : t.tone === "info" ? "font-medium text-info" : "font-medium text-muted"}>
        {t.label}
      </span>
      {t.detail && <span className="block text-muted">{t.detail}</span>}
    </p>
  );
}

const JOB_TYPES: Record<string, string> = {
  UpdateScan: "Scan for updates",
  InstallUpdates: "Install updates",
  DownloadUpdates: "Download updates",
  UninstallUpdate: "Uninstall an update",
  InventoryRefresh: "Refresh inventory",
  Restart: "Restart",
  NotifyUser: "Notify the user",
  AgentUpdate: "Update the EasyPatch agent",
  UninstallAgent: "Uninstall the EasyPatch agent",
};

/** EasyPatch's job types, for filters. */
export const JOB_TYPE_OPTIONS = Object.entries(JOB_TYPES).map(([value, label]) => ({ value, label }));

/** How a job started (EasyPatch's trigger). */
export const JOB_TRIGGERS: Record<string, string> = {
  Manual: "By hand",
  Scheduled: "On a schedule",
  System: "By EasyPatch",
};

export function triggerLabel(trigger: string): string {
  return JOB_TRIGGERS[trigger] ?? trigger;
}

export function jobTypeLabel(type: string): string {
  return JOB_TYPES[type] ?? type;
}

/** What the EasyPatch agent is busy with. It reports most jobs by their type's name, and other work in words. */
const ACTIVITIES: Record<string, string> = {
  UpdateScan: "Scanning for updates",
  InstallUpdates: "Installing updates",
  InventoryRefresh: "Refreshing inventory",
  Restart: "Restarting",
  NotifyUser: "Notifying the user",
};

export function activityText(activity: string | null | undefined): string | null {
  if (!activity || activity === "Idle") return null;
  return ACTIVITIES[activity] ?? activity;
}

const JOB_STATUS: Record<string, { label: string; tone: Tone }> = {
  Queued: { label: "Queued", tone: "neutral" },
  Delivered: { label: "Sent to the device", tone: "info" },
  Acknowledged: { label: "Accepted", tone: "info" },
  Running: { label: "Running", tone: "info" },
  WaitingForReboot: { label: "Waiting for a restart", tone: "info" },
  Completed: { label: "Completed", tone: "ok" },
  Failed: { label: "Failed", tone: "danger" },
  Cancelled: { label: "Cancelled", tone: "neutral" },
  Expired: { label: "Expired", tone: "warn" },
};

/** EasyPatch's job statuses, for filters. */
export const JOB_STATUS_OPTIONS = Object.entries(JOB_STATUS).map(([value, s]) => ({ value, label: s.label }));

/** EasyPatch job statuses that still change. */
const ACTIVE = new Set(["Queued", "Delivered", "Acknowledged", "Running", "WaitingForReboot"]);

export function isActiveJob(j: Pick<PatchJob, "status">): boolean {
  return ACTIVE.has(j.status);
}

/**
 * Whether a job is worth running again: it finished without doing all it should (failed, cancelled, expired, or
 * some of its updates failed). EasyPatch does not retry downloads.
 */
export function canRetry(j: Pick<PatchJob, "status" | "type" | "failedCount">): boolean {
  if (isActiveJob(j) || j.type === "DownloadUpdates") return false;
  return j.status === "Failed" || j.status === "Cancelled" || j.status === "Expired" || j.failedCount > 0;
}

export function PatchJobBadge({ job }: { job: Pick<PatchJob, "status" | "cancelRequested" | "progressPercent"> }) {
  const s = JOB_STATUS[job.status] ?? {
    label: job.status,
    tone: "neutral" as Tone,
  };
  let label = s.label;
  if (job.cancelRequested && isActiveJob(job)) label = "Cancelling";
  else if (job.status === "Running" && job.progressPercent !== null) label = `Running · ${job.progressPercent}%`;
  return (
    <Badge tone={s.tone} icon={<Dot tone={s.tone} />}>
      {label}
    </Badge>
  );
}

/** What a job did, in a few words: "3 of 4 installed, 1 failed". */
export function jobOutcome(j: PatchJob): string {
  if (j.itemCount === 0) return "";
  const parts = [`${j.succeededCount} of ${plural(j.itemCount, "update")} installed`];
  if (j.failedCount > 0) parts.push(`${j.failedCount} failed`);
  return parts.join(", ");
}

export const UPDATE_STATES: Record<PatchUpdateState, { label: string; tone: Tone }> = {
  Missing: { label: "Missing", tone: "warn" },
  Failed: { label: "Failed", tone: "danger" },
  PendingVerification: { label: "Verifying", tone: "info" },
  PendingReboot: { label: "Needs a restart", tone: "info" },
  Installed: { label: "Installed", tone: "ok" },
  Superseded: { label: "Superseded", tone: "neutral" },
  NotApplicable: { label: "Not applicable", tone: "neutral" },
  Excluded: { label: "Excluded", tone: "neutral" },
  Reoffered: { label: "Offered again", tone: "warn" },
};

export function UpdateStateBadge({ state }: { state: PatchUpdateState }) {
  const s = UPDATE_STATES[state] ?? { label: state, tone: "neutral" as Tone };
  return <Badge tone={s.tone}>{s.label}</Badge>;
}

/** States of updates that can be installed. */
export const INSTALLABLE: PatchUpdateState[] = ["Missing", "Failed", "Reoffered"];

const CATEGORIES: Record<string, string> = {
  ServicingStack: "Servicing stack",
  DotNet: ".NET",
};

export function categoryLabel(c: string): string {
  return CATEGORIES[c] ?? c;
}

const DAYS = ["Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"];

/**
 * When EasyPatch installs on its own: "Off", or "Saturday 02:00 for 3 hours (Europe/Paris)". EasyPatch installs automatically
 * only inside a maintenance window, so automatic installs with no window install nothing.
 */
export function maintenanceText(p: PatchPolicy): string {
  if (!p.autoInstallEnabled) return "Off: updates install only when someone starts an install";
  if (!p.maintenanceStart || !p.maintenanceDays || p.maintenanceDays.length === 0) {
    return "On, but there is no maintenance window, so nothing installs automatically";
  }
  const days = p.maintenanceDays.length < 7 ? p.maintenanceDays.map((d) => DAYS[d] ?? String(d)).join(", ") : "Every day";
  const minutes = p.maintenanceDurationMinutes ?? 0;
  const length = minutes === 0 ? "" : minutes % 60 === 0 ? ` for ${plural(minutes / 60, "hour")}` : ` for ${plural(minutes, "minute")}`;
  return `${days} at ${p.maintenanceStart}${length} (${p.timeZone})`;
}

/**
 * Who asked for a job: an EasyPatch user, or an API token such as EasyRMM's — "token:<name>", or "token:<name> for <person>" when the
 * EasyPatch server records who the token acted for (its on-behalf-of capability). EasyRMM sends its users' email addresses, so the
 * person is what follows the last " for " when it looks like one; a token named "Patch for prod" stays a token.
 */
export function requester(by: string): string {
  if (!by.startsWith("token:")) return by;
  const token = by.slice(6);
  const cut = token.lastIndexOf(" for ");
  const person = cut > 0 ? token.slice(cut + 5) : "";
  if (/^[^\s@]+@[^\s@]+$/.test(person)) return `${person}, through API token ${token.slice(0, cut)}`;
  return `API token ${token}`;
}

/** Why an install would leave an update out, from EasyPatch's reason code. */
const SKIP_REASONS: Record<string, string> = {
  AlreadyInstalled: "Already installed",
  PendingReboot: "Installed, waiting for a restart",
  NotApplicable: "No longer offered by the update source",
  NotSelected: "Not selected",
  CategoryNotAllowed: "Its category is not allowed by the policy",
  OptionalNotAllowed: "Optional, and the policy leaves optional updates out",
  Excluded: "Excluded on this device or by the policy",
  RequiresUserInput: "Needs someone at the computer to install",
  EulaNotAccepted: "Has a license agreement the policy does not accept",
  MaintenanceWindowClosed: "The maintenance window is closed",
  Cancelled: "Cancelled",
  ApplicationNotApproved: "The application is not approved by the policy",
  Reoffered: "Offered again after a successful install: installed only when chosen",
  NotInstalled: "Not installed",
  Held: "On hold: not installed automatically",
  WindowStarted: "Not downloaded before the window opened; the install downloads it",
};

export function skipReasonText(reason: string): string {
  return SKIP_REASONS[reason] ?? reason;
}

/** Pages of an EasyPatch list, numbered from 1; nothing when it fits on one. */
export function Pager({ page, total, size, onPage, previous = "Previous", next = "Next" }: {
  page: number;
  total: number;
  size: number;
  onPage: (p: number) => void;
  previous?: string;
  next?: string;
}) {
  const pages = Math.max(1, Math.ceil(total / size));
  if (pages <= 1) return null;
  return (
    <div className="mt-2 flex items-center justify-between text-xs text-muted">
      <span>
        Page {page.toLocaleString()} of {pages.toLocaleString()}
      </span>
      <span className="flex gap-2">
        <Button size="sm" variant="ghost" disabled={page <= 1} onClick={() => onPage(page - 1)}>
          {previous}
        </Button>
        <Button size="sm" variant="ghost" disabled={page >= pages} onClick={() => onPage(page + 1)}>
          {next}
        </Button>
      </span>
    </div>
  );
}

/** A labelled select for a list's filters; the first option is usually "any". */
export function FilterSelect({
  label,
  value,
  onChange,
  options,
  className,
}: {
  label: string;
  value: string;
  onChange: (v: string) => void;
  options: { value: string; label: string }[];
  className?: string;
}) {
  const id = useId();
  return (
    <Field label={label} htmlFor={id} className={className}>
      <Select id={id} value={value} onChange={(e) => onChange(e.target.value)}>
        {options.map((o) => (
          <option key={o.value} value={o.value}>
            {o.label}
          </option>
        ))}
      </Select>
    </Field>
  );
}
