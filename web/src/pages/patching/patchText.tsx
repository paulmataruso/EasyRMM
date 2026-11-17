import type { ReactNode } from "react";
import type { AgentInstall, ComplianceStatus, PatchJob, PatchLink, PatchPolicy, PatchUpdateState } from "../../api/types";
import { ArrowUpRight, ExternalLink } from "lucide-react";
import { Badge, buttonClasses, cx, Dot, type Tone } from "../../components/ui";
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

const UPDATE_STATES: Record<PatchUpdateState, { label: string; tone: Tone }> = {
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

/** When EasyPatch installs on its own: "Off", "Any time", or "Saturday 02:00 for 3 hours (Europe/Paris)". */
export function maintenanceText(p: PatchPolicy): string {
  if (!p.autoInstallEnabled) return "Off: updates install only when someone starts an install";
  if (!p.maintenanceStart) return "On, at any time (no maintenance window)";
  const days =
    p.maintenanceDays && p.maintenanceDays.length > 0 && p.maintenanceDays.length < 7
      ? p.maintenanceDays.map((d) => DAYS[d] ?? String(d)).join(", ")
      : "Every day";
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

/** What a link into EasyPatch's console is about: an EasyRMM device or organization, or an EasyPatch job or update. */
export interface EasyPatchTarget {
  device?: string;
  /** A device's page in EasyPatch: updates, installed, history, jobs or policy. */
  tab?: "updates" | "installed" | "history" | "jobs" | "policy";
  organization?: string;
  job?: string;
  update?: string;
}

/**
 * The address of a link into EasyPatch's console. It goes through EasyRMM's own server, which finds the EasyPatch
 * page for the device or organization (or EasyPatch's list, when it is not linked) and redirects there.
 */
export function easyPatchHref(t: EasyPatchTarget): string {
  const q = new URLSearchParams();
  if (t.device) {
    q.set("device", t.device);
    if (t.tab) q.set("tab", t.tab);
  } else if (t.organization) q.set("organization", t.organization);
  else if (t.job) q.set("job", t.job);
  else if (t.update) q.set("update", t.update);
  const query = q.toString();
  return query ? `/go/to-easypatch?${query}` : "/go/to-easypatch";
}

/**
 * A link to where EasyPatch's console changes something EasyRMM only shows, named for the action ("Change in
 * EasyPatch"). It opens in the same tab, so Back returns.
 */
export function EasyPatchLink({ to, children, className }: { to: EasyPatchTarget; children: ReactNode; className?: string }) {
  return (
    <a href={easyPatchHref(to)} className={cx("inline-flex items-center gap-0.5 rounded-sm font-medium text-accent hover:underline", className)}>
      {children}
      <ArrowUpRight className="size-3.5 shrink-0" aria-hidden />
    </a>
  );
}

/** EasyPatch's own console, in a new tab: for what EasyRMM does not show, such as its policies and settings. */
export function OpenEasyPatch({ href }: { href: string }) {
  return (
    <a href={href} target="_blank" rel="noopener noreferrer" className={buttonClasses("secondary", "sm")}>
      <ExternalLink className="size-3.5" aria-hidden />
      Open EasyPatch
      <span className="sr-only"> (opens in a new tab)</span>
    </a>
  );
}
