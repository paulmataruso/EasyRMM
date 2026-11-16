import type { ComplianceStatus, PatchJob, PatchLink, PatchPolicy, PatchUpdateState } from "../../api/types";
import { Badge, Dot, type Tone } from "../../components/ui";
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

/** Who asked for a job: a user, or the API token EasyRMM uses where EasyPatch cannot record users. */
export function requester(by: string): string {
  return by.startsWith("token:") ? `EasyRMM (token ${by.slice(6)})` : by;
}
