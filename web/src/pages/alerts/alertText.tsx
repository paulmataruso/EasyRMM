// Words and badges for alert policies and alerts (ADR-0019; disk health, ADR-0065).
import { OctagonAlert, Pause, Play, TriangleAlert } from "lucide-react";
import type { AlertEntry, AlertKind, AlertPolicy, AlertResolution, AlertSeverity, DiskCheck } from "../../api/types";
import { Badge, Button } from "../../components/ui";
import { useAlertFlash } from "../../lib/alertFlash";
import { formatDuration, plural } from "../../lib/format";

export const KIND_NAMES: Record<AlertKind, string> = {
  offline: "Device offline",
  cpu: "Processor use",
  memory: "Memory use",
  disk: "Disk use",
  disk_health: "Disk health",
  remote_down: "Remote access down",
  agent_silent: "EasyRMM agent silent",
  repair_failed: "Repair failed",
};

export const KINDS: AlertKind[] = ["offline", "cpu", "memory", "disk", "disk_health", "remote_down", "agent_silent"];

/** A disk health policy's checks, in words. */
export const CHECK_NAMES: Record<DiskCheck, string> = {
  failing: "Disk failing",
  errors: "Reallocated sectors and media errors",
  pending: "Pending and uncorrectable sectors",
  wear: "Wear",
  temperature: "Temperature",
};

export const CHECKS: DiskCheck[] = ["failing", "errors", "pending", "wear", "temperature"];

/** Limits the server enforces (monitoring/policies.go). Disks are read every 30 minutes (diskMinutes, which the checks
 * other than temperature take), so a temperature check watches at least two readings' worth. */
export const POLICY_LIMITS = { name: 200, description: 2000, maxMinutes: 1440, minOfflineMinutes: 3, diskMinutes: 30, minTemperatureMinutes: 60 };

/** "15 minutes", "1 hour", "90 minutes". */
export function formatMinutes(m: number): string {
  if (m >= 60 && m % 60 === 0) return plural(m / 60, "hour");
  return plural(m, "minute");
}

type Condition = Pick<AlertPolicy, "kind" | "threshold" | "minutes"> & { checkName?: DiskCheck | null };

/** "Processor at 95% or more for 15 minutes", "No check-in for 15 minutes", "A disk's own verdict is failing". */
export function conditionText(c: Condition): string {
  const span = formatMinutes(c.minutes);
  const at = `${c.threshold ?? 0}% or more`;
  switch (c.kind) {
    case "offline":
      return `No check-in for ${span}`;
    case "cpu":
      return `Processor at ${at} for ${span}`;
    case "memory":
      return `Memory at ${at} for ${span}`;
    case "disk":
      return `A disk ${c.threshold ?? 0}% full or more for ${span}`;
    case "disk_health":
      return diskCondition(c, span);
    case "remote_down":
      return `MeshAgent not connected to MeshCentral for ${span}, while the EasyRMM agent checks in`;
    case "agent_silent":
      return `No EasyRMM check-in for ${span}, while MeshAgent is connected`;
    case "repair_failed":
      return "An automatic repair ended with the agent still broken";
    default:
      // A kind a newer server knows.
      return String(c.kind);
  }
}

function diskCondition(c: Condition, span: string): string {
  const n = c.threshold ?? 0;
  switch (c.checkName) {
    case "failing":
      return "A disk's own verdict is failing";
    case "errors":
      return `A disk with ${n.toLocaleString()} or more reallocated sectors and media errors`;
    case "pending":
      return `A disk with ${n.toLocaleString()} or more pending and uncorrectable sectors`;
    case "wear":
      return `A disk with ${n}% or more of its rated endurance used`;
    case "temperature":
      return c.threshold === null ? `A disk at or over its own temperature limit for ${span}` : `A disk at ${n} °C or more for ${span}`;
    default:
      return c.checkName ? `Disk health: ${c.checkName}` : "Disk health";
  }
}

/** The latest reading behind an alert: "97%", "Offline 2 h 5 min", or for disk health the count, wear or temperature. */
export function valueText(a: Pick<AlertEntry, "kind" | "lastValue"> & { checkName?: DiskCheck | null }): string {
  const v = Math.round(a.lastValue);
  if (a.kind === "offline") return `Offline ${formatDuration(a.lastValue * 60)}`;
  if (a.kind === "remote_down") return `Not connected ${formatDuration(a.lastValue * 60)}`;
  if (a.kind === "agent_silent") return `Silent ${formatDuration(a.lastValue * 60)}`;
  if (a.kind === "repair_failed") return "Repair failed";
  if (a.kind !== "disk_health") return `${v}%`;
  switch (a.checkName) {
    case "failing":
      return v >= 1 ? "Failing" : "Not failing";
    case "errors":
      return plural(v, "error");
    case "pending":
      return plural(v, "sector");
    case "wear":
      return `${v}% used`;
    case "temperature":
      return `${v} °C`;
    default:
      return v.toLocaleString();
  }
}

/** Checks whose counts only rise: their alerts clear only when the threshold is raised or the disk is replaced, and
 * resolving one by hand while the count holds opens it again (ADR-0065, "Alerts"). */
const RISING: DiskCheck[] = ["errors", "wear"];

/** Advice on an active disk alert whose count only rises: acknowledge it rather than resolve it. */
export function risingHint(a: Pick<AlertEntry, "kind" | "checkName" | "status">): string | null {
  if (a.kind !== "disk_health" || a.status === "resolved" || !a.checkName || !RISING.includes(a.checkName)) return null;
  return a.checkName === "wear"
    ? "Wear only rises: acknowledge this alert rather than resolve it, or it opens again within a minute. It resolves when the disk is replaced or the policy's threshold is raised."
    : "This count only rises: acknowledge this alert rather than resolve it, or it opens again within a minute. It resolves when the disk is replaced or the policy's threshold is raised.";
}

export const RESOLUTIONS: Record<AlertResolution, string> = {
  cleared: "Condition cleared",
  manual: "Resolved",
  not_covered: "Device left the policy's scope",
  policy_off: "Policy turned off",
  policy_changed: "Policy changed",
  policy_deleted: "Policy deleted",
  subject_gone: "The disk is gone: missing from the device's disk readings for 14 days",
};

/** Why and by whom an alert was resolved. */
export function resolutionText(a: Pick<AlertEntry, "resolution" | "resolvedBy">): string {
  if (!a.resolution) return "Resolved";
  if (a.resolution === "manual") return a.resolvedBy ? `Resolved by ${a.resolvedBy}` : "Resolved by hand";
  return RESOLUTIONS[a.resolution] ?? a.resolution;
}

/** Which devices a policy covers. */
export function policyScope(p: Pick<AlertPolicy, "level" | "organizationName" | "siteName">): string {
  if (p.level === "shared") return "Every device";
  if (p.level === "organization") return p.organizationName ?? "Organization";
  return `${p.organizationName ?? "Organization"} / ${p.siteName ?? "Site"}`;
}

export function SeverityBadge({ severity }: { severity: AlertSeverity }) {
  return severity === "critical" ? (
    <Badge tone="danger" icon={<OctagonAlert className="size-3" aria-hidden />}>
      Critical
    </Badge>
  ) : (
    <Badge tone="warn" icon={<TriangleAlert className="size-3" aria-hidden />}>
      Warning
    </Badge>
  );
}

/** How many alerts are active, beside a list's title and pulsing with them; "100+" past the first page. */
export function ActiveCount({ count, more = false }: { count: number; more?: boolean }) {
  const label = more ? `More than ${plural(count, "active alert")}` : plural(count, "active alert");
  return (
    <span
      title={label}
      className="alert-active-pulse alert-active-pulse--filled min-w-5 rounded-full px-1.5 text-center text-xs leading-5 font-semibold tabular-nums"
    >
      {count.toLocaleString()}
      {more && "+"}{" "}
      <span className="sr-only">active</span>
    </span>
  );
}

/** Stops the pulse of active alerts in this browser, or starts it again (lib/alertFlash.ts). */
export function AlertFlashToggle() {
  const [on, set] = useAlertFlash();
  return (
    <Button
      size="sm"
      variant="ghost"
      icon={on ? <Pause className="size-3.5" aria-hidden /> : <Play className="size-3.5" aria-hidden />}
      title={on ? "Hold active alerts in steady red, in this browser" : "Pulse active alerts in red again, in this browser"}
      onClick={() => set(!on)}
    >
      {on ? "Stop flashing" : "Flash active alerts"}
    </Button>
  );
}

/** A disk alert's disk and what holds on it: "PhysicalDrive1 · Samsung SSD 870 EVO 1TB", "Pending sectors 8". */
export function DiskSubject({ alert: a, className }: { alert: Pick<AlertEntry, "kind" | "subjectLabel" | "detail">; className?: string }) {
  if (a.kind !== "disk_health" || (!a.subjectLabel && !a.detail)) return null;
  return (
    <p className={className}>
      {a.subjectLabel && <span className="block text-xs font-medium text-fg">{a.subjectLabel}</span>}
      {a.detail && <span className="block text-xs text-muted">{a.detail}</span>}
    </p>
  );
}
