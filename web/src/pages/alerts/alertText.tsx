// Words and badges for alert policies and alerts (ADR-0019).
import { OctagonAlert, TriangleAlert } from "lucide-react";
import type { AlertEntry, AlertKind, AlertPolicy, AlertResolution, AlertSeverity } from "../../api/types";
import { Badge } from "../../components/ui";
import { formatDuration, plural } from "../../lib/format";

export const KIND_NAMES: Record<AlertKind, string> = {
  offline: "Device offline",
  cpu: "Processor use",
  memory: "Memory use",
  disk: "Disk use",
};

export const KINDS: AlertKind[] = ["offline", "cpu", "memory", "disk"];

/** Limits the server enforces (monitoring/policies.go). */
export const POLICY_LIMITS = { name: 200, description: 2000, maxMinutes: 1440, minOfflineMinutes: 3 };

/** "15 minutes", "1 hour", "90 minutes". */
export function formatMinutes(m: number): string {
  if (m >= 60 && m % 60 === 0) return plural(m / 60, "hour");
  return plural(m, "minute");
}

type Condition = Pick<AlertPolicy, "kind" | "threshold" | "minutes">;

/** "Processor at 95% or more for 15 minutes", "No check-in for 15 minutes". */
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
  }
}

/** The latest reading behind an alert: "97%", or "Offline 2 h 5 min". */
export function valueText(a: Pick<AlertEntry, "kind" | "lastValue">): string {
  return a.kind === "offline" ? `Offline ${formatDuration(a.lastValue * 60)}` : `${Math.round(a.lastValue)}%`;
}

export const RESOLUTIONS: Record<AlertResolution, string> = {
  cleared: "Condition cleared",
  manual: "Resolved",
  not_covered: "Device left the policy's scope",
  policy_off: "Policy turned off",
  policy_changed: "Policy changed",
  policy_deleted: "Policy deleted",
};

/** Why and by whom an alert was resolved. */
export function resolutionText(a: Pick<AlertEntry, "resolution" | "resolvedBy">): string {
  if (!a.resolution) return "Resolved";
  if (a.resolution === "manual") return a.resolvedBy ? `Resolved by ${a.resolvedBy}` : "Resolved by hand";
  return RESOLUTIONS[a.resolution];
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
