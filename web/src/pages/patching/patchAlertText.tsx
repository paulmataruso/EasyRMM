import { Info, OctagonAlert, TriangleAlert } from "lucide-react";
import type { PatchAlert, PatchAlertRuleKind, PatchAlertSeverity, PatchNotificationStatus } from "../../api/types";
import { Badge } from "../../components/ui";
import { formatRelative } from "../../lib/format";

// EasyPatch's alerts in EasyRMM's words: what each type of rule looks for, its threshold, and the
// badges for severity, state and a message's delivery.

export const RULE_KINDS: Record<PatchAlertRuleKind, { label: string; about: string }> = {
  EndpointOffline: { label: "Device offline", about: "The device's EasyPatch agent has not checked in for a while." },
  InstallFailed: { label: "Update failed to install", about: "An update the device needs failed to install." },
  SecurityUpdateMissing: {
    label: "Security update missing",
    about: "A security update the device needs is still missing some days after its policy made it required.",
  },
  ScanStale: { label: "Scan out of date", about: "The device has not scanned for updates as often as its policy asks." },
  RestartPending: { label: "Restart pending", about: "The device has waited some days for a restart to finish installing." },
  EnrollmentPending: {
    label: "Enrollment waiting for approval",
    about: "An organization has EasyPatch agents waiting for approval in EasyPatch. One alert for the organization.",
  },
  OsUnsupported: {
    label: "Operating system unsupported",
    about: "The device's operating system no longer gets security updates, or stops soon, by Settings → Patching → OS lifecycle.",
  },
  KnownExploitedMissing: {
    label: "Exploited vulnerability unpatched",
    about: "The device misses an update that fixes a vulnerability in CISA's Known Exploited Vulnerabilities catalog.",
  },
  UpdateHeld: {
    label: "Update on hold",
    about: "An update the organization's devices need is on hold, so EasyPatch does not install it. One alert for the organization.",
  },
};

export const RULE_KIND_ORDER = Object.keys(RULE_KINDS) as PatchAlertRuleKind[];

export const SEVERITIES: PatchAlertSeverity[] = ["Critical", "Warning", "Info"];

/** "Offline for 24 hours or more", from a rule's type and threshold; null when the type has none. */
export function thresholdText(type: PatchAlertRuleKind, threshold: number | null): string | null {
  if (threshold === null) return null;
  const n = (unit: string) => `${threshold.toLocaleString()} ${unit}${threshold === 1 ? "" : "s"}`;
  switch (type) {
    case "EndpointOffline":
      return `Offline for ${n("hour")} or more`;
    case "SecurityUpdateMissing":
      return threshold === 0 ? "As soon as it is required" : `Missing ${n("day")} after it became required`;
    case "RestartPending":
      return `Waiting ${n("day")} or more`;
    case "OsUnsupported":
      return threshold === 0 ? "Once support has ended" : `Support ends within ${n("day")}, or has ended`;
    default:
      return null;
  }
}

export function PatchSeverityBadge({ severity }: { severity: PatchAlertSeverity }) {
  if (severity === "Critical") {
    return (
      <Badge tone="danger" icon={<OctagonAlert className="size-3" aria-hidden />}>
        Critical
      </Badge>
    );
  }
  if (severity === "Warning") {
    return (
      <Badge tone="warn" icon={<TriangleAlert className="size-3" aria-hidden />}>
        Warning
      </Badge>
    );
  }
  return (
    <Badge tone="info" icon={<Info className="size-3" aria-hidden />}>
      Info
    </Badge>
  );
}

export function PatchAlertState({ alert }: { alert: Pick<PatchAlert, "status" | "acknowledgedBy" | "acknowledgedAt" | "resolvedAt"> }) {
  if (alert.status === "Resolved") {
    return (
      <span className="flex flex-col items-start gap-0.5">
        <Badge tone="ok">Resolved</Badge>
        {alert.resolvedAt && <span className="text-xs text-muted">{formatRelative(alert.resolvedAt)}</span>}
      </span>
    );
  }
  if (alert.status === "Acknowledged") {
    return (
      <span className="flex flex-col items-start gap-0.5">
        <Badge tone="neutral">Acknowledged</Badge>
        {alert.acknowledgedBy && (
          <span className="max-w-48 truncate text-xs text-muted" title={alert.acknowledgedBy}>
            by {acknowledgedBy(alert.acknowledgedBy)}
            {alert.acknowledgedAt ? `, ${formatRelative(alert.acknowledgedAt)}` : ""}
          </span>
        )}
      </span>
    );
  }
  return <Badge tone="accent">Open</Badge>;
}

/** EasyPatch names those who act through EasyRMM "easyrmm:<email>". */
export function acknowledgedBy(name: string): string {
  return name.startsWith("easyrmm:") ? name.slice("easyrmm:".length) : name;
}

const DELIVERY: Record<PatchNotificationStatus, { tone: "ok" | "danger" | "neutral"; label: string }> = {
  Sent: { tone: "ok", label: "Sent" },
  Failed: { tone: "danger", label: "Failed" },
  Pending: { tone: "neutral", label: "Sending" },
};

export function DeliveryBadge({ status }: { status: PatchNotificationStatus }) {
  const d = DELIVERY[status];
  return <Badge tone={d.tone}>{d.label}</Badge>;
}
