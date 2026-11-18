import { CircleDashed, FlaskConical, Loader2, Power, RotateCw, ShieldAlert } from 'lucide-react';
import type {
  ComplianceStatus,
  EndpointStatus,
  EndpointUpdateState,
  EnrollmentRequestStatus,
  EventSeverity,
  JobItemStatus,
  JobStatus,
  OsSupportStatus,
  UpdateCategory,
} from '../api/types';
import { humanize, isLinux, isMacOS, MACOS_EXPERIMENTAL } from '../lib/format';
import { Badge, Dot, type Tone } from './ui';

export const complianceTone: Record<ComplianceStatus, Tone> = {
  Compliant: 'ok',
  MissingUpdates: 'warn',
  FailedUpdates: 'danger',
  RebootRequired: 'info',
  ScanStale: 'neutral',
  NeverScanned: 'neutral',
};

export function ComplianceBadge({ status }: { status: ComplianceStatus }) {
  return <Badge tone={complianceTone[status]}>{humanize(status)}</Badge>;
}

export function OnlineBadge({ online, lastSeen }: { online: boolean; lastSeen?: string | null }) {
  return (
    <span className="inline-flex items-center gap-1.5 text-xs" title={lastSeen ? `Last check-in ${new Date(lastSeen).toLocaleString()}` : undefined}>
      <Dot tone={online ? 'ok' : 'neutral'} />
      <span className={online ? 'text-fg' : 'text-muted'}>{online ? 'Online' : 'Offline'}</span>
    </span>
  );
}

const jobTone: Record<JobStatus, Tone> = {
  Queued: 'neutral',
  Delivered: 'info',
  Acknowledged: 'info',
  Running: 'accent',
  Completed: 'ok',
  Failed: 'danger',
  Cancelled: 'neutral',
  Expired: 'warn',
  WaitingForReboot: 'info',
};

export function JobStatusBadge({ status, timedOut }: { status: JobStatus; timedOut?: boolean }) {
  const active = status === 'Running' || status === 'Delivered' || status === 'Acknowledged';
  return (
    <Badge tone={jobTone[status]} icon={active ? <Loader2 className="size-3 animate-spin" aria-hidden /> : status === 'WaitingForReboot' ? <Power className="size-3" aria-hidden /> : undefined}>
      {humanize(status)}
      {timedOut ? ' (timed out)' : ''}
    </Badge>
  );
}

const itemTone: Record<JobItemStatus, Tone> = {
  Pending: 'neutral',
  Downloading: 'accent',
  Downloaded: 'info',
  Installing: 'accent',
  Succeeded: 'ok',
  Failed: 'danger',
  Skipped: 'neutral',
  Cancelled: 'neutral',
};

/** @param removal The item belongs to an update removal job: "Removing" and "Removed" instead of "Installing" and "Succeeded". */
export function JobItemStatusBadge({ status, percent, removal = false }: { status: JobItemStatus; percent?: number | null; removal?: boolean }) {
  const busy = status === 'Downloading' || status === 'Installing';
  const label = removal && status === 'Installing' ? 'Removing' : removal && status === 'Succeeded' ? 'Removed' : humanize(status);
  return (
    <Badge tone={itemTone[status]} icon={busy ? <Loader2 className="size-3 animate-spin" aria-hidden /> : undefined}>
      {label}
      {busy && percent !== null && percent !== undefined ? ` ${percent}%` : ''}
    </Badge>
  );
}

const updateStateTone: Record<EndpointUpdateState, Tone> = {
  Missing: 'warn',
  Failed: 'danger',
  PendingVerification: 'info',
  PendingReboot: 'info',
  Installed: 'ok',
  Superseded: 'neutral',
  NotApplicable: 'neutral',
  Excluded: 'neutral',
  Reoffered: 'warn',
};

export function UpdateStateBadge({ state }: { state: EndpointUpdateState }) {
  return (
    <Badge
      tone={updateStateTone[state]}
      icon={state === 'PendingReboot' ? <RotateCw className="size-3" aria-hidden /> : state === 'PendingVerification' ? <CircleDashed className="size-3" aria-hidden /> : undefined}
      title={
        state === 'PendingVerification'
          ? 'The agent reported success; the next scan confirms it.'
          : state === 'PendingReboot'
            ? 'Installed; takes effect after the endpoint restarts.'
            : state === 'Reoffered'
              ? 'Windows reported a successful installation but still offers this update. It is not installed again automatically and does not count against compliance.'
              : undefined
      }
    >
      {humanize(state)}
    </Badge>
  );
}

const categoryTone: Partial<Record<UpdateCategory, Tone>> = {
  Security: 'danger',
  Critical: 'warn',
  Cumulative: 'accent',
  Feature: 'info',
  Driver: 'info',
};

export function CategoryBadge({ category }: { category: UpdateCategory }) {
  return <Badge tone={categoryTone[category] ?? 'neutral'}>{humanize(category)}</Badge>;
}

export function SeverityBadge({ severity }: { severity: string | null }) {
  if (!severity) return <span className="text-subtle">—</span>;
  const tone: Tone = severity === 'Critical' ? 'danger' : severity === 'Important' ? 'warn' : severity === 'Moderate' ? 'info' : 'neutral';
  return <Badge tone={tone}>{severity}</Badge>;
}

/** The update fixes a vulnerability in the CISA Known Exploited Vulnerabilities catalog. */
export function KnownExploitedBadge({ dueDate }: { dueDate?: string | null }) {
  return (
    <Badge
      tone="danger"
      icon={<ShieldAlert className="size-3" aria-hidden />}
      title={`Fixes a vulnerability attackers are known to exploit (CISA KEV catalog)${dueDate ? `. CISA remediation due date: ${dueDate}` : ''}`}
    >
      Known exploited
    </Badge>
  );
}

/** "3 CVEs", with the IDs in the tooltip. */
export function CveCount({ cves, count }: { cves?: string[] | null; count?: number }) {
  const n = count ?? cves?.length ?? 0;
  if (n === 0) return null;
  const shown = cves && cves.length > 0 ? cves.slice(0, 20).join(', ') + (cves.length > 20 ? ', …' : '') : undefined;
  return (
    <span className="font-mono" title={shown}>
      {n} CVE{n === 1 ? '' : 's'}
    </span>
  );
}

export function OsSupportBadge({ status }: { status: OsSupportStatus }) {
  if (status === 'Supported') return <Badge tone="ok">Supported</Badge>;
  if (status === 'ExtendedSecurityUpdates') return <Badge tone="info">ESU</Badge>;
  if (status === 'Unsupported') return <Badge tone="danger">Unsupported</Badge>;
  return <Badge tone="neutral">Unknown</Badge>;
}

/** "Windows", "Linux" or "macOS" (EndpointSummaryDto.platform); macOS is marked experimental. */
export function PlatformBadge({ platform }: { platform: string | null | undefined }) {
  if (isMacOS(platform)) {
    return (
      <Badge tone="warn" title={`macOS endpoint (Apple software update). ${MACOS_EXPERIMENTAL}`} icon={<FlaskConical className="size-3" aria-hidden />}>
        macOS <span className="font-normal">(experimental)</span>
      </Badge>
    );
  }
  const linux = isLinux(platform);
  return (
    <Badge tone={linux ? 'info' : 'neutral'} title={linux ? 'Linux endpoint (apt or dnf)' : 'Windows endpoint'}>
      {linux ? 'Linux' : 'Windows'}
    </Badge>
  );
}

export function EndpointStatusBadge({ status }: { status: EndpointStatus }) {
  if (status === 'Active') return null;
  return <Badge tone={status === 'Revoked' ? 'danger' : 'neutral'}>{status}</Badge>;
}

export function EventSeverityDot({ severity }: { severity: EventSeverity }) {
  return <Dot tone={severity === 'Error' ? 'danger' : severity === 'Warning' ? 'warn' : 'info'} />;
}

export function RequestStatusBadge({ status }: { status: EnrollmentRequestStatus }) {
  const tone: Tone = status === 'Approved' ? 'ok' : status === 'Rejected' ? 'danger' : status === 'Expired' ? 'neutral' : 'warn';
  return <Badge tone={tone}>{status === 'Pending' ? 'Pending approval' : status}</Badge>;
}

export function StateBadge({ state }: { state: string }) {
  const tone: Tone = state === 'Active' ? 'ok' : state === 'Revoked' ? 'danger' : state === 'Expired' || state === 'Exhausted' ? 'neutral' : 'info';
  return <Badge tone={tone}>{state}</Badge>;
}
