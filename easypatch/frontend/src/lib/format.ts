// Formatting helpers. Dates render in the browser locale and time zone.

export function formatBytes(bytes: number | null | undefined, digits = 1): string {
  if (bytes === null || bytes === undefined || !Number.isFinite(bytes)) return '—';
  if (bytes < 0) return '—';
  if (bytes < 1024) return `${bytes} B`;
  const units = ['KB', 'MB', 'GB', 'TB', 'PB'];
  let value = bytes / 1024;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit++;
  }
  return `${value.toFixed(value >= 100 ? 0 : digits)} ${units[unit]}`;
}

export function parseDate(value: string | null | undefined): Date | null {
  if (!value) return null;
  const d = new Date(value);
  return Number.isNaN(d.getTime()) ? null : d;
}

export function formatDateTime(value: string | null | undefined): string {
  const d = parseDate(value);
  if (!d) return '—';
  return d.toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' });
}

export function formatDate(value: string | null | undefined): string {
  if (!value) return '—';
  // Date-only values (yyyy-MM-dd) must not shift across time zones.
  const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(value);
  const d = m ? new Date(Number(m[1]), Number(m[2]) - 1, Number(m[3])) : parseDate(value);
  if (!d || Number.isNaN(d.getTime())) return '—';
  return d.toLocaleDateString(undefined, { dateStyle: 'medium' });
}

const RELATIVE_UNITS: [Intl.RelativeTimeFormatUnit, number][] = [
  ['year', 365 * 24 * 3600],
  ['month', 30 * 24 * 3600],
  ['week', 7 * 24 * 3600],
  ['day', 24 * 3600],
  ['hour', 3600],
  ['minute', 60],
  ['second', 1],
];

export function formatRelative(value: string | null | undefined, now: number = Date.now()): string {
  const d = parseDate(value);
  if (!d) return 'never';
  const seconds = Math.round((d.getTime() - now) / 1000);
  if (Math.abs(seconds) < 45) return 'just now';
  const rtf = new Intl.RelativeTimeFormat(undefined, { numeric: 'auto' });
  for (const [unit, size] of RELATIVE_UNITS) {
    if (Math.abs(seconds) >= size || unit === 'second') {
      return rtf.format(Math.round(seconds / size), unit);
    }
  }
  return rtf.format(seconds, 'second');
}

export function formatPercent(value: number | null | undefined, digits = 0): string {
  if (value === null || value === undefined || !Number.isFinite(value)) return '—';
  return `${value.toFixed(digits)}%`;
}

export function formatNumber(value: number | null | undefined): string {
  if (value === null || value === undefined || !Number.isFinite(value)) return '—';
  return value.toLocaleString();
}

export function formatDuration(minutes: number | null | undefined): string {
  if (minutes === null || minutes === undefined) return '—';
  if (minutes >= 1440 && minutes % 1440 === 0) return minutes === 1440 ? '1 day' : `${minutes / 1440} days`;
  const h = Math.floor(minutes / 60);
  const m = minutes % 60;
  if (h === 0) return `${m} min`;
  return m === 0 ? `${h} h` : `${h} h ${m} min`;
}

/** "PendingReboot" → "Pending reboot", "DotNet" → ".NET", "ExtendedSecurityUpdates" → "Extended security updates". */
export function humanize(value: string | null | undefined): string {
  if (!value) return '—';
  const special: Record<string, string> = {
    DotNet: '.NET',
    ServicingStack: 'Servicing stack',
    UpdateScan: 'Update scan',
    InstallUpdates: 'Install updates',
    InventoryRefresh: 'Inventory refresh',
    NotifyUser: 'Message to users',
    AgentUpdate: 'Agent update',
    UninstallAgent: 'Agent uninstall',
    UninstallUpdate: 'Update removal',
    DownloadUpdates: 'Download before the window',
    PromptWithDeadline: 'Ask users, with a deadline',
    PromptNoDeadline: 'Ask users, no deadline',
    OnlyIfPending: 'Only if a restart is pending',
    AutoDownloadNotifyInstall: 'Download automatically, notify to install',
    AutoDownloadScheduleInstall: 'Download and install on a schedule',
    NotifyDownload: 'Notify before downloading',
    NotManaged: 'Not managed',
    WaitingForUser: 'Waiting for user',
    AllEligible: 'All eligible',
    WaitingForReboot: 'Waiting for restart',
    PendingReboot: 'Pending restart',
    RebootRequired: 'Restart required',
    ExtendedSecurityUpdates: 'ESU',
    NeverScanned: 'Never scanned',
    ScanStale: 'Scan stale',
    FailedUpdates: 'Failed updates',
    MissingUpdates: 'Missing updates',
    PendingVerification: 'Pending verification',
    Reoffered: 'Offered again',
    NotApplicable: 'Not applicable',
    SuperAdmin: 'Super admin',
    ReadOnly: 'Read only',
    NotEnrolled: 'Not enrolled',
  };
  if (special[value]) return special[value];
  const spaced = value.replace(/([a-z0-9])([A-Z])/g, '$1 $2').replace(/([A-Z]+)([A-Z][a-z])/g, '$1 $2');
  return spaced.charAt(0).toUpperCase() + spaced.slice(1).toLowerCase();
}

const DAY_NAMES = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
export const DAY_LABELS = DAY_NAMES;

export function formatDays(days: number[] | null | undefined): string {
  if (!days || days.length === 0) return 'No days';
  if (days.length === 7) return 'Every day';
  return [...days]
    .sort((a, b) => a - b)
    .map((d) => DAY_NAMES[d] ?? String(d))
    .join(', ');
}

/** How far along an update in a running job is: its download percentage while downloading, its install percentage
 * while installing, and null otherwise or when the agent did not report one. */
export function jobItemPercent(item: {
  status: string;
  downloadPercent?: number | null;
  installPercent?: number | null;
}): number | null {
  const value = item.status === 'Downloading' ? item.downloadPercent : item.status === 'Installing' ? item.installPercent : null;
  return value === null || value === undefined ? null : Math.max(0, Math.min(100, Math.round(value)));
}

/** Human description of a WUA skip reason (mirrors SkipReasons.Describe on the server). */
export function describeSkipReason(reason: string | null | undefined): string {
  switch (reason) {
    case 'AlreadyInstalled':
      return 'Already installed';
    case 'PendingReboot':
      return 'Installed, waiting for a restart';
    case 'NotApplicable':
      return 'No longer offered by the update source';
    case 'NotSelected':
      return 'Not selected';
    case 'CategoryNotAllowed':
      return 'Category not allowed by policy';
    case 'OptionalNotAllowed':
      return 'Optional update not allowed by policy';
    case 'Excluded':
      return 'Excluded';
    case 'RequiresUserInput':
      return 'Requires interactive user input';
    case 'EulaNotAccepted':
      return 'License agreement not accepted by policy';
    case 'MaintenanceWindowClosed':
      return 'Maintenance window closed';
    case 'Cancelled':
      return 'Cancelled';
    case 'ApplicationNotApproved':
      return 'Application not approved by policy';
    case 'Reoffered':
      return 'Offered again after a successful installation (select it to install it anyway)';
    case 'NotInstalled':
      return 'Not installed';
    case 'Held':
      return 'On hold (not installed automatically)';
    case 'WindowStarted':
      return 'Not downloaded before the window started (the installation downloads it)';
    case null:
    case undefined:
    case '':
      return '';
    default:
      return reason;
  }
}

export function truncate(value: string | null | undefined, max: number): string {
  if (!value) return '';
  return value.length > max ? `${value.slice(0, max - 1)}…` : value;
}

/** Validates "HH:mm" (24 h). */
export function isValidTime(value: string): boolean {
  return /^([01]\d|2[0-3]):[0-5]\d$/.test(value);
}

/** Normalizes a KB entry: "kb5030219" / "5030219" → "KB5030219"; null when invalid. */
export function normalizeKb(value: string): string | null {
  const m = /^\s*(?:kb)?(\d{1,10})\s*$/i.exec(value);
  return m ? `KB${m[1]}` : null;
}

/**
 * Converts a local calendar date from an `<input type="date">` into an ISO instant at the start of that day
 * or, for `end`, the last millisecond of that day, so date-range filters include the whole day the admin picked.
 */
export function dayBoundary(value: string, end: boolean): string | undefined {
  if (!value) return undefined;
  const [y, m, d] = value.split('-').map(Number);
  if (!y || !m || !d) return undefined;
  const date = end ? new Date(y, m - 1, d, 23, 59, 59, 999) : new Date(y, m - 1, d);
  return Number.isNaN(date.getTime()) ? undefined : date.toISOString();
}

/** Short, human description of a browser user agent ("Edge on Windows"). Best effort; falls back to the raw string. */
export function describeUserAgent(ua: string | null | undefined): string {
  if (!ua) return 'Unknown device';
  const browser = /Edg\//.test(ua)
    ? 'Edge'
    : /OPR\//.test(ua)
      ? 'Opera'
      : /Firefox\//.test(ua)
        ? 'Firefox'
        : /Chrome\//.test(ua)
          ? 'Chrome'
          : /Safari\//.test(ua)
            ? 'Safari'
            : null;
  const os = /Windows/.test(ua)
    ? 'Windows'
    : /iPhone|iPad/.test(ua)
      ? 'iOS'
      : /Mac OS X|Macintosh/.test(ua)
        ? 'macOS'
        : /Android/.test(ua)
          ? 'Android'
          : /Linux/.test(ua)
            ? 'Linux'
            : null;
  if (browser && os) return `${browser} on ${os}`;
  return browser ?? os ?? truncate(ua, 60);
}

// ---------------------------------------------------------------------------------------------
// Platforms (Windows, Linux and macOS endpoints)
// ---------------------------------------------------------------------------------------------

/** Shown wherever the macOS agent appears. */
export const MACOS_EXPERIMENTAL = 'Experimental: the macOS agent is in development and not for production use.';

/** True for a Linux endpoint ("Linux" platform). */
export function isLinux(platform: string | null | undefined): boolean {
  return platform?.toLowerCase() === 'linux';
}

/** True for a macOS endpoint ("macOS" platform; the macOS agent is experimental). */
export function isMacOS(platform: string | null | undefined): boolean {
  return platform?.toLowerCase() === 'macos';
}

/** True for a Windows endpoint: anything that is not Linux or macOS, including a missing value (agents before 1.3.0). */
export function isWindows(platform: string | null | undefined): boolean {
  return !isLinux(platform) && !isMacOS(platform);
}

/** "Windows", "Linux" or "macOS". */
export function platformName(platform: string | null | undefined): string {
  return isLinux(platform) ? 'Linux' : isMacOS(platform) ? 'macOS' : 'Windows';
}

/**
 * The secondary OS line: "23H2 · build 22631.4317" on Windows; "kernel 6.8.0-45-generic" on Linux and "build 24G325" on
 * macOS, where the version (VERSION_ID, or the macOS version) is only added when the OS name does not already contain it.
 */
export function osDetails(os: { platform: string; operatingSystem: string | null; osVersion: string | null; osBuild: string | null }): string[] {
  if (isLinux(os.platform) || isMacOS(os.platform)) {
    const version = os.osVersion && !(os.operatingSystem ?? '').includes(os.osVersion) ? os.osVersion : null;
    const build = os.osBuild && (isLinux(os.platform) ? `kernel ${os.osBuild}` : `build ${os.osBuild}`);
    return [version, build].filter((v): v is string => !!v);
  }
  return [os.osVersion, os.osBuild && `build ${os.osBuild}`].filter((v): v is string => !!v);
}

/** How a Linux or macOS agent protects its private key (LinuxDetailsDto/MacOSDetailsDto.keyProtection). */
export function describeKeyProtection(value: string | null | undefined): string {
  switch (value) {
    case 'systemd-creds-host':
      return 'systemd-creds (host key)';
    case 'file-permissions':
      return 'File permissions only';
    case null:
    case undefined:
    case '':
      return '—';
    default:
      return value;
  }
}

/** "1.2-1 → 1.2-2"; only the new version when the installed one is unknown. */
export function formatVersionChange(installed: string | null | undefined, version: string | null | undefined): string {
  if (installed && version) return `${installed} → ${version}`;
  return version || installed || '—';
}

/** Agent package format for display: "msi" → "MSI", "deb" → "DEB", "rpm" → "RPM", "pkg" → "macOS package (.pkg)". */
export function formatPackageFormat(format: string | null | undefined): string {
  if (format?.toLowerCase() === 'pkg') return 'macOS package (.pkg)';
  return format ? format.toUpperCase() : '—';
}

/** An agent package in a sentence: "MSI package", "DEB package", "macOS package (.pkg)". */
export function describeAgentPackage(format: string | null | undefined): string {
  if (!format) return 'package';
  return format.toLowerCase() === 'pkg' ? formatPackageFormat(format) : `${formatPackageFormat(format)} package`;
}
