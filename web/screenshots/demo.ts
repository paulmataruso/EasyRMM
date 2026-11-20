// A fictional MSP's data, shaped like the API's JSON, for the README's screenshots (readme.spec.ts).
//
// Every name, address and number here is invented. Organizations and people use the reserved example.com domain and
// the documentation address ranges (RFC 5737, RFC 3849). Times are relative to NOW, which the browser's clock is
// fixed to, so "5 minutes ago" reads the same on every run.

import type {
  PatchAlert,
  PatchAlertCounts,
  AlertEntry,
  AlertSummary,
  AuditEntry,
  Device,
  DeviceAgent,
  DeviceInventory,
  DevicePatching,
  MetricSample,
  MetricsHistory,
  Organization,
  PatchEndpoint,
  PatchFleet,
  PatchFleetDevice,
  PatchFleetUpdate,
  PatchJobView,
  PatchMonthlyReport,
  PatchMonthlyReportList,
  PatchLifecycleList,
  PatchSettingsView,
  PatchPolicy,
  PatchPolicyLayer,
  PatchPolicyView,
  PatchStatus,
  PatchTag,
  PatchTagRef,
  PatchTrend,
  PatchUpdate,
  PatchUpdateDevice,
  PatchUpdateView,
  Platform,
  RecentConnection,
  RemoteAccessStatus,
  Report,
  SessionView,
  Site,
  User,
} from "../src/api/types";
import { alertEntry, auditEntry, device as baseDevice, inventory, metrics, org, person, site as baseSite } from "../src/test/fixtures";

export const NOW = new Date("2026-11-17T15:20:00Z");
export const TIME_ZONE = "America/Chicago";

const ago = (minutes: number) => new Date(NOW.getTime() - minutes * 60_000).toISOString();
const days = (n: number) => ago(n * 24 * 60);
const GiB = 1024 ** 3;
/** What a build from an untagged checkout reports (Makefile: git describe). */
const AGENT_VERSION = "8519085";

const SUPER_PERMISSIONS: SessionView["permissions"] = [
    "org.view",
    "org.manage",
    "org.create",
    "site.view",
    "site.manage",
    "device.view",
    "device.edit",
    "device.remote_desktop",
    "device.terminal",
    "device.files",
    "script.view",
    "script.manage",
    "script.run",
    "job.view",
    "job.manage",
    "software.view",
    "software.manage",
    "patch.view",
    "patch.manage",
    "patch.configure",
    "monitoring.view",
    "monitoring.manage",
    "alert.view",
    "alert.manage",
    "enrollment.manage",
    "user.view",
    "user.manage",
    "audit.view",
    "report.view",
    "settings.manage",
  ];

export const session: SessionView = {
  state: "active",
  user: { id: "u-sam", email: "sam.okafor@example.com", displayName: "Sam Okafor", status: "active", mfaEnabled: true, totp: false, securityKeys: 1 },
  csrfToken: "demo",
  expiresAt: "2030-01-01T00:00:00Z",
  permissions: SUPER_PERMISSIONS,
  // A super administrator holds every permission everywhere.
  globalPermissions: SUPER_PERMISSIONS,
  isSuperAdmin: true,
  features: { remoteAccess: true },
};

// ---------------------------------------------------------------------------------------------
// Organizations and sites

export const organizations: Organization[] = [
  org("o-alder", "Alder & Finch LLP", { siteCount: 1, createdAt: days(410) }),
  org("o-bright", "Brightline Architects", { siteCount: 1, createdAt: days(120) }),
  org("o-cedar", "Cedar Valley Library", { siteCount: 2, createdAt: days(260) }),
  org("o-harbor", "Harbor Dental Group", { siteCount: 2, createdAt: days(530) }),
  org("o-meridian", "Meridian Freight", { siteCount: 2, createdAt: days(300) }),
];
const orgName = (id: string) => organizations.find((o) => o.id === id)?.name ?? "";

function site(id: string, organizationId: string, name: string, groups: number, timezone = "America/Chicago"): Site {
  return baseSite(id, organizationId, name, { organizationName: orgName(organizationId), deviceGroupCount: groups, timezone });
}

export const sites: Site[] = [
  site("s-alder", "o-alder", "Downtown office", 2),
  site("s-bright", "o-bright", "Studio", 1, "America/Denver"),
  site("s-cedar", "o-cedar", "Central branch", 1),
  site("s-cedar-n", "o-cedar", "North branch", 0),
  site("s-harbor", "o-harbor", "Main clinic", 2),
  site("s-harbor-e", "o-harbor", "Eastside clinic", 1),
  site("s-mf-wh", "o-meridian", "Warehouse", 2),
  site("s-mf-disp", "o-meridian", "Dispatch", 1),
];

// ---------------------------------------------------------------------------------------------
// Devices

const OS: Record<string, string> = {
  w11: "Windows 11 Pro, version 24H2",
  w11e: "Windows 11 Enterprise, version 24H2",
  w10: "Windows 10 Enterprise LTSC 2021",
  s25: "Windows Server 2025 Standard",
  s22: "Windows Server 2022 Datacenter",
  ubuntu: "Ubuntu 24.04.3 LTS",
  debian: "Debian GNU/Linux 13 (trixie)",
  rocky: "Rocky Linux 9.6 (Blue Onyx)",
};

function agent(online: boolean, lastSeen: string): DeviceAgent {
  return {
    version: AGENT_VERSION,
    arch: "amd64",
    sha256: "c".repeat(64),
    online,
    lastSeenAt: lastSeen,
    enrolledAt: days(90),
    update: { status: "current", version: AGENT_VERSION, attempts: 0, error: "", requested: false },
  };
}

function device(id: string, name: string, siteId: string, os: string, platform: Platform, opts: { offline?: number } = {}): Device {
  const s = sites.find((x) => x.id === siteId)!;
  const online = opts.offline === undefined;
  const lastSeen = online ? ago(0.2) : ago(opts.offline!);
  return baseDevice(id, name, {
    organizationId: s.organizationId,
    organizationName: s.organizationName,
    siteId,
    siteName: s.name,
    hostname: platform === "windows" ? name : name.toLowerCase(),
    osDescription: OS[os],
    platform,
    online,
    remoteOnline: online,
    lastSeenAt: lastSeen,
    agent: agent(online, lastSeen),
    createdAt: days(90),
    canRunScripts: true,
    canUpdateAgent: true,
    canManageSoftware: true,
  });
}

export const devices: Device[] = [
  device("d-af-fs01", "AF-FS01", "s-alder", "s22", "windows"),
  device("d-af-lt-02", "AF-LT-PARALEGAL2", "s-alder", "w11", "windows", { offline: 47 }),
  device("d-af-lt-01", "AF-LT-PARTNER1", "s-alder", "w11", "windows"),
  device("d-af-rec", "AF-RECEPTION", "s-alder", "w11", "windows"),
  device("d-ba-cad01", "BA-CAD-01", "s-bright", "w11", "windows"),
  device("d-ba-cad02", "BA-CAD-02", "s-bright", "w11", "windows"),
  device("d-ba-nas", "ba-nas-01", "s-bright", "debian", "linux"),
  device("d-cvl-circ", "CVL-CIRC-01", "s-cedar", "w11", "windows"),
  device("d-cvl-kiosk", "cvl-kiosk-01", "s-cedar", "ubuntu", "linux"),
  device("d-cvl-pub3", "CVL-PUBLIC-03", "s-cedar-n", "w10", "windows", { offline: 60 * 26 }),
  device("d-hdg-dc01", "HDG-DC01", "s-harbor", "s25", "windows"),
  device("d-hdg-front1", "HDG-FRONT-01", "s-harbor", "w11", "windows"),
  device("d-hdg-front2", "HDG-FRONT-02", "s-harbor", "w11", "windows"),
  device("d-hdg-xray", "HDG-XRAY-01", "s-harbor", "w10", "windows"),
  device("d-hdg-east", "HDG-EAST-FRONT", "s-harbor-e", "w11e", "windows"),
  device("d-mf-db01", "mf-db-01", "s-mf-wh", "debian", "linux"),
  device("d-mf-scan", "mf-scan-gw", "s-mf-wh", "rocky", "linux"),
  device("d-mf-wms01", "mf-wms-01", "s-mf-wh", "ubuntu", "linux"),
  device("d-mf-disp1", "MF-DISPATCH-01", "s-mf-disp", "w11", "windows"),
  device("d-mf-disp2", "MF-DISPATCH-02", "s-mf-disp", "w11", "windows"),
];
export const byId = (id: string) => devices.find((d) => d.id === id);

export const remoteAccess: RemoteAccessStatus = {
  address: "https://rmm.example.com",
  connected: true,
  lastSyncAt: ago(0.5),
  devices: devices.length,
  devicesOnline: devices.filter((d) => d.online).length,
};

export const recentConnections: RecentConnection[] = [
  { device: byId("d-hdg-front2")!, kind: "desktop", at: ago(6) },
  { device: byId("d-mf-db01")!, kind: "terminal", at: ago(38) },
  { device: byId("d-af-fs01")!, kind: "files", at: ago(95) },
  { device: byId("d-ba-cad01")!, kind: "desktop", at: ago(60 * 5) },
  { device: byId("d-hdg-dc01")!, kind: "rdp", at: ago(60 * 26) },
];

// ---------------------------------------------------------------------------------------------
// Alerts

function alert(id: string, name: string, deviceId: string, extra: Partial<AlertEntry>): AlertEntry {
  const d = byId(deviceId)!;
  return alertEntry(id, name, {
    deviceId,
    deviceName: d.name,
    organizationId: d.organizationId,
    organizationName: d.organizationName,
    siteId: d.siteId,
    siteName: d.siteName,
    ...extra,
  });
}

export const alerts: AlertEntry[] = [
  alert("a1", "Disk space", "d-mf-db01", { kind: "disk", threshold: 90, minutes: 5, severity: "critical", value: 91.2, lastValue: 94.4, openedAt: ago(52) }),
  alert("a2", "Sustained CPU", "d-ba-cad01", { kind: "cpu", threshold: 95, minutes: 15, severity: "warning", value: 96, lastValue: 98.1, openedAt: ago(21) }),
  alert("a3", "Device offline", "d-af-lt-02", { kind: "offline", threshold: null, minutes: 30, severity: "warning", value: 30, lastValue: 47, openedAt: ago(17) }),
  alert("a4", "Memory pressure", "d-hdg-dc01", {
    kind: "memory",
    threshold: 90,
    minutes: 10,
    severity: "warning",
    value: 90.6,
    lastValue: 91.8,
    openedAt: ago(140),
    status: "acknowledged",
    acknowledgedAt: ago(120),
    acknowledgedBy: "priya.nair@example.com",
  }),
];

export const alertSummary: AlertSummary = { active: 4, critical: 1, warning: 3, acknowledged: 1, devices: 4 };

// ---------------------------------------------------------------------------------------------
// People and the audit log

export const users: User[] = [
  person("u-sam", "Sam Okafor", "sam.okafor@example.com", { isSelf: true }),
  person("u-priya", "Priya Nair", "priya.nair@example.com"),
  person("u-jordan", "Jordan Lee", "jordan.lee@example.com"),
  person("u-mia", "Mia Hoffmann", "mia.hoffmann@example.com"),
  person("u-dev", "Dev Patel", "dev.patel@example.com"),
  person("u-erin", "Erin Walsh", "erin.walsh@example.com"),
  person("u-lucas", "Lucas Moreau", "lucas.moreau@example.com"),
];

function audit(id: number, minutesAgo: number, actor: string, action: string, extra: Partial<AuditEntry>): AuditEntry {
  return auditEntry(id, action, { occurredAt: ago(minutesAgo), actorId: actor, actorLabel: `${actor.slice(2)}@example.com`, sourceIp: "203.0.113.24", ...extra });
}

export const auditLog: AuditEntry[] = [
  audit(9120, 6, "u-sam.okafor", "device.remote_session", { targetType: "device", targetId: "d-hdg-front2", details: { device: "HDG-FRONT-02", kind: "desktop" } }),
  audit(9119, 14, "u-priya.nair", "patch.install", {
    targetType: "device",
    targetId: "d-af-fs01",
    details: { device: "AF-FS01", name: "3 updates" },
  }),
  audit(9118, 23, "u-jordan.lee", "device.script_run", {
    targetType: "device",
    targetId: "d-cvl-circ",
    details: { script: "Clear the print queue", device: "CVL-CIRC-01" },
  }),
  audit(9117, 38, "u-sam.okafor", "device.remote_session", { targetType: "device", targetId: "d-mf-db01", details: { device: "mf-db-01", kind: "terminal" } }),
  audit(9116, 61, "u-mia.hoffmann", "device.software_action", {
    targetType: "device",
    targetId: "d-ba-cad01",
    details: { package: "7-Zip", device: "BA-CAD-01", action: "install" },
  }),
  audit(9115, 120, "u-priya.nair", "alert.acknowledge", { targetType: "alert", targetId: "a4", details: { name: "Memory pressure", device: "HDG-DC01" } }),
  audit(9114, 190, "u-dev.patel", "device.enroll", { targetType: "device", targetId: "d-mf-disp2", details: { device: "MF-DISPATCH-02" } }),
  audit(9113, 260, "u-sam.okafor", "easypatch.organization_update", {
    targetType: "organization",
    targetId: "o-bright",
    details: { organization: "Brightline Architects", autoInstall: true },
  }),
  audit(9112, 330, "u-erin.walsh", "user.invite", { targetType: "user", targetId: "u-lucas", details: { email: "lucas.moreau@example.com" } }),
  audit(9111, 400, "u-jordan.lee", "auth.login", { targetType: "user", targetId: "u-jordan.lee" }),
];

// ---------------------------------------------------------------------------------------------
// One server's health: HDG-DC01, the dental group's domain controller

export const HEALTH_DEVICE = "d-hdg-dc01";

export const healthInventory: DeviceInventory = {
  inventory: inventory({
    system: { manufacturer: "Dell Inc.", model: "PowerEdge T360", serial: "4HQ7RT3", biosVendor: "Dell Inc.", biosVersion: "1.4.3", biosDate: "2025-06-10", virtualization: "" },
    cpu: { model: "Intel(R) Xeon(R) E-2488 CPU @ 3.20GHz", sockets: 1, cores: 8, threads: 16 },
    memoryBytes: 64 * GiB,
    os: { name: "Windows Server 2025 Standard", id: "windows", version: "10.0.26100", kernel: "26100.7171", timezone: "Central Standard Time" },
    disks: [
      { name: "PhysicalDrive0", model: "Dell BOSS-N1", serial: "PHAB4153002T480D", sizeBytes: 480 * 1000 ** 3, kind: "ssd", removable: false },
      { name: "PhysicalDrive1", model: "PERC H755 RAID 5", serial: "", sizeBytes: 3840 * 1000 ** 3, kind: "ssd", removable: false },
    ],
    interfaces: [{ name: "Embedded NIC 1", mac: "c4:cb:e1:10:22:31", addresses: ["192.0.2.10/24", "2001:db8:10::10/64"], up: true, speedMbps: 1000 }],
    gateways: ["192.0.2.1"],
    dnsServers: ["127.0.0.1", "192.0.2.11"],
    packageManager: "windows",
    packageCount: 61,
    receivedAt: ago(42),
  }),
  metrics: metrics({
    at: ago(0.5),
    cpuPercent: 23.4,
    memoryTotal: 64 * GiB,
    memoryUsed: 58.8 * GiB,
    swapTotal: 9.5 * GiB,
    swapUsed: 1.2 * GiB,
    load1: 0,
    load5: 0,
    load15: 0,
    uptimeSeconds: 11 * 86_400 + 6 * 3_600,
    processes: 186,
    filesystems: [
      { mount: "C:\\", device: "C:", type: "NTFS", totalBytes: 446 * GiB, usedBytes: 181 * GiB },
      { mount: "D:\\", device: "D:", type: "ReFS", totalBytes: 3491 * GiB, usedBytes: 2210 * GiB },
    ],
  }),
};

/** A smooth day: a working-hours swell, the backup at 01:00 on disk, memory creeping up to its alert. */
export function healthHistory(range: string): MetricsHistory {
  const span = { "1h": 1, "24h": 24, "7d": 168, "30d": 720 }[range] ?? 24;
  const bucket = span <= 1 ? 60 : span <= 24 ? 300 : span <= 168 ? 1800 : 7200;
  const points = Math.floor((span * 3600) / bucket);
  const end = NOW.getTime();
  const samples: MetricSample[] = [];
  for (let i = 0; i <= points; i++) {
    const t = end - (points - i) * bucket * 1000;
    const hour = new Date(t).getUTCHours() - 6; // Chicago, near enough for a shape
    const local = (hour + 24) % 24;
    const work = local >= 8 && local < 18 ? Math.sin(((local - 8) / 10) * Math.PI) : 0;
    const wobble = Math.sin(i * 1.7) * 3 + Math.sin(i * 0.37) * 2;
    const backup = local >= 1 && local < 3 ? 40 : 0;
    samples.push({
      at: new Date(t).toISOString(),
      cpuPercent: Math.max(2, Math.min(100, 9 + work * 26 + backup * 0.5 + wobble)),
      memoryPercent: Math.min(96, 78 + (i / points) * 13 + work * 2 + Math.sin(i * 0.9)),
      swapPercent: 12 + Math.sin(i * 0.2) * 2,
      diskPercent: 41 + (i / points) * 0.6,
      load1: 0,
    });
  }
  return { range: range as MetricsHistory["range"], bucketSeconds: bucket, from: new Date(end - span * 3_600_000).toISOString(), to: NOW.toISOString(), samples };
}

// ---------------------------------------------------------------------------------------------
// Patching through the patching engine in the deployment

export const patchStatus: PatchStatus = { configured: true, canSchedule: true };

type Compliance = Pick<
  PatchEndpoint,
  "complianceStatus" | "missingRequiredCount" | "missingTotalCount" | "failedCount" | "rebootPending" | "knownExploitedMissingCount"
> &
  Partial<PatchEndpoint>;

const COMPLIANT: Compliance = {
  complianceStatus: "Compliant",
  missingRequiredCount: 0,
  missingTotalCount: 0,
  failedCount: 0,
  rebootPending: false,
  knownExploitedMissingCount: 0,
};

const PATCH_STATE: Record<string, Compliance> = {
  "d-af-fs01": { complianceStatus: "MissingUpdates", missingRequiredCount: 3, missingTotalCount: 4, failedCount: 0, rebootPending: false, knownExploitedMissingCount: 1 },
  "d-af-lt-02": { complianceStatus: "ScanStale", missingRequiredCount: 2, missingTotalCount: 2, failedCount: 0, rebootPending: false, knownExploitedMissingCount: 0 },
  "d-ba-cad01": { complianceStatus: "RebootRequired", missingRequiredCount: 0, missingTotalCount: 0, failedCount: 0, rebootPending: true, knownExploitedMissingCount: 0 },
  "d-cvl-pub3": { complianceStatus: "FailedUpdates", missingRequiredCount: 1, missingTotalCount: 1, failedCount: 1, rebootPending: false, knownExploitedMissingCount: 1 },
  "d-hdg-dc01": { complianceStatus: "MissingUpdates", missingRequiredCount: 2, missingTotalCount: 2, failedCount: 0, rebootPending: false, knownExploitedMissingCount: 1 },
  "d-hdg-xray": { complianceStatus: "MissingUpdates", missingRequiredCount: 1, missingTotalCount: 3, failedCount: 0, rebootPending: false, knownExploitedMissingCount: 0 },
  "d-mf-db01": { complianceStatus: "MissingUpdates", missingRequiredCount: 6, missingTotalCount: 6, failedCount: 0, rebootPending: false, knownExploitedMissingCount: 0 },
  "d-mf-scan": { complianceStatus: "MissingUpdates", missingRequiredCount: 4, missingTotalCount: 11, failedCount: 0, rebootPending: false, knownExploitedMissingCount: 0 },
};

function endpoint(d: Device, i: number): PatchEndpoint {
  const c = PATCH_STATE[d.id] ?? COMPLIANT;
  return {
    id: `e0000000-0000-4000-8000-${String(i).padStart(12, "0")}`,
    hostname: d.hostname,
    organizationId: `ep-${d.organizationId}`,
    organizationName: d.organizationName,
    siteName: d.siteName,
    status: "Active",
    operatingSystem: d.osDescription,
    platform: d.platform === "windows" ? "Windows" : "Linux",
    agentVersion: "1.11.1",
    agentOutdated: false,
    isOnline: d.online,
    lastCheckInAt: d.lastSeenAt,
    lastScanAt: c.complianceStatus === "ScanStale" ? days(9) : ago(30 + i * 7),
    missingDeferredCount: 0,
    currentActivity: "",
    ...c,
  };
}

const linkedOrgs = new Set(["o-alder", "o-bright", "o-cedar", "o-harbor", "o-meridian"]);

export const fleet: PatchFleet = {
  truncated: false,
  errors: [],
  // A front-desk PC enrolled in EasyPatch before EasyRMM's agent was on it.
  unmatched: [
    {
      id: "e0000000-0000-4000-8000-000000000900",
      hostname: "HDG-FRONTDESK-2",
      organizationId: "o-harbor",
      organizationName: "Harbor Dental Group",
      siteName: "Eastside clinic",
      status: "Active",
      operatingSystem: "Windows 11 Pro 24H2",
      platform: "Windows",
      agentVersion: "1.11.1",
      agentOutdated: false,
      isOnline: true,
      lastCheckInAt: ago(4),
      lastScanAt: ago(95),
      complianceStatus: "MissingUpdates",
      missingRequiredCount: 2,
      missingTotalCount: 2,
      missingDeferredCount: 0,
      failedCount: 0,
      rebootPending: false,
      knownExploitedMissingCount: 0,
      currentActivity: "",
    },
  ],
  devices: devices
    .filter((d) => linkedOrgs.has(d.organizationId))
    .map(
      (d, i): PatchFleetDevice => ({
        deviceId: d.id,
        name: d.name,
        organizationId: d.organizationId,
        organizationName: d.organizationName,
        siteId: d.siteId,
        siteName: d.siteName,
        platform: d.platform,
        link: "linked",
        canManage: true,
        endpoint: endpoint(d, i),
        checkedAt: ago(2),
      }),
    ),
};

export const PATCH_DEVICE = "d-af-fs01";

const policy: PatchPolicy = {
  autoInstallEnabled: true,
  maintenanceDays: [6],
  maintenanceStart: "22:00",
  maintenanceDurationMinutes: 240,
  timeZone: "America/Chicago",
  scanIntervalMinutes: 240,
  allowedCategories: ["Security Updates", "Critical Updates", "Update Rollups"],
  includeOptional: false,
  installDelayDays: 7,
  securityInstallDelayDays: 2,
  checkInIntervalSeconds: 60,
  inventoryIntervalMinutes: 1440,
  jitterPercent: 10,
  excludedKbs: [],
  acceptEulas: true,
  scanStaleAfterHours: 72,
  maxConcurrentInstallsPerSite: 10,
  trayIconEnabled: true,
  installNotificationsEnabled: true,
  agentAutoUpdateEnabled: true,
  knownExploitedSkipsDelay: true,
  preDownloadHours: 4,
  restartSchedule: {
    enabled: true,
    days: [0],
    time: "03:00",
    condition: "OnlyIfPending",
    mode: "PromptWithDeadline",
    countdownMinutes: 10,
    deadlineMinutes: 240,
    expiryMinutes: 120,
  },
  windowsUpdate: {
    automaticUpdates: { mode: "AutoDownloadNotifyInstall", scheduledInstallDay: 0, scheduledInstallHour: 3 },
    featureUpdates: { deferDays: 180, targetProductVersion: "", targetReleaseVersion: "" },
    qualityUpdates: null,
    restartBehavior: { noAutoRestartWithSignedInUsers: true, activeHoursStart: 7, activeHoursEnd: 19 },
  },
  windowsUpdateValues: null,
  applicationUpdates: null,
  sources: {
    AutoInstallEnabled: "Organization",
    MaintenanceWindow: "Site",
    AllowedCategories: "Organization",
    InstallDelayDays: "Organization",
    SecurityInstallDelayDays: "Organization",
    RestartSchedule: "Site",
    PreDownloadHours: "Organization",
    "WindowsUpdate.AutomaticUpdates": "Organization",
    "WindowsUpdate.FeatureUpdates": "Organization",
    "WindowsUpdate.RestartBehavior": "Site",
  },
  sourceTags: null,
};

export function devicePatching(id: string): DevicePatching {
  const f = fleet.devices.find((x) => x.deviceId === id);
  if (!f?.endpoint) return { deviceId: id, link: "none", canManage: true, canSchedule: true };
  return {
    deviceId: id,
    link: "linked",
    checkedAt: ago(2),
    canManage: true,
    canSchedule: true,
    endpoint: {
      summary: f.endpoint,
      serialNumber: "8RKQ2V3",
      lastScanAttemptAt: f.endpoint.lastScanAt,
      lastScanError: "",
      rebootReasons: null,
      rebootPendingSince: null,
      installedCount: 212,
      pendingRebootUpdateCount: 0,
      complianceEvaluatedAt: f.endpoint.lastScanAt,
      activeJob: null,
      agentCapabilities: ["restart", "notify-user", "tray", "windows-update-policy", "self-update", "app-updates", "uninstall", "uninstall-updates", "download-updates"],
      signedInUsers: 2,
      trayConnectedSessions: 2,
      hasOwnPolicy: false,
      agentUpdate: {
        supported: true,
        automaticUpdates: true,
        availableVersion: "",
        code: "agent_up_to_date",
        message: "The agent already runs the newest package for its platform.",
        packageFormat: "msi",
      },
      restart: null,
      windowsUpdatePolicy: {
        groups: [
          { group: "AutomaticUpdates", state: "Applied", message: "", appliedAt: ago(30), conflictingValues: null },
          { group: "FeatureUpdates", state: "Applied", message: "", appliedAt: ago(30), conflictingValues: null },
          { group: "RestartBehavior", state: "Applied", message: "", appliedAt: ago(30), conflictingValues: null },
        ],
        mdmUpdatePoliciesPresent: false,
      },
    },
    policy,
  };
}

function update(n: number, title: string, kb: string, category: string, severity: string, extra: Partial<PatchUpdate> = {}): PatchUpdate {
  return {
    updateGuid: `u0000000-0000-4000-8000-${String(n).padStart(12, "0")}`,
    title,
    kbNumber: kb,
    kbNumbers: kb ? [kb] : [],
    category,
    msrcSeverity: severity,
    releaseDate: days(7),
    sizeBytes: 520 * 1024 ** 2,
    rebootLikely: true,
    supportUrl: "",
    state: "Missing",
    isRequired: true,
    isExcluded: false,
    firstDetectedAt: days(6),
    stateChangedAt: days(6),
    installedAt: null,
    failedAttempts: 0,
    errorCode: "",
    errorMessage: "",
    activeJob: null,
    package: null,
    deferredUntil: null,
    cveIds: null,
    knownExploited: false,
    kevDueDate: "",
    holdReason: "",
    ...extra,
  };
}

/** Invented updates for AF-FS01; the KB numbers are not real ones. */
export const missingUpdates: PatchUpdate[] = [
  update(1, "2026-11 Cumulative Update for Microsoft server operating system version 21H2 for x64-based Systems", "KB5099001", "Security Updates", "Critical", {
    knownExploited: true,
    sizeBytes: 612 * 1024 ** 2,
  }),
  update(2, "2026-11 Cumulative Update for .NET Framework 3.5, 4.8 and 4.8.1 for Microsoft server operating system version 21H2", "KB5099002", "Security Updates", "Important", {
    sizeBytes: 74 * 1024 ** 2,
  }),
  update(3, "Microsoft Defender Antivirus antimalware platform update", "KB5099003", "Definition Updates", "", {
    sizeBytes: 15 * 1024 ** 2,
    rebootLikely: false,
    releaseDate: days(1),
    firstDetectedAt: ago(300),
  }),
  update(4, "2026-11 Servicing Stack Update for Microsoft server operating system version 21H2", "KB5099004", "Updates", "", {
    isRequired: false,
    sizeBytes: 22 * 1024 ** 2,
    rebootLikely: false,
  }),
];

export const patchJobs: PatchJobView[] = [
  {
    id: "j0000000-0000-4000-8000-000000000001",
    endpointId: fleet.devices[0]!.endpoint!.id,
    hostname: "AF-FS01",
    type: "InstallUpdates",
    status: "Running",
    trigger: "Manual",
    requestedBy: "priya.nair@example.com via EasyRMM",
    createdAt: ago(14),
    startedAt: ago(13),
    completedAt: null,
    expiresAt: ago(-60 * 24),
    progressPercent: 46,
    phase: "Downloading",
    progressMessage: "Downloading 1 of 3",
    errorCode: "",
    errorMessage: "",
    rebootRequired: false,
    timedOut: false,
    cancelRequested: false,
    itemCount: 3,
    succeededCount: 0,
    failedCount: 0,
    deviceId: "d-af-fs01",
    deviceName: "AF-FS01",
    canManage: true,
  },
];

// ---------------------------------------------------------------------------------------------
// Updates across devices (Patching → Updates and an update's page)

function fleetUpdate(n: number, title: string, kb: string, category: string, severity: string, extra: Partial<PatchFleetUpdate>): PatchFleetUpdate {
  return {
    updateGuid: `u0000000-0000-4000-8000-${String(n).padStart(12, "0")}`,
    title,
    kbNumber: kb,
    category,
    msrcSeverity: severity,
    releaseDate: days(7),
    sizeBytes: 520 * 1024 ** 2,
    missingCount: 0,
    failedCount: 0,
    installedCount: 0,
    pendingRebootCount: 0,
    excludedCount: 0,
    package: null,
    cveCount: 0,
    knownExploited: false,
    reofferedCount: 0,
    onHold: false,
    ...extra,
  };
}

/** The same invented updates as AF-FS01's, counted across the linked organizations. */
export const fleetUpdates: PatchFleetUpdate[] = [
  fleetUpdate(1, missingUpdates[0]!.title, "KB5099001", "Security", "Critical", {
    sizeBytes: 612 * 1024 ** 2,
    missingCount: 2,
    failedCount: 1,
    installedCount: 5,
    pendingRebootCount: 1,
    cveCount: 3,
    knownExploited: true,
  }),
  fleetUpdate(2, missingUpdates[1]!.title, "KB5099002", "Security", "Important", { sizeBytes: 74 * 1024 ** 2, missingCount: 4, installedCount: 8, cveCount: 2 }),
  fleetUpdate(5, "openssl 3.5.4-1~deb13u1", "", "Security", "", {
    sizeBytes: 2 * 1024 ** 2,
    missingCount: 1,
    installedCount: 1,
    cveCount: 1,
    package: { name: "openssl", version: "3.5.4-1~deb13u1", installedVersion: "3.5.1-1", repository: "trixie-security", advisories: ["DSA-6061-1"] },
  }),
  fleetUpdate(3, missingUpdates[2]!.title, "KB5099003", "Definition", "", { sizeBytes: 15 * 1024 ** 2, missingCount: 3, installedCount: 10, releaseDate: days(1) }),
  fleetUpdate(4, missingUpdates[3]!.title, "KB5099004", "ServicingStack", "", { sizeBytes: 22 * 1024 ** 2, missingCount: 2, installedCount: 11, onHold: true }),
];

export const UPDATE_GUID = fleetUpdates[0]!.updateGuid;

export const updateView: PatchUpdateView = {
  summary: fleetUpdates[0]!,
  description:
    "This security update fixes vulnerabilities in the print spooler, the kernel and Remote Desktop Services. It includes the quality improvements of the previous month's preview update.",
  supportUrl: "https://support.example.com/kb/5099001",
  kbNumbers: ["5099001"],
  products: ["Microsoft server operating system, version 21H2"],
  msClassification: "Security Updates",
  rebootLikely: true,
  supersededUpdateGuids: ["u0000000-0000-4000-8000-000000000099"],
  vulnerabilities: [
    {
      cveId: "CVE-2026-41001",
      title: "Windows Print Spooler elevation of privilege vulnerability",
      severity: "Critical",
      cvssBase: 8.8,
      msrcExploited: true,
      kev: true,
      kevDateAdded: "2026-11-11",
      kevDueDate: "2026-12-02",
      kevRansomware: true,
      kevName: "Microsoft Windows Print Spooler",
    },
    {
      cveId: "CVE-2026-41017",
      title: "Windows kernel information disclosure vulnerability",
      severity: "Important",
      cvssBase: 5.5,
      msrcExploited: false,
      kev: false,
      kevDateAdded: null,
      kevDueDate: null,
      kevRansomware: false,
      kevName: "",
    },
    {
      cveId: "CVE-2026-41023",
      title: "Remote Desktop Services denial of service vulnerability",
      severity: "Important",
      cvssBase: 7.5,
      msrcExploited: false,
      kev: false,
      kevDateAdded: null,
      kevDueDate: null,
      kevRansomware: false,
      kevName: "",
    },
  ],
  holds: [],
  canManage: true,
  canHold: true,
  holdIn: organizations.filter((o) => linkedOrgs.has(o.id)).map((o) => ({ id: o.id, name: o.name })),
  canHoldEverywhere: true,
};

function updateDevice(id: string, state: PatchUpdateDevice["state"], minutes: number, extra: Partial<PatchUpdateDevice> = {}): PatchUpdateDevice {
  const d = byId(id)!;
  return {
    endpointId: `e-${id}`,
    hostname: d.hostname,
    deviceId: d.id,
    deviceName: d.name,
    organizationName: d.organizationName,
    siteName: d.siteName,
    platform: d.platform,
    isOnline: d.online,
    state,
    isRequired: true,
    isExcluded: false,
    failedAttempts: 0,
    errorCode: "",
    errorMessage: "",
    stateChangedAt: ago(minutes),
    canManage: true,
    ...extra,
  };
}

export const updateDevices: PatchUpdateDevice[] = [
  updateDevice("d-af-fs01", "Missing", 60 * 24 * 6),
  updateDevice("d-af-lt-01", "Installed", 60 * 30),
  updateDevice("d-af-rec", "Installed", 60 * 29),
  updateDevice("d-ba-cad01", "PendingReboot", 60 * 5),
  updateDevice("d-ba-cad02", "Installed", 60 * 28),
  updateDevice("d-cvl-circ", "Installed", 60 * 52),
  updateDevice("d-cvl-pub3", "Failed", 60 * 26, {
    failedAttempts: 2,
    errorCode: "0x800f0922",
    errorMessage: "The update could not be installed: the system reserved partition is too small.",
  }),
  updateDevice("d-hdg-dc01", "Missing", 60 * 24 * 6),
  updateDevice("d-hdg-front1", "Installed", 60 * 27),
];

// Policies and tags.

const noValues: PatchPolicyLayer = {
  checkInIntervalSeconds: null,
  scanIntervalMinutes: null,
  inventoryIntervalMinutes: null,
  jitterPercent: null,
  allowedCategories: null,
  includeOptional: null,
  excludedKbs: [],
  acceptEulas: null,
  autoInstallEnabled: null,
  maintenanceDays: null,
  maintenanceStart: null,
  maintenanceDurationMinutes: null,
  preDownloadHours: null,
  installDelayDays: null,
  securityInstallDelayDays: null,
  knownExploitedSkipsDelay: null,
  scanStaleAfterHours: null,
  maxConcurrentInstallsPerSite: null,
  trayIconEnabled: null,
  installNotificationsEnabled: null,
  agentAutoUpdateEnabled: null,
  restartSchedule: null,
  windowsUpdate: null,
  applicationUpdates: null,
};

/** The default policy: automatic installs on Saturday nights, a week's grace for non-security updates. */
export const defaultPolicy: PatchPolicyLayer = {
  checkInIntervalSeconds: 60,
  scanIntervalMinutes: 360,
  inventoryIntervalMinutes: 1440,
  jitterPercent: 10,
  allowedCategories: ["Security", "Critical", "Cumulative", "Definition", "ServicingStack", "DotNet", "Other"],
  includeOptional: false,
  excludedKbs: ["KB5005565"],
  acceptEulas: true,
  autoInstallEnabled: true,
  maintenanceDays: [6],
  maintenanceStart: "22:00",
  maintenanceDurationMinutes: 240,
  preDownloadHours: 4,
  installDelayDays: 7,
  securityInstallDelayDays: 0,
  knownExploitedSkipsDelay: true,
  scanStaleAfterHours: 48,
  maxConcurrentInstallsPerSite: 10,
  trayIconEnabled: true,
  installNotificationsEnabled: true,
  agentAutoUpdateEnabled: true,
  restartSchedule: null,
  windowsUpdate: {
    automaticUpdates: { managed: true, value: { mode: "NotifyDownload", scheduledInstallDay: 0, scheduledInstallHour: 3 } },
    featureUpdates: { managed: true, value: { deferDays: 180, targetProductVersion: "", targetReleaseVersion: "" } },
    qualityUpdates: null,
    restartBehavior: null,
  },
  applicationUpdates: { enabled: false, approvedApps: [] },
};

function fromDefault(over: Record<string, string> = {}): Record<string, string> {
  const from: Record<string, string> = {};
  for (const k of Object.keys(defaultPolicy)) from[k] = "Default policy";
  for (const g of ["automaticUpdates", "featureUpdates", "qualityUpdates", "restartBehavior"]) from[`windowsUpdate.${g}`] = "Default policy";
  return { ...from, "windowsUpdate.qualityUpdates": "EasyPatch's defaults", "windowsUpdate.restartBehavior": "EasyPatch's defaults", ...over };
}

/**
 * Harbor Dental Group's policy: clinics close at 19:00, so its window opens earlier, it restarts on Sunday mornings
 * when a restart is pending, and it keeps its imaging software's browser up to date.
 */
export const organizationPolicy: PatchPolicyView = {
  level: "organization",
  name: "Harbor Dental Group",
  own: {
    ...noValues,
    maintenanceDays: [0, 6],
    maintenanceStart: "20:00",
    maintenanceDurationMinutes: 360,
    excludedKbs: ["KB5034441"],
    restartSchedule: {
      enabled: true,
      days: [0],
      time: "06:00",
      condition: "OnlyIfPending",
      mode: "PromptWithDeadline",
      countdownMinutes: 5,
      deadlineMinutes: 120,
      expiryMinutes: 240,
    },
    applicationUpdates: { enabled: true, approvedApps: ["Google.Chrome", "Mozilla.Firefox"] },
  },
  hasOwn: true,
  updatedAt: days(3),
  inherited: defaultPolicy,
  inheritedFrom: fromDefault(),
  windows: true,
  canEdit: true,
  organizationId: "o-harbor",
};

export const patchTags: PatchTag[] = [
  {
    id: "t-pilot",
    name: "Pilot ring",
    color: "amber",
    description: "Gets updates first, without the week's delay.",
    priority: 50,
    endpointCount: 4,
    siteCount: 0,
    organizationCount: 0,
    hasPolicy: true,
    createdAt: days(200),
  },
  {
    id: "t-servers",
    name: "Servers",
    color: "teal",
    description: "Restarts only in the window, never prompted.",
    priority: 40,
    endpointCount: 9,
    siteCount: 0,
    organizationCount: 0,
    hasPolicy: true,
    createdAt: days(400),
  },
  {
    id: "t-clinical",
    name: "Clinical workstations",
    color: "blue",
    description: null,
    priority: 10,
    endpointCount: 0,
    siteCount: 0,
    organizationCount: 1,
    hasPolicy: false,
    createdAt: days(90),
  },
];

export const organizationTags: PatchTagRef[] = [{ id: "t-clinical", name: "Clinical workstations", color: "blue" }];

export const defaultPolicyView: PatchPolicyView = {
  level: "default",
  name: "Default policy",
  own: defaultPolicy,
  hasOwn: true,
  updatedAt: days(40),
  inherited: defaultPolicy,
  inheritedFrom: fromDefault(),
  windows: true,
  canEdit: true,
};

// ---------------------------------------------------------------------------------------------
// Patch reports

const COMPLIANCE_LABELS: Record<string, string> = {
  Compliant: "Up to date",
  MissingUpdates: "Updates missing",
  FailedUpdates: "Updates failed",
  RebootRequired: "Restart needed",
  ScanStale: "Scan out of date",
  NeverScanned: "Never scanned",
};

/** The compliance report as the server builds it from the fleet (reports/patch.go). */
export const patchComplianceReport: Report = {
  name: "patch-compliance",
  title: "Patch compliance",
  columns: [
    { key: "organization", label: "Organization", type: "text" },
    { key: "site", label: "Site", type: "text" },
    { key: "device", label: "Device", type: "text" },
    { key: "platform", label: "Platform", type: "text" },
    { key: "compliance", label: "Compliance", type: "text" },
    { key: "notPatched", label: "Not patched because", type: "text" },
    { key: "missingRequired", label: "Required updates missing", type: "number" },
    { key: "missingTotal", label: "Updates missing", type: "number" },
    { key: "failed", label: "Updates failed", type: "number" },
    { key: "knownExploited", label: "Known exploited", type: "number" },
    { key: "restartPending", label: "Restart pending", type: "bool" },
    { key: "os", label: "Operating system", type: "text" },
    { key: "osBuild", label: "Build", type: "text" },
    { key: "osSupport", label: "OS support", type: "text" },
    { key: "online", label: "Patching agent online", type: "bool" },
    { key: "lastScan", label: "Last scan", type: "time" },
    { key: "lastCheckIn", label: "Last patching check-in", type: "time" },
  ],
  rows: fleet.devices.map((d) => {
    const e = d.endpoint!;
    const windows = d.platform === "windows";
    return [
      d.organizationName,
      d.siteName,
      d.name,
      windows ? "Windows" : "Linux",
      COMPLIANCE_LABELS[e.complianceStatus] ?? e.complianceStatus,
      "",
      e.missingRequiredCount,
      e.missingTotalCount,
      e.failedCount,
      e.knownExploitedMissingCount,
      e.rebootPending,
      e.operatingSystem,
      windows ? "26100.7171" : "",
      windows ? "Supported" : "",
      e.isOnline,
      e.lastScanAt ?? null,
      e.lastCheckInAt ?? null,
    ];
  }),
  total: fleet.devices.length,
  truncated: false,
  generatedAt: NOW.toISOString(),
};

/**
 * Thirty days of compliance: high, a drop the day after Patch Tuesday (10 November) as the month's updates arrive,
 * and the climb back as Saturday's maintenance windows install them.
 */
export const patchTrend: PatchTrend = (() => {
  const total = fleet.devices.length + fleet.unmatched.length;
  const shares = [
    0.86, 0.86, 0.89, 0.89, 0.89, 0.92, 0.92, 0.94, 0.94, 0.94, 0.94, 0.97, 0.97, 0.97, 0.97, 0.97, 0.97, 0.97, 0.97, 0.97, 0.97, 0.97, 0.97,
    0.36, 0.42, 0.47, 0.81, 0.83, 0.86, 0.89,
  ];
  const points = shares.map((share, i) => {
    const d = new Date(NOW);
    d.setUTCDate(d.getUTCDate() - (shares.length - 1 - i));
    const compliant = Math.round(share * total);
    const missing = total - compliant;
    return {
      date: d.toISOString().slice(0, 10),
      totalEndpoints: total,
      compliant,
      missingUpdates: missing,
      failedUpdates: 0,
      rebootRequired: 0,
      scanStale: 0,
      neverScanned: 0,
      offline: 0,
      missingRequiredUpdates: missing * 2,
      compliancePercent: Math.round((compliant / total) * 1000) / 10,
    };
  });
  return { points, organizations: organizations.length };
})();

function monthlyReport(id: string, organizationId: string, periodStart: string, extra: Partial<PatchMonthlyReport> = {}): PatchMonthlyReport {
  return {
    id,
    organizationId,
    organizationName: orgName(organizationId),
    periodStart,
    periodEnd: periodStart.slice(0, 8) + "31",
    monthToDate: false,
    scheduled: true,
    generatedAt: days(16),
    // EasyPatch names no one for a report its schedule made.
    generatedBy: undefined,
    fileName: `patch-report-${organizationId}-${periodStart.slice(0, 7)}.pdf`,
    sizeBytes: 214_000,
    deliveryStatus: "Sent",
    recipients: ["it@example.com"],
    sentAt: days(16),
    canManage: true,
    ...extra,
  };
}

export const monthlyReports: PatchMonthlyReportList = {
  items: [
    monthlyReport("mr-5", "o-harbor", "2026-11-01", {
      monthToDate: true,
      scheduled: false,
      generatedAt: ago(40),
      generatedBy: "jordan@example.com",
      periodEnd: "2026-11-17",
      deliveryStatus: "",
      recipients: [],
      sentAt: null,
    }),
    monthlyReport("mr-4", "o-harbor", "2026-10-01", { recipients: ["office.manager@example.com", "it@example.com"] }),
    monthlyReport("mr-3", "o-meridian", "2026-10-01", { sizeBytes: 388_000 }),
    monthlyReport("mr-2", "o-cedar", "2026-10-01", { deliveryStatus: "Failed", lastError: "550 5.1.1 Mailbox unavailable", sentAt: null }),
    monthlyReport("mr-1", "o-alder", "2026-10-01", { scheduled: false, generatedBy: "jordan@example.com", deliveryStatus: "", recipients: [], sentAt: null }),
  ],
  capped: false,
  canGenerate: organizations.map((o) => o.id),
};

/** Settings → Patching → Server. */
export const patchServerSettings: PatchSettingsView = {
  settings: {
    globalMaxConcurrentInstalls: 50,
    jobDefaultExpiryHours: 168,
    runningJobTimeoutHours: 12,
    waitingForRebootExpiryDays: 30,
    deliveryLeaseMinutes: 10,
    maxDeliveryAttempts: 5,
    offlineThresholdMinutes: 10,
    credentialLifetimeDays: 365,
    credentialRotateBeforeDays: 30,
    retentionEventsDays: 90,
    retentionAuditDays: 365,
    retentionJobsDays: 180,
    retentionScansDays: 90,
    retentionHistoryDays: 730,
    retentionReportsMonths: 24,
    vulnerabilityFeedsEnabled: true,
    reportBrandName: "Northwind IT Services",
    rolloutGuardEnabled: true,
    rolloutGuardMinFailedEndpoints: 3,
    rolloutGuardFailurePercent: 20,
    rolloutGuardWindowDays: 7,
  },
  feeds: [
    { name: "kev", lastAttemptAt: ago(95), lastSuccessAt: ago(95), version: "2026.11.17", itemCount: 1484 },
    { name: "msrc", lastAttemptAt: ago(610), lastSuccessAt: ago(610), version: "2026-Nov", itemCount: 9213 },
    { name: "debian", lastAttemptAt: ago(615), lastSuccessAt: ago(615), itemCount: 41_877 },
  ],
  version: "1.11.1",
  canEdit: true,
};

/** Settings → Patching → OS lifecycle. */
export const patchLifecycle: PatchLifecycleList = {
  items: [
    { id: "lc-1", product: "Windows 10", editionGroup: "HomePro", buildNumber: 19045, versionLabel: "22H2", endOfServicing: "2025-10-14", esuEndDate: "2028-10-10", notes: "Commercial ESU through 2028-10-10." },
    { id: "lc-2", product: "Windows 11", editionGroup: "HomePro", buildNumber: 26200, versionLabel: "25H2", endOfServicing: "2027-10-12", esuEndDate: null, notes: null },
    { id: "lc-3", product: "Windows 11", editionGroup: "HomePro", buildNumber: 26100, versionLabel: "24H2", endOfServicing: "2026-10-13", esuEndDate: null, notes: null },
    { id: "lc-4", product: "Windows Server", editionGroup: "Server", buildNumber: 26100, versionLabel: "2025", endOfServicing: "2034-10-10", esuEndDate: null, notes: null },
    { id: "lc-5", product: "Windows Server", editionGroup: "Server", buildNumber: 17763, versionLabel: "2019", endOfServicing: "2029-01-09", esuEndDate: null, notes: null },
    { id: "lc-6", product: "Ubuntu", editionGroup: "LTS", buildNumber: 2404, versionLabel: "24.04 LTS", endOfServicing: "2029-05-31", esuEndDate: "2034-04-30", notes: "ESU: Ubuntu Pro (ESM) until 2034-04." },
  ],
  canEdit: true,
};

// Patching → Alerts: what EasyPatch's alert rules raised, the most severe first.
const patchAlert = (n: number, a: Partial<PatchAlert> & Pick<PatchAlert, "ruleType" | "severity" | "title" | "organizationId">): PatchAlert => ({
  id: `pa000000-0000-4000-8000-${String(n).padStart(12, "0")}`,
  ruleId: `pr-${a.ruleType}`,
  ruleName: null,
  status: "Open",
  details: null,
  organizationName: orgName(a.organizationId),
  hostname: null,
  openedAt: ago(60 * 5),
  lastSeenAt: ago(2),
  resolvedAt: null,
  acknowledgedAt: null,
  acknowledgedBy: null,
  canAcknowledge: true,
  ...a,
});

export const patchAlerts: PatchAlert[] = [
  patchAlert(1, {
    ruleType: "KnownExploitedMissing",
    severity: "Critical",
    title: "AF-FS01 misses an update for an exploited vulnerability",
    details: "KB5099001 fixes CVE-2026-41001, in CISA's Known Exploited Vulnerabilities catalog.",
    organizationId: "o-alder",
    deviceId: "d-af-fs01",
    deviceName: "AF-FS01",
    hostname: "AF-FS01",
    openedAt: days(2),
  }),
  patchAlert(2, {
    ruleType: "InstallFailed",
    severity: "Critical",
    ruleName: "Failed installs, library",
    title: "An update failed to install on CVL-PUBLIC-03",
    details: "KB5099001: 0x80070005, access is denied. Failed twice.",
    organizationId: "o-cedar",
    deviceId: "d-cvl-pub3",
    deviceName: "CVL-PUBLIC-03",
    hostname: "CVL-PUBLIC-03",
    openedAt: ago(60 * 20),
    status: "Acknowledged",
    acknowledgedBy: "easyrmm:alex@example.com",
    acknowledgedAt: ago(60 * 3),
    canAcknowledge: false,
  }),
  patchAlert(3, {
    ruleType: "EndpointOffline",
    severity: "Warning",
    title: "CVL-PUBLIC-03 has been offline for 26 hours",
    organizationId: "o-cedar",
    deviceId: "d-cvl-pub3",
    deviceName: "CVL-PUBLIC-03",
    hostname: "CVL-PUBLIC-03",
    openedAt: ago(60 * 2),
  }),
  patchAlert(4, {
    ruleType: "OsUnsupported",
    severity: "Warning",
    title: "HDG-XRAY-01 runs Windows 10 22H2, out of support since 2025-10-14",
    details: "Extended Security Updates continue until 2028-10-10.",
    organizationId: "o-harbor",
    deviceId: "d-hdg-xray",
    deviceName: "HDG-XRAY-01",
    hostname: "HDG-XRAY-01",
    openedAt: days(9),
  }),
  patchAlert(5, {
    ruleType: "ScanStale",
    severity: "Warning",
    title: "AF-LT-PARALEGAL2 has not scanned for 9 days",
    organizationId: "o-alder",
    deviceId: "d-af-lt-02",
    deviceName: "AF-LT-PARALEGAL2",
    hostname: "AF-LT-PARALEGAL2",
    openedAt: days(2),
  }),
  patchAlert(6, {
    ruleType: "UpdateHeld",
    severity: "Warning",
    title: "1 update Meridian Freight's devices need is on hold",
    details: "KB5099004, held after it failed on 3 devices.",
    organizationId: "o-meridian",
    openedAt: days(1),
    canAcknowledge: false,
  }),
  patchAlert(7, {
    ruleType: "RestartPending",
    severity: "Info",
    title: "BA-CAD-01 has waited 8 days for a restart",
    organizationId: "o-bright",
    deviceId: "d-ba-cad01",
    deviceName: "BA-CAD-01",
    hostname: "BA-CAD-01",
    openedAt: days(1),
  }),
  patchAlert(8, {
    ruleType: "SecurityUpdateMissing",
    severity: "Warning",
    title: "HDG-FRONTDESK-2 misses 2 security updates required for 14 days",
    organizationId: "o-harbor",
    hostname: "HDG-FRONTDESK-2",
    openedAt: days(3),
  }),
];

export const patchAlertCounts: PatchAlertCounts = {
  open: patchAlerts.filter((a) => a.status === "Open").length,
  acknowledged: patchAlerts.filter((a) => a.status === "Acknowledged").length,
  critical: patchAlerts.filter((a) => a.severity === "Critical").length,
  warning: patchAlerts.filter((a) => a.severity === "Warning").length,
  info: patchAlerts.filter((a) => a.severity === "Info").length,
  capped: false,
};
