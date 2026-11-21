// Fictional records shaped like the API's JSON, for page tests.

import type {
  AlertEntry,
  AlertPolicy,
  AuditEntry,
  Device,
  DeviceGroup,
  DeviceMetrics,
  Inventory,
  Job,
  JobRun,
  MetricSample,
  MetricsHistory,
  Organization,
  RoleView,
  RunStatus,
  Script,
  SessionItem,
  Site,
  User,
} from "../api/types";

const T = "2026-11-01T10:00:00Z";

export function org(id: string, name: string, extra: Partial<Organization> = {}): Organization {
  return { id, name, timezone: "UTC", notes: "", siteCount: 0, canManage: true, canRename: true, createdAt: T, updatedAt: T, ...extra };
}

export function site(id: string, organizationId: string, name: string, extra: Partial<Site> = {}): Site {
  return {
    id,
    organizationId,
    organizationName: "Northwind Traders",
    name,
    timezone: "Europe/London",
    address: "",
    notes: "",
    deviceGroupCount: 0,
    canManage: true,
    createdAt: T,
    updatedAt: T,
    ...extra,
  };
}

export function group(id: string, siteId: string, name: string, extra: Partial<DeviceGroup> = {}): DeviceGroup {
  return { id, organizationId: "o1", siteId, name, description: "", createdAt: T, updatedAt: T, ...extra };
}

export function device(id: string, name: string, extra: Partial<Device> = {}): Device {
  return {
    id,
    organizationId: "o1",
    organizationName: "Northwind Traders",
    siteId: "s1",
    siteName: "Head office",
    deviceGroupId: null,
    name,
    hostname: name.toLowerCase(),
    osDescription: "Windows 11 Pro, version 24H2",
    platform: "windows",
    online: extra.online ?? extra.remoteOnline ?? true,
    agent: null,
    remoteAgent: true,
    remoteOnline: true,
    lastSeenAt: T,
    createdAt: T,
    updatedAt: T,
    canDesktop: true,
    canTerminal: true,
    canFiles: true,
    canRunScripts: false,
    canUpdateAgent: false,
    canManageSoftware: false,
    canRemove: false,
    removal: null,
    ...extra,
  };
}

export function person(id: string, displayName: string, email: string, extra: Partial<User> = {}): User {
  return {
    id,
    email,
    displayName,
    status: "active",
    mfaEnabled: true,
    passwordSet: true,
    locked: false,
    lastLoginAt: T,
    createdAt: T,
    assignments: [],
    hiddenAssignments: 0,
    canManage: true,
    isSelf: false,
    ...extra,
  };
}

export function auditEntry(id: number, action: string, extra: Partial<AuditEntry> = {}): AuditEntry {
  return {
    id,
    occurredAt: T,
    actorType: "user",
    actorId: "u-alex",
    actorLabel: "alex@example.com",
    action,
    targetType: "organization",
    targetId: "o1",
    outcome: "success",
    sourceIp: "203.0.113.10",
    userAgent: "Mozilla/5.0",
    details: null,
    ...extra,
  };
}

export function sessionItem(id: string, extra: Partial<SessionItem> = {}): SessionItem {
  return {
    id,
    state: "active",
    createdAt: T,
    lastSeenAt: T,
    expiresAt: "2030-01-01T00:00:00Z",
    idleExpiresAt: "2030-01-01T00:00:00Z",
    sourceIp: "203.0.113.10",
    userAgent: "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0 Safari/537.36",
    current: false,
    ...extra,
  };
}

export const ROLES: RoleView[] = [
  { role: "super_admin", name: "Super Administrator", description: "Everything.", rank: 100, scopes: ["global"], permissions: [] },
  { role: "org_admin", name: "Organization Administrator", description: "Runs one organization.", rank: 80, scopes: ["organization"], permissions: [] },
  { role: "technician", name: "Technician", description: "Supports devices.", rank: 40, scopes: ["organization", "site"], permissions: [] },
  { role: "read_only", name: "Read-Only", description: "Views only.", rank: 10, scopes: ["organization", "site"], permissions: [] },
];

export function script(id: string, name: string, extra: Partial<Script> = {}): Script {
  return {
    id,
    level: "shared",
    organizationId: null,
    siteId: null,
    name,
    description: "",
    shell: "bash",
    sha256: "a".repeat(64),
    size: 120,
    timeoutSeconds: 300,
    createdAt: T,
    updatedAt: T,
    canEdit: true,
    canRun: true,
    ...extra,
  };
}

const NO_COUNTS: Record<RunStatus, number> = { queued: 0, sent: 0, running: 0, succeeded: 0, failed: 0, timed_out: 0, canceled: 0, expired: 0, lost: 0 };

export function counts(c: Partial<Record<RunStatus, number>>): Record<RunStatus, number> {
  return { ...NO_COUNTS, ...c };
}

export function jobRun(id: string, deviceId: string, deviceName: string, status: RunStatus, extra: Partial<JobRun> = {}): JobRun {
  const finished = !["queued", "sent", "running"].includes(status);
  return {
    id,
    jobId: "j1",
    deviceId,
    deviceName,
    organizationId: "o1",
    organizationName: "Northwind Traders",
    siteId: "s1",
    siteName: "Head office",
    scriptName: "Disk usage",
    status,
    createdAt: T,
    expiresAt: "2026-11-02T10:00:00Z",
    sentAt: status === "queued" ? null : "2026-11-01T10:00:01Z",
    deliveries: status === "queued" ? 0 : 1,
    startedAt: ["queued", "sent", "expired"].includes(status) ? null : "2026-11-01T10:00:02Z",
    finishedAt: finished ? "2026-11-01T10:01:07Z" : null,
    exitCode: status === "succeeded" ? 0 : status === "failed" ? 2 : null,
    error: "",
    stdoutTruncated: false,
    stderrTruncated: false,
    cancelRequested: false,
    canCancel: !finished,
    ...extra,
  };
}

export function job(id: string, scriptName: string, extra: Partial<Job> = {}): Job {
  return {
    id,
    kind: "script",
    software: null,
    scriptId: "sc1",
    scriptName,
    shell: "bash",
    sha256: "a".repeat(64),
    args: [],
    timeoutSeconds: 300,
    expiresAt: "2026-11-02T10:00:00Z",
    createdBy: "alex@example.com",
    createdAt: T,
    counts: counts({ succeeded: 1 }),
    total: 1,
    finished: true,
    canCancel: true,
    ...extra,
  };
}

const GiB = 1024 ** 3;

/** A Debian server's inventory, as an agent reports it. */
export function inventory(extra: Partial<Inventory> = {}): Inventory {
  return {
    system: {
      manufacturer: "Dell Inc.",
      model: "PowerEdge R650",
      serial: "7XK2LM3",
      biosVendor: "Dell Inc.",
      biosVersion: "1.13.2",
      biosDate: "2024-03-14",
      virtualization: "",
    },
    cpu: { model: "Intel(R) Xeon(R) Silver 4314 CPU @ 2.40GHz", sockets: 2, cores: 32, threads: 64 },
    memoryBytes: 128 * GiB,
    os: { name: "Debian GNU/Linux 13 (trixie)", id: "debian", version: "13", kernel: "6.12.38+deb13-amd64", timezone: "Europe/London" },
    disks: [
      { name: "nvme0n1", model: "Samsung PM9A3", serial: "S64GNE0R1234", sizeBytes: 960 * 1000 ** 3, kind: "nvme", removable: false },
      { name: "sdb", model: "Ultra Fit", serial: "", sizeBytes: 64 * 1000 ** 3, kind: "hdd", removable: true },
    ],
    interfaces: [
      { name: "eno1", mac: "b0:7b:25:01:02:03", addresses: ["192.0.2.20/24", "2001:db8::20/64"], up: true, speedMbps: 10000 },
      { name: "eno2", mac: "b0:7b:25:01:02:04", addresses: [], up: false, speedMbps: 0 },
    ],
    gateways: ["192.0.2.1"],
    dnsServers: ["192.0.2.53", "2001:db8::53"],
    packageManager: "dpkg",
    packageCount: 3,
    receivedAt: T,
    ...extra,
  };
}

/** The latest measurements of a busy server whose /var is nearly full. */
export function metrics(extra: Partial<DeviceMetrics> = {}): DeviceMetrics {
  return {
    at: T,
    cpuPercent: 37.5,
    memoryTotal: 128 * GiB,
    memoryUsed: 104 * GiB,
    swapTotal: 8 * GiB,
    swapUsed: 0,
    load1: 4.25,
    load5: 3.5,
    load15: 2.75,
    uptimeSeconds: 3 * 86_400 + 4 * 3_600,
    processes: 412,
    filesystems: [
      { mount: "/", device: "/dev/nvme0n1p2", type: "ext4", totalBytes: 100 * GiB, usedBytes: 40 * GiB },
      { mount: "/var", device: "/dev/nvme0n1p3", type: "xfs", totalBytes: 400 * GiB, usedBytes: 372 * GiB },
    ],
    ...extra,
  };
}

/** A day of samples every five minutes, ending at the fixtures' time. */
export function history(points = 3, extra: Partial<MetricsHistory> = {}): MetricsHistory {
  const end = new Date(T).getTime();
  const samples: MetricSample[] = Array.from({ length: points }, (_, i) => ({
    at: new Date(end - (points - 1 - i) * 300_000).toISOString(),
    cpuPercent: 20 + i * 10,
    memoryPercent: 80,
    swapPercent: 0,
    diskPercent: 93,
    load1: 1,
  }));
  return { range: "24h", bucketSeconds: 300, from: new Date(end - 86_400_000).toISOString(), to: T, samples, ...extra };
}

export function alertPolicy(id: string, name: string, extra: Partial<AlertPolicy> = {}): AlertPolicy {
  return {
    id,
    level: "shared",
    organizationId: null,
    siteId: null,
    name,
    description: "",
    kind: "cpu",
    threshold: 95,
    minutes: 15,
    severity: "warning",
    enabled: true,
    activeAlerts: 0,
    createdAt: T,
    updatedAt: T,
    canEdit: true,
    ...extra,
  };
}

export function alertEntry(id: string, name: string, extra: Partial<AlertEntry> = {}): AlertEntry {
  return {
    id,
    policyId: "p1",
    deviceId: "d1",
    deviceName: "DB-01",
    organizationId: "o1",
    organizationName: "Northwind Traders",
    siteId: "s1",
    siteName: "Head office",
    name,
    kind: "disk",
    threshold: 90,
    minutes: 5,
    severity: "critical",
    status: "open",
    value: 93,
    lastValue: 94.4,
    openedAt: T,
    acknowledgedAt: null,
    resolvedAt: null,
    canManage: true,
    ...extra,
  };
}
