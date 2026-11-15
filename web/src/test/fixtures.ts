// Fictional records shaped like the API's JSON, for page tests.

import type { AuditEntry, Device, DeviceGroup, Organization, RoleView, SessionItem, Site, User } from "../api/types";

const T = "2026-11-01T10:00:00Z";

export function org(id: string, name: string, extra: Partial<Organization> = {}): Organization {
  return { id, name, notes: "", siteCount: 0, canManage: true, createdAt: T, updatedAt: T, ...extra };
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
    remoteAgent: true,
    remoteOnline: true,
    lastSeenAt: T,
    createdAt: T,
    updatedAt: T,
    canDesktop: true,
    canTerminal: true,
    canFiles: true,
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
