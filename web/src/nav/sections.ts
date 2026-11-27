import type { Permission } from "../api/types";
import { deviceKey, groupKey, orgKey, siteKey } from "./tree";

/**
 * The console's sections. On a section's pages the sidebar shows that section's own navigation (ADR-0021): a tree of
 * organizations, sites, device groups and devices that narrows the section's list (ADR-0069), or, for settings, its
 * parts.
 */
export type SectionId = "organizations" | "devices" | "alerts" | "scripts" | "jobs" | "patching" | "quickassist" | "settings";

/** The permission that shows a section in the main menu, and its navigation. */
export const SECTION_PERMISSION: Record<Exclude<SectionId, "organizations" | "settings">, Permission> = {
  devices: "device.view",
  alerts: "alert.view",
  scripts: "script.view",
  jobs: "job.view",
  patching: "patch.view",
  quickassist: "quickassist.view",
};

export function sectionFor(pathname: string): SectionId | null {
  const under = (base: string) => pathname === base || pathname.startsWith(`${base}/`);
  if (under("/organizations") || under("/sites") || under("/groups")) return "organizations";
  if (under("/devices")) return "devices";
  if (under("/alerts")) return "alerts";
  if (under("/scripts") || under("/scheduled")) return "scripts";
  if (under("/jobs")) return "jobs";
  if (under("/patching")) return "patching";
  if (under("/quickassist")) return "quickassist";
  if (under("/settings") || under("/users")) return "settings";
  return null;
}

/** Where a tree row leads. */
export type Target =
  | { kind: "all" }
  | { kind: "shared" }
  | { kind: "approvals" }
  | { kind: "org"; id: string }
  | { kind: "site"; id: string; organizationId: string }
  | { kind: "group"; id: string; organizationId: string; siteId: string }
  | { kind: "device"; id: string; organizationId: string; siteId: string; groupId?: string | null };

/** The section's list page, which its tree narrows. */
const LIST: Partial<Record<SectionId, string>> = {
  devices: "/devices",
  alerts: "/alerts",
  scripts: "/scripts",
  jobs: "/jobs",
  patching: "/patching",
};

const one = (re: RegExp, pathname: string) => {
  const m = re.exec(pathname);
  return m?.[1] ? decodeURIComponent(m[1]) : null;
};

/** The row the page is about: "all", "shared", a node key, or null when no row is. */
export function selectedKey(section: SectionId, pathname: string, search: string): string | null {
  const p = new URLSearchParams(search);
  const scope = () => {
    const device = p.get("deviceId");
    const group = p.get("groupId");
    const site = p.get("siteId");
    const org = p.get("organizationId");
    return device ? deviceKey(device) : group ? groupKey(group) : site ? siteKey(site) : org ? orgKey(org) : "all";
  };
  switch (section) {
    case "organizations": {
      if (pathname === "/organizations") return "all";
      const org = one(/^\/organizations\/([^/]+)$/, pathname);
      if (org) return orgKey(org);
      const group = one(/^\/groups\/([^/]+)$/, pathname);
      if (group) return groupKey(group);
      const site = one(/^\/sites\/([^/]+)$/, pathname);
      return site ? siteKey(site) : null;
    }
    case "devices": {
      if (pathname === "/devices") return scope();
      if (pathname === "/devices/approvals") return "approvals";
      const device = one(/^\/devices\/([^/]+)$/, pathname);
      return device && device !== "add" ? deviceKey(device) : null;
    }
    case "alerts":
      if (pathname !== "/alerts") return null;
      // Policies are scoped by organization only.
      if (p.get("tab") === "policies") return p.get("organizationId") ? orgKey(p.get("organizationId")!) : null;
      return scope();
    case "scripts": {
      if (pathname !== "/scripts") return null;
      const library = p.get("library");
      const site = p.get("siteId");
      if (library === "shared") return "shared";
      if (p.get("deviceId")) return deviceKey(p.get("deviceId")!);
      if (p.get("groupId")) return groupKey(p.get("groupId")!);
      if (site) return siteKey(site);
      return library ? orgKey(library) : "all";
    }
    case "jobs":
      return pathname === "/jobs" ? scope() : null;
    case "patching":
      if (pathname === "/patching") return scope();
      // A device's own patching page (ADR-0072).
      {
        const device = one(/^\/patching\/devices\/([^/]+)$/, pathname);
        return device ? deviceKey(device) : null;
      }
    case "quickassist":
    case "settings":
      return null;
  }
}

/**
 * Where a row leads. On the section's list page a row changes only the list's scope, keeping its other filters
 * (status, severity, search); from any other page of the section it opens the list with that scope.
 */
export function targetHref(section: SectionId, target: Target, pathname: string, search: string): string {
  if (section === "organizations") {
    if (target.kind === "org") return `/organizations/${encodeURIComponent(target.id)}`;
    if (target.kind === "site") return `/sites/${encodeURIComponent(target.id)}`;
    if (target.kind === "group") return `/groups/${encodeURIComponent(target.id)}`;
    // A device's own page is its part of this view.
    if (target.kind === "device") return `/devices/${encodeURIComponent(target.id)}`;
    return "/organizations";
  }
  if (section === "devices" && target.kind === "device") return `/devices/${encodeURIComponent(target.id)}`;
  // In Patching a device has its own page, in the Patching section (ADR-0072).
  if (section === "patching" && target.kind === "device") return `/patching/devices/${encodeURIComponent(target.id)}`;
  if (target.kind === "approvals") return "/devices/approvals";
  const list = LIST[section];
  if (!list) return "/";
  const params = new URLSearchParams(pathname === list ? search : "");
  const set = (values: Record<string, string | null>) => {
    for (const [k, v] of Object.entries(values)) {
      if (v) params.set(k, v);
      else params.delete(k);
    }
  };
  // Paging restarts with a new scope.
  set({ before: null, after: null, ...(section === "patching" ? { page: null } : {}) });
  if (section === "scripts") {
    const none = { groupId: null, deviceId: null };
    if (target.kind === "shared") set({ library: "shared", siteId: null, ...none });
    else if (target.kind === "org") set({ library: target.id, siteId: null, ...none });
    else if (target.kind === "site") set({ library: target.organizationId, siteId: target.id, ...none });
    // The scripts that run on a group's or a device's computers are those of its organization and its site.
    else if (target.kind === "group") set({ library: target.organizationId, siteId: null, groupId: target.id, deviceId: null });
    else if (target.kind === "device") set({ library: target.organizationId, siteId: null, groupId: null, deviceId: target.id });
    else set({ library: null, siteId: null, ...none });
  } else {
    const scope =
      target.kind === "org"
        ? { organizationId: target.id, siteId: null, groupId: null, deviceId: null }
        : target.kind === "site"
          ? { organizationId: target.organizationId, siteId: target.id, groupId: null, deviceId: null }
          : target.kind === "group"
            ? { organizationId: target.organizationId, siteId: target.siteId, groupId: target.id, deviceId: null }
            : target.kind === "device"
              ? { organizationId: target.organizationId, siteId: target.siteId, groupId: target.groupId ?? null, deviceId: target.id }
              : { organizationId: null, siteId: null, groupId: null, deviceId: null };
    set(scope);
    // Alert policies can be narrowed to an organization; anything else shows the alerts themselves.
    if (section === "alerts" && target.kind !== "org") set({ tab: null });
  }
  const qs = params.toString();
  return qs ? `${list}?${qs}` : list;
}
