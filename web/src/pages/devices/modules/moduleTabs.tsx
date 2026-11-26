import type { ComponentType } from "react";
import type { Device, DeviceRoles, Permission } from "../../../api/types";
import { BackupTab } from "../backup/BackupTab";
import { SecurityTab } from "./SecurityTab";
import { RolesTab } from "./roles/RolesTab";
import { ROLE_VIEWS } from "./roles/registry";

// The Windows management modules' tabs on the device page (ADR-0073, section 7). A module is one line in
// DEVICE_MODULE_TABS. What a tab does with the device's roles and the module's toggle is `moduleTabState`, one rule
// for every module: absent, off, or shown.

export interface DeviceModuleTab {
  id: string;
  label: string;
  /** The module, as `Catalog` names it on the server. */
  module: string;
  permission: Permission;
  component: ComponentType<{ device: Device }>;
  /** A tab with a view per module (the Roles tab, ADR-0076): shown when any of them is, with the view's own rule. */
  views?: readonly { module: string; permission: Permission }[];
}

/** The registry. A later module (ADR-0075 to 0077) adds one line here and one file beside this one. */
export const DEVICE_MODULE_TABS: readonly DeviceModuleTab[] = [
  {
    id: "security",
    label: "Security",
    module: "defender",
    permission: "defender.view",
    component: SecurityTab,
  },
  // Server roles (ADR-0076): one tab, a view per role; a role adds its line to roles/registry.ts, not here.
  {
    id: "roles",
    label: "Roles",
    module: "roles",
    permission: "dns.view",
    views: ROLE_VIEWS,
    component: RolesTab,
  },
  {
    id: "backup",
    label: "Backup",
    module: "windows_backup",
    permission: "backup.view",
    component: BackupTab,
  },
];

/**
 * - `shown`: the role is detected, the module is on for the site and the viewer holds the permission.
 * - `off`: the same, but the module is off for the site. The tab is hidden; its URL shows the "module off" page.
 * - `absent`: no role, no permission or no report yet. Nothing is shown and the URL falls back to Overview, so the
 *   page confirms nothing about the device's roles (the server answers 404 in the same case).
 */
export type ModuleTabState = "shown" | "off" | "absent";

export function moduleTabState(
  tab: DeviceModuleTab,
  roles: DeviceRoles | undefined,
  can: (p: Permission) => boolean,
): ModuleTabState {
  if (!roles?.known) return "absent";
  const states = (tab.views ?? [{ module: tab.module, permission: tab.permission }]).map((v): ModuleTabState => {
    const role = can(v.permission) ? roles.roles.find((r) => r.module === v.module) : undefined;
    return !role ? "absent" : role.enabled ? "shown" : "off";
  });
  return states.includes("shown") ? "shown" : states.includes("off") ? "off" : "absent";
}
