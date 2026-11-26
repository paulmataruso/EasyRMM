import type { ComponentType } from "react";
import type { Device, DeviceRoles, Permission } from "../../../api/types";
import { SecurityTab } from "./SecurityTab";

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
  if (!can(tab.permission) || !roles?.known) return "absent";
  const role = roles.roles.find((r) => r.module === tab.module);
  if (!role) return "absent";
  return role.enabled ? "shown" : "off";
}
