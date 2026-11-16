import type { Device, Inventory, SoftwareAction, SoftwareManager, SoftwareVerb } from "../../api/types";

export const DEFAULT_SOFTWARE_TIMEOUT = 3600;

export interface ManagerInfo {
  label: string;
  platform: "windows" | "linux";
  /** What the package field holds, with an example. */
  hint: string;
  example: string;
  /** The names the server accepts (ADR-0028): never a leading dash, never a space or shell character. */
  pattern: RegExp;
}

export const MANAGERS: Record<SoftwareManager, ManagerInfo> = {
  winget: {
    label: "winget",
    platform: "windows",
    hint: "The package ID, as winget search shows it. Installs come from the winget source, for every user of the device.",
    example: "Mozilla.Firefox",
    pattern: /^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$/,
  },
  chocolatey: {
    label: "Chocolatey",
    platform: "windows",
    hint: "The package ID from the Chocolatey community repository or your own feed. Chocolatey must already be on the device.",
    example: "7zip",
    pattern: /^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$/,
  },
  system: {
    label: "Linux package manager",
    platform: "linux",
    hint: "The package's name in the distribution's repositories. The device's own apt-get, dnf, yum or zypper installs it.",
    example: "jq",
    pattern: /^[A-Za-z0-9][A-Za-z0-9._+:-]{0,127}$/,
  },
};

export const MANAGER_ORDER: SoftwareManager[] = ["winget", "chocolatey", "system"];

export const VERSION_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._+~:-]{0,63}$/;

export const VERBS: Record<SoftwareVerb, string> = { install: "Install", upgrade: "Update", uninstall: "Uninstall" };

/** The managers that work on a platform. */
export function managersFor(platform: string): SoftwareManager[] {
  return MANAGER_ORDER.filter((m) => MANAGERS[m].platform === platform);
}

/** "Install jq 1.7", like the server names the job. */
export function actionLabel(a: SoftwareAction): string {
  return [VERBS[a.action], a.package, a.version].filter(Boolean).join(" ");
}

/**
 * Whether a device's inventory names packages the way its package manager
 * does, so a row can be updated or removed by name. Windows' installed
 * programs are display names, not winget or Chocolatey IDs; apk and pacman
 * are not managed.
 */
export function rowsAreManaged(inventory: Pick<Inventory, "packageManager">, device: Pick<Device, "platform">): boolean {
  return device.platform === "linux" && (inventory.packageManager === "dpkg" || inventory.packageManager === "rpm");
}
