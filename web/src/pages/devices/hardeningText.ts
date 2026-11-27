// Words and rules for hardening Linux computers (ADR-0051), shared by the device's Hardening tab and the Devices list.
import type { HardeningFilter, HardeningPlatform, HardeningState, HardeningSummary } from "../../api/types";
import type { Tone } from "../../components/ui";

export interface ModuleInfo {
  id: string;
  name: string;
  /** What applying it does, in a sentence. */
  does: string;
  /** Recommended modules are preselected; the others are chosen one by one. */
  recommended: boolean;
  /** For the others: what applying it can break. */
  risk?: string;
}

/** Every module, in the order the script runs them (jobs.HardeningModules on the server). */
export const MODULES: ModuleInfo[] = [
  {
    id: "ssh",
    name: "SSH",
    recommended: true,
    does: "PermitRootLogin prohibit-password, no empty passwords, a 30-second sign-in window, no X11 forwarding, and dead connections closed.",
  },
  {
    id: "firewall",
    name: "Firewall",
    recommended: true,
    does: "EasyRMM's own nftables table on incoming traffic only: new connections to ports nothing listens on are dropped. Hosts with a firewall of their own are left alone.",
  },
  { id: "fail2ban", name: "fail2ban", recommended: true, does: "Bans an address for an hour after 5 failed SSH sign-ins in 10 minutes." },
  {
    id: "kernel",
    name: "Kernel parameters",
    recommended: true,
    does: "Network redirects and source routing off, SYN cookies, and restrictions on kernel logs, pointers, ptrace and BPF. Values are only ever tightened.",
  },
  {
    id: "audit",
    name: "Audit rules",
    recommended: true,
    does: "auditd records changes to accounts, sudo, SSH and PAM settings, the time and kernel modules, and commands run with raised privileges.",
  },
  {
    id: "permissions",
    name: "File permissions",
    recommended: true,
    does: "Account files, sshd_config, cron's files and the boot loader's configuration: permission bits are only removed.",
  },
  {
    id: "services",
    name: "Legacy services",
    recommended: true,
    does: "Turns off telnet, rsh, rlogin, rexec, finger, talk and the NIS server where they are installed. TFTP is reported, not turned off.",
  },
  {
    id: "kernel-modules",
    name: "Kernel modules",
    recommended: true,
    does: "Keeps rarely used network protocols (DCCP, SCTP, RDS, TIPC) and filesystems from loading. A module in use is left alone.",
  },
  { id: "sudo", name: "sudo", recommended: true, does: "Commands run in a pseudo-terminal and are logged to /var/log/sudo.log." },
  { id: "time", name: "Time synchronisation", recommended: true, does: "A time synchronisation service running: the one installed, or the distribution's own." },
  {
    id: "shared-memory",
    name: "Shared memory",
    recommended: false,
    does: "/dev/shm mounted nodev, nosuid and noexec.",
    risk: "Programs that run code from shared memory stop working.",
  },
  {
    id: "usb-storage",
    name: "USB storage",
    recommended: false,
    does: "USB mass storage kept from loading. Refused where a mounted disk is on USB.",
    risk: "USB disks and backup drives stop working.",
  },
  {
    id: "mac",
    name: "SELinux or AppArmor",
    recommended: false,
    does: "SELinux from permissive to enforcing; AppArmor profiles in complain mode are listed, not changed.",
    risk: "Enforcing SELinux stops whatever its policy does not allow, which can break a service that ran under permissive.",
  },
  {
    id: "integrity",
    name: "File integrity (AIDE)",
    recommended: false,
    does: "AIDE installed, with a baseline of the system's files checked daily.",
    risk: "Building the baseline and each daily check read the whole filesystem, which loads the disk.",
  },
  {
    id: "lockout",
    name: "Account lockout",
    recommended: false,
    does: "Reports whether failed sign-ins are counted by pam_faillock and lock the account after 10 or fewer. Changes nothing.",
    risk: "It changes nothing: a wrong change to the sign-in stack can lock everyone out, so the person makes it.",
  },
  {
    id: "luks",
    name: "Disk encryption (LUKS)",
    recommended: false,
    does: "Reports whether the root filesystem is on a LUKS volume. Changes nothing.",
    risk: "It changes nothing: encrypting a disk in place can lose data, so the person does it.",
  },
  {
    id: "host-firewall",
    name: "Host firewall",
    recommended: false,
    does: "Reports whether ufw, firewalld or nftables runs, starts at boot and drops incoming traffic by default. Changes nothing.",
    risk: "It changes nothing: a firewall change can cut off remote access, so the person makes it.",
  },
  {
    id: "selinux-apparmor",
    name: "SELinux or AppArmor",
    recommended: false,
    does: "Reports whether SELinux is enforcing or AppArmor is on with profiles loaded. Changes nothing.",
    risk: "It changes nothing: the mac module applies a mode, with its guards.",
  },
  {
    id: "auto-updates",
    name: "Automatic updates",
    recommended: false,
    does: "Reports whether unattended-upgrades or dnf-automatic is installed, scheduled and installing updates. Changes nothing.",
    risk: "It changes nothing: the person installs and schedules it, or uses the EasyPatch connector.",
  },
];

const BY_ID = new Map(MODULES.map((m) => [m.id, m]));

/** A module by its name; an unknown one (from a newer server) keeps its name. */
export function moduleInfo(id: string): ModuleInfo {
  return BY_ID.get(id) ?? { id, name: id, does: "", recommended: false };
}

export const RECOMMENDED = MODULES.filter((m) => m.recommended).map((m) => m.id);

interface StateMeta {
  label: string;
  tone: Tone;
  title: string;
}

const STATES: Record<HardeningState, StateMeta> = {
  in_place: { label: "In place", tone: "ok", title: "Everything this module checks is in place." },
  partly: { label: "Partly in place", tone: "warn", title: "Some of what this module checks is in place; the rest is listed." },
  not_in_place: { label: "Not in place", tone: "warn", title: "None of what this module checks is in place." },
  not_applicable: { label: "Not applicable", tone: "neutral", title: "This module does not apply to this computer; the reason is given." },
  managed_elsewhere: { label: "Managed elsewhere", tone: "info", title: "Something else manages this on the computer, so EasyRMM leaves it alone." },
  not_supported: {
    label: "Not supported on this version",
    tone: "neutral",
    title: "EasyRMM has not tested this module with what this computer runs; it reports what it found but changes nothing.",
  },
  half_applied: {
    label: "Half applied",
    tone: "danger",
    title: "An apply or undo of this module was interrupted before it finished; undo reverses what it recorded.",
  },
  failed: { label: "Failed", tone: "danger", title: "The module could not do its work; the reason is given." },
};

export function stateMeta(state: HardeningState): StateMeta {
  return STATES[state] ?? { label: state, tone: "neutral", title: "" };
}

/** The Devices list's hardening filter. "Needs attention": a module partly or not in place, half applied or failed. */
export const FILTERS: { value: HardeningFilter; label: string }[] = [
  { value: "attention", label: "Needs attention" },
  { value: "in_place", label: "In place" },
  { value: "unchecked", label: "Not checked" },
];

const ORDER: HardeningState[] = ["in_place", "partly", "not_in_place", "half_applied", "failed", "managed_elsewhere", "not_applicable", "not_supported"];

/** A device's hardening in a few words for the Devices list, with the full count in the title. */
export function summarize(s: HardeningSummary): StateMeta {
  const n = (state: HardeningState) => s.states[state] ?? 0;
  const title = ORDER.filter((st) => n(st) > 0)
    .map((st) => `${n(st).toLocaleString()} ${stateMeta(st).label.toLowerCase()}`)
    .join(", ");
  const inPlace = n("in_place");
  const todo = n("partly") + n("not_in_place");
  const applicable = inPlace + todo + n("half_applied") + n("failed");
  if (n("half_applied") > 0) return { label: "Half applied", tone: "danger", title };
  if (n("failed") > 0) return { label: `${n("failed").toLocaleString()} failed`, tone: "danger", title };
  if (applicable === 0) return { label: "Not applicable", tone: "neutral", title };
  return { label: `${inPlace.toLocaleString()} of ${applicable.toLocaleString()} in place`, tone: todo > 0 ? "warn" : "ok", title };
}

const DISTRIBUTIONS: Record<string, string> = {
  debian: "Debian",
  ubuntu: "Ubuntu",
  rocky: "Rocky Linux",
  almalinux: "AlmaLinux",
  rhel: "Red Hat Enterprise Linux",
  centos: "CentOS",
  fedora: "Fedora",
  ol: "Oracle Linux",
};

/** "Debian 12", from os-release's ID and VERSION_ID. */
export function distributionName(p: Pick<HardeningPlatform, "id" | "versionId">): string {
  const name = DISTRIBUTIONS[p.id] ?? (p.id || "An unknown distribution");
  return p.versionId ? `${name} ${p.versionId}` : name;
}

export const SUPPORT: Record<HardeningPlatform["support"], StateMeta> = {
  full: { label: "Tested", tone: "ok", title: "EasyRMM's hardening is tested on this release." },
  check_only: {
    label: "Check only",
    tone: "warn",
    title:
      "Not supported on this version: apply and undo are not tested on this release (one EasyRMM's machine tests do not cover, or newer than those they do), or it is out of its standard support (Debian 11, Ubuntu 20.04) and needs upgrading first. Checks report on it; no module is applied or undone here.",
  },
  unsupported: {
    label: "Not supported",
    tone: "neutral",
    title: "EasyRMM's hardening is not tested on this distribution or release. Checks report what they can; no module is applied or undone here.",
  },
};

/** The script tells these containers apart; any other is "other". */
const CONTAINERS: Record<string, string> = { lxc: "LXC", docker: "Docker", podman: "Podman" };

/** The container the script ran in ("LXC container"), or null on a whole computer. */
export function containerName(container: string): string | null {
  if (container === "none" || container === "") return null;
  const kind = CONTAINERS[container];
  return kind ? `${kind} container` : "A container";
}
