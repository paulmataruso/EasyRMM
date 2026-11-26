// Words and rules for hardening Windows computers and servers (ADR-0054, W3), shared by the device's Hardening tab and
// the fleet views of organizations, sites and groups. What is checked, the tiers and the settings come from the
// server's catalog; these are the names and the sentences a person reads beside them.
import type { HardeningGuard, HardeningSettingState, HardeningState, WindowsHardeningSwitch } from "../../api/types";
import type { Tone } from "../../components/ui";

export interface WindowsModuleInfo {
  id: string;
  name: string;
  /** What applying it does, in a sentence. */
  does: string;
  /** What applying it can break; absent where it breaks nothing current. */
  risk?: string;
  /** Options without a value, each with what it does. */
  options?: { field: WindowsHardeningSwitch; label: string }[];
}

/** Every module, in the order the script runs them (jobs.WindowsHardeningModules on the server). */
export const WINDOWS_MODULES: WindowsModuleInfo[] = [
  {
    id: "accounts",
    name: "Accounts",
    does: "Password length and history, account lockout, the Guest account off, no reversible encryption.",
    risk: "Lockout can lock a person out; on a computer failed sign-ins reach from the internet it is left unset without the option.",
    options: [{ field: "lockoutExposed", label: "Set the lockout even though failed sign-ins from public addresses were seen" }],
  },
  {
    id: "firewall",
    name: "Windows Firewall",
    does: "The domain, private and public profiles on, inbound connections blocked unless a rule allows them.",
    risk: "Can cut off remote access if a needed port is not allowed. Needs the computer's name typed and a second factor.",
    options: [
      { field: "portsChecked", label: "I checked which ports the computer needs open" },
      { field: "firewallServer", label: "Apply to this server too" },
    ],
  },
  {
    id: "defender",
    name: "Microsoft Defender",
    does: "Antivirus settings written as policy: cloud protection, PUA blocking, network protection and SmartScreen that warns.",
    risk: "Technicians can no longer switch these in Windows Security.",
    options: [
      { field: "defenderServerRealtime", label: "Turn real-time protection on for a server" },
      { field: "smartScreenBlock", label: "SmartScreen blocks instead of warns" },
      { field: "cloudBlockHigh", label: "Cloud protection level high" },
    ],
  },
  { id: "asr", name: "Attack surface reduction", does: "Most rules in audit mode, a few blocking.", risk: "A blocking rule can stop a program from starting." },
  { id: "smb", name: "SMB 1", does: "SMBv1 off for the server and the client, and the optional feature removed (a restart).", risk: "Old devices that only speak SMB 1 stop connecting." },
  {
    id: "smb-signing",
    name: "SMB signing",
    does: "SMB signing required by the client and the server; guest access off.",
    risk: "Scanners that save to a share and NAS boxes that cannot sign stop connecting.",
  },
  { id: "ntlm", name: "NTLM", does: "NTLMv1 and LM off, NTLMv2 only.", risk: "Old devices and applications that only speak NTLMv1 stop signing in." },
  { id: "wdigest", name: "WDigest", does: "Passwords are not kept in memory for WDigest." },
  {
    id: "lsa-protection",
    name: "LSA protection",
    does: "The local security authority runs as a protected process.",
    risk: "A driver or plug-in that loads into it and is not signed stops loading.",
    options: [
      { field: "lsaUefiLock", label: "Lock it in UEFI (cannot be undone remotely)" },
      { field: "lsaUnaudited", label: "Apply without waiting for the audit period" },
    ],
  },
  { id: "name-resolution", name: "Name resolution", does: "LLMNR off; NetBIOS ignores name release requests.", risk: "On networks without DNS for local devices, names only LLMNR found stop resolving." },
  { id: "powershell", name: "PowerShell", does: "Windows PowerShell 2.0 removed where it is still installed.", risk: "Tools that start powershell -Version 2 stop working." },
  { id: "rdp", name: "Remote Desktop", does: "Network level authentication required, an encrypted connection and a time limit on idle sessions.", risk: "A client that cannot do network level authentication cannot connect." },
  {
    id: "uac",
    name: "User Account Control",
    does: "The prompt on, administrators asked for consent on the secure desktop.",
    risk: "Remote support that must answer a prompt can be stopped by it.",
    options: [
      { field: "uacEnable", label: "Turn UAC on where it is off" },
      { field: "uacBuiltinAdmin", label: "Filter the built-in Administrator over the network" },
      { field: "denyUserElevation", label: "Standard users are not offered elevation" },
    ],
  },
  { id: "autoplay", name: "AutoPlay", does: "AutoPlay off for all drives, no AutoRun commands.", risk: "CDs and USB drives no longer start anything by themselves." },
  { id: "anonymous", name: "Anonymous access", does: "No anonymous enumeration of accounts or shares, no anonymous name translation.", risk: "Very old clients that browse shares anonymously stop seeing them." },
  {
    id: "winrm",
    name: "WinRM",
    does: "No Basic authentication, no unencrypted traffic, no stored RunAs credentials.",
    options: [{ field: "winrmBasicOff", label: "Turn Basic authentication off where it was turned on" }],
  },
  {
    id: "printing",
    name: "Printing",
    does: "Only administrators install print drivers; drivers never downloaded over HTTP; the spooler off on domain controllers.",
    options: [
      { field: "spoolerOff", label: "Turn the spooler off on this server" },
      { field: "domainController", label: "This is a domain controller" },
    ],
  },
  { id: "features", name: "Legacy features", does: "The Telnet and TFTP clients and Simple TCP/IP Services removed where installed.", risk: "Someone using the Telnet client to test ports loses it." },
  { id: "tls", name: "TLS", does: "SSL 2.0 and 3.0 and TLS 1.0 and 1.1 off for clients and servers (a restart).", risk: "Older SQL Server clients and old browsers stop connecting." },
  { id: "audit", name: "Audit policy", does: "Reports the audit policy against what log collection needs. Changes nothing." },
  { id: "device-guard", name: "Device Guard", does: "Reports virtualization-based security, memory integrity and Credential Guard. Changes nothing." },
  { id: "bitlocker", name: "BitLocker", does: "Reports whether the system volume is protected, and by which protectors. Changes nothing." },
  { id: "laps", name: "Windows LAPS", does: "Reports whether Windows LAPS manages the local administrator's password. Changes nothing." },
];

const BY_ID = new Map(WINDOWS_MODULES.map((m) => [m.id, m]));

/** A module by its ID; an unknown one (from a newer server) keeps its ID. */
export function windowsModule(id: string): WindowsModuleInfo {
  return BY_ID.get(id) ?? { id, name: id, does: "" };
}

export const TIERS: Record<number, { label: string; tone: Tone; title: string }> = {
  0: { label: "Report only", tone: "neutral", title: "EasyRMM reads this and changes nothing." },
  1: { label: "Safe", tone: "ok", title: "Reversible, and breaks nothing current." },
  2: { label: "Can break a workflow", tone: "warn", title: "Can stop something a person or a program uses." },
  3: { label: "Can cut access", tone: "danger", title: "Can lock you out of the computer, or cannot be undone remotely. One computer at a time, its name typed, and a second factor." },
};

export function tierMeta(tier: number) {
  return TIERS[tier] ?? TIERS[2]!;
}

export const SETTING_STATES: Record<HardeningSettingState, { label: string; tone: Tone; title: string }> = {
  in_place: { label: "In place", tone: "ok", title: "The computer has the value EasyRMM wants, or stricter." },
  not_in_place: { label: "Not in place", tone: "warn", title: "Apply would change it." },
  managed_elsewhere: { label: "Managed elsewhere", tone: "info", title: "Group Policy, an MDM or another tool holds this setting, so EasyRMM leaves it alone." },
  check_only: { label: "Check only", tone: "neutral", title: "An owner EasyRMM cannot read may hold this setting, so it is reported and not changed." },
  not_applicable: { label: "Not applicable", tone: "neutral", title: "This setting does not apply to this computer." },
  reported: { label: "Reported", tone: "neutral", title: "EasyRMM never changes this setting." },
  unknown: { label: "Unknown", tone: "neutral", title: "The check could not tell." },
};

export function settingState(s: string) {
  return SETTING_STATES[s as HardeningSettingState] ?? { label: s, tone: "neutral" as Tone, title: "" };
}

/** How a setting stands against its rules (the catalog's cite). */
export const CITE: Record<string, { label: string; title: string }> = {
  meets: { label: "Meets its rules", title: "The value EasyRMM sets meets the setting's rule in the STIGs and baselines it is related to." },
  differs: { label: "Differs on purpose", title: "EasyRMM chooses safety over strictness here, so the value is looser than the rule." },
  not_set: { label: "Reported only", title: "The rule asks for it, EasyRMM leaves it unset unless its option is given." },
};

/** How a change's outcome on a setting reads. */
export const OUTCOMES: Record<string, string> = {
  undone: "Undone",
  partly_undone: "Partly undone",
  nothing_to_undo: "Nothing to undo",
  refused: "Refused",
  not_run: "Not run",
  applied: "Applied",
  unchanged: "Already as wanted",
  skipped: "Skipped",
  failed: "Failed",
  restored: "Put back",
  left: "Left as it was",
};

/** The states that ask for a person's attention. */
export const ATTENTION: HardeningState[] = ["partly", "not_in_place", "half_applied", "failed"];

export function needsAttention(s: HardeningState): boolean {
  return ATTENTION.includes(s);
}

/** Whole minutes and seconds left, "7:42", never negative. */
export function countdown(rollbackAt: string, now: number): string {
  const left = Math.max(0, Math.ceil((Date.parse(rollbackAt) - now) / 1000));
  return `${Math.floor(left / 60)}:${String(left % 60).padStart(2, "0")}`;
}

export const GUARD_STATES: Record<HardeningGuard["state"], { label: string; tone: Tone; title: string }> = {
  armed: { label: "Waiting", tone: "warn", title: "The computer undoes the change by itself unless the agent confirms it." },
  confirmed: { label: "Kept", tone: "ok", title: "The agent confirmed in time, and the change stands." },
  timed_out: { label: "Undone by the computer", tone: "danger", title: "The agent did not confirm in time, so the computer undoes the change. The next check shows whether it did." },
};
