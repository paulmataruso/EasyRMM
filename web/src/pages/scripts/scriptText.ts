// Words and numbers for scripts, jobs and runs (ADR-0017), shared by the pages and their tests.
import type { Device, Job, JobRun, PowerShellInstall, RunProgram, RunStatus, Script, ScriptLevel, Shell } from "../../api/types";
import type { Tone } from "../../components/ui";
import { parseDate } from "../../lib/format";

/** Server limits (jobs package). */
export const LIMITS = {
  body: 64 * 1024,
  name: 200,
  description: 2000,
  args: 32,
  argBytes: 1024,
  minTimeout: 1,
  maxTimeout: 4 * 3600,
  defaultTimeout: 300,
  devices: 500,
};

export const SHELLS: Shell[] = ["powershell", "pwsh", "cmd", "bash", "sh", "python3"];

export const SHELL_NAMES: Record<Shell, string> = {
  powershell: "Windows PowerShell 5.1",
  pwsh: "PowerShell 7",
  cmd: "Command Prompt (cmd)",
  bash: "Bash",
  sh: "POSIX sh",
  python3: "Python 3",
};

/** The platform each shell runs on (agentproto.ShellPlatforms). */
export const SHELL_PLATFORM: Record<Shell, "windows" | "linux"> = {
  powershell: "windows",
  pwsh: "windows",
  cmd: "windows",
  bash: "linux",
  sh: "linux",
  python3: "linux",
};

export const PLATFORM_NAMES: Record<string, string> = { windows: "Windows", linux: "Linux" };

export const LEVEL_NAMES: Record<ScriptLevel, string> = {
  shared: "Shared",
  organization: "Organization",
  site: "Site",
};

/** Where a script can run, in a few words: "All organizations", "Acme" or "Acme / HQ". */
export function scriptScope(s: Pick<Script, "level" | "organizationName" | "siteName">): string {
  if (s.level === "shared") return "All organizations";
  if (s.level === "organization") return s.organizationName ?? "Organization";
  return `${s.organizationName ?? "Organization"} / ${s.siteName ?? "Site"}`;
}

/** Whether a script may run on a device: its level covers the device's organization or site. */
export function scriptCovers(s: Pick<Script, "level" | "organizationId" | "siteId">, d: Pick<Device, "organizationId" | "siteId">): boolean {
  if (s.level === "shared") return true;
  if (s.level === "organization") return s.organizationId === d.organizationId;
  return s.siteId === d.siteId;
}

/** Why a device cannot run scripts (in the given shell), or null when it can. */
export function cannotRunReason(d: Pick<Device, "canRunScripts" | "agent" | "platform">, shell?: Shell): string | null {
  if (!d.agent) return "The device has no EasyRMM agent.";
  if (!d.canRunScripts) return "Your role does not run scripts here.";
  if (d.platform !== "windows" && d.platform !== "linux") return "Scripts run on Windows and Linux devices.";
  if (shell && SHELL_PLATFORM[shell] !== d.platform) return `${SHELL_NAMES[shell]} scripts run on ${PLATFORM_NAMES[SHELL_PLATFORM[shell]]} devices.`;
  // The agent's polls say whether its build runs PowerShell 7 scripts (ADR-0064); the server refuses the job otherwise.
  if (shell === "pwsh") {
    if (d.agent.accepts === null) {
      return "The device's agent has not yet said whether it can run PowerShell 7 scripts; try again in a minute, and update the agent if it still has not.";
    }
    if (!d.agent.accepts.includes(CAP_PWSH)) return "The device's agent cannot run PowerShell 7 scripts; update the agent.";
  }
  return null;
}

/** The job capability an agent's polls list when its build runs PowerShell 7 scripts (agentproto.CapJobPwsh). */
export const CAP_PWSH = "job.pwsh";

/**
 * The run dialog's warning for a PowerShell 7 script: how many of the chosen devices reported no usable PowerShell 7 at
 * their last inventory, and what the script does there. Null when it does not apply. The server does not refuse these
 * devices: the inventory can be an hour old, and the agent decides when the run starts.
 */
export function pwshWarning(s: Pick<Script, "shell" | "pwshFallback">, devices: Pick<Device, "agent">[]): string | null {
  if (s.shell !== "pwsh") return null;
  const without = devices.filter((d) => d.agent?.powerShell7 === false);
  const blocked = without.filter((d) => d.agent?.powerShell7Blocked);
  const missing = without.length - blocked.length;
  const what = s.pwshFallback ? "this script runs in Windows PowerShell 5.1 there" : "this script fails there";
  if (devices.length === 1) {
    const why = blocked[0]?.agent?.powerShell7Blocked;
    if (why) return `PowerShell 7 was found at the device's last inventory, not usable: ${why} This script fails there.`;
    return missing ? `The device reported no usable PowerShell 7 at its last inventory; ${what}.` : null;
  }
  const parts: string[] = [];
  if (missing) parts.push(`${missing} of ${devices.length} devices reported no usable PowerShell 7 at their last inventory; ${what}.`);
  if (blocked.length) {
    parts.push(
      `${blocked.length} of ${devices.length} devices have PowerShell 7 found, not usable: its module folders or configuration fail the agent's check, ` +
        `so this script fails there${s.pwshFallback ? " without running in Windows PowerShell 5.1" : ""}. Their Hardware tab says why.`,
    );
  }
  return parts.length ? parts.join(" ") : null;
}

/** What a PowerShell 7 script does where no usable PowerShell 7 is found. */
export function fallbackText(pwshFallback: boolean): string {
  return pwshFallback ? "Runs in Windows PowerShell 5.1" : "Fails the run";
}

const ARCH_NAMES: Record<string, string> = { x64: "64-bit", arm64: "ARM64", x86: "32-bit" };

function withArch(name: string, arch?: string): string {
  return arch ? `${name}, ${ARCH_NAMES[arch] ?? arch}` : name;
}

export const NOT_REPORTED = "Not reported by this agent's version";

/**
 * The program a run started, as its agent reported it (ADR-0064): "PowerShell 7.6.10, 64-bit", "Windows PowerShell
 * 5.1.26100.7019, 64-bit", or the program's file name for cmd and the Linux shells. NOT_REPORTED for a run that ended
 * with an exit code from an agent that reports none; null for a run that never started a program.
 */
export function programText(r: Pick<JobRun, "program" | "exitCode">): string | null {
  const p = r.program;
  if (!p) return r.exitCode === null ? null : NOT_REPORTED;
  if (p.edition === "Core" || p.edition === "Desktop") {
    return withArch(`${p.edition === "Core" ? "PowerShell" : "Windows PowerShell"} ${p.version ?? ""}`.trim(), p.arch);
  }
  return p.path.slice(Math.max(p.path.lastIndexOf("/"), p.path.lastIndexOf("\\")) + 1);
}

/** Why the program is the one it is, for a fallback: shown after its name on the run's page. */
export function programNote(p: RunProgram | null): string | null {
  return p?.fallback ? "PowerShell 7 was not found, and this script allows Windows PowerShell." : null;
}

/** A PowerShell the agent found, in a few words: "PowerShell 7.6.10, 64-bit". */
export function installName(i: PowerShellInstall): string {
  return withArch(`${i.edition === "Desktop" ? "Windows PowerShell" : "PowerShell"} ${i.version}`.trim(), i.arch);
}

/** Why a queued run is not sent (JobRun.held). */
export const HELD_TEXT: Record<NonNullable<JobRun["held"]>, string> = {
  unable: "The device's agent says it cannot run PowerShell 7 scripts, so the run is not sent. Update the agent; otherwise the run expires.",
  unreported:
    "The device's agent has not yet said whether it can run PowerShell 7 scripts, so the run is not sent. An agent says so within a minute of starting; update it if it does not.",
};

/**
 * Why a delivered run that has not started is not sent again (JobRun.held): the agent changed versions after taking it,
 * as a rollback does, and the version it runs now has not said it can run PowerShell 7 scripts.
 */
export const HELD_SENT_TEXT: Record<NonNullable<JobRun["held"]>, string> = {
  unable:
    "The device took the script, but its agent has since changed to a version that cannot run PowerShell 7 scripts, so the run will not start. Update the agent; otherwise the run expires.",
  unreported:
    "The device took the script, but its agent has since changed versions and has not yet said whether it can run PowerShell 7 scripts, so the run is not sent again until it does.",
};

/** "45 seconds", "5 minutes", "1 hour 30 minutes". */
export function formatSeconds(total: number): string {
  const h = Math.floor(total / 3600);
  const m = Math.floor((total % 3600) / 60);
  const s = total % 60;
  const parts: string[] = [];
  if (h) parts.push(`${h} ${h === 1 ? "hour" : "hours"}`);
  if (m) parts.push(`${m} ${m === 1 ? "minute" : "minutes"}`);
  if (s || parts.length === 0) parts.push(`${s} ${s === 1 ? "second" : "seconds"}`);
  return parts.join(" ");
}

/** A short elapsed time: "under 1 s", "12 s", "3 min 4 s", "2 h 5 min". */
export function formatElapsed(ms: number): string {
  const total = Math.floor(ms / 1000);
  if (total < 1) return "under 1 s";
  const h = Math.floor(total / 3600);
  const m = Math.floor((total % 3600) / 60);
  const s = total % 60;
  if (h) return m ? `${h} h ${m} min` : `${h} h`;
  if (m) return s ? `${m} min ${s} s` : `${m} min`;
  return `${s} s`;
}

/** How long a run took, or has been running; null before it starts. */
export function runElapsed(r: Pick<JobRun, "startedAt" | "finishedAt">, now: number = Date.now()): number | null {
  const start = parseDate(r.startedAt);
  if (!start) return null;
  const end = parseDate(r.finishedAt)?.getTime() ?? now;
  return Math.max(0, end - start.getTime());
}

export function formatBytes(n: number): string {
  if (n < 1024) return `${n} ${n === 1 ? "byte" : "bytes"}`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(n < 10 * 1024 ? 1 : 0)} KiB`;
  return `${(n / 1024 / 1024).toFixed(1)} MiB`;
}

/** Bytes of a string in UTF-8, as the server counts them. */
export function utf8Length(s: string): number {
  return new TextEncoder().encode(s).length;
}

/** Arguments typed one per line. Blank lines are dropped; everything else is passed as typed. */
export function parseArgs(text: string): string[] {
  return text
    .split("\n")
    .map((line) => line.replace(/\r$/, ""))
    .filter((line) => line.trim() !== "");
}

interface StatusMeta {
  label: string;
  tone: Tone;
  title: string;
}

export const RUN_STATUS: Record<RunStatus, StatusMeta> = {
  queued: { label: "Queued", tone: "neutral", title: "Waiting for the device to pick it up. Devices check for work continuously while online." },
  sent: { label: "Delivered", tone: "info", title: "The device has the script and is about to start it." },
  running: { label: "Running", tone: "info", title: "The script is running on the device." },
  succeeded: { label: "Succeeded", tone: "ok", title: "The script exited with code 0." },
  failed: { label: "Failed", tone: "danger", title: "The script exited with a non-zero code, or could not start." },
  timed_out: { label: "Timed out", tone: "warn", title: "The script ran past its timeout and was stopped." },
  canceled: { label: "Canceled", tone: "neutral", title: "Canceled before it finished." },
  expired: { label: "Expired", tone: "warn", title: "The device did not come online to pick it up in time." },
  lost: { label: "No result", tone: "warn", title: "The script started, but the device did not report how it ended before the deadline." },
};

export const OPEN_STATUSES: RunStatus[] = ["queued", "sent", "running"];

export function isOpen(status: RunStatus): boolean {
  return OPEN_STATUSES.includes(status);
}

/** Statuses in display order, for a job's breakdown. */
export const STATUS_ORDER: RunStatus[] = ["running", "sent", "queued", "succeeded", "failed", "timed_out", "lost", "expired", "canceled"];

/** A job as a whole, from its runs' statuses. */
export function jobState(j: Pick<Job, "counts" | "total" | "finished">): StatusMeta {
  const c = j.counts;
  const n = (s: RunStatus) => c[s] ?? 0;
  if (!j.finished) {
    if (n("running") + n("sent") > 0) return { label: "Running", tone: "info", title: "Some devices are running the script." };
    return { label: "Waiting", tone: "neutral", title: "Waiting for devices to come online and pick the job up." };
  }
  const bad = n("failed") + n("timed_out") + n("lost") + n("expired");
  if (n("succeeded") === j.total) return { label: "Succeeded", tone: "ok", title: "Every device ran the script successfully." };
  if (bad > 0) {
    return n("succeeded") > 0
      ? { label: "Some failed", tone: "warn", title: "The script did not succeed on every device." }
      : { label: "Failed", tone: "danger", title: "The script did not succeed on any device." };
  }
  return n("succeeded") > 0
    ? { label: "Partly canceled", tone: "neutral", title: "Some runs were canceled; the rest succeeded." }
    : { label: "Canceled", tone: "neutral", title: "Every run was canceled." };
}

/** Options for how long to wait for offline devices, in hours. */
export const WAIT_OPTIONS: [number, string][] = [
  [1, "1 hour"],
  [4, "4 hours"],
  [24, "24 hours"],
  [72, "3 days"],
  [168, "7 days"],
];
