// Scripts that patch the system themselves (docs/operations/scripts-and-jobs.md). Where EasyPatch patches devices, a
// script that installs operating-system updates, upgrades every package or turns on automatic updates works around
// EasyPatch's policies and maintenance windows. The console warns; nothing is refused.
//
// Only the operating system's own update paths count. Installing or updating one named package (EasyRMM's software
// actions, ADR-0028) and application updates (winget, Chocolatey) do not.
import type { Shell } from "../../api/types";

/** A line of a script that patches the system. */
export interface SelfPatchingLine {
  /** 1-based. */
  line: number;
  /** The line as written, trimmed, at most 120 characters. */
  text: string;
  /** What it does, completing "This line …". */
  what: string;
}

const INSTALLS_WINDOWS = "installs Windows updates";
const INSTALLS_PACKAGE = "installs a Windows update package";
const WINDOWS_POLICY = "changes Windows Update policy";
const UPGRADES_ALL = "upgrades every package";
const NEW_RELEASE = "upgrades to a new release";
const AUTOMATIC = "turns on automatic updates";

const WINDOWS_RULES: [RegExp, string][] = [
  // PSWindowsUpdate.
  [/\b(?:Install-WindowsUpdate|Get-WUInstall|Install-WUUpdates|Invoke-WUJob)\b/i, INSTALLS_WINDOWS],
  [/\bGet-WindowsUpdate\b.*\s-Install\b/i, INSTALLS_WINDOWS],
  // The Windows Update Agent API.
  [/\bCreateUpdateInstaller\b/i, INSTALLS_WINDOWS],
  [/\busoclient(?:\.exe)?\s+(?:StartInstall|ScanInstallWait|ResumeUpdate)\b/i, INSTALLS_WINDOWS],
  [/\bwuauclt(?:\.exe)?\b.*\/updatenow\b/i, INSTALLS_WINDOWS],
  [/\bwusa(?:\.exe)?\b.*\.msu\b/i, INSTALLS_PACKAGE],
  [/\bdism(?:\.exe)?\b.*\/add-package\b/i, INSTALLS_PACKAGE],
  [/\bAdd-WindowsPackage\b/i, INSTALLS_PACKAGE],
  // Writes, not reads, of the Windows Update policy keys, with the key on the same line.
  [
    /\b(?:Set-ItemProperty|New-ItemProperty|Remove-ItemProperty|Set-Item|New-Item|Remove-Item|reg(?:\.exe)?\s+(?:add|delete|import))\b.*Policies\\Microsoft\\Windows\\WindowsUpdate\b/i,
    WINDOWS_POLICY,
  ],
];

/** Finds the lines of a script that patch the system, in order. */
export function selfPatching(shell: Shell, body: string): SelfPatchingLine[] {
  const found: SelfPatchingLine[] = [];
  const lines = body.split("\n");
  let inBlockComment = false;
  lines.forEach((raw, i) => {
    let line = raw.replace(/\r$/, "");
    if (shell === "powershell") {
      // <# … #> block comments.
      if (inBlockComment) {
        const end = line.indexOf("#>");
        if (end < 0) return;
        inBlockComment = false;
        line = line.slice(end + 2);
      }
      const start = line.indexOf("<#");
      if (start >= 0) {
        const end = line.indexOf("#>", start + 2);
        if (end < 0) inBlockComment = true;
        line = line.slice(0, start) + (end < 0 ? "" : line.slice(end + 2));
      }
    }
    const code = shell === "cmd" ? cmdCode(line) : stripComment(line);
    if (!code.trim()) return;
    const what = shell === "powershell" || shell === "cmd" ? windowsLine(code) : shell === "python3" ? pythonLine(code) : shellLine(code);
    if (what) found.push({ line: i + 1, text: cut(raw.trim()), what });
  });
  return found;
}

function cut(s: string): string {
  return s.length > 120 ? `${s.slice(0, 119)}…` : s;
}

function windowsLine(code: string): string | null {
  for (const [re, what] of WINDOWS_RULES) if (re.test(code)) return what;
  return null;
}

/** A cmd line without REM and :: comments. */
function cmdCode(line: string): string {
  const t = line.trim();
  return /^(?:@?rem\b|::)/i.test(t) ? "" : line;
}

/** The line up to a # comment: a # outside quotes at the start or after whitespace (sh, bash, PowerShell, Python). */
function stripComment(line: string): string {
  let quote = "";
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (quote) {
      if (c === "\\" && quote === '"') i++;
      else if (c === quote) quote = "";
    } else if (c === '"' || c === "'") {
      quote = c;
    } else if (c === "#" && (i === 0 || /\s/.test(line.charAt(i - 1)))) {
      return line.slice(0, i);
    }
  }
  return line;
}

/** Python: the commands in its string literals, as one shell line each (os.system("apt-get -y upgrade")) and all
 * together (subprocess.run(["apt-get", "-y", "upgrade"])). */
function pythonLine(code: string): string | null {
  const literals = [...code.matchAll(/(["'])((?:\\.|(?!\1).)*)\1/g)].map((m) => m[2] ?? "");
  if (literals.length === 0) return null;
  for (const l of literals) {
    const what = shellLine(l);
    if (what) return what;
  }
  return shellLine(literals.join(" "));
}

// Words that run the command after them.
const PREFIXES = new Set(["sudo", "doas", "env", "nohup", "time", "exec", "command", "nice", "ionice", "then", "do", "else", "if", "elif", "while", "until", "!"]);
// Their options that take a value.
const PREFIX_VALUE_OPTS = new Set(["-u", "-g", "-n", "-c", "-C", "-p", "-U"]);

function shellLine(code: string): string | null {
  for (const segment of code.split(/&&|\|\||\$\(|[;|&(){}`\n]/)) {
    const what = simpleCommand(segment.trim().split(/\s+/).filter(Boolean).map(unquote));
    if (what) return what;
  }
  return null;
}

function unquote(w: string): string {
  return w.replace(/^["']+|["']+$/g, "");
}

function simpleCommand(all: string[]): string | null {
  // Redirections are not arguments: ">/dev/null", "2>", "> file".
  const words: string[] = [];
  let skipNext = false;
  for (const w of all) {
    if (skipNext) skipNext = false;
    else if (/^\d*(?:>>?|<)&?$/.test(w)) skipNext = true;
    else if (!/^\d*(?:>>?|<)/.test(w)) words.push(w);
  }
  let i = 0;
  for (;;) {
    const w = words[i];
    if (w === undefined) return null;
    if (/^[A-Za-z_][A-Za-z0-9_]*=/.test(w)) {
      i++;
    } else if (PREFIXES.has(w)) {
      i++;
      for (let o = words[i]; o?.startsWith("-"); o = words[i]) i += PREFIX_VALUE_OPTS.has(o) ? 2 : 1;
    } else {
      return programRule(w.replace(/^.*\//, ""), words.slice(i + 1));
    }
  }
}

/** The words that are not options, skipping the values of options that take one. */
function operands(args: string[], valueOpts: Set<string>): string[] {
  const out: string[] = [];
  let skipNext = false;
  for (const [i, a] of args.entries()) {
    if (skipNext) {
      skipNext = false;
    } else if (a === "--") {
      out.push(...args.slice(i + 1));
      break;
    } else if (a.startsWith("-")) {
      skipNext = valueOpts.has(a);
    } else {
      out.push(a);
    }
  }
  return out;
}

const APT_VALUE = new Set(["-o", "-c", "-t", "--option", "--config-file", "--target-release", "--default-release"]);
const DNF_VALUE = new Set(["-c", "--config", "-x", "--exclude", "--installroot", "--repo", "--repoid", "--enablerepo", "--disablerepo", "--setopt", "--releasever", "--advisory", "--advisories", "--cve", "--bz", "--sec-severity"]);
const ZYPPER_VALUE = new Set(["-r", "--repo", "-t", "--type", "--root", "-R", "--category", "--severity", "--date"]);
const AUTOMATIC_UNITS = /^(?:unattended-upgrades|dnf-automatic(?:-install|-notifyonly|-download)?|yum-cron|apt-daily-upgrade)(?:\.service|\.timer)?$/;

/** Whether `sub` with no package named upgrades everything: the subcommand is one of `bulk`, with no operands after. */
function bulk(args: string[], valueOpts: Set<string>, subs: string[]): boolean {
  const [sub, ...rest] = operands(args, valueOpts);
  return sub !== undefined && subs.includes(sub) && rest.length === 0;
}

function programRule(program: string, args: string[]): string | null {
  switch (program) {
    case "apt":
    case "apt-get":
      return bulk(args, APT_VALUE, ["upgrade", "dist-upgrade", "full-upgrade"]) ? UPGRADES_ALL : null;
    case "aptitude":
      return bulk(args, APT_VALUE, ["upgrade", "safe-upgrade", "full-upgrade", "dist-upgrade"]) ? UPGRADES_ALL : null;
    case "dnf":
    case "dnf5":
    case "yum":
    case "microdnf":
    case "tdnf":
      return bulk(args, DNF_VALUE, ["upgrade", "update", "up", "distro-sync", "dsync", "upgrade-minimal", "update-minimal", "up-min"])
        ? UPGRADES_ALL
        : null;
    case "zypper": {
      const [sub, ...rest] = operands(args, ZYPPER_VALUE);
      if (sub === "patch" || sub === "dist-upgrade" || sub === "dup") return UPGRADES_ALL;
      return (sub === "update" || sub === "up") && rest.length === 0 ? UPGRADES_ALL : null;
    }
    case "pacman":
      return args.some((a) => /^-[A-Za-z]*S[A-Za-z]*$/.test(a) && a.includes("u")) || (args.includes("--sync") && args.includes("--sysupgrade"))
        ? UPGRADES_ALL
        : null;
    case "apk":
      return bulk(args, new Set(["-X", "--repository", "-p", "--root"]), ["upgrade"]) ? UPGRADES_ALL : null;
    case "unattended-upgrade":
    case "unattended-upgrades":
      return UPGRADES_ALL;
    case "dnf-automatic":
    case "yum-cron":
      return AUTOMATIC;
    case "do-release-upgrade":
      return NEW_RELEASE;
    case "systemctl": {
      const ops = operands(args, new Set(["-H", "--host", "-M", "--machine"]));
      return ["enable", "start", "restart", "reenable"].includes(ops[0] ?? "") && ops.slice(1).some((u) => AUTOMATIC_UNITS.test(u)) ? AUTOMATIC : null;
    }
    case "dpkg-reconfigure":
      return operands(args, new Set(["-f", "--frontend", "-p", "--priority"])).includes("unattended-upgrades") ? AUTOMATIC : null;
    default:
      return null;
  }
}
