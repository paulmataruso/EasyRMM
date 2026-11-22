import { describe, expect, it } from "vitest";
import type { Shell } from "../../api/types";
import { selfPatching } from "./selfPatching";

/** What each line does, or null when it is left alone. */
function each(shell: Shell, lines: string[]): (string | null)[] {
  return lines.map((l) => selfPatching(shell, l)[0]?.what ?? null);
}

describe("scripts that patch the system", () => {
  it("finds bulk upgrades on Linux and leaves single packages alone", () => {
    expect(
      each("bash", [
        "apt-get -y upgrade",
        "sudo DEBIAN_FRONTEND=noninteractive apt-get -o Dpkg::Options::=--force-confold dist-upgrade -y",
        "apt full-upgrade >/dev/null 2>&1",
        "if command -v apt >/dev/null; then apt -y upgrade; fi",
        "dnf -y upgrade --security",
        "yum update -y --exclude kernel*",
        "/usr/bin/dnf distro-sync",
        "zypper --non-interactive patch",
        "zypper dup",
        "pacman -Syu --noconfirm",
        "apk upgrade",
        "unattended-upgrade -d",
        "do-release-upgrade -f DistUpgradeViewNonInteractive",
        "systemctl enable --now dnf-automatic.timer",
        "systemctl start unattended-upgrades",
        "dpkg-reconfigure -f noninteractive unattended-upgrades",
      ]),
    ).toEqual([
      "upgrades every package",
      "upgrades every package",
      "upgrades every package",
      "upgrades every package",
      "upgrades every package",
      "upgrades every package",
      "upgrades every package",
      "upgrades every package",
      "upgrades every package",
      "upgrades every package",
      "upgrades every package",
      "upgrades every package",
      "upgrades to a new release",
      "turns on automatic updates",
      "turns on automatic updates",
      "turns on automatic updates",
    ]);
    expect(
      each("sh", [
        "apt-get install --only-upgrade -y nginx",
        "apt-get -y upgrade openssl",
        "dnf -y update nginx",
        "yum check-update",
        "zypper update curl",
        "apt list --upgradable",
        "pacman -S vim",
        "apk add curl",
        "systemctl status unattended-upgrades",
        "systemctl stop dnf-automatic.timer",
        'echo "remember: apt upgrade"',
        "# apt-get -y upgrade",
        "apt-get update # then upgrade later",
        'echo "$#" # args',
      ]),
    ).toEqual(Array(14).fill(null));
  });

  it("reads commands out of Python strings", () => {
    expect(
      each("python3", [
        'subprocess.run(["apt-get", "-y", "upgrade"], check=True)',
        "os.system('dnf -y upgrade')",
        'subprocess.run(["dnf", "-y", "install", "nginx"])',
        "# os.system('apt-get upgrade')",
        "x = 1",
      ]),
    ).toEqual(["upgrades every package", "upgrades every package", null, null, null]);
  });

  it("finds Windows Update installs, update packages and policy changes", () => {
    expect(
      each("powershell", [
        "Install-WindowsUpdate -AcceptAll -AutoReboot",
        "Get-WindowsUpdate -MicrosoftUpdate -Install -AcceptAll",
        "Get-WUInstall -AcceptAll",
        "$installer = $session.CreateUpdateInstaller()",
        "usoclient.exe StartInstall",
        "UsoClient ScanInstallWait",
        "wusa.exe C:\\temp\\windows10.0-kb5040442-x64.msu /quiet /norestart",
        "dism /online /add-package /packagepath:C:\\temp\\update.cab",
        "Add-WindowsPackage -Online -PackagePath C:\\temp\\update.cab",
        "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU' -Name NoAutoUpdate -Value 1",
        "New-Item -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate' -Force",
      ]),
    ).toEqual([
      "installs Windows updates",
      "installs Windows updates",
      "installs Windows updates",
      "installs Windows updates",
      "installs Windows updates",
      "installs Windows updates",
      "installs a Windows update package",
      "installs a Windows update package",
      "installs a Windows update package",
      "changes Windows Update policy",
      "changes Windows Update policy",
    ]);
    expect(
      each("powershell", [
        "Get-WindowsUpdate -MicrosoftUpdate",
        "Install-Module PSWindowsUpdate -Force",
        "usoclient StartScan",
        "Get-ItemProperty 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU'",
        "winget upgrade --all --silent",
        "choco upgrade all -y",
        "# Install-WindowsUpdate -AcceptAll",
      ]),
    ).toEqual(Array(7).fill(null));
  });

  it("reads cmd scripts and skips their comments", () => {
    expect(
      each("cmd", [
        'reg add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU" /v NoAutoUpdate /t REG_DWORD /d 1 /f',
        "wuauclt /detectnow /updatenow",
        'powershell -NoProfile -Command "Install-WindowsUpdate -AcceptAll"',
        "REM usoclient StartInstall",
        ":: wusa update.msu",
        "reg query HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate",
      ]),
    ).toEqual(["changes Windows Update policy", "installs Windows updates", "installs Windows updates", null, null, null]);
  });

  it("skips PowerShell block comments and reports line numbers and text", () => {
    const body = ["<#", "Install-WindowsUpdate -AcceptAll", "#>", "Write-Host 'start'", "  Install-WindowsUpdate -AcceptAll   ", "<# a #> usoclient StartInstall"].join("\r\n");
    const found = [
      { line: 5, text: "Install-WindowsUpdate -AcceptAll", what: "installs Windows updates" },
      { line: 6, text: "<# a #> usoclient StartInstall", what: "installs Windows updates" },
    ];
    expect(selfPatching("powershell", body)).toEqual(found);
    // PowerShell 7 scripts are read the same way (ADR-0064).
    expect(selfPatching("pwsh", body)).toEqual(found);
    expect(selfPatching("bash", `${"x".repeat(200)} ; apt-get -y upgrade`)[0]?.text).toHaveLength(120);
    expect(selfPatching("bash", "")).toEqual([]);
  });
});
