# Antivirus and EasyRMM

The EasyRMM agent is not signed by a public certificate yet
([CODE_SIGNING.md](../../CODE_SIGNING.md)), and it does what antivirus
products watch for: it runs as LocalSystem, downloads and runs scripts,
replaces its own executable, installs MeshAgent for remote access and
drives `msiexec`. Microsoft Defender can quarantine or block any of that.
This page says what EasyRMM does about it on Windows, and where to find the
hashes if you allow-list by hash.

Linux and macOS agents do none of this.

## What the install does to Microsoft Defender

When the Windows install script runs, in this order and each step only if
the one before it worked:

1. It creates the agent's folders.
2. It locks them down so that only SYSTEM and Administrators can write
   them.
3. It verifies that: the folders, the folders above them, and everything
   inside.
4. It adds the Defender exclusions.
5. Only then does it download anything.

If any step fails, the script says why, downloads nothing, and removes the
exclusions and the folders it made.

The agent excludes only folders it has locked down and verified, and it
checks them again every hour. If a folder becomes writable by anyone else,
the agent removes its own exclusion for it and the device page says so.

| Kind | What is added |
|---|---|
| Path (`ExclusionPath`) | `%ProgramFiles%\EasyRMM\Agent`, `%ProgramFiles%\EasyRMM\MeshAgent`, `%ProgramData%\EasyRMM\Agent` |
| Process (`ExclusionProcess`) | the full paths of `easyrmm-agent.exe` and `meshagent.exe` |
| Attack Surface Reduction (`AttackSurfaceReductionOnlyExclusions`) | the same three folders |
| Controlled Folder Access (`ControlledFolderAccessAllowedApplications`) | the full paths of the same two programs |

EasyRMM never adds an extension exclusion, never excludes `%TEMP%`,
`powershell.exe` or `msiexec.exe`, and never turns off real-time
protection, Controlled Folder Access, Attack Surface Reduction or AMSI.

**The cost of process exclusions.** Defender does not scan what an excluded
process opens or writes, anywhere, at that moment: files the agent receives,
scripts it writes and runs, updates it downloads, and files MeshAgent moves
during a remote session. Such a file is scanned when a different process
opens it. The programs sit in folders only administrators can write.

There is no organization setting. An administrator who removes the
exclusions in Defender will see the agent add them back at its next check;
the way to stop that is to uninstall the agent.

## Removing them

Uninstalling the agent removes exactly the exclusions it recorded, and not
one that an administrator added by hand, even for the same folder. The
record is `defender-exclusions.json` in the agent's state folder. If the
record is missing or unreadable, the agent removes only entries that match
its fixed set exactly, and only for folders that still verify.

If Defender cannot be reached during an uninstall, the uninstall still
finishes, and the record is kept so that a new install finds the leftover
exclusions and removes them.

## What the device page shows

On a Windows device, **Microsoft Defender exclusions** shows one status and
the reason when it is not working, each of the four kinds, and each folder:

| Status | Meaning |
|---|---|
| Working | every folder is locked down and listed, and Defender honors local exclusions |
| Listed, not in effect | the exclusions are listed, but a policy ignores them: `DisableLocalAdminMerge` is set (Intune, Group Policy or Configuration Manager manage the exclusions) |
| A folder is not locked down | a folder could not be locked down or verified, so it was not excluded |
| Defender refused | the add failed or the path was not listed afterwards, for example with Tamper Protection on |
| Cannot be read | Defender hid its lists ("N/A: Must be an administrator or have Tamper Protection") or could not be reached by PowerShell or WMI |
| Not applicable | Defender is not the active antivirus: another product is, Defender is passive or off, or it is not installed. The folders are still locked down; nothing is added and nothing is wrong |

Attack Surface Reduction and Controlled Folder Access show **Not needed**
when they are off.

## Hashes, for allow lists

**Settings, Agent files** lists every file this server hands out or the
agents install, each with its platform, version, size, **MD5** and
**SHA-256**, where the value comes from, and when it was computed. Anyone
with the `org.view` permission can read it, and nobody can edit it: it is
rebuilt when the server starts, when a signed build is accepted or removed,
when a device reports a version the list lacks, every thirty minutes, and
when a super administrator presses **Refresh**. A value whose source could
not be read keeps its last value, marked **Stale**.

MD5 is there because some allow lists still ask for it. EasyRMM never trusts
a file by its MD5.

To allow-list by hash in Microsoft Defender for Endpoint, add the SHA-256
values as file indicators. Elsewhere, allow the folders above by path.

On a device's page, **Installed files** shows the hashes the device reports
for its agent, MeshAgent and the EasyPatch agent's files, labeled **reported
by the device** because an agent could report anything, next to the value
this server expects for the version it reports:

* **Matches the list.**
* **Differs from the list**: a different hash, or the file is missing. Nothing
  is done about it.
* **Not the current build**: MeshAgent updates itself, so a different hash is
  not a mismatch.
* **No expected value**: the version has no entry (an older build). The files
  inside the EasyPatch agent's installer are not listed yet.

The device sends fresh hashes after an install, an update and a self-update,
in the first heartbeat that reports a changed version, and once a day.

## Not covered

Exclusions are a stopgap. Signing the agent is the real fix, because the
reputation Defender and SmartScreen give follows a publisher's certificate,
not a folder. The text of `install.ps1` itself is still checked by AMSI when
it runs.

Tamper Protection on, Intune or Group Policy managed exclusions, a
third-party antivirus and Defender passive mode are not reachable by EasyRMM's
automated tests; they are untested until run on real devices.
