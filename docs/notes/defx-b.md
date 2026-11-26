# defx-b: ADR-0070 slice B (EasyPatch agent and MSI), notes for the integrator

## Changelog lines

* Added: the EasyPatch agent's MSI creates, locks down, verifies and excludes
  its two folders from Microsoft Defender before it lays down files, then the
  agent adds its process and Controlled Folder Access exclusions; it records
  exactly what it added, reconciles at every service start and removes exactly
  that on uninstall. Defender not being the active antivirus is "not
  applicable"; a policy that ignores local exclusions
  (`DisableLocalAdminMerge`) is reported.
* Changed: the EasyPatch data folder is created with its access list in one
  step, a folder that cannot be trusted is moved aside, and the whole tree is
  checked; the program folder is locked down (SYSTEM and Administrators full
  control, Users read and execute).
* Changed: winget and msiexec run with `TEMP`, `TMP` and (winget) their working
  directory in `%ProgramData%\EasyPatch\work`; the service and the installer's
  commands extract their single file into their own folder under
  `%ProgramData%\EasyPatch\bundle`.
* Added: `EasyPatch.Agent.exe defender add|remove|status`; the installer build
  writes `<msi>.files.json` with the hashes of the installed program file.

## Implementation-status rows

| Feature | State |
|---|---|
| Defender exclusions at install (EasyPatch side, ADR-0070 slice B) | built, unit-tested; Windows behaviour unverified on a real device |
| MSI order (create, lock, verify, exclude, files) | built, table order checked in a Wine-built MSI; not run on Windows |

## Privacy notes

Nothing beyond slice A's line: the paths of the agents' own folders and
Defender's exclusion state, from Windows devices. `defender status` prints the
report on the device; this slice sends nothing to the server.

## Not done, not verified

* Nothing was run on Windows. Unverified: the PowerShell pre-step inside the MSI
  (it parsed as a property in a Wine-built package, no PowerShell was available),
  `cmd /s /c` quoting of the custom actions, `Set-Acl` with the SDDL, the
  `Environment` value for the service, .NET extracting into the new folders
  (the ADR's "to confirm on the runner where it extracts today"), and the
  Defender cmdlets themselves.
* No heartbeat carries the EasyPatch report to the server (slice A's `Facts`
  are the Go agent's); the console can read it through `defender status` only.
  Decide whether the EasyRMM agent should run that command and forward it.
* The Windows CI steps 1 to 5 and 8 of the ADR are not written (they need the
  Windows job slice A owns).
* A failed MSI install after the pre-step leaves the two exclusions and the
  record; the next install or `defender remove` handles them (no rollback action).
* `INSTALLFOLDER` overridden on the command line: the exclusions still name the
  fixed `%ProgramFiles%\EasyPatch Agent`, and the program exclusion is skipped
  because the program is not inside it.
* The dev-scope guard (`devscope.Allowed`) is not used here, on purpose: see the
  ADR amendment (4); EasyPatch builds reach devices only by the dev-only override.

## Manual test on a DHI server (real device, run as an administrator)

Use the MSI built for this branch: `scripts/build-msi-linux.sh --version <v>`
(or `agent/Installer/build-installer.ps1` on Windows). Defender must be active
(`Get-MpComputerStatus`: `AMRunningMode` Normal, real-time on). Run in an
elevated Windows PowerShell. Install with the same properties as today
(`msiexec /i EasyPatchAgent-<v>-x64.msi /qn SERVERURL=... ENROLLMENTTOKEN=... /l*v C:\ep-install.log`).

1. Before: `(Get-MpPreference).ExclusionPath` and the other three lists; write
   them down. Add a path of your own first (`Add-MpPreference -ExclusionPath C:\Keep-Me`).
2. Install. In `C:\ep-install.log` check the order: `CreateFolders`, then
   `DefenderPreExclude`, then `InstallFiles`, `ServiceBundleEnvironment`,
   `DefenderExclude`. Any non-zero exit of those two steps is logged and ignored.
3. Check the add: `ExclusionPath` and `AttackSurfaceReductionOnlyExclusions` list
   `C:\Program Files\EasyPatch Agent` and `C:\ProgramData\EasyPatch`;
   `ExclusionProcess` and `ControlledFolderAccessAllowedApplications` list
   `C:\Program Files\EasyPatch Agent\EasyPatch.Agent.exe`; nothing else was added,
   `C:\Keep-Me` is still there, and `%TEMP%` and powershell.exe are not listed.
4. Check the record: `type C:\ProgramData\EasyPatch\state\defender-exclusions.json`
   has six entries (kind, path, at, agentVersion), the same format as the EasyRMM agent's.
5. Check the report: `& 'C:\Program Files\EasyPatch Agent\EasyPatch.Agent.exe' defender status`
   says `effective` (or `present_not_effective` with the `DisableLocalAdminMerge`
   reason where a policy manages Defender, or `not_applicable` with a reason where
   a third-party antivirus is active).
6. Check the locks: `icacls "C:\Program Files\EasyPatch Agent"` shows SYSTEM and
   Administrators full control and Users read and execute only; `icacls C:\ProgramData\EasyPatch`
   shows SYSTEM and Administrators only; both owned by Administrators.
7. Check the extraction: `reg query HKLM\SYSTEM\CurrentControlSet\Services\EasyPatchAgent /v Environment`
   shows `DOTNET_BUNDLE_EXTRACT_BASE_DIR=C:\ProgramData\EasyPatch\bundle\EasyPatchAgent`;
   after the service has started, `dir C:\ProgramData\EasyPatch\bundle\EasyPatchAgent` holds
   what it extracted; `Get-ChildItem Env:` in a new console has no such variable
   (not machine-wide). Record where .NET really extracts (this was "to confirm").
8. Check the moved work: trigger an application update (winget) and an agent
   update from the console; `dir C:\ProgramData\EasyPatch\work` has temporary
   files, and nothing new appears in `%TEMP%` or `C:\Windows\Temp` from them.
9. Check the safety net: `icacls C:\ProgramData\EasyPatch /grant Users:(W)` then
   restart the service (`Restart-Service EasyPatchAgent`); the service starts, the
   list is reset to SYSTEM and Administrators, and `defender status` is still
   `effective`. Then create a junction inside the data folder
   (`cmd /c mklink /J C:\ProgramData\EasyPatch\x C:\Windows`) and restart: the
   junction is removed (C:\Windows is untouched).
10. Check not locked: `icacls "C:\Program Files\EasyPatch Agent" /grant Users:(M)`
    then `defender add` (it re-locks first, so repeat with the data folder's parent
    `C:\ProgramData` made writable by Users, `icacls C:\ProgramData /grant Users:(M)`; undo it
    after). `defender status` says `not_locked` with the reason and no new exclusion
    for the folder is added; an exclusion the agent added earlier for it is removed
    on the next `defender add`.
11. Check not applicable: where the server has a third-party antivirus, or Defender
    passive or real-time off, reinstall: the install succeeds, `defender status`
    says `not_applicable` with the reason, the record has no entries, and nothing
    is raised.
12. Upgrade: install a newer MSI over it. The exclusions and the record stay;
    nothing is removed and re-added.
13. Uninstall: `msiexec /x {product code} /qn /l*v C:\ep-remove.log`. The log shows
    `DefenderRemove` before `UnenrollAgent`; afterwards all six exclusions are gone,
    `C:\Keep-Me` is still listed, and the record is deleted. Repeat once with the
    record deleted or edited to garbage before the uninstall: only the exact
    fixed set is removed.
