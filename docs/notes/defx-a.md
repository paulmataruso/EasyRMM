# defx-a: ADR-0070 slice A (Defender exclusions, hash list), notes for the integrator

## Changelog lines

* Added: the Windows install script creates the agent's folders, locks them
  down to SYSTEM and Administrators, verifies them, excludes them from
  Microsoft Defender (path, process, Attack Surface Reduction and Controlled
  Folder Access allowed apps), and only then downloads; a failed install
  removes what it made and added.
* Added: the Windows agent keeps those exclusions (recorded, reconciled hourly,
  removed exactly on uninstall) and reports whether they work; the device page
  shows it. Defender not being the active antivirus is "not applicable".
* Added: Settings, "Agent files": every file the server hands out or the
  agents install, with MD5 and SHA-256, always current; each device's
  reported hashes are shown beside the expected ones.
* Added: documentation page "Antivirus and EasyRMM".

## Implementation-status rows

| Feature | State |
|---|---|
| Defender exclusions at install (EasyRMM side, ADR-0070 slice A) | built; Windows behaviour unverified on a real device |
| Hash list (Settings, Agent files) and per-device comparison | built, tested with PostgreSQL |
| EasyPatch side (ADR-0070 slice B) | not started |
| AMSI probe | written (CI), not yet run |

## Privacy notes (PRIVACY.md gains a line)

The paths of the agents' own folders, Microsoft Defender's exclusion state
(including whether a policy ignores local exclusions), and MD5 and SHA-256
hashes of the agents' own program files are collected from Windows devices.

## Where things plug in

* Development scope: `agents.DefenderScope` (server/internal/agents/defender.go).
  Wire `d.Agents.SetDefenderScope(agents.ScopeFunc(devscope.Allowed))` in
  server/internal/app/app.go where the comment says so. Until then every
  organization is allowed. Agents act on Defender and send hashes only after a
  heartbeat answer with `defender.enabled`; `install.ps1` and `easyrmm-agent
  install` run for any new install, and `uninstall` only removes what the
  record lists.
* Migration `00045_defender_hashes.sql` (devices.defender, devices.installed_files,
  agent_file_hashes); renumber on merge.
* New heartbeat fields: `defender`, `installedFiles` (request), `defender`
  (answer): server/internal/agentproto/defender.go.
* Routes: GET /api/v1/settings/agent-files, POST .../refresh,
  GET /api/v1/devices/{id}/defender.
* Audit actions: device.defender_exclusion.add|remove|lock|not_locked|refuse.
