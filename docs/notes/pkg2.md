# pkg2: ADR-0056 slice 2 (the installer recorded, new devices on the server's build, Uninstalled)

Branch `ws/pkg2`, migration `90711_agent_installer_build.sql` (renumber at merge).

## What it is

- `agentproto.HeartbeatRequest.Installer` (`deb`, `rpm`, `msi`, none for the command), `ValidInstaller`,
  `PathUninstalled` and `UninstalledReport`. The agent's runner sends `Installer` from the package record only
  after an answer of level 2 or higher; the enrollment request gains nothing.
- Server: the heartbeat stores `devices.installer` (a value that is no package kind is ignored; a heartbeat that
  names none changes nothing), sets `devices.ran_server_build_at` once, at the first heartbeat whose build is the one
  served (withheld builds count for nothing), and clears the *Uninstalled* mark and resolves its notice.
- `planUpdate`: under *When asked* a device with no `ran_server_build_at` is updated at its first heartbeat, within
  *Devices at once*; *Off* still holds it.
- `POST /api/agent/v1/uninstalled` (signed with the device key): `Service.Uninstalled` marks the device
  (`agent_uninstalled_at`, `agent_uninstalled_installer`), audits `device.agent_uninstalled`, resolves its policy alerts
  (`uninstalled`) and opens the notice `agent_uninstalled` ("Agent removed without a request"), one per device.
- `Service.Removed`: a `removed` report with no removal pending marks the device the same way instead of deleting it.
- Agent: `easyrmm-agent uninstall` (also what a package's removal script runs) reports to `/uninstalled` after removing
  the service and before deleting its key, within 10 seconds, never failing the removal; any answer, 404 included, that is
  not success counts as "not heard".
- Console: the device page's agent line shows the installer and whether the device has run the server's build (or is
  new); the status badge reads *Uninstalled*.

## Gaps

- ADR-0053's `removal_instructions` table is not built, so a removal cancelled meanwhile and then confirmed by the agent
  now marks the device Uninstalled where ADR-0050 deleted it; the person removes it. The notice has no severity column,
  so "critical" is only in its wording; the device-rule condition, the maintenance-window exemption, the Devices filter
  and the "enrolled again as" resolution belong to ADR-0053's slice.
- The bundle test of the slice is not run here.

## CHANGELOG lines

- Agents report how they were installed (DEB, RPM, MSI or the install command), and the device page shows it.
- Devices record when they first ran the server's build; under *When asked* a new device updates at its first
  check-in, and *Off* still holds it.
- An agent uninstalled by hand or by removing its package tells the server (`/uninstalled`): the device shows
  *Uninstalled* and a notice, "Agent removed without a request", opens. A removal report nobody asked for no longer
  deletes the device.
