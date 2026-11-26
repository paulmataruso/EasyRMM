# wm-s12: ADR-0073 slices 1 and 2

## Changelog lines

* Windows agents report which roles and features they have (AD DS, AD CS, DNS, DHCP, file server, print server, Windows Backup, Defender) with the heartbeat, read from the registry and service control, at start and every 6 hours; the console can ask for a rescan. Nothing is offered for a role that is not detected.
* Windows modules can be turned on or off per organization, with an override per site, in a "Windows modules" tab on the organization and site pages. The change is audited (`windows_module.set`).
* New permissions for the Windows modules (`defender.*`, `ad.*`, `ca.*`, `dns.*`, `dhcp.*`, `shares.*`, `print.*`, `backup.*`). Technicians do not get `ca.view`, `dns.view` or `shares.view`.

## Implementation-status rows

* ADR-0073 slice 1 (roles in Facts, detection, storage, read API, rescan, role-removal hook, `modules.Allowed`): built; the detection is not verified on a real Windows server.
* ADR-0073 slice 2 (toggles, resolution, card, permissions, 404 rule): built.

## Privacy

The roles list names server roles installed on a computer. It is stored per device and never executed. No personal data.

## Integration

* Migrations 00052 (devices.roles, roles_at, roles_rescan) and 00053 (windows_module_settings).
* web/e2e/console.spec.ts and web/e2e/agent.ts on integration did not compile (a `});` lost in the ws/repair1 merge and two `heartbeat` methods in the agent helper after ws/defx-a). Fixed here with the smallest edit.
