# ADR-0086: NTP and LAPS Modules

**Status:** Accepted  
**Date:** 2026-11-27

## Context

Clock skew caused agent_silent alerts across multiple organizations when a
Windows device's UTC clock drifted past the 5-minute `MaxSkew` threshold in
`agentproto.Auth.Fresh`. The root cause was a wrong timezone combined with a
manual clock adjustment that corrupted the underlying UTC, leaving no fleet-wide
tool to inspect or correct NTP configuration.

Separately, MSPs need visibility into LAPS (Local Administrator Password
Solution) state across managed devices: whether Windows LAPS or legacy LAPS is
configured, the admin account's password age, the AD-stored expiry, and the
ability to trigger an immediate rotation.

## Decision

Add two non-role winmod modules, registered alongside BitLocker in
`modules.Known` via a `nonRole` map so they run on any Windows device without
requiring a detected server role or an organization toggle.

### NTP module (`ntp.*`)

| Action | Permission | Scheduled | Changes |
|---|---|---|---|
| `ntp.status` | `device.view` | hourly, 5 min freshness | no |
| `ntp.set_timezone` | `device.configure` | — | yes |
| `ntp.set_ntp_server` | `device.configure` | — | yes |
| `ntp.force_sync` | `device.configure` | — | yes |

`status` reads the system timezone (`Get-TimeZone`), Windows Time service state,
NTP source, last sync, peers and registry config. `set_timezone` validates the
ID against `GetSystemTimeZones()` before calling `Set-TimeZone`. `set_ntp_server`
calls `w32tm /config /manualpeerlist:<server> /syncfromflags:manual /update`.
`force_sync` starts w32time if stopped and calls `w32tm /resync /force`.

### LAPS module (`laps.*`)

| Action | Permission | Scheduled | Changes |
|---|---|---|---|
| `laps.status` | `device.view` | hourly, 5 min freshness | no |
| `laps.reset_password` | `device.configure` | — | yes |

`status` checks both Windows LAPS registry paths
(`HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\LAPS\Config` and
`HKLM:\SOFTWARE\Microsoft\Policies\LAPS`) and legacy LAPS (`AdmPwd.dll`),
the local administrator account state, and the AD password expiry attributes
(`msLAPS-PasswordExpirationTime`, `ms-Mcs-AdmPwdExpirationTime`).

`reset_password` prefers `Reset-LapsPassword` (Server 2022+), falling back to
setting the AD expiration attribute to now and triggering `gpupdate /force`.
Requires a domain-joined computer.

## Consequences

- Fleet-wide NTP visibility prevents the class of outage that caused the
  clock_skew incident.
- LAPS status gives MSPs a single pane for local admin password management
  without logging into each domain controller.
- Both modules follow the existing winmod pattern: embedded scripts, SHA-256
  pins, typed decoders, RBAC permissions.
- No database migration needed; results are stored in the existing
  `winmod_results` table.
- Console UI pages for both modules are deferred to a follow-up.
