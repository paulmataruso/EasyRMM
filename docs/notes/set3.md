# set3: agent settings in the console (ADR-0058, slice 3)

Branch `ws/set3`, from `integration/2026-11`. No migration.

## Changelog lines

- Devices with the EasyRMM agent have a **Settings** tab: how the settings document stands (Applied N minutes ago with its version; Waiting for the device: it is offline; Not applied after three heartbeats; This agent's version does not take settings, with a link to agent updates) and, for each setting, its value in effect and where it comes from (Default, Inherited from site X, Set for this device, Set by your MSP), with an editor and *Use inherited* for who holds `device.configure`; others see it read-only.
- Organizations and sites have an **Agent settings** tab with the same editors and an *Enforce for everything below* switch.
- Settings > **Agent settings** (super administrators): the platform's own values, the shortest heartbeat interval anything below may set, the devices whose agent does not take settings and those whose settings are not applied.
- The devices list filters to *Settings not applied* (`?settings=not_applied`).

## Implementation-status rows

- Server (`agentsettings/overview.go`): `Describe` judges a device's state (applied, pending, waiting, not_applied, unsupported, none); `Listing.Document` carries it for a device; `Service.Problems` lists unsupported and not-applied devices for `settings.manage` globally. Unit test and PostgreSQL integration test: built.
- API: `GET /settings/agent-settings/problems` new; `GET /devices/{id}/agent-settings` now also returns `document`; `GET /devices?settings=not_applied` new (`devices.Query.Settings`, integration test). Built.
- Console: `pages/agentsettings/` (panel, device tab), `pages/organizations/tabs/AgentSettingsTab.tsx`, `pages/settings/AgentSettingsPlatform.tsx`, the devices filter. vitest: 10 tests.
- **Not verified:** in a real browser against a real agent; the Windows device tab.

## For the integrator

- The read and write routes the brief asked for already existed as `/devices/{id}/agent-settings` (+ `/{key}`, `PUT`/`DELETE`, also for organizations, sites and the platform), so no `/devices/{id}/settings` routes were added; the document state rides on the same GET.
- The catalogue has one key (`agent.heartbeat_seconds`). `agent.transport` is not in the catalogue, so there is no select editor; the panel renders every catalogue key with the integer editor and says "seconds" (a second key with another unit needs the entry to carry its unit).
- The editor's tab permission at organization and site level is `device.view`; the server's `canWrite` / `canEnforce` decide whether an editor shows.
- No new Go package, so no new coverage floor; `agentsettings` (90) and `devices` (88) hold.
- The first attempt at this branch lost its tracked edits when another session switched the shared `/var/tmp/wt/integration` worktree to `integration/2026-11`; the work was redone in `/var/tmp/wt/set3`.
