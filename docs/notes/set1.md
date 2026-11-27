# set1: ADR-0058 slice 1 (settings on the server, and the interval for every agent)

Branch `ws/set1`, migration `00084_agent_settings.sql` (renumber at merge).

## What it is

- `server/internal/agentsettings`: the catalog (one key, `agent.heartbeat_seconds`, 30 to 300), precedence
  (device, site, organization, platform, default) and enforcement, the platform's minimum (`settings` key
  `agent_settings.limits`), the writes (permission at the scope written, dev scope, two rate limits, audit), and
  `EffectiveHeartbeat`, which the heartbeat and the channel's settings push call.
- `server/internal/httpapi/agentsettingsapi`: `GET /api/v1/agent-settings/keys`; per scope `GET`, `PUT` and `DELETE /{key}`
  at the platform, `/organizations/{id}`, `/sites/{id}` and `/devices/{id}`; `GET` and `PUT` the platform's limits.
- New permission `device.configure` (Site Administrators and above), in `rbac.go`, `docs/security/rbac.md` and the
  console's permission type.
- Migration: `agent_settings` (row-level security as for scripts, a definer check that a device row is for an enrolled
  device in the site it names), `devices.agent_heartbeat_seconds` and `agent_online_until`, the trigger that sets
  the second, `easyrmm_touch_device` redefined to ignore both, the backfill and the index.
- Online reads `agent_online_until` in the device list and filter, reports, monitoring (offline and remote), the Windows
  modules' sweep and the recovery conditions. Metric samples are stored 0.7 of the interval apart; windows are at least
  1.2 intervals and need `ceil(window / (2 x interval))` measurements.
- The fleet-wide hold, the recovery conditions and plan, and the Active Directory controller choice also follow the device's
  interval (they each had a three-minute or two-minute window of their own).
- `GET /api/v1/alert-policies/{id}/slow-devices` and the policy dialog's list of devices that wait longer, with a
  notice on saving.
- A device's own rows end with a move to another site (`moveOne`); ADR-0069 amended; `TestMoveDispositionOfEveryTable`
  lists `agent_settings`.

## Decided in review

See ADR-0058, *Amended 2026-11-26 (decided in review): as built in slice 1*: integer-only catalog, limits in `settings`,
online by trigger, 400 for `setting_invalid` and `setting_scope`, clearing allowed under enforcement, dev scope on
writes and on the interval, in-process rate limits, device rows end on a site move, 60 seconds in the enrollment and
removal answers, the slow-devices endpoint.

## Not done, and why

- Slice 2 (the signed document, the agent) needs ADR-0057 (the key hand-over), which is not built, so it was not
  taken. The cases the brief names for signed settings (wrong key, context or device, expired, replayed or older
  version, oversize, unknown fields) belong to it and are untested because nothing is signed yet.
- Slice 3 (the console's Settings tab, organization and site editors, Settings, Agent settings, the Devices filter)
  needs slice 2's state; only the alert policy page's list is in this slice, as the ADR says.
- Not run: the bundle check with rc.4's real agent following a site's interval; anything on Windows.
- The agent was not touched (rc.4 and later already obey `heartbeatSeconds`, bounded 10 to 600 from the later
  releases).

## For CHANGELOG (Unreleased)

- Added: heartbeat interval settings for agents (ADR-0058, slice 1): set at the platform, an organization, a site or a
  device through the API, 30 seconds to 5 minutes, with enforcement from above and a platform minimum; every agent
  follows the interval in its heartbeat answer. A device counts as online for three of its own intervals, metric
  samples follow the interval, and an alert policy's page lists the devices that wait longer because of it.
- Added: the `device.configure` permission (Site Administrators and above).
- Changed: a one-minute processor, memory or disk window judges 72 seconds of measurements.

## For IMPLEMENTATION_STATUS

| Feature | Status |
|---|---|
| Agent settings, server side and the heartbeat interval (ADR-0058 slice 1) | Built; unit, integration, API, vitest and one browser spec pass; rc.4's agent following a site's interval (bundle) not run |
| Signed settings document and the agent's apply (ADR-0058 slice 2) | Not built (needs ADR-0057) |
| Settings console (ADR-0058 slice 3) | Not built; only the alert policy page's list is |

## Privacy

`agent_settings.set_by_label` holds the e-mail address of the person who set a value (as `audit_log.actor_label` does);
the `set_by` user reference becomes null when the user is deleted, the label stays. Nothing else personal is stored.
