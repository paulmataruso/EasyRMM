# repair1 notes (ADR-0069 follow-ups)

## Changelog lines
* The device page has one **Repair** button instead of three. It says what will happen first: the server works out which of the EasyRMM agent, MeshAgent and the EasyPatch agent is down and which running agent repairs it (ADR-0069, amended 2026-11-26). `POST /api/v1/devices/{id}/repairs` no longer takes a `target`; `GET /api/v1/devices/{id}/repair-plan` is new.
* A repair step's diagnostics now appear in the device's Logs tab, as EasyPatch agent records, redacted.
* The Logs tab is strictly time-ordered across sources, newest first, with the record id breaking ties; it no longer shows a late batch out of order.

## Implementation status rows
* Part R, one Repair button: implemented (plan, endpoint, audit, auto-repair reads the same table); not tested on real computers.
* Part R, diagnostics in agent logs: implemented, migration 00047 (drops `agent_repairs.diagnostics`).
* Part L, merged time order: implemented, migration 00046 (index).

## Privacy
* Diagnostics now live in `agent_log_records` under the log retention (14 days by default), not in `agent_repairs`. They are redacted as before.

## For the integrator
* Migrations 00046 and 00047 need renumbering.
* Dev-scope guard: `server/internal/recovery/auto.go`, `evaluateTarget`, in the `for _, d := range list` loop, before the plan is read: `if !devscope.Allowed(d.org) { continue }` (a TODO marks it). A repair by hand needs no guard.
