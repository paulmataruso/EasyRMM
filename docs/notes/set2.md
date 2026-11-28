# set2: signed settings delivery (ADR-0058, slice 2)

Branch `ws/set2`, from `integration/2026-11`. Migration `90611_agent_device_state.sql` (the integrator renumbers; 00094 onward is free).

## Changelog lines

- Agents now take their settings from the server as a signed, versioned document. The heartbeat interval set for a device, site, organization or the platform reaches an agent that reports `settings.v1` as a document signed with the job key; the agent verifies it, saves it (`settings.json`, owner only), applies it and acknowledges the version in its next heartbeat. A restart applies the saved settings before the first heartbeat.
- An agent holding a document heartbeats at the shorter of the document's interval and the server's answer, never below 30 seconds, and reports the interval it uses; online and monitoring follow it.
- An agent sends `metrics` only 0.8 of its interval after the last heartbeat whose metrics the server accepted, so the extra heartbeats (a document applied, a wake) never record two measurements seconds apart.
- The server keeps, per device, what its agent understands and applied (`agent_device_state`) and flags a device whose agent sent three heartbeats with the report without applying the current version ("Not applied"; shown by slice 3).

## Implementation-status rows

- Signed settings document (`internal/agentproto/settings.go`): `SignSettings` / `VerifySettings`, strict envelope, version 1 to 2^53 - 1, no expiry: built; unit tests.
- Server delivery (`server/internal/agentsettings/document.go`, called from `agents.Heartbeat`): capabilities, effective values for the keys and schema versions the agent reported, versions `max(now ms, last + 1, reported + 1)`, lazy issue under `FOR UPDATE`, restore handling, *Not applied* counter, older-catalogue rule, build and signed-time order: built; PostgreSQL integration tests.
- Agent (`agent/settings`, `agent/runner`, `agent/state`): catalogue with schema versions, verify, check, save, apply, per-key `invalid` and `clamped`, refusals reported, restart applies saved settings, bound to the device ID, interval rule, `metrics` spacing, report only after an answer of level 2 (and the second heartbeat within 5 seconds): built; unit tests.
- The real agent code against the real server code: one integration test (`TestTheAgentAppliesWhatTheServerIssuesAndTheServerHearsIt`).
- **Not verified:** Windows (the agent's own tests run on Linux here; the Windows runner and the Windows end to end are not run), the bundle end to end with the current and the previous release's real agents and against the previous release's server, rc.4's agent. Slice 3 (console: Settings tab, editors, filter) is not started.

## For the integrator

- Migration `90611_agent_device_state.sql` (renumber). The move test (`move_api_integration_test.go`) lists `agent_device_state` as *follows*.
- `scripts/ci/check-coverage.sh`: new floor `agent/settings 95`.
- ADR-0058 gains "Amended 2026-11-28: as built in slice 2"; ADR-0009 gains its *Refined by ADR-0058* line; `docs/architecture/database.md` gains the `agent_device_state` row.
- Decisions that differ from the ADR's text are listed in that amendment: the signature is over the context and the payload's JSON bytes (as jobs, updates and uninstalls), a heartbeat signed earlier than the latest processed is not processed at all, `agent_device_state` carries no organization or site columns (row-level security reads through `devices`), the next heartbeat after an applied or refused document comes in 5 seconds.
