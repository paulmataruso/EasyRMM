# Notes for the integrator: slice P1 (ADR-0082, endpoint security posture) and C2's leftovers

## Changelog lines

- Security posture (ADR-0082, slice P1): each Windows and Linux computer with the agent has a security posture, read from hardening and
  patching with the compliance engine's words and rules ("meets / does not meet / cannot tell its security policy"; unknown and stale never
  count as passing) and one weighted score with its reasons. It shows as one **Security** column and filter on the Devices list, a **Security
  posture** card on the computer's Hardening tab and a **Security** report with CSV. It collects nothing new.
- Two compliance alerts (ADR-0078, section 7): **Compliance fix failed** (a fix queue item in the failed state) and **Compliance results out of
  date** (a computer's newest compliance result is older than the organization's window). Neither belongs to a policy; both follow the
  compliance module's switch and `devscope.Allowed`.

## Implementation-status rows

| Item | State |
|---|---|
| ADR-0082 P1: posture (hardening and patching under one vocabulary, `unknown` and stale, weighted score with reasons) | built, tested against PostgreSQL |
| ADR-0082 P1: Devices column and filter, computer card, Security report and CSV | built, vitest and browser spec |
| ADR-0078 C2: alert kinds `compliance_fix_failed`, `compliance_scan_stale` | built (kinds use an underscore: ADR-0082 section 5) |
| ADR-0078 C2: Reports row, Devices column | built as posture's Security report and column (one column, one report) |
| ADR-0082 P2 to P5 | not built |
| Compliance screens showing the shared score | not built (`rollup.ScoreOf` is ready) |
| Posture on a real Windows computer | not run (no real Windows computer; the Windows hardening results are the browser spec's stand-in) |
| Patching copy against a real EasyPatch engine | not run; tested with a stand-in feed (the engine is outside this server) |

## For the integrator

- Migration `00071_posture.sql`: renumber after the last on integration. It adds `posture_patching` (follows its device in the move test) and
  a unique index on `alerts` for the two compliance kinds. Down removes both.
- ADR number: 0082 (the next after 0081). It is added to the ADR index.
- Hotspot edits (additive): `app.go` (posture service and its loop, the compliance alerts loop, the posture route), `devices.go` (`Posture` on a
  device, the `posture` filter, `attachPosture`), `devicesapi.go`, `reports.go` and `reportsapi.go` (the Security report and its filter),
  `monitoring/policies.go` and `modulekinds.go` (two reserved kind names), `DevicesPage.tsx`, `DeviceDetailPage.tsx`, `ReportsPage.tsx`,
  `web/src/api/types.ts`, alert text and guide for the two new kinds, `move_api_integration_test.go`.
- The new e2e spec `web/e2e/posture.spec.ts` needs console.spec.ts to run first (its admin and organization).
- There is no notification sender for alerts in this tree; the two alerts are alerts rows like Repair failed, which is the path the alerts
  page and later notices read.

## Privacy notes

- Posture holds no personal data. `posture_patching` holds a device id, the patching engine's compliance word and a time, behind the
  device's row-level security. The Security report lists device names, as the Device inventory report does, and its search is treated as
  private in the audit entry of an export.
