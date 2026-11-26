# Notes for ev1 (ADR-0068 slice 1: the event viewer on demand, one device), for the integrator

## Changelog lines

- Event logs, on demand (ADR-0068 slice 1): an Event logs tab on Windows devices, for holders of the new `eventlog.view` permission
  (Technicians and above). It lists the computer's logs, searches one or several by level, event ID (ranges and exclusions), provider,
  time and text, newest first in pages, and shows each event's fields, message and XML, in your time, the computer's or UTC. Data comes
  from a built-in of the agent that calls the Windows Event Log API directly, with no PowerShell, so a search never writes into the logs
  it reads. The Security log, and command lines, scripts and service and task definitions, need `log.view_sensitive` (Organization
  Administrators and above, from an organization-wide grant only), are hidden on the computer and again on the server, and every search
  is an audit record without its text or any event. An agent that does not list the viewer is refused with a clear message.
- A running search is cancelled through the child's input, so Windows is told to stop: the agent closes a pipe, the built-in cancels its
  query. A new search from the same person cancels their old one; two are open on a device at most.

## Implementation-status rows

| Item | State |
|---|---|
| `internal/eventrules`: model, classification, query builder, inputs and results v1, the server's check of a result | built, tested |
| `eventlog.view`, `log.view_sensitive` (organization-wide only), kind `eventlog_query`, definer functions, refusal bound, audit events | built, tested against PostgreSQL and a real agent client |
| Builtin `easyrmm-agent builtin eventlog` (`channels` with `CrashOnAuditFail`, `query`, `event`, `provider`), cancel through the child's input, `builtin.eventlog.v1` | engine tested against an in-memory log on Linux; the wevtapi half (`backend_windows.go`) and its Windows tests written, not run here; CI job `windows-eventlog` (x64, ARM64, LocalSystem) added |
| Event logs tab | built; vitest; browser test written (`eventlog.spec.ts`) |
| Presets, counts, archived logs, saved searches, export; ADR-0060 collected mode; channel settings; files; clearing | not built (slices 2 to 6) |
| A query's time from click to list; the Event Log service's load on a 256 MiB log; the error codes the ADR marks to be confirmed | not measured; for the Windows runners and a real computer |
| A real Windows computer of the owner's test instance | not used |

## Privacy notes

- PRIVACY.md and ADR-0060's Privacy section gain the amendment the slice asks for: on demand, Technicians and above see one computer's events,
  sign-in and process starts outside the Security log included, without command lines and scripts; each query is recorded. A page of events is
  kept one hour, in `job_runs.result` (a column the server's role cannot select), for the person who asked only.

## For the integrator

- Migration 90431 (`90431_eventlog_query.sql`), to be renumbered: admits the kind, replaces `easyrmm_job_refusal`, adds
  `easyrmm_eventlog_refusal`, `easyrmm_eventlog_result`, `easyrmm_eventlog_input`, `easyrmm_eventlog_page`. Working Down (it deletes
  `eventlog_query` jobs first).
- Hotspots, additive: `rbac.go` (a block of two permissions, `orgWideOnly`, the technician and org-admin lists), `jobs.go` (the Jobs filter,
  one guard so a page writes no audit record), `delivery.go` (one clause, one candidate field), `registry.go` (one branch in
  `recordRegistryResult`, one in `readStructuredInput`), `service.go` (the held-run message names the viewer), `agent/jobs` (stdin pipe and
  `InputGrace`, the builtins map), `exec_windows.go` (accepts), `agent main builtin.go`, `agentproto/jobs.go` (the builtin's name),
  `DeviceDetailPage.tsx` (one tab, one panel), `StatusBadges.tsx`, `JobsPage.tsx` (one filter), `types.ts`, the CI workflow (job
  `windows-eventlog`), `check-coverage.sh` (two floors).
- The Logs tab already exists (agent logs, ADR-0069), so the viewer is its own tab `eventlog` ("Event logs"); recorded in ADR-0068 as
  amended (decided in review). For ADR-0072: shown for Windows devices with the agent and `eventlog.view` at the site.
- Every operation checks `devscope.Allowed(org)` when it is created.
- Existing tests changed: `TestAcceptsListsTheEditorWhereItRuns` also checks `builtin.eventlog.v1`.
- To confirm on the runners (the ADR says so): the Windows error codes in `backend_windows.go` (`15026` filter too complex, `15002`
  publisher metadata, `15033` locale), what Windows returns for unresolved inserts, whether enabling analytic channels is read as the ADR
  says, the keyword masks for Audit Success and Audit Failure, forwarded events.
