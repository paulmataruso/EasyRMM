# Notes for reg1 (ADR-0067 slice 1: F2, browsing, search and export), for the integrator

## Changelog lines

- Registry editor, read-only (ADR-0067 slice 1): a Registry tab on Windows devices, for holders of the new `registry.view` permission
  (Technicians and above; Read-Only has none, and reading a result needs `job.view_sensitive` too). It browses both registry views (the x86
  view included), reads every value type raw, searches a key's subtree within bounds, and exports a key as `.reg` or JSON. Data comes from a
  built-in of the agent, run as a child process, with no PowerShell. `SAM`, `SECURITY`, loaded copies of them and the agents' own keys are
  refused, and values whose names suggest a secret are masked. Every read is an audit record (a search term's length, never the term).
  An agent that does not list the editor is refused with a clear message.
- Jobs (F2, shared by later features): kinds with a signed input and a stored result, kept and removed per kind, read only through
  functions that check who may; an answer to a poll holds at most 8 runs and 6 MiB, quick runs first; a run delivered five times without
  starting fails.

## Implementation-status rows

| Item | State |
|---|---|
| F2: kinds table, `job_inputs`, `job_runs.result`, masked store, functions, `GET /job-runs/{id}/result`, purge per kind, claim size, order and delivery limit, `MaxResultBody` 8 MiB | built, tested against PostgreSQL and a real agent client |
| Builtin executor (child process, input and result files, job object memory limit, quick lane, `job.structured`, `builtin.registry.v1`) | built; tested on Linux with a stand-in child; Windows job-object limit untested until the runners run it |
| `internal/registryrules` | built, tested |
| Registry builtin reads (list, value, search, export) | engine tested against an in-memory registry; Windows tests written (`registry_windows_test.go`), not run here; CI job `windows-registry` added |
| Registry tab | built; vitest; browser test written (`registry.spec.ts`) |
| Registry writes, backup and undo; import; bulk; reveal; protected paths | not built (slices 2 to 4) |
| Time to list a key of 1,000 subkeys; 100,000-subkey paging | measured by the Windows runners' test, not yet |
| A real Windows computer of the owner's test instance | not used |

## Privacy notes

- A registry read's record holds the hive, view, path (first 2,048 characters), operation and limits, and a search term's length.
  Results and inputs are kept one hour (reads) in tables the server's role cannot select; masked values' data is never stored or sent.
  The `.reg` and JSON exports hold values read from the computer (not masked ones): the person who asked downloads them within the hour.

## For the integrator

- Migrations 00072 (F2) and 00073 (refusal bound, `easyrmm_registry_refusal`), to be renumbered. Both have working Down.
- `agentproto`: payload version 3 (signature context `EASYRMM-JOB-SIG-V3`), new capabilities `job.structured` and `builtin.registry.v1`,
  `ResultRequest.Result/ResultCut/AgentVersion` (sent only to a server of level 2 or higher: `agent/client`), `MaxResultBody` 8 MiB.
- Hotspots, additive: `rbac.go` (two permissions, in a block of their own), `DeviceDetailPage.tsx` (one tab, one panel), `agent main.go`
  (`builtin` command, `jobs.AgentVersion`), `StatusBadges.tsx` (audit labels), `types.ts`, the CI workflow (job `windows-registry`).
- Existing tests changed: `TestTheServerRoleCannotReadOutputOrArguments` now lists `job_runs.result` among the columns the role cannot read, and
  `TestMoveDispositionOfEveryTable` lists `registry_masked_values` as stays (ADR-0069 amended to say so).
- The branch has integration/2026-11 merged in up to ws/ci10 and ws/c2/ks2 (conflicts in `rbac.go`, `types.ts`, `DeviceDetailPage.tsx` and the move test
  resolved by keeping both sides).
- Every job created for a registry read checks `devscope.Allowed(org)`.
- For ADR-0072: the Registry tab id is `registry`, shown for Windows devices with the agent and `registry.view` at the site.
- For ADR-0064/W2: F2 built job retention per kind for its two kinds (`Kind.KeepResult`, `KeepJob`) and the delivery limit; W2 extends them.
