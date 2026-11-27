# jk1: ADR-0057 slice 1, agents that can follow, the ring, and the tripwires

Branch `ws/jk1` from `integration/2026-11`. Migrations `00085` (the ring and the
servers) and `00086` (reports, issued instructions, flags, restores). ADR-0057
amended ("Amended 2026-11-27 (decided in review), slice 1 as built"); ADR-0069
amended (the move dispositions).

There is **no way to rotate** in this slice (slice 2). The ring holds the one key
it was born with. The statements exist on the agent and in `agentproto` (signing
and verifying), and the server never sends one.

## Changelog lines

* Agents keep a set of server job keys, each with its generation, and accept a
  signed hand-over or cut-over only when it verifies under a key they already
  trust (ADR-0057). The server does not send them yet.
* The server's job key moved from the `settings` table into a ring of keys with
  generations. Existing installs keep their key: the same seed and public key
  become generation 1, and the settings row is replaced by a tombstone that
  stops a server from before the ring starting against the migrated database.
* Agents report the keys they trust, the authorities in their `ca.pem` and a log
  of every instruction they accepted. A key a device trusts that the server never
  issued, and an instruction an agent ran that the server never issued, are flagged and
  audited (`device.job_key_unknown`, `device.instruction_unknown`).
* `easyrmm-agent trust-key <generation>:<key> [--force]` and `easyrmm-agent
  status` (keys, latest accepted instructions). `easyrmm-server incident
  restored`.
* The server's database connections are named `easyrmm-server/<version>`.

## Implementation status rows

| Item | Status |
|---|---|
| ADR-0057 slice 1: statements, report, trust store, instruction log, `trust-key`, `status` | Built and tested; Windows: builds and lints, unit tests not run on Windows |
| ADR-0057 slice 1: ring, move from `settings`, tombstone, `server_instances`, `issued_instructions`, last restore, key per device, unknown keys, unissued instructions | Built; integration-tested against PostgreSQL |
| ADR-0057 slices 2 to 4 (rotation, console, incidents) | Not built |
| Bundle test steps 1 (machine 3) and 6; this agent against the last release's server; ADR-0052's upgrade and rollback across the move | Not run (see below) |

## Privacy

No new personal data. The tables hold public keys, fingerprints, run, attempt and
download IDs, the instruction kind and times, the device's id, and the SHA-256 of
certificates in `ca.pem`. No secret is stored beyond what was already: the sealed
seed, now in `job_keys`. Agents send the log to the server; it holds IDs and
fingerprints only, no script text. 90 days of issued instructions.

## Decided in review (the ADR left a choice)

All are written in the ADR's amendment. In short: generic verifiers over a key or a
set; the trust store in `agent/trust`; statements bound to the install (SHA-256 of the
device's public key); dropped keys kept as public keys (8); the worker's third-delivery
count in memory; the log kinds (the escrow key is not logged or recorded); `NeedsRepinning`
signs with the floor's key until slice 2 adds the refusal; the unrecorded-restore alert is
a `server_restores` row and an audit record until slice 3's banner; `incident restored`
is built here because the table needs a writer; the updater's status is not read as a source
of restores.

## For slice 2 (what it must know)

* `agentchannel.Options.Key` and Quick Assist's key (`quickassist.New`) still take
  `ring.Newest().Private` once at start. Both must go per device before a second key
  is the newest (ADR-0059's "looks the key up for each message"; the Quick Assist
  runner is given the key its device is signed for, and `job_key_given_generation`
  is set for it).
* `jobkeys.Ring.NextGeneration` is built and tested; `job_key_cutover_*` columns are
  read by the signing rule and are written by nothing yet.
* Refusals that read `server_instances` and the database connection names
  (`database.AppName`) are slice 2's.
* `Source.Issue` signs and records in the caller's transaction. Services that sign
  outside a transaction (EasyPatch installs, repairs) open their own.
* The enrollment answer sets `job_key_given_generation`; QA's enrollment does not yet.

## Not verified, and why

* **ADR-0052 is merged** in integration (the updater's code, `updater/`), but its
  upgrade and rollback test (`updater/machinetest`, build tag `vm`) needs virtual
  machines (KVM), which this host does not run. The test "an upgrade from the last
  release across the move from `settings`, then Roll back; the agent reaches the
  restored server and runs a script" is **not built and not run**.
* **The bundle test** (`scripts/e2e/bundle.sh`) has one machine, no
  last-release agent by tag, and no rotation API; steps 1 (machine 3) and 6 are not
  built there. Step 6's content (a key the server never issued put on a device with
  `trust-key --force`: flagged, audited, then cleared with the server's key and a script
  running) is run in-process instead, with the real agent code against the real server
  over PostgreSQL: `TestAgentFollowsTheRingAndTheTripwiresShow` in
  `server/internal/app`. `docker exec` and MeshCentral's terminal are not exercised.
* **This agent against the last release's server**: not run (needs the release bundle
  by tag). By construction every new request field is sent only after an answer of
  level 2 or higher, and the first heartbeat of a process carries none (tested in
  `agent/runner`).
* **Windows**: `GOOS=windows` build, vet and lint pass; no test ran on Windows.
* The web console, the API and the guide have nothing in this slice.
