# ADR-0061 slice 1: the check, `set-server`, `install` again and the fall-back

Branch `ws/name1`, based on `integration/2026-11`. Migration `00102`.

This is the first slice of [ADR-0061](../architecture/adr/0061-moving-to-a-new-name.md).
It moves nothing by itself: no instruction is sent, no capability is reported
(`move.easyrmm` is slice 4's), and nothing reads the per-server record yet.
What it gives is what the ADR says is useful alone: a computer can be moved by
hand between two addresses the server serves, and an agent that lost its
address can find its way back.

## Built

* **`internal/agentproto/move.go`**: `PathAddress` and `PathMove`; the
  confirmation, `EASYRMM-ADDRESS-SIG-V1`, signed with the job key over the
  device, the request's nonce and the address, and `VerifyAddress` against the
  keys an agent trusts (it refuses another device, nonce or address, an
  untrusted key and no signature); `MoveReport`; `MoveTarget`, which accepts
  only an `https` origin (plain `http`, loopback included, is refused, which
  `client.ParseServer` does not do) and drops a default `:443`. New
  instruction kind `address`.
* **Server, `POST /api/agent/v1/address`** (`agentapi/move.go`,
  `agents.Service.ConfirmAddress`): signs only for an enrolled device (the
  route's signature check, retired devices refused), for an address that is
  among the origins agents are served on, and only when the request's `Host`
  is that address. The key is the one the device trusts (ADR-0057), recorded in
  `issued_instructions` under the request's nonce in the transaction that
  signs. With no key the route answers `503 address_unconfirmable`; for any
  other address `421 address_not_served`.
* **Server, `POST /api/agent/v1/move`** (`agents.Service.Moved`): takes the
  agent's report of a change of address or of why it could not, in its own
  path and not in a heartbeat field, and audits it as `device.address_change`
  or `device.address_change_failed` with the way (`set-server`, `install`,
  `fallback`), both addresses and the error (bounded, cleaned). A server
  without the route answers 404 and the agent drops the report, once.
* **`server_env_pairs`** (migration `00102`) and `server/internal/serverenv`:
  each server makes a random ID at its first start, keeps it in
  `<data dir>/server-id` (written aside and linked into place, so racing starts
  agree; a damaged file is replaced and logged), and records the pair
  `EASYRMM_PUBLIC_URL` and `EASYRMM_MESH_PUBLIC_URL` name under it, with when
  the pair was recorded (it changes only when the pair does) and when the
  server was last seen: at each start and hourly. A record that cannot be
  written is logged and tried again every minute. Row-level security and the
  grants follow `job_keys` (the system scope only). Nothing reads it yet.
* **Agent**:
  * `agent/client`: `ConfirmAddress` (signed request to the new address,
    following no redirect, a 404 or any other answer a failed check, the
    confirmation verified against the agent's own nonce and the address it
    dialled), `Moved`, and `Options.NoRedirect`.
  * `agent/state`: `address.json`, a file of its own that a build that does not
    know it neither reads nor rewrites (`SaveConfig` leaves it alone), holding
    the addresses the agent left, newest last (at most 8); `SetServer` writes it
    before `agent.json`, so an interruption leaves an agent that is where it was
    and never one that is somewhere new with no way back. A new enrollment
    forgets it.
  * `agent/move`: the check, the wait for running jobs and installs (as an
    update waits), the switch and the reports (a failure at the address the
    agent is at, a success at the new one), and `Fallback`.
  * `easyrmm-agent set-server https://rmm.example.com` (root or administrator),
    which restarts the agent's service; `easyrmm-agent install` and `enroll`
    run again on an enrolled computer: for an address the agent moved from they
    say "Already enrolled; this server is now at ..." and succeed, for another
    address they run the check and switch if this server confirms it, and
    otherwise refuse as before; `easyrmm-agent status` shows the previous address.
  * The running agent falls back: after an hour in which every heartbeat failed
    (and then at most hourly while they go on failing) it runs the check at the
    address it last moved from, and if that confirms itself it switches back and
    restarts. A restarted process counts its hour from its own start; downtime of
    both addresses changes nothing, as the check fails.
* The console's audit list labels the two new actions.

## Tests

Unit (`agentproto`, `agent/state`, `agent/move`, `agent/client`, `agent/runner`,
`agent/cmd/easyrmm-agent`) and, against a real PostgreSQL (build tag
`integration`): `serverenv` (the record, its time rules, the system scope only,
the retry loop, the ID file and racing starts), `agents` (the confirmation and its
record by nonce, the move reports), `agentapi` (both routes over HTTP, and the
agent's own client against the real handler, ring and database over TLS), and
`app` (the recorder from a configuration).

Coverage floors added to `scripts/ci/check-coverage.sh`: `agent/move` 85 (measured
89), `server/internal/serverenv` 80 (measured 84).

## Not built here (later slices)

The signed `move` instruction and `move.easyrmm` (slice 4), the EasyPatch
agent's `set-server` and the agent running it after its own move (slice 2),
MeshAgent following (slice 3), `name_moves`, the console, the alert for a
confirmation that does not verify (the agent audits it as a failed change, but
no alert is raised), the alert for a record that cannot be written (it is
logged), the shared-ID alert and **Forget**, and the required upgrade stop at
this release (`upgradeFrom` in the release manifest; the release itself is cut
separately).

The ADR names `<data root>/server/server-id`; the file is `server-id` in the
server's data directory (`EASYRMM_DATA_DIR`), which is `/srv/easyrmm/server` on
the host.

## CHANGELOG

```
- **Move an agent between a server's addresses by hand**
  ([ADR-0061](docs/architecture/adr/0061-moving-to-a-new-name.md), slice 1).
  `easyrmm-agent set-server https://rmm.example.com` asks the address to
  confirm itself with a signature by a job key the agent trusts, over the
  agent's own request, and only then makes it the agent's server; `install`
  run again on an enrolled computer does the same for an address it was not
  given before, and succeeds quietly for one the agent moved from. An agent
  whose server has not answered for an hour goes back to the address it
  moved from if that confirms itself. The server answers the check on
  `/api/agent/v1/address` for the addresses it serves agents on, takes the
  agent's reports on `/api/agent/v1/move` and audits them. Nothing moves
  agents by itself yet.
- **A record of the names each server's `.env` gives it**
  ([ADR-0061](docs/architecture/adr/0061-moving-to-a-new-name.md), slice 1).
  Each server keeps a random ID in its data directory and records its
  `EASYRMM_PUBLIC_URL` and `EASYRMM_MESH_PUBLIC_URL` pair under it, at every
  start and hourly (migration 00102). Nothing acts on it yet; the release that
  moves agents starts from it.
```
