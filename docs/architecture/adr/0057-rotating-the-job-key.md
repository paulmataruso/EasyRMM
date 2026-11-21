# ADR-0057: Rotating the job key

* Status: Proposed (2026-11-21). Not implemented.
* Builds on: [ADR-0015](0015-enrollment-and-meshagent-delivery.md) (signed
  requests, MeshAgent's signed downloads),
  [ADR-0017](0017-scripts-and-jobs.md) (the job key),
  [ADR-0027](0027-agent-updates.md), [ADR-0031](0031-easypatch-agent-install.md)
  and [ADR-0050](0050-removing-a-device.md) (the other instructions it
  signs), [ADR-0008](0008-unified-endpoint-installer.md) and
  [ADR-0016](0016-ip-address-access.md) (MeshAgent's own pin of MeshCentral).
* Amends: [ADR-0017](0017-scripts-and-jobs.md), "Signing" and
  "Consequences": the agent follows a signed hand-over instead of refusing
  every other key, and a lost key means re-pinning, not re-enrolling;
  [ADR-0052](0052-the-host-updater.md), "Rollback": how the updater tells
  that a rollback would cross a cut-over.
* Part of [the feature plan](../feature-plan.md): F0. F1 (signed settings),
  feature 8 (the WebSocket channel) and 5c (moving to a new name) depend
  on it.

## Context

**What the key signs.** One Ed25519 key signs everything the server asks
an agent to do. Five signature contexts in `internal/agentproto` use it:
jobs (`EASYRMM-JOB-SIG-V1`, `jobs.go`), agent updates
(`EASYRMM-UPDATE-SIG-V1`, `update.go`), uninstalls
(`EASYRMM-UNINSTALL-SIG-V1`, `uninstall.go`), EasyPatch agent installs
(`EASYRMM-EASYPATCH-INSTALL-SIG-V1`, `easypatch.go`) and, since the plan's
fixes, MeshAgent's binary and `.msh` (`EASYRMM-DOWNLOAD-SIG-V1`,
`download.go`). Jobs are signed when they are delivered, not when they are
created (`claim` in `server/internal/jobs/delivery.go`), so nothing stored
in the database carries a signature.

**Where the server keeps it.** `jobs.LoadKey`
(`server/internal/jobs/key.go`) reads the seed from the `settings` row
`jobs.signing_key`, sealed with `EASYRMM_SECRET_KEY`
(`server/internal/secrets/seal.go`: AES-256-GCM, additional data
`easyrmm:jobs.signing_key`). It makes the key on first start (when several
servers start at once, the first one stored wins) and seals it again when
the encryption key has changed. `server/internal/app/app.go` loads it once
at start and hands the private key to the jobs service, to the agents
service (updates, uninstalls, download signatures) and to the EasyPatch
service (install instructions). The public key goes out in every
enrollment and heartbeat answer (`server/internal/agents/enroll.go`,
`heartbeat.go`).

**How the agent pins it.** The agent stores it in `agent.json`
(`agent/state/state.go`, `Config.JobKey`) from its enrollment answer, or
from the first heartbeat answer that carries one. `pinJobKey`
(`agent/cmd/easyrmm-agent/main.go`) never follows a change: once an hour it
logs that the key differs and that the agent should be reinstalled. The
updater, the EasyPatch installer, the remover and MeshAgent's install
(`installMesh` in `agent/runner/runner.go`) read the pinned key through
`pinnedKey`. The job worker keeps its own copy (`SetKey` in
`agent/jobs/worker.go`) and reports a job whose signature does not verify
as failed. The uninstaller, started outside the service, checks its saved
instruction again (`agent/cmd/easyrmm-agent/removal.go`).

**What vouches for the server's answers.** Agents sign every request with
their device key (ADR-0015), which proves the agent to the server. The
server's answers are vouched for by TLS, against the system's roots or
EasyRMM's own authority (ADR-0016), and by the job key. Agents pin no TLS
key. The job key is what stops a TLS-intercepting middlebox, or a
certificate wrongly issued for the server's name, from running anything on
a device.

**What does not rest on it.** MeshAgent authenticates MeshCentral by
MeshCentral's own identity, which its `.msh` names (ADR-0008) and which
MeshAgent pins (ADR-0016), not by the job key or the system's roots. The
EasyPatch agent trusts EasyRMM's authority for TLS (ADR-0042) and installs
only updates signed by the release keys built into it
(`easypatch/agent/EasyPatch.Agent.Core/Security/ReleaseKeyRing.cs`). The key
that signs EasyRMM's statements to the patching engine
(`EASYRMM_PATCHING_KEY`, ADR-0038) is another key. None of these changes
with the job key. The only link is the EasyPatch install instruction,
which EasyRMM's agent checks with the job key.

**It cannot be rotated.** ADR-0017 said so: rotating needs a signed
hand-over that agents accept, and until then a server restored without its
secret key must re-enroll its agents. The plan puts more on the same key
(signed settings, a new address, WebSocket messages), so it becomes
rotatable first.

**Why rotate.**
* **Compromise.** The seed leaked, or may have: the database and `.env`
  together (a backup set, a copied disk), or the host.
* **Planned.** Hygiene: someone who held the server's secrets left, a
  policy asks for a yearly rotation, an incident nearby.
* **Moving the deployment.** The key is bound to no name, so a move to a
  new name (5c) does not need one by itself. It does when the move goes
  with a new host or a new operator (an install restored onto a new host,
  an MSP taking over a deployment): rotating after the move leaves the old
  host's disks, its backups and whoever ran it with a key no agent trusts.

**Two facts that shape the design.**
* The server decodes agent requests strictly (`decode` in
  `server/internal/httpapi/agentapi/agentapi.go`,
  `DisallowUnknownFields`); the agent decodes the server's answers
  leniently (`agent/client/client.go`). A new field in an answer is ignored
  by older agents. A new field in a request is refused, with 400, by an
  older server, such as one ADR-0052 has rolled back to.
* Several servers may share one database (ADR-0017's delivery, `LoadKey`'s
  first-stored rule), so a key change must reach all of them.

## Decision

### One ring of keys, each with a generation
* The server keeps its job keys in a table of their own, `job_keys`: for
  each key its **generation**, its public key, its seed sealed as today
  (with `EASYRMM_SECRET_KEY`; the additional data now names the
  generation, `easyrmm:job_key:<generation>`), when, by whom and why it was
  made, and when it was cut over to, marked compromised, or forgotten.
* **Generations only increase, even across a restore.** A new key's
  generation is the time it is made in milliseconds, at least one more
  than the highest in the ring (the rule F1 uses for settings versions). A
  server restored from an older backup still makes keys newer than any it
  made before the restore.
* The existing key moves into the ring as generation 1 on the first start
  with this ADR, in one transaction that also removes the `settings` row. A
  fresh install makes generation 1 as `LoadKey` makes the key now.
* A package of its own, `server/internal/jobkeys`, holds the ring. The
  jobs, agents and EasyPatch services ask it for the key to sign each
  device's instruction; none keeps a key of its own. Every server reloads
  the ring every 30 seconds and whenever an agent names a key it has not
  loaded, so servers on one database agree within seconds.
* A key's **fingerprint**, wherever a person reads it, is the first 32
  hexadecimal digits of the SHA-256 of its public key, in groups of four.

### What agents report
* An agent keeps the keys it trusts in `agent.json`, each with its
  generation, at most four: two during a rotation, three when a rotation
  for a compromise starts during another's overlap. `jobKey`, today's
  field, holds the oldest of them. A build from before this ADR reads only
  that field, and a server from before this ADR signs only with the old
  key, so an agent moved back to an older build (a rollback of its update,
  ADR-0027, or of the server, ADR-0052, during an overlap) still trusts
  the key that is used for it.
* Its heartbeats and job polls carry them (`jobKeys`: each key and its
  generation). The report is in the request's body, so the device's
  signature covers it: something between the agent and the server can drop
  it but not change it.
* The agent sends the report only to a server that has answered with
  `jobKeyGeneration` (below), and remembers that in `agent.json`, so its
  first requests after a restart carry the report too. When a request with
  the report is refused as malformed, it forgets that and sends the request
  again without it, so it keeps working with a server rolled back to a
  release before this ADR.

### Two statements
Both are signed with a job key under a context of their own, bound to one
device and valid for 10 minutes, like the other instructions, and travel
in the heartbeat answer (and on the WebSocket channel once it carries
instructions, ADR-0059).

* **The hand-over** (`EASYRMM-JOB-KEY-HANDOVER-V1`): "the server's newer
  key is K, generation G", signed with a key the device already trusts.
  The agent accepts it only if it is signed by a key it trusts, is for its
  device and not expired, introduces a key it does not trust yet, with a
  generation above every one it trusts and no more than a day ahead of its
  own clock, and leaves it with at most four keys. It then trusts both.
* **The cut-over** (`EASYRMM-JOB-KEY-CUTOVER-V1`): "trust only K", signed
  with K. The agent accepts it only if K is the newest key it trusts. It
  then drops the others, keeping their fingerprints to name them in
  errors.
* The agent writes `agent.json` before it acts on either. It handles the
  hand-over before the cut-over, and both before the answer's
  instructions, which it checks with the keys it now trusts. It reports a
  statement it refused, with the reason, in its next heartbeat.
* Every verifier in `agentproto` (`VerifyJob`, `VerifyUpdate`,
  `VerifyUninstall`, `VerifyEasyPatchInstall`, `VerifyDownload`) takes the
  keys the agent trusts and accepts a signature by any of them.

### What the server signs with
* For each device, the newest key the device reported in this request
  that the server holds (its seed is in the ring). A request without a
  report gets the oldest key of the device's last report: a build that
  cannot follow reads that one from `jobKey`, and an agent that can follow
  sends a report to every server that understands one. For a device that
  never reported, the key it was given at enrollment (generation 1 for
  devices enrolled before this ADR). The device's row keeps its last report
  and when it came.
* Enrollment, with a deployment token or after approval (ADR-0015,
  ADR-0024), gives the ring's newest key.
* Enrollment and heartbeat answers keep `jobKey`, which is now the key the
  server signs with for that device, and add `jobKeyGeneration`.
* The **hand-over** is offered to a device that reports keys and lacks the
  ring's newest one, signed with the key the server signs with for it. The
  **cut-over** is offered once the newest key has been cut over to, to a
  device whose report has that key and any other. Neither goes to a device
  while an agent update is open for it (ADR-0027), so a build that rolls
  back never finds its keys changed underneath it.
* So no device is sent an instruction signed with a key it may have
  dropped: it drops keys only on a cut-over, which it is sent only after it
  reported the newer key, and from that report on the server signs with
  the newer key.

### A rotation
1. **Start.** A super administrator, or the host (below), gives the
   reason: planned, moving the deployment, or compromised. The server
   makes the new key under an advisory lock, so one rotation starts at a
   time; a rotation for a compromise may start during another's overlap,
   and its key is handed to every device from whichever key it trusts.
   Enrollments get the new key at once.
2. **Following.** Within a heartbeat each agent that can follow gets the
   hand-over, trusts both keys and reports them; from that report on, its
   instructions are signed with the new key.
3. **Cut-over.** Planned and moving rotations: when a super administrator
   finishes the rotation (next section). A rotation for a compromise: as it
   starts. Each device then gets the cut-over with the heartbeat after its
   report shows the new key.
4. **After.** The old key's seed is kept, for hand-overs only, while any
   device may still trust it: an enrolled device whose last report has it,
   one that never reported, or a device removed in the last 90 days that
   ADR-0050 still answers with an uninstall instruction. Once none is left,
   the seed is deleted; the public key and its record stay. A super
   administrator may **forget** it sooner; the devices still on it then
   need re-pinning (below).

### The overlap
* A planned rotation, or one for a move, ends only when a super
  administrator **finishes** it, no sooner than **24 hours** after it
  started, confirming that a backup taken since it started exists. Every
  super administrator is reminded after 7 days. It never ends by itself:
  that would end the protection older backups have without anyone having
  made a newer one.
* 24 hours is ADR-0052's window for rolling back a confirmed upgrade, so a
  planned rotation never takes away a rollback the console still offers.
* While both keys are trusted, a restore or a rollback to a backup from
  before the rotation still works (its server signs with the old key,
  which agents still accept), instructions signed with the old key on
  their way still verify (an uninstall saved for the uninstaller, a job a
  server signed before it loaded the new key), and there is time to take a
  backup that holds the new key.
* A rotation for a compromise has no overlap. Each device gets the
  hand-over in one heartbeat answer and the cut-over in the next.

### Agents offline across the overlap
* An agent offline from before the rotation until after its cut-over
  still trusts only the old key, which the server keeps. Its first
  heartbeat answer hands it the new key and the next cuts over: within two
  heartbeats, two minutes. Jobs it receives meanwhile are signed with the
  old key, which it still trusts. Nobody has to do anything.
* The console lists devices still on an older key with when each was last
  seen. Only a device whose key the server no longer holds (forgotten, or
  lost with a restore, below) needs someone: it shows as **needs
  re-pinning**.

### Agents that cannot follow
A build from before this ADR sends no report and ignores the statements.
It keeps getting what the server signs with the key it pinned, agent
updates (ADR-0027) included, which bring it a build that can follow; with
its first report it moves like the others. The console shows how many
devices cannot follow and why (their agent's version; agent updates set to
*When asked* or *Off*), with a link to Agent updates. Their key stays
alive until they move (above).

### A compromised key
* **The old key still carries the hand-over**, and the console says what
  that proves. Whoever holds the leaked key and can answer a device's
  requests (a TLS position: an intercepting proxy, or a certificate for the
  server's name) could already run anything on it, before the rotation as
  after, and could hand it a key of their own whatever the server does.
  Refusing to use the old key would not stop them; it would leave every
  device to be re-pinned by hand. What the server does instead is believe
  a move only when the device's own report, signed with its device key,
  which nobody in the path can forge, says it trusts exactly the new key.
  A device that reports another key, or never reports, shows as such.
* **Unknown keys.** A report with a key the ring has never held is
  recorded on the device, audited, and shown to super administrators as
  **trusts a key this server never issued**. Its causes: someone holding a
  key the device trusts, in a position to answer it, handed it one; this
  server was restored from a backup older than a rotation (below); or
  someone ran `trust-key` on the device with another key. The console names
  all three. The flag clears when the device no longer reports that key. It
  works from the first slice, before any rotation exists: a hand-over
  nobody at the server made shows at once.
* **Re-pinning a device.** `easyrmm-agent trust-key <key>`, run as root or
  administrator on the device, replaces the keys the agent trusts with the
  one given (the console prints it as `<generation>:<key>`, with its
  fingerprint) and restarts the agent's service. The key is public, so the
  command carries no secret and can be run:
  * in a terminal session through MeshCentral: the device's page shows the
    command beside **Open terminal** to anyone with `device.terminal`
    there. MeshAgent authenticates MeshCentral by MeshCentral's own
    identity, so this channel does not depend on what leaked, unless
    MeshCentral's data leaked too;
  * by Group Policy, Intune or the customer's own tools, for many devices
    at once;
  * by hand at the device.

  The device keeps its identity, its history and its MeshAgent; nothing is
  enrolled again.
* **Reinstalling** (uninstall, then the install command) is for devices
  that may have run what they should not have: a new device key and a new
  enrollment, trusting the key on first use as at the first install
  (ADR-0017's caveat). It comes back as a new device (ADR-0024).
* **What leaked decides what to do.** The guide's incident page:

  | What leaked | The job key | MeshCentral's channel | What to do |
  |---|---|---|---|
  | A database dump, without `.env` | Safe: sealed | Not involved | Nothing has to be rotated; a planned rotation if unsure |
  | `.env`, without the database | Safe: the seed is in the database | Not involved | Rotate the encryption key ([docker.md](../../deployment/docker.md#rotating-the-encryption-key)), then a planned rotation, since any earlier database backup opens with that `.env` |
  | `.env` and a database dump together (a backup set) | Compromised | Intact, unless `/srv/easyrmm/meshcentral` went too | Rotate the encryption key, then the job key as compromised; re-pin devices that do not confirm through MeshCentral's terminal |
  | The host | Compromised | Compromised | Rebuild the host from a known state and restore; a new encryption key; MeshCentral's identity replaced, so MeshAgent is installed again everywhere ([backup-restore.md](../../operations/backup-restore.md)); the job key rotated as compromised; devices that do not confirm re-pinned through Group Policy, Intune or by hand |

  The rotation comes after the cause is gone and the encryption key is
  new: a key made on a host the attacker still controls, or sealed with a
  key they hold, is compromised as it is made.
* **A lost key.** If the seed cannot be opened (a restore without `.env`)
  or is gone, the server still refuses to start, as now, so that a
  mistaken `EASYRMM_SECRET_KEY` is fixed in `.env`, not by losing the key.
  `docker compose run --rm server easyrmm-server job-key replace-lost`, on
  the host, marks it lost and makes a new key with no hand-over; every
  device then needs re-pinning.
  This replaces ADR-0017's re-enrollment.

### Storage, backups and restore
* The ring lives in the database, sealed with the encryption key, so the
  guide's backup (the database dump and `.env`) carries it; nothing new is
  backed up. Keys are sealed again at the next start after the encryption
  key changes, as now.
* A restore across a rotation depends on when its backup was taken:

  | Backup taken | Restored before the cut-over | Restored after the cut-over |
  |---|---|---|
  | Since the rotation started | Works | Works: the restored server holds the new key and signs with what each device reports |
  | Before the rotation started | Works: agents still trust the old key. Devices that had moved show the new key as unknown, with the reason; the next rotation's cut-over ends their trust in it | Devices that moved trust only a key the restored server never held: they need re-pinning, or a newer backup restored |

* The server signs from each device's report, not from what its restored
  rows say. That is why a backup from the overlap works after the cut-over
  with nothing to do.
* A job or any other instruction for a device that **needs re-pinning** is
  refused at once, with the command that fixes it, instead of queued to
  fail. Removing such a device skips the uninstall instruction it could not
  verify and goes as **Remove anyway** does (ADR-0050).

### The updater's rollback (amends ADR-0052)
ADR-0052 refuses a rollback across a cut-over. This is how:

* At step 3 of an upgrade, when every other service has stopped and
  PostgreSQL has not yet, the updater reads the ring's highest generation
  (1 for a database from before this ADR, which has no ring) and keeps it
  with the backup.
* **Roll back** after a confirmed upgrade first reads, before it stops
  anything, the newest generation that has been cut over to. If that is
  above the backup's, the rollback is refused and nothing stops: "Agents
  moved to a signing key made after this backup, on <time>; restoring it
  would leave them unable to accept anything from the server." Otherwise
  it goes ahead; when the live ring held a newer key than the backup, its
  record says so: devices that moved keep trusting that key until the next
  rotation's cut-over.
* A rollback during an upgrade cannot cross a cut-over: the new version is
  held, and neither the console nor the host command rotates while `hold`
  exists. The same check runs anyway.
* The updater's status gains the backup's generation, so the console shows
  that **Roll back** is gone, and why, before anyone tries, and the
  dialogs that would end it say so first.
* Because of the 24-hour minimum, only a rotation for a compromise, or one
  finished early from the host, can make a rollback impossible.

### Who may rotate
* **Super administrators** (`settings.manage` platform-wide, as for signed
  agent builds), with step-up: their password, as for adding a security key
  (`reauthenticate` in `server/internal/auth/service.go`), or, for a user
  with no password (single sign-on only), a sign-in within the last 10
  minutes (the session's `AuthenticatedAt`). The same holds for finishing
  and forgetting.
* **The host**, as root, through `docker compose exec server
  easyrmm-server job-key …`, for an incident where the console cannot be
  reached or trusted. Whoever is root on the host already holds everything
  the key protects. `replace-lost` exists only there.
* While a rotation is in progress, and after one that ended a rollback,
  every super administrator sees a banner.
* One key for the whole server: organizations have no keys of their own,
  and their administrators cannot rotate.

### Console
* **Settings → Agent signing key**, for super administrators:
  * the current key: fingerprint, when and by whom it was made, how many
    devices trust it, its age;
  * **Rotate key**: the reason, and what follows from it: for a planned
    rotation or a move, an overlap of at least 24 hours finished by hand;
    for a compromise, a cut-over at once and, when the updater offers a
    rollback, its end. Each says to take a backup now;
  * during a rotation, its progress: devices moved; devices still on an
    older key (online, or offline since when); devices that cannot follow,
    with their agent's version; devices that need re-pinning; devices that
    trust an unknown key. Each count opens the devices list filtered;
  * **Finish rotation**: from 24 hours on, with the backup confirmation and
    the devices not moved yet (they follow when they come back);
  * older keys still held, for how many devices, with **Forget** and the
    devices it would leave needing re-pinning.
* **Devices**: the signing key's state as a column and a filter: *Current*,
  *Moving* (trusts the new key and older ones), *On an older key*, *Cannot
  follow*, *Needs re-pinning*, *Trusts an unknown key*.
* **A device's page**: its state; for the last two, the re-pin command,
  **Open terminal** when MeshAgent is connected, and the reasons.

### API and host commands
* `GET /api/v1/settings/job-key`: the ring (fingerprint, generation,
  reason, made, cut over, compromised, for how many devices it is kept),
  the rotation's progress, when it may be finished, and whether finishing
  it ends the updater's rollback.
* `POST /api/v1/settings/job-key/rotations` (`reason`, `password`);
  `POST /api/v1/settings/job-key/finish` (`backupTakenSinceStart`,
  `password`); `POST /api/v1/settings/job-key/keys/{generation}/forget`
  (`password`). Super administrators only.
* Device lists and a device's page gain the state, under `device.view` like
  any other field.
* On the host, through `docker compose exec server`, or `docker compose run
  --rm server` when the server is not running: `easyrmm-server job-key
  status`, `rotate --reason planned|moving|compromised`, `finish [--now]`
  (`--now` skips the 24 hours, and its record says so), `forget
  <generation>` and `replace-lost`. Each refuses while the updater holds
  the server.
* On the device: `easyrmm-agent status` lists the keys the agent trusts,
  with fingerprints and generations; `easyrmm-agent trust-key`.

### Audit records
| Action | When | Details |
|---|---|---|
| `job_key.rotate` | A rotation starts | Reason; the new key's fingerprint and generation; the keys it follows; console or host |
| `job_key.finish` | A planned rotation is cut over to | Devices in each state; the backup confirmation; whether `--now` skipped the minimum |
| `job_key.forget` | A seed is deleted | By a person, or by the server once no device needs it; the devices it left needing re-pinning |
| `job_key.replace_lost` | The host replaces a lost key | The lost key's generation; the new key |
| `device.job_key_unknown` | A report names a key never issued | The key's fingerprint and generation (recorded as the agent) |
| `device.job_key_unknown_cleared` | That key is gone from the device's report | The key's fingerprint |
| `device.job_key_refused` | An agent refused a statement whose signature did not verify | The statement and the agent's reason |

A wrong password at step-up is audited by `reauthenticate`, as for other
sensitive changes. One device's move is not audited: its row keeps when it
reported which key, and the finish record counts them; 10,000 records per
rotation would bury the ones above. Forwarding (ADR-0023) carries these
like any other.

### What depends on this
* **Everything new the server signs for an agent goes through the ring**,
  with the device's key; nothing keeps a copy of a key.
* **F1, signed settings (ADR-0058)**: an agent checks a settings document
  when it receives it and keeps it as checked; it does not check it again
  later against keys it may have dropped since.
* **Feature 8, the WebSocket channel (ADR-0059)**: the report travels with
  heartbeats on the channel; what the server signs on a connection uses the
  key from that device's latest report; the statements may travel on it
  like other instructions.
* **5c, moving to a new name**: the move is signed like any instruction.
  A rotation and a move are independent; each device follows each by its
  own statements. The guide advises finishing one before starting the
  other, and rotating after a move that leaves a host behind. A device
  offline past both the old name's cut-off and its key's removal needs
  `trust-key` and the local step 5c's ADR gives for the address, or a
  reinstall.
* MeshCentral's identity, the EasyPatch agent and the engine's statement
  key are unchanged (Context).

## Options considered
* **Every instruction signed with both keys during the overlap.** It needs
  a wire format with several signatures everywhere and still needs agents
  to learn the new key. Choosing the key from the device's report needs
  neither.
* **The new key fetched over TLS.** TLS alone is what the job key exists
  not to rely on.
* **A cut-over at a fixed time.** It would end the protection of older
  backups whether or not a newer one exists; a person confirms one
  instead.
* **A compromised key never used again; every device re-pinned by hand.**
  No safer (above), and not workable for an MSP's fleet.
* **An offline recovery key** that the operator keeps outside EasyRMM,
  that agents pin and that signs new job keys, as ADR-0049 leaves code
  signing keys with operators. A compromise could then be handled without
  the compromised key at all, at the price of a key someone must keep and
  find in an incident. Left to the owner, as an ADR of its own; the
  statements here leave room for it (a hand-over signed by another trusted
  key).
* **EasyRMM re-pinning devices through MeshCentral by itself.** It would
  give the server a second way, beside the job key, to run commands as
  root on every device, a path ADR-0022 and ADR-0033 have kept narrow. A
  person runs the command through a terminal session instead.
* **A key per organization.** More keys to rotate, and no gain while one
  server holds them all.

## Testing
* **Unit** (`internal/agentproto`, `agent`): the statements signed and
  verified; each refusal (a signer not trusted, another device, expired, a
  generation not above, more than a day ahead, a fifth key, a cut-over by a
  key that is not the newest, unknown fields); each verifier with two keys;
  the trust store's writes, `jobKey` kept as the oldest, and a build from
  before this ADR reading it; the report sent only to a server that
  understands it, remembered across a restart, and sent again without it
  after a 400; `trust-key` and `status`. The agent tests run on CI's
  Windows runner too (`backend-tests.yml`, *Agent tests on Windows*),
  `trust-key`'s service restart included.
* **Integration** (PostgreSQL, with the race detector): the key moved from
  `settings` into the ring byte for byte, and sealed again after the
  encryption key changes; the key per device from its reports; the
  hand-over and the cut-over offered exactly when due; two servers on one
  database, one starting a rotation while the other signs with the new key
  for a device that reported it; generations above a restored ring's;
  unknown keys flagged and cleared; a seed kept while a device, or a
  removed device, needs it and deleted after; instructions refused for a
  device that needs re-pinning; the API's permissions, step-up and audit
  records; nothing while held.
* **Console**: the page, its dialogs and the device states, in the
  console's checks.
* **The bundle test, with real agents, every machine on the host's
  network** (`--network host`, as `scripts/e2e/bundle.sh` runs its machine
  today; never a bridge network):
  1. machine 1, today's Debian machine with systemd, online throughout;
     machine 2, the same build, enrolled, then its agent stopped; machine 3
     with the agent of the last release before this ADR's first slice, by
     its tag, checked against that release's `SHA256SUMS`;
  2. a planned rotation, through the API until slice 3 and through the
     console with step-up from then on: machine 1 reports both keys within
     a heartbeat and runs a script signed with the new key; machine 3 shows
     *Cannot follow*, is updated by the server, then follows;
  3. finished from the host with `--now`: machines 1 and 3 report only the
     new key (`easyrmm-agent status`) and run a script; MeshAgent removed
     from machine 1 and installed again, its download verified with the new
     key; the EasyPatch agent installed through EasyRMM after the cut-over;
  4. machine 2's agent started: the hand-over, the cut-over and a script,
     within two heartbeats;
  5. a rotation for a compromise with machine 2 stopped again: it follows
     once started;
  6. on machine 2, `trust-key` with a key the server never issued: flagged
     and audited; then `trust-key` with the server's key: cleared, and a
     script runs. The test runs it with `docker exec`, a stand-in for
     MeshCentral's terminal; the terminal session itself is checked by hand
     on the owner's instance and recorded.

  The machines share the host's network; each has its own state and its
  own MeshAgent. If two MeshAgents cannot share one network namespace, the
  slice that finds it says how it was solved, never with a bridge network.
* **A restore across a rotation:**
  * ADR-0052's upgrade test on CI gains a real agent on the runner's
    network. After a confirmed upgrade: a planned rotation started, then
    **Roll back**; the agent reaches the restored server (which, from a
    release with this ADR, shows the newer key as unknown), is moved back
    to that server's build, and runs a script. Then an upgrade again, a
    rotation finished with `--now`, and **Roll back** refused with nothing
    stopped.
  * The backup-restore drill (`scripts/drill/backup-restore.sh`, whose
    agent runs on the host's network) takes one backup before a rotation
    and one during its overlap, finishes the rotation, restores the second
    (the agent runs a script, nothing done), then the first (the device
    needs re-pinning, and a job is refused with the command), then runs
    `trust-key`. Recorded in [drills.md](../../development/drills.md).
* **Then** the owner's instance on the edge channel: a planned rotation
  through the console with their real Windows and Linux devices.

## Slices
1. **Agents that can follow, and the ring.** The statements and the report
   in `agentproto`; the agent's trust store, the report's gating,
   `trust-key` and `status`; the ring, the move from `settings`, the key
   chosen per device (one key so far), and unknown keys flagged. No way to
   rotate yet. It can merge before the rest of the plan's step 9: the
   sooner such agents are in the field, the fewer devices a first rotation
   finds unable to follow.
2. **Rotation**: the statements offered; start, finish, forget and
   replace-lost through the API and the host, with their audit records;
   the bundle test.
3. **Console**: the page, the devices' states, the re-pin helper; the
   bundle test through the console.
4. **Restore and rollback**: the updater's check and status field
   (ADR-0052), the drill, and the guide: a page on rotating and on
   incidents, with backup-restore.md, docker.md's encryption key steps and
   the threat model updated.

## Consequences
* The job key can be rotated with no downtime, and with nothing to do for
  devices that are online, or come back while the server still holds their
  key.
* A compromise is answered with a rotation that counts a device as moved
  only on its own signed report; the devices that do not confirm are
  re-pinned with a command that carries no secret, through MeshCentral,
  Group Policy, Intune or by hand.
* A key handed to a device that this server never issued shows at once,
  from the first slice.
* ADR-0017's "must re-enroll its agents" after a lost key becomes "must
  re-pin them".
* Backups from before a rotation stop restoring a working fleet once it is
  cut over to. Finishing asks for a newer backup, and the updater refuses
  such a rollback.
* Old keys stay sealed in the database while any device may need them.
* Agents send one more field in two requests, only to servers that
  understand it.
* **The rollback problem is wider than this ADR.** A release that adds any
  field to an agent request is refused by the server ADR-0052 rolls back
  to, so agents that updated in the meantime would not reach it to be
  moved back to its build. This ADR avoids it for its own field; a rule
  for every request belongs in ADR-0052 or ADR-0009.
