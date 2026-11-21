# ADR-0057: Rotating the job key

* Status: Proposed (2026-11-21). Not implemented.
* Revised (2026-11-21) after an independent review: what a leaked backup
  set gives besides the job key, the key the server signs with, the order
  in which devices are moved, generations, older servers on a migrated
  database, the updater's rollback, a lost key, and the protocol rule now
  in ADR-0009 (amended, PR #52); step-up as ADR-0055 defines it; and the
  six needs ADR-0058 and ADR-0059 list. Revised again after a second
  check: devices left on a lost key, the record of issued instructions,
  the updater's rollback (its first release, the hold, other hosts), a
  shorter declared transition, the authority replaced in two phases, and
  the patching engine's part of a leaked backup set.
* Builds on: [ADR-0009](0009-agent-protocol.md) (amended, PR #52: how the
  protocol evolves), [ADR-0015](0015-enrollment-and-meshagent-delivery.md)
  (signed requests, MeshAgent's signed downloads),
  [ADR-0017](0017-scripts-and-jobs.md) (the job key),
  [ADR-0027](0027-agent-updates.md), [ADR-0031](0031-easypatch-agent-install.md)
  and [ADR-0050](0050-removing-a-device.md) (the other instructions it
  signs), [ADR-0016](0016-ip-address-access.md) and
  [ADR-0042](0042-agents-trust-easyrmms-authority.md) (EasyRMM's own
  certificate authority), ADR-0055 ("Step-up authentication").
* Amends: [ADR-0017](0017-scripts-and-jobs.md), "Signing" and
  "Consequences": the agent follows a signed hand-over instead of refusing
  every other key, and a lost key alone means re-pinning, not re-enrolling;
  [ADR-0052](0052-the-host-updater.md), "Rollback": what the updater
  records and refuses, a requirement written here for the updater being
  built.
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
in the database carries a signature. Updates and uninstalls are valid for
10 minutes (`updateValidity` in `server/internal/agents/updates.go`,
`UninstallValid` in `removal.go`), EasyPatch installs for 15
(`installValidFor` in `server/internal/easypatch/install.go`), and a job
until its run expires: 24 hours by default, up to 7 days
(`DefaultWaitHours`, `MaxWaitHours` in `server/internal/jobs/service.go`;
`ExpiresAt` set in `delivery.go`).

**Where the server keeps it.** `jobs.LoadKey`
(`server/internal/jobs/key.go`) reads the seed from the `settings` row
`jobs.signing_key`, sealed with `EASYRMM_SECRET_KEY`
(`server/internal/secrets/seal.go`: AES-256-GCM, additional data
`easyrmm:jobs.signing_key`). It makes a key whenever the row is missing
(when several servers start at once, the first one stored wins) and seals
it again when the encryption key has changed. `server/internal/app/app.go`
loads it once at start, after the internal certificate authority
(`pki.Load`) and MeshCentral's secrets (`remote.LoadSecrets`), and hands
the private key to the jobs service, to the agents service (updates,
uninstalls, download signatures) and to the EasyPatch service (install
instructions). The public key goes out in every enrollment and heartbeat
answer (`server/internal/agents/enroll.go`, `heartbeat.go`, and
`RetiredHeartbeat` in `removal.go`).

**How the agent pins it.** The agent stores it in `agent.json`
(`agent/state/state.go`, `Config.JobKey`) from its enrollment answer
(`agent/cmd/easyrmm-agent/main.go`, and `approval.go` after an approval),
or from the first heartbeat answer that carries one. It stores no
generation: none exists. `pinJobKey` (`main.go`) never follows a change:
once an hour it logs that the key differs and that the agent should be
reinstalled. The updater, the EasyPatch installer, the remover and
MeshAgent's install (`installMesh` in `agent/runner/runner.go`) read the
pinned key through `pinnedKey`. The job worker keeps its own copy
(`SetKey` in `agent/jobs/worker.go`) and reports a job whose signature does
not verify as failed (`accept`). The uninstaller, started outside the
service, checks its saved instruction again
(`agent/cmd/easyrmm-agent/removal.go`).

**What vouches for the server's answers.** Agents sign every request with
their device key (ADR-0015), which proves the agent to the server. The
device key is a file only root (on Windows SYSTEM and Administrators) can
read (`device.key`, `agent/state/state.go`), so it proves the agent only
as long as nothing else ran as root on the device. The server's answers
are vouched for by TLS and by the job key. Agents pin no TLS key. An agent
installed against EasyRMM's own authority (`internal` mode, ADR-0016)
trusts that authority, copied to `ca.pem` in its state directory at
install (`main.go`), *instead of* the system's roots
(`agent/client/client.go`, `Options.CAFile`); every other agent trusts the
system's roots. Go's verifier, which the agent uses, checks no revocation.
The job key is what stops whoever can answer a device's requests from
running anything on it.

**What does not rest on it.** MeshAgent authenticates MeshCentral by
MeshCentral's own identity, which its `.msh` names (the ServerID,
ADR-0008) and which lives in `/srv/easyrmm/meshcentral`
([backup-restore.md](../../operations/backup-restore.md)), not in the
database. (ADR-0016's pin is another one: MeshAgent pins the exact TLS
certificate it is served.) The EasyPatch agent trusts EasyRMM's authority
for TLS in `internal` mode (ADR-0042) and installs only updates signed by
the release keys built into it
(`easypatch/agent/EasyPatch.Agent.Core/Security/ReleaseKeyRing.cs`). The key
that signs EasyRMM's statements to the patching engine
(`EASYRMM_PATCHING_KEY`, ADR-0038) is another key. None of these changes
with the job key. The links are MeshAgent's download and `.msh`, and the
EasyPatch install instruction, which EasyRMM's agent checks with the job
key.

**What a leaked backup set gives besides the job key.** A complete backup
([backup-restore.md](../../operations/backup-restore.md)) is the database
dump, `.env` and the data directories. With the dump and `.env`, whoever
holds them can open:
* the internal authority and the server's TLS key (`tls.internal_ca`,
  `server/internal/pki/pki.go`), which `internal`-mode agents trust instead
  of the system's roots;
* MeshCentral's login and session keys (`meshcentral.secrets`,
  `server/internal/remote/secrets.go`): the login key mints MeshCentral
  sign-ins for any account;
* authenticator-app secrets, single sign-on client secrets, audit
  forwarding client keys, and the kept secrets of deployment and approval
  tokens (`server/internal/auth`, `sso`, `auditfwd`,
  `agents/tokens.go`).

The engine's keys (`/srv/easyrmm/easypatch/keys`) open its mail and
webhook credentials, and `.env` holds the statements key the engine
trusts; of its agents' credentials, the engine's database holds only the
public keys (After a leaked backup set, below).

`/srv/easyrmm/server` holds the ACME account and the certificates' keys
(autocert's cache, `server/internal/app/edge.go`), `/srv/easyrmm/tls` the
manual certificate's key, and `/srv/easyrmm/meshcentral` MeshCentral's
identity. A certificate key from the set works against agents until the
certificate expires, since nothing on the agent checks revocation. So
after a leaked backup set, answering a device is not rare: anyone holding
the set who can get between a device and the server (the same network, a
hotspot a laptop joins, DNS for the server's name) can answer it.

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
  an MSP taking over a deployment): the old host's disks, its backups and
  whoever ran it hold the same set as a leaked backup, and can answer
  agents from any path to them. Rotating the job key after the move leaves
  them with a key no agent trusts; the guide adds a new encryption key and
  the rest of "After a leaked backup set" (below), since a rotation alone
  leaves them the TLS identities.

**Two facts that shape the design.**
* **The protocol evolves by ADR-0009's rule** (amended, PR #52): a server
  of protocol level 2 ignores request fields it does not know and states
  its level in every heartbeat answer; an agent sends a field added after
  level 2 only while its last heartbeat answer came from a level-2 server
  or higher, so the first heartbeat of each process carries none; a
  feature the agent's behaviour depends on is listed in the answer; signed
  instructions stay strict on the agent, and the server sends a new one
  only to a build that reported understanding it. Answers stay lenient:
  older agents ignore new answer fields.
* Several servers may share one database (ADR-0017's delivery, `LoadKey`'s
  first-stored rule), so a key change must reach all of them, and a server
  from before this ADR must not keep signing with its own idea of the key.

## Decision

### One ring of keys, each with a generation
* The server keeps its job keys in a table of their own, `job_keys`: for
  each key its **generation**, its public key, its seed sealed as today
  (with `EASYRMM_SECRET_KEY`; the additional data now names the
  generation, `easyrmm:job_key:<generation>`), when, by whom and why it was
  made, and when it was cut over to, marked compromised, marked lost, or
  had its seed deleted.
* **Generations only increase, even across a restore.** A new key's
  generation is the largest of: the time in milliseconds; the ring's
  highest generation plus one; and the highest generation any device or
  removed device has reported, among those at most `MaxSkew` (5 minutes,
  `internal/agentproto/agentproto.go`) ahead of the server's clock, plus
  one. The ring's term covers keys this ring made; the reported term covers
  keys made before a restore that the restored ring never held, and keys
  someone handed a device (see "Unknown keys"). The bound is the one agents
  apply to a hand-over, so no report pushes generations far ahead, and a
  server whose clock is more than 5 minutes off cannot talk to agents
  anyway (requests outside `MaxSkew` are refused).
* **The move from `settings`**, on the first start with this ADR, in one
  transaction under an advisory lock: the seed becomes generation 1,
  sealed again under the new additional data (the same seed and public
  key; the sealed value differs, since the additional data does), and the
  `settings` row `jobs.signing_key` is replaced by a **tombstone**: a JSON
  string naming this ADR. An older server's `LoadKey` cannot read a string
  into its `storedKey` and fails (`key.go`), so it refuses to start against
  the migrated database instead of finding no row and making a key of its
  own. A fresh install makes generation 1 and writes the tombstone too.
* A package of its own, `server/internal/jobkeys`, holds the ring. The
  jobs, agents and EasyPatch services ask it for the key to sign each
  device's instruction; none keeps a key of its own. Every server reloads
  the ring every 30 seconds, and when a report names a key it has not
  loaded, at most once every 5 seconds; a key still unknown after a reload
  is remembered as unknown until the next periodic reload, so repeated
  reports of it cause no more reloads.
* A key's **fingerprint**, wherever a person reads it, is the first 32
  hexadecimal digits of the SHA-256 of its public key, in groups of four.

### What agents report
* An agent keeps the keys it trusts in `agent.json` (`jobKeys`), each with
  its generation, in a trust store of its own (`agent/trust`). It holds two
  in practice (a hand-over goes to a device that trusts one key, below),
  three when it also trusts a key the server never held, and refuses a
  fifth.
* `jobKey`, today's field, holds the oldest of them. A build from before
  this ADR reads only that field, and a server from before this ADR signs
  only with generation 1, so an agent moved back to an older build (a
  rollback of its update, ADR-0027, or of the server, ADR-0052, during an
  overlap) still trusts the key that is used for it. When `jobKeys` exists,
  the agent ignores `jobKey` on reading and writes it again, as the oldest,
  with every change.
* **A key without a generation.** `agent.json` from before this ADR, and
  enrollment answers from servers before it, carry `jobKey` alone
  (`main.go`, `approval.go`). The agent keeps that key with its generation
  unknown, and takes the generation from the first answer whose `jobKey`
  is the same key and which carries `jobKeyGeneration`. The server matches
  reports by public key, never by generation, so an unknown generation
  never makes a known key unknown.
* Heartbeats and job polls carry the report (`jobKeys`: each key and its
  generation). It is in the request's body, so the device's signature
  covers it: something between the agent and the server can drop it but
  not change it.
* **When it is sent** is ADR-0009's rule (amended, PR #52): only while the
  agent's last heartbeat answer came from a server of level 2 or higher;
  never in the first heartbeat of a process. A level-2 server from before
  this ADR ignores it. Nothing is remembered in `agent.json` for it, and no
  `400` is read as "not supported".
* **Heartbeats also carry the authorities the agent trusts**: the SHA-256
  fingerprint of each certificate in the `ca.pem` it loaded at start
  (none when it uses the system's roots), under the same rule. The
  replacement of EasyRMM's own authority after a leak counts them (After a
  leaked backup set, below).

### Two statements
Both are signed with a job key under a context of their own, bound to one
device, carry an ID, are valid for 10 minutes like updates and uninstalls,
and travel only in heartbeat answers, which stay on HTTPS (ADR-0059 carries
no instructions). The server sends them only to a device whose report
shows a build that understands them (ADR-0009).

* **The hand-over** (`EASYRMM-JOB-KEY-HANDOVER-V1`): "the server's newer
  key is K, generation G", signed with a key the device already trusts.
  The agent accepts it only if it is signed by a key it trusts, is for its
  device and not expired, introduces a key with a generation above every
  one it trusts and no more than `MaxSkew` (5 minutes) ahead of its own
  clock, and leaves it with at most four keys. It then trusts both. A
  hand-over of a key it already trusts at the same generation changes
  nothing and is not an error, so a statement offered twice (two servers,
  a repeated answer) is harmless. One refused as ahead of the device's
  clock is offered again with each heartbeat and accepted once the clock
  reaches it.
* **The cut-over** (`EASYRMM-JOB-KEY-CUTOVER-V1`): "trust only K", signed
  with K. The agent accepts it only if K is the newest key it trusts. It
  then drops the others, keeping their fingerprints to name them in errors.
  A cut-over to the only key it trusts changes nothing.
* The agent writes `agent.json` before it acts on either. It handles the
  hand-over before the cut-over, and both before anything else in the
  answer (its instructions, and ADR-0058's settings document), which it
  checks with the keys it now trusts. It reports a statement it refused,
  with the reason, in its next heartbeat.
* **A declared transition.** An agent is in a key transition from the
  cut-over it accepts until 10 minutes after (the longest anything signed
  with a dropped key can still be on its way). Between a hand-over and
  its cut-over nothing can fail for the rotation's sake: the agent trusts
  both keys, and the server signs with one of them. So the transition is
  minutes long, not the 24 hours or more of a planned overlap, and
  ADR-0059's detection of middleboxes stays on through the overlap. Its
  trust store records it, and `easyrmm-agent status` shows it. ADR-0059
  counts no channel failure for a message that does not verify during it.
  It is declared by a signed statement, not by a field of the answer, so
  nothing on the path can declare one.
* Every verifier in `agentproto` (`VerifyJob`, `VerifyUpdate`,
  `VerifyUninstall`, `VerifyEasyPatchInstall`, `VerifyDownload`) takes the
  keys the agent trusts and accepts a signature by any of them.
* **A job signed by a key the agent dropped** (one whose fingerprint it
  kept) is left alone the first times: not journaled, not run, not
  reported. The server delivers a run again when it has been sent and not
  started for 2 minutes (`RedeliverAfter`, `jobs/service.go`; the `due`
  query in `delivery.go`), signed from the device's newer report. The
  third delivery of the same run still signed with a dropped key is
  reported failed ("signed with a key this agent no longer trusts"), so a
  run never stays *sent* silently until it expires, up to 7 days later.
  Today the worker reports such a job as failed at once (`accept` in
  `agent/jobs/worker.go`). A job signed by a key the agent never trusted is
  still refused and reported failed at once.

### The key the server signs with
* **For each device, from its report**, where "its report" is the newer
  (by the signed request's time) of the report in this request and the one
  stored for the device:
  * after the server sent the device a cut-over to K, K, until a later
    report lacks K;
  * otherwise, the newest key in the report whose seed the ring holds.

  Two cases are builds not known to follow, and only they use a device's
  oldest key:
  * a device that has never sent a report (its build is from before this
    ADR, or it has not yet reached a server of this ADR) gets the key it
    was given at enrollment, generation 1 for devices enrolled before this
    ADR: the key its `jobKey` holds;
  * a device whose build has changed since its stored report (an update,
    or its rollback; the heartbeat names the build's SHA-256, ADR-0027),
    while its request carries none, gets the oldest key of the stored
    report until it reports again: a build that follows still trusts all
    of them, since no statement goes to a device while its update is open,
    and one that does not reads the oldest from `jobKey`. No statement
    goes to it until it reports.

  When the server has sent a cut-over to K and the build has also changed
  since, with no report in the request, the cut-over rule wins. The
  cut-over went only to a device whose report had K, and no update opens
  in an answer that carries a statement, so the build it runs now trusts
  K whether or not it took the cut-over; and a build from before this ADR
  cannot come back, since ADR-0027 removes the previous build once the
  new one reaches the server.
* **Why the newer of the two.** Some requests carry no report: the first
  heartbeat of a process (ADR-0009), MeshAgent's downloads (plain `GET`s,
  `installMesh` in `agent/runner/runner.go`, signed by `SignDownload` in
  `server/internal/agents/meshagent.go`), and builds from before this ADR.
  Others are older than what the server knows: a job poll is held up to
  25 seconds (`PollWait`), and a heartbeat in between can carry a
  cut-over. Two races follow, and both are tested:
  * a heartbeat answer carries a cut-over to K, and the agent then fetches
    MeshAgent's settings in the same pass, without a report; the stored
    report still holds the old key, so "its oldest key" would sign with
    the key the agent has just dropped;
  * a poll opened with a report of the old key is still waiting when a
    heartbeat brings the cut-over; a job arriving then would be signed
    with the old key, and the worker would fail it.

  With the rule above both are signed with K. What can still slip through
  (another server that read the device's row just before the cut-over was
  stored) is caught by the worker's redelivery for jobs, by the next
  heartbeat for heartbeat instructions, and by the next attempt
  (`InstallWait`) for MeshAgent.
* The device's row keeps its last report, when it first sent it, and the
  cut-over it was sent (the key and when). The report is written only when
  it changes.
* **Removed devices** (ADR-0050) keep their last report too, in
  `retired_devices` (today it keeps none: `remember` in
  `server/internal/agents/removal.go`). `RetiredHeartbeat` and
  `uninstallFor`, which sign with the single key today, sign by the same
  rule. Neither a removed device nor one being removed is offered a
  statement: it gets nothing but its uninstall instruction.
* Enrollment, with a deployment token or after approval (ADR-0015,
  ADR-0024), gives the ring's newest key.
* Enrollment and heartbeat answers keep `jobKey`, which is now the key the
  server signs with for that device, and add `jobKeyGeneration`.

### What the server offers each device
Statements are decided in the heartbeat, after `planUpdate` in the same
transaction (`server/internal/agents/heartbeat.go`), and never while an
agent update is open for the device: an attempt that holds a place under
ADR-0027's **Devices at once**, until the agent comes back with the new
build, reports a failure, or 15 minutes pass, including one opened in this
very answer. A build that rolls back so never finds its keys changed
underneath it.

Let the **floor** be the newest key that has been cut over to, and the
**newest** the ring's newest key. From the device's report:
1. **The target** is the floor if the device trusts any key older than
   the floor; otherwise the newest.
2. A device that trusts the target and other keys is sent the cut-over to
   the target when the target is the floor and the newest key the device
   trusts. Otherwise it is sent nothing: during a planned rotation's
   overlap, or while it also trusts a newer key the server never held, in
   which case it moves with the next rotation (rule 3).
3. A device that lacks the target and trusts more than one key:
   * when the newest key it trusts is one the server holds, is first sent
     the cut-over to that key, so that the hand-over which follows finds
     it on one key;
   * when the newest key it trusts is one the server never held (a key
     lost with a restore or with a rollback during an overlap, or one
     someone handed it), is sent the hand-over to the target at once,
     signed with a key it trusts that the server holds. It then trusts
     three keys, within its limit of four, and the target's cut-over drops
     the unknown one. The hand-over needs the target's generation above
     the unknown key's. A lost key's generation is the time it was made,
     and any reported key within the 5-minute bound raises the next one's
     (One ring, above), so only an unknown key beyond the bound, or one
     handed over in the 5 minutes before the target was made and not
     reported by then (Generations, below), is above the target. Such a
     device is sent nothing and needs re-pinning.
4. A device that lacks the target and trusts one key the server holds is
   sent the hand-over to the target, signed with that key.
5. A device that trusts no key the server holds is sent nothing: it
   **needs re-pinning**.

So a device still on a key older than the floor (a laptop offline across a
rotation for a compromise) is moved to the floor before any newer planned
key reaches it, and never carries a compromised key through a planned
rotation's overlap; and a device left trusting a key the server lost moves
with the next rotation, which the console offers (Orphaned keys, below).

### A rotation
1. **Start.** A super administrator, or the host (below), gives the
   reason: planned, moving the deployment, or compromised. The server
   makes the new key under an advisory lock, so one rotation starts at a
   time. A rotation for a compromise may start during a planned rotation's
   overlap: it marks every older key compromised, the planned rotation
   ends there, and its key is never cut over to as the floor. Starting is
   refused while the updater holds the server or an upgrade is under way,
   or while a server older than the ring is seen (below). Enrollments get
   the new key at once.
2. **Following.** Each agent that can follow gets the hand-over in a
   heartbeat answer, trusts both keys, and reports them; from that report
   on, its instructions are signed with the new key.
3. **Cut-over.** Planned and moving rotations: when a super administrator
   finishes the rotation (next section), the new key becomes the floor. A
   rotation for a compromise: as it starts. Each device then gets the
   cut-over with the heartbeat after its report shows the new key.
4. **After.** An older key's seed is kept, and used for every device that
   trusts nothing newer, while any device may still trust it: an enrolled
   device whose last report has it, one that never reported and was given
   it at enrollment, or a removed device in `retired_devices` (90 days,
   ADR-0050) whose last report has it or that never reported. Once none is
   left, the seed is deleted; the public key and its record stay. A super
   administrator may **forget** it sooner, but never the newest key; the
   devices still on it then need re-pinning (below).

**One lock for every change to the ring.** Starting, finishing,
forgetting, `replace-lost`, `recover` and the automatic deletion of a seed
each run in one transaction that first takes the ring's advisory lock and
then, inside it, checks again that the updater does not hold the server
and has no upgrade under way, and, for starting and finishing, that no
server older than the ring is seen. The hold is checked by looking at the
file itself, not at the flag the server keeps: PR #51 checks that flag
once, when a request arrives (`Handler` in `server/internal/updater/hold.go`
on `feat/server-hold`), and refreshes it every second, so a request
admitted just before the hold may still be running. Such a change
therefore either commits before the updater can read the ring under the
same lock, or finds the file inside the lock and is refused (The updater's
rollback, below). The host commands take the same path.

**When a rotation ends** is separate from the devices it has not reached.
A planned rotation, or one for a move, ends when it is finished; a rotation
for a compromise ends as it starts. **Devices owed a cut-over**, those that
trust a key older than the floor, are a list of their own, shrinking as
they come back, whatever rotation made the floor. The list does not block
the next rotation (rule 1 above moves its devices to the floor first).
While it holds a device that trusts a compromised key, every super
administrator sees a banner with the count.

### The overlap
* A planned rotation, or one for a move, ends only when a super
  administrator **finishes** it, no sooner than **24 hours** after it
  started, confirming that a backup taken since it started exists (in the
  console, and with `--backup-taken` on the host). Every super
  administrator is reminded after 7 days. It never ends by itself: that
  would end the protection older backups have without anyone having made a
  newer one.
* 24 hours is ADR-0052's window for rolling back a confirmed upgrade, so a
  planned rotation never takes away a rollback the console still offers.
* While both keys are trusted, a restore or a rollback to a backup from
  before the rotation still works (its server signs with the old key,
  which agents still accept), instructions signed with the old key on
  their way still verify (an uninstall saved for the uninstaller, a job a
  server signed before it loaded the new key), and there is time to take a
  backup that holds the new key.
* A rotation for a compromise has no overlap. An online device gets the
  hand-over in one heartbeat answer and the cut-over in the next, and
  confirms with the third: about 3 minutes at the 60-second heartbeat
  (`HeartbeatInterval`, `server/internal/agents/service.go`); one heartbeat
  more for a device in a planned rotation's overlap (rule 3 above).

### Agents offline across the overlap
* An agent offline from before the rotation until after its cut-over
  still trusts only the old key, which the server keeps. Its first
  heartbeat answer hands it the floor (from its report, or from the stored
  one when its agent restarted and the first heartbeat carries none), the
  second cuts over, the third confirms: about three minutes. Its
  instructions meanwhile are signed with the old key, which it still
  trusts, until the cut-over is sent. Nobody has to do anything.
* The console lists devices still on an older key with when each was last
  seen. Only a device whose key the server no longer holds (forgotten, or
  lost with a restore, below) needs someone: it shows as **Needs
  re-pinning**.

### Agents that cannot follow
A build from before this ADR sends no report and ignores the statements.
It keeps getting what the server signs with the key it pinned, agent
updates (ADR-0027) included, which bring it a build that can follow; with
its first report it moves like the others. Updates go at ADR-0027's pace,
**Devices at once** at a time (20 by default): 2,000 such devices take two
to three hours, and after a compromise they trust only the leaked key
until their update arrives. The rotation dialog for a compromise therefore
offers raising **Devices at once** and switching agent updates to
*Automatically*. The console shows how many devices cannot follow and why
(their agent's version; agent updates set to *When asked* or *Off*; an
update that failed), with a link to Agent updates. Their key stays alive
until they move (above). A device whose update fails needs reinstalling:
its build has no `trust-key`.

### A compromised key
* **The old key still carries the hand-over**, and the console says what
  that proves. Whoever holds the leaked key and can answer a device's
  requests could already run anything on it, before the rotation as after,
  and could hand it a key of their own whatever the server does. After a
  leaked backup set, answering is not rare (Context): `internal`-mode
  agents trust the authority in the same database, and certificate keys
  from the set work until they expire. Refusing to use the old key would
  not stop such an attacker; it would leave every device to be re-pinned
  by hand.
* **What a device's report proves.** A device counts as moved only when
  its own report, signed with its device key, says it trusts exactly the
  new key; nobody in the path can forge that. But the device key is a file
  root can read (`device.key`), so on a device where the leaked key ran
  something, the report could be forged too. After a compromise, *Current*
  proves only that an agent nobody tampered with refuses the old key. The
  ADR, the rotation page, each device's page and the incident page say so,
  and the incident page says to reinstall the devices whose path to the
  server the attacker could reach.
* **Instructions the server never issued.** From the first slice, the agent
  records every instruction it accepts in a log in its state directory
  (the last 1,000): its kind, its ID (a job's run, an update's or an
  EasyPatch install's attempt, an uninstall's ID; for a MeshAgent download,
  the nonce of the request it answered; a hand-over's or cut-over's key),
  the fingerprint of the key that signed it, and when. It sends the
  entries the server has not acknowledged with its heartbeats, with the
  sequence of the last one acknowledged, to a server that lists this
  feature in its answer (ADR-0009).
  * **What the server checks against.** Not the rows that drive the work:
    they do not last. An agent update's row is deleted when the device
    comes back on the target build (`updates.go` in
    `server/internal/agents`), and its `attempt_id` is overwritten by each
    attempt (`00011_agent_updates.sql`); a removal's row is deleted when
    it is cancelled (`CancelRemoval` in `removal.go`) and with the device;
    EasyPatch installs are deleted when patching is stopped or resumed for
    a device, or its agent is removed after a move (`optout.go`, and
    `saveRemoval` in `reconcile.go`, in `server/internal/easypatch`).
    Under ADR-0009 the first heartbeat of the new build carries no log,
    and that heartbeat is the one that deletes the update's row, so every
    successful update would be flagged.
    Instead a table of its own, `issued_instructions`, is appended to
    wherever the server signs something for a device: the kind, the ID,
    the device, the generation of the key that signed it, and when. It is
    written in the transaction that signs, so nothing leaves the server
    unrecorded; a redelivery signed with another key adds a row. Rows are
    never updated, have no foreign key (removing or deleting a device
    keeps them), and are kept 90 days.
  * **The check.** An entry whose kind, ID, device and key match no row is
    flagged: **Ran instructions this server never issued**, audited with
    the entries. An entry older than 90 days, or dated before the server's
    last restore, is shown as *not checked*: the rows that would match it
    may be gone.
  * **The server's last restore** is known from the updater's status,
    which records a rollback (ADR-0052); from `easyrmm-server incident
    restored`, which the guide's restore procedure runs on the host after
    `pg_restore`; and, for a restore nobody recorded, from the first
    heartbeat whose acknowledged sequence is ahead of what the database
    says it acknowledged. That last one records a restore at that moment
    and withdraws, as *not checked*, the flags raised since the server
    started for entries dated before it.

  This is a tripwire, not proof: code that ran as root can erase the log
  before it is sent.
* **Unknown keys.** A report with a key the ring has never held is
  recorded on the device, audited once per device and key, and shown to
  super administrators as **Trusts an unknown key**: a key this server
  never issued. Its
  causes: someone holding a key the device trusts, in a position to answer
  it, handed it one; this server was restored from a backup older than a
  rotation (below); or someone ran `trust-key` on the device with another
  key. The console names all three. The flag clears when the device no
  longer reports that key. It works from the first slice, before any
  rotation exists: a hand-over nobody at the server made shows at once.
  * **Generations.** A hand-over is accepted at most 5 minutes ahead of
    the device's clock, so a key someone handed a device has a generation
    at most that far ahead of the moment they did. Once a device reports
    it, the server's next key gets a generation above it (One ring,
    above), so it cannot hold back the server's keys. Only a key handed
    over in the 5 minutes before the server makes its next key, and not
    reported by then, can still be above that key: the hand-over is then
    refused as "not above", and the device shows the unknown key and needs
    re-pinning (`trust-key --force`).
* **Re-pinning a device.** `easyrmm-agent trust-key <generation>:<key>`,
  run as root or administrator on the device, replaces the keys the agent
  trusts with the one given (the console prints it in that form, with its
  fingerprint) and restarts the agent's service. It refuses when the agent
  trusts a key with a higher generation than the one given, unless
  `--force`, so a command deployed by policy that runs again never moves a
  device back to an older key. The key is public, so the command carries
  no secret and can be run:
  * in a terminal session through MeshCentral: the device's page shows the
    command beside **Open terminal** to anyone with `device.terminal`
    there. MeshAgent authenticates MeshCentral by MeshCentral's identity,
    which is not in the database, so this channel does not depend on the
    database and `.env`, unless `/srv/easyrmm/meshcentral` leaked too;
  * by Group Policy, Intune or the customer's own tools, for many devices
    at once; the guide's examples run once (each writes a marker and
    exits when it finds one);
  * by hand at the device.

  Before deploying a key widely, the guide has the operator compare its
  fingerprint with `easyrmm-server job-key status` on the host, since a
  console in the wrong hands could show another key. The device keeps its
  identity, its history and its MeshAgent; nothing is enrolled again. A
  build from before this ADR has no `trust-key`: it is reinstalled, or its
  `jobKey` in `agent.json` is set by hand and its service restarted (the
  agent reads it at start, `main.go`).
* **Reinstalling** (uninstall, then the install command) is for devices
  that may have run what they should not have, or whose path the attacker
  could reach: a new device key and a new enrollment, trusting the key on
  first use as at the first install (ADR-0017's caveat). It comes back as
  a new device (ADR-0024).

### After a leaked backup set
The job key is one of the secrets a leaked backup set gives (Context). The
response replaces the others too:
* **EasyRMM's own authority** (`internal` mode), in two phases. An
  EasyRMM agent with a `ca.pem` trusts the certificates in it instead of
  the system's roots (`CAFile`, a PEM bundle read at start,
  `agent/client/client.go`), and an EasyPatch agent installed with the
  authority trusts that one authority beside the system's roots
  (`ServerCertificateAuthority`, from `SERVERCACERT` or `enroll
  --server-ca`, in `easypatch/agent/EasyPatch.Agent.Core/Security`).
  Switching the server to a new authority at once would cut off every one
  of them.
  1. **Both authorities.** `easyrmm-server incident replace-authority
     begin`, on the host, makes a new authority and keeps serving with
     the old one's certificate. It writes a bundle holding both. Each
     EasyRMM agent gets it as its `ca.pem`, and each EasyPatch agent as its
     `ServerCaCertificate` (the registry value on Windows, `agent.conf` on
     Linux), each with its service restarted, through the channels
     `trust-key` uses (MeshCentral's terminal, Group Policy, Intune, or by
     hand). The EasyPatch agent accepts a PEM bundle there; today `Parse`
     reads one certificate. Each agent reports the authorities it loaded:
     the EasyRMM agent in its heartbeat (What agents report, above), the
     EasyPatch agent in a new optional field of its check-in
     (`CheckInRequest`, `AgentDtos.cs`), which an engine without it
     ignores (no unmapped-member handling is set). The console and
     `replace-authority status` count the agents that trust the old one
     only, both, and the new one only (Console, below).
  2. **The switch.** `easyrmm-server incident replace-authority switch`
     serves a certificate from the new authority, with a new server key,
     and deletes the old authority; install commands change, since they
     pin the server key (`pki.go`). It refuses while an agent seen in the
     last 30 days reports the old authority alone, unless `--strand`,
     which lists them; they are reinstalled. An EasyRMM agent of a build
     from before this ADR reports nothing and counts as on the old
     authority alone; updated first (ADR-0027), it reports. MeshAgent
     follows the new certificate as at a renewal (ADR-0016). The bundle is
     then replaced with the new authority alone, by the same channels,
     since the old one's key leaked; the console counts the agents that
     still trust it.

  The first phase can take days by hand. Meanwhile the leaked authority
  still lets someone in the path answer agents, as it did before; the
  rotated job key is what keeps that from running anything, as for ACME
  and manual certificates (below). A signed hand-over of the authority is
  left to the owner (below).
* **ACME and manual certificates.** New keys and certificates: for ACME,
  autocert's cache (`/srv/easyrmm/server/acme`: the account and the
  certificates' keys) moved aside before a start, so the server obtains
  new ones; for manual TLS, from the operator's issuer. The old ones are
  revoked with the issuer, for browsers. They still count as live until
  they expire, because agents check no revocation: the job key is what
  protects devices meanwhile.
* **MeshCentral's keys.** `easyrmm-server incident replace-remote-keys`
  makes new login and session keys (`meshcentral.secrets`); the server
  writes MeshCentral's configuration at its next start
  ([backup-restore.md](../../operations/backup-restore.md)), and MeshCentral
  is restarted after it. EasyRMM's gateway still asks for an EasyRMM grant
  in front of MeshCentral's browser routes
  (`server/internal/remote/gateway.go`), but the login key is a credential
  and is replaced. MeshCentral's identity is replaced only when
  `/srv/easyrmm/meshcentral` leaked, and then MeshAgent is installed again
  everywhere (backup-restore.md).
* **What stays readable with the leaked encryption key**, in this dump
  and in every later one, until it is replaced: authenticator-app secrets
  (sealed again only when a user enrolls again,
  [docker.md](../../deployment/docker.md#rotating-the-encryption-key)),
  single sign-on client secrets, audit forwarding client keys, and the kept
  secrets of deployment and approval tokens. A bulk re-seal would not help:
  each is a secret the attacker already holds. Each is replaced at its
  source instead (authenticators enrolled again, client secrets changed at
  the provider, forwarding credentials replaced, tokens revoked and made
  again), and then the old key is removed from
  `EASYRMM_SECRET_KEYS_PREVIOUS`. The job keys, the authority and
  MeshCentral's keys are sealed again at every start by their loaders, and
  replaced above.
* **The patching engine's part.** The engine's database and its keys
  (`/srv/easyrmm/easypatch/keys`) are in the backup set
  ([backup-restore.md](../../operations/backup-restore.md)):
  * **Its agents' credentials** are not secrets there: the engine keeps
    each EasyPatch agent's public key only (`AgentCredential` in
    `easypatch/backend/Core/Entities/Endpoints.cs`) and its enrollment
    tokens hashed, and EasyRMM never stores the tokens it makes
    (`server/migrations/00014_easypatch_install.sql`). Nothing in the set
    lets anyone act as an EasyPatch agent, so nothing is replaced for the
    leak itself. What the set does give is answering those agents, by the
    authority or the certificate keys, replaced above. The EasyPatch agent
    on a device that is reinstalled (A compromised key) gets a new key
    with its new install, and its enrollment revokes the endpoint's old
    credentials ("Endpoint re-enrolled", `EnrollmentService.cs` in
    `easypatch/backend/Infrastructure/Services`).
  * **Its notification credentials** (the mail password, Slack and Teams
    webhook URLs, and generic webhooks' signing keys,
    `easypatch/backend/Core/Entities/Notifications.cs`) are sealed with
    the keys in that directory, so they are readable. First the engine's
    key ring is moved aside, so the API makes a new one at its next start
    (only the API makes keys, `AddEasyPatchDataProtection` in
    `easypatch/backend/Infrastructure/DependencyInjection.cs`; the worker
    reads the ring again when a value does not open). Then each credential
    is replaced at its source and entered again in the patching settings:
    a new mail password, new webhook URLs from the receiving service, and
    a new signing key made by the engine and given to the receiver.
  * **The statements key** (`EASYRMM_PATCHING_KEY`, in `.env`) lets anyone
    who can reach the engine on loopback speak as EasyRMM (ADR-0038). It
    is replaced by emptying it in `.env`, rerunning `setup.sh`, which
    makes a new one, and `docker compose up -d`
    ([patching.md](../../operations/patching.md)).
* **Persistence.** When someone could have signed in or written to the
  database (the host, or credentials from the set), the restored database
  is reviewed for what they could have added: users with their sign-in
  methods and roles, deployment and approval tokens, identity providers,
  audit forwarding, scripts, runs still queued (they wait up to 7 days;
  EasyRMM has no scheduled jobs), operator-signed agent builds (ADR-0049),
  and the engine's patching policies. `easyrmm-server incident review
  --since <time>` lists, read-only, what in those was made or changed
  since a time, by their `created_at` and `updated_at`. Whoever could
  write to the database could also set those columns, so the list is a
  starting point only when the database was out of reach (credentials
  that only sign in). When the host or the database was writable,
  `incident review --all` lists everything in those tables, and the guide
  has the operator compare it with the audit records their collector
  received (ADR-0023): forwarded records are outside the database, so
  something present with no record of its making was added behind the
  server.

### What leaked decides what to do
The guide's incident page:

| What leaked | The job key | Answering agents | MeshCentral | What to do |
|---|---|---|---|---|
| A database dump, without `.env` | Safe: sealed | Safe: the authority is sealed | Safe | Nothing has to be rotated; a planned rotation if unsure |
| `.env`, without the database | Safe: the seed is in the database | Safe | Safe | Rotate the encryption key ([docker.md](../../deployment/docker.md#rotating-the-encryption-key)), then a planned rotation, since any earlier database backup opens with that `.env` |
| `.env` and a database dump together (a backup set) | Compromised | Possible from any path: in `internal` mode by the authority; with `/srv/easyrmm/server` or the `tls` directory, by the certificate keys until they expire | Its login and session keys; its identity too if `/srv/easyrmm/meshcentral` went | The sequence below |
| The host | Compromised | Possible from any path | Compromised, identity included | Rebuild the host from a known state and restore a backup from before the compromise; then the sequence below, with MeshCentral's identity replaced and MeshAgent installed again everywhere (backup-restore.md), and devices re-pinned through Group Policy, Intune or by hand |

**The sequence, and how long it takes:**
1. **Contain**: what leaked is closed off; a compromised host is rebuilt.
2. **A new encryption key** (docker.md), and in `acme` or `manual` mode new
   certificate keys. The rotation comes after the cause is gone and the
   encryption key is new: a key made on a host the attacker still
   controls, or sealed with a key they hold, is compromised as it is made.
3. **Rotate the job key as compromised**, from the console or the host;
   the dialog offers raising **Devices at once** and switching agent
   updates to *Automatically*.
4. **Online devices move in about 3 minutes.** Offline devices need
   nothing: each moves when it comes back.
5. **Act only on** *Needs re-pinning* and *Trusts an unknown key*
   (`trust-key`, `--force` where the device trusts a newer unknown key,
   after checking the key on the host); *Cannot follow* with
   a failed update (reinstall); *Ran instructions this server never
   issued*, and devices whose path the attacker could reach (reinstall).
6. In `internal` mode, **replace the authority** in its two phases
   (above): the bundle of both to every agent, the switch once the
   console shows none left on the old authority alone, then the new
   authority alone.
7. **MeshCentral's keys**, **what stays readable**, **the patching
   engine's part**, and the **persistence** review (above).

Steps 2 to 4 take minutes; builds from before this ADR take ADR-0027's
pace (above). Step 6 takes as long as the channels it uses, by hand.

### A lost key
* If the seed cannot be opened or is gone, the server still refuses to
  start, as now, so that a mistaken `EASYRMM_SECRET_KEY` is fixed in
  `.env`, not by losing the key.
* `docker compose run --rm server easyrmm-server job-key replace-lost`, on
  the host, marks the key lost and makes a new one with no hand-over;
  every device on the lost key then needs re-pinning. It refuses unless
  the other values the server opens at start (`tls.internal_ca`,
  `meshcentral.secrets`, where the deployment has them) open with the
  current key: ".env does not match this database". A restore without its
  `.env` never reaches `LoadKey` (`pki.Load` and `remote.LoadSecrets` fail
  first, `app.go`), and is answered as backup-restore.md says, by
  reinstalling every agent; `replace-lost` is for a seed lost while `.env`
  still opens the rest. Where the database holds neither value, it checks
  the sealed values it does hold (Context) instead, and goes ahead only if
  they open or there are none.
* The lost key's sealed seed is kept, never deleted by the automatic rule.
  `easyrmm-server job-key recover <generation>` opens it with the current
  key or one in `EASYRMM_SECRET_KEYS_PREVIOUS`; if it opens, the key is
  held again, and the devices still on it get the hand-over to the floor
  and stop needing re-pinning.
* Devices with a build from before this ADR are reinstalled or edited by
  hand (Re-pinning, above).
* This replaces ADR-0017's re-enrollment for a lost key alone.

### Several servers, and older ones
* Each server records itself in `server_instances` (an ID per process, its
  version, when it started, when it last reloaded the ring, and whether
  the updater holds it), at start, with each reload, and at once when it
  enters or leaves a hold; it removes its row when it stops. It names its
  database connections `easyrmm-server/<version>` (today every server is
  `easyrmm-server`, `server/internal/database/database.go`). The console
  lists them.
* An older server started after the move from `settings` refuses to
  start (the tombstone). One already running when another server moved
  the key keeps the key it loaded at start, generation 1, and would keep
  signing with it after a cut-over. So starting a rotation, and finishing
  one, are refused, in the console and on the host, while a server older
  than the ring is seen: a database connection named plain
  `easyrmm-server`, which only builds from before this ADR use, or a
  recorded instance, seen in the last 2 minutes, of a version older than
  the server acting. A rotation so waits for a rolling upgrade to end.

### Storage, backups and restore
* The ring lives in the database, sealed with the encryption key, so the
  guide's backup (the database dump and `.env`) carries it; nothing new is
  backed up. Keys are sealed again at the next start after the encryption
  key changes, as now.
* A restore across a rotation depends on when its backup was taken:

  | Backup taken | Restored before the cut-over | Restored after the cut-over |
  |---|---|---|
  | Since the rotation started | Works | Works: the restored server holds the new key and signs with what each device reports |
  | Before the rotation started | Works: agents still trust the old key. Devices that had moved show the new key as unknown, with the reason, and move with the next rotation | Devices that moved trust only a key the restored server never held: they need re-pinning, or a newer backup restored |

* The server signs from each device's report, not from what its restored
  rows say. That is why a backup from the overlap works after the cut-over
  with nothing to do.
* **Orphaned keys.** After a restore, or a rollback during an overlap,
  devices that had moved trust a key the restored server never held, beside
  one it holds. The console offers a rotation, planned by default. Its
  hand-over reaches those devices at once, signed with the key they trust
  that the server holds (rule 3 of "What the server offers each device"),
  and its cut-over drops the lost key. The guide has the operator match the
  unknown fingerprint against the `job_key.rotate` record their collector
  received (ADR-0023: forwarded records outlive the restore), to tell the
  server's own lost key from someone else's; where that record shows that
  the lost rotation was for a compromise, the operator chooses a rotation
  for a compromise instead.
* A job or any other instruction for a device that **needs re-pinning** is
  refused at once, with the command that fixes it, instead of queued to
  fail. Removing such a device skips the uninstall instruction it could not
  verify and goes as **Remove anyway** does (ADR-0050).

### The updater's rollback (a requirement on ADR-0052)
ADR-0052 refuses a rollback across a cut-over ("Rollback"). The host
updater is being built now; this is what it must do, and ADR-0052 is
amended when it does.

* **When it ships.** With the second slice of this ADR, which first allows
  a cut-over, or before it: the second slice does not merge before an
  updater with the record and the refusal is released.
* **What a backup records.** At step 3 of an upgrade, when every other
  service has stopped and PostgreSQL has not yet, the updater reads the
  highest generation whose seed the database holds (1 for a database
  without `job_keys`, whose `settings` key becomes generation 1) and keeps
  it with the backup. If it cannot read it, it records "unknown". The
  upgrade that brings the first updater with the record is backed up by
  the updater before it (ADR-0052: the backup is step 4, and the updater
  replaces itself only at step 7), so that backup has no record; the rule
  below lets it roll back, since no cut-over can have happened before
  slice 2.
* **A rollback during an upgrade** (a failure after step 3) is never
  blocked: the new version was held throughout (ADR-0052), so nothing can
  have been cut over, and ADR-0052 allows PostgreSQL not to start then.
* **A rollback after a confirmed upgrade** first writes `hold`
  (`/run/easyrmm-updater/hold` in the server, PR #51: the server looks
  every second and then answers `503` everywhere but its health checks),
  and waits until the server's `/readyz` says it is held. It then reads,
  in one transaction that takes the ring's advisory lock (One lock for
  every change to the ring, above), so that a change admitted before the
  hold has committed and none can follow:
  * the newest generation that has been cut over to, the **floor** (1 for
    a database without `job_keys`);
  * the server instances seen in the last 2 minutes that the hold has not
    reached (`server_instances`, above: a server on another host shares
    the database but not this host's `hold`), and the database connections
    named plain `easyrmm-server` (servers from before this ADR, which
    record nothing).

  It decides:
  * a floor of 1 goes ahead whatever the backup recorded: no device has
    ever been cut over, and every backup holds generation 1 or the
    `settings` key that becomes it;
  * a floor above the backup's generation, or a backup without one (from
    an updater before the record, or "unknown"), or a floor that cannot be
    read, is refused: "Agents moved to a signing key made after this
    backup, on <time>; restoring it would leave them unable to accept
    anything from the server", or, without a generation, that the updater
    cannot tell whether restoring would do so;
  * any instance the hold has not reached is refused too: "A server on
    another host shares this database; it would keep changing the ring
    during the rollback." A rollback that is safe for rotations is a
    single-host one; with several hosts, the operator stops the others
    first;
  * otherwise it goes ahead; when the live ring held a newer key than the
    backup, its record says that devices that moved keep trusting that key
    until the next rotation's cut-over.

  On a refusal `hold` is removed, and nothing was stopped.
* **`--strand-agents`**, on the host only, rolls back anyway; the record
  says so. A restored server of this ADR shows the devices that need
  re-pinning. A restored version from before this ADR shows nothing: it
  has no ring, no reports and no states, and a job it sends a moved device
  just fails. So the guide has the operator re-pin every device with this
  ADR's agent by policy, with `trust-key --force 1:<key>` and the key the
  restored server holds, since that version cannot tell which devices
  moved; devices on an older build never moved and need nothing.
* **Why the updater reads the database.** The plan's rule is that the
  updater trusts nothing the server writes beyond a version number
  ([feature-plan.md](../feature-plan.md), "What the reviews changed"). This
  departs from it by two values, read by a fixed `psql` query that the
  updater runs as PostgreSQL's own user in the `postgres` container,
  parsed as integers and nothing else: the floor, and the count of
  instances the hold has not reached. They decide only between the
  rollback the operator asked for and a refusal, which the host can
  override; they never make the updater do anything else.
* The updater's status gains the backup's generation, so the console shows
  that **Roll back** is gone, and why, before anyone tries; the console's
  dialog for a rotation for a compromise, and `finish --now` on the host,
  say so before they end it.
* Because of the 24-hour minimum, only a rotation for a compromise, or one
  finished early from the host, can make a rollback impossible.

### Who may rotate
* **Super administrators** (`settings.manage` platform-wide, as for signed
  agent builds), with **step-up authentication as ADR-0055 defines it**
  ("Step-up authentication"), for starting, finishing and forgetting. A
  super administrator who cannot pass it (no second factor enrolled) uses
  the host.
* **The host**, as root, through `docker compose exec server
  easyrmm-server job-key …`, for an incident where the console cannot be
  reached or trusted. Whoever is root on the host already holds everything
  the key protects. `replace-lost`, `recover`, `--now` and the `incident`
  commands exist only there.
* While a rotation is in progress, while devices that trust a compromised
  key are owed a cut-over, and after a rotation that ended a rollback,
  every super administrator sees a banner.
* One key for the whole server: organizations have no keys of their own,
  and their administrators cannot rotate.

### Console
* **Settings → Agent signing key**, for super administrators:
  * the current key: fingerprint, when and by whom it was made, how many
    devices trust it, its age; the servers sharing the database, with
    their versions;
  * **Rotate key**: the reason, and what follows from it: for a planned
    rotation or a move, an overlap of at least 24 hours finished by hand;
    for a compromise, a cut-over at once, what a device's report then
    proves (above), **Devices at once** and *Automatically* offered when
    devices cannot follow, and, when the updater offers a rollback, its
    end. Each says to take a backup now. Refused, with the reason, while a
    server older than the ring is seen, or while the updater holds the
    server or an upgrade is under way;
  * during a rotation, its progress: devices moved; devices still on an
    older key (online, or offline since when); devices that cannot follow,
    with their agent's version and whether an update failed; devices that
    need re-pinning; devices that trust an unknown key. Each count opens
    the devices list filtered. Devices owed a cut-over have the same view
    after the rotation ended;
  * **Finish rotation**: from 24 hours on, with the backup confirmation and
    the devices not moved yet (they follow when they come back); refused,
    with the reason, while a server older than the ring is seen;
  * older keys still held, for how many devices, with **Forget** (not for
    the newest key) and the devices it would leave needing re-pinning;
  * after a restore that left devices on an unknown key, the offer of a
    rotation, planned unless the operator finds the lost one was for a
    compromise (Orphaned keys, above);
  * during the replacement of EasyRMM's own authority, the agents that
    trust the old authority only, both, and the new one only, for EasyRMM's
    agents and the EasyPatch agents, each count opening the devices list
    filtered.
* **Devices**: the signing key's state as a column and a filter:
  *Current*, *Moving* (trusts the new key and older ones), *On an older
  key*, *Cannot follow*, *Not reporting* (its agent's version reports
  keys, but three heartbeats in a row carried none), *Needs
  re-pinning*, *Trusts an unknown key*; the flag *Ran instructions this
  server never issued*; and, while EasyRMM's own authority is being
  replaced, which authorities each agent trusts. After a rotation for a
  compromise, *Current* says what it proves.
* **A device's page**: its state; for *Needs re-pinning* and *Trusts an
  unknown key*, the re-pin command, **Open terminal** when MeshAgent is
  connected, and the reasons; for the flag, the entries and the advice to
  reinstall.

### API and host commands
* `GET /api/v1/settings/job-key`: the ring (fingerprint, generation,
  reason, made, cut over, compromised, lost, for how many devices it is
  kept), the rotation's progress, the devices owed a cut-over, the
  servers seen, when the rotation may be finished, whether finishing it
  ends the updater's rollback, and the server's last restore.
* `POST /api/v1/settings/job-key/rotations` (`reason`);
  `POST /api/v1/settings/job-key/finish` (`backupTakenSinceStart`);
  `POST /api/v1/settings/job-key/keys/{generation}/forget`. Super
  administrators only, each with step-up (ADR-0055).
* Device lists and a device's page gain the state and the flag, under
  `device.view` like any other field.
* On the host, through `docker compose exec server`, or `docker compose run
  --rm server` when the server is not running:
  * `easyrmm-server job-key status`, `rotate --reason
    planned|moving|compromised`, `finish --backup-taken [--now]` (`--now`
    skips the 24 hours, and its record says so), `forget <generation>`,
    `replace-lost` and `recover <generation>`;
  * `easyrmm-server incident replace-authority begin|status|switch
    [--strand]`, `replace-remote-keys`, `restored`, and `review --since
    <time>|--all`.

  Each refuses while the updater holds the server (`hold`, PR #51) or its
  status shows an upgrade under way, except `status` and `review`, which
  only read; those that change the ring check it again inside the ring's
  lock (A rotation, above).
* On the device: `easyrmm-agent status` lists the keys the agent trusts,
  with fingerprints and generations, and its latest logged instructions;
  `easyrmm-agent trust-key <generation>:<key> [--force]`.

### Audit records
| Action | When | Details |
|---|---|---|
| `job_key.rotate` | A rotation starts | Reason; the new key's fingerprint and generation; the keys it follows, and those it marked compromised; a planned rotation it ended; console or host |
| `job_key.finish` | A planned rotation is cut over to | Devices in each state; the backup confirmation; whether `--now` skipped the minimum |
| `job_key.forget` | A seed is deleted | By a person, or by the server once no device needs it; the devices it left needing re-pinning |
| `job_key.replace_lost` | The host replaces a lost key | The lost key's generation; the new key |
| `job_key.recover` | The host recovers a lost key | Its generation; the devices that no longer need re-pinning |
| `device.job_key_unknown` | A report names a key never issued, once per device and key | The key's fingerprint and generation (recorded as the agent) |
| `device.job_key_unknown_cleared` | That key is gone from the device's report | The key's fingerprint |
| `device.job_key_refused` | An agent refused a statement | The statement and the agent's reason |
| `device.instruction_unknown` | An agent logged an instruction the server never issued | Kind, ID, signer fingerprint and time of each entry |
| `tls.authority_begin` | The host makes a new internal authority beside the old one | Both authorities' fingerprints |
| `tls.authority_switch` | The host serves the new authority's certificate | Both fingerprints; the agents that reported the old authority alone, if `--strand` was given |
| `server.restored` | `incident restored` on the host, a rollback in the updater's status, or a heartbeat that shows a restore nobody recorded | How it was learned; the time from which instruction log entries are not checked; the flags withdrawn |
| `remote.keys_replace` | The host replaces MeshCentral's keys | That they were replaced (never the keys) |

Step-up itself is ADR-0055's. One device's move is not audited:
its row keeps when it reported which key, and the finish record counts
them; 10,000 records per rotation would bury the ones above. Forwarding
(ADR-0023) carries these like any other.

### What depends on this
* **Everything new the server signs for an agent goes through the ring**,
  with the device's key; nothing keeps a copy of a key.
* **F1, signed settings (ADR-0058), and feature 8, the WebSocket channel
  (ADR-0059)**, list six needs ("What this needs from ADR-0057" in each).
  This ADR provides them:
  1. *Agents report the generations they accept in their signed
     heartbeat*: the report, with each key's generation, in heartbeats and
     job polls, by ADR-0009's rule; for a process's first heartbeat, which
     carries none, the server uses the stored report.
  2. *The server signs per device with a key that device reported*:
     ADR-0058's documents and ADR-0059's messages are signed by the rule in
     "The key the server signs with", like every instruction. The channel
     looks the key up for each message, so a connection is bound to no key:
     after a device's cut-over to K, its next message is signed with K.
  3. *The agent applies a hand-over before anything else in an answer*:
     the statements come before the instructions and the settings
     document (Two statements). In an answer that carries a cut-over to K,
     the rest is signed with K; in one that carries a hand-over, with the
     key the device reported; either verifies once the statements are
     applied.
  4. *The channel opens only after a successful heartbeat in the agent's
     process*: ADR-0059's rule; the server then knows the device's keys,
     from that heartbeat's report or from the stored one.
  5. *`closing` (`refresh`) at a cut-over*: when a rotation's key becomes
     the floor (a planned rotation finished, a rotation for a compromise
     started), every server sends `closing` (`refresh`) to its live
     connections, spread over ADR-0059's 5 minutes. Each agent reconnects,
     checks in at once (ADR-0059), and gets its statement in that
     heartbeat's answer instead of waiting for its next one.
  6. *No failures counted during a declared transition*: the agent's
     declared transition (Two statements), from the signed cut-over it
     accepts until 10 minutes after. Before the cut-over nothing fails for
     the rotation's sake, so ADR-0059's detection stays on through the
     overlap.

  An agent checks a settings document when it receives it and keeps it as
  checked; it does not check it again later against keys it may have
  dropped since. Heartbeats, and the report and statements with them, stay
  on HTTPS; the channel carries none of them (ADR-0059). This ADR adds no
  agent endpoint (were one added, a `404` would mean "not supported here",
  ADR-0009), and no request field outside heartbeats and job polls.
* **5c, moving to a new name**: the move is signed like any instruction.
  A rotation and a move are independent; each device follows each by its
  own statements. The guide advises finishing one before starting the
  other, and rotating after a move that leaves a host behind. A device
  offline past both the old name's cut-off and its key's removal needs
  `trust-key` and the local step 5c's ADR gives for the address, or a
  reinstall.
* A rotation changes neither MeshCentral's identity, nor the EasyPatch
  agent, nor the engine's statement key (Context). After a leak, the
  EasyPatch agent takes a bundle of authorities and reports them, and the
  statement key is replaced (After a leaked backup set).

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
  find in an incident. Left to the owner (below); the statements here
  leave room for it (a hand-over signed by another trusted key).
* **EasyRMM re-pinning devices through MeshCentral by itself.** It would
  give the server a second way, beside the job key, to run commands as
  root on every device, a path ADR-0022 and ADR-0033 have kept narrow. A
  person runs the command through a terminal session instead.
* **A key per organization.** More keys to rotate, and no gain while one
  server holds them all.
* **A per-field gate on the report** (sent only to a server that once
  answered with `jobKeyGeneration`, remembered in `agent.json`, forgotten
  on a `400`). Replaced by ADR-0009's rule for every field (amended,
  PR #52), which reads no `400` as "not supported".
* **A bulk re-seal after a leak.** It would not make a leaked secret
  secret again; the secrets that stay readable are replaced at their
  source instead (above).

## Open questions for the owner
* **An offline recovery key** (Options considered): worth an ADR of its
  own?
* **A signed hand-over of EasyRMM's own authority** for `internal`-mode
  deployments: worth an ADR of its own? With the two phases above, it no
  longer decides whether agents are cut off; the bundle of both
  authorities and the agents' reports already prevent that. What it would
  change is how the two bundles reach the agents: through the heartbeat,
  signed with the rotated job key, instead of by hand through policy tools
  or a terminal, twice per device. ADR-0055's trust instruction (5b1),
  which adds an authority to an agent's trust once a chain verifies, is
  the likely base for the first bundle; the second, which removes the old
  authority, and the EasyPatch agent's own setting, which the EasyRMM
  agent would write, are what such an ADR adds.

## Testing
* **Unit** (`internal/agentproto`, `agent`): the statements signed and
  verified; each refusal (a signer not trusted, another device, expired, a
  generation not above, more than 5 minutes ahead, a fifth key, a
  cut-over by a key that is not the newest, unknown fields); a hand-over
  and a cut-over received twice; the declared transition, from the
  cut-over until 10 minutes after, none after a hand-over alone, and
  across a restart; three keys after a hand-over to a device that also
  trusts a key the server never held, and the cut-over that leaves one;
  the statements applied before the instructions and a settings document
  in the same answer; each verifier with two keys; the trust
  store's writes, `jobKey` kept as the oldest, ignored on reading when
  `jobKeys` exists, and a generation learnt from `jobKeyGeneration`; the
  report sent only by ADR-0009's rule (never in a process's first
  heartbeat, never after an answer of level 1), and the authorities in
  `ca.pem` by the same rule; a job signed by a dropped key left for
  redelivery twice and reported failed at the third, one by a key never
  trusted failed at once; the instruction log written, bounded, sent with
  its acknowledged sequence only when the answer lists it, and dropped
  once acknowledged; `trust-key` (refusing a lower generation, `--force`)
  and `status`. The EasyPatch agent (`EasyPatch.Agent.Tests`): a bundle of
  two authorities accepted, a certificate from either verifies, and their
  fingerprints in the check-in. The agent tests run on CI's Windows runner
  too (`backend-tests.yml`, *Agent tests on Windows*), `trust-key`'s
  service restart included.
* **Integration** (PostgreSQL, with the race detector):
  * the move from `settings`: the same seed and public key, sealed under
    the new additional data, the tombstone written; sealed again after the
    encryption key changes;
  * **mixed versions**: the server of the last release before this ADR,
    by its tag, refuses to start against the migrated database; starting
    and finishing a rotation are refused while a connection named plain
    `easyrmm-server` is open or an older recorded instance was seen;
  * **the signing key's precedence**: a cut-over sent, then a heartbeat
    with no report from a changed build, signed with the cut-over key;
  * **a lost key**: a device moved to a key the restored ring never held,
    beside one it holds, gets the next rotation's hand-over at once, signed
    with the held key, and its cut-over; one whose unknown key is beyond
    the bound needs re-pinning;
  * **the lock**: a rotation started while a hold appears, across the
    moment the updater reads the ring: either committed before the read or
    refused inside the lock; each change to the ring and each host command
    refused while held or while an upgrade is under way;
  * the key per device from its reports, the newer of the request's and
    the stored one; **the races**: a cut-over sent in a heartbeat, then a
    MeshAgent download without a report, signed with the new key; a poll
    opened with the old key still waiting when a heartbeat sends the
    cut-over, then a job queued, signed with the new key; a job delivered
    with a dropped key redelivered after `RedeliverAfter`;
  * **the injected key**: a device reports a key the ring never held,
    4 minutes ahead: flagged, and the next key's generation is above it; a
    report an hour ahead: flagged, and outside the bound;
  * **the order of moves**: a device on key A, offline while C is cut
    over for a compromise and D starts as planned, gets C's hand-over and
    cut-over before D's hand-over, and never trusts A and D together; a
    device on A and B is cut over to B before C's hand-over;
  * statements decided after `planUpdate`: none in an answer that opens an
    update, none while one is open, none to a removed device;
  * two servers on one database, one starting a rotation while the other
    signs with the new key for a device that reported it; generations
    above a restored ring's and above reported ones; unknown keys flagged
    and audited once per device and key, and cleared; reloads limited; the
    report written only when it changes; a seed kept while a device, or a
    removed device, needs it, and deleted after; removed devices signed by
    their report; instructions
    refused for a device that needs re-pinning; `replace-lost` refused
    when `.env` does not match, the seed kept, and `recover`; the API's
    permissions, step-up and audit records; nothing while held;
  * **issued instructions**, for each kind: a job run; an agent update
    whose device comes back on the new build, whose first heartbeat
    carries no log and deletes the update's row, and whose second brings
    the entry, not flagged; an uninstall, after the removal is cancelled
    and after the device is deleted; an EasyPatch install, after patching
    is stopped and resumed; a MeshAgent download; a hand-over and a
    cut-over. Each flagged when its ID, device or key does not match; an
    entry older than 90 days, or dated before the last restore, *not
    checked*; a restore learnt from `incident restored`, from the
    updater's status, and from a heartbeat whose acknowledged sequence is
    ahead, withdrawing the flags raised since the start;
  * **the authority's replacement**: `begin` keeps the old certificate
    served and writes a bundle of both; agents' reports counted; `switch`
    refused while one reports the old authority alone, and with
    `--strand`;
* **Console**: the page, its dialogs and the device states, in the
  console's checks.
* **The bundle test, with real agents, every machine on the host's
  network** (`--network host`, as `scripts/e2e/bundle.sh` runs its machine
  today; never a bridge network):
  1. Agent updates set to *When asked* before any machine enrolls, so that
     machine 3 is updated only when the test asks; machine 1, today's
     Debian machine with systemd, online throughout; machine 2, the same
     build, enrolled, then its agent stopped; machine 3 with the agent of
     the last release before this ADR's first slice, by its tag, checked
     against that release's `SHA256SUMS`;
  2. a planned rotation, through the API until slice 3 and through the
     console with step-up from then on: machine 1 reports both keys within
     a heartbeat and runs a script signed with the new key; machine 3 shows
     *Cannot follow*, is updated when the test asks, then follows;
  3. finished from the host with `--backup-taken --now`: machines 1 and 3
     report only the new key (`easyrmm-agent status`) and run a script;
     MeshAgent removed from machine 1 and installed again, its download
     verified with the new key; the EasyPatch agent installed through
     EasyRMM after the cut-over;
  4. machine 2's agent started: the hand-over, the cut-over and a script,
     within three heartbeats;
  5. a rotation for a compromise with machine 2 stopped again: it follows
     once started;
  6. on machine 2, `trust-key --force` with a key the server never issued:
     flagged
     and audited; then `trust-key --force` with the server's key: cleared,
     and a script runs. The test runs it with `docker exec`, a stand-in for
     MeshCentral's terminal; the terminal session itself is checked by hand
     on the owner's instance and recorded.

  The machines share the host's network; each has its own state and its
  own MeshAgent. If two MeshAgents cannot share one network namespace,
  each machine gets a namespace of its own, joined to the host's by a veth
  pair and routed, never a bridge network; the slice that finds it says
  so.
* **The last release against this one**: this ADR's agent against the last
  release's server, from its bundle by tag: it enrolls, sends no report the
  server would refuse, and runs a script.
* **A restore across a rotation:**
  * ADR-0052's upgrade test on CI gains a real agent on the runner's
    network. From slice 1: an upgrade from the last release across the move
    from `settings`, then **Roll back** after the confirm; the agent
    reaches the restored server and runs a script. From slice 2: after a
    confirmed upgrade, a planned rotation started, then **Roll back**; the
    agent reaches the restored server (which shows the newer key as
    unknown), is moved back to that server's build, and runs a script.
    Then an upgrade again, a rotation finished with `--now`, and **Roll
    back** refused with nothing stopped; a backup without a generation
    refused the same way, unless the floor is generation 1, which rolls
    back (the release that brings the recording updater); refused while
    another instance, not held, is recorded; `--strand-agents` rolling
    back anyway.
  * **A rollback during an overlap, then a new rotation**: a planned
    rotation started, the agent moved to both keys, **Roll back** (allowed:
    nothing was cut over); the restored server shows the newer key as
    unknown; a new planned rotation's hand-over reaches the agent at once,
    signed with the old key, its finish cuts over, and the agent trusts
    only the new key and runs a script.
  * The backup-restore drill (`scripts/drill/backup-restore.sh`, whose
    agent runs on the host's network) takes one backup before a rotation
    and one during its overlap, finishes the rotation, restores the second
    (the agent runs a script, nothing done), then the first (the device
    needs re-pinning, and a job is refused with the command), then runs
    `trust-key`. In `internal` mode it then replaces the authority:
    `begin`, the bundle copied to the agent and its service restarted, the
    agent's report counted, `switch`, a script run, and the new authority
    alone copied. Recorded in [drills.md](../../development/drills.md).
* **Windows**: the agent's unit tests run on CI's Windows runner; a
  rotation end to end on Windows is marked unverified until the plan's
  Windows end-to-end harness exists, and is checked meanwhile on the
  owner's instance.
* **Then** the owner's instance on the edge channel: a planned rotation
  through the console with their real Windows and Linux devices.
* **Coverage floors** (`scripts/ci/check-coverage.sh`): 90 for
  `server/internal/jobkeys` and for `agent/trust`; the packages each slice
  touches keep theirs.
* **database.md** gains, with each migration: `job_keys`, the report and
  cut-over columns on `devices` and `retired_devices`, `server_instances`,
  `issued_instructions`, the last restore, the authorities each device
  reports, and the tombstone in `settings`.

## Slices
Two of them depend on work not merged yet. Slice 1's rollback test needs
the host updater, being built on `feat/updater` (ADR-0052), and slice 2
needs that updater released with the record and the refusal (above).
Slice 2's API needs step-up authentication, which ADR-0055's slice 5b2
builds, so slice 2 does not merge before 5b2 either.

1. **Agents that can follow, the ring, and the tripwires.** The statements
   and the report in `agentproto`; the agent's trust store, the report by
   ADR-0009's rule (the authorities in `ca.pem` with it), the worker's
   redelivery and its failure at the third, the instruction log,
   `trust-key` and `status`; the ring, the move from `settings` with its
   tombstone, `server_instances`, `issued_instructions` and the last
   restore, the key chosen per device (one key so far), unknown keys and
   never-issued instructions flagged. No way to rotate yet. Verified on
   its own: the bundle test's step 1 with machine 3 and step 6; this agent
   against the last release's server; ADR-0052's upgrade and rollback test
   across the move, once the updater is merged. It can merge before the
   rest of the plan's step 9: the sooner such agents are in the field, the
   fewer devices a first rotation finds unable to follow.
2. **Rotation**: the statements offered by the rules above; start,
   finish, forget, replace-lost and recover through the API and the host,
   each under the ring's lock, with their audit records; the refusals
   while an older server is seen, while held and while an upgrade is under
   way; the floor's change made an event every server sees, on which
   ADR-0059's channel, when it is built, sends `closing` (`refresh`),
   tested there; the bundle test. Not merged before a released updater
   records the generation and refuses (above); its API needs ADR-0055's
   step-up (5b2).
3. **Console**: the page, the devices' states, the re-pin helper; the
   bundle test through the console.
4. **Restore and incidents**: the `incident` host commands (the
   authority's two phases among them, with the EasyPatch agent taking a
   bundle and reporting it), the drill, and the guide: a page on rotating
   and one on incidents with the sequence and the patching engine's part,
   with backup-restore.md (its restore procedure ending with `incident
   restored`), docker.md's encryption key steps and the threat model
   updated.

## Consequences
* The job key can be rotated with no downtime, and with nothing to do for
  devices that are online, or come back while the server still holds their
  key.
* A compromise is answered with a rotation that moves online devices in
  minutes and offline ones when they return, counts a device as moved only
  on its own signed report, and says that this report proves only an
  untouched agent. A leaked backup set is answered beyond the job key: the
  TLS identities, MeshCentral's keys, the secrets that stay readable, and
  a review for what was added.
* A key handed to a device that this server never issued, and an
  instruction it never issued, show from the first slice. The server keeps
  a record of everything it signs for 90 days to tell them apart.
* Replacing EasyRMM's own authority after a leak no longer cuts agents
  off, but takes two rounds through the operator's own tools until a
  signed hand-over of it exists.
* ADR-0017's "must re-enroll its agents" after a lost key becomes "must
  re-pin them" only for a seed lost while `.env` still opens the rest; a
  restore without `.env` still means reinstalling every agent, and builds
  from before this ADR need a reinstall or a hand edit.
* Backups from before a rotation stop restoring a working fleet once it is
  cut over to. Finishing asks for a newer backup, and the updater refuses
  such a rollback, reading two integers from the database to do so. A
  rollback that is safe for rotations is a single-host one: it is refused
  while a server on another host shares the database.
* Old keys stay sealed in the database while any device may need them,
  and a lost key's seed stays until it is recovered.
* A server from before this ADR cannot start against a migrated database,
  and no rotation starts while one is running.
* Agents send the report in heartbeats and job polls, and their
  instruction log in heartbeats, under ADR-0009's rule (amended, PR #52).
