# ADR-0081: The keystore, and BitLocker and LUKS recovery keys

* Status: Accepted (2026-11-26, decided in review). Design only; no code is changed by this ADR.
* Asked for by the owner (binding): "I think we should also create a highly
  secure keystore, to backup bitlocker keys for client devices as well";
  "yah it can hold LUKS to thats fine"; and that the keys stay on the
  EasyRMM server: "So we just need to find a super secure way to store the
  keys on the EasyRMM server". Everything marked *decided in review* is the
  writer's call; the three choices once left to the owner are decided in review below.
* Builds on: [ADR-0007](0007-hash-chained-audit-log.md) (audit),
  [ADR-0055](0055-lets-encrypt-in-one-step.md) section Step-up (5 minutes),
  [ADR-0057](0057-rotating-the-job-key.md) (what the job key signs),
  [ADR-0073](0073-windows-management-modules.md) (`winmod` actions),
  [ADR-0079](0079-saved-rdp-credentials.md) (credentials to re-wrap),
  [ADR-0052](0052-the-host-updater.md) (backups and restarts),
  [ADR-0053](0053-one-notification-sender.md) (notices),
  [ADR-0037](0037-one-licence.md) (licences of what we add),
  `server/internal/secrets`, `server/internal/devscope`.
* Source of the owner's words and the first design:
  [feature-plan-msp.md](../feature-plan-msp.md), sections 8 and "The keystore
  for BitLocker and LUKS recovery keys".

## Context

A BitLocker recovery password or a LUKS passphrase is the one secret that
opens a stolen or dead computer's disk, and the owner wants EasyRMM to keep
them, safely, for every managed computer.

What exists today:

* `secrets.Sealer` (`server/internal/secrets/seal.go`): AES-256-GCM under
  **one master key**, `EASYRMM_SECRET_KEY` from `.env`, with a key ring for
  rotation and associated data binding each value to its row. No key per
  organization, no envelope. The server holds that key in its own process
  and uses it unattended.
* **Backups put that key beside the data.** The backup guide writes `.env`
  into the folder that holds the database dumps, and ADR-0052's updater
  copies the data root and the deployment directory (with `.env`) into one
  backup directory. A stolen backup set opens every sealed secret. That is
  acceptable for TOTP seeds and integration credentials; it is not for
  recovery keys, whose theft opens customers' disks.
* The reveal pattern of ADR-0047 (open a secret in the transaction that
  writes its audit record) and a per-key rate limiter in `auth`.
* The deployment: one Docker host with every service on `network_mode: host`
  (never bridge). The server container mounts its data directory and reads
  `.env`; it holds no device and no host socket.

Nothing reads BitLocker, and LUKS has no code; feature 8's reader (read-only
status) comes first and is not this ADR's scope.

## Decision

### In short

* **A separate keystore process** in its own container, with no network, holds
  the key-encryption key (KEK) and does every wrap and unwrap. The main
  server never holds the KEK.
* **KEK versions are protected on the host**: sealed to the host's TPM 2.0
  where one exists, otherwise by a passphrase typed at the host after each
  start. A plain file is a named stand-in, off unless the operator chooses it.
* **One HPKE key pair per organization** (private half wrapped by the KEK)
  seals every recovery key at the agent, so the server can store and check
  escrow without being able to open it.
* **A recovery bundle for every KEK version is mandatory**: the keystore
  refuses to wrap anything until the operator has proved a restore works.
* **Reads** need their own permission, step-up, a reason, rate limits, an
  audit record written in the transaction that releases the key, a notice to
  every super administrator and, where an organization turns it on, a second
  person's approval.
* **No disk is encrypted until its recovery key is escrowed and verified.**

### 1. Key hierarchy

```
recovery code (offline, 160 bits) ──► recovery key pair (X25519)
                                        │ (public half stored by the keystore)
KEK vN (32 bytes, AES-256) ──sealed to host──► TPM blob or passphrase-wrapped
   │ wraps (AES-256-GCM)
   ├── per organization: escrow key pair (HPKE, X25519) — private half wrapped
   └── per organization: service key (32 bytes, AES-256-GCM) — wrapped
          │ (service key: only for §9, ADR-0079's credentials; later others)
recovery key (BitLocker password / LUKS passphrase)
   └── sealed at the agent to the organization's escrow public key
```

* **KEK**: random 32 bytes made inside the keystore. **Versioned**: version
  numbers rise by one; each wrapped key records the version that wrapped it.
  A *key check value* (HKDF-SHA-256 of a fixed label under the KEK, truncated
  to 16 bytes) is stored beside the version so a wrong or missing version is
  recognised without trying to unwrap.
* **Escrow key pair per organization**: HPKE (RFC 9180) base mode, KEM
  DHKEM(X25519, HKDF-SHA256), KDF HKDF-SHA256, AEAD AES-256-GCM. The public
  half is stored in PostgreSQL in clear (the server hands it to agents); the
  private half is stored in PostgreSQL **wrapped**: AES-256-GCM under the KEK,
  associated data `keystore-wrap-v1|<org>|<org key id>|escrow`, wire format
  `ks1.<kek version>.<base64url>`. HPKE is in the Go standard library
  (`crypto/hpke`) on the Go version this repository uses once it ships there,
  else `filippo.io/hpke`; either is checked against ADR-0037 first.
* **Service key per organization**: a symmetric key, same wrapping, used only
  for the optional move in §9.
* **Each escrow record** is one HPKE single-shot seal. Its `info` (HPKE's
  bound context) is `easyrmm-escrow-v1|<org>|<device>|<volume id>|<protector
  id>|<org key id>`, so a record copied to another device, volume, protector
  or organization fails to open. The row stores the HPKE encapsulation and
  ciphertext, never plaintext.
* **Fingerprint**: the first 16 bytes of SHA-256 over
  `easyrmm-fp-v1|<protector id>|<normalized secret>`. A BitLocker numerical
  password carries 128 bits of entropy (eight 16-bit groups), so the
  fingerprint reveals nothing usable; a LUKS passphrase has none (LUKS is
  checked another way, §5). It is stored with the escrow row.
* **Algorithms are named in the wire formats** (`ks1`, `easyrmm-escrow-v1`),
  so a later suite is a new version, not a migration of meaning.

### 2. Where the KEK lives

**The keystore container** (new service `keystore` in `deploy/docker-compose.yml`):

* `network_mode: none` (no network at all; not bridge, and not host: this is
  the one service that must not see the network), a read-only root file
  system, `cap_drop: ALL`, `no-new-privileges`, a non-root user, `ulimits`
  for memory locking, core files off (`core: 0`), and its own small tmpfs.
* It reaches **only**: its own state directory (a bind mount outside the
  data root and outside the deployment directory, so no backup copies it);
  a Unix socket directory `/run/easyrmm-keystore`; and, in TPM mode,
  `/dev/tpmrm0` (the kernel's resource-managed TPM device, never
  `/dev/tpm0`). It has no database, no `.env`, no Docker socket.
* **The server container reaches the keystore only through that socket**,
  mode 0660; the keystore checks the peer's user ID (`SO_PEERCRED`) and
  refuses any other. The server's container gets no TPM device, no keystore
  state and no KEK.

**Protection of the KEK on disk** (decided in review; the research the plan
waited for is folded in here: the TPM-sealed KEK in a separate process, with
a passphrase fallback, is the strongest combination that works unattended
and on every host):

1. **`tpm` (default when `/dev/tpmrm0` exists, physical or virtual).** The
   KEK is sealed to the TPM under a key in the owner hierarchy, with a policy
   bound to PCR 7 (Secure Boot state). A copy of the disk, a backup or the
   state directory opens nothing on another machine. It unseals unattended
   at start. Honest limits: root on the running host can ask the TPM to
   unseal as the keystore does; PCR 7 changes (firmware update, Secure Boot
   key change) make unseal fail until the recovery bundle is used (§4), so
   the keystore reports *TPM policy changed* in the console, never silently
   falls back; a virtual TPM's state belongs to whoever controls the
   hypervisor. The Go library (`go-tpm`, Apache-2.0) is checked against
   ADR-0037 in slice 1.
2. **`passphrase` (default when no TPM exists).** The KEK is wrapped by a key
   from Argon2id (64 MiB, 3 passes, 4 lanes, per-installation salt) of a
   passphrase chosen at init (at least 16 characters, or a generated
   six-word one). After every start the keystore is **sealed** until an
   operator unseals it **at the host** with `easyrmm keystore unseal`,
   which asks the keystore over its socket (prompt without echo). Unseal is
   **never offered by the console**, so a compromised console administrator
   can neither feed nor capture the passphrase. While sealed: the rest of
   EasyRMM works; agents still upload escrow (it is sealed to the public key
   and stored as *pending*); reads, verification and organization-key
   creation wait, and the console says *Keystore sealed* with the time. The
   updater's restarts therefore leave key reads waiting for a person, which
   is the price of this mode and is stated in the guide.
3. **`file` (opt-in stand-in).** The KEK in a root-only file in the
   keystore's state directory, for a host with no TPM where nobody can be
   present at restarts. It needs `EASYRMM_KEYSTORE_MODE=file` set on
   purpose. The console shows a standing *Keystore protection: file
   (stand-in)* warning, and the guide says what it does not protect against
   (a copy of the host disk opens it). Never the default.

Later and not built here: a split unseal (Shamir shares held by several
people) and a USB HSM through PKCS#11, as further `mode` values; the
format has room (`mode` is recorded with each KEK version).

**What a compromised main server can and cannot do.** It can ask the keystore
to unwrap, which the keystore counts, limits and records (§7); it cannot
read the KEK, and the keystore's own log (below) is out of its reach. Root on
the host can do what root can do; the threat model says so (§8).

### 3. Unseal at start and memory handling

* On start the keystore loads the wrapped KEK versions from its state
  directory, unseals them (TPM, or passphrase over the socket) and checks
  each against its key check value. It answers *unsealed* only when the
  newest version it needs is open; a missing older version leaves only the
  data wrapped by it unreadable, and the status lists which.
* The process calls `mlockall(MCL_CURRENT|MCL_FUTURE)`, sets `RLIMIT_CORE`
  to 0 and `PR_SET_DUMPABLE` to 0, and runs with swap disabled for the
  container (`memswap_limit` equal to `mem_limit`), so neither the KEK nor
  an opened key reaches swap or a crash dump. The KEK lives in a locked,
  `MADV_DONTDUMP` region, not in ordinary Go heap.
* An organization's private key is unwrapped **per operation** and zeroed
  after it; nothing is cached. HPKE open is cheap.
* **Plaintext handling** (decided in review, tighter than the feature plan,
  which had the server handle plaintext twice): the check at escrow upload
  happens **inside the keystore**, which opens the record, computes its
  fingerprint and returns only *match* or *mismatch*. The server sees a
  plaintext key **only at an authorized read**, where the keystore returns it
  over the socket and the server passes it once to the browser. Go cannot
  promise to erase every copy in a garbage-collected heap, so the process is
  locked and dump-free (above) and the server's read handler holds the value
  in one buffer it zeroes after the response is written; that is
  best-effort, and said so.

### 4. Backup and restore: recovery is mandatory

A KEK lost with its TPM, or a host lost with its disk, would make every
escrowed key worthless at the moment it is needed. So:

* **A recovery code at init.** `easyrmm keystore init` (run on the host at
  install, by `setup.sh` for a new deployment) generates a 160-bit recovery
  code, shown once as Crockford base32 groups, and derives a **recovery key
  pair** from it with Argon2id (the same parameters). The keystore keeps only
  the salt and the public half. The code is never stored.
* **A bundle per KEK version.** Whenever a KEK version is made, the keystore
  HPKE-seals it to the recovery public key and writes
  `recovery/kek-v<N>.bundle` in its state directory, plus a key check value.
  A bundle opens only with the code. Because the keystore holds only the
  public half, **rotating the KEK needs no code typed**.
* **The keystore refuses to wrap any organization key under a version until
  that version has been proved restorable**: the operator runs
  `easyrmm keystore verify-recovery --bundle <path>`, enters the code, and the
  keystore decrypts the bundle and compares the key check value. Init does
  this for version 1 before it finishes. A later version stays *pending* and
  the old one stays primary until verified. The console shows *recovery
  verified: yes/no* per version and an overdue banner.
* **Keep the three apart.** The backup guide and `setup.sh` say: the database
  dump (which holds wrapped keys and sealed escrow), the bundle and the
  recovery code are three things that must not share a place. The database
  alone opens nothing; the bundle alone opens nothing; together with the
  code they open everything, so the code goes to a password manager or a
  safe and the bundle to offline storage. **The guide's `.env` and dump
  step is changed so the dump no longer sits beside the master key** (that
  was already the case for the Sealer; it is fixed for good here), and the
  recovery bundle is never written to the folder that holds dumps.
* **The updater (ADR-0052) does not copy the keystore's state.** It copies
  the data root and the deployment directory as now; the keystore's state is
  outside both. KEK versions are only ever added, never changed, so a
  rollback of the database to an older state needs no older keystore state.
  The updater starts the keystore service and waits for *sealed or
  unsealed*; it never waits for an unseal. An existing deployment that
  upgrades gets the service but not an init: the console shows *Keystore not
  initialised, escrow is off* and the host command to run.
* **Restoring to a new host.** Install, restore the database, then
  `easyrmm keystore restore --bundle kek-v1.bundle [--bundle …]` with the
  code. The command imports each version, checks it against the version
  table's key check values, and re-seals it to the new host's TPM or
  passphrase. A version the database needs and no bundle supplies leaves only
  its data unreadable, and the console says which organizations and that key
  reads for them are off.
* **After any restore**, escrow is checked again on every device: the console
  marks every escrow *to be rechecked* and the agents report their current
  protectors, since a restored escrow may be older than a device's protector.
  Reads recorded after the backup are lost unless audit was forwarded
  (ADR-0023); the keystore's own log (§7) is a second record.
* **The recovery code itself** can be replaced (`easyrmm keystore
  rotate-recovery`, which needs the old code), writing new bundles; the old
  bundles remain valid for restoring old backups until destroyed. Up to
  three recovery recipients (so two people can each hold a code) is later.

### 5. Escrow flows

Escrow runs on **a signed agent route of its own**, never as job output and
never in the agent's journal, logs or a script's output. It is Go code in the
agent (a new capability under ADR-0009's protocol levels, sent only to
agents that announce it).

**How the agent gets the organization's public key.** As a signed instruction
in the heartbeat's answer, in the pattern of an update or an uninstall
(`internal/agentproto`): signed with the job key (ADR-0057) under a context of
its own (`easyrmm-escrow-key-v1`), bound to the device, the organization, the
escrow key's ID and version and an expiry. The agent keeps the newest version
it has verified and never goes back. A compromised server could hand an agent
a public key of its own, but it can already run code on every agent, so the
trust does not change; the threat model records it.

**Rate and size limits on the route** (decided in review): one escrow upload
per volume per five minutes, at most 20 per device per hour, a body of at
most 2 KiB, and a record is refused when the server would have to store a
second *current* record for the same protector.

#### BitLocker

1. **Read the protectors.** The agent calls `Win32_EncryptableVolume` through
   WMI in its own process: `GetKeyProtectors`, then for each type 3
   (numerical password) `GetKeyProtectorNumericalPassword`. This is the one
   exception to the agent inventory's no-WMI rule, and this ADR records it.
   Never `manage-bde` (its text is localized and goes through a pipe) and
   never a script: Group Policy's PowerShell transcription, where an
   organization turns it on, would write the output to disk. A Go WMI
   library (`go-ole`, `yusufpapurcu/wmi` or a thin COM binding of our own) is
   chosen and checked against ADR-0037 in slice 1.
2. **Escrow.** For each recovery password: compute the fingerprint, seal with
   HPKE to the organization's public key (the `info` above), upload with the
   volume ID, protector ID and fingerprint. Plaintext exists in the agent's
   memory only, is zeroed after the upload, and is never logged.
3. **Verify at upload.** The server passes the record to the keystore, which
   opens it, recomputes the fingerprint and returns *match*. A match marks
   the escrow **verified**; a mismatch marks it **stale** and the agent is
   told to escrow again. **Nothing is ever replaced by a record that does
   not match**: a record for a protector that already has a verified one must
   carry the same fingerprint, or it is stored as *conflict* beside the old
   one, which stays current, and an alert is raised (a compromised agent
   could otherwise destroy a good escrow). Superseded records are kept for 30
   days.
4. **Enable.** A `winmod` BitLocker `enable` action (ADR-0073) with a
   permission of its own (`device.bitlocker.manage`), step-up and the guards
   below. Because it handles the key, its executor is **native** (agent Go
   code) not a script: ADR-0073 is amended to allow an action whose executor
   is `native` (same catalogue entry, permission, audit and lint; no `.ps1`).
   Order: (a) check preconditions: TPM present and ready, an edition that
   allows it, no reboot pending; (b) add a numerical-password protector;
   (c) **escrow it and wait for *verified***; only then (d) add the TPM
   protector, or TPM+PIN, and (e) start encryption (used space only by
   default) and re-read the protectors. **Encrypt is refused until the
   escrow is verified.** On a failure after (b) the added protector stays
   escrowed and is removed only once the volume is encrypted or on request.
   TPM+PIN: the PIN is chosen by the technician as a one-time starting PIN
   and delivered as a job parameter on the existing channel, marked secret
   (redacted from the journal, audit and output), passed in-process to
   `ProtectKeyWithTPMAndPIN` (never a command line), and the user is told to
   change it; EasyRMM does not keep it. (Decided in review; slice 6.)
5. **Rotate after use.** A read (§6) marks the volume *rotation due*. At the
   next heartbeat after the read, once at least ten minutes have passed (the
   person has had time to type it), the agent adds a new numerical password,
   escrows it, the server verifies it, and only then does the agent delete
   the old protector by ID. **A volume is never without a verified escrowed
   protector.** A rotation that cannot verify leaves the old protector in
   place and alerts.

#### LUKS

There is no recovery key to read, so the agent makes one:

1. **Needs an existing unlock the agent has by itself**: a TPM2 token in a
   LUKS2 header, or a key file (`/etc/crypttab`'s). A volume protected only
   by a passphrase cannot be escrowed by the agent alone (see "Decided in review in place of owner questions").
2. The agent generates a passphrase from `crypto/rand` (40 characters from a
   32-letter alphabet, about 200 bits), then `cryptsetup luksAddKey`, with the
   new key on standard input or a descriptor (**never a command line**) and
   the existing unlock through the token (`--token-only`) or key file, with
   a bounded Argon2id memory cost so small hosts are not starved. It adds a
   LUKS2 token of type `easyrmm-escrow` naming the slot (LUKS1 has the slot
   number only).
3. It tests (`cryptsetup open --test-passphrase`), seals to the organization's
   key (`info` with the volume's LUKS UUID and slot), uploads, and **wipes its
   copy once the server confirms**. Nothing is removed before this.
4. **Checking afterwards is by metadata only**: the slot and its token still
   present and the slot's key-derivation parameters unchanged (a hash of the
   slot's header area, reported with each report). A changed slot marks the
   escrow *stale*.
5. **Rotate** (after a read, or on request): add a new slot, test, escrow,
   confirm, then remove the old slot. **Never the last slot, and never a slot
   without EasyRMM's token.** Every header change is exercised on VMs first.
6. `systemd-cryptenroll` and TPM2 tokens come with systemd 248; hosts with
   older systemd (RHEL 8 family's 239) add the slot with `luksAddKey` and
   no token. Each distribution is verified on its VM before it is listed.
   Volumes Clevis or a distribution's own TPM scheme manages are *managed
   elsewhere* and never rewritten.

### 6. Who may read a key

* **A permission of its own, `device.recovery_key.read`** (and
  `…recovery_key.approve` for approvers), **granted per user as a role
  add-on, and never implied** by any built-in role, super administrator
  included (decided in review: super administrators already run anything on
  every computer, so the permission is not a barrier to them, but a read
  must still be an explicit, recorded act of someone who holds it). Scoped
  like device permissions: by organization and site.
* **Step-up** (ADR-0055: a second factor in the last 5 minutes, recorded as
  `stepped_up_at`), checked on every read.
* **A reason**, free text of at least 10 characters, required and kept in the
  audit record. A ticket reference field is offered.
* **Two-person approval** on ADR-0055's general approvals, which this ADR's
  slice 2 builds. **Decided in review: optional per organization, off by
  default**, since a solo operator at a customer's locked laptop cannot wait
  for a second person; an organization needs at least two holders of the
  approve permission to turn it on, and the console recommends it. When on:
  the requester gives a reason; an approver other than the requester, with
  their own step-up, approves within 10 minutes; the approval is single-use
  and the key is shown to the requester only. (Decided in review below.)
* **Shown once**, with `Cache-Control: no-store`, in a panel that clears on
  close or after 60 seconds, with no copy-to-clipboard history on our side.
  Never in any list, export, report CSV, notification, error or job output.
* **Audit**, in the transaction that releases the key: the server begins a
  transaction, writes the hash-chained audit record (ADR-0007: who, which
  device, volume and protector, the reason, the approver if any, the escrow
  record ID and the keystore request ID, never the key), calls the keystore
  with that request ID, and commits **before** returning the key to the
  browser; if the commit fails the key is discarded. A refused or failed read
  writes its own record. Also `recovery_key.escrowed`, `.verified`, `.stale`,
  `.conflict`, `.rotated`, `.exported` and `.destroyed`.
* **Notice** to every super administrator and every administrator of that
  organization (who, which device, the reason; never the key), through
  ADR-0053's sender.
* **Rotation after use** (§5) follows every read, so a key read for one
  recovery is short-lived.

### 7. Rate limits and alerting on reads

* **In the server**, per user and per organization, on the existing limiter
  (`auth/ratelimit.go`): per user 5 reads per hour and 20 per day; per
  organization 10 per hour and 40 per day. A denied read is audited.
* **Inside the keystore too** (decided in review), because a compromised
  server process would skip the server's limits: global counters per
  organization (10 plaintext-returning calls per hour, 50 per day) and in
  total (30 per hour). Escrow verification returns no plaintext and has a
  separate, higher ceiling.
* **The keystore keeps its own append-only, hash-chained log** in its state
  directory of every operation (type, organization, record ID, the server's
  audit request ID, time, result), which the server cannot rewrite. It is
  forwarded to the host's journal.
* **Reconciliation** (decided in review): every hour a server job compares
  the keystore's plaintext-returning entries against audit rows. An entry
  with no audit row, or a plaintext-returning count above the audit's, is a
  **critical alert**: someone with the server process asked for a key without
  the process the console controls.
* **Alerts** (ADR-0053 channels, the alert system's own dedupe): any read (a
  notice, above); a read that reached half of a limit; any limit hit;
  keystore sealed for more than 15 minutes; keystore unreachable; protection
  mode `file`; *TPM policy changed*; recovery not verified; a KEK version
  overdue for verification; an escrow *conflict*; a rotation that could not
  verify.

### 8. Threat model

Super administrators and the host operator are trusted: they can run any
command on every managed computer already. Anyone who holds `script.run` or
`device.terminal` on a device can reach `manage-bde` on **an online** device,
and the keystore's permission does not change that: said plainly in the
console and the guide. (Accepted; decided in review below.)

| Attacker | What they get | What stops the rest |
|---|---|---|
| **Stolen database dump** | Wrapped private keys, HPKE ciphertext, fingerprints, public keys. | No key opens anything: the KEK is not in PostgreSQL or `.env`. 128-bit fingerprints reveal nothing. |
| **Stolen host disk or full backup set** (with `.env`, dumps, state directory) | Same, plus the keystore's wrapped KEK blob. | TPM mode: the blob opens only on that TPM. Passphrase mode: Argon2id of a passphrase not on the disk. File mode: nothing; stated. A bundle without the code opens nothing. |
| **Compromised console administrator** (session or password, without the read permission) | Cannot read a key: no permission, no step-up; cannot unseal (host-only). Can see status and that escrow exists. | Permission, step-up, reason, notice, limits, two-person where on. |
| **Compromised server process** | Can ask the keystore to unwrap, within the keystore's limits and logged by it. Cannot read the KEK or rewrite the keystore's log. | Keystore counters, its own log, hourly reconciliation raising a critical alert. Root on the host still wins; stated. |
| **Compromised agent** | Its own device's keys only (it can read them anyway). Can send a bogus escrow record. | AAD and `info` bind records to the device, volume and protector; a record that does not match a verified protector's fingerprint is stored as *conflict* and the good one stays current; 30-day retention of superseded records; rate and size limits. It cannot read another organization's or device's keys. |
| **Malicious technician** with the read permission | A key they are entitled to read, once, with a recorded reason. | Reason, notice to every super administrator, rate limits, two-person where on, rotation after use, per-site scope. A technician with `script.run` reaches online devices' keys without the keystore at all (accepted above). |
| **Malicious technician without it** | Nothing from the keystore. | Permission and row-level security on `organization_id`; AAD binds to the organization. |

Root on the running keystore host can ask the TPM to unseal or read the
process's memory. That is not defended against; the design keeps recovery
keys of **offline, stolen or dead devices** safe from database dumps, backups
and lower roles, and makes every read visible.

### 9. Re-wrapping ADR-0079's saved RDP credentials

ADR-0079 seals saved RDP passwords with the Sealer and left a `sealed_format`
column (`sealer-v1`, `keystore-v1`) for this move. The keystore exposes a
second, narrower call, **`service seal/open`** under the organization's
service key (AAD `rdp-credential:<id>:<device>:<scope>:<user>`, the same
string ADR-0079 defines), which returns plaintext to the server for the
gateway's injection. The move is a one-off, resumable job that opens each
value with the Sealer, seals it through the keystore, writes it with
`sealed_format = keystore-v1` and keeps both readable meanwhile.

**Decided in review: it is optional and off by default**, and ships last.
Moving it couples every saved-credential RDP session to the keystore being
unsealed (in passphrase mode, after every restart a person must unseal before
a saved credential works), and the gateway then uses the keystore on every
session, which is a different job from escrow's rare reads. An organization
that wants the stronger protection turns it on; the console says the cost.
The service call has its own limits (per session, not per read) and no
reason prompt. `EASYRMM_SECRET_KEY`'s other uses (TOTP seeds, integration
credentials, ADR-0057's job keys) stay on the Sealer; moving them is not
decided here.

### 10. Rotation and re-wrap

* **KEK rotation** (`easyrmm keystore rotate`, or a console request that only
  the host completes): make version N+1, write its recovery bundle, and wait
  for `verify-recovery` of it (§4). Then re-wrap, in batches that resume,
  every organization's escrow and service private keys under N+1 (the
  keystore unwraps with N and wraps with N+1; the server writes the new
  wrapped column and `kek_version` in one update; plaintext of the private
  key never leaves the keystore). Nothing is deleted.
* **An old version is kept**, apart from the data, **as long as any retained
  backup holds keys wrapped by it**. The console lists each version with the
  oldest backup (from the updater's and the backup guide's retention) that
  still needs it; `easyrmm keystore destroy-version N` is allowed only when
  no retained backup does, and requires the code. A version is therefore
  destroyed only after the backups that needed it have expired.
* **Organization key rotation**: a new escrow pair is made; agents receive
  the new public key by the signed instruction and re-escrow; the keystore
  re-seals existing records to the new key inside itself (open with the old
  private key, seal to the new one), with no plaintext leaving it. The old
  private key is *retired* and kept until every record is moved and the
  retention in §4 passes, then destroyed.
* **Offboarding**: an organization's keys exported to a passphrase or a key
  the customer gives, behind step-up, audit and approval, never through a
  report's CSV; deleting the organization destroys its wrapped keys, final
  once every backup that holds them has expired and the KEK versions only
  those backups needed are destroyed.

### 11. Storage and the migration

New tables (migration `9xxxx_keystore`, goose up and down, numbered by the
brief; none of them is created by this ADR):

* `keystore_kek_versions` (`version`, `check_value`, `mode`, `created_at`,
  `recovery_verified_at`, `state`): metadata only; no key material.
* `keystore_org_keys` (`id`, `organization_id`, `purpose` (`escrow` or
  `service`), `version`, `public_key`, `wrapped_private`, `kek_version`,
  `state` (`active`, `retired`, `destroyed`), timestamps).
* `recovery_key_escrows` (`id`, `organization_id`, `device_id`, `volume_id`,
  `kind` (`bitlocker`, `luks`), `protector_id`, `org_key_id`, `enc`,
  `ciphertext`, `fingerprint`, `state` (`pending`, `verified`, `stale`,
  `conflict`, `superseded`, `destroyed`), `rotation_due`, timestamps).
* `recovery_key_reads` is not needed: reads are audit rows.

All three have `ENABLE` and `FORCE ROW LEVEL SECURITY` on `organization_id`
as the other per-organization tables, and a test proves another
organization's scope sees no row. The pieces that use these tables sit behind
one Go interface in `server/internal/keystore` so the main server never
imports key material handling.

### 12. What `devscope` gates

`devscope.Allowed(orgID)` is checked, once per decision, before every
**automatic** behaviour this ADR adds: creating an organization's keys on its
first escrow; the signed heartbeat instruction that carries the public key
and asks for escrow; automatic rotation after a read; the hourly
reconciliation and every alert, notice and recheck after a restore; the
RDP-credential move. An organization outside the dev scope gets no keys, no
instruction and no job. A **human's explicit act** (a read, an export, an
`enable` action) is not an automatic behaviour and is not gated by it, but
creates nothing for an organization outside the scope: it is refused with
the reason. The keystore itself, which is not per organization, starts
regardless. Until the guard has landed everywhere, the framework's wrapper
calls `devscope.Allowed`, as ADR-0073 does.

### 13. Tests

* **A known key through every path.** A test escrows a known password and
  reads, rotates and exports it, then searches the logs, audit rows
  (including forwarded), notices, errors, job output and journal for it,
  as ADR-0053 does for webhook URLs.
* Keystore unit tests: wrap and unwrap, a wrong version, a swapped context
  (every `info` and AAD field), tampered ciphertext (`ErrDecrypt`), counters
  and limits, a locked-memory check, no core file on a forced crash.
* Integration tests on real PostgreSQL and a real keystore process:
  escrow, verify, conflict, stale, the audit-then-release order, a failed
  commit discarding the key, reconciliation raising on a forged call,
  restore from a bundle, sealed and unsealed, RLS.
* A TPM VM and a no-TPM VM; a Windows VM for BitLocker enable and rotate; LUKS
  VMs for each distribution; a test that a restored database with a missing
  KEK version turns only that data's reads off.

### 14. Slices

1. **The keystore and BitLocker escrow.** The `keystore` service and
   container; init, KEK versions, TPM and passphrase modes (file stand-in);
   recovery bundles and `verify-recovery`; the backup guide, `setup.sh` and
   the updater changed with it; organization keys; the signed public-key
   instruction; the agent's WMI reader (the exception) and escrow route;
   verification at upload; per-volume escrow state (*missing*, *pending*,
   *verified*, *stale*, *conflict*) in the console and for feature 2's
   control. No reads yet. Needs feature 8's read-only reader.
2. **Reads**: the permission, step-up, reason, limits (server and keystore),
   audit, notices, the keystore's log, reconciliation, and ADR-0055's
   general approvals with the two-person rule.
3. **LUKS escrow** where the agent can unlock by itself.
4. **Actions and rotation**: BitLocker `enable` (the verified-escrow gate),
   rotation after a read, LUKS rotation, KEK and organization-key rotation.
5. **Restore tooling and the offboarding export.**
6. **Later**: TPM+PIN, the RDP-credential move (§9), split unseal, a USB HSM,
   extra recovery recipients, and the passphrase-only LUKS route once decided.

## Decided in review in place of owner questions

These were open when the ADR was written. Each is decided in review as
recommended below and can be changed by the owner; none blocks slice 1.

1. **Two-person approval default:** off per organization, with the
   console recommending it; an organization turns it on.
2. **LUKS volumes protected only by a passphrase:** report *cannot escrow*;
   slice 6 adds the console flow where a technician types the existing
   passphrase under step-up, delivered like TPM+PIN's PIN and never kept.
3. **Script and terminal rights reach an online device's keys:** accepted,
   and said so in the console and the guide.

## Consequences

* A new container and a host command; a TPM-less host needs a person at each
  restart for the keystore to open (or the weaker `file` stand-in).
* Recovery is mandatory and visible: installs prove a restore before escrow
  starts; losing both the bundle and the code ends the escrow.
* The agent gains a WMI reader for one class, a signed escrow route and
  native `winmod` actions; ADR-0073 gains a `native` executor.
* Plaintext is in the server's memory only at a read; every read is audited,
  noticed, limited twice and reconciled.
* ADR-0054's `bitlocker` module takes its values from feature 8's reader, as
  the feature plan says; that is an amendment for ADR-0054's owner, not made
  here.

## Amendments

Amended 2026-11-26 (decided in review, while building slice 1):

* **HPKE is the standard library's.** `crypto/hpke` ships in Go 1.26 and later
  and this repository builds with Go 1.27, so `filippo.io/hpke` is not added.
  The suite is the one in section 1; `internal/escrowcrypto` is the one place
  that names it, for the agent (seal) and the keystore (open).
* **Dependencies (ADR-0037).** `github.com/google/go-tpm` (Apache-2.0, already
  in the module graph through Sigstore) for TPM mode; `github.com/go-ole/go-ole`
  (MIT) for the agent's WMI reader, with our own thin use of its dispatch calls
  (no `yusufpapurcu/wmi`, which reads properties into structs and cannot call
  methods with out-parameters); `github.com/google/go-tpm-tools` (Apache-2.0)
  only through go-tpm's simulator package, in tests built with cgo, so no
  shipped binary links it.
* **Two sockets.** The service socket (`/run/easyrmm-keystore/keystore.sock`,
  mode 0660) carries `status`, `create_org_key` and `verify_escrow` and admits
  only the server's user ID (`SO_PEERCRED`). `init`, `unseal`,
  `verify-recovery` and `new-version` are on a second socket inside the
  keystore container (`/run/keystore-admin/admin.sock`, mode 0600, admits only
  the keystore's own user ID) that is not mounted anywhere else, so the only
  way to it is `docker compose exec` at the host. This is how "unseal only
  from the host CLI" is enforced rather than promised. A peer that is not
  admitted gets no answer at all.
* **The host command is the keystore binary.** `easyrmm-keystore serve` is the
  process; `init`, `status`, `unseal`, `verify-recovery` and `new-version` are
  commands of the same binary, run in the container by
  `deploy/scripts/easyrmm-keystore`. Secrets are read from the terminal
  without echo, never from arguments or the environment. Init shows the
  recovery code once, asks for it typed again and verifies the version-1 bundle
  before it ends; a keystore whose recovery is not verified wraps nothing
  (`recovery_not_verified`). The generated six-word passphrase is not built; a
  passphrase of at least 16 characters is typed twice.
* **One image, two programs.** The keystore container runs the server image's
  second binary (`/usr/local/bin/easyrmm-keystore`, entrypoint and healthcheck
  set in the compose file), so a release pulls and verifies one image, the
  manifest and the updater's `compose config --images` check are unchanged, and
  the keystore needs no image of its own. It is still its own container with
  `network_mode: none`, a read-only root, `cap_drop: ALL`,
  `no-new-privileges`, user 65531, `memlock` unlimited, no core files and
  `memswap_limit` equal to `mem_limit`. `network_mode: none` is the one
  exception to the deployment's host networking (`docs/architecture/network.md`).
* **Where the socket lives.** The service socket's folder is `run/` inside the
  keystore's state directory (`/var/lib/easyrmm-keystore/run`, mounted at
  `/run/easyrmm-keystore` in both containers, read-only in the server's), not
  a host `/run` folder, so it exists after a reboot with nothing to recreate
  it. The state directory is `EASYRMM_KEYSTORE_DIR`, which `setup.sh` refuses
  to put in or around the data root or the deployment's tree, and the updater
  refuses the same at every upgrade (`checkMounts`).
* **The TPM device** is offered through `EASYRMM_TPM_DEVICE` and
  `EASYRMM_TPM_GID` in `.env` (set by `setup.sh` when `/dev/tpmrm0` exists),
  because the updater refuses a second compose file and `COMPOSE_FILE`.
* **Device moves (ADR-0069).** Within an organization the escrow and volume
  rows follow the device; a move to another organization deletes them, audited
  with counts only, and the agent escrows again to the new organization's key.
  An agent keeps its rollback protection per organization: it records the
  organization with the newest key version it verified, and a verified key of
  another organization resets that record.
* **KEK versions are mirrored.** The keystore has no database, so the server
  copies each version's metadata (`keystore_kek_versions`: check value, mode,
  state, verified-at; no key) from its status, to show recovery state and for
  the overdue-verification alert later.
* **Escrow states, as built.** The unique index admits one `pending` or one
  `verified` record per protector. A `stale` record never displaces a verified
  one: with a verified record standing, a mismatching record is stored `stale`
  beside it, and a matching record of another secret is stored `conflict`. The
  console shows a conflict over the verified record it sits beside. A
  `pending` record (stored while the keystore was sealed or away) is checked by
  a 30-second server job when the keystore is ready, behind `devscope.Allowed`.
  Uploads are limited by counting rows (one per volume in five minutes, twenty
  per device per hour), so the limit survives a restart.
* **Capability.** An agent announces `escrow.v1` in `HeartbeatRequest.Caps`
  (sent only to a server of level 2 or higher, like the channel list). The
  server sends the escrow key only to a Windows device whose agent announced it,
  in an organization `devscope.Allowed`, once the keystore is unsealed with its
  recovery verified; a heartbeat without the key tells the agent to stop. The
  agent has no dev-scope setting of its own: it escrows only with a key the
  server signed, which is the server's gate.
* **Not in slice 1, as the slice list says:** reads and their permission,
  step-up, reason, limits, the keystore's hash-chained log, reconciliation and
  the alerts of section 7; LUKS; rotation of any key; restore tooling
  (`easyrmm-keystore restore` is slice 5). A KEK version made with
  `new-version` stays pending until `verify-recovery`, and the re-wrap of
  organization keys that follows a rotation is slice 4.
* **Honest limits found in the code.** The sealing command carries the KEK to
  the TPM through the kernel's device without a parameter-encryption session.
  WMI returns the recovery password as a BSTR that the agent overwrites in
  place, but the Go string the COM layer makes of it cannot be erased, so the
  agent's zeroing is best-effort, as the server's is.

Amended 2026-11-26 (decided in review, while building slice 2):

* **The permission is two add-on roles.** The ADR asks for a "role add-on"; no
  per-user permission grants exist, so `device.recovery_key.read` and
  `device.recovery_key.approve` are carried by two roles, *Recovery Key Reader*
  and *Recovery Key Approver* (`key_reader`, `key_approver`), assigned beside a
  person's ordinary role at an organization or a site. They are not in
  `rbac.AllPermissions`, which is what the super administrator role holds, so
  no built-in role implies them, the super administrator included. The
  `role_assignments` checks name the two new roles.
* **Two-person approvals are minimal and for key reads only.** ADR-0055's
  general approvals do not exist in this tree, so `recovery_key_requests`
  holds one request per person per record: pending for 30 minutes, then
  approved by a person other than the requester (with the approver's own
  step-up) and usable by the requester alone, once, within 10 minutes. The
  requester and the approver may not be the same person (a database check as
  well as the service's). Turning the rule on needs two holders of the approver
  role in the organization and a step-up; it is off by default. When ADR-0055's
  approvals land, this table can be moved onto them.
* **Server limits count the audit log.** The per-user and per-organization
  limits count `recovery_key.read` rows with outcome success in the audit log,
  not the in-memory limiter, so a restart resets nothing; a refused read is
  audited, and reaching half of a limit or a limit raises a warning.
* **The keystore's log and its answers.** The log is `log/keystore.log` in the
  state directory (JSON lines, each with the hash of the one before, fsynced,
  also sent to the process log). A read writes its line before the key is
  returned, and a keystore whose log does not verify at start, or cannot write
  it, returns no key. The keystore's counters (10 an hour and 50 a day per
  organization, 30 an hour in total) are rebuilt from the log at start. The
  `read_escrow` answer is encoded by hand into a buffer the keystore zeroes;
  the server's client reads it into a buffer it zeroes, and the HTTP handler
  writes the key by hand and zeroes its own copy. Go's HTTP and TLS buffers
  may still hold a copy until they are overwritten: stated, not defended.
* **Reconciliation.** The hourly job reads the log after its cursor, verifies
  the chain, leaves entries younger than two minutes for the next run (the
  audit record commits just after the keystore answers) and requires each
  plaintext-returning entry to be matched by as many `recovery_key.read` audit
  rows carrying its request ID. A failed read after the keystore was asked is
  audited with that request ID (outcome failure), so a discarded key is
  accounted for. A key with no audit row, or more entries than rows, is a
  critical alert; so is a log that does not verify.
* **Keystore alerts have their own table.** `alerts` is per device and its
  kinds are constrained; the keystore's alerts (unaudited read, log broken,
  read-limit) are rows of `keystore_alerts` with the same dedupe (one open per
  kind and subject), shown in the console and mailed to administrators.
  Slice 2 builds only the read-related alerts of section 7; sealed for more
  than 15 minutes, unreachable, file mode, TPM policy changed, recovery not
  verified, a KEK version overdue and the rotation alerts wait for the slices
  that have those events (or a monitor), and an alert is resolved by a person
  in the database until the console gets a control for it (slice 3 added the
  monitor, the control and the pages: see its amendment below).
* **Notices** are a row per read (`keystore_notices`, shown to administrators
  of the organization and super administrators) and a mail to each of them
  through ADR-0053's sender when one is in force; the dev-scope guard is
  checked before the mail.
* **Rotation after a read** (section 6) is slice 4, as the slice list says.

Amended 2026-11-26 (decided in review, while building slice 3):

* **Condition alerts and the control to resolve one.** The server checks the
  keystore's status every minute (`keystore.Monitor`) and raises, into
  `keystore_alerts`: *unreachable* (critical, after three failed checks in a
  row, so a restart is not an alert), *sealed* for more than 15 minutes
  (critical), *TPM policy changed* (critical), *protection mode file*
  (warning), *recovery not verified* (warning: no version proved, or a pending
  version older than a day) and *KEK version overdue* (warning, a pending
  version older than a week). A conflicting escrow raises *escrow conflict*
  (warning, the organization's) from the upload. Conditions close by
  themselves when they end (`resolved_by` stays empty); a person who resolves
  one while it still holds is not told again for 24 hours. They are mailed to
  the super administrators (the organization's alert, to its administrators)
  through the same sender as slice 2's, once when opened. *A rotation that
  could not verify* waits for slice 4, which has that event. The control is
  `POST /keystore/alerts/{id}/resolve` (platform alerts need
  `settings.manage`; an organization's, `user.manage` there), audited as
  `keystore.alert_resolved`, with who did it.
* **Console pages** go where ADR-0072 puts them: an organization's
  *Recovery keys* tab (`org.manage`: the two-person switch, off by default and
  recommended, the notices of reads, and its alerts) and *Settings >
  Keystore* (`settings.manage`: the keystore's state, its KEK versions and
  every open alert).
* **LUKS fingerprint.** Section 1 says a LUKS passphrase has no fingerprint. It
  has one: the agent's passphrase is 200 bits from `crypto/rand`, more than a
  BitLocker password's 128, so the same SHA-256 fingerprint reveals nothing
  usable, and the keystore verifies a LUKS record exactly as a BitLocker one
  (opens it, normalizes by kind, compares). The agent has also tested the
  passphrase against the new slot (`cryptsetup open --test-passphrase`) before
  it uploads, which is the "checked another way" of section 5.
* **How the agent marks and finds its key slot.** A LUKS2 token of type
  `easyrmm-escrow` with an `escrow_id` (a UUID) names the slot; that UUID is the
  protector's ID in the record's `info`, the report and the console, so a slot
  number reused later never confuses two records. **LUKS1 is *cannot escrow*:**
  it has no token, so a slot of EasyRMM's could not be told from an
  administrator's, and the rule never to remove a slot without EasyRMM's token
  could not be kept. The agent unlocks by itself with a key file named in
  `/etc/crypttab` for that volume (not a `/dev/` file) or, failing that, a
  `systemd-tpm2` token; a Clevis token makes the volume *managed elsewhere*
  and nothing is written to it. The new key goes to `cryptsetup` on standard
  input only; the key file is named by path on the command line, the key never
  is. Argon2id memory is a quarter of the available memory, between 64 and 256
  MiB.
* **Stale by metadata only.** Each report carries, per slot of ours, the
  SHA-256 of the slot's header metadata (key derivation with its salt, area
  and splitter). A verified record whose slot is gone or whose hash differs
  from the one stored with the record becomes *stale* at once, and the server
  asks for a new key naming the stale slots to *replace*. The agent adds the
  new slot, escrows it, and only when the server says *verified* removes each
  stale slot of its own, never the last slot of the volume, never a slot
  without its token, never a slot another token names. A key the server did not
  accept (or an upload that failed) has its slot removed again at once.
* **Rate limits for LUKS** are slice 1's (one upload per volume per five
  minutes, twenty per device per hour). A volume whose unlock fails is left
  alone for an hour.
* **A device that runs Linux** gets the signed key instruction, in an
  organization the dev-scope guard allows, once its agent announces the
  capability; the console shows the card only for a Linux device that
  reported a LUKS volume.

Amended 2026-11-26 (decided in review, while building slice 4):

* **The native executor.** A native action is a job of shell `native` whose
  script names a handler built into the agent. It is not a shell a person may
  give a script (`agentproto.ValidShell` refuses it, and the jobs table's
  `shell` check gains the value for the server's own jobs only); an agent
  accepts it only if its poll lists the capability `job.native`, and the server
  sends one only to such an agent; the payload must be of the params version,
  so the signature covers the parameters' hash; the pin the job records is the
  SHA-256 of the handler's name. The handler answers with the same single
  result line a script prints (`agentproto.NativeResult`), so the server
  records, types and audits it as it does any action, and no output is kept.
  An agent without the handler fails the run and never runs the name as a
  script.
* **BitLocker `enable`** is `bitlocker.enable` of a module, `bitlocker`, that
  is not in the modules catalogue: no role offers it and it has no toggle,
  since turning BitLocker on is always a person's explicit act (the dev-scope
  guard still applies). Its permission is `device.bitlocker.manage`, held by
  organization administrators and the super administrator, and not by site
  administrators or technicians; the action is `Destructive`, so it needs the
  typed `bitlocker.enable:<computer's name>` (the name is compared with the
  device's real name, as `SubjectIsDeviceName` does), a step-up and an audit
  row recording both. The server's half of the gate (`EnableReady`) makes no
  job unless the organization is in the dev scope, the keystore can wrap and
  verify, and the organization has its escrow key. The agent's half is the
  order in section 5, step 4, kept exactly: preconditions, add the
  numerical-password protector, **report it, escrow it and wait for the server
  to say verified**, then the TPM protector, then encryption. The agent also
  refuses a computer that is not the one named, **a domain controller** (the
  ADR allows none), a TPM that is not ready, an edition without BitLocker, a
  pending restart, and a volume that already has BitLocker or any protector.
  Clarified from step 4: a protector that the server did *not* verify (stale,
  conflict, a failed upload) is removed again, because an unescrowed password
  is useless to keep; one whose record is only *pending* (the keystore is
  away) stays and encryption is still refused. The Windows reader now also
  lists a volume with a drive letter that BitLocker is not on, as `decrypted`
  with no protectors, which is what the console offers the action for. The
  action does not run TPM+PIN (slice 6).
* **Rotation after a read.** A read sets `rotation_due` and `rotation_due_at`
  on the record in the same transaction that releases the key. Ten minutes
  later (by the database's clock) the next report's answer carries
  `Rotating` (BitLocker) or `Replace` (LUKS: its existing replace-after-verified
  step is the rotation). The agent adds the new protector, reports it so that
  the server knows it, escrows it, and only when the answer is *verified*
  removes the old one. A new key that did not verify is removed again and the
  old one stays. If the keystore was away (the answer is *pending*), nothing is
  removed; when the new record is verified the server's next answer carries
  `Remove` with the `Successor`, and the agent removes the old protector only
  if the successor is on the volume (LUKS also through the backend's rules:
  never the last slot, never a slot without EasyRMM's token, confirm-before-
  remove). While a rotation is under way the answer says `Watch`, so the agent
  reports every ten minutes instead of every hour. A rotation is complete when
  the old protector is gone from a report and another verified record stands:
  the old record becomes *superseded* and `recovery_key.rotated` is audited.
* **The alert for a rotation that could not verify** (`rotation_unverified`,
  warning, the organization's, mailed to its administrators once): raised when
  a record that arrives for a volume whose key is due for rotation is stale,
  and when a rotation has been due for more than a day (the computer is off or
  its agent cannot finish). It carries no key, writes `recovery_key.rotation_failed`,
  is behind `devscope.Allowed`, and closes when the rotation completes.
* **KEK rotation.** `easyrmm-keystore new-version` and `verify-recovery` are
  unchanged and still the host's. Once a version is verified it is the primary,
  and the server's re-wrap job (`RewrapKEK`, every half minute with the pending
  check) asks the keystore to unwrap each organization key with the version
  that wraps it and wrap it with the primary (`rewrap_org_key`, on the service
  socket; the key never leaves), and writes the new form and `kek_version` in
  one update that succeeds only on the form it read. Nothing is deleted: the
  old version stays in the keystore. The job is resumable because what is left
  is what a query finds; it is an automatic behavior and checks
  `devscope.Allowed` for each organization. The reconciliation compares each
  key's recorded version with the version its wrapped form names and raises a
  critical alert (`keystore_rewrap_drift`) on a difference. The console shows,
  per version, how many organization keys it still wraps. **Not built, as the
  slice list leaves them for slice 5:** `destroy-version`, and a console
  request for a rotation (the ADR's text says only the host completes it).
* **Organization-key rotation.** `POST /organizations/{id}/keystore/rotate-key`
  (organization manager, step-up, refused as not found outside the dev scope)
  makes the next escrow key, retires the active one in the same transaction and
  audits it. Agents get the new key by the signed instruction at their next
  heartbeat; they do not re-escrow, because the keystore moves the records:
  `reseal_escrow` opens a record under the old key and seals it to the new one
  inside the keystore, refusing unless the record's fingerprint is the one the
  server holds and unless old and new contexts differ only in the key's ID; the
  server then has the keystore open the result under the *new* key before it
  replaces the stored record, and the replacement succeeds only on the record
  it read. Verified and conflict records move; stale ones on a retired key are
  superseded; pending ones wait for the check that settles them; superseded
  ones are not moved. A retired key with no record left is marked drained once
  and kept (wrapped, and still re-wrapped by a KEK rotation): its destruction
  waits for the retention in section 4, which is slice 5.
* **Honest limits.** The Windows manager's WMI calls (the numerical-password
  protector, the TPM protector, `Encrypt` and its used-space flag, the TPM and
  edition checks) were compiled and linted for Windows and exercised only
  against a stand-in; the CI step on a file-backed virtual disk exercises the
  recovery-password protectors where the runner's edition has BitLocker, and
  nothing there has a TPM or encrypts. The agent cannot tell a removable drive
  from a fixed one, so the console may offer the action for a USB drive with a
  letter (its TPM step would then fail after the key is escrowed).

## References

ADR-0007, 0009, 0023, 0037, 0047, 0052, 0053, 0054, 0055 (step-up), 0057, 0066,
0073, 0079; RFC 9180 (HPKE); `server/internal/secrets/seal.go`,
`server/internal/auth/ratelimit.go`, `server/internal/devscope`,
`internal/agentproto`, [the feature plan](../feature-plan-msp.md).
