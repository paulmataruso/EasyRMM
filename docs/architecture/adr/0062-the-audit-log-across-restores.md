# ADR-0062: The audit log across restores

* Status: Proposed (2026-11-21). Not implemented.
* Amends: [ADR-0007](0007-hash-chained-audit-log.md) (how a record's ID
  is chosen), [ADR-0023](0023-audit-forwarding.md) (what an `id` means to
  a collector) and [ADR-0052](0052-the-host-updater.md) (two fields in the
  rollback's audit record). Each gains an *Amended by ADR-0062* line when
  this is implemented.
* Builds on: the [backup guide](../../operations/backup-restore.md), with
  *Restore in place* (PR #74); the updater's rollback (PR #70,
  `updater/internal/host/db.go`); and
  [ADR-0060](0060-collecting-logs.md)'s identity for its log store.

## Context
A run of the restore drill found that a manual restore makes audit
record IDs repeat.

What a restore does today:

* **IDs come from a sequence.** `audit_log.id` is `bigint GENERATED
  ALWAYS AS IDENTITY` (`server/migrations/00001_core.sql`).
  `easyrmm_audit_append`, the only writer, takes an advisory lock, reads
  the newest record's hash and inserts; the identity sequence gives the
  ID. The hash covers the record's fields and the previous hash, not its
  ID (`easyrmm_audit_canonical`).
* **The dump carries the sequence.** `pg_dump` writes
  `setval('public.audit_log_id_seq', …)`, so a restored database hands
  out the IDs that followed the backup again. They were already used by
  the records the restore discarded.
* **Forwarding keys on the ID.** One row, `audit_forwarding`, keeps
  `last_id`, the last record sent; the forwarder sends records with a
  higher ID, in order (`server/internal/auditfwd/service.go`). Each
  message carries the record as JSON with `id`, `prevHash` and
  `entryHash` (`message.go`). The forwarding guide tells collectors that
  a record "can arrive twice after a failure; its `id` tells the copies
  apart" ([audit-forwarding.md](../../operations/audit-forwarding.md)).
* **So after a manual restore**, a collector receives new records under
  IDs it already holds with other content. And `last_id` comes back with
  the database, so the records between the backup's position and the
  backup's newest record are sent again.
* **The updater already handles its own restores** (ADR-0052, PR #70).
  Before restoring, it reads the discarded database's highest ID (the
  larger of the newest record's ID and the sequence's last value) and
  chain head. After restoring, it moves the sequence past that ID (by a
  million when the database could not be read) and appends
  `updater.rolled_back`, naming the discarded head, through
  `easyrmm_audit_append`. Its restore copies the data root back, so the
  database is the same PostgreSQL cluster, as it was.
* **A manual restore has no such step.** Both of the guide's paths load
  dumps into a new cluster: onto a new host, and in place, where the data
  root (`/srv/easyrmm/postgres` with it) is set aside first. On a new
  host, the old database is gone.

What can be seen from inside the database, checked while writing this on
PostgreSQL 18.6 (the deployment's image, in throwaway containers):

* `pg_control_system()`, which gives the cluster's system identifier, can
  be run by a role that is not a superuser.
* A dump restored into a new cluster: a new system identifier. The
  database's OID was the same as before (16386 in both); the table's
  OID differed by one.
* The same dump restored with `pg_restore --clean` into the database it
  came from: the same system identifier, a new OID for `audit_log`.
* A copy of a stopped cluster's directory, started as another container:
  the same system identifier and the same OIDs.
* The timeline was 1 in all three.
* A `SECURITY DEFINER` function owned by a role that is not a superuser
  can insert an ID it chose with `OVERRIDING SYSTEM VALUE` and move the
  sequence with `setval`; a later insert that took the sequence's next
  value continued after it.

## Decision

### IDs that never repeat
*Decided in review.*

* `easyrmm_audit_append` chooses each ID, under the lock it already
  holds. The ID is the greatest of three values: the newest record's ID
  plus one, the sequence's last value plus one, and the database's clock
  (`clock_timestamp()`) in microseconds since 1970. The function moves
  the sequence to that ID and inserts the record with `OVERRIDING SYSTEM
  VALUE`. The sequence stays for three reasons: the dump carries it, the
  updater reads it and moves it, and a version from before this ADR,
  which a rollback can start, takes IDs from it alone.
* **Why it holds without detecting anything.** The one thing outside the
  database that every restore leaves in place is the clock. A restored
  database's newest ID was made no later than its backup. Every ID the
  restore discarded was made by the clock before the restore. The clock
  has moved on since, so the first ID after any restore is above all of
  them, whether the restore is detected or not. ADR-0052's rollback
  guards use the same rule for their generations.
* IDs get ahead of the clock only while records are appended faster than
  one a microsecond. Each append is a locked query and an insert, which
  take longer, so the lead does not build up. Microseconds, not
  milliseconds: a burst of appends could run ahead of a millisecond clock.
* **Their size.** In 2026 an ID is about 1.8 × 10^15 (16 digits). That
  stays below 2^53 until the year 2255. 2^53 is the largest integer that
  JSON readers using doubles (the console, many collectors) hold exactly.
  The API's bounds (`after` up to 2^62) hold.
* Existing records keep their IDs, and the first record after the
  migration jumps to the clock. IDs are no longer consecutive. They never
  were a count: a transaction that rolls back already leaves a gap in a
  sequence. The chain shows a missing record, not the IDs (ADR-0023). The
  ID is not hashed, so existing chains verify unchanged.
* **The limit: a clock that goes back.** IDs can repeat if the restored
  host's clock is behind the lost host's by more than the time between
  the last discarded record and the first new one. That time is the
  restore itself, minutes at least, and synchronized clocks are far
  closer than that. When the discarded head is known (the updater, and in
  place through the guide's step below), the sequence is also moved past
  it, so the clock does not matter there. A collector sees a repeat as the
  same `id` with another `entryHash`, which the forwarding guide tells it
  to treat as an alarm.

### Detecting a restore
*Decided in review.*

* **The signal** is a pair: the cluster's system identifier (from
  `pg_control_system()`) and the audit table's OID
  (`'public.audit_log'::regclass`). The server compares it with a one-row
  table, `audit_log_identity`. The migration fills that table, and only
  the owner's functions read and write it.
  * **The system identifier** is made by `initdb`, once for each cluster.
    It lives in the cluster's control file, which no dump carries. Both of
    the guide's restores load the dump into a cluster that PostgreSQL's
    first start has just made. The row comes back from the dump naming
    the old cluster, so the live identifier differs.
  * **The table's OID** covers a dump restored into the cluster it came
    from (`pg_restore --clean`, or the database dropped and made again).
    The guide never does this, but an operator restoring by hand might.
    The table is made again and gets a new OID: OIDs come from one counter
    per cluster that only moves forward. It wraps after 2^32, far beyond
    what this cluster's objects use.
  * Neither OID identifies a cluster on its own. In the check above, the
    database's OID was the same in the new cluster.
* **Where it runs.** In `easyrmm_audit_append`, under its lock, before it
  reads the newest record; and once when the server starts, after its
  migrations, so that a restore is recorded before the server serves
  anything.
  * In the append, so that whoever appends first after a restore
    (the server, the updater's `psql`, a migration, `recover`) appends
    the restore's record first, in the same transaction. If that
    transaction rolls back, the record goes with it, and the next append
    writes it.
  * Not only on new connections, as ADR-0060 checks its store. A dump
    restored into the same cluster leaves the server's connections open,
    and they would append to the restored table until they reconnect.
  * The cost is one read of PostgreSQL's control file (8 KiB, held in
    memory by the kernel) for each record.
* **What it cannot see: a file-level restore.** Such a restore brings
  back the cluster itself, with its control file and catalog. This covers
  the updater's copy of the data root; a rolled-back snapshot of the host,
  the virtual machine or the data root's file system; and the guide's way
  back from a restore in place. Nothing in such a database differs from
  the moment it was copied, and the time since its last record looks
  like a server that was off. Whoever does such a restore records it
  (*The restore paths*), and its IDs still do not repeat.

### The restore in the chain
*Decided in review.*

* **`audit_log.restored`** is a system record. Its outcome is success
  (informational in syslog), and a collector matches it by its MSGID. It
  is appended through `easyrmm_audit_append` as the first record after
  the restored head, and is chained to that head. The restored chain stays
  valid as it is, and removing the record would break every hash after
  it. Its details:
  * `detectedBy`: `cluster`, `table`, or `operator` (the command below);
  * `previous` and `current`: the system identifier and the table's OID,
    as the row held them and as they are now (equal for `operator`). The
    identifier is a string, because it is a 64-bit number, beyond what
    JSON doubles hold;
  * `resumesAfter`: the restored head's `id`, `occurredAt` and
    `entryHash`, or null for an empty log;
  * `discarded`: `{lastId, entryHash}` when the operator gave it, else
    null (unknown);
  * `forwarding`: each destination's restored position, after which
    records are sent again.
* **What it tells an auditor.** Whatever was written after
  `resumesAfter` and before this record is not in this log. The records
  a collector holds in that ID range are exactly those, because IDs
  never repeat and the restored log has none between `resumesAfter.id`
  and this record's `id`. A move that loses nothing is recorded the same
  way, and the collector then holds nothing in the range. Such a move is
  a stopped deployment dumped and loaded elsewhere, or `pg_upgrade`,
  which writes into a new cluster.
* **Verify shows it.** `GET /api/v1/audit/verify` adds `restores`: each
  `audit_log.restored` and `updater.rolled_back` in the range it checked,
  with its ID, its time and the ID it resumes after. The console's
  *Verify integrity* shows them under the result: "Restored from a backup
  on <time>: records written between <time> and <time> are not in this
  log." `easyrmm_audit_verify` does not change.
* The record has no organization, so only platform-wide auditors see it,
  as with other platform records.

### Forwarding after a restore
*Decided in review.*

* **Sent again, never skipped.** The forwarding position comes back with
  the database, and the forwarder sends the records after it again. They
  are the same records: the same `id`, `prevHash`, `entryHash` and
  fields. Only the header's `swVersion` can differ, after a rollback to
  another version. The forwarder does not jump to the restored head. The
  server cannot know whether the lost host delivered those records
  (forwarding may have been failing or behind), and for an audit trail a
  gap at the collector is worse than a copy. ADR-0023 already promises
  at least once.
* **Discarded records are not marked.** The server no longer has them.
  The restore record names their range.
* **What a collector receives**, in ID order:
  1. copies of the records after the restored position, up to the
     restored head;
  2. `audit_log.restored`, or `updater.rolled_back`;
  3. new records, with IDs above every discarded one.

  A collector that keys on `id` drops the copies, as it does after any
  failure today. The forwarding guide gains *After a restore*:
  * key on `id`;
  * the same `id` with the same `entryHash` is a copy;
  * the same `id` with another `entryHash` is an alarm;
  * alert on the two restore actions;
  * the records between `resumesAfter` and the restore record are the
    discarded ones.
* The forwarding settings come back as the backup had them. If forwarding
  was turned on or moved after the backup, the restore record goes to
  the backup's destination, or nowhere. The guide's last restore step
  says to check *Settings → Audit forwarding*.
* With ADR-0060's list of destinations (proposed), all of this applies
  to each destination that carries the audit log.

### The restore paths
In every path, the IDs after the restore are above the discarded ones,
by the clock.

| Path | The database after it | Seen by the check | Recorded by | The discarded head |
|---|---|---|---|---|
| The updater's rollback (ADR-0052, PR #70) | Its copy of the data root: the same cluster | No | The updater, `updater.rolled_back` | Read before restoring; unknown if PostgreSQL does not start |
| Restore in place (guide, PR #74) | A new cluster, loaded from the dump | `cluster` | The server; or the command, before the server starts | Saved with `easyrmm-server audit head` before stopping, given to the command |
| Restore onto a new host (guide) | A new cluster | `cluster` | The server | Unknown, unless taken from the collector |
| The way back from a restore in place (guide, step 4) | The set-aside cluster, as it stopped | No | The command, a step in the guide | The restored deployment's, saved before stopping it |
| A rolled-back snapshot of the host, VM or data root | The same cluster | No | The command, as the guide advises | From the collector, if it has it |
| `pg_restore` into the running cluster | The same cluster, the table made again | `table` | The server | Unknown |
| `pg_upgrade`, by hand | A new cluster; nothing discarded | `cluster` (expected, as ADR-0060 notes; checked when its guide is written) | The server | None |

* **The updater (PR #70)** keeps what it does: it reads the head before
  restoring, moves the sequence past it, and appends
  `updater.rolled_back`. Its sequence move still matters for rollbacks to
  versions from before this ADR. Its restores are file-level, so the check
  finds the same cluster and adds no `audit_log.restored`: each rollback
  has one record. The only change to PR #70: its record's details gain
  `resumesAfter` and `forwarding`, in the shape above, so that a
  collector reads both actions the same way.
* **The commands**, beside `recover`:
  * `easyrmm-server audit head` prints `<id>:<entryHash>`: the highest ID
    handed out and the newest record's hash. It uses the same query as
    the updater's `readAuditHead`.
  * `easyrmm-server audit restored [--discarded <id>:<entryHash>]`
    appends `audit_log.restored`. `detectedBy` is what the check finds
    (`cluster` or `table`), else `operator`. Its record replaces the one
    the server would write. With `--discarded`, it records that head and
    moves the sequence past its ID, as the updater does. It refuses, as a
    mistake, a hash that is not 64 hexadecimal digits or an ID more than
    a day ahead of the database's clock. Run twice, it records twice.
  * It runs against PostgreSQL alone, before the server starts:
    `docker compose run --rm --no-deps server audit restored …` (the
    image's entry point is `easyrmm-server`).
* **The guide** (with PR #74's *Restore in place*):
  * **In place**: before stopping, `docker compose exec -T server
    easyrmm-server audit head`, saved beside the set-aside `.env`. After
    loading the dumps and before starting, the command with
    `--discarded`. If the step is skipped, the server records the restore
    without the head.
  * **The way back**: the restored deployment's head, read before taking
    it down. Once the set-aside data root is back: `docker compose up -d
    postgres`, the command with that head, then `docker compose up -d`.
  * **Onto a new host**: `--discarded` is optional, from the last record
    the collector received.
  * **A new section, *Snapshots***: after rolling back a snapshot of the
    host, the virtual machine or the data root, run the command before
    the server starts.
  * The last step, verifying the chain, also shows the restore's record,
    and says to check the forwarding settings.

### Not chosen
* **An era sent with every record, the key becoming (era, id).** An era
  changes only when a restore is detected. A file-level restore leaves
  nothing to detect, so (era, id) repeats exactly where `id` does. Every
  collector that keys on `id` would also have to change its key, and
  records already forwarded have no era. ADR-0060 needs an era because
  its order is PostgreSQL's transaction IDs, which start again in a new
  cluster and cannot be chosen. Audit IDs are chosen by EasyRMM's own
  function under one lock, so they can follow the clock. Here the restore
  record marks the boundary an era would.
* **A margin added to the IDs at a detected restore.** It needs
  detection, and no margin is known to cover what a lost host wrote. The
  updater keeps its margin for a database it cannot read.
* **UUIDs, or the entry hash, as the record's key.** Either is unique
  without the clock. But UUIDs would change the column's type, the API,
  the forwarder's position, retention and every collector's parsing. The
  hash orders nothing. The console's pages, the forwarder's position and
  a collector's order all rest on the ID, so the ID itself must not
  repeat. The entry hash stays the check.
* **Other restore signals:**
  * **The timeline** (`pg_control_checkpoint()`) changes only when
    recovery from a WAL archive ends or a standby is promoted. The
    deployment archives no WAL. A new cluster starts at 1, and a copy
    keeps its own; it was 1 in all three cases of the check.
  * **A WAL position recorded elsewhere.** Kept in the database, it goes
    back with the database. Kept in the data root, it goes back with the
    data root on every path: the updater copies the whole data root, the
    guide restores `server/` from the same backup set, and a snapshot
    holds both. A new cluster's position is not reliably lower than the
    old one's either.
  * **A value in the data root compared with one in the database.** The
    same flaw: the two come back together from one backup set, so they
    agree after every restore, which is when they would need to differ.
  * **The database's OID alone** is the same in a new cluster (checked).
  * **The time since the last record**: a restored database looks the
    same as one whose server was off.
  * **A copy in ADR-0060's log store**, which lives outside the data root
    and which the updater never copies. The store is not built. A host
    snapshot takes it back too, and on a new host it is empty or restored
    from the same backup set. It would catch only the updater's rollback,
    which records itself.
* **Skipping the copies.** A position kept where a restore does not take
  it back (ADR-0060's store again) would avoid copies only on the paths
  where it survives. Copies cost a collector nothing it does not already
  handle.

## Consequences
* A collector can key on `id` across every restore, as the forwarding
  guide already says, given clocks that do not go back by minutes.
  Copies after a restore are exact copies.
* IDs become 16-digit numbers, no longer consecutive. A collector that
  stores `id` in a 32-bit field must widen it; the release notes say so.
  The forwarding guide's "Compare `id`s and hashes to find gaps" becomes
  "compare each `prevHash` with the `entryHash` before it".
* Each restore the server can see is in the chain, with where the log
  resumes. *Verify integrity* lists it, and a collector can find what was
  discarded.
* A file-level restore is recorded only by the updater or by the
  operator's command. If the command is skipped, IDs still do not repeat,
  and a collector that checks the chain sees it fork at the restored head
  without a record that explains it.
* A move that loses nothing, and `pg_upgrade`, are recorded as restores.
  The collector holds nothing in their range.
* A backup from before this ADR, restored onto a release with it, is not
  detected: the migration records the new cluster as its own. The guide
  already restores onto the backup's release first.
* Every append reads the control file once.
* The updater changes only in two fields of its record (PR #70).
* This covers EasyRMM's audit log. The patching engine's and Authentik's
  own records are not hash-chained or forwarded by EasyRMM.

## Testing
* **Integration tests**, in Go against real PostgreSQL through `testdb`,
  as the audit and forwarding tests are now:
  * **IDs.** Appends increase and are at or above the clock in
    microseconds. 16 concurrent writers get unique IDs, visible in order.
    After each real restore below, the first ID is above every discarded
    one. `--discarded` moves the sequence past its ID, and an ID too far
    ahead is refused.
  * **Detection, by real restores.** The test database is dumped with
    `pg_dump`, records are appended, and the dump is restored three ways:
    1. into a new database in the same cluster: `table`;
    2. with `pg_restore --clean` into the same database: `table`;
    3. into a second cluster: `cluster`. This is a PostgreSQL from the
       deployment's image, with host networking on another loopback port,
       which `make test-db` starts beside the first.

    Each gives one `audit_log.restored`, first after the restored head,
    with the details above. Concurrent first appends make one record. A
    first append that rolls back takes its record with it, and the next
    append writes it. The chain verifies, and `restores` lists the
    record. Nothing is recorded for a database that was not restored, or
    after a migration.
  * **Forwarding**, with the forwarding tests' loopback collectors (real
    listeners over TCP, TLS and UDP). Forwarding is on, a dump is taken,
    records are forwarded, the dump is restored and records are appended.
    The collector receives the copies after the restored position (the
    same `id`, `entryHash` and fields), then the restore record, then the
    new records. No `id` arrives with two `entryHash`es. The records the
    collector holds between `resumesAfter` and the restore record are
    exactly those appended after the dump.
* **The drill** (`scripts/drill/backup-restore.sh`, run plain, with
  `--in-place`, with `--authentik`, and with both) uses a real syslog
  receiver: rsyslog, installed in the drill's Debian image, in a
  container with host networking on the drill's address, configured as
  in the forwarding guide's example. Forwarding is turned on over TCP
  before the backup. The changes made after the backup are forwarded
  before the host is lost or set aside. After the restore and a new
  change, the drill checks:
  * no `id` in the receiver's file has two `entryHash`es;
  * there is one `audit_log.restored` (`cluster`). Its `resumesAfter` is
    the head read at the backup, and its `forwarding` is the backup's
    position;
  * every record the receiver holds between the two was received before
    the restore and is not in the restored log;
  * the copies match the originals;
  * *Verify integrity* lists the restore.

  In place, the record also names the head saved with `easyrmm-server
  audit head`, and the first new ID is above it. The way back records
  `operator` with the restored deployment's head, and the IDs after it
  are above every ID the restored deployment wrote.
* **The updater's job** (ADR-0052's upgrade test, PR #70) uses the same
  receiver. After a rollback during an upgrade, and after one following
  a confirmed upgrade, it checks for one `updater.rolled_back` with
  `resumesAfter` and `forwarding`, no `audit_log.restored`, and no `id`
  with two `entryHash`es. It runs once against a version from before
  this ADR, which takes IDs from the sequence alone.
* **The console**: *Verify integrity*'s result with restores, in the
  page tests with the fake API.

## Owner questions
1. **Snapshots.** Should the backup guide describe snapshots of the
   host, the virtual machine or the data root as a way to back up? This
   ADR only tells operators who roll one back to run the command.
2. **A notice after a restore.** Beyond the record and *Verify
   integrity*, should super administrators see a console notice until
   someone dismisses it? It would list what to check: the forwarding
   settings, and devices enrolled after the backup. This is not decided
   here.
