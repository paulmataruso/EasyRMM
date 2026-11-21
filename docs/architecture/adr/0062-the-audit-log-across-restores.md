# ADR-0062: The audit log across restores

* Status: Proposed (2026-11-21). Not implemented.
* Revised 2026-11-21 after an independent review. The review covered:
  a restore into a running database, the head and boundary the operator
  gives, the clock's limit, the updater in PR #70, moves and
  `pg_upgrade`, test restores, *Verify integrity*, the commands, going
  back across this ADR, and the tests.
* Amends: [ADR-0007](0007-hash-chained-audit-log.md) (how a record's ID
  is chosen, and when an append is refused),
  [ADR-0023](0023-audit-forwarding.md) (what an `id` means to a
  collector) and [ADR-0052](0052-the-host-updater.md) (the rollback's
  sequence move and its audit record). Each gains an *Amended by
  ADR-0062* line when this is implemented.
* Builds on: the [backup guide](../../operations/backup-restore.md) and
  its [Restore in place](../../operations/backup-restore.md#restore-in-place);
  the updater in PR #70 (not merged); and
  [ADR-0060](0060-collecting-logs.md)'s identity for its log store.

## Context
This was noticed while building the in-place restore (PR #74). No drill
checks it yet: a manual restore makes audit record IDs repeat.

What a restore does today:

* **IDs come from a sequence.** `audit_log.id` is `bigint GENERATED
  ALWAYS AS IDENTITY` (`server/migrations/00001_core.sql`).
  `easyrmm_audit_append` is the only writer. It takes an advisory lock,
  reads the newest record's hash and inserts, and the identity sequence
  gives the ID. The hash covers the record's fields and the previous
  hash, not its ID (`easyrmm_audit_canonical`). Migrations append too
  (`00023_retire_connector.sql`).
* **The dump carries the sequence.** `pg_dump` writes
  `setval('public.audit_log_id_seq', …)`. A restored database therefore
  hands out again the IDs that followed the backup, which the records
  the restore discarded had already used.
* **Forwarding keys on the ID.** One row, `audit_forwarding`, keeps
  `last_id`, the last record sent. The forwarder sends records with a
  higher ID, in order (`server/internal/auditfwd/service.go`). Each
  message carries the record as JSON with `id`, `prevHash` and
  `entryHash` (`message.go`), under the server's public name as
  HOSTNAME. The forwarding guide tells collectors that a record "can
  arrive twice after a failure; its `id` tells the copies apart"
  ([audit-forwarding.md](../../operations/audit-forwarding.md)).
* **So after a manual restore**, a collector receives new records under
  IDs it already holds with other content. `last_id` comes back with the
  database too, so the records between the backup's position and the
  backup's newest record are sent again.
* **The updater in PR #70 (not merged)** handles its own restores
  (`updater/internal/host/db.go`).
  * Before restoring, it reads the discarded database's highest ID (the
    larger of the newest record's ID and the sequence's last value) and
    its chain head.
  * After restoring, it moves the sequence past that ID. When the
    database could not be read, it moves it a million past the restored
    database's own.
  * It appends `updater.rolled_back` through `easyrmm_audit_append`, with
    `discardedHead` (hexadecimal, `"unknown"` or `"none"`) and
    `discardedLastId`.
  * Its restore copies the data root back, so the database is the same
    PostgreSQL cluster as before.
* **A manual restore has no such step.** Both of the guide's paths load
  dumps into a new cluster: onto a new host, and in place, where the
  data root (`/srv/easyrmm/postgres` with it) is set aside first. On a
  new host, the old database is gone. The guide's `pg_restore` commands
  do not use `--single-transaction`.
* **A `pg_restore` without `--single-transaction` commits each step on
  its own**, and the reviewer reproduced the failure this causes. While
  `audit_log` exists but its rows are not yet loaded, an append sees an
  empty table and writes `prev_hash` NULL. The old rows then load
  beneath it, and `easyrmm_audit_verify` reports a break.

What can be seen from inside the database, checked while writing this on
PostgreSQL 18.6 (the deployment's image, in throwaway containers):

* `pg_control_system()`, which gives the cluster's system identifier, can
  be run by a role that is not a superuser.
* A dump restored into a new cluster gets a new system identifier. The
  database's OID was the same as before (16386 in both), and the table's
  OID differed by one.
* The same dump restored with `pg_restore --clean` into the database it
  came from keeps the system identifier and gives `audit_log` a new OID.
* A copy of a stopped cluster's directory, started as another container,
  keeps the system identifier and the same OIDs.
* The timeline was 1 in all three.
* `pg_restore -l` lists both tables' data and the sequence's value
  before the primary keys.
* A `SECURITY DEFINER` function owned by a role that is not a superuser
  can insert an ID it chose with `OVERRIDING SYSTEM VALUE` and move the
  sequence with `setval`.
* Appends ran in a loop on new connections during a `pg_restore --clean`,
  once without `--single-transaction` and once with it, under an append
  that refuses without a matching identity row (below). None landed in
  the restored table, and the chain checked clean. Once the restore was
  recorded, appends continued above it.

## Decision

### IDs that never repeat
*Decided in review.*

* `easyrmm_audit_append` chooses each ID under the lock it already holds.
  The ID is the greatest of three terms:
  * the newest record's ID plus one;
  * the sequence's last value plus one;
  * the database's clock (`clock_timestamp()`) in microseconds since 1970.

  It moves the sequence to that ID and inserts the record with
  `OVERRIDING SYSTEM VALUE`. The sequence stays because the dump carries
  it, the updater reads it and moves it, and a version from before this
  ADR, which a rollback can start, takes IDs from it alone.
* **Why the clock.** The clock is the one thing outside the database
  that every restore leaves in place. ADR-0052's rollback guards use the
  same rule for their generations.
* **The condition, exactly.** After a restore without the discarded
  head, new IDs fall among the discarded ones if, and only if, the
  highest discarded ID is above the restored host's clock (in
  microseconds) when the first new record is written. Then they can
  repeat them, and the range a restore record names is no longer only
  discarded records. When the discarded head is given (the updater, and
  `--discarded`), the sequence moves past it and the clock does not
  matter. Each ID is at least the one before plus one, so an ID can lead
  the clock:
  * by microseconds during a burst of appends. Each append is a locked
    query and an insert, which take longer than a microsecond, so this
    lead does not build up;
  * by the size of a jump, after the lost host's clock jumped forward,
    even once it was corrected. Every later ID stays at least that far
    ahead, and real time reaches it only as long after the jump as the
    jump was: for good, in practice, after a jump of years. A restore
    from before the jump, made within that time, repeats IDs, even when
    the restored host's clock is right.

  Microseconds, not milliseconds: a burst of appends could get ahead of
  a millisecond clock.
* **A lead is reported** (decided in review). At start and then every
  hour, the server compares the newest ID with the database's clock.
  When the ID leads by more than **5 minutes**, it logs a warning and
  appends `audit_log.ids_ahead`, with the lead and the newest ID. It
  appends at most one a day while the lead lasts.
  * Why 5 minutes: legitimate leads are microseconds (bursts) or a
    second (the updater's margin of a million). No restore by hand is
    quick enough to reach back into a lead shorter than 5 minutes:
    stopping, setting aside, loading dumps and starting take longer.
  * 5 minutes is also ADR-0057's `MaxSkew` (proposed).
  * The record tells an auditor that the clock went back, and that a
    restore from before then needs the discarded head (`--discarded`,
    below) to avoid repeating IDs.
* **Size.** In 2026 an ID is about 1.8 × 10^15 (16 digits), below 2^53
  until the year 2255. 2^53 is the largest integer that JSON readers
  using doubles (the console, many collectors) hold exactly. The append
  raises an error, and writes nothing, when the clock term or the ID it
  would choose is 2^53 or more: a clock past 2255, or a wildly wrong
  one. The API's bounds (`after` up to 2^62) hold.
* Existing records keep their IDs, and the first record after the
  migration jumps to the clock. IDs are no longer consecutive. They
  never were a count: a transaction that rolls back already leaves a gap
  in a sequence. The chain shows a missing record (ADR-0023), not the
  IDs. The ID is not hashed, so existing chains verify unchanged.

### Detecting a restore
*Decided in review.*

* **The signal** is a pair: the cluster's system identifier (from
  `pg_control_system()`) and the audit table's OID
  (`'public.audit_log'::regclass`). It is compared with a one-row table,
  `audit_log_identity`, which only the owner's functions read and write.
  * **The system identifier** is made by `initdb`, once for each cluster,
    and kept in the cluster's control file, which no dump carries. Both
    of the guide's restores load the dump into a cluster that
    PostgreSQL's first start has just made. The row comes back from the
    dump naming the old cluster.
  * **The table's OID** covers a dump restored into the cluster it came
    from (`pg_restore --clean`, or the database dropped and made again).
    The table is made again, and OIDs come from one counter per cluster
    that only moves forward. The counter wraps after 2^32, far beyond
    what this cluster's objects use.
  * Neither OID identifies a cluster on its own: in the check above, the
    database's OID was the same in the new cluster.
* **How often.** The append compares both with the row on every record.
  It reads the system identifier once per connection, keeping it in a
  session setting (`easyrmm.audit_cluster`), because a connection never
  outlives its cluster. It looks up the table's OID on every record,
  because a restore into the same cluster can happen under an open
  connection. The server's role can change its own session setting.
  That can only make its own appends refuse, or skip a comparison that
  the start-time check repeats from the control file.
* **Who writes the row** (decided in review):
  * the migration, which makes the table and writes the live identity;
  * the start-time check and `audit restored` (below), when they record
    a restore.

  The append never writes it.

### Never a chain break
*Decided in review.*

**The invariant: no record is ever written with `prev_hash` NULL into a
table that will later hold older rows.** Three rules hold it:

1. **Every appender stopped, and `--single-transaction`.** A restore into
   an existing cluster needs every appender stopped first. The appenders
   are every server on the database, `recover`, and the updater. The
   guide's `down` stops them; on a new host only PostgreSQL is up. Every
   `pg_restore` in the guide uses `--single-transaction`, so the
   restored database appears whole or not at all. (The guide uses it for
   the engine's and Authentik's dumps too, for the same reason.)
2. **The append refuses without a matching identity row.** If the row is
   missing, or names another cluster or table, the append raises an
   error and writes nothing. This holds through every restore that makes
   the tables again, whether atomic or not, into a new cluster or the
   same one, and whatever order `pg_restore` loads them in. Until the
   row's data is loaded, the row is missing. Once loaded, it names the
   dump's cluster or table, which is not the live one. So no append
   lands in a table that is still being loaded, by the server's own
   rule, even when rule 1 is broken.
3. **A restore is recorded only once it has finished.** It is recorded
   only by the start-time check and by `audit restored`, and both refuse
   while `audit_log` has no primary key. `pg_restore` makes constraints
   in its last section, after every table's data and the sequence's
   value (checked above). So once the key exists, the restored rows are
   in. ADR-0060's finished-restore marker is not needed here. ADR-0060's
   marker is a row the guide's restore writes last, so that its init
   never takes a store still being restored for an empty one. Here the
   append's refusal keeps records out, and the primary key shows that
   the load has finished, without a step to write.

Rule 2 does not cover **a data-only restore into the existing tables**
(`TRUNCATE` and `COPY`, keeping the table's OID). The guide never does
one, and rule 1 covers it. Such a restore is also not detected
(*What it cannot see*).

### At start, and in the append
*Decided in review.*

* **At start**, before migrations, so that a migration's appends never
  meet a restored database first. If `audit_log_identity` exists:
  * no primary key on `audit_log`: the server does not start, with "a
    restore of the database is unfinished";
  * the row is missing: the server does not start, with "the audit log's
    identity row is missing: if the database was restored, run
    `easyrmm-server audit restored`". The command writes the row again
    and records that it did;
  * the row names another cluster or table: the server appends
    `audit_log.restored` and rewrites the row, then starts;
  * the row matches: it starts.

  Then the migrations run, then the lead check.
* **A dump from before this ADR** has no `audit_log_identity`. The check
  is skipped, and this ADR's migration makes the table and writes the
  live identity, so the restore behind it is not recorded. The guide
  already restores onto the backup's own release first; a release from
  before this ADR records nothing either way. *Going back across this
  ADR* (below) covers the other direction.
* **A server whose database is restored beneath it**, against the guide,
  refuses every audited action from then on (rule 2). Its log says why
  and names the fix: restart it, or run `audit restored`. It does not
  record the restore itself.
* **What it cannot see** are file-level restores, which bring back the
  cluster with its control file and catalog:
  * the updater's copy of the data root;
  * a rolled-back snapshot of the host, the virtual machine or the data
    root's file system;
  * the guide's way back from a restore in place;
  * a data-only restore.

  Nothing in such a database differs from the moment it was copied, and
  the time since its last record looks like a server that was off. The
  updater or the operator records these (*The restore paths*), and their
  IDs do not repeat given the condition above.

### The restore in the chain
*Decided in review.*

* **`audit_log.restored`** is a system record. Its outcome is success
  (informational in syslog), and a collector matches it by its MSGID. It
  is appended through the same chain as every record. Its details:
  * `detectedBy`: `cluster`, `table`, or `operator` (the command, when
    the identity is unchanged, or when the row was missing);
  * `previous` and `current`: the system identifier and the table's OID,
    as the row held them (null when it was missing) and as they are
    now. The identifier is a string: it is a 64-bit number, beyond what
    JSON doubles hold;
  * `resumesAfter`: the restored head's `id`, `occurredAt` and
    `entryHash`, or null for an empty log;
  * `firstAfterId`: the first record written after the restore. It is
    null when that is this record, whose ID is chosen inside the append,
    after its details are hashed. With `--resumes-after`, it is the ID
    of the record after `resumesAfter`;
  * `discarded`: `{lastId, entryHash}` as given with `--discarded`
    (`entryHash` null for a discarded log with no record), or null when
    unknown;
  * `nothingDiscarded`: true when the discarded head's hash is the
    restored head's, as after a move or `pg_upgrade`;
  * `forwarding`: each destination's restored position, after which
    records are sent again.
* **What it tells an auditor:** "any records written after
  `resumesAfter` and before `firstAfterId` are not in this log", where a
  null `firstAfterId` means this record's own ID. At a collector, those
  are the records with an ID between the two. Once this
  is implemented, IDs do not repeat (given the condition above), and the
  restored log has none in that range.
* **Moves and `pg_upgrade` are no false alarm.** The guide's move and
  upgrade steps pass the saved head with `--discarded`, so their record
  says `nothingDiscarded`. The forwarding guide tells collectors to
  alert on the same `id` arriving with another `entryHash`, not on every
  restore record.
* **Verify shows it.** `GET /api/v1/audit/verify` adds `restores`: every
  `audit_log.restored` and `updater.rolled_back` in the whole log,
  whatever range was checked. The console checks the oldest 1,000,000
  records (`AuditTab.tsx`). Each entry gives its ID, time, `resumesAfter`
  and `firstAfterId`, and whether anything was discarded (yes, no or
  unknown). The console shows them under the result: "Restored from a
  backup on <time>: any records written between <time> and <time> are
  not in this log", or "Moved on <time>; nothing was discarded".
  `easyrmm_audit_verify` does not change.
* The record has no organization, so only platform-wide auditors see
  it, as with other platform records.

### Forwarding after a restore
*Decided in review.*

* **Sent again, never skipped.** The forwarding position comes back with
  the database, and the forwarder sends the records after it again.
  * They are the same records: the same `id`, `prevHash`, `entryHash`
    and fields.
  * The header can differ: `swVersion` after a rollback to another
    version, and HOSTNAME when the new host has another public name
    (ADR-0023).
  * The forwarder does not jump to the restored head. The server cannot
    know whether the lost host delivered those records (forwarding may
    have been failing or behind), and for an audit trail a gap is worse
    than a copy. ADR-0023 already promises at least once.
* **Discarded records are not marked.** The server no longer has them,
  and the restore record names their range.
* **What a collector receives**, in ID order:
  1. copies of the records after the restored position, up to the
     restored head;
  2. `audit_log.restored`, or `updater.rolled_back`;
  3. new records.

  After a rolled-back snapshot whose server already ran, new records
  come before the restore record, which `--resumes-after` places by its
  fields, not by its position.
* **The forwarding guide gains *After a restore***:
  * key on `id`;
  * the same `id` with the same `entryHash` is a copy, to drop;
  * the same `id` with another `entryHash` is the alarm;
  * a restore record is information, and its range names the discarded
    records.
* **Test restores** (decided in review). The forwarding settings come
  back as the backup had them, usually on, and the forwarder sends
  within about two seconds of the server's start. A test restore would
  send copies and new records to the production collector. So:
  * `easyrmm-server audit stop-forwarding`, run before start, turns
    forwarding off with nothing left to deliver (`drain_until` cleared,
    unlike the console's off, which delivers its own record first);
  * it records the change as `audit_forwarding.update`, by the system
    actor `audit stop-forwarding`. That record is not forwarded;
  * the guide's restore steps say: for a test of a backup, run it
    before starting.

  A command, not an environment variable. The command changes the
  stored setting, which the console shows, the audit log records, and
  the console turns back on like any change. A variable would be a
  second switch beside the setting: the console would show forwarding
  on while it was off, nothing in the log would say so, and a variable
  left in `.env` after a test would silently stop forwarding on the
  next real restore.
* With ADR-0060's list of destinations (proposed), all of this applies
  to each destination that carries the audit log.

### The commands
*Decided in review.*

Beside `recover`. Each connects with `EASYRMM_DATABASE_MIGRATION_URL`,
the owner. As `easyrmm_app`, row-level security hides the records and
`pg_sequence_last_value` returns NULL. Each runs with PostgreSQL up,
and, except `audit restored --resumes-after`, with every appender
stopped: `docker compose run --rm --no-deps server audit …` (the
image's entry point is `easyrmm-server`). This is as in ADR-0052's step
3, where the updater reads its values once every other service has
stopped.

* **`audit head`** prints `<id>:<entryHash>`, or `<id>:none` for a log
  with no record. The ID is the highest handed out: the newest record's
  ID, the sequence's last value, or 0, whichever is greatest. It uses
  the updater's query in PR #70 (`readAuditHead`).
* **`audit restored`** `[--discarded <id>:<entryHash>|<id>:none]`
  `[--resumes-after <id>]` `[--force]` appends `audit_log.restored`, by
  the same function as the start-time check, and rewrites the row.
  * It refuses while the restore is unfinished (no primary key).
  * With a detected restore, `detectedBy` is `cluster` or `table`, and
    the server's start then finds the row matching. Otherwise it is
    `operator`.
  * `--discarded` records that head and moves the sequence past its ID,
    as the updater does.
    * An ID more than a day ahead of the database's clock is refused as
      a likely mistake, with the reason and the lead shown. `--force`
      overrides that.
    * An ID of 2^53 or more, or a hash that is not 64 hexadecimal
      digits or `none`, is refused even with `--force`.
  * **`--resumes-after <id>`** names the restored head when records were
    appended after the restore. This is for a rolled-back snapshot whose
    server already ran (*Snapshots*). The ID must be in the log. It is
    refused with a detected restore, since appends were refused until
    the restore was recorded.
  * Run twice, it records twice.
* **`audit stop-forwarding`**: above.

### The restore paths
*Decided in review.*

Once this is implemented, the IDs after a restore are above the
discarded ones on every path below, given the condition above. That
needs three things: the clock term, the updater changes listed below,
and the guide's `setval` when going back across this ADR.

| Path | The database after it | Seen by the check | Recorded by | The discarded head |
|---|---|---|---|---|
| The updater's rollback (ADR-0052, PR #70) | Its copy of the data root: the same cluster | No | The updater, `updater.rolled_back` | Read before restoring; unknown if PostgreSQL did not start |
| [Restore in place](../../operations/backup-restore.md#restore-in-place) | A new cluster, loaded from the dump | `cluster` | `audit restored`, before start; else the server at start | `audit head`, once the server is stopped |
| [Restore onto a new host](../../operations/backup-restore.md#restore-onto-a-new-host), the host lost | A new cluster | `cluster` | The server at start | Unknown, unless taken from the collector |
| A planned move to another host | A new cluster; nothing discarded | `cluster` | `audit restored --discarded`, before start | `audit head` on the old host, its server stopped, before the dump |
| The way back from a restore in place | The set-aside cluster, as it stopped | No | `audit restored`, before start | The restored deployment's, read with `audit head` once its server is stopped |
| A rolled-back snapshot of the host, VM or data root | The same cluster | No | `audit restored --resumes-after`, once noticed | From the collector, if it has it |
| `pg_restore` into the same cluster | The same cluster, the table made again | `table` | The server at start | Unknown |
| `pg_upgrade`, by hand | A new cluster; nothing discarded | `cluster` (expected, as ADR-0060 notes; checked when its guide is written) | `audit restored --discarded`, before start | `audit head`, every appender stopped |

**What the guide must say** (backup-restore.md, upgrading.md and
audit-forwarding.md):

* **Every restore:**
  * every `pg_restore` with `--single-transaction`, with every appender
    stopped first;
  * for a test of a backup, `audit stop-forwarding` before starting;
  * the last step also shows the restore's record in *Verify integrity*,
    and says to check *Settings → Audit forwarding*, which came back as
    the backup had it. The guide does not say that today.
* **In place:**
  * before `down`: `docker compose stop server` (and any server on
    another host), then `audit head`, saved beside the set-aside `.env`;
  * after loading the dumps and before starting: `audit restored
    --discarded` with that head;
  * if skipped, the server records the restore at start without the
    head.
* **The way back:**
  * the restored deployment's server is stopped, and its head read with
    `audit head` before its `down` (on a release from before this ADR,
    the same query through `psql`);
  * once the set-aside data root is back: `docker compose up -d
    postgres`, `audit restored --discarded` with that head, then `up -d`.
* **Onto a new host:** `--discarded` is optional, from the last record
  the collector received.
* **A planned move** (the old host still there): stop its server, `audit
  head`, then the backup, and `--discarded` on the new host. The
  major-version upgrade guide, when written (ADR-0052), does the same.
* **Snapshots, a new section:** a VM snapshot resumes with its server
  running, and a disk snapshot boots with `restart: unless-stopped`
  starting it. So the guide gives `--resumes-after` rather than "stop the
  server first", for which there is no moment.
  * The ID to give is the newest record from before the snapshot was
    taken: in *Settings → Audit log* by time, or at the collector, where
    it is the record whose `entryHash` two later records both name as
    `prevHash`.
  * `docker compose exec server easyrmm-server audit restored
    --resumes-after <id>`, with the server running.
* **Going back across this ADR**, to a release from before it, through
  [Going back](../../operations/upgrading.md#going-back) and the restore
  in place. The older image has no `audit restored`, and takes IDs from
  the sequence alone, so they would repeat. The guide gives one `psql`
  command, as the updater's `recordRollback` does, run after loading
  the dumps and before starting. It does two things:
  * moves the sequence to the greatest of its value, the saved head's
    ID (read with `audit head` from the newer release before `down`),
    and the clock in microseconds;
  * appends `audit_log.restored` (`operator`, with the saved head)
    through that release's `easyrmm_audit_append`, whose signature is
    unchanged.

**What the updater needs**, part of this ADR's implementation. PR #70 is
not changed for an ADR that is not accepted.

* **The record's details gain the shared fields**: `resumesAfter`,
  `firstAfterId` (null: it is the first after the restore), `discarded`
  and `forwarding`. Its
  `discardedHead` and `discardedLastId` map onto `discarded` like this:
  * a hexadecimal head becomes `{lastId: discardedLastId, entryHash}`;
  * `"none"` becomes `{lastId: discardedLastId, entryHash: null}`;
  * `"unknown"` becomes null.

  Once this is implemented, both actions carry the same fields for a
  collector's rules. If PR #70 has merged by then, its two fields stay
  beside them, since records with them already exist.
* **Its sequence move gains the clock**: `greatest(…, clock in
  microseconds)`, which matters most in the margin path. A target from
  before this ADR takes IDs from the sequence alone. If the margin
  added a million to its own small IDs, its new IDs would fall below
  the clock-made IDs of a discarded database the updater could not read.
* Otherwise it keeps its steps. Its restores are file-level, so the
  check finds the same cluster and adds no `audit_log.restored`: one
  record per rollback.

### Not chosen
*Decided in review.*

* **An era sent with every record, the key becoming (era, id).** An era
  changes only when a restore is detected. A file-level restore leaves
  nothing to detect, so (era, id) repeats exactly where `id` does. Every
  collector that keys on `id` would also have to change its key, and
  records already forwarded have no era. ADR-0060 needs an era because
  its order is PostgreSQL's transaction IDs, which start again in a new
  cluster and cannot be chosen. Audit IDs are chosen by EasyRMM's own
  function under one lock, so they can follow the clock.
* **A margin added to the IDs at a detected restore.** It needs
  detection, and no margin is known to cover what a lost host wrote.
* **UUIDs, or the entry hash, as the record's key.** Either is unique
  without the clock. But UUIDs would change the column's type, the API,
  the forwarder's position, retention and every collector's parsing. The
  hash orders nothing. The console's pages, the forwarder's position and
  a collector's order all rest on the ID, so the ID itself must not
  repeat. The entry hash stays the check.
* **The append recording the restore itself.** During a restore that is
  not atomic, it could record before the old rows are in. This is the
  reviewer's failure, and it would also collide with the row the dump
  brings.
* **Other restore signals:**
  * **The timeline** (`pg_control_checkpoint()`) changes only when
    recovery from a WAL archive ends or a standby is promoted. The
    deployment archives no WAL. A new cluster starts at 1, and a copy
    keeps its own; it was 1 in all three cases checked.
  * **A WAL position recorded elsewhere.** Kept in the database, it goes
    back with the database. Kept in the data root, it goes back with
    the data root on every path: the updater copies the whole data root,
    the guide restores `server/` from the same backup set, and a
    snapshot holds both. A new cluster's position is not reliably lower
    than the old one's.
  * **A value in the data root compared with one in the database.** The
    same flaw: the two come back together from one backup set, so they
    agree after every restore, which is when they would need to differ.
  * **The database's OID alone** is the same in a new cluster (checked).
  * **The time since the last record**: a restored database looks the
    same as one whose server was off.
  * **A copy in ADR-0060's log store**, outside the data root, which the
    updater never copies. The store is not built. A host snapshot takes
    it back too, and on a new host it is empty or restored from the
    same backup set. It would catch only the updater's rollback, which
    records itself.
* **Skipping the copies.** A position kept where a restore does not take
  it back would avoid copies only on the paths where it survives. Copies
  cost a collector nothing it does not already handle.

## Consequences
* A collector can key on `id` across restores, as the forwarding guide
  already says, as long as the highest discarded ID is below the
  restored host's clock. Copies after a restore are exact copies, apart
  from their header.
* IDs become 16-digit numbers, no longer consecutive. A collector that
  stores `id` in a 32-bit field must widen it, and the release notes say
  so. The forwarding guide's "Compare `id`s and hashes to find gaps"
  becomes "compare each `prevHash` with the `entryHash` before it".
* Each restore the server can see is in the chain, with where the log
  resumes. *Verify integrity* lists every restore, and a collector can
  find what was discarded.
* No restore, atomic or not, can put a record beneath restored rows. A
  server whose database is restored beneath it stops recording, and so
  stops audited actions, until it restarts or the command runs.
* A server does not start on a database whose restore is unfinished, or
  whose identity row is missing.
* A file-level restore is recorded only by the updater or by the
  operator's command. If the command is skipped, IDs still do not
  repeat, given the condition, and a collector that checks the chain
  sees it fork at the restored head without a record that explains it.
* A backup from before this ADR, restored onto a release with it, is not
  detected.
* Each append reads the identity row and the table's OID. Each
  connection reads the control file once.
* The guide gains steps on every restore path. A test restore needs one
  more command, or it forwards to the production collector.
* The updater gains a clock term and four fields, with this ADR's
  implementation, not before.
* This covers EasyRMM's audit log. The patching engine's and Authentik's
  own records are not hash-chained or forwarded by EasyRMM.

## Testing
* **Integration tests**, in Go against real PostgreSQL through `testdb`,
  as the audit and forwarding tests are now. `pg_dump` and `pg_restore`
  run through `docker exec` in the test-db container, so that their
  version is the server's.
  * **IDs.**
    * Appends increase and are at or above the clock in microseconds.
    * 16 concurrent writers get unique IDs, visible in order.
    * After each real restore below, the first ID is above every
      discarded one.
    * `--discarded` moves the sequence past its ID. One more than a day
      ahead is refused without `--force` and accepted with it. 2^53 is
      refused even with it.
    * An ID or clock term of 2^53 or more makes the append fail and
      write nothing. The test sets the sequence there.
    * A lead of more than 5 minutes, made by moving the sequence ahead,
      gives one warning and one `audit_log.ids_ahead`, not one per hour.
  * **Detection, by real restores.** The test database is dumped,
    records are appended, and the dump is restored three ways:
    1. with `pg_restore --clean --single-transaction` into the same
       database, then appending through a connection opened before the
       restore, which only the per-append OID comparison can catch:
       `table`;
    2. into a new database in the same cluster: `table`;
    3. into a second cluster: `cluster`. This is a PostgreSQL from the
       deployment's image, with host networking on another loopback
       port, which `make test-db` starts beside the first.

    For each restore:
    * appends are refused until the start-time check runs;
    * the check then appends one `audit_log.restored`, first after the
      restored head, with the details above, and later appends follow
      it;
    * the chain verifies, and `restores` lists the record;
    * concurrent start-time checks make one record;
    * nothing is recorded for a database that was not restored, after a
      migration, or for a dump from before this ADR.
  * **Never a chain break.** Appends run in a loop, on connections
    opened before and during the restore, while `pg_restore --clean`
    runs without `--single-transaction`:
    * every append during it is refused, and none lands in the restored
      table;
    * the start-time check refuses while the primary key is missing, and
      records once it is there;
    * no record other than the first has `prev_hash` NULL;
    * the chain verifies.

    With the row deleted, the append refuses, the server does not start,
    and `audit restored` writes the row back and records it.
  * **The commands.**
    * `audit head` as the owner, on an empty log (`<id>:none`) and on a
      full one. As `easyrmm_app` it is shown to fail rather than print a
      wrong head.
    * `audit restored` with and without each option. `--resumes-after`
      after records appended since gives the right `firstAfterId`, and
      is refused with a detected restore.
    * `audit stop-forwarding` turns forwarding off with nothing left to
      deliver, and records it.
  * **Forwarding**, with the forwarding tests' loopback collectors (real
    listeners over TCP, TLS and UDP). Forwarding is on, a dump is taken,
    records are forwarded, the dump is restored and records are
    appended. The collector receives the copies after the restored
    position (the same `id`, `entryHash` and fields), then the restore
    record, then the new records. No `id` arrives with two `entryHash`es.
    The records the collector holds between `resumesAfter` and
    the restore record are exactly those appended after the dump. After
    `audit stop-forwarding`, the collector receives nothing.
* **The drill** (`scripts/drill/backup-restore.sh`) runs plain, with
  `--in-place`, with `--authentik`, and with both. Each run follows the
  guide's new steps. It has a real syslog receiver: rsyslog, installed
  in the drill's Debian image, in a container with host networking on
  the drill's address, configured as in the forwarding guide's example.
  Forwarding is turned on over TCP before the backup. The changes after
  the backup are forwarded before the host is lost or set aside. After
  the restore and a new change, the drill checks:
  * no `id` in the receiver's file has two `entryHash`es;
  * there is one `audit_log.restored` (`cluster`), whose `resumesAfter`
    is the head read at the backup and whose `forwarding` is the
    backup's position;
  * every record the receiver holds in its range was received before
    the restore and is not in the restored log;
  * the copies match the originals;
  * *Verify integrity* lists the restore.

  In place, the record also names the head saved with `audit head`, and
  the first new ID is above it. The way back records `operator` with the
  restored deployment's head, and the IDs after it are above every ID
  the restored deployment wrote. One more plain run, as a test restore
  with `audit stop-forwarding`, delivers nothing to the receiver after
  the restore.
* **The updater's job** (ADR-0052's upgrade test, with PR #70), once the
  updater changes above are made, uses the same receiver. After a
  rollback during an upgrade, and after one following a confirmed
  upgrade, it checks:
  * one `updater.rolled_back` with the shared fields;
  * no `audit_log.restored`;
  * no `id` with two `entryHash`es.

  It also runs once against a version from before this ADR, both with
  the discarded database readable and with it not (the margin path), and
  once going back across this ADR by the guide's `psql` step.
* **The console.** *Verify integrity*'s restores are covered in the page
  tests and in `make e2e` against a real server. The e2e records a
  restore with `easyrmm-server audit restored --resumes-after` against
  its own database, then checks the listing and its wording.

## Owner questions
1. **Snapshots.** Should the backup guide describe snapshots of the
   host, the virtual machine or the data root as a way to back up? This
   ADR only tells operators who roll one back to run the command.
2. **A notice after a restore.** Beyond the record and *Verify
   integrity*, should super administrators see a console notice until
   someone dismisses it? It would list what to check: the forwarding
   settings, and devices enrolled after the backup. This is not decided
   here.
3. **Test restores as a whole.** `audit stop-forwarding` keeps a test
   restore away from the collector. A test copy can still reach other
   things: agents, if it answers at the same name; notification
   channels (ADR-0053, proposed); and the engine's mail and webhooks.
   Should the guide describe a test restore as a whole, with everything
   to turn off before start?
4. **A server restored beneath.** A server whose database is restored
   beneath it, against the guide, refuses audited actions until it
   restarts. Should it exit on that refusal instead, so that Compose
   starts it again and its start-time check records the restore once
   the restore has finished?
