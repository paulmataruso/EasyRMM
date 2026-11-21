# Drills: backup and restore, load and soak

`scripts/drill/` runs EasyRMM the way an operator does, on a disposable
deployment of the current checkout: `deploy/scripts/setup.sh`, the
Docker Compose stack built from this commit, and the console API used the
way the console uses it. Unit and integration tests cannot catch what these
catch: a deployment file that does not start, a guide's command that does
not work, a server that slows down under a fleet.

Both drills need root (`setup.sh` sets the data directories' owners),
Docker Compose, curl, jq and openssl. They serve on `127.0.0.2` (set
`DRILL_ADDR` to change it), so they do not collide with anything on the
host's own addresses. They also use PostgreSQL's `127.0.0.1:15432` and the
server's loopback ports, Authentik's too with `--authentik`, so stop any
other EasyRMM deployment on the host first. Each run builds the server
image from the checkout. Set `DRILL_IMAGE` to use an image you already
have.

## Backup and restore

```bash
sudo scripts/drill/backup-restore.sh /tmp/easyrmm-drill
sudo scripts/drill/backup-restore.sh --authentik /tmp/easyrmm-drill-authentik
sudo scripts/drill/backup-restore.sh --in-place /tmp/easyrmm-drill-in-place
sudo scripts/drill/backup-restore.sh --authentik --in-place /tmp/easyrmm-drill-both
```

1. It deploys a source host and gives it real state: first-run setup, an
   administrator with an authenticator, a site, a deployment token, and a
   real agent in a Debian container that enrolls and runs a job.
2. It backs up with the commands in
   [Backup and restore](../operations/backup-restore.md).
3. It deletes the stack, the data root and the checkout, and restores onto a
   new checkout with the guide's steps.
4. It then checks:
   * TLS verifies against the certificate authority saved before the backup;
   * the administrator signs in with the same password and authenticator;
   * the audit chain verifies;
   * a site created after the backup is gone;
   * the same agent, never re-enrolled, reconnects and runs a new job;
   * MeshCentral's identity is unchanged;
   * the patching engine has the same organization and data-protection
     keys.

With `--authentik`, the source host is set up with `setup.sh
--with-authentik`, with Authentik at `auth.drill.invalid` on the same edge,
and there is no first-run setup. The administrator's account is made in
Authentik from the invitation `setup.sh` printed, with a password and an
authenticator app, and signs in to EasyRMM through Authentik, then signs in
again from EasyRMM's sign-in page. The drill goes through Authentik's flows
as the browser does, through the edge, answering each stage through
Authentik's flow API. After the restore it also checks that:
* the administrator signs in through Authentik with the same email,
  password and authenticator app, to the same EasyRMM account, through the
  link EasyRMM made before the backup;
* Authentik has the same user, with the same subject (what EasyRMM links
  the account to), and a user made in Authentik after the backup is gone;
* the provider's signing key is unchanged: the same key pair by name, key
  id and SHA-256 fingerprint, read from Authentik and from the keys it
  publishes to EasyRMM;
* `akadmin`'s password file is the backup's, owned by Authentik's user, and
  still opens `akadmin`.

With `--in-place`, with or without `--authentik`, the drill restores over
the running deployment instead, in its own checkout, with the steps in
[Restore in place](../operations/backup-restore.md#restore-in-place). It
stops the deployment, sets the data root and `.env` aside, restores, and
makes the same checks. It then checks that:
* the set-aside data root, PostgreSQL's data with it, is as it was when the
  deployment stopped: every entry's owner, mode, size and time, and every
  file's contents; the set-aside `.env` too;
* the guide's way back works: the restored deployment set aside, the
  set-aside one put back and started, the same checks pass again, and
  what changed after the backup is back: the site and, with
  `--authentik`, the Authentik user. The agent, which ran a job on the
  restored deployment, runs another on the one put back.

It prints each step to `report.txt` in the working directory, with the
stack's output in `compose.log`.

The agent's container has no systemd, so MeshAgent is not installed there.
MeshAgent reconnecting is checked only when the device reports one; the
drill checks MeshCentral's identity in every case.

### Runs

| Date | Variant | Outcome |
|---|---|---|
| 2026-11-16 | Plain | The first run found that the guide's database commands failed and that a fresh deployment did not start; both were fixed |
| 2026-11-19 | Plain, with the patching engine in every deployment | Passed: the engine's database and keys backed up and restored with the guide's steps |
| 2026-11-21 | `--authentik`, Authentik 2026.8.5 | Passed twice, in 11 and 10 minutes. The backup held Authentik's database (3.1 MB) and directory. After the restore, the administrator signed in through Authentik with the same email, password and authenticator app, as the same Authentik user with the same subject. They reached the same EasyRMM account, through the link made before the backup. The provider's signing key was the same, by Authentik's record and by the keys it publishes. `akadmin`'s password file was the backup's and still opened `akadmin`, and an Authentik user made after the backup was gone. The agent, MeshCentral and patching engine checks passed as in the plain variant |
| 2026-11-21 | Plain, with the guide's Authentik steps | Passed twice: the backup had no Authentik files, and the restore, with `tar --numeric-owner`, passed every check. Two attempts in between failed after the restore, on a host loaded by other work (a load average of 16 to 150 on 16 cores): the device list ran into PostgreSQL's statement timeout, with even `DISCARD ALL` taking 35 seconds in the second. The run after them, with the load back under 15, passed |

## Load and soak

```bash
sudo scripts/drill/soak.sh /tmp/easyrmm-soak 2000 1h
```

`tools/agentsim` simulates the fleet. Every simulated device enrolls with its
own key first. Then, for the run's duration, each does what the real agent
does, over its own TLS connection:
* a heartbeat with metrics every minute;
* its inventory, about 21 KB with 300 packages, uploaded when the server's
  copy differs;
* a job long poll held open at all times.

A delivered job is checked against the pinned job key, started, and reported
as succeeded without running anything. Meanwhile, every minute, the drill:
* lists the online devices as the console does, and times it;
* samples the containers' CPU and memory and the database's size.

Every ten minutes it runs a job on 500 devices and times it until every run
has reported.

Results are in the working directory: `report.txt`, `samples.csv`,
`jobs.csv`, `agentsim.log` (per-minute latency percentiles) and
`summary.json` (the whole run).

`agentsim` can also run on its own against any server:

```bash
go run ./tools/agentsim -server https://rmm.example.com -token ert_… \
    -devices 500 -duration 30m -state sim.json -out summary.json
```

The server allows four enrollments a second from one address after a burst
of 120, so 2,000 devices take about eight minutes to enroll. `-state` keeps
their keys, and a later run with the same file enrolls none.

### Results

One hour with 2,000 devices, on 2026-11-16. The host was a 16-core Xeon
E5-2670 v2 with 30 GB of memory, also running other work, so treat the
CPU figures as upper bounds.

| Measure | Result |
|---|---|
| Requests | 2,000 enrollments, 2,000 inventories, 119,785 heartbeats, 287,866 long polls and 3,000 job deliveries, with no errors |
| Heartbeat | p50 29 ms, p95 51 ms, p99 136 ms |
| Inventory upload | p50 127 ms, p99 297 ms |
| Job delivered to a waiting agent | p50 231 ms, p99 627 ms |
| Job on 500 devices, until every run reported | median 6.0 s (4.1–7.7 s over six jobs) |
| The console's list of online devices | median 0.27 s |
| Server memory, once every device was online | 471 MiB, 487 MiB an hour later |
| CPU (sampled each minute) | server 0.9 of a core on average, 3.7 cores at most while a job ran; PostgreSQL 0.8 and 2.8 |
| Database after the hour | 155 MiB: agent nonces 63 MB, installed software 58 MB, metric samples 14 MB |

Agent nonces were the largest table. Each signed request stores one for six
minutes, and the hourly maintenance removed expired ones, so the table held
an hour of requests. The agents service now removes them every minute. A
20-minute run with that change ended with 10 MB of nonces, about seven
minutes of requests, again with no errors.

The same fleet was then run with the server's `GOMAXPROCS` set through a
Compose override, five steady minutes for each value, to see whether fewer
threads would save CPU:

| `GOMAXPROCS` | Server CPU | Heartbeat p50 / p95 / p99 |
|---|---|---|
| 16, the default on this host | 0.83 of a core | 20 / 43 / 150 ms |
| 4 | 0.69 | 12 / 41 / 146 ms |
| 2 | 0.51 | 17 / 108 / 1,215 ms |

Four saves a little at no cost in latency. With two, requests queue and the
p99 grows eightfold. PostgreSQL moved between 0.64 and 0.79 of a core across
the three runs with nothing of its own changed, so differences of that size
are noise. The server keeps Go's default. Since Go 1.25 the default follows
the container's CPU limit, so limiting the server container's CPUs in
Compose (`cpus:`) lowers it too.
