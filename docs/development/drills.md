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
server's loopback ports, so stop any other EasyRMM deployment on the host
first. Each run builds the server image from the checkout. Set
`DRILL_IMAGE` to use an image you already have.

## Backup and restore

```bash
sudo scripts/drill/backup-restore.sh /tmp/easyrmm-drill
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
   * MeshCentral's identity is unchanged.

It prints each step to `report.txt` in the working directory, with the
stack's output in `compose.log`.

The agent's container has no systemd, so MeshAgent is not installed there.
MeshAgent reconnecting is checked only when the device reports one; the
drill checks MeshCentral's identity in every case.

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
