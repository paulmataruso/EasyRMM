# Docker deployment

EasyRMM runs as a small set of containers on one Linux host, all with **host
networking**: no Docker bridge networks, no port mappings. Internal services
listen on loopback; only the server's TLS edge listens publicly.

| Container | Listens on | Data |
|---|---|---|
| `postgres` | `127.0.0.1:15432` | `/srv/easyrmm/postgres` |
| `server` | `:443`, `:80` (optional), `127.0.0.1:18081` (health) | `/srv/easyrmm/server`; `/srv/easyrmm/updater/status`, read-only ([the updater's](#held-by-the-updater)); `/srv/easyrmm/secrets`, read-only at `/run/secrets/easyrmm` (a Microsoft 365 application's secret or key for mail, [Mail](../operations/mail.md#microsoft-365)) |
| `meshcentral` | `127.0.0.1:14430` | `/srv/easyrmm/meshcentral` (its data), `/srv/easyrmm/meshcentral-config` (configuration written by the server) |
| `easypatch-api` | `127.0.0.1:18180` | `/srv/easyrmm/easypatch/keys`, `/srv/easyrmm/easypatch/winget`; its database `easypatch` in `postgres` |
| `easypatch-worker` | `127.0.0.1:18181` (health) | The same, keys read-only; `/srv/easyrmm/updater/status`, read-only |
| `easypatch-db-init`, `easypatch-migrate` | Nothing; they run once at each start and exit | |

See [network.md](../architecture/network.md) for the full port plan.

## Requirements

* Linux x86-64 or arm64 with Docker Engine 24+ and the Compose plugin.
* Two DNS names pointing at the host (recommended): the main name (for
  example `rmm.example.com`) and the remote-access name (default
  `mesh.rmm.example.com`). A wildcard record works. The separate name keeps
  MeshCentral in its own browser origin (ADR-0004). Both names must share a
  parent domain; see [network.md](../architecture/network.md#host-names).
  Without DNS, use the server's IP address instead (see
  [Without DNS](#without-dns)).
* Inbound TCP 443, plus TCP 80 if you use Let's Encrypt HTTP-01 validation,
  and TCP 4443 for remote sessions by IP address.
* Outbound HTTPS to `github.com` the first time MeshCentral starts: it
  downloads its agent binaries (about 120 MiB) from GitHub releases.
* Nothing else listening on 443, 4443, 80, 15432, 14430, 18081, 18180 or 18181. On a
  host with several addresses, `EASYRMM_LISTEN_HTTPS` and
  `EASYRMM_LISTEN_HTTP` in `.env` can name one, such as `203.0.113.10:443`
  and `203.0.113.10:80`; remote sessions by IP address then use port 4443
  of the same address.

## Install

```bash
git clone https://github.com/paulmataruso/easyrmm.git
cd easyrmm/deploy
sudo ./scripts/setup.sh --hostname rmm.example.com --acme-email you@example.com
sudo docker compose up -d
sudo docker compose logs -f server
```

Without git, download `easyrmm-v<version>-deploy.tar.gz` from a release
instead, unpack it as root into a directory only root can write, and run
the same commands from its `deploy/` directory; its `.env.example` already
names that release's image:

```bash
sudo install -d -m 0755 /opt/easyrmm
sudo tar -xzf easyrmm-v<version>-deploy.tar.gz -C /opt/easyrmm
cd /opt/easyrmm/easyrmm-v<version>/deploy
```

`setup.sh` writes `deploy/.env` (mode 600) with freshly generated database
passwords and the encryption key, and creates the data directories with the
ownership the containers expect. It never overwrites an existing `.env`.
Run as root, it also installs the [host updater](../operations/updater.md),
which upgrades the deployment and rolls it back; `--no-updater` installs
none. A bundle carries the updater; from a clone, build it first with
`make updater` (Go needed), or `setup.sh` says it is missing and goes on.

When the server starts with an empty database it writes a one-time **setup
token** to `/srv/easyrmm/server/setup-token` and logs where it is. Open
`https://rmm.example.com/`, paste the token, and create the first
administrator. The file is deleted once setup completes. Until then, only
someone with access to the server can claim it.

## TLS modes

| `EASYRMM_TLS_MODE` | Certificates | Listeners |
|---|---|---|
| `acme` (default) | Obtained and renewed from Let's Encrypt (or `EASYRMM_ACME_DIRECTORY`). Cached in `/srv/easyrmm/server/acme`. | 443, and 80 for HTTP-01 + redirects |
| `manual` | Your files, mounted from `EASYRMM_TLS_DIR` at `/etc/easyrmm/tls`. Renewed files are picked up within 30 seconds, without a restart. | 443, and 80 for redirects |
| `internal` | Issued by the server's own certificate authority, created on first start and stored encrypted in the database. Default for an IP address. | 443, 4443, and 80 for redirects |
| `offload` | Terminated by your reverse proxy. See [nginx.md](nginx.md). | `127.0.0.1:18080` only |

Both host names must be covered by the certificate (`manual`) or be
reachable for validation (`acme`). With IP access on (the default), the
server's IP addresses are served beside them with a certificate from its own
authority, on 443 and 4443.

## Without DNS

DNS is recommended, but you can reach the server by IP address: when DNS is
not working, use `https://<server address>` instead of the name (IP access,
on by default), or run the whole deployment without DNS:

```bash
sudo ./scripts/setup.sh --hostname 203.0.113.10
```

That sets `EASYRMM_PUBLIC_URL=https://203.0.113.10`; remote sessions use
`https://203.0.113.10:4443`, and TLS comes from the server's own certificate
authority (`internal` mode). Browsers warn about that authority until you
install it: **Devices → Add devices** shows its SHA-256 fingerprint and a
download. Agents installed from that page pin the server's key and need no
other step.

Install the authority only on the computers you administer EasyRMM from.
It has no name constraints (ADR-0016): a computer that trusts it would
accept a certificate signed with its key for any website. The key is sealed
in the database under `EASYRMM_SECRET_KEY`, so protect both as you would
the server. Where browsers can reach the console by a DNS name, prefer a
public certificate (`acme`) and keep the IP address as a way in when DNS
fails.

If you click through the warning instead of installing the authority,
remember that remote sessions run on port 4443, inside a frame where a
browser cannot ask. Chrome and Edge apply your exception to the whole
address; Firefox asks again for each port. In Firefox, open
`https://203.0.113.10:4443` once and accept the warning there. A session's
**Not loading?** button explains the same steps.

| Variable | Default | Meaning |
|---|---|---|
| `EASYRMM_IP_ACCESS` | `true` | Also answer on the server's IP addresses. `false` serves only `EASYRMM_PUBLIC_URL` and does not open 4443 |
| `EASYRMM_IP_ADDRESSES` | detected | Comma-separated addresses to answer on. Detected: the addresses of the default routes. Behind NAT, list the public address |
| `EASYRMM_IP_MESH_PORT` | `4443` | The remote-session port on an IP address |

See ADR-0016 for the design and its limits. In particular, with a DNS
deployment, MeshAgent on each device keeps using the MeshCentral name.

Security keys and passkeys need a name. Browsers allow them (WebAuthn) only
on a domain name, so an IP-only deployment signs in with authenticator apps.
With a name, they work at `EASYRMM_PUBLIC_URL` only; a console opened at
one of the server's IP addresses links there. Each key belongs to the name it
was registered at: if you later change the host of `EASYRMM_PUBLIC_URL`,
every registered key stops working. People then sign in with their
authenticator app or a recovery code, or an administrator resets their
second factor. See `docs/security/sign-in.md`.

## Remote access (MeshCentral)

The `meshcentral` container provides remote desktop, RDP, terminal and
files.
EasyRMM owns its configuration: the server writes `config.json` into
`/srv/easyrmm/meshcentral-config` on every start (mode 600, read-only to the
container), and the container's start script restarts MeshCentral when it
changes. Beside it the server writes `web/scripts/custom.js`, EasyRMM's
tuning of MeshCentral's session view (ADR-0025), which MeshCentral serves
from then on without a restart. Do not edit either by hand.

| Variable | Default | Meaning |
|---|---|---|
| `EASYRMM_MESH_ENABLED` | `true` | `false` runs EasyRMM without remote access; then start only `postgres` and `server` |
| `EASYRMM_MESH_PUBLIC_URL` | `https://mesh.` + the public host | The remote-access name agents and browsers use |
| `EASYRMM_MESH_CERT_URL` | this server's HTTPS listener | Where MeshCentral reads the certificate agents pin. In `offload` mode, `https://127.0.0.1:443` (your proxy). `file:///easyrmm/config/<name>.pem` also works |

EasyRMM keeps MeshCentral in step with its own data: a device group per site,
an account per user with remote-session rights, limited to the sites their
roles cover. Administrators see the connection under **Settings → Remote
access**. MeshCentral's own web interface, account pages, invitations and
sharing links are not reachable; sessions start only from a device's page in
the console.

### When devices check in but remote access is not connected

A device's page then says "The device is checking in, but its MeshAgent is
not connected to MeshCentral". When every device says it, MeshCentral is
usually holding the agents' connections because the certificate they see is
not the one it last read from `EASYRMM_MESH_CERT_URL`. Its log shows
`Agent bad web cert hash … holding connection`:

```sh
docker compose logs meshcentral | grep "bad web cert"
```

MeshCentral reads the certificate again when an agent reports a different
one, at most every two minutes, so a second change within two minutes
leaves the agents held. Restart MeshCentral, which reads the certificate as
it starts; the agents reconnect within a minute or two:

```sh
docker compose restart meshcentral
```

The certificate changes on renewal, on a change of the server's addresses,
and with the files you supply in `manual` mode. Earlier builds also issued a
new one on every restart in `internal` mode; it is now stored.

Devices join with the EasyRMM agent, which installs MeshAgent from this
server: see [Installing the EasyRMM agent](agents.md). The image includes the
Linux agent builds in `/usr/share/easyrmm/agents` (`EASYRMM_AGENT_DIR`).

## Sign-in with Authentik

With `--with-authentik`, everyone signs in to EasyRMM through
[Authentik](https://goauthentik.io), running in this deployment, with a
second factor on every sign-in ([ADR-0044](../architecture/adr/0044-authentik-when-chosen.md)).

```bash
sudo ./scripts/setup.sh --hostname rmm.example.com --with-authentik
# Sign-in name for Authentik (such as auth.example.com): auth.example.com
# Administrator's email address: you@example.com
sudo docker compose up -d
```

`setup.sh` prints an invitation link for the administrator. Point DNS for
Authentik's name at the server as well. The first `docker compose up -d`
waits for Authentik's first start, a few minutes while it sets up its
database; then open the link. Choose a name and a password, set up an
authenticator app or a security key, and you land in EasyRMM as its super
administrator. There is no setup token and no first-run page.

* **The invitation** is valid for 7 days and once. Authentik uses it up
  when the link is opened; a sign-up left half-way can be finished in the
  same browser. For another, run
  `sudo ./scripts/setup.sh --new-invitation`, then `sudo docker compose up -d`.
* **Other people** are invited in EasyRMM as usual (Settings → Users), and
  sign in with an Authentik account with the same email address, which
  Authentik's administrator makes. Roles are granted in EasyRMM only:
  Authentik's groups never grant any.
* **Authentik's own administrator** is `akadmin`, with the password in
  `/srv/easyrmm/authentik/secrets/akadmin-password`. Its console is at
  `https://auth.example.com/if/admin/`.
* **When Authentik is down,** EasyRMM's sign-in through it fails with
  "Sign-in is not answering". A super administrator can still get in with a
  one-time link, valid for 15 minutes:

  ```bash
  sudo docker compose exec server easyrmm-server recover
  # several super administrators: add --email you@example.com
  ```

  Using it is recorded in the audit log.

Authentik's settings are in `.env`: `EASYRMM_AUTHENTIK_HOSTNAME`,
`EASYRMM_AUTHENTIK_ADMIN_EMAIL`, and the secrets
`EASYRMM_AUTHENTIK_CLIENT_SECRET`, `AUTHENTIK_SECRET_KEY` and
`AUTHENTIK_DB_PASSWORD`. Its data is the `authentik` database in the same
PostgreSQL, and `/srv/easyrmm/authentik/`; back both up with the rest, as
in [Backup and restore](../operations/backup-restore.md). A backup without
them loses everyone's sign-in and the key that signs EasyRMM's ID tokens.
Settings → Single sign-on shows the Authentik provider as set by the
deployment, so it is changed only through `.env` (below). EasyRMM's edge
holds Authentik's name with its own certificate, so `--with-authentik` does
not work with TLS offload. Authentik listens on loopback only:
`127.0.0.1:18280` and `18243` (its server) and `18281` (its worker).

**Changing `EASYRMM_PUBLIC_URL`.** Edit it in `.env`, then run
`sudo docker compose up -d` (not `docker compose restart`, which keeps the
old settings). The `authentik-setup` service then runs again with the new
`.env`: it finds that Authentik still uses the old URL for EasyRMM's
redirect URI, for where an invitation's sign-up goes on to, and for the
application's link, applies EasyRMM's blueprint again, and checks that
Authentik then uses the new one. A changed
`EASYRMM_AUTHENTIK_CLIENT_SECRET` is taken the same way. Authentik's worker
does not do this by itself: it applies the blueprint again only when the
file changes. Applying takes a minute or more; signing in at the new URL
works once `authentik-setup` has finished:
`sudo docker compose ps -a authentik-setup` shows `Exited (0)`. If the
check fails, it stops with an error instead; see
`sudo docker compose logs authentik-setup`. When `.env` changed nothing
Authentik holds, `authentik-setup` applies nothing.

## Retention

| Variable | Default | Meaning |
|---|---|---|
| `EASYRMM_AUDIT_RETENTION` | `8760h` (365 days) | How long audit records are kept; at least `720h` (30 days). While [audit forwarding](../operations/audit-forwarding.md) is on, records the collector has not received are kept longer |
| `EASYRMM_JOB_RETENTION` | `2160h` (90 days) | How long finished jobs, their runs and their arguments are kept; at least `24h`. See [Scripts and jobs](../operations/scripts-and-jobs.md#retention) |
| `EASYRMM_JOB_OUTPUT_RETENTION` | `720h` (30 days), or `EASYRMM_JOB_RETENTION` when that is shorter | How long a run's output is kept after it arrived; then it is emptied and the run kept. At least `24h` and at most `EASYRMM_JOB_RETENTION`. See [Who sees output and arguments](../operations/scripts-and-jobs.md#who-sees-output-and-arguments) |
| `EASYRMM_METRICS_RETENTION` | `168h` (7 days) | How long per-minute device measurements are kept for charts; at least `24h`. See [Inventory and health](../operations/inventory.md) |
| `EASYRMM_ALERT_RETENTION` | `2160h` (90 days) | How long resolved alerts are kept; at least `24h`. See [Alerts](../operations/alerts.md) |
| `EASYRMM_HARDWARE_RETENTION` | `17520h` (730 days) | How long one disk health sample per disk and day is kept. Every reading is kept for `EASYRMM_METRICS_RETENTION`, then thinned to the day's worst state, highest temperature and last counts; at least `EASYRMM_METRICS_RETENTION`. See [Disk health](../operations/disk-health.md#history-and-retention) |
| `EASYRMM_AGENT_LOG_RETENTION_DAYS` | `14` | How many days agents' log records are kept, 1 to 90. Records are deleted in batches by the server's hourly maintenance; each device stores at most 200,000 a day. See [Agent logs](../operations/agent-logs.md) |

## Patching engine

The patching engine runs inside this deployment
([how it works](../architecture/patching-engine.md)): `setup.sh` sets it
up and `docker compose up -d` starts it with everything else. There is no
setting to turn it on or off.

On an existing install, `sudo ./scripts/setup.sh --upgrade` (which takes
every setting from `.env`; see [Upgrading](../operations/upgrading.md)) adds the
engine's database passwords and `EASYRMM_PATCHING_KEY` to `.env` if they are
missing, and removes `EASYRMM_PATCHING` and the `patching` profile from
`COMPOSE_PROFILES`, which no longer exist, without changing anything else
there. The key signs
EasyRMM's calls to the engine, one short statement per request
([ADR-0038](../architecture/adr/0038-statements-to-the-patching-engine.md));
treat it like the other secrets in `.env`. The engine's services are:

| Service | What it does |
|---|---|
| `easypatch-db-init` | Creates the `easypatch` database and its roles in EasyRMM's PostgreSQL, or brings them up to date; runs before every start, also on an existing install |
| `easypatch-migrate` | Applies the engine's migrations as `easypatch_owner`, then exits |
| `easypatch-api` | The engine, on `127.0.0.1:18180` only, as `easypatch_app` |
| `easypatch-worker` | Background work, health on `127.0.0.1:18181` only. Needs outbound HTTPS to Microsoft's update and security feeds, CISA's catalogue of exploited vulnerabilities, the Debian security tracker and GitHub (winget) |

To bring a standalone EasyPatch's endpoints, history and settings over, see
[Importing a standalone EasyPatch](../operations/import-easypatch.md).

The engine's data-protection keys and winget copy are under
`${EASYRMM_DATA_ROOT}/easypatch/` (owner 1654, the image's user). Back up
the keys with the database: they decrypt the engine's stored mail and
webhook credentials.

**The engine comes with the release.** A release bundle's
`docker-compose.yml` names the engine built from the same commit, by digest,
so upgrading the bundle upgrades both; the release's manifest lists both
images ([ADR-0043](../architecture/adr/0043-one-release.md)). The engine's
image carries the EasyPatch agent's Windows and Linux packages of its own
version, each with its release signature, read-only. There is nothing to
download or copy
([ADR-0041](../architecture/adr/0041-agent-packages-in-the-engine-image.md)).
From a clone, Compose builds the engine from this repository,
**without agent packages**, so EasyRMM cannot install the EasyPatch agent.
For a test install, `easypatch/scripts/build-test-agent-packages.sh` (needs
the .NET SDK) stages Linux packages signed with a throwaway key before
`docker compose build`. Their agents trust only that key; `make e2e-bundle`
works this way.

EasyRMM's patching pages use the engine:

* **Settings → Patching engine** shows the engine and its state; there is no
  address or token to enter, and it cannot be removed there. *Check now*
  shows whether the engine accepts EasyRMM's key.
* **EasyRMM keeps the engine's organizations.** Every organization and site
  has its own in the engine, created, renamed and archived with EasyRMM's
  ([ADR-0040](../architecture/adr/0040-one-set-of-organizations.md),
  [Patching](../operations/patching.md#organizations-in-the-engine));
  there is nothing to link in Settings.
* **Agents use EasyRMM's name.** EasyRMM's edge forwards the engine's agent
  API and package downloads (`/api/v1/agents/`, `/downloads/agent/`,
  `/downloads/winget/`) and nothing else of it
  ([ADR-0039](../architecture/adr/0039-agents-on-easyrmms-name.md)).
  EasyRMM installs the EasyPatch agent itself; EasyPatch's own install
  one-liners (`/downloads/install/`) do not work on EasyRMM's name.
* **Installs addressed by IP** (`EASYRMM_TLS_MODE=internal`): EasyRMM gives
  the EasyPatch agents its own certificate authority, which they trust for
  EasyRMM's address only: the Windows MSI as `SERVERCACERT`, the Linux
  agent with `enroll --server-ca`
  ([ADR-0042](../architecture/adr/0042-agents-trust-easyrmms-authority.md)).
  Nothing is added to the device's own certificate store.

## Security posture of the containers

* The server runs as UID 65532 on a distroless image with a read-only root
  filesystem and **every capability dropped except `NET_BIND_SERVICE`**,
  which the binary holds as a file capability to bind 443/80.
  `no-new-privileges` is not set because it would disable that file
  capability; the image contains no setuid binaries.
* PostgreSQL listens on loopback only and uses SCRAM-SHA-256. The server
  connects with two roles: `easyrmm_owner` (migrations only) and
  `easyrmm_app` (runtime, data access only, subject to row-level security).
* The patching engine runs as UID 1654 with a read-only root
  filesystem, every capability dropped and `no-new-privileges`, on loopback
  only. Its runtime role, `easypatch_app`, reads and writes rows in its own
  database and can neither change the schema nor connect to EasyRMM's.
* MeshCentral runs as UID 65532 with a read-only root filesystem, every
  capability dropped and `no-new-privileges`. It listens on
  `127.0.0.1:14430` only, with TLS offloaded to the server's edge, and trusts
  forwarded client addresses only from loopback.
* Secrets are passed as environment variables from `deploy/.env`. Every
  `EASYRMM_*` secret also accepts a `_FILE` variant (for example
  `EASYRMM_SECRET_KEY_FILE`) if you prefer files mounted from a secret store.

## Operations

```bash
docker compose ps                    # health of each container
docker compose logs -f server        # structured JSON logs
docker compose logs -f meshcentral   # remote-access service
docker compose exec server easyrmm-server version
```

To upgrade, follow [Upgrading](../operations/upgrading.md). Migrations run at
start-up under an advisory lock, so several servers starting at once cannot
race. They only run forward, so take a backup first
([backup-restore.md](../operations/backup-restore.md)).

EasyRMM reaches PostgreSQL directly, as the compose file has it. A pooler
between them must keep each session on one connection to PostgreSQL
(PgBouncer's `pool_mode = session`): **a pooler in transaction mode, such
as PgBouncer's `pool_mode = transaction`, is not supported**. Advisory
locks held by a session belong to the connection to PostgreSQL, and
EasyRMM's servers choose the one that gives the patching engine its mail
server with one ([Mail](../operations/mail.md#the-patching-engine)); behind
such a pooler, the lock would go to whichever session used that
connection next.

### Held by the updater

`/srv/easyrmm/updater/status` belongs to root (mode 755): `setup.sh`
makes it, and the server and the engine's worker mount it read-only at
`/run/easyrmm-updater`. The updater on the host
([ADR-0052](../architecture/adr/0052-the-host-updater.md), not built yet)
will tell the deployment there what it is doing.

While a file named `hold` exists in it, the server answers its health
check and nothing else: the console, the API, agents, the patching
engine's agents, and Authentik's and MeshCentral's names get
`503 Service Unavailable` with `Retry-After: 60`. Only ACME's challenges
are still answered, so that certificates can be renewed. The updater
writes the file before it starts a new version and removes it once the
upgrade is confirmed, so that nothing reaches a version it may still roll
back. The server looks for it every second and logs when it is held and
when it serves again; without the file nothing is held. The health check
passes while the server is held, and says so:

```bash
curl -s http://127.0.0.1:18081/readyz   # "ready, held by the updater"
```

A restart, an upgrade or a hold raises no offline alert: see
[Alerts](../operations/alerts.md#restarts-and-upgrades).

### Rotating the encryption key

1. Generate a new key: `openssl rand -base64 32`.
2. In `.env`, move the current pair into `EASYRMM_SECRET_KEYS_PREVIOUS`
   (`k1:<old key>`), set `EASYRMM_SECRET_KEY` to the new key and
   `EASYRMM_SECRET_KEY_ID` to a new identifier (`k2`).
3. `docker compose up -d server`. New values are sealed with the new key;
   values sealed with the old key stay readable as long as it is listed in
   `EASYRMM_SECRET_KEYS_PREVIOUS`. Keep it listed: today, existing
   second-factor secrets are only re-sealed when a user enrolls again. A bulk
   re-seal command is on the roadmap.

Changing the key also invalidates every CSRF token, so signed-in users reload
once.

## Building the image yourself

```bash
docker compose build server          # uses docker/server/Dockerfile
```

The image build runs the web interface build (Node), the Go build and the
Linux agent builds in separate stages; the final image contains only the
static server binary and the agent binaries it serves.
