# Docker deployment

EasyRMM runs as a small set of containers on one Linux host, all with **host
networking**: no Docker bridge networks, no port mappings. Internal services
listen on loopback; only the server's TLS edge listens publicly.

| Container | Listens on | Data |
|---|---|---|
| `postgres` | `127.0.0.1:15432` | `/srv/easyrmm/postgres` |
| `server` | `:443`, `:80` (optional), `127.0.0.1:18081` (health) | `/srv/easyrmm/server` |
| `meshcentral` | `127.0.0.1:14430` | `/srv/easyrmm/meshcentral` (its data), `/srv/easyrmm/meshcentral-config` (configuration written by the server) |

See [network.md](../architecture/network.md) for the full port plan.

## Requirements

* Linux x86-64 or arm64 with Docker Engine 24+ and the Compose plugin.
* Two DNS names pointing at the host: the main name (for example
  `rmm.example.com`) and the remote-access name (default
  `mesh.rmm.example.com`). A wildcard record works. The separate name keeps
  MeshCentral in its own browser origin (ADR-0004). Both names must share a
  parent domain; see [network.md](../architecture/network.md#host-names).
* Inbound TCP 443, plus TCP 80 if you use Let's Encrypt HTTP-01 validation.
* Outbound HTTPS to `github.com` the first time MeshCentral starts: it
  downloads its agent binaries (about 120 MiB) from GitHub releases.
* Nothing else listening on 443, 80, 15432, 14430 or 18081.

## Install

```bash
git clone https://github.com/paulmataruso/easyrmm.git
cd easyrmm/deploy
sudo ./scripts/setup.sh --hostname rmm.example.com --acme-email you@example.com
sudo docker compose up -d
sudo docker compose logs -f server
```

`setup.sh` writes `deploy/.env` (mode 600) with freshly generated database
passwords and the encryption key, and creates the data directories with the
ownership the containers expect. It never overwrites an existing `.env`.

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
| `offload` | Terminated by your reverse proxy. See [nginx.md](nginx.md). | `127.0.0.1:18080` only |

Both host names must be covered by the certificate (`manual`) or be
reachable for validation (`acme`).

## Remote access (MeshCentral)

The `meshcentral` container provides remote desktop, terminal and files.
EasyRMM owns its configuration: the server writes `config.json` into
`/srv/easyrmm/meshcentral-config` on every start (mode 600, read-only to the
container), and the container's start script restarts MeshCentral when it
changes. Do not edit it by hand.

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

Devices appear in EasyRMM when a MeshCentral agent connects. EasyRMM does
not build agent installers yet (phase 6).

## Security posture of the containers

* The server runs as UID 65532 on a distroless image with a read-only root
  filesystem and **every capability dropped except `NET_BIND_SERVICE`**,
  which the binary holds as a file capability to bind 443/80.
  `no-new-privileges` is not set because it would disable that file
  capability; the image contains no setuid binaries.
* PostgreSQL listens on loopback only and uses SCRAM-SHA-256. The server
  connects with two roles: `easyrmm_owner` (migrations only) and
  `easyrmm_app` (runtime, data access only, subject to row-level security).
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
docker compose pull && docker compose up -d   # upgrade (migrations run automatically)
docker compose exec server easyrmm-server version
```

Upgrades apply database migrations at start-up under an advisory lock, so
several servers starting at once cannot race. Take a backup first; see
[backup-restore.md](../operations/backup-restore.md).

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

The image build runs the web interface build (Node) and the Go build in
separate stages; the final image contains only the static server binary.
