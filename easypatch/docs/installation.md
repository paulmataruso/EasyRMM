# Installing the EasyPatch server

The EasyPatch server is a Docker Compose stack with four long-running containers (`caddy`,
`api`, `worker`, `postgres`) and one one-shot container (`migrate`). See
[architecture.md](architecture.md#6-docker-deployment-design) for the design. This guide covers
installation, first sign-in, agent packages, upgrades, backup and restore.

## Requirements

| | |
|---|---|
| Host | 64-bit Linux with Docker Engine and the Docker Compose plugin. The development override (`docker-compose.dev.yml`) uses the `!override` tag, which needs Compose 2.24.4 or later |
| DNS | One public DNS name pointing at the host, for example `patch.example.com`; see [DNS records](#dns-records) |
| Inbound | TCP 443 from administrators and from every managed endpoint. TCP 80 from the internet, for ACME certificate validation and the HTTP to HTTPS redirect |
| Outbound | The ACME certificate authority (Caddy's defaults). If you use alert notifications: your SMTP server (usually TCP 587 or 465) and the webhook hosts (TCP 443, for example `hooks.slack.com` or your Teams workflow host), from the `worker` container only. Vulnerability data, also from the `worker` only (TCP 443): `www.cisa.gov`, `raw.githubusercontent.com` (fallback), `api.msrc.microsoft.com`, and `security-tracker.debian.org` while Debian endpoints are managed; it can be turned off under *Settings → Server*. winget, from the `worker` only and only after a Windows agent could not download it from GitHub itself: `github.com` and `release-assets.githubusercontent.com` (see [winget for agents](#winget-for-agents)). If you use single sign-on: the identity providers' HTTPS endpoints (TCP 443), from the `api` container. Pulling the images needs `ghcr.io` and Docker Hub (PostgreSQL). Building them yourself needs `mcr.microsoft.com`, Docker Hub, `api.nuget.org` and `registry.npmjs.org` instead of `ghcr.io` |

Nothing else is published. PostgreSQL is attached only to an internal Docker network and has no
host port.

### DNS records

The console, the API, agent check-ins, agent downloads and install scripts all use the one name in
`EASYPATCH_DOMAIN`, so EasyPatch needs a single DNS name:

| Type | Name | Value | Needed |
|---|---|---|---|
| A | `patch.example.com` | The host's public IPv4 address | Yes |
| AAAA | `patch.example.com` | The host's public IPv6 address | Only if the host answers on IPv6 (TCP 80 and 443). Certificate authorities try IPv6 first, so an AAAA record for an address that does not answer makes certificate issuance fail |
| CAA | `example.com` | `0 issue "letsencrypt.org"` and `0 issue "zerossl.com"` (Caddy's two default certificate authorities) | Only if the domain already has CAA records |

* The bundled Caddy obtains certificates with the HTTP and TLS-ALPN challenges only (it has no
  DNS-challenge plugin), so the name must resolve to an address that the certificate authority
  can reach on TCP 80 or 443.
* If the zone is on Cloudflare, set the record to *DNS only*: the proxy would present its own
  certificate to agents and browsers instead of the server's.
* Choose a name you will keep. Every enrolled agent stores the server's address, and SSO
  providers need the redirect address under that name registered.

## 1. Get the deployment files

The server runs from the release images on GitHub Container Registry
(`ghcr.io/paulmataruso/easypatch-server` and `ghcr.io/paulmataruso/easypatch-proxy`, for x64 and
ARM64). You need the repository for `docker-compose.yml`, the Caddy configuration and the
scripts. Check out the release tag you want to run:

```bash
git clone --branch v1.10.0 https://github.com/paulmataruso/EasyPatch.git easypatch
cd easypatch
```

To build the images yourself instead, see [Building the images from source](#building-the-images-from-source).

## 2. Prepare secrets and configuration

```bash
./scripts/init-secrets.sh
```

The script is safe to re-run and never overwrites existing files. It creates:

* `secrets/db_password`: a random 64-character database password, used as a Compose secret.
  The `secrets/` directory is mode 700. The password never appears in `.env`, environment
  variables or image layers;
* `data/agent-packages/`: the directory from which agent MSIs are offered for download;
* `.env`, copied from `.env.example` (mode 600).

Edit `.env`:

| Variable | Required | Meaning |
|---|---|---|
| `EASYPATCH_DOMAIN` | yes | The public DNS name. Browsers and agents connect to `https://<EASYPATCH_DOMAIN>` |
| `ACME_EMAIL` | yes | Contact address given to the certificate authority |
| `EASYPATCH_VERSION` | no | The release to run: the image tag pulled from `ghcr.io` (default `1.10.0`). Images you build yourself get this tag too |
| `EASYPATCH_PUBLIC_URL` | no | Overrides the URL used in install commands, reset links and scripts. Defaults to `https://<EASYPATCH_DOMAIN>` |
| `EASYPATCH_EDGE_SUBNET` | no | Subnet of the network between Caddy and the API (default `172.30.0.0/24`). Change it only if it collides with an existing network. The API trusts `X-Forwarded-For` only from this subnet |

`.env` holds no passwords. `secrets/`, `data/`, `backups/` and `.env` are ignored by git.

## 3. Start

```bash
docker compose pull
docker compose up -d
docker compose ps
```

Start-up order is enforced by health checks: `postgres` becomes healthy, `migrate` applies the
database migrations and exits, then `api` and `worker` start, and `caddy` starts once the API is
ready. Caddy requests the certificate on first start; follow it with
`docker compose logs -f caddy`.

## 4. Create the first administrator

```bash
docker compose run --rm api create-admin --email admin@example.com
```

This creates a SuperAdmin who signs in with that email address and prints a temporary password
once. The password is not logged. Users always sign in with their email address (case does not
matter); `--name` sets the account name shown in the console and the audit log (by default the
part of the address before `@`).
To set the password yourself instead, pass `--password-stdin` and supply it on standard input
(use `-T` so Compose passes stdin through):

```bash
docker compose run --rm -T api create-admin --email admin@example.com --password-stdin
```

## 5. First sign-in

Open `https://<EASYPATCH_DOMAIN>` and sign in with the email address and the temporary password. Before anything else
the console requires you to:

1. **Set up multi-factor authentication**: scan the QR code with an authenticator app, enter a
   code, then store the recovery codes it shows once.
2. **Choose a new password**: 12 to 256 characters with at least 4 distinct characters. It may
   not contain the username.

MFA is required for every user while the server setting `RequireMfa` is on (the default). An
authenticator app, a security key or a passkey each satisfies it. Passkeys and security keys
work only when `EASYPATCH_DOMAIN` is a DNS name with a certificate the browsers trust (the
public ACME certificate does this); with an IP address the console offers the authenticator app
only. Users manage them under **My account → Passkeys and security keys**; see
[security.md](security.md#admin-authentication). To let administrators sign in with Microsoft
Entra ID, Google, Keycloak or another OpenID Connect provider, see
[single-sign-on.md](single-sign-on.md).

Then:

* create other users under **Settings → Users** (roles: SuperAdmin, Admin, ReadOnly, optionally
  restricted to specific organizations);
* review **Settings → Global policy** and **Settings → Server settings**;
* to receive alerts by email or chat, set up the SMTP server and channels under
  **Settings → Notifications**, then select the channels in **Settings → Alert rules** (see
  [alerts.md](alerts.md)). Without channels, alerts are only shown on the **Alerts** page;
* create an organization and its sites under **Organizations**.

## 6. Offer agent packages

Download the agent packages of the same release from
[GitHub Releases](https://github.com/paulmataruso/EasyPatch/releases), check them, and copy them,
each with its `.sig` release signature, to `data/agent-packages/`:

```bash
mkdir -p /tmp/easypatch-v1.10.0
gh release download v1.10.0 --repo paulmataruso/EasyPatch --dir /tmp/easypatch-v1.10.0 \
  --pattern 'EasyPatchAgent-*' --pattern SHA256SUMS
# or download the same files from the release page in a browser
(cd /tmp/easypatch-v1.10.0 && sha256sum --check --ignore-missing SHA256SUMS)
# Windows and Linux; the macOS .pkg files are experimental (see below)
cp /tmp/easypatch-v1.10.0/EasyPatchAgent-1.10.0-*.{msi,deb,rpm}* data/agent-packages/
chmod 644 data/agent-packages/*
```

Each release has MSIs (x64, ARM64) for Windows, `.deb` and `.rpm` packages (x64, ARM64) for
Linux and, from 1.9.0, `.pkg` packages (x64, ARM64) for macOS, each with a `.sig` file. Copy only
the packages you need. **The macOS agent is experimental: it is in development and not for
production use** ([macos-agent.md](macos-agent.md)). Copy the `.pkg` files only to a server you
use to test it: once they are there, the console offers the macOS install commands. The `.sig` files are what let
agents update themselves; agents verify them against the release public key built into them, so
`SHA256SUMS` is only a check of the download. The MSIs are not Authenticode-signed, so Windows
SmartScreen may warn when an MSI is opened by hand. To build the packages yourself, see
[agent-installation.md](agent-installation.md#building-from-source),
[linux-agent.md](linux-agent.md#building-from-source) and
[macos-agent.md](macos-agent.md#building-from-source).

* File names must match `EasyPatchAgent-<version>-<x64|arm64>.<msi|deb|rpm|pkg>` (version
  `MAJOR.MINOR.BUILD`, optionally with a fourth part). Other files starting with `EasyPatchAgent-`
  are ignored and a warning is logged; `.sig` and `.sha256` files are not packages.
* The API runs as uid 1654 and mounts the directory read-only, so the files must be
  world-readable.
* The server computes each package's SHA-256 itself. The package list is refreshed at most once a
  minute.
* Packages appear under **Deploy → Agent packages**. The console uses the newest MSI to
  build `msiexec` commands and the PowerShell install script for deployment codes. That script
  verifies the package's SHA-256, and optionally its Authenticode signature, before installing.
  The Linux install script offers the newest `.deb` and `.rpm` for each architecture and
  verifies the SHA-256 of the one it downloads; the macOS install script does the same with the
  newest `.pkg`.
* Agents (Windows 1.2.0 and later, all Linux and macOS agents) update themselves to the newest **signed**
  package in their own format and architecture (one with a valid `.sig` file): automatically when the *Agent updates* policy is Automatic (the default), or when
  an Operator chooses *Update agent…*. Copying a newer signed package here therefore starts a
  rollout. Set the policy to Manual first if you want to choose when. Agents check the release
  signature against the key built into them, so the server cannot make them install anything
  else. See [agent-installation.md](agent-installation.md#upgrading). Older agents only log that
  a newer version exists; install the MSI on them once.
* The release private key belongs on the machine that builds the agent. Never copy it to the
  server: the server needs only the packages and their `.sig` files.

### winget for agents

Windows agents 1.7.0 and later install winget when a computer has none (see
[agent-installation.md](agent-installation.md#winget)). They download it from GitHub, and from
the server (`/downloads/winget/…`) when GitHub cannot be reached. Nothing needs to be set up:
the first time an agent asks the server, the `worker` downloads the pinned release (about
315 MB) from GitHub into the `winget` volume, and agents try again 15 minutes later. If that
download fails, the endpoint page shows the server's error next to the agent's.

If the server cannot reach GitHub either, download the three files of the
[winget v1.29.380 release](https://github.com/microsoft/winget-cli/releases/tag/v1.29.380)
elsewhere and copy them to `data/agent-packages/winget/` (world-readable, like the packages):

* `Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle`
* `DesktopAppInstaller_Dependencies.zip`
* `e53e159d00e04f729cc2180cffd1c02e_License1.xml`

The server serves a file only when its size and SHA-256 match the values built into EasyPatch,
and agents check them again.

Agent installation and enrollment are described in [agent-installation.md](agent-installation.md)
(Windows), [linux-agent.md](linux-agent.md) (Linux) and [macos-agent.md](macos-agent.md) (macOS,
experimental).

## Upgrading

Back up first, then switch to the new release and restart:

```bash
./scripts/backup.sh
git fetch --tags && git checkout v1.4.1      # the new release's docker-compose.yml and scripts
$EDITOR .env                                 # EASYPATCH_VERSION=1.4.1
docker compose pull
docker compose up -d
```

Then download the new release's agent packages into `data/agent-packages/` (see
[Offer agent packages](#6-offer-agent-packages)). With the default *Automatic* agent updates
policy, agents then update themselves. If you build the images yourself, run
`docker compose build` instead of `docker compose pull`.

`migrate` runs again on `up -d` and applies any new migrations before `api` and `worker` start.
Agents keep working through the restart. Each agent stores its unsent reports in an outbox and
retries them, and jobs stay queued in the database.

Use the `docker-compose.yml` of the new version: it may add networks or volumes. For example,
the release with alerts gives the `worker` the `dpkeys` volume (read-only) and the outbound
`egress` network. The upgrade adds seven default alert rules without notification channels. The
release with vulnerability data adds an eighth, *Known-exploited vulnerability unpatched*, and the
worker then downloads vulnerability data (see the outbound row in [Requirements](#requirements)).
It needs no configuration change. The release with monthly reports adds two tables; reports are
off until you set up a schedule (**Reports → Monthly reports**), and emailing them needs SMTP with
STARTTLS or TLS. Release 1.7.0 adds the `winget` volume (written by the `worker`, read-only in the
`api`); see [winget for agents](#winget-for-agents). Release 1.8.0 adds a ninth default alert
rule, *Update on hold*, and the rollout guard, which is on by default (**Settings → Server
settings → Rollout guard**; see [architecture.md](architecture.md#update-holds-and-the-rollout-guard)).
It also adds the `api_tokens` table; no API tokens exist until a super administrator creates one.
Release 1.9.0 adds the experimental macOS agent and no database changes. For Windows and Linux
agents, 1.9.0 only fixes when the agent log is rotated (see the [changelog](../CHANGELOG.md)). The
console's macOS install script needs the macOS packages in `data/agent-packages/`.
Release 1.10.0 changes how users sign in: **with their email address, no longer their
username**. Before upgrading, make sure each user has an email address of their own and that you
know the one of your own account; the upgrade stops, changing nothing, if two users share an
address (ignoring case). The administration commands take `--email` instead of `--username`. The
upgrade adds the tables for passkeys, security keys and single sign-on; none is set up until a
user or super administrator does it. Pull both images: the proxy image now keeps single sign-on
codes out of its access log. The agents do not change in 1.10.0.

## Backup and restore

```bash
./scripts/backup.sh
```

This writes `backups/<UTC timestamp>/`, created with umask 077, containing:

| File | Contents |
|---|---|
| `easypatch.dump` | `pg_dump` custom-format database dump |
| `dpkeys.tar` | ASP.NET Data Protection keys. **Without these, MFA secrets, notification secrets (SMTP password, webhook URLs and signing keys) and single sign-on client secrets in the dump cannot be decrypted: every user must enroll MFA again and the secrets must be entered again** |
| `agent-packages.tar` | The agent MSIs |
| `SHA256SUMS` | Checksums of the three files |

The stack must be running (the script uses the `postgres` and `api` containers). Copy backups off
the host and protect them. The dump contains hashed credentials and agent public keys, and
`dpkeys.tar` decrypts MFA secrets, notification secrets and single sign-on client secrets. Keep them in separate locations if you can.

To restore:

```bash
./scripts/restore.sh backups/20261113T020000Z --yes
```

The script:

1. verifies `SHA256SUMS`;
2. stops `caddy`, `api` and `worker`;
3. restores the database with `pg_restore --clean --if-exists`, then replaces the key ring and the
   agent packages;
4. starts the stack again.

**The restore replaces the current database.** The stack must have been started at least once
so that the volumes exist. `secrets/db_password` is not part of the backup. To restore onto a new
host, first follow steps 1 to 3 above (which initialize a database with that host's own
password), then run `restore.sh`. You do not need to create an administrator: the restored
database contains the users.

## Operational commands

The API image includes administration commands. Run them with
`docker compose run --rm api <command>`:

| Command | Purpose |
|---|---|
| `migrate` | Apply database migrations (the `migrate` service runs this automatically) |
| `create-admin --email <email> [--name <name>] [--password-stdin]` | Create a SuperAdmin who signs in with `<email>`. `<name>` is the account name shown in the console (default: the part of the address before `@`) |
| `reset-password --email <email> [--password-stdin]` | Reset a password and revoke the user's sessions. A generated password must be changed at next sign-in |
| `reset-mfa --email <email>` | Remove a user's MFA (authenticator app, passkeys and security keys) and revoke their sessions. They enroll again at next sign-in |
| `unlock --email <email>` | Clear a login lockout |
| `help` | List the commands |

These are for recovery when no SuperAdmin can sign in. Day-to-day, a SuperAdmin uses
**Settings → Users**. `reset-password`, `unlock` and the console actions are recorded in the
audit log.

## Rate limits and other configuration

Per-client rate limits can be changed with environment variables on the `api` service, for
example in a `docker-compose.override.yml`, which Compose loads automatically:

```yaml
services:
  api:
    environment:
      RateLimits__LoginPerMinute: "20"     # per IP: login, MFA and password routes
      RateLimits__EnrollPerMinute: "30"    # per IP: agent enrollment
      RateLimits__AgentPerMinute: "120"    # per agent credential
      RateLimits__DownloadsPerMinute: "60" # per IP: package and install-script downloads
      RateLimits__AdminPerMinute: "600"    # per user (or IP when anonymous): admin API
```

The values shown are the defaults. Everything else, including job limits, offline threshold,
credential lifetime, retention and session timeouts, is under **Settings → Server settings**.

## Development and lab mode

`docker-compose.dev.yml` replaces ACME with Caddy's internal certificate authority
(`local_certs`), and publishes HTTPS only on `127.0.0.1:8443` (HTTP is not published).

```bash
# in .env: EASYPATCH_DOMAIN=localhost (ACME_EMAIL must be set but is not used)
docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d --build
docker compose -f docker-compose.yml -f docker-compose.dev.yml run --rm api create-admin --email admin@example.com
```

Open `https://localhost:8443` and accept the certificate warning, or trust Caddy's root
certificate. To use a different port, set `EASYPATCH_HTTPS_PORT`.

To reach a lab server from other machines on a private network, set both the address and the
name to the host's LAN IP address in `.env`, for example `EASYPATCH_BIND_ADDRESS=192.168.1.20`
and `EASYPATCH_DOMAIN=192.168.1.20`. Then open `https://192.168.1.20:8443`. Caddy's internal CA
issues a certificate for the IP address. Anyone who can reach that address can reach the sign-in
page, so do this only on a trusted network. Browsers do not allow passkeys or security keys on
an IP address, so such a server offers only the authenticator app for MFA. Agents only connect to a server whose certificate
they trust. For a lab agent, either put Caddy's root certificate in the computer's Trusted Root
store, or turn on *Skip certificate check* when you generate the Windows install script: the
agent then trusts Caddy's CA, which the lab proxy publishes at `/server-ca.crt`, for its
EasyPatch connection only (see
[Servers with a private certificate authority](agent-installation.md#servers-with-a-private-certificate-authority)).
Do not use this mode in production.

## Building the images from source

`docker-compose.yml` names the release images but also says how to build them, so you can run
your own build of any commit:

```bash
docker compose build        # tags the images with EASYPATCH_VERSION from .env
docker compose up -d
```

Use a version of your own in `.env` (for example `EASYPATCH_VERSION=1.10.0-local`) so that
`docker compose pull` never replaces your images with the release images.

## Building and testing from source

Building requires the .NET SDK version pinned in `global.json` and Node.js 24.

```bash
dotnet build EasyPatch.slnx -c Release
dotnet test backend/Tests/EasyPatch.Tests.csproj           # needs Docker (Testcontainers PostgreSQL)
dotnet test agent/EasyPatch.Agent.Tests/EasyPatch.Agent.Tests.csproj

cd frontend
npm ci
npm run typecheck && npm test && npm run build
```

`scripts/build-msi-linux.sh --arch all` builds the agent MSIs with Docker (see
[agent-installation.md](agent-installation.md#building-from-source)).
`scripts/audit-dependencies.sh` lists known-vulnerable NuGet packages, including transitive
ones, and runs `npm audit`.
