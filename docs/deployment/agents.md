# Installing the EasyRMM agent

The EasyRMM agent puts a computer under management. It enrolls with a
deployment token, reports in every minute, and installs MeshAgent, the
remote-access agent, from your own server (ADR-0015).

Today the agent runs on **Linux with systemd**, on x86-64, ARM 64-bit,
ARMv7 and 32-bit x86. There is no Windows or macOS agent yet, and no DEB or
RPM package: Linux computers install with the script below.

## Requirements

* Root (the installer is run through `sudo`).
* systemd, `sha256sum`, and `curl` or `wget`.
* Outbound HTTPS (443) to the EasyRMM server name, for example
  `rmm.example.com`, and to the MeshCentral name, `mesh.rmm.example.com`.
  Nothing connects to the computer.
* A clock within five minutes of the server's. Signed requests from a
  computer with a wrong clock are refused (`clock_skew`).

## 1. Create a deployment token

In the console, open **Devices → Add devices** (or **Add devices** on a
site's page). Choose the site the computers belong to and, optionally, a
device group; name the token after the rollout; choose when it expires (1 to
90 days) and, optionally, how many devices may use it.

The install command is shown once, right after the token is created. Copy it
then: the server keeps only a hash of the token. Anyone holding the token can
add computers to that site until it expires, reaches its device limit or is
revoked, so revoke it under **Deployment tokens** once the rollout is done.
Revoking a token does not affect computers that already enrolled with it.

You need a role with the `enrollment.manage` permission for the site:
Super Administrator, Organization Administrator or Site Administrator.

## 2. Install

On each computer:

```sh
curl -fsSL https://rmm.example.com/api/agent/v1/install.sh | sudo sh -s -- --token ert_…
```

Without curl, replace `curl -fsSL` with `wget -qO-`. The script:

1. checks that it runs as root on Linux with systemd;
2. maps the machine's architecture to an agent build;
3. downloads that build and `SHA256SUMS` from the server (HTTPS only when the
   server URL is HTTPS) and refuses a binary whose checksum does not match;
4. installs it as `/usr/local/bin/easyrmm-agent`;
5. runs `easyrmm-agent install`, which enrolls the computer and starts the
   `easyrmm-agent` service.

The token reaches the agent in the `EASYRMM_TOKEN` environment variable. It is
used once and not stored.

Within a minute the computer is listed under **Devices** as online. On its
next heartbeat the agent downloads MeshAgent and its settings from the EasyRMM
server and starts it; the device page's **Remote access** row changes from
*Not set up yet* to *Connected* once MeshCentral links it.

### Installing without the script

The binaries are listed with their SHA-256 under **Agent downloads** on the
Add devices page, and served at
`https://rmm.example.com/api/agent/v1/download/<file>` with
`/api/agent/v1/download/SHA256SUMS` alongside.

```sh
curl -fsSLO https://rmm.example.com/api/agent/v1/download/easyrmm-agent-linux-amd64
curl -fsSL https://rmm.example.com/api/agent/v1/download/SHA256SUMS | grep ' easyrmm-agent-linux-amd64$' | sha256sum -c -
sudo install -m 0755 easyrmm-agent-linux-amd64 /usr/local/bin/easyrmm-agent
sudo EASYRMM_TOKEN=ert_… easyrmm-agent install --server https://rmm.example.com
```

If the server's certificate comes from a private certificate authority, add
`--ca-file /path/to/ca.pem`; the agent keeps a copy and trusts it for every
later request.

## What is installed

| Path | What |
|---|---|
| `/usr/local/bin/easyrmm-agent` | The agent |
| `/etc/systemd/system/easyrmm-agent.service` | Its service |
| `/var/lib/easyrmm-agent/agent.json` | Server URL and device ID |
| `/var/lib/easyrmm-agent/device.key` | The device's Ed25519 private key (mode 600). It never leaves the computer; the agent refuses to start if the file is readable by others |
| `/var/lib/easyrmm-agent/status.json` | Last heartbeat, last error, MeshAgent state (read by `easyrmm-agent status`) |
| `/usr/local/lib/easyrmm-agent/meshagent/` | MeshAgent, its settings and database |
| `/etc/systemd/system/easyrmm-meshagent.service` | MeshAgent's service |

## Checking a computer

```console
$ sudo easyrmm-agent status
Server:     https://rmm.example.com
Device:     6f1c…
Enrolled:   Sun, 15 Nov 2026 10:02:11 UTC
Service:    active
Heartbeat:  Sun, 15 Nov 2026 10:41:12 UTC
MeshAgent:  installed
```

`journalctl -u easyrmm-agent` shows the agent's log. A failed heartbeat is
retried after 5 seconds, then with a doubling delay up to 5 minutes.

| Error | Meaning |
|---|---|
| `token_invalid` | The token is wrong, expired, revoked or used up. Create a new one |
| `key_in_use` | Another device already enrolled with this key. Uninstall and install again |
| `clock_skew` | The computer's clock is more than five minutes off. Fix time synchronization |
| `device_unknown` | The server has no record of this device, for example after restoring an older database backup. Uninstall and enroll again |
| `rate_limited` | Too many enrollments from one address at once; the installer can simply be run again |
| `meshagent_unavailable` | The server cannot reach MeshCentral right now; the agent retries later |

## Uninstalling

```sh
sudo easyrmm-agent uninstall
```

This stops and removes both services, MeshAgent and the agent's state. The
device stays listed in the console as offline; its history is kept. To enroll
the computer again, install it with a new token.

## Serving the agents

The server hands out the agent builds in its agent directory,
`EASYRMM_AGENT_DIR` (default `/usr/share/easyrmm/agents`). The Docker image
includes the four Linux builds there. A server built from source serves the
ones `make build-agents` writes to `bin/agents`:

```sh
make build-agents
EASYRMM_AGENT_DIR=$PWD/bin/agents bin/easyrmm-server serve
```

Files must be named `easyrmm-agent-<os>-<arch>` (`.exe` for Windows). The
server computes their checksums when it starts.
