# Installing the EasyRMM agent

The EasyRMM agent puts a computer under management. It enrolls with a
deployment token, reports in every minute, and installs MeshAgent, the
remote-access agent, from your own server (ADR-0015).

The agent runs on:

* **Windows** 10 and 11, and Windows Server 2016 and later, on x64 and
  ARM64, as a Windows service (ADR-0020);
* **Linux with systemd**, on x86-64, ARM 64-bit, ARMv7 and 32-bit x86.

There is no macOS agent, no MSI package and no DEB or RPM package yet:
computers install with the PowerShell or shell command below.

## Requirements

* **Windows:** an administrator, and Windows PowerShell 5.1 (built into
  Windows 10 and Server 2016 and later).
* **Linux:** root (the installer is run through `sudo`); systemd,
  `sha256sum`, and `curl` or `wget`.
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

## 2. Install on Windows

The Add devices page shows the command under **Windows**. Open **Windows
PowerShell** as administrator (right-click Start, **Terminal (Admin)** or
**Windows PowerShell (Admin)**) and paste it:

```powershell
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor 3072; & ([scriptblock]::Create((New-Object Net.WebClient).DownloadString('https://rmm.example.com/api/agent/v1/install.ps1'))) -Token 'ert_…'
```

The first part turns on TLS 1.2, which Windows PowerShell leaves off on some
systems; the rest downloads `install.ps1` from your server and runs it with
the token. The same command works from an RMM or deployment tool that runs
PowerShell as SYSTEM.

**By IP address.** The command for an address that uses the server's own
certificate authority checks the server's public key itself: it accepts only
a certificate whose key has the SHA-256 shown in the command, downloads the
script, and then turns the check off again. The script does the same for its
own downloads and gives the agent the server's certificate authority to
trust from then on (ADR-0016, ADR-0020). Run it in **Windows PowerShell**
(`powershell.exe`): PowerShell 7 cannot run this check.

`install.ps1`:

1. checks that it runs as an administrator on Windows 10, Windows Server
   2016 or later, on x64 or ARM64;
2. downloads `easyrmm-agent-windows-<arch>.exe` and `SHA256SUMS` from the
   server and refuses a program whose SHA-256 does not match;
3. runs `easyrmm-agent.exe install`, which copies itself to
   `%ProgramFiles%\EasyRMM\Agent`, enrolls the computer and starts the
   **EasyRMM Agent** service;
4. removes its downloads.

Any failure stops it with a message starting `easyrmm:`; the window stays
open. The agent is not code-signed yet; if endpoint protection holds
`easyrmm-agent.exe`, allow it by its SHA-256 from the Add devices page.

## 3. Install on Linux

Choose **Linux** on the Add devices page. On each computer:

```sh
curl -fsSL https://rmm.example.com/api/agent/v1/install.sh | sudo sh -s -- --token ert_…
```

Without curl, replace `curl -fsSL` with `wget -qO-`.

**By IP address.** When computers cannot look up the server's name, choose
the server's IP address under **Server address** after creating the token.
That address uses the server's own certificate authority, which the computer
does not trust yet, so the command pins the server's public key instead:

```sh
curl -fsSL --insecure --pinnedpubkey 'sha256//…' https://203.0.113.10/api/agent/v1/install.sh | sudo sh -s -- --token ert_…
```

`--insecure` skips only the certificate authority check; curl refuses any
other key. The script then needs curl (wget cannot pin), downloads the
server's certificate authority over the pinned connection, and enrolls the
agent with it, so the agent trusts that authority from then on (ADR-0016).

The script:

1. checks that it runs as root on Linux with systemd;
2. maps the machine's architecture to an agent build;
3. downloads that build and `SHA256SUMS` from the server (HTTPS only when the
   server URL is HTTPS) and refuses a binary whose checksum does not match;
4. installs it as `/usr/local/bin/easyrmm-agent`;
5. runs `easyrmm-agent install`, which enrolls the computer and starts the
   `easyrmm-agent` service.

On both systems the token reaches the agent in the `EASYRMM_TOKEN`
environment variable, not on its command line. It is used once and not
stored.

Within a minute the computer is listed under **Devices** as online. On its
next heartbeat the agent downloads MeshAgent and its settings from the EasyRMM
server and starts it; the device page's **Remote access** row changes from
*Not set up yet* to *Connected* once MeshCentral links it.

### Installing without the script

The binaries are listed with their SHA-256 under **Agent downloads** on the
Add devices page, and served at
`https://rmm.example.com/api/agent/v1/download/<file>` with
`/api/agent/v1/download/SHA256SUMS` alongside.

On Windows, in PowerShell as administrator:

```powershell
(Get-FileHash .\easyrmm-agent-windows-amd64.exe -Algorithm SHA256).Hash   # compare with SHA256SUMS
$env:EASYRMM_TOKEN = 'ert_…'
.\easyrmm-agent-windows-amd64.exe install --server https://rmm.example.com
Remove-Item Env:EASYRMM_TOKEN
```

On Linux:

```sh
curl -fsSLO https://rmm.example.com/api/agent/v1/download/easyrmm-agent-linux-amd64
curl -fsSL https://rmm.example.com/api/agent/v1/download/SHA256SUMS | grep ' easyrmm-agent-linux-amd64$' | sha256sum -c -
sudo install -m 0755 easyrmm-agent-linux-amd64 /usr/local/bin/easyrmm-agent
sudo EASYRMM_TOKEN=ert_… easyrmm-agent install --server https://rmm.example.com
```

If the server's certificate comes from a private certificate authority, add
`--ca-file /path/to/ca.pem`; the agent keeps a copy and trusts it for every
later request. For the server's own authority (IP addresses), download
`/api/agent/v1/ca.pem` and compare its fingerprint with the one on the Add
devices page before using it.

The same certificate is at `/api/agent/v1/easyrmm-ca.crt` in DER, the form
Windows and macOS install directly. To stop browser warnings on a Windows
computer, right-click the file, choose **Install Certificate**, **Local
Machine**, and **Place all certificates in the following store: Trusted Root
Certification Authorities** (letting Windows pick the store can leave it
where browsers do not trust it). In an administrator PowerShell:

```powershell
Import-Certificate -FilePath .\easyrmm-ca.crt -CertStoreLocation Cert:\LocalMachine\Root
```

## What is installed

On Windows:

| Path | What |
|---|---|
| `%ProgramFiles%\EasyRMM\Agent\easyrmm-agent.exe` | The agent, run by the **EasyRMM Agent** service (`EasyRMMAgent`) as LocalSystem, started automatically and restarted by Windows if it stops |
| `%ProgramData%\EasyRMM\Agent\` | Its state: `agent.json`, `device.key`, `status.json` and `jobs\`, as on Linux. The folder is readable only by SYSTEM and Administrators |
| `%ProgramData%\EasyRMM\Agent\logs\agent.log` | The agent's log (10 MiB, then `agent.log.1`) |
| `%ProgramFiles%\EasyRMM\MeshAgent\` | MeshAgent, run by the **EasyRMM MeshAgent** service (`EasyRMMMeshAgent`), separate from any other MeshCentral's agent on the computer |

On Linux:

| Path | What |
|---|---|
| `/usr/local/bin/easyrmm-agent` | The agent |
| `/etc/systemd/system/easyrmm-agent.service` | Its service |
| `/var/lib/easyrmm-agent/agent.json` | Server URL, device ID and the server's job-signing public key, pinned at enrollment |
| `/var/lib/easyrmm-agent/device.key` | The device's Ed25519 private key (mode 600). It never leaves the computer; the agent refuses to start if the file is readable by others |
| `/var/lib/easyrmm-agent/status.json` | Last heartbeat, last error, MeshAgent state (read by `easyrmm-agent status`) |
| `/var/lib/easyrmm-agent/jobs/` | Scripts being run (`work/`, removed after each run) and results not yet reported (`journal/`). See [Scripts and jobs](../operations/scripts-and-jobs.md) |
| `/usr/local/lib/easyrmm-agent/meshagent/` | MeshAgent, its settings and database |
| `/etc/systemd/system/easyrmm-meshagent.service` | MeshAgent's service |

## Checking a computer

On Windows, in PowerShell as administrator:

```powershell
& "$env:ProgramFiles\EasyRMM\Agent\easyrmm-agent.exe" status
Get-Service EasyRMMAgent, EasyRMMMeshAgent
Get-Content "$env:ProgramData\EasyRMM\Agent\logs\agent.log" -Tail 50
```

On Linux:

```console
$ sudo easyrmm-agent status
Server:     https://rmm.example.com
Device:     6f1c…
Enrolled:   Sun, 15 Nov 2026 10:02:11 UTC
Service:    active
Heartbeat:  Sun, 15 Nov 2026 10:41:12 UTC
MeshAgent:  installed
Inventory:  sent Sun, 15 Nov 2026 10:02:14 UTC
```

`journalctl -u easyrmm-agent` shows the agent's log. A failed heartbeat is
retried after 5 seconds, then with a doubling delay up to 5 minutes.

Each heartbeat carries the computer's processor, memory and disk use. The
**Inventory** line is when the agent last sent its hardware and software
list, which it does at start and whenever the list changes (checked every
hour); `not sent: …` gives the reason when an upload failed, and the agent
tries again after 15 minutes. See [Inventory and health](../operations/inventory.md).

| Error | Meaning |
|---|---|
| `token_invalid` | The token is wrong, expired, revoked or used up. Create a new one |
| `key_in_use` | Another device already enrolled with this key. Uninstall and install again |
| `clock_skew` | The computer's clock is more than five minutes off. Fix time synchronization |
| `device_unknown` | The server has no record of this device, for example after restoring an older database backup. Uninstall and enroll again |
| `rate_limited` | Too many enrollments from one address at once; the installer can simply be run again |
| `meshagent_unavailable` | The server cannot reach MeshCentral right now; the agent retries later |

## Uninstalling

On Windows, in PowerShell as administrator:

```powershell
& "$env:ProgramFiles\EasyRMM\Agent\easyrmm-agent.exe" uninstall
```

The running program cannot delete itself; Windows removes
`easyrmm-agent.exe` at the next restart, and the command says so.

On Linux:

```sh
sudo easyrmm-agent uninstall
```

This stops and removes both services, MeshAgent and the agent's state. The
device stays listed in the console as offline; its history is kept. To enroll
the computer again, install it with a new token.

## Serving the agents

The server hands out the agent builds in its agent directory,
`EASYRMM_AGENT_DIR` (default `/usr/share/easyrmm/agents`). The Docker image
includes the two Windows and four Linux builds there. A server built from
source serves the ones `make build-agents` writes to `bin/agents`:

```sh
make build-agents
EASYRMM_AGENT_DIR=$PWD/bin/agents bin/easyrmm-server serve
```

Files must be named `easyrmm-agent-<os>-<arch>` (`.exe` for Windows). The
server computes their checksums when it starts.
