# Privacy policy

Effective 20 November 2026. This policy covers the EasyRMM software
published by DHI Technical Services LLC in this repository: the server and
its web console, the EasyRMM agent, the patching engine and its EasyPatch
agent, and the deployment files.

## In short

* **EasyRMM is self-hosted.** It runs on your server and sends nothing to
  DHI Technical Services LLC or anyone else: no telemetry, usage
  statistics, crash reports, licence checks or update checks.
* **You control the data.** Everything EasyRMM collects goes to the server
  of the organization that installed it (the operator) and stays in that
  server's database and data directory. For personal data in it, the
  operator decides what is collected, who sees it and how long it is kept.
* **It contacts other systems only as configured.** This program will not
  transfer any information to other networked systems unless specifically
  requested by the user or the person installing or operating it. The
  downloads it makes on its own are of public data, listed
  [below](#connections-it-makes-on-its-own), and can be turned off.

We do not operate a hosted service, and we receive no data from
deployments. If you contact us (an issue, a pull request or a security
report on GitHub), GitHub's privacy statement covers what you send there.

## What the software collects

Each part sends what it collects only to the operator's own EasyRMM
server.

| Part | What it collects | Why |
|---|---|---|
| **EasyRMM agent** (on managed computers) | Host name, operating system and version, architecture, time zone; hardware: manufacturer, model, serial numbers, BIOS, processor, memory, disks; network interfaces with their MAC and IP addresses, gateways and DNS servers; installed software and its versions. Every minute: processor, memory and swap use, load, uptime, the number of processes and filesystem use. The output of scripts that technicians run on the computer | Inventory, monitoring and alerts, scripts and software deployment |
| **MeshAgent** (installed beside the agent) | What MeshCentral needs to open remote desktop, terminal and file sessions that technicians start; MeshCentral's own device information | Remote access, through the MeshCentral server in the same deployment |
| **EasyPatch agent** (patching) | Operating system and hardware details, Windows Update settings, available, installed and failed updates, installed applications (for application updates on Windows), whether a restart is pending, and the **number** of signed-in users (not their names), to decide when to restart | Patching and patch reports |
| **Server and console** | Accounts of the people who use the console: name, email address, a password hash, second-factor secrets (encrypted) and security keys' public keys; their sign-in sessions with IP address and browser; an audit log of who did what, from where, including remote sessions | Signing in, permissions and accountability |
| **The customer record** (typed in by technicians) | For each customer organization: its main phone, email, website and business hours, and each site's address and hours. Contacts, the customer's staff: name, job title, email, office and mobile phone, a note, and whether they are the primary, secondary or emergency contact | Reaching the right person at a customer, and knowing when they are open |

**In the browser** the console sets only the cookies needed to sign in
(the session, a short-lived single sign-on cookie and the remote-access
grant) and keeps one setting in the browser's storage: the light or dark
theme. It loads no third-party scripts, fonts or trackers; its content
security policy forbids them.

**Script output** (what a script printed on a device) and a job's
arguments can hold whatever the script or the person who ran it put there.
Only Technicians and above of the device's organization or site can read
them, and every read is recorded in the audit log; Read-Only users see that
a script ran and how it ended, not what it printed
([Scripts and jobs](docs/operations/scripts-and-jobs.md#who-sees-output-and-arguments)).

**Contacts** are people at the operator's customers who do not use
EasyRMM: the software never contacts them, and they cannot sign in. Only
people with `doc.view` at the customer's organization, or at the contact's
site, can read them; a site's people see that site's contacts and not the
organization's own. The audit log records that a contact was added,
changed or deleted, which fields changed, the contact's priority
(primary, secondary or none) and whether they are an emergency contact,
but not their name, job title, email address, phone numbers or note.
Contacts are kept until someone deletes them, or deletes their site or
organization, and can be exported with the **Contacts** report; the
audit log records each export, and that it was searched, but not what
was searched for ([The customer record](docs/operations/customer-record.md)).

**Retention** is up to the operator: metrics, alerts, job output, jobs and
the audit log are kept for the periods set in the deployment's `.env`
(`EASYRMM_METRICS_RETENTION`, `EASYRMM_ALERT_RETENTION`,
`EASYRMM_JOB_OUTPUT_RETENTION`, 30 days by default, `EASYRMM_JOB_RETENTION`,
`EASYRMM_AUDIT_RETENTION`), and devices and accounts until someone removes
them. A run's output can also be removed at once from its page.

## Connections it makes on its own

None of these send data about the managed computers or the people using
EasyRMM. Like any download, they show the source the address of the
computer making the request.

| What | Where | When | How to stop it |
|---|---|---|---|
| TLS certificates | Let's Encrypt, or the ACME server you set | With automatic certificates (the default for a DNS name) | Use your own certificates or the server's own authority (`EASYRMM_TLS_MODE`) |
| MeshAgent installers | GitHub (MeshCentral's releases) | The first time MeshCentral starts | Needed for remote access |
| Vulnerability data | CISA's Known Exploited Vulnerabilities catalog (with its GitHub mirror), Microsoft Security Response Center's API, the Debian security tracker | Every 6 hours (the exploited catalog) or daily, by the patching engine | **Settings → Patching → Server**: vulnerability data off |
| Updates | Windows Update, Microsoft Update or your WSUS server on Windows; the apt or dnf repositories configured on Linux computers; winget's sources for application updates | When a computer scans for or installs updates, as its own operating system would | Patch policies (automatic installs, application updates) |
| winget itself | Microsoft's winget release on GitHub, or a copy on your server | Once, on a Windows computer without a usable winget, when application updates are on | Leave application updates off |

Only when the operator sets them up, EasyRMM also sends to: an email
server (alerts, password links, reports), webhook addresses (Slack,
Microsoft Teams or others), a syslog collector (audit forwarding), and
OpenID Connect sign-in providers. Authentik, when installed with
EasyRMM, runs in the same deployment.

## Downloads

EasyRMM's releases and container images are downloaded from GitHub
(`github.com`, `ghcr.io`), whose privacy statement covers those
downloads. Managed computers download the agents from the operator's own
server.

## Security

How EasyRMM protects this data is in the
[threat model](docs/security/threat-model.md); how to report a
vulnerability is in [SECURITY.md](SECURITY.md).

## Changes

Changes to this policy are made in this file, and its history is the
repository's history. A release's notes say when this policy changed.

## Contact

Open an issue on [GitHub](https://github.com/paulmataruso/EasyRMM/issues),
or, for anything you would rather not post publicly, use GitHub's private
vulnerability reporting described in [SECURITY.md](SECURITY.md).
