# Phase 9 security review

In November 2026, before the first release, EasyRMM's code was reviewed in
four parts. Each part was read by a reviewer who had not written it, looking
for ways across the boundaries in [the threat model](threat-model.md):

1. sign-in and sessions;
2. the agent channel and what runs on endpoints;
3. remote access through MeshCentral, and the server's outbound integrations;
4. tenant isolation and authorization.

Each finding was then reproduced or traced before it was fixed. Where a
finding depended on MeshCentral's or MeshAgent's behaviour, that behaviour
was checked in MeshCentral 1.3.1's sources and against a running MeshCentral
and MeshAgent. The fixes come with tests. The tests for the remote-access,
agent API and integration fixes were also run with the fix removed, to show
they fail without it.

Severities are the reviewers' own. The sign-in review's findings were fixed
together and are listed without one.

## Findings

### Sign-in and sessions (`e1e0d0e`)

| Finding | Outcome |
|---|---|
| An authenticator secret that was never confirmed worked as a second factor, and setting one up from a signed-in session needed no password | Fixed: only confirmed secrets count, and setup asks for the password |
| Wrong second-factor codes were counted per session, so signing in again reset the count | Fixed: counted across sign-ins; ten in a row lock the account |
| Re-entering the password for a password change or new recovery codes had no limit | Fixed: rate-limited, audited; the fifth wrong password ends the session |
| A password change kept the session token | Fixed: the token rotates |
| Password reset requests revealed through their timing whether an account existed, and replaced an invitee's invitation | Fixed: answered at once, handled in the background; invitees get a new invitation |
| Per-address limits keyed on full IPv6 addresses | Fixed: keyed on the /64 |

Details: [Signing in](sign-in.md).

### Agent channel and endpoints

| Severity | Finding | Outcome |
|---|---|---|
| High | Windows: a standard user who created `C:\ProgramData\EasyRMM\Agent` before the install kept control of it, and could later point the agent at another server and run code as SYSTEM | Fixed (`c961761`): the agent checks every folder's owner and links, and replaces one it does not trust |
| Medium | The Linux install command put the deployment token on the command line | Fixed (`c961761`): passed in the environment |
| Medium | Chocolatey actions could run a `choco.exe` a standard user planted before Chocolatey was installed | Fixed (`c961761`): Chocolatey and winget programs run only if only administrators can change them |
| Low | A cmd script's arguments could end their quotes through `%` expansion | Fixed (`c961761`): `%`, quotes and line breaks refused in cmd arguments, by the server and the agent |
| Low | The agent API read up to 4 MiB of a request before checking who sent it, with no time limit, and had no per-device limits | Fixed: the header is checked first. Bodies must arrive within two minutes, and each device has request, inventory and long-poll limits ([ADR-0015](../architecture/adr/0015-enrollment-and-meshagent-delivery.md)) |
| Low (hardening) | The internal certificate authority has no name constraints | Documented, not changed: constraints would cut agents off when the server's addresses change ([ADR-0016](../architecture/adr/0016-ip-address-access.md)). Install the authority only on administration computers |

### Remote access and integrations

| Severity | Finding | Outcome |
|---|---|---|
| Medium | Tunnel requests on MeshCentral's control channel were not tied to the session's grants: a grant for one device could bring another device's agent onto the relay, or change the session type | Fixed (`e62a0ea`, [ADR-0033](../architecture/adr/0033-relays-bound-to-grants.md)) |
| Medium | `devicefile.ashx` on the agent path downloaded a file from a device with only a user's MeshCentral cookie | Fixed (`e62a0ea`): the agent path serves only what MeshCentral's agent port serves, and browser downloads need a files grant |
| — | Found while fixing the above: device messages (process and service control, opening web pages) reached agents for any remote session type; MeshCentral reads `tcpport[]` as `tcpport`; batch uploads to devices were reachable | Fixed (`e62a0ea`) |
| Low | EasyPatch and audit forwarding connect wherever a Super Administrator points them, and their errors tell what is listening | Partly fixed: link-local and cloud metadata addresses are refused. Detailed connection errors are kept for troubleshooting; only Super Administrators see them |

Control actions other than device messages are still MeshCentral's to
check. They need rights EasyRMM never grants (ADR-0033).

### Tenant isolation (`b3bbe5a`)

The review found no way to read or change another organization's data.
It found three low findings:

| Severity | Finding | Outcome |
|---|---|---|
| Low | A report export's audit entry was filed under the organization named in the request | Fixed: filed under each organization whose rows the export holds |
| Low | Renaming an organization told its administrator whether another customer's name existed | Fixed: renames need a Super Administrator |
| Low | Inviting an address with an account elsewhere says that it exists | Documented in [Roles and permissions](rbac.md), with how to avoid it |

## What this review did not cover

* **Windows behaviour of the fixes.** The Windows checks (state folder,
  package-manager programs, cmd arguments) have tests that run on a Windows
  CI runner, and those workflows have not run yet. The gateway changes were
  checked with a Linux MeshAgent, not a Windows one.
* **MeshCentral and MeshAgent themselves**, beyond the behaviour EasyRMM
  depends on. Report their vulnerabilities to those projects
  ([SECURITY.md](../../SECURITY.md)).
* **EasyPatch's own server and agent.**
* No outside penetration test has been done.
