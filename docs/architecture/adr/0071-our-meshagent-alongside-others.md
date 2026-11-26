# ADR-0071: EasyRMM's MeshAgent beside other MeshAgents

* Status: Accepted (2026-11-26). Audit done against MeshAgent's source;
  the one code change is small; the real-Windows checks below are not yet
  run.
* Asked for by the owner (2026-11-26): "Our meshagent install on the client
  must be independent of all other meshagent installs. I have clients that
  have mesh agent for themselves, and then I would have ours in this
  project. They must be able to run next to each other, and our system must
  never mess with their mesh install, it can only touch ours."
* Related: [ADR-0015](0015-enrollment-and-meshagent-delivery.md) (delivery),
  [ADR-0050](0050-removing-a-device.md) (removal),
  [ADR-0069](0069-recovery-agent-logs-and-one-device-tree.md) (repair; its
  force-stop, #122, matches by exact image path),
  [ADR-0070](0070-defender-exclusions-at-install.md) (exclusions by full
  path). Amends ADR-0050 (see *The Diagnostic Agent*): MeshCentral's `uninstallagent`
  is no longer sent to Windows devices.

## Context

A client who runs MeshCentral for themselves has a stock MeshAgent on the
same computer. Two MeshAgents share a machine safely only if they share no
name, folder, file, key or process. MeshAgent derives most names from one
setting, `meshServiceName`, whose defaults are `Mesh Agent` on Windows and
`meshagent` elsewhere (`meshcore/agentcore.c:5317-5327`). Everything
below cites <https://github.com/Ylianst/MeshAgent> (`MeshAgent/...`) or
MeshCentral's `agents/meshcore.js` (`meshcore.js`), the script the server
sends every MeshAgent.

## What is separate, and why

| # | Thing | Stock MeshAgent | EasyRMM's | Collides? |
|---|---|---|---|---|
| 1 | Service name | `Mesh Agent` / `meshagent` (custom names exist) | `EasyRMMMeshAgent` (Windows), `easyrmm-meshagent.service` (Linux); display name `EasyRMM MeshAgent` (`agent/meshagent/meshagent.go:34`, `:150`) | No |
| 2 | Install folder | `%ProgramFiles%\Mesh Agent`, `/usr/local/mesh_services/meshagent` | `%ProgramFiles%\EasyRMM\MeshAgent`, `/usr/local/lib/easyrmm-agent/meshagent` (`agent/host/host.go:60-65`) | No |
| 3 | `.msh`, `.db`, `.log`, `.update*` | beside the executable (`MeshAgent_MakeAbsolutePath(exePath, ".msh")`, `agentcore.c:5134-5142`; `.update.exe`, `agentcore.c:2902`) | the same names inside our folder only | No: all paths derive from the executable's own folder |
| 4 | Registry, service state | `HKLM\SOFTWARE\Open Source\<meshServiceName>` (`agentcore.c:5503-5505`) | `...\Open Source\EasyRMMMeshAgent`, because we write `meshServiceName` into the `.msh` (`WithServiceName`, `meshagent.go:560`) | No |
| 5 | Windows certificate store | subject `CN=MeshNodeCertificate` for the name `Mesh Agent`, else `CN=<name>_NodeCertificate` (`agentcore.c:2277-2283`, `:2396-2402`) | `CN=EasyRMMMeshAgent_NodeCertificate` | No |
| 6 | Node identity | the key in `meshagent.db`, hashed (`SelfNodeCert`, `agentcore.c:2264`); `meshagent -nodeid` reads it | our folder's `.db`, read by our own binary (`NodeID`, `meshagent.go:526`) | No |
| 7 | Named pipes | the diagnostic IPC is `\\.\pipe\<nodeid>-DAIPC` on Windows, `<cwd>/DAIPC` on Linux (`modules/_agentStatus.js:4`); helper pipes are `taskRedirection-<random>` (`modules/child-container.js:81`, `win-dispatcher.js:159`) and `\\.\pipe\<pointer><counter>` (`microstack/ILibProcessPipe.c:514`) | unique per node and per process; our unit and child set the working directory to our folder | No |
| 8 | Local ports | UDP 16990 for LAN discovery, opened shared (`SO_REUSEADDR`/`SO_REUSEPORT`, `agentcore.c:5834`; `microstack/ILibAsyncUDPSocket.c:127-129`); no TCP listener | the same, shared by design | No: sharing is what the socket asks for |
| 9 | Log and temp | `meshagent.log` beside the executable (`modules/util-agentlog.js:183`); Linux `/var/tmp/<exe name>_ev` (`modules/message-box.js:704`), macOS-only `/tmp/meshagent-kvm-<uid>.sock` | our folder's `meshagent.log`; the `_ev` file is named by the executable, `meshagent`, and exists only while a message box is shown | Possible only for one message box at a time, on Linux; not touched by EasyRMM |
| 10 | Self-update (Windows) | `net stop "<meshServiceName>"`, then a script that kills processes whose lower-cased path equals the executable's, `copy .update.exe`, `net start "<meshServiceName>"` (`agentcore.c:2915-2918`, the base64 script decodes to an exact-path match) | the same, with our name and our path | No |
| 11 | Self-update (Linux, systemd) | `getService("meshagent").isMe()` is read-only `systemctl status`; false for our unit, so MeshAgent takes the generic path: replaces its own executable and `execv`s itself (`agentcore.c:6603-6620`) | the same; our unit's service name is *not* told to MeshAgent, deliberately (below) | No |
| 12 | `uninstallagent` from MeshCentral | acts only if `getService(MeshAgent.serviceName).isMe()` (`meshcore.js:2098-2106`, `:6108-6117`) | on Windows our name matches and it uninstalls ours; on Linux it does not match and is ignored (ADR-0050) | Only through the Diagnostic Agent, below |

### EasyRMM's own code, by exact identity

Every touch of a MeshAgent by the EasyRMM agent or server is by one of three
identities, never by a name pattern:

* **Service name**, exact: `EasyRMMMeshAgent` or `easyrmm-meshagent.service`
  (`Manager.service()`). Nothing enumerates services, and nothing matches
  `Mesh Agent`, `meshagent*` or `*MeshAgent*`.
* **Exact image path**, case-insensitive on Windows: `StopImage` terminates a
  process only when its whole image path equals `...\EasyRMM\MeshAgent\
  meshagent.exe` (`agent/host/force_windows.go:23-52`); `ForceStop` ends the
  process of our service and then the same image match. #122 holds: nothing
  matches by name, there is no `taskkill /IM`, no `Get-Process -Name`, no
  `Stop-Process -Name`, no wildcard. Another vendor's `meshagent.exe` is
  left alone (test below).
* **Folder**: `os.RemoveAll` of our folder, the temp files `.meshagent-*`
  inside it, and the `Remove` of the service and registry keys named
  below. The EasyRMM agent's uninstaller removes the empty parent folders
  with `os.Remove`, which fails on a folder that holds anything else
  (`agent/cmd/easyrmm-agent/main.go:714-720`).
* **Node id**, for the server: MeshCentral calls (`removedevices`,
  `changeDeviceMesh`, `uninstallagent`) name the node id our own binary
  printed (`server/internal/meshcentral/commands.go`). The server's
  recovery (`server/internal/recovery`) works on the device's recorded
  MeshAgent state, not on anything it finds on the computer.

The installers (`install.ps1`, `install.sh`) touch the agent's own folder and
service only; neither mentions MeshAgent beyond a comment.

## What collided, and how it is fixed

1. **A leftover registry key (fixed).** MeshAgent keeps
   `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\<meshServiceName>`
   correct, and creates it if absent (`meshcore.js:421-423`, `:442-444`:
   `WriteKey` of `EstimatedSize` and `DisplayVersion`). Removing EasyRMM
   deleted `Open Source\EasyRMMMeshAgent` only, so a `Uninstall\
   EasyRMMMeshAgent` key stayed behind. Not a collision with another agent,
   but a leftover of ours; `removeRegistry` now deletes both, by the exact
   name (`agent/meshagent/registry_windows.go`). Other agents' keys, such as
   `Mesh Agent`, or a name that merely starts with ours, are never touched
   (test below).
2. **Nothing else of ours was shared.** The rest of the table is separate by
   construction. In particular the Windows name was already set in the
   `.msh` (ADR-0020), so there is nothing to migrate: every existing install
   already carries `meshServiceName=EasyRMMMeshAgent`, and a repair or a new
   site group (ADR-0069) writes it again (`WithServiceName`). The change
   above takes effect at the next removal; nothing is rewritten or
   restarted on installed devices, and nothing of another MeshAgent is
   looked at.

### Decided in review: Linux keeps MeshAgent's default `meshServiceName`

Telling the Linux MeshAgent its unit's name (`easyrmm-meshagent`) was
built and then **reverted**. With the default name, `isMe()` is false for our
unit, so MeshAgent does two things only: its update replaces its own
executable and `execv`s itself, and MeshCentral's `uninstallagent` is
ignored (ADR-0050 relies on that). With our name set, `isMe()` becomes true,
the same `uninstallagent` would act, and it would run the Diagnostic Agent
cleanup below. The default is read-only (`systemctl status meshagent.service`)
and can never reach a client's `meshagent.service`: MeshAgent only restarts
`meshServiceName` by `service`/`initctl`/`launchctl` on init systems other
than systemd (`agentcore.c:6573-6596`), and `install.sh` requires systemd.

### Shared by MeshAgent's design, not changeable by us

* **`HKLM\SOFTWARE\Open Source\MeshAgent2\KeyStore`.** Both MeshAgents may
  write it (`meshcore/wincrypto.cpp:65-89`, called at `agentcore.c:2328`
  and `wincrypto.cpp:339`). Nothing in MeshAgent reads it: it is
  informational, and "last writer wins" changes no behaviour. EasyRMM never
  reads, writes or deletes it, and its removal does not.
* **UDP 16990** is shared with `SO_REUSEPORT` by design.

### The Diagnostic Agent (decided in review, 2026-11-26)

MeshCentral's Diagnostic Agent is one fixed name per computer: service,
scheduled task and folder are all `meshagentDiagnostic`, whatever the main
agent is called (`meshcore.js:694-800`). `uninstallagent` runs
`diagnosticAgent_uninstall()` first, always (`meshcore.js:2105`, `:6116`):
it stops and deletes that service, its task, its certificates and, on
Windows, its folder, which on a computer with a client's MeshAgent may be
the client's. The owner's rule is absolute, so:

1. **EasyRMM never sends `uninstallagent` to a Windows device.** Our
   MeshAgent is removed only by our own EasyRMM agent: service
   `EasyRMMMeshAgent`, folder `%ProgramFiles%\EasyRMM\MeshAgent`, and our
   registry keys. `removeRetired` skips the request when
   `retired_devices.platform = 'windows'` (`server/internal/remote/service.go`)
   and goes straight to removing the node. Linux is unchanged (the request
   is ignored there anyway).
2. **Agent offline at retire time.** The retire completes as before.
   Migration `90011_retired_mesh_left_behind.sql` adds `platform` and
   `mesh_may_remain` to `retired_devices`; the flag is set for a Windows
   device with a MeshAgent node whose agent was removed by force or reported
   a failure (`server/internal/agents/removal.go`). The copy-able script that
   removes only our service, folder and keys, by exact name and path, is in
   [removing-our-meshagent.md](../../operations/removing-our-meshagent.md).
   **Not built: showing the flag and the script in the console.** The data
   and the script exist; the page is a follow-up.
3. **MeshCentral configuration.** EasyRMM's `config.json`
   (`server/internal/meshcentral/config.go`) sets no option about the
   Diagnostic Agent, and MeshCentral has none: the agent is installed only
   by the console command `diagnostic install` typed on a device
   (`meshcore.js:6496-6525`); the server side only records links
   (`meshagent.js:1449-1501`). EasyRMM never sends that command, nothing in
   `server/` mentions it, `selfUpdate` is off and `lockAgentDownload` is on.
   So our MeshCentral installs nothing under a shared name on a client
   device. Anyone who types `diagnostic install` in a MeshCentral console
   for one of our devices would install a `meshagentDiagnostic` service that
   a client's own MeshAgent shares: operators must not.

## Rules

1. Every touch of a MeshAgent is by exact path, exact service name or exact
   node id. No process, service, file or registry match by pattern, prefix
   or program name. A new feature that stops, kills, deletes or lists
   MeshAgent must name one of the three and has a test with a bystander of
   a different name or folder.
2. Everything we create is under `EasyRMM` (folders, service, keys). The
   `.msh` always says `meshServiceName=EasyRMMMeshAgent` on Windows.
3. EasyRMM never reads or changes `HKLM\SOFTWARE\Open Source\*` except the
   key of its own name, and never runs MeshAgent's installer, which is the
   only code that manipulates other agents' services (`-fullinstall`
   replaces a previous install of the same name only).
4. Nothing here uses MeshCentral's `diagnostic` command, and
   `uninstallagent` is never sent to a Windows device.

## Tests

* Unit, all platforms: our names are never the stock ones and live under
  EasyRMM's folder (`TestOurNamesAreNeverTheStockOnes`); the Windows `.msh`
  carries our service name and replaces a stock one
  (`TestWindowsService`, existing).
* Windows unit (`GOOS=windows`, run on a runner): `TestForceStopAndRepairOnWindows`
  (#122) starts a same-named program in another folder and asserts it
  survives; `TestRemoveRegistryTouchesOnlyItsKey` asserts that our two keys
  go and a neighbouring key whose name starts with ours stays.
* Integration (real PostgreSQL): `TestDeviceRemoval` asserts a Windows device whose
  agent reported a failure is retired with `platform = 'windows'` and
  `mesh_may_remain`. The `removeRetired` skip is covered only by
  `TestRemovedDeviceNode`'s setup (needs the MeshCentral container); not run here.
* Both are built here with `GOOS=windows go vet`; the Windows-only tests were
  not run on Windows.

## Checks on real Windows (to run, with a stock agent beside ours)

On a test server, install a stock MeshAgent from a second MeshCentral (or
the stock `meshagent.exe -fullinstall`): service `Mesh Agent`, folder
`%ProgramFiles%\Mesh Agent`. Then:

1. Enroll the computer in EasyRMM. Expect two services, `Mesh Agent` and
   `EasyRMMMeshAgent`, both running; both nodes online in their own
   MeshCentral; two folders; `HKLM\SOFTWARE\Open Source` holds `Mesh Agent`
   and `EasyRMMMeshAgent` keys; `certlm.msc` Personal holds
   `MeshNodeCertificate` and `EasyRMMMeshAgent_NodeCertificate`.
2. Record the stock agent's service state, process id and start time, and the
   `Mesh Agent` registry key.
3. Run **Repair remote access** on the EasyRMM device, with the EasyRMM
   service's MeshAgent hung if possible. The stock agent's process id and
   start time must not change.
4. Update EasyRMM's MeshAgent through MeshCentral (or `Restart`): the stock
   service stays running with the same process id.
5. Remove the device with the EasyRMM agent online. Ours goes (service,
   folder, `Open Source\EasyRMMMeshAgent`, `Uninstall\EasyRMMMeshAgent`,
   certificate subject if left); the stock agent, its service, folder,
   registry key and node are intact and still online.
6. Repeat 1 and 5 with the stock agent installed under a custom name
   (`--meshServiceName="Client Agent"`).
7. Install the stock agent's Diagnostic Agent (`diagnostic install` in its
   own MeshCentral's console). Remove the device with **Remove anyway**
   while the EasyRMM agent is **stopped** and ours is still connected.
   Expected: no `uninstallagent` is sent (the server log has no "asked the
   MeshAgent of a removed device to uninstall itself"); the node is removed;
   the service `meshagentDiagnostic`, its scheduled task and folder are
   untouched; our MeshAgent is still installed. Then run the script in
   `docs/operations/removing-our-meshagent.md`: ours goes, the stock agent
   and its Diagnostic Agent stay.
8. Start the EasyRMM agent again after step 7 (within 90 days): it gets the
   uninstall instruction and removes itself and our MeshAgent; the stock
   agent is untouched.
