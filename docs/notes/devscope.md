# Notes: dev-scope guard (`ws/devscope`)

## Changelog lines

- Added the dev scope, a development-only control: `EASYRMM_DEV_SCOPE_ORG` limits test agent builds and automatic repairs to one organization, and `EASYRMM_AGENT_STABLE_DIR` holds the builds every other organization keeps. Unset, nothing changes.
- The agent signs its update download, so the server can tell whose build to hand out.
- `install.sh` and `install.ps1` send the deployment token with their downloads.

## Implementation-status rows

- Dev scope (`server/internal/devscope`): built, integration-tested against PostgreSQL; not run on a deployed host.

## Privacy

Nothing new is stored. The installers send the deployment token in a header
(`X-Easyrmm-Token`) with their downloads; the server already receives it at
enrollment.

## Automatic server-started paths found

| Path | Gated |
|---|---|
| Agent update offers in heartbeat answers (`agents.planUpdate`) | Yes: the organization's build set |
| Manual update request, "Update all" (`RequestUpdate`, `RequestAll`) | Yes: the stable build outside the scope (an administrator can still ask) |
| `install.sh` / `install.ps1` / `download/{file}` / `SHA256SUMS` | Yes: by token, signature or none |
| Console agent downloads (`enrollapi.downloads`) | Yes: stable while the scope is set |
| Device update status (`devices.updateStatus`) and the fleet counts | Yes: per organization |
| Recovery `publishes()` / `SetBuilds` | Yes: per organization |
| Signed Windows builds (`LoadSignedBuilds`) | Yes: builds signed from a release under test never join the stable set |
| Auto-repair (`recovery.Evaluate`) | Yes |
| Repair steps of a repair already running (`Advance`, `Dispatch`) | No: they continue a repair an administrator, or an earlier in-scope one, started |
| Restart after install (`easypatch.SweepRestarts`) | No: an administrator asked for it with the install |
| Alert policies and their emails (`monitoring.Evaluate`) | No: existing behaviour; new alert kinds must check `devscope.Allowed` |
| MeshAgent install and settings at enrollment and heartbeat | No: existing behaviour, serves the MeshCentral binary unchanged |
| Retention, nonce and job sweeps | No: bookkeeping, nothing reaches a device |

## EasyPatch and MeshCentral

- EasyPatch agent versions come from the patching engine's agent packages,
  not from EasyRMM. `easypatch.RepairOffer` offers the packages of the
  version the device already has, and installs use what the engine hosts. An
  unchanged engine image is therefore enough to keep every organization on
  its current EasyPatch agent. A dev-only override for new packages is not
  built.
- MeshCentral updates MeshAgents itself when its own agent binaries change;
  EasyRMM fetches the binary from it and signs it for the agent. An unchanged
  MeshCentral image is enough. Not verified: whether a changed MeshCentral
  configuration, which the server writes at startup, can trigger an update.
