# Dev scope (development only)

The dev scope is a control for development builds. It is not a feature for
production, and it is off unless `EASYRMM_DEV_SCOPE_ORG` is set.

## What it does

With `EASYRMM_DEV_SCOPE_ORG` set to an organization's id, test builds reach
that organization only. Every other organization is held at the stable
builds:

- A device outside the scope is offered the stable agent build, with the
  stable build's hash, so nothing updates. Manual update requests and
  "Update all" ask for the stable build too.
- `install.sh` and `install.ps1` send the deployment token with their
  downloads. A token inside the scope downloads the server's builds; a token
  outside it, an unknown token or none gets the stable builds.
- The console's Add devices downloads are tied to no organization, so while
  the scope is set they are the stable builds.
- Recovery accepts the hashes of the build set that applies to the device's
  organization.
- Signed Windows builds made from a release under test are never served
  outside the scope.
- Automatic repairs (`organizations.auto_repair`) start only for devices in
  the scope. An administrator's repair still runs anywhere.

Every new automatic behaviour asks `devscope.Allowed(organization)` first.

## Settings

| Variable | Meaning |
|---|---|
| `EASYRMM_DEV_SCOPE_ORG` | The organization's UUID. Unset: no scope, and the server behaves exactly as without this feature. |
| `EASYRMM_AGENT_STABLE_DIR` | The stable agent builds, laid out like `EASYRMM_AGENT_DIR`. Default `/usr/share/easyrmm/agents-stable`. Read only while a scope is set. |

With a scope set and the stable directory missing or empty, the server
refuses to start. The scope is logged once at startup.

## What it does not cover

- An agent signs its update download from this release on. An agent of an
  earlier release does not, so a device inside the scope running one gets the
  stable build from an update offer, which fails its hash check and leaves the
  device unchanged. Reinstall it with `install.sh` or `install.ps1` and a
  token inside the scope.
- The patching engine and MeshCentral are separate images and are not
  changed by the scope. Keep their images unchanged while it is set.

## Removing it

Unset `EASYRMM_DEV_SCOPE_ORG` and restart. Every organization is then offered
the server's builds.
