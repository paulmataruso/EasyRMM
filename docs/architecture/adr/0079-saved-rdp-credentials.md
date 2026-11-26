# ADR-0079: Saved RDP credentials per device

* Status: Proposed (2026-11-26). Design only; no code is changed by this ADR.
* Asked for by the owner on 2026-11-26: "meshcenter needs to be able to save
  RDP creds for each device, if a user wants". Everything marked *decided in
  review* is the writer's call; everything marked *owner decision* is open.
* Amends: [ADR-0026](0026-rdp-sessions.md) (its "typed for each session and
  never stored" rule becomes "never stored unless the person opts in, and
  then never by MeshCentral").
* Builds on: ADR-0022 and ADR-0033 (the gateway reads the RDP relay's first
  message), ADR-0055 section Step-up (5 minutes), ADR-0007 (audit),
  ADR-0072 (where pages go), `server/internal/secrets`,
  `server/internal/devscope`.

## Context

ADR-0026 turned MeshCentral's "Remember credentials" off, on purpose.
Technicians who open the same server all day now retype a domain, user and
password each time. The owner wants them saved per device, if the person
chooses.

### What MeshCentral can do (1.3.1, the version `deploy/docker-compose.yml:237` pins by digest)

Read from the tagged source, `1.3.1`:

* **It can save, per MeshCentral user and device.** When the browser's first
  RDP message has `options.savepass == true`, `apprelays.js:908` calls
  `saveRdpCredentials()` (`apprelays.js:945-964`), which writes
  `node.rdp[<userid>] = {d, u, p}` into MeshCentral's own database. It
  returns at once when `domain.allowsavingdevicecredentials == false`
  (`apprelays.js:946`), which is what EasyRMM sets
  (`server/internal/meshcentral/config.go:226`).
* **The password is stored in clear.** `d`, `u` and `p` are plain strings in
  the node document. `CloneSafeNode` hides it from browsers (only the user
  ids survive, `webserver.js:10195`), but anyone with the MeshCentral
  database has it, and it is not sealed by EasyRMM's key.
* **It can inject server-side.** When the first message has
  `options.useServerCreds == true`, the relay replaces `domain`, `username`
  and `password` with the stored ones before it opens the TCP tunnel
  (`apprelays.js:1029-1045`), so a browser need not hold them. The web UI
  learns only that credentials exist (`serverCredentials`,
  `webserver.js:2417-2418`, `2475-2476`).
* **It has no per-user permission, audit or step-up for this.** It is keyed
  by MeshCentral user id, never shown a second factor, and logs only a
  "Changed RDP credentials" node event. It cannot share one credential across
  an organization.

So MeshCentral's own feature is not enough: plaintext storage, no audit and
no step-up. Turning `allowSavingDeviceCredentials` on would also let any
browser that reaches the relay set `savepass` itself.

### What EasyRMM has

* `secrets.Sealer` (`server/internal/secrets/seal.go`): AES-256-GCM, a key
  ring that supports rotation, associated data that binds a value to its
  row. It already seals TOTP seeds, integration credentials and the
  MeshCentral login key.
* The keystore the owner asked for (feature-plan-msp.md) is **not built**.
* The gateway (`server/internal/remote/relayguard.go`, about line 318)
  already reads the browser's side of `mstscrelay.ashx` message by message
  and requires the first one to be `infos` with `ip` a node ID the session
  holds an RDP grant for.
* Step-up exists as a definition (ADR-0055); `stepped_up_at` is on the
  session once 5b2 is built.

## Decision

### In short

* Saved credentials are **EasyRMM's, not MeshCentral's**. MeshCentral's
  saving stays off and is made unreachable (below).
* They are **sealed with `secrets.Sealer`**, **never returned by any API**,
  and **injected by the gateway** into the RDP relay's first message, so the
  browser never holds them.
* Saving and the first use in a session need **step-up**. Every use is
  **audited**.

### 1. Opt-in and scope

* **Personal (default).** A person with `device.remote_desktop` on a device
  may save one credential for themselves on it. Nothing is saved unless they
  tick "Save for this device" in the RDP dialog or add one on the device's
  Remote menu. Only that person's sessions use it.
* **Shared (organization), optional.** A credential saved at device level
  that every person with the new permission `device.rdp_credentials.use`
  can start sessions with, without seeing it. Creating, replacing or
  deleting one needs `device.rdp_credentials.manage_shared` and step-up.
  Shared is **off until an organization administrator turns it on** in the
  organization's settings (decided in review: a shared local-admin password
  is how one stolen session becomes many devices).
* One personal and at most one shared credential per device and person.
  When both exist the personal one wins; the dialog shows which will be used
  (its label and username, never the password).
* **Owner decision:** whether the shared level ships in the first release or
  waits. The design below supports both; slice 4 is the shared level.

### 2. Storage

* A new table `device_rdp_credentials` (migration `9xxxx_rdp_credentials`
  when built; goose up and down): `id`, `device_id`, `org_id`,
  `scope` (`user` or `device`), `user_id` (null for `device`),
  `label`, `domain`, `username`, `sealed_password` (the Sealer's wire
  format), `created_by`, `created_at`, `updated_at`, `last_used_at`,
  `rotated_at`. Unique on `(device_id, scope, user_id)`.
* The **username and domain are stored in clear** (they are needed for the
  label and the audit row and are not secrets); **only the password is
  sealed**. Associated data is
  `rdp-credential:<id>:<device_id>:<scope>:<user_id>`, so a sealed value
  copied to another row, device or person fails to open (`ErrDecrypt`).
* **Today: `secrets.Sealer`.** Decided in review: it is built, rotatable
  and reviewed, and the keystore's design is for recovery keys the server
  must not use unattended, which is a different job.
* **Migration to the keystore, if the owner builds it for this:** the value
  is re-sealed in a one-off job that opens with the Sealer and stores under
  the keystore's key, behind a `sealed_format` column (`sealer-v1`,
  `keystore-v1`) so both can be read during the move and the job can be
  resumed. Nothing in the API or the audit changes.
* Key rotation uses the Sealer's existing ring; a re-seal job (as ADR-0057
  does for the job key) must include this table.

### 3. Never shown back

* No endpoint returns a password, to anyone, including administrators and
  the person who saved it. The list endpoint returns `id`, `scope`,
  `label`, `domain`, `username`, `created_at`, `last_used_at`, nothing else.
* Replacing is the only way to change one ("Replace password"). There is no
  "reveal", no export, and the credential is excluded from backups' readable
  forms (it is in the database dump sealed, like every Sealer value).
* Logs and audit rows never carry it. A test (below) greps the whole audit
  and log output of a session for the password.

### 4. How the credential reaches the RDP session

MeshCentral can inject server-side, but only from its own plaintext store
(`useServerCreds`), which this ADR rejects. EasyRMM therefore injects one
step earlier, in the gateway, which already parses this message:

1. The browser opens `mstscrelay.ashx` and sends `["infos", {..., "domain":
   "", "username": "", "password": "", "options": {"useSavedCredential":
   "<id>"}}]` (the console's dialog sends an id, never a password).
2. The gateway checks, as it does now, that `ip` is a node ID the session
   holds an RDP grant for. It then checks that the credential `<id>` is
   the person's own, or a shared one on this device, that the person holds
   `device.rdp_credentials.use`, that `devscope.Allowed(orgID)` is true,
   and that the session is stepped up (section 5).
3. It opens the sealed password, **rewrites the first frame**, setting
   `domain`, `username` and `password`, and **removes** `useSavedCredential`.
   It always **forces `options.savepass` false and `useServerCreds` false**
   on every first frame, saved credential or not, so MeshCentral can never
   store or load its own copy even if the setting changes.
4. The gateway sends the frame to MeshCentral over the host-local
   connection it already uses, and zeroes its copy. MeshCentral holds the
   password in memory for the session, as it does for a typed one.

The browser holds only the credential's id. The resize reconnect
(ADR-0026) sends the same id and the gateway injects again, so the page
does not keep the password in memory at all (an improvement over typed
credentials, which the page keeps for the reconnect).

* **Residual exposure, stated plainly:** the password exists in clear in the
  gateway's and MeshCentral's process memory during the session, and on the
  loopback hop between them. That is the same as a typed password today.
  **MeshCentral cannot be made to take a credential it does not hold
  without storing it**, so injecting through the gateway is the safest
  option available; the alternative (writing `node.rdp` into MeshCentral)
  would store it unsealed in a second database.
* The gateway today forwards frames; rewriting one frame is a change to the
  guard, and slice 1 must prove it does not break the frame size or the
  message order the relay expects (a Windows RDP session in the tests).

### 5. Step-up

* **To save, replace or delete:** step-up (ADR-0055, 5 minutes).
* **On first use in a session:** the first redeem of a saved credential in a
  console session needs a step-up not older than 5 minutes; later uses in
  the same session within 5 minutes do not ask again, so a technician
  opening three servers is asked once. After 5 minutes the next use asks
  again (decided in review: the 5 minutes of ADR-0055 are the one number;
  no longer window).
* A person with no second factor cannot save or use one and is told to set
  one up. A recovery code or a password alone never counts.
* Failures count as ADR-0055 says (`auth.step_up`).

### 6. Audit (ADR-0007)

Rows, all with actor, device, organization, credential id, scope, label and
username (never the password):

* `rdp_credential.created`, `.replaced`, `.deleted`, `.shared_enabled`,
  `.shared_disabled`.
* `rdp_credential.used` on every session start that injected one, with the
  grant id, the session id and the client address. A refused use
  (`.use_denied`, with the reason: no permission, step-up, devscope, wrong
  device) is audited too.
* `rdp_credential.purged` for a deletion by cascade (below).

### 7. Edge cases

* **Device removal:** deleting or retiring a device deletes its credentials
  in the same transaction (`ON DELETE CASCADE` plus an audit row per
  credential). Moving a device to another organization or site deletes
  **shared** credentials (the new owner of the device did not agree to
  them) and keeps personal ones.
* **User removal or deactivation:** the person's personal credentials are
  deleted with the user. A deactivated user keeps none usable: the
  gateway refuses a credential whose user is not active.
* **Permission removed:** the gateway checks the permissions on every use,
  so revoking `device.remote_desktop` or `device.rdp_credentials.use`
  stops use at once; the rows stay (and a person's role can return) except
  that a shared credential used by nobody for 180 days is flagged in the
  list (not deleted).
* **Rotation:** "Replace password" seals a new value and sets `rotated_at`.
  When a Windows computer's password changes, the next use fails to log
  in; the console says "The saved credential was refused. Replace it."
  and offers the replace dialog. Nothing retries, so no lockout loop.
* **Sealer key rotation:** the re-seal job covers this table.
* **Organization scope (`devscope`):** saving, listing and use all check
  `devscope.Allowed(orgID)`; when it is false the credential is neither
  used nor offered, and the gateway refuses with an audited
  `.use_denied`. This ADR predates the guard's landing and says so.
* **Linux devices:** not offered (RDP to xrdp does not work, ADR-0026).
* **Wrong device:** the id is bound to the device, both by the row and by
  the associated data; using it with another device's node ID is refused.
* **Windows Credential Guard, NLA and domain controllers:** the saved
  credential is the same login a typed one is; nothing special.

### 8. Permissions (`server/internal/rbac/rbac.go`)

Added to the hotspot, additively:

| Permission | Meaning | Default roles |
| --- | --- | --- |
| `device.rdp_credentials.save` | save and delete one's own credential | those that hold `device.remote_desktop` |
| `device.rdp_credentials.use` | start sessions with a shared credential | technicians and above |
| `device.rdp_credentials.manage_shared` | create, replace, delete shared credentials, with step-up | administrators |

Personal saving needs `device.remote_desktop` as well as
`.save`; nobody can use a credential for a device they cannot reach.

### 9. Where it shows (ADR-0072)

* In the RDP dialog on `/devices/:id/remote/rdp`: a "Saved credential"
  choice listing label and username, a "Save for this device" tick on the
  typed form, "Replace" and "Delete".
* In the device's Remote menu (ADR-0072 lists "Saved RDP credentials" there)
  for managing them, with the shared ones marked "Shared by your
  organization".
* The organization's remote-access settings carry the one switch that
  enables the shared level.
* Nothing on the dashboard.

### 10. Threat model

| Threat | Answer |
| --- | --- |
| Database dump or backup stolen | Passwords are sealed; the master key is not in the database. A stolen key is the existing worst case for every Sealer value. |
| A stolen console session | Saving, replacing and the first use need a fresh second factor; the attacker cannot read a password back. They could use a credential after stealing a fresh step-up, for 5 minutes, which is audited. |
| A malicious or compromised browser | It never holds the password; the id is useless on another device or user. |
| MeshCentral compromised or a rogue MeshCentral user | MeshCentral stores nothing (saving forced off at the config and in the gateway). It sees the password in memory during a session, as today. |
| A technician abuses a shared credential | Allowed by design; every use is audited, the permission is separate, shared is off by default. |
| Replay of an old `infos` frame | A grant is one-time and the gateway accepts one `infos`; the id is checked every time. |
| Credential used after a person leaves | Gateway checks the user is active and still holds the permissions on every use. |
| Credential reuse across customers | Shared credentials are per device, and deleted on a move between organizations. |
| Our own logs | Tests assert the password never appears in audit rows, application logs or API bodies. |

Out of scope: a compromised gateway process, which holds the Sealer key
anyway.

## Tests

* **Unit:** seal and open with associated data bound to row, device, scope
  and user (a value copied elsewhere fails); the frame rewrite (forced
  `savepass` and `useServerCreds` false, id removed, a typed credential
  passes through unchanged); API bodies never contain the password.
* **Integration, real PostgreSQL:** the permission matrix; deletion by
  device, user and organization move; step-up required to save and on the
  first use per session and not within 5 minutes; every audit row; devscope
  refusal; re-seal after Sealer key rotation.
* **Gateway (`relayguard_test.go`):** a saved id of another user or device
  is refused; a second `infos` is refused; a message after the first passes.
* **A real RDP session to a Windows test server, by hand and in the
  `vm` suite:** save a credential, connect with only the id, confirm the
  Windows logon event names the saved account, resize and see the reconnect
  work, replace the password, confirm a wrong password gives the "refused"
  message and no loop, delete and confirm the session cannot start. The
  ADR-0026 note stands until this has run: a complete session against
  Windows has not yet been run.
* **Secret scan:** the session's audit rows, server logs and MeshCentral's
  database are searched for the test password after the run; MeshCentral's
  must show no `rdp` field on the node.
* **Web:** vitest for the dialog states; an e2e spec for the save and use
  flow with a stub step-up.

## Slices

1. **Storage and gateway injection, personal only:** migration, sealed
   store, the rewrite in the guard, forced `savepass` false, audit rows, and
   the real Windows session. No UI beyond an API.
2. **Step-up on save and first use** (needs 5b2's `stepped_up_at`).
3. **UI:** the RDP dialog and the Remote menu (ADR-0072).
4. **Shared level:** the organization switch, the permissions, the move
   rule.
5. **Cleanup and rotation:** cascades, the re-seal job, the keystore
   migration if built.

## Consequences

* The owner's wish is met without MeshCentral keeping a password in clear.
* The gateway grows from admitting a message to rewriting one; that is the
  design's main risk and slice 1 tests it first.
* A saved credential is a standing secret in the database; the opt-in, the
  step-up and the audit are what pay for that.
* MeshCentral's own "Remember credentials" stays off and cannot be turned on
  by a browser.

## Owner decisions

1. Does the shared (organization) level ship in the first release, or
   later? The writer's call is later (slice 4).
2. Should saved credentials move to the keystore once it exists, or stay
   with the Sealer? The writer's call is to stay.
