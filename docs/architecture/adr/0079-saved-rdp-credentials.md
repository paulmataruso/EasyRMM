# ADR-0079: Saved RDP credentials per device

* Status: Accepted (2026-11-26, after an independent review). Design only; no code is changed by this ADR.
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
* Decided in review: the shared level ships later (slice 4).

### 2. Storage

* A new table `device_rdp_credentials` (migration `9xxxx_rdp_credentials`
  when built; goose up and down): `id`, `device_id`, `organization_id`,
  `scope` (`user` or `device`), `user_id` (null for `device`),
  `label`, `domain`, `username`, `sealed_password` (the Sealer's wire
  format), `created_by`, `created_at`, `updated_at`, `last_used_at`,
  `rotated_at`. Unique on `(device_id, scope, user_id)`.
* The **username and domain are stored in clear** (they are needed for the
  label and the audit row and are not secrets); **only the password is
  sealed**. Associated data is
  `rdp-credential:<id>:<device_id>:<scope>:<user_id>`, where `<user_id>` is the person's UUID for `user` scope and the literal `-` for `device` scope (the column is NULL there), so a sealed value
  copied to another row, device or person fails to open (`ErrDecrypt`).
* **Row-level security** on `organization_id`, as the other per-organization
  tables (`ENABLE` and `FORCE ROW LEVEL SECURITY`, a policy on
  `easyrmm_scope_all() OR organization_id = ANY (easyrmm_scope_ids('easyrmm.scope_orgs'))`
  with a matching `WITH CHECK`, as `devices_tenant` in
  `00002_remote_access.sql`); a test proves another organization's scope
  sees no row.
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
   connection it already uses. MeshCentral holds the password in memory for
   the session, as it does for a typed one.

The browser holds only the credential's id. The resize reconnect
(ADR-0026) sends the same id and the gateway injects again, so the page
does not keep the password in memory at all (an improvement over typed
credentials, which the page keeps for the reconnect).

* **Residual exposure, stated plainly:** the password exists in clear in the
  gateway's and MeshCentral's process memory during the session, and on the
  loopback hop between them. Go cannot zero strings or the buffers JSON
  decoding makes, and `g.payload` and `g.held` keep the browser's message
  until the garbage collector frees them, so **this ADR does not claim the
  gateway erases the password**. It minimises the exposure: the opened
  password and the rewritten frame are built in byte slices the gateway
  owns, with no conversion to a string, and those slices are zeroed after
  the frame is written; the message the browser sent holds only an id and
  empty fields. A heap dump of the gateway during a session can still show
  the password. This is the same as a typed password today.
  **MeshCentral cannot be made to take a credential it does not hold
  without storing it**, so injecting through the gateway is the safest
  option available; the alternative (writing `node.rdp` into MeshCentral)
  would store it unsealed in a second database.

**The rewrite is new plumbing, not a tweak.** Today `wsGuard.next`
(`relayguard.go`, about lines 225-320) forwards the browser's original
masked bytes (`g.held`) and the check is `func([]byte) error`: it can only
admit, drop or pass the rest. To inject, this ADR adds:

* **A transform hook.** A second kind of check, `func(msg []byte) ([]byte,
  error)`, for the first RDP message only. When it returns replacement
  bytes, `next` forwards those instead of `g.held`; every other check is
  unchanged.
* **A rebuilt frame.** The replacement is sent as one new text frame
  (FIN set, opcode 1, no reserved bits): a fresh header with the new
  payload length in the 7-bit, 16-bit (126) or 64-bit (127) form that
  length needs, **a fresh random mask key** (never the browser's), and the
  payload masked with it. A long password or domain can push the message
  across 125 or 65535 bytes, so the form is chosen from the new length.
* **Fragmented and continuation frames.** `next` already joins fragments
  into `g.payload` before the check runs (it refuses a continuation outside
  a message); the transform sees the whole joined message, and its
  replacement is one frame regardless of how many the browser sent. The
  original fragments are not forwarded. The size cap
  (`maxControlMessage`) applies to the replacement too.
* **Where the identity comes from.** `rdpCheck` is built per connection
  with the session and device from the relay's authenticated request
  context (the redeemed grant). The same context supplies the user id, the
  organization id and the session's `stepped_up_at`; none of them is read
  from the message. The transform receives them as closure values.
* **New code with its own tests** (see Tests): none of this exists today.

**Bypass.** The browser must reach MeshCentral's RDP relay only through
the gateway. Slice 1 asserts it with a test: a request to
`mstscrelay.ashx` that does not pass the gateway (straight at
MeshCentral's port, or with the edge's grant cookie missing) is refused,
and a first message that skips the transform is never forwarded.

### 5. Step-up

* **Prerequisite:** step-up is being built in `ws/f5-stepup` (ADR-0055).
  No slice that saves a credential or injects one ships before it has
  merged; the slices are ordered so (below).
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
  credential). One rule for a move between organizations
  (decided in review): **all** the device's credentials, shared and
  personal, are deleted in the move's transaction, each with an audit row,
  and `organization_id` is never rewritten. A move between sites of the
  same organization keeps them. (Simpler and safer than checking each
  person's new access; people save again.)
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

Three permissions are added, additively. One table says what each action
needs; the gateway and the API check exactly this, on every call:

| Action | Needs |
| --- | --- |
| Save, replace or delete one's own credential | `device.rdp_credentials.save` and `device.remote_desktop` |
| Use one's own credential | `device.remote_desktop` and being its owner |
| Use a shared credential | `device.remote_desktop` and `device.rdp_credentials.use` |
| Create, replace or delete a shared credential | `device.rdp_credentials.manage_shared` and `device.remote_desktop`, with step-up |
| Turn the shared level on or off | organization administrator, with step-up |

Default roles: `.save` goes to every role that holds
`device.remote_desktop`; `.use` to technicians and above;
`.manage_shared` to administrators.

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
* **Frame rewrite (new tests in `relayguard_test.go`):** a long password
  that moves the message across 125 and 65535 bytes, so each length form
  (7-bit, 126, 127) is built and read back by a standard WebSocket reader;
  a fresh mask key on every rewrite; an `infos` frame the browser sent in
  several fragments; a replacement over the size cap refused; and a fuzz
  test that feeds random frame splits, mask keys and JSON bodies and
  checks that the output is a valid WebSocket stream, that the stream
  after the first message is byte-identical to the input, and that a
  password never appears outside the rewritten frame.
* **Bypass:** the direct-to-MeshCentral request is refused (slice 1).
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

Order (step-up first, so nothing saves or injects without it):

0. **Prerequisite, not ours:** step-up (ADR-0055, `ws/f5-stepup`) merged.
1. **Storage, API and audit, personal only, no injection:** migration with
   row-level security, the sealed store, the permissions, save, replace and
   delete behind step-up, the audit rows, the cascades.
2. **Gateway injection:** the transform hook, the rebuilt frame, forced
   `savepass` false, first-use step-up, the bypass test, the frame tests and
   fuzz, and the real Windows session.
3. **UI:** the RDP dialog and the Remote menu (ADR-0072).
4. **Shared level:** the organization switch, `.use` and `.manage_shared`.
5. **Rotation:** the re-seal job, and the keystore migration if built.

## Consequences

* The owner's wish is met without MeshCentral keeping a password in clear.
* The gateway grows from admitting a message to rewriting one; that is the
  design's main risk and slice 1 tests it first.
* A saved credential is a standing secret in the database; the opt-in, the
  step-up and the audit are what pay for that.
* MeshCentral's own "Remember credentials" stays off and cannot be turned on
  by a browser.

## Amendments

Amended 2026-11-26 (decided in review), while building slices 1 to 3 of the
brief's order (gateway hook, storage, API, UI). The personal level only; the
shared level and re-sealing (slices 4 and 5 above) are not built.

* **Row-level security is by organization, as written, but the service reads and
  writes under the system scope after its own checks.** A site-scoped
  technician's database scope names sites, not the organization, so the
  organization policy would hide their own credential. The service checks the
  person (`user_id` is the caller's), the permissions at the device's site and
  `devscope` itself; the policy still bounds every other path, and a test proves
  another organization's scope sees nothing and cannot write a row.
* **Only `device.rdp_credentials.save` is added** (technicians and above, every
  role holding `device.remote_desktop`). `.use` and `.manage_shared` come with
  the shared level, since nothing checks them yet. Using one's own credential
  needs `device.remote_desktop` and being its owner, as the table says.
* **"Save for this device" is a form in the console, not a tick in
  MeshCentral's dialog.** The credentials dialog belongs to MeshCentral's page,
  in an iframe on another origin, which cannot call the console's API or ask for
  step-up. The remote desktop page therefore asks first: a saved credential, or
  "type credentials in the session" (MeshCentral's own dialog, as before), and a
  "Saved credential" button that saves, replaces or deletes one. The page
  starts a session with `savedCredential: true` (the API asks for step-up
  then, so the person is asked before the session, not in the middle of it)
  and puts `rdpcred=<id>` on the session's address; the session view's script
  (`viewer.js`) skips the dialog and writes only that id into the connection
  request, on every connection, including the reconnect after a resize.
* **First use needs a step-up not older than 5 minutes, read by the gateway from
  the session's `stepped_up_at`.** That is the same as the "once per 5 minutes"
  rule above, with no extra state.
* **A refused credential closes the session; it does not say so.** The gateway
  cannot write to the browser's side of a MeshCentral page, so "The saved
  credential was refused. Replace it." is not shown. The audit row
  (`rdp_credential.use_denied`, with the reason) and the "Saved credential" button
  are the way back.
* **Device removal and moves audit each credential through `PurgeDevice`**,
  called in the removal paths of `agents/removal.go` and in a move between
  organizations. The two other places that delete a device (merging a duplicate
  at heartbeat, MeshCentral-only devices at sync) rely on the foreign key's
  cascade and write no per-credential row.
* **MeshCentral's RDP client does not reveal the account before CredSSP**, so a
  stand-in RDP port cannot show that the saved account reached the device. The
  gateway tests check the rewritten message with a standard WebSocket reader;
  the end-to-end test through the real MeshCentral checks that it accepts the
  rebuilt frame, saves nothing, and is not reachable around the gateway. The
  real session against Windows is still the manual step above.

## Owner decisions

None. Decided in review: the shared level comes later (slice 4), and
credentials stay with `secrets.Sealer` now, moving to the keystore only if
it is built for this.
