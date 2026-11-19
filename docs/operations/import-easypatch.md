# Importing a standalone EasyPatch

EasyRMM patches with EasyPatch's engine, which runs in every EasyRMM
deployment. A standalone EasyPatch server, release 1.4 to 1.10, can be
moved into it. Its devices keep their agents and their history, and
nothing is reinstalled on them. The design is in
[ADR-0045](../architecture/adr/0045-importing-a-standalone-easypatch.md).

## What comes across

| From the EasyPatch server | In EasyRMM |
|---|---|
| Organizations and sites | EasyRMM organizations and sites, linked to the engine's (see [Names](#names)) |
| Endpoints, their agents and enrollment | The engine's. The agents keep connecting to the old server's name, which EasyRMM then answers |
| Policies, maintenance windows, deferrals, holds, tags | The engine's, unchanged |
| Update history, jobs, schedules, monthly reports, compliance | The engine's, unchanged |
| Alert rules and notification channels (webhooks, email recipients) | The engine's, shown under **Settings → Patching** |
| Data Protection keys | Added to the engine's key ring, so webhook addresses and other stored secrets still decrypt |
| User accounts, API tokens, sessions, security keys, single sign-on providers | **Not imported.** The accounts are kept but disabled; people sign in to EasyRMM with EasyRMM's accounts and roles |
| Mail server settings | **Replaced** by EasyRMM's own (**Settings → Email**) |
| Agent packages, winget cache | **Not needed.** The engine's image carries the agent packages; the worker downloads winget again |
| Archived organizations and sites | Stay archived in the engine; not created in EasyRMM |

## Before you start

- **EasyRMM is installed** with `deploy/scripts/setup.sh` and runs. If this
  deployment's engine already patches devices, an import is no longer
  possible: it replaces the engine's data. The script checks this and
  refuses.
- **You control the old server's DNS name**, the `EASYPATCH_DOMAIN` its
  agents connect to (for example `patch.example.com`). After the import it
  points at the EasyRMM server.
- **Agents connect on port 443.** The import keeps agents working on the
  old name at port 443, where EasyRMM's edge listens. Agents set up with
  another port (an `EASYPATCH_PUBLIC_URL` such as
  `https://patch.example.com:8443`) cannot follow and must be enrolled
  again.
- **The certificate covers the old name.** How depends on EasyRMM's TLS
  mode:
  - `acme`: EasyRMM requests a certificate for the old name on the first
    connection once DNS points at it. Nothing to do.
  - `manual`: add the old name to the certificate in
    `EASYRMM_TLS_CERT_FILE` first. The script checks it and refuses
    otherwise.
  - `offload`: have the proxy in front of EasyRMM send the old name to
    EasyRMM, with a certificate for it.
  - IP-address installs (EasyRMM's own certificate authority): agents
    trust only the CA they were installed with. Agents of a lab server that
    used Caddy's internal CA cannot follow and must be enrolled again.

## Import

1. **Stop the old server for good, and back it up.** On the EasyPatch
   server, from its install folder:

   ```bash
   scripts/backup.sh /root/easypatch-backup
   docker compose down
   ```

   Stopping it first matters: agents that still reach it would report
   there and not to EasyRMM. The backup folder holds `easypatch.dump`
   (the database), `dpkeys.tar` (the Data Protection key ring),
   `agent-packages.tar` (not used) and `SHA256SUMS`. It holds secrets:
   copy it to the EasyRMM server over SSH (`scp -r`), never by email or a
   shared folder.

2. **Run the import** on the EasyRMM server, as root, from `deploy/`:

   ```bash
   sudo ./scripts/import-easypatch.sh --backup /root/easypatch-backup --hostname patch.example.com
   ```

   Give `--hostname` once for each name the agents use. The script asks
   you to type `import` before it changes anything (`--yes` skips the
   question). EasyRMM stops for a minute or two. At the end it prints what
   it made: each organization and site, and whether it is new in EasyRMM
   or joined one of the same name.

3. **Point the old name at EasyRMM.** Change the DNS record of
   `patch.example.com` to EasyRMM's address. Agents reconnect within
   minutes of the change reaching them; until then they keep retrying,
   and patch nothing. Someone who opens the old console's address in a
   browser lands on EasyRMM's **Patching** page.

4. **Install EasyRMM's agent** on the imported devices, in the
   organization the import made for them. As each EasyRMM agent reports
   the EasyPatch agent beside it, **Patching** links the two, and the
   device's **Patches** tab shows its history. An EasyRMM agent in
   another organization than its EasyPatch agent is not linked, and
   **Settings → EasyPatch**, under **Devices not linked**, says why. Its
   EasyPatch agent keeps patching in its own organization.

5. **Retire the old server** once its agents have all come across: in
   **Patching**, every imported device shows a recent check-in. Keep the
   backup until then.

## What the script does

1. Checks the backup: its checksums, that `easypatch.dump` is a
   PostgreSQL dump, and that `dpkeys.tar` holds Data Protection key files
   and nothing else. It checks that EasyRMM accepts the names (the
   server's settings, with the names added), and that the engine has no
   agents yet.
2. Restores the dump into a new database, `easypatch_import`.
3. Prepares it with the engine's `prepare-import` command: it refuses a
   database from a newer EasyPatch than the engine, or one that is not
   EasyPatch's; brings it to the engine's schema; disables EasyPatch's
   accounts (inactive, no usable password, no second factor) and deletes
   their sessions, API tokens, security keys and single sign-on
   settings. Two accounts whose addresses differ only in case (releases
   before 1.10 allowed it) no longer block the 1.10 schema: the later one
   gets an address ending in `@duplicate.invalid`. Until this step, nothing
   in the deployment has changed; when it refuses, the script removes
   `easypatch_import` and stops.
4. Stops EasyRMM's server and the engine, renames the engine's database
   to `easypatch_before_import_<time>` (kept), and `easypatch_import` to
   `easypatch`.
5. Adds the backup's Data Protection keys to the engine's key ring
   (`<data root>/easypatch/keys`). The engine's own keys stay.
6. Adds the names to `EASYRMM_PATCHING_AGENT_HOSTNAMES` in `.env`.
7. Starts the engine and runs `easyrmm-server import-easypatch`, which
   makes the engine's organizations and sites EasyRMM's (below), then
   starts everything.

## Names

EasyPatch's organization names are unique exactly; EasyRMM's are unique
ignoring case. Each active organization of the engine, in name order:

- **joins** the EasyRMM organization with exactly its name, if there is
  one;
- otherwise becomes a **new** EasyRMM organization with its name and time
  zone;
- unless EasyRMM has the name in another case: then it becomes a new
  organization named `<name> (2)` (or `(3)`, and so on). Two EasyPatch
  organizations `Fabrikam` and `fabrikam` become EasyRMM's `Fabrikam`
  and `fabrikam (2)`. They are never merged.

Sites are placed the same way within their organization. To have an
EasyRMM organization join an imported one whose name differs only in
case, rename one of them to match before importing.

After the import, EasyRMM's names and time zones lead, as for every
organization: the engine's `fabrikam` is renamed `fabrikam (2)`, and an
organization that joined EasyRMM's takes EasyRMM's time zone. The
import's report notes each time zone that changes, because maintenance
windows follow it. A time zone EasyRMM does not know becomes UTC, also
noted.

Running `docker compose run --rm --no-deps server import-easypatch` again
finds what it made, by name, and changes nothing else.

## Audit trail

EasyRMM records `easypatch.import`, with what it made, and
`easypatch.organization_import` or `easypatch.site_import` for each link.
The engine records `import.prepare`. The old server's own audit log stays
in the engine's database.

## Going back

Before the old name's DNS changes, the import can be undone. From
`deploy/`, with the time the script printed:

```bash
docker compose stop server easypatch-worker easypatch-api
docker compose exec -u postgres postgres psql -p 15432 \
  -c 'ALTER DATABASE easypatch RENAME TO easypatch_failed_import' \
  -c 'ALTER DATABASE easypatch_before_import_<time> RENAME TO easypatch'
```

Then remove the names from `EASYRMM_PATCHING_AGENT_HOSTNAMES` in `.env`
and run `docker compose up -d`. The organizations the import made in
EasyRMM stay: delete them in **Organizations** if they are not wanted.
Start the old EasyPatch server again with `docker compose up -d` in its
folder.

## When the script refuses

| Message | Meaning |
|---|---|
| `the backup's checksums do not match` | The backup was damaged in transit: copy it again. |
| `dpkeys.tar holds something other than Data Protection keys` | The archive is not one `backup.sh` made. |
| `comes from a newer EasyPatch than this patching engine` | Upgrade EasyRMM first, then import. |
| `not an EasyPatch database` | The dump is not EasyPatch's. |
| `the patching engine here already has N agent(s)` | This deployment already patches devices; an import would replace its data. |
| `EasyRMM does not accept these settings` | Usually a name EasyRMM already uses (its own, or MeshCentral's). The message says which. |
| `the certificate in EASYRMM_TLS_CERT_FILE is not valid for …` | Add the old name to the certificate first. |

When the script stops after replacing the database, it prints how to
finish the import or go back.
