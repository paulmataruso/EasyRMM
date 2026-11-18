# ADR-0040: One set of organizations

* Status: Accepted (2026-11-18)
* Plan: [one product](../one-product-plan.md), phase B5.
* Refines: [ADR-0030](0030-easypatch-connector.md) (links chosen in
  Settings) and [ADR-0031](0031-easypatch-agent-install.md)
  (automatic installs) for the engine inside EasyRMM's deployment.

## Context
With `EASYRMM_PATCHING=bundled`, the patching engine belongs to this
EasyRMM and nobody else. Asking an administrator to create each
organization twice and then link the two copies in Settings is work only
EasyRMM can do correctly. EasyRMM is where organizations, sites and devices
are created, renamed, moved and deleted, so EasyRMM should keep the engine
the same.

What the engine requires, checked against a real engine in the contract
suite:
* Organization names are **unique case-sensitively, archived ones
  included** (409 `conflict`). EasyRMM's are unique ignoring case. Names are
  at most 200 UTF-16 code units.
* Organizations and sites are archived, not deleted, and can be restored.
  An archived organization refuses enrollment tokens.
* A time zone is an IANA name; an empty one is refused. A new site takes its
  organization's time zone. PUT replaces the whole record.
* An endpoint moves only between sites of its own organization.
* An agent uninstalls itself when sent an `uninstall-agent` job, if it
  reports the `uninstall` capability; otherwise the engine answers 409
  `agent_upgrade_required`. Revoking an endpoint cancels its open jobs, and
  its agent stops being served.

## Decision
A **reconciler** in EasyRMM makes the engine match EasyRMM. It is driven by
EasyRMM's link tables, and it is safe to stop at any point and run again.

### When it runs
* **A full pass** compares every organization and site. It runs when
  EasyRMM's organizations or sites change (tenancy tells it), and otherwise
  every 5 minutes. A pass that ran into problems is repeated every minute
  until one finishes cleanly.
* **Every minute**, each pass also moves endpoints and removes agents.
* Settings → EasyPatch shows when the engine was last in step, what it could
  not do, and how many archives and agent removals are waiting
  (`GET /api/v1/settings/easypatch/sync`).

### Organizations and sites (bundled mode only)
In the order below, each pass:
1. **Archives what EasyRMM deleted.** Deleting an organization or site
   removes its link, and a database trigger records the engine's id at that
   moment. The reconciler renames the engine's record with
   ` (deleted YYYY-MM-DD 1a2b3c4d)`, which frees the name, and archives it.
   It renames before it archives, and only while the suffix is missing, so a
   lost reply does no harm.
2. **Organizations.** For each EasyRMM organization:
   * *Linked:* the engine's record follows EasyRMM's name and time zone. It
     is restored if someone archived it in the engine's console, and created
     again if someone deleted it there.
   * *Not linked:* it first **adopts** an active, unlinked engine
     organization whose name matches exactly. That is what a create looks
     like when its reply was lost, and how an engine set up by hand joins.
     Otherwise it creates one, with automatic agent installs on (ADR-0031).
   * *Names:* a name another engine organization holds, in any case or
     archived, gets ` (1a2b3c4d)` (from EasyRMM's id). The plain name comes
     back once it is free. When both names are held, the problem is shown and
     the organization waits.
3. **Sites.** The same steps for each organization's sites, recorded in a
   site link table (`easypatch_sites`).

An organization or site deleted in EasyRMM *while* the engine creates it
leaves a record behind, and that record is archived in the next pass.

### Devices
* **Within an organization**, a device moved to another site has its
  endpoint moved to that site's engine site (bundled mode).
* **To another organization**, an endpoint cannot follow. EasyRMM has the old
  agent uninstall itself (reason `moved`). Once it is gone, the device's
  install record is cleared, so automatic installs enroll it again in the
  new organization.
* **A device deleted in EasyRMM** has its agent removed (reason `deleted`).
  The trigger records only the engine's endpoint, so the removal is
  cancelled before anything is sent if another EasyRMM device is linked to
  that endpoint or reports it in its inventory, as after merging two device
  records.
* **Stopping patching** is per device (`patch.manage`). It removes any
  waiting install, has the agent uninstall itself if EasyRMM linked it, and
  keeps EasyRMM from installing the agent again, automatically or by hand,
  until someone allows patching again. It is refused while an install is
  under way. Allowing patching again cancels a removal not sent yet.

**Removing an agent:**
* Send `uninstall-agent`.
* Check again every 5 minutes. The removal is done when the endpoint is no
  longer Active or is gone.
* A failed, expired or vanished job is sent again.
* After **7 days**, or at once if the agent is too old to uninstall itself,
  the endpoint is **revoked**, so the engine stops serving it.
* Device removals run in both modes, since the API token's server is
  EasyRMM's to patch.

### Settings
In bundled mode, links are not chosen: linking or unlinking answers 409
`patching_linked_by_easyrmm`. Settings lists each organization with its
engine organization, or "Being created". The connector mode keeps choosing
links by hand. Its tombstones are dropped, because an organization deleted in
EasyRMM is not EasyRMM's to archive on someone else's server. Changing or
removing the connection, or switching modes, forgets site links, removals
and tombstones with the other links.

### Time zones
Organizations gain a time zone (IANA, default `UTC`), which the engine's
monthly reports use. The console offers the browser's zone for a new
organization. An update that leaves it out keeps it.

### Audit
`easypatch.organization_create`, `easypatch.organization_adopt`,
`easypatch.site_create`, `easypatch.site_adopt`,
`easypatch.organization_archive`, `easypatch.site_archive`,
`easypatch.agent_uninstall`, `easypatch.agent_remove`,
`easypatch.endpoint_revoke`, `patch.stop` and `patch.allow`.

## Consequences
* An organization created in EasyRMM can patch within a minute, with no step
  in Settings, and its devices get the agent automatically.
* The engine's own console can still edit organizations, but EasyRMM
  changes name, time zone and archive state back at the next full pass.
  Descriptions, notes and addresses entered there are kept.
* Archived engine organizations keep their endpoints. An agent EasyRMM did
  not remove (one that was never linked) keeps checking in until someone
  revokes it in the engine.
* EasyRMM's console does not move devices between sites or retire them
  yet. The reconciler acts on what the database says, so a move made through
  the API or a future screen is handled.
* At most 200 endpoint moves and 100 agent removals run per pass. More wait
  for the next minute.
* `TestReconcile*` covers each case against the engine's test double:
  lost replies, the engine down, a restart in the middle, connector mode,
  and every failing engine call. The contract suite checks the engine
  behaviour listed above against a real engine.
