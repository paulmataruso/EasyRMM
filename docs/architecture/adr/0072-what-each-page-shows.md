# ADR-0072: What each page shows, at each level of the tree

* Status: Accepted (2026-11-26, after independent review). Design only; no code is changed by this ADR.
* Asked for by the owner (2026-11-26). Everything marked *decided in review*
  is the writer's call and the owner can overturn it.
* Builds on [ADR-0069](0069-recovery-agent-logs-and-one-device-tree.md) Part T
  (one device tree on every view) and [ADR-0021](0021-console-navigation.md)
  (sidebar tree per section); amends 0069 Part T where it says
  "with a device selected, each view shows that device's part".

## Context

The owner is happy with the console's look and its navigation tree. What
needs work is what appears in the main page after a section is chosen and the
tree is walked: "easy to navigate, but still including all the features, in a
way that makes sense". Most of an organization's settings should live under
the organization, then under the site, and anything specific to a group under
the group: "more tight and coherent".

One bug sits on top of that: in Patching the tree looks right, but choosing a
device opens the full Patching page, not a page about that device. Choosing a
group or an organization should open the Patching page narrowed to it.

## The owner's words (binding)

* "I am happy with the GUI and the navtree. What I am trying to focus on is
  not the navtree itself, its what shows up in the main page after you select
  a navbar item, then start going through the navtree."
* "most of all the settings for each org/etc should live under the org
  navitem, then under the orgname, then anything that is group specific
  should live under the groups name. More tight and coherent."
* Patching: a device opens "a device specific patching page"; a group or a
  top-level organization opens "the full patching page scoped to the group or
  org level".

## Today (inventory)

Sections are those of `web/src/nav/sections.ts`: the tree sections
(Organizations, Devices, Alerts, Scripts, Jobs, Patching) and Settings, which
lists its own parts. Reports and the Dashboard have no tree. There is no
section called Monitoring or Documentation: alert policies (permission
`monitoring.view`) sit in Alerts, and the customer record (`doc.view`: contacts,
places) sits in Organizations.

| Section | Route | What it shows today |
|---|---|---|
| Dashboard | `/` | Fleet summary cards. No tree. |
| Organizations | `/organizations` | List of organizations. |
| | `/organizations/:id` | Tabs Overview (sites, details, key contacts, delete), Contacts (`doc.view`), Patch policy (once the patching engine is set up). |
| | `/sites/:id` | Tabs Overview (device groups, devices, details, Places card (`doc.view`), Add devices button, delete) and Patch policy; only these two tabs exist. A group is `/sites/:id?groupId=`, which shows the same page. |
| Devices | `/devices` | Device list; scope by `organizationId`, `siteId`, `groupId`, `deviceId`. |
| | `/devices/approvals` | Devices waiting for approval. |
| | `/go/from-easypatch/:kind/:id` | Redirect page for links coming from the EasyPatch console; unchanged by this ADR. |
| | `/devices/add` | Add devices: tokens, install commands, downloads, approval mode. |
| | `/devices/:id` | Tabs Overview, Hardware, Software, Patches, Hardening (Linux), Logs. Header actions: remote desktop, terminal, files, run script, move, delete. |
| | `/devices/:id/remote/:kind` | Full-window remote session. |
| Alerts | `/alerts` | Tabs Alerts (list) and Policies (by organization only). |
| Scripts | `/scripts`, `/scripts/new`, `/scripts/:id`, `/scripts/:id/edit` | Script library (shared and per organization), editor, run. |
| Jobs | `/jobs`, `/jobs/:id`, `/jobs/:jobId/runs/:runId` | Jobs and their runs. |
| Patching | `/patching` | Tabs Overview, Devices, Updates, Jobs, Alerts. Every scope shows this one page. |
| | `/patching/updates/:guid` | One update. |
| Reports | `/reports` | Table reports and monthly PDFs; organization and site are filters on the page. |
| Settings | `/settings?tab=` | Users, Audit log, Remote access, Agent updates, Notifications, Audit forwarding, Patching engine, Patching (nine views: default policy, tags, report schedules, server, OS lifecycle, agent packages, alert rules, notifications, audit), Single sign-on. |
| | `/users/:id` | One user. |
| | `/account` | The signed-in person's own account. |

Settings are scattered: an organization's patch policy is on its page, but its
tags, report schedule, automatic agent install, alert policies, people
install tokens are in Settings, Alerts, Devices or Patching; there are two
Settings entries about patching.

## Decision

### Principles

1. **One home per feature.** Every feature is reachable from exactly one
   obvious place. Other pages may link to it, never show a second copy. Where
   two places use the same screen (below), it is one component, one URL.
2. **The tree level picks the page.** The tree sets `organizationId`,
   `siteId`, `groupId`, `deviceId` (unchanged from 0069). A level's own page
   holds that level's settings and its members.
3. **The same tabs at each level, in the same order**, hidden (never greyed)
   when the user lacks the permission or the feature is off.
4. **Lists are for looking, level pages are for changing.** A list section
   (Alerts, Scripts, Jobs, Devices) narrowed to a node shows that node's rows
   and keeps its filters. Settings never live in a list section.
5. **Settings go where their scope is**: server-wide in Settings, the rest on
   the organization, site or group page.
6. Old URLs redirect; nothing is removed without one.

### The matrix: what the main page shows

"Everything" is no node chosen. In list sections the URL is the list route
with the scope as query parameters, as today. Group and device have the
Organizations-section pages below.

| Section | Everything | Organization | Site | Group | Device |
|---|---|---|---|---|---|
| **Organizations** | `/organizations`: list | `/organizations/:id` (tabs below) | `/sites/:id` (tabs below) | `/groups/:id` (new, tabs below) | `/devices/:id` (its own page) |
| **Devices** | `/devices`: all devices | `/devices?organizationId=` | `…&siteId=` | `…&groupId=` | `/devices/:id` |
| **Patching** | `/patching`: five tabs, fleet-wide | `/patching?organizationId=`: same tabs, that organization | `…&siteId=`: that site | `…&groupId=`: Overview and Devices narrowed to the group; Updates, Jobs and Alerts show the group's site with a note (the engine counts these per site) | `/patching/devices/:id` (new): that device's patching page, in the Patching section |
| **Alerts** | `/alerts`: list | `?organizationId=` | `&siteId=` | `&groupId=` | `?deviceId=`: its alerts |
| **Scripts** | `/scripts`: all libraries | `?library=<orgId>`: that organization's library | `&siteId=` | `&groupId=` (runs on the group) | `?deviceId=` (runs on the device) |
| **Jobs** | `/jobs` | `?organizationId=` | `&siteId=` | `&groupId=` | `?deviceId=` |
| **Reports** | `/reports`: all | `?organizationId=` filter, set from a link on the organization page | `&siteId=` | not offered (a report is per site or organization) | not offered |
| **Settings** | server-wide parts only | n/a: organization settings are on its page | n/a | n/a | n/a |
| **Dashboard** | `/` | n/a | n/a | n/a | n/a |

Alerts' Policies tab goes away as a tab of the Alerts section. Policies have
three levels (`server/internal/monitoring/policies.go`): shared (every
organization), organization and site. Each goes with its scope: shared
policies are server-wide and live in Settings as "Alert policies"; an
organization's on its page; a site's on its page. The Alerts list keeps a
"Policies" link that goes to the policies for its current scope (Everything to
Settings, organization or site to that page; group and device to their site).
`/alerts?tab=policies[&organizationId=]` redirects the same way (*decided in
review*).

### The Patching selection fix (first slice)

Today `selectedKey` and `targetHref` for Patching put a device in
`/patching?deviceId=` and the page ignores it for every tab but Devices.

* **Device**: the tree row opens `/patching/devices/:id`. This is a page in the
  Patching section (the sidebar keeps the Patching tree, the node stays
  highlighted). It shows that device's patching: patch state and last scan,
  pending and installed updates, its patch jobs and alerts, and the same
  actions as the Devices page (scan, install, reboot rules). It reuses
  `DevicePatches` (the component of the Devices-section Patches tab); the two
  pages differ only in their frame and header. The Devices section's Patches
  tab stays, because from a device you may want to stay in the device page.
  If the device has no patching agent, the page says so and offers the
  install action.
* **Group**: `/patching?organizationId=&siteId=&groupId=`. Overview
  Devices narrow to the group; the other tabs keep showing the group's site
  with the existing note, until the engine counts per group.
* **Organization / site**: `/patching?organizationId=` / `&siteId=`, as
  today, but every tab honours the scope, and the tab strip keeps the chosen
  node when switching tabs.
* `/patching?deviceId=X` (old links and bookmarks) redirects to
  `/patching/devices/X`.
* The page header always names the node ("Patching · <name>") and has a
  link up one level.

### Pages per level in the Organizations section

Same tab order at each level; a tab that does not apply is hidden, never
greyed. Each tab names its permission, checked at the level of the selection
(the organization or site being viewed, not only globally).

| Tab | Organization | Site | Group |
|---|---|---|---|
| Overview | sites, key contacts, details, delete | groups, devices, details, Places card (`doc.view`), delete | devices in the group, rename, delete |
| Contacts (`doc.view`) | Contacts | - | - |
| People (`user.view`) | who holds a role here (invite, change, remove) | - | - |
| Alert policies (`monitoring.view` to see, `monitoring.manage` to change) | the organization's policies | the site's policies | - |
| Patching (`patch.configure`; the tab shows once the engine is set up) | patch policy, tags, monthly report schedule, install the patching agent automatically | patch policy (override) | - |
| Windows modules (`org.view` to see, `org.manage` or `site.manage` to change) | which Windows management modules are on (ADR-0073) | the same, with a per-site override | - |
| Install (`enrollment.manage`) | install tokens and commands for the organization | the same, for the site | - |
| Settings (`device.edit`) | - | - | group-wide verbose agent logging |

What the site strip gains: today it has Overview and Patch policy only
(Places is a card on Overview). It gains Alert policies, Patching (the
renamed Patch policy) and Install. Places stays where it is, on Overview.

"Install" is the Add devices page (`/devices/add`) embedded with the scope
fixed, so there is one component. `/devices/add` stays for no scope, with an
organization and site picker; `?siteId=` redirects to the site's Install tab.

Groups do have a setting today: group-wide verbose agent logging
(`PUT` and `DELETE /device-groups/{id}/agent-logs/verbose`,
`agentlogsapi.go`), switched from `DeviceLogs.tsx`. It moves to the group
page's Settings tab. `DeviceLogs.tsx` keeps a read-only line saying a group
setting is on, linking to the group page. No other group setting is invented;
a new one later adds to this tab.

### Where each Settings item goes

| Today | Where | Reason |
|---|---|---|
| Settings > Users | Stays: the list of every person, MFA, super administrators, invites with no organization. The organization's own people are the same list in the organization's People tab (one component, scope fixed). `?tab=users&organizationId=X` redirects to it. This changes what that old link shows (a filtered list inside Settings becomes the organization page), so it is tested. | A person can hold roles in many organizations. |
| `/users/:id` | Stays | |
| Audit log | Stays (server-wide); organization filter stays | |
| Remote access | Stays | MeshCentral is the deployment's |
| Agent updates | Stays | |
| Notifications (mail server) | Stays | |
| Audit forwarding | Stays | |
| Single sign-on | Stays | |
| Patching engine: status, linked devices | Merged into Settings > Patching, view "Engine" | Two entries about patching become one |
| Patching engine: each organization's automatic agent install | Organization > Patching | It is per organization |
| Patching: default policy | Settings > Patching (the server-wide default) | |
| Patching: tags | Organization > Patching (tags are per organization) | |
| Patching: report schedules | Organization > Patching | Per organization |
| Patching: server, OS lifecycle, agent packages, alert rules, notifications, audit | Settings > Patching | Server-wide |
| Organization > Patch policy tab | Organization > Patching tab (renamed, grouped with the above; `patch.configure`) | |
| Site > Patch policy tab | Site > Patching | |
| Alerts > Policies tab | Shared policies: Settings > Alert policies (new item, `monitoring.manage`); organization policies: Organization > Alert policies; site policies: Site > Alert policies | Policies have three levels |
| Verbose agent logging for a group (Devices > Logs) | Group > Settings | It is a group setting |
| Devices > Add devices (with org and site chosen) | Organization/Site > Install | |
| Organization > Contacts, Site places | Unchanged | |
| Scripts library per organization | Stays in Scripts (it is work, not a setting) | |
| Account (own name, password, MFA, passkeys) | Stays | |

### Two findings on Add devices and invitations (in scope)

* **The show-again button has no label.** The terminal-icon button in the
  token table is named only for screen readers. It becomes a text button,
  "Show install command", visible beside "Revoke".
* **Tokens made before secrets were kept cannot be shown, and the page does
  not say so clearly.** Today only a faint line under the name says it. Those
  rows instead show a disabled "Show install command" with the reason in
  plain words ("Made before EasyRMM kept tokens; make a new one"), and a
  note above the table when any such token exists.
* **The invite dialog says "Send invitation" even with no mail server.**
  The button reads "Create invitation link" when the mail server is not set up
  (the dialog reads the mail status, as the Notifications tab does),
  "Send invitation" when it is, with a line saying which will happen. The
  link is still shown after either.

## Amendments

* Amended 2026-11-26 (decided in review, while building ADR-0073 slice 8):
  organization-level module settings had no slot. The "Windows modules" tab
  (ADR-0073's toggles, `org.view` to see) sits at the organization and the site
  between Patching and Install: both are configuration, and Install stays last
  because it is the action tab. The device's module tabs (Security first) come
  after Logs and show only when the role is detected, the module is on for the
  site and the viewer holds the module's view permission; a module that is off
  keeps its URL, which says so.

* Amended 2026-11-26 (decided in review): S1 and S2 as built. The `?deviceId=`
  redirect leaves `?tab=alerts&deviceId=` alone, because the Alerts tab filters
  by device on its own (a bookmarked filter, not a device page). The mail status
  the invite dialog reads is `passwordResetAvailable` of `GET /auth/options`
  (the server's `mailer.Available`), which any signed-in user may read; the
  Notifications tab's `/settings/mail-server` needs `settings.manage`.
* Amended 2026-11-26 (decided in review): S7 and S8 as built.
  * Alert policies: Settings > Alert policies shows with `monitoring.view` and lists only the shared policies (a super
    administrator adds them); the organization and site tabs list only their own level, so a site's tab does not repeat
    its organization's. The policy dialog no longer has a level picker, because every page that opens it fixes the scope.
    The Alerts "Policies" link follows the page's filter (a group or a device goes to its site).
  * Patching tab: the tab id is `patching` and needs `patch.configure` (it was `patch-policy` with `patch.view`);
    `?tab=patch-policy` still opens it. Tag definitions (names, colours, priorities, policies) are shared by every
    organization, so they stay in Settings > Patching beside the default policy; the organization's tab carries what is
    per organization: its tags (assignment), policy, monthly report schedule and automatic agent install. Settings >
    Patching gains an "Engine" view (the old Patching engine entry, now without the per-organization rows), and
    `?tab=easypatch` redirects to it. `?tab=patching&view=reports` redirects to the organization's Patching tab, or to
    the list of organizations when none is named.
  * Server: the automatic agent install needed `settings.manage` anywhere. `PATCH /settings/easypatch/organizations/{id}`
    now also accepts `patch.configure` on that organization, and `GET /patching/organizations/{id}/agent-install` (the
    organization's own link, `patch.configure` on it, no call to the engine) feeds the tab.

## Slices

Hotspots: `DeviceDetailPage.tsx` (every module that adds a device tab edits
it), the nav tree (`SectionNav.tsx`, `sections.ts`, `tree.ts`), `App.tsx`,
`OrganizationDetailPage.tsx` and `SiteDetailPage.tsx`. Edits are small and
additive. `web/e2e/console.spec.ts` is shared: each slice adds its own
`web/e2e/ia-<slice>.spec.ts`.

True order and parallelism:

1. **S1** and **S2** run in parallel (they share no files).
2. **S3** after S1 (both edit `sections.ts` and `App.tsx`).
3. **S4** after S3 (it edits the organization and site pages S3 also edits).
4. **S5, S6, S7, S8** after S4, in parallel: each is its own tab component
   file plus one line in the tab registry S4 creates. They do not edit the
   organization or site pages. Only S8 edits `SectionNav.tsx`
   (`settingsParts`), and only S7 and S8 edit `SettingsPage.tsx`, so S7 and
   S8 are sequenced (S7 first) if they would conflict.
5. **S9** last.

* **S1: Patching selection.** `nav/sections.ts` (`sectionFor` already covers
  `/patching/…`; patching `targetHref` and `selectedKey`), `nav/SectionNav.tsx`
  (patching target only), `App.tsx` (route `/patching/devices/:id` and the
  `?deviceId=` redirect), new `pages/patching/PatchingDevicePage.tsx`,
  `pages/patching/PatchingPage.tsx`, `nav/sections.test.ts`, `nav/nav.test.tsx`.
* **S2: Add devices and invite fixes.** `pages/devices/AddDevicesPage.tsx`,
  `pages/settings/UsersTab.tsx`, `pages/pages.test.tsx`.
* **S3: Group page and its API.** Server: `GET /device-groups/{id}` in
  `tenancyapi.go` (the router beside the existing `PUT` and `DELETE`, which
  today are the only per-group routes, with `list by site`), the same
  `site.view` check at the group's organization and site as the list, a 404
  for a group the caller cannot see, and integration tests against PostgreSQL
  for allowed, other-organization and missing cases. Web: new
  `pages/organizations/GroupDetailPage.tsx` (Overview, Settings),
  `App.tsx` (route `/groups/:id`, redirect from `/sites/:id?groupId=`),
  `nav/sections.ts` (`sectionFor` gains `/groups`, so the Organizations
  tree shows; `targetHref`, `selectedKey`), `SiteDetailPage.tsx` (group rows
  link to it), `DeviceLogs.tsx` (the read-only line). `rbac.go` is a hotspot:
  one additive entry if a route needs one.
* **S4: Tab registry.** New `pages/organizations/levelTabs.tsx`: a registry
  of `{ id, label, permission, levels, component }`, with order, permission
  check at the selection's level, hidden-not-greyed and `?tab=`. The
  organization and site pages use it for their current tabs. No behaviour
  change.
* **S5: Install tab.** New `pages/organizations/tabs/InstallTab.tsx`;
  `AddDevicesPage.tsx` takes a scope prop; redirect for `/devices/add?siteId=`.
  `enrollment.manage`.
* **S6: People tab.** New `tabs/PeopleTab.tsx`; `UsersTab.tsx` takes a scope
  prop; the redirect in `SettingsPage.tsx`. `user.view`.
* **S7: Alert policies tabs.** New `tabs/AlertPoliciesTab.tsx` (organization
  and site); new `settings/AlertPoliciesSettings.tsx` for shared policies;
  `AlertsPage.tsx` (drop the tab, add the link and the redirect);
  `settingsParts`. `monitoring.view` / `monitoring.manage`.
* **S8: Patching tab.** New `tabs/PatchingTab.tsx` (organization and site):
  tags, report schedule, automatic agent install; `settings/PatchingTab.tsx`
  and `EasyPatchTab.tsx` merged into one Settings entry
  (`settingsParts`: one patching entry, `patch.configure` as today).
* **S9: Redirect and link sweep.** Every in-app link to a moved URL (grep for
  `/settings?tab=`, `/alerts?tab=policies`, `/devices/add`,
  `/patching?deviceId`), and docs that name an old place.

## Tests

Each slice adds Playwright specs (`web/e2e/ia-<slice>.spec.ts`) and vitest
tests, and names a test per tree level it changes. The tree selection round
trip uses the matrix URLs as the expected values.

* S1: Patching at Everything, organization, site, group, device (the URL, the
  tree stays on Patching, the device node highlighted, the page shows only that
  device; group tabs and the site note); the old `?deviceId=` redirect.
* S2: visible "Show install command" name; disabled button and reason for an
  old token; invite button text with and without a mail server.
* S3: server integration tests for `GET /device-groups/{id}` (allowed,
  denied, missing); browser: group row opens `/groups/:id`, the tree shows
  the Organizations section, the old URL redirects, rename and delete, the
  verbose-logging switch.
* S4: organization and site tab lists and order with and without each
  permission, `?tab=` round trip, at organization and site level.
* S5 to S8: for each, the tab at organization and site level (group where it
  applies: none), hidden without its permission, each moved feature working
  from its new home, each old URL redirecting. S6 also tests that
  `?tab=users&organizationId=` lands on the People tab.
* Scripts, Jobs and Alerts (one spec in S1's sweep and again in S9): select
  an organization, site, group and device in each and check the URL and that
  only that scope's rows show.

## How later modules slot in

A module adds, per level, at most one tab or one page section, hidden when it
does not apply. It never adds a new top-level section unless it is a
cross-organization workspace nobody could reach otherwise. No redesign: a
module adds a row below and a tab to the existing strip.

| Module | Device | Group / Site | Organization | Settings / elsewhere |
|---|---|---|---|---|
| Windows Defender (0074) | "Security" tab: state, exclusions, hashes check | Site: Security on the Overview | Organization: Security tab if it has an organization switch | Server-wide hash list in Settings |
| Active Directory (0075) | "Roles" tab on a domain controller | - | Directory health card on the organization Overview | - |
| DNS, DHCP, certificate authority, file shares, print (0076) | one "Roles" tab, with a view per role found | - | Overview card per role count | - |
| Windows Backup (0077) | "Backup" tab | - | Backup status card; alert policy kinds in Alert policies | - |
| Compliance (0078) | "Compliance" in the Security tab | Site result card | "Compliance" tab | Compliance table in Reports |
| Quick Assist (0080) | A header action beside Remote | - | - | - |
| Saved RDP credentials (0079) | in the Remote menu | - | - | - |

New alert kinds and scheduled jobs land in the existing Alerts and Jobs
lists with the same scope parameters, so they appear at every level with no
change.

## Consequences

* Technicians find an organization's settings in one place, and a device's
  patching one click from the Patching tree.
* The Patching tree and the Devices tree now lead to different pages for a
  device, on purpose: each stays in its own section.
* Settings shrinks to what is server-wide. Old bookmarks keep working
  through redirects.
* The engine counts updates, jobs and alerts per site, not per group, so a
  group in Patching shows the site's numbers on three tabs, with a note,
  until the engine changes.

## Owner decisions

None are blocking. Two calls were made in review that the owner may overturn:
policies move to the level they belong to (the Alerts section no longer has a
Policies tab), and Settings > Users stays as the all-people list beside the
organization's People tab.

## References

* [ADR-0069](0069-recovery-agent-logs-and-one-device-tree.md), Part T
* `web/src/nav/`, `web/src/App.tsx`, `web/src/pages/`
