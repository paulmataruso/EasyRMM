# ADR-0072: What each page shows, at each level of the tree

* Status: Proposed (2026-11-26). Design only; no code is changed by this ADR.
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
| | `/sites/:id` | Tabs Overview (device groups, devices, details, Add devices, delete), Patch policy. A group is `/sites/:id?groupId=`, which shows the same page. |
| Devices | `/devices` | Device list; scope by `organizationId`, `siteId`, `groupId`, `deviceId`. |
| | `/devices/approvals` | Devices waiting for approval. |
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

Alerts' Policies tab goes away as a tab of the Alerts section. A policy is
about one organization, so it lives on that organization's page (below).
`/alerts?tab=policies&organizationId=X` redirects there; `?tab=policies` with
no organization redirects to `/organizations` (*decided in review*).

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

Same tab order at each level; a tab that does not apply is hidden.

| Tab | Organization | Site | Group |
|---|---|---|---|
| Overview | sites, key contacts, details, delete | groups, devices, details, delete | devices in the group, rename, delete |
| Contacts / Places (`doc.view`) | Contacts | Places | - |
| People (`user.view`) | who holds a role here (invite, change, remove) | - | - |
| Alert policies (`monitoring.view`) | the organization's policies | - | - |
| Patching (once the engine is set up) | patch policy, tags, monthly report schedule, install the patching agent automatically | patch policy (override) | - |
| Install (`enrollment.manage`) | install tokens and commands for the organization | the same, for the site | - |

"Install" is the Add devices page (`/devices/add`), embedded with the scope
fixed, so there is one component. `/devices/add` stays as the page for no
scope, with an organization and site picker; `?siteId=` redirects to the
site's Install tab. A group has no settings of its own today, because the
product has none (a group is a set of devices). The tab list for a group is
Overview now; a new group setting, when one is designed, adds a tab there.
No group setting is invented by this ADR.

### Where each Settings item goes

| Today | Where | Reason |
|---|---|---|
| Settings > Users | Stays: the list of every person, MFA, super administrators, invites with no organization. The organization's own people are the same list in the organization's People tab (one component, scope fixed). `?tab=users&organizationId=X` redirects to it. | A person can hold roles in many organizations. |
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
| Organization > Patch policy tab | Organization > Patching tab (renamed, grouped with the above) | |
| Site > Patch policy tab | Site > Patching | |
| Alerts > Policies tab | Organization > Alert policies | |
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

## Slices

Ordered. Each names the files it touches. Slices S1 to S3 touch distinct
files and may run in parallel; the hotspot files are called out so that two
builders do not edit them at once.

Hotspots: `web/src/pages/devices/DeviceDetailPage.tsx` (also edited by every
module that adds a device tab) and the nav tree
(`web/src/nav/SectionNav.tsx`, `sections.ts`, `tree.ts`). Edits to them are
small and additive, and only S1 and S3 touch the nav files, so they go in that
order, never together. `web/e2e/console.spec.ts` is shared: each slice adds
its own spec file `web/e2e/ia-<slice>.spec.ts` instead.

* **S1: Patching selection** (first). `nav/sections.ts`, `nav/SectionNav.tsx`
  (patching target only), `App.tsx` (route `/patching/devices/:id`, redirect),
  new `pages/patching/PatchingDevicePage.tsx`, `pages/patching/PatchingPage.tsx`
  (scope on every tab, header, group note), `nav/sections.test.ts`,
  `nav/nav.test.tsx`.
* **S2: Add devices and invite fixes.** `pages/devices/AddDevicesPage.tsx`,
  `pages/settings/UsersTab.tsx`, `pages/pages.test.tsx`. Independent of S1.
* **S3: Group page.** New `pages/organizations/GroupDetailPage.tsx`,
  `App.tsx` (route `/groups/:id`, redirect from `/sites/:id?groupId=`),
  `nav/sections.ts` (`targetHref`, `selectedKey` for organizations),
  `pages/organizations/SiteDetailPage.tsx` (group rows link to it). After S1.
* **S4: One tab strip per level.** New `pages/organizations/levelTabs.tsx`
  (the tab list with permissions), used by `OrganizationDetailPage.tsx`
  `SiteDetailPage.tsx`; tab order, hidden-not-greyed, `?tab=` handling. No
  behaviour change yet. After S3.
* **S5: Install tab.** `pages/devices/AddDevicesPage.tsx` (scope prop),
  Organization and Site pages (tab), `App.tsx` redirect for
  `/devices/add?siteId=`. After S2 and S4.
* **S6: People tab.** `pages/settings/UsersTab.tsx` (scope prop),
  `OrganizationDetailPage.tsx`, redirect in `SettingsPage.tsx`. After S4.
* **S7: Alert policies tab.** `pages/alerts/AlertsPage.tsx` (drop tab,
  redirect), `OrganizationDetailPage.tsx`. After S4.
* **S8: Patching tab.** `pages/settings/PatchingTab.tsx`,
  `pages/settings/EasyPatchTab.tsx`, `pages/settings/SettingsPage.tsx`,
  `nav/SectionNav.tsx` (`settingsParts`: one patching entry), the
  organization and site pages; moves tags, report schedules and automatic
  install. Last of the settings moves, because it touches `settingsParts`.
* **S9: Redirect and link sweep.** Every in-app link to a moved URL
  (`grep` for `/settings?tab=`, `/alerts?tab=policies`, `/devices/add`,
  `/patching?deviceId`), plus `docs/` screenshots text that names the old
  place. After S5 to S8.

## Tests

Each slice adds browser tests (Playwright, its own `web/e2e/ia-<slice>.spec.ts`)
and component tests (vitest). Each tree level is covered where the slice
changes it.

* S1: in Patching, click an organization (tab strip and rows scope to it),
  a site, a group (Overview and Devices narrowed, other tabs show the site
  note), a device (URL is `/patching/devices/:id`, the Patching tree stays,
  the device node is highlighted, the page shows only that device); and the old
  `?deviceId=` link redirects. Everything level unchanged.
* S2: the show-again button has a visible name; an old token shows the
  disabled button and the reason; the invite dialog says "Create invitation
  link" with no mail server and "Send invitation" with one (existing tests in
  `pages.test.tsx` updated).
* S3: group row opens `/groups/:id`; the old `/sites/:id?groupId=` redirects;
  rename and delete from the page.
* S4 to S8: for the organization, the site and (where it applies) the group,
  the tab list and order, a hidden tab for a user without the permission, each
  moved feature working from its new home, and each old URL redirecting.
* Every slice: the tree selection round trip, section by section, through
  Everything, organization, site, group and device, using the matrix as the
  expected URLs.

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
policies move wholly to the organization page (the Alerts section no longer
has a Policies tab), and Settings > Users stays as the all-people list beside
the organization's People tab.

## References

* [ADR-0069](0069-recovery-agent-logs-and-one-device-tree.md), Part T
* `web/src/nav/`, `web/src/App.tsx`, `web/src/pages/`
