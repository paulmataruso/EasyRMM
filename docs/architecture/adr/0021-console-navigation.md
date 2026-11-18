# ADR-0021: Console navigation by section

* Status: Accepted (2026-11-16). Replaces the device tree dock.

## Context
Technicians work inside one area at a time (one customer's devices, the
alerts at one site, the jobs that ran on one machine) and the console's
lists already filter by organization, site and device. The main menu said
nothing about where in the customer tree a list was, and the device tree
was a separate panel docked to the right of the devices pages only.

A separate Software page listed every package on every device. Installed
software belongs to a device: technicians look it up on the device page.

## Decision
* **The sidebar follows the section.** On a section's pages the sidebar
  shows that section's own navigation in place of the main menu: a Back
  button, the section's title and actions, a filter, an "All …" row and the
  tree. Back shows the main menu on the current page; the next page in a
  section, or choosing a section from the menu, shows its navigation again.
  Focus moves to Back on entering a section and to the section's menu item
  after Back.
* **One tree, per section.** Organizations › sites (› devices where the
  section is about devices), built from the organization, site and device
  lists the caller can see, so empty organizations and sites appear too:

  | Section | Rows | Counts | A row leads to |
  |---|---|---|---|
  | Organizations | organizations, sites | devices | the organization or site page |
  | Devices | organizations, sites, devices | online of total | the list narrowed to it; a device opens its page |
  | Alerts | organizations, sites, devices with active alerts | active alerts (red when any is critical), from `GET /alerts/devices` | the alerts narrowed to it |
  | Scripts | "Shared library", organizations, sites | scripts | the library narrowed to it |
  | Jobs | organizations, sites, devices | none | the jobs that ran there (`GET /jobs?organizationId=&siteId=&deviceId=`) |
  | Settings | Users, Audit log, Remote access (as permitted) | none | that part |

  On the section's list a row changes only the scope and keeps the other
  filters (status, severity, search); paging restarts. The scope lives in
  the URL, as before, so the lists' own organization, site and device
  filters and the tree always agree. The tree is a WAI-ARIA tree: arrow
  keys, Home and End move, Right and Left open and close, Enter follows a
  row. Each row's accessible name carries its count in words.
* **The sidebar fits the tree's names.** While a tree shows, the sidebar is
  as wide as its longest row needs: every organization, site and device
  name with its indent, icon, count and quick-connect button, measured with
  a canvas in the sidebar's font, collapsed branches included, so the width
  holds still as branches open and close or the filter narrows the list. It
  is at least the main menu's 15rem and at most 24rem and a third of the
  window (85% of the screen for the phone drawer); past that, names end in
  an ellipsis and show in full on hover. The main menu and settings keep
  15rem. The width changes without animation: animating it would lay the
  page out again on every frame.
* **Quick connect.** Devices with remote access offer a quick-connect
  button on their tree row (on hover or focus, always on touch screens),
  also opened with the context menu, Shift+F10 or the context-menu key.
  It opens a small panel with the session types the caller may start,
  each in its own window or in the current tab, and says why when the
  device cannot take a session.
* **Recent connections.** The dashboard lists the ten devices the signed-in
  user most recently started a remote session on, newest first, each with
  quick connect. The list is read from the audit log
  (`device.remote_session`, last 90 days, `GET
  /devices/recent-connections`), so it needs no table of its own, and
  devices the user may no longer see drop out. The dashboard's setup
  checklist and organizations card are gone.
* **No Software page.** Installed software is shown on each device's page
  only; the console has no fleet-wide software list.
* **A console that changed reloads.** API responses carry
  `X-EasyRMM-Console`, the path of the console bundle the server serves.
  A tab running an older bundle reloads on its next navigation instead of
  running old code against a new API.

## Consequences
* Every section's list and the tree read the same organization, site and
  device lists, which TanStack Query shares; the tree adds one request in
  alerts (`/alerts/devices`) and scripts (`/scripts`).
* Fleets over 5,000 devices see the first 5,000 in the devices and jobs
  trees, and the readout says so; the lists themselves page on the server.
* The fleet-wide software search (`GET /software`) stays in the API for
  reporting; the console no longer calls it.
