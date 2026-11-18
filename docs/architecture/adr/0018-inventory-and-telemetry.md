# ADR-0018: Inventory and telemetry

* Status: Accepted (2026-11-16).

## Context
Technicians need to know what a device is before they touch it: its
hardware, disks, network addresses and installed software, and whether it is
healthy now (processor, memory, disk space). Monitoring and alerts (the next
slice) need the same measurements over time. The agent already sends a
heartbeat every minute over a signed request (ADR-0009, ADR-0015) and the
RBAC model has had `device.view` and `software.view` since phase 2.

## Decision

### Two kinds of data
* **Inventory** changes rarely: system (manufacturer, model, serial number,
  BIOS, virtualization), processor, memory size, operating system and
  kernel, physical disks, network interfaces with their addresses, the
  default gateways and DNS servers, and the installed packages. Network
  interfaces backed by hardware (`/sys/class/net/<name>/device`) are listed
  before software ones such as Docker's bridges; loopback and `veth` pairs
  are left out.
* **Metrics** change all the time: processor use, memory and swap use, load
  averages, uptime, process count and the space used on each filesystem.

### Inventory: sent only when it changes
* The agent collects its inventory at start and every hour, sorts every list
  so the same machine always produces the same document, and hashes it
  (SHA-256 of its JSON).
* Every heartbeat answer carries the hash of the inventory the server holds
  (`inventoryHash`, empty when it holds none). When it differs from the
  agent's, the agent uploads the whole document to
  `POST /api/agent/v1/inventory` (signed like every agent request, at most
  4 MiB). A restored database or a lost upload is therefore repaired at the
  next heartbeat, and an unchanged device sends nothing more than its
  heartbeat. A failed upload is retried after 15 minutes.
* Packages come from the system's package database: dpkg
  (`/var/lib/dpkg/status`), apk (`/lib/apk/db/installed`) and pacman
  (`/var/lib/pacman/local`) are read as files; RPM systems run
  `rpm -qa` with a fixed query format. At most 20,000 packages are kept.
* The server stores the document (without packages) as JSON per device and
  the packages as rows (`device_software`), replaced as a whole on each
  upload, so the fleet can be searched by package name and version. The
  serial number and MAC addresses are inventory, not secrets; they are shown
  to everyone who can see the device.

### Metrics: on every heartbeat
* The heartbeat request gains an optional `metrics` object. Processor use is
  measured between two heartbeats (over one second for the first one).
  Filesystems are the mounted local ones (ext2/3/4, XFS, Btrfs, ZFS, F2FS,
  FAT, NTFS and the root filesystem whatever its type), one entry per
  underlying device, at most 64. Mount points that are files are skipped:
  in a container, `/etc/hostname`, `/etc/hosts` and `/etc/resolv.conf` are
  files bind-mounted from the host's disk.
* The server keeps the latest metrics per device (`device_metrics`) and one
  sample per heartbeat (`device_metric_samples`: processor, memory, swap,
  load and the fullest filesystem's use). Samples older than
  `EASYRMM_METRICS_RETENTION` (default 7 days, at least 1 day) are removed
  hourly. One device produces 1,440 samples a day, about 100 KiB; 1,000
  devices kept for 7 days take about 1 GiB with indexes.
* Charts read raw samples for the last hour, 5-minute averages for a day and
  30-minute averages for a week, so a chart never has more than about 350
  points.

### Access
* Inventory and metrics are read with `device.view` on the device's site;
  packages, and the fleet software search, with `software.view`. Both are
  in every built-in role. The tables follow the devices' row-level security
  through the device they belong to, so moving a device later needs no
  change here.
* Nothing in inventory or metrics is audited: they describe the device, and
  reading them changes nothing.

### Compatibility
* Older agents send no metrics and never upload an inventory; their devices
  show "No inventory yet" until the agent is reinstalled. The server ignores
  nothing it does not understand: agents come from the server, so an agent
  is never newer than its server.

## Consequences
* The device page shows hardware, disks, network, software and health with
  charts; a fleet **Software** page finds which devices have a package.
* Alerts (next slice) evaluate the stored samples and the online state.
* Inventory history (what changed and when) is not kept yet; only the
  current inventory is.
* Windows inventory (WMI, the registry's uninstall keys) comes with the
  Windows agent; the protocol does not change for it.
