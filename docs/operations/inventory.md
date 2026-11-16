# Inventory and health

Every device with the EasyRMM agent reports what it is (its **inventory**)
and how it is doing (its **metrics**). The design is in
[ADR-0018](../architecture/adr/0018-inventory-and-telemetry.md).

Inventory and metrics come from **Linux** devices for now. Windows devices
report them once the Windows agent ships. Devices that only have MeshAgent
show neither.

## What is collected

| Inventory, sent when it changes | Metrics, sent every minute |
|---|---|
| Manufacturer, model, serial number, firmware (BIOS) version and date | Processor use since the last heartbeat |
| Physical machine, virtual machine or container | Memory and swap in use |
| Processor model, sockets, cores and threads; memory size | Load averages (1, 5 and 15 minutes) |
| Operating system, version, kernel and time zone | Time since start, number of processes |
| Physical disks: model, type (SSD, NVMe, hard disk), size, serial number | Size and space used of each local filesystem |
| Network interfaces with MAC and IP addresses and link speed, default gateways, DNS servers | |
| Installed packages from dpkg, RPM, apk or pacman (up to 20,000) | |

The agent reads all of this from the files the kernel and the package
manager keep (`/proc`, `/sys`, `/etc/os-release`, the package database).
On RPM systems it runs `rpm -qa`. It runs nothing else and changes nothing.

Inventory is collected when the agent starts and every hour. The agent
sends it only when it differs from what the server already holds, which the
server tells it with every heartbeat. A device that changes nothing sends
its inventory once.

### Inside containers

An agent running in a container reports what the container sees. Disks and
the processor come from the host. Processes and filesystems are the
container's own. Network interfaces are the host's when the container uses
the host's network. **Runs as** on the **Hardware** tab says *Container*.

## In the console

The device page has three tabs once the agent has reported:

* **Overview**: the device's details and its **Health**. Health shows the
  current processor, memory and swap use, the four fullest filesystems,
  the load average, how long the device has been up and its process count.
  A meter turns amber from 80% and red from 90%, with a warning icon.
  **Performance** charts processor, memory and the fullest filesystem over
  the last hour, 24 hours or 7 days. Points are averaged over 5 minutes for
  a day and 30 minutes for a week. A gap means the device did not check in.
  **Show as a table** lists the values. The arrow keys move along the chart
  when it has focus.
* **Hardware**: system, operating system, disks, every filesystem with its
  use, and the network.
* **Software**: the installed packages, filtered as you type.

The **Software** page searches the packages on every device you can see,
optionally within one organization. Each row is one version of a package
with the number of devices that have it. Select the count to list those
devices. A search returns at most 500 package versions; search by name to
narrow it.

## Who can see it

| Permission | Allows | Roles |
|---|---|---|
| `device.view` | The **Overview** and **Hardware** tabs | Every role, on the devices it covers |
| `software.view` | The **Software** tab and the **Software** page | Every role, on the devices it covers |

Serial numbers and MAC addresses are shown to everyone who can see the
device. Reading inventory is not audited.

## Retention and size

The latest inventory and metrics of each device are kept for as long as the
device is. One measurement per device per minute is kept for the charts
for `EASYRMM_METRICS_RETENTION` (default `168h`, 7 days; at least `24h`) and
removed hourly after that. One device adds about 100 KiB a day: 1,000
devices kept for 7 days take about 1 GiB of database space.

Inventory history (what changed and when) is not kept yet. Only the current
inventory is.

## Troubleshooting

| What you see | What to check |
|---|---|
| *No inventory yet* or *No measurements yet* on a device with the agent | The agent is older than this feature, or has not checked in since it started. Run `sudo easyrmm-agent status` on the device. Reinstalling with the install command updates the agent |
| `Inventory:  not sent: …` in `easyrmm-agent status` | The upload failed. The message says why; the agent tries again after 15 minutes. `journalctl -u easyrmm-agent` has the details |
| *No packages found* | The device has no dpkg, RPM, apk or pacman database. Software installed in other ways (Snap, Flatpak, built from source) is not listed |
| *No disks reported* | Containers and some virtual machines do not show their disks |
| A chart ends before *now* | The device stopped checking in. The **Last seen** time under **Details** says when |
