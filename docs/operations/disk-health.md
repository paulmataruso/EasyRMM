# Disk health

The EasyRMM agent reads each disk's own health record (NVMe's health log,
ATA's SMART) every 30 minutes, and the server judges what it read with one
set of rules. The console shows each disk's state on the device's
**Hardware** tab, a device's worst disk in the **Devices** list, and raises
alerts through [disk health policies](alerts.md#disk-health-policies). The
design is in [ADR-0065](../architecture/adr/0065-hardware-health.md).

**SMART predicts some failures, not all.** A disk shown *Healthy* can still
fail without warning. Disk health is no substitute for backups.

**Many servers show *Unavailable* until RAID controllers are read.** Disks
behind a hardware RAID controller, SAS disks and USB disks are not read in
this release; see [What is read where](#what-is-read-where).

## States

Every disk, and every fact about it, is in one of these states. The same
words are used in the console, in alerts and here.

| State | Means | What changes it |
|---|---|---|
| **Healthy** | Read within the last 2 hours: the drive's own verdict and every fact the server judges, all within the rules below | — |
| **Warning** | Read, and a sign of wear or damage holds | A later reading without it |
| **Failing** | Read, and the drive's own verdict says it is failing | A later reading that is not failing |
| **Unknown** | EasyRMM could read this disk, and this time it could not tell | Usually the next reading |
| **Unavailable** | The disk keeps health data, but EasyRMM cannot reach it from where the agent runs | Something else in place: the controller's own tools, another driver, a later release |
| **Unsupported** | The disk, by what it is, keeps no such data | Never, for that disk |
| **Reported** | A fact shown as read, which EasyRMM does not judge (power-on hours, data written, firmware) | — |

Rules the console follows for a disk, the first that applies:

1. A disk the device's latest report no longer lists shows **Missing**,
   with the state and time it was last read (*Missing since 3 May; last
   read Failing, 2 May 14:30*). It counts as *Unknown* in the Devices list.
2. A disk that is **Unsupported** or **Unavailable** as a whole shows that.
3. A disk last read **Failing** or **Warning** keeps showing it, however
   long ago that was, with *last read …*. Readings that could not tell (the
   disk asleep, a timeout, the device offline) do not change it; only a
   reading that reads the drive's verdict does.
4. A disk read **Healthy** within the last 2 hours is **Healthy**.
5. Anything else is **Unknown**: a healthy disk not read for over 2 hours
   (*Unknown: not read since …*, for example because the device is
   offline), or a disk with no complete reading yet, with the reason.

Readings since the last complete one that could not tell are noted under
the state (*The 3 readings since could not tell; the latest: timed out.*).

**A disk is never shown *Healthy* because something could not be read.**
Without the drive's verdict, or with a fact the rules judge unread, a
reading is *Unknown*.

## The rules

| State | When |
|---|---|
| **Failing** | NVMe: the critical warning says the spare is below its threshold, reliability is degraded, the media is read-only, or the volatile memory backup failed. ATA: SMART status *threshold exceeded*, or a pre-fail attribute at or below its (non-zero) threshold |
| **Warning** | Any reallocated sector or NVMe media error; any pending or offline-uncorrectable sector; 90% or more of the rated endurance used; a temperature at or above the drive's own limit; the NVMe temperature or persistent memory warning, or a warning bit the NVMe specification reserves today; an ATA attribute that is not pre-fail at or below its threshold |
| **Healthy** | The verdict read, every judged fact the drive keeps read, none of the above |

* A drive that reports **no temperature limit** has its temperature
  *Reported*, not judged; a [temperature policy](alerts.md#disk-health-policies)
  with a value in °C still applies to it.
* A fact the drive does not keep (NVMe drives have no pending sectors) is
  *Unsupported* and does not make the disk *Unknown*.
* Where Windows does not return the ATA SMART status, the verdict comes from
  the attributes against their thresholds. A drive that answers neither is
  *Unknown: the drive's verdict could not be read*, never judged from
  attribute values alone.
* Vendors' own wear attributes are not read yet: a SATA SSD without ATA's
  Device Statistics page shows wear as *Unsupported*.

## Reasons

A state other than *Healthy* comes with a reason, shown after it: *Unavailable:
behind a RAID controller*. A *Warning* or *Failing* disk says instead what
holds (*Pending sectors 8*).

| Shown | Means |
|---|---|
| *Unknown: asleep, not woken* | The disk was in standby and was not spun up. A disk asleep for a day is read once anyway |
| *Unknown: timed out* | The disk did not answer within the operating system's timeout |
| *Unknown: timed out in the last 24 hours, left alone until then* | After a timeout, the agent leaves the disk alone for a day |
| *Unknown: an I/O error* | The query failed |
| *Unknown: the answer's checksum was wrong* | The answer could not be trusted |
| *Unknown: the answer was too short or malformed* | The same |
| *Unknown: the agent failed reading it* | The agent failed reading the answer; please report it |
| *Unknown: the drive's verdict could not be read* | Neither the SMART status nor the attributes against their thresholds could be read |
| *Unknown: the drive holds no valid value for this now* | The drive keeps this statistic but holds no valid value now |
| *Unknown: not read for over 2 hours* | A healthy disk not read since; *not read since …* on the disk |
| *Unknown: not in the device's latest report* | A missing disk, shown as *Missing since …* |
| *Unknown: the agent's report could not be used* | The agent sent a state, reason or value the server does not know |
| *Unavailable: behind a RAID controller* | A hardware RAID controller's volume, on Linux |
| *Unavailable: a storage driver refused the query* | A driver on the way refused, as hardware RAID and some vendor drivers do on Windows |
| *Unavailable: a SAS or other SCSI disk, not read yet* | SAS, Fibre Channel, iSCSI and other SCSI disks |
| *Unavailable: behind a USB bridge, not read yet* | A USB disk |
| *Unavailable: SMART is turned off on the drive* | Turn it on with the maker's tool or `smartctl -s on` |
| *Unavailable: the agent is not allowed to query the disk* | On Linux, the agent's service lacks `CAP_SYS_ADMIN` |
| *Unavailable: the agent runs in a container* | It cannot reach the host's disks |
| *Unavailable: the operating system does not show this* | A fact the operating system does not give |
| *Unsupported: a virtual machine's emulated disk* | A hypervisor's emulated disk |
| *Unsupported: a virtual machine that does not pass the disk's health through* | A read failed on a machine the inventory names as virtual |
| *Unsupported: a Storage Spaces virtual disk* | Windows Storage Spaces |
| *Unsupported: an SD or MMC card* | Memory cards keep no SMART |
| *Unsupported: the drive has no SMART* | An ATA drive without SMART |
| *Unsupported: the disk refused the query* | The disk itself answered that it does not support it |
| *Unsupported: the drive does not keep this* | A fact the drive does not keep, such as pending sectors on NVMe |

## What is read where

| Disk | Windows | Linux |
|---|---|---|
| NVMe | Read | Read |
| SATA or ATA, also behind a host bus adapter | Read | Read |
| Intel RST or VMD (Windows bus type RAID) | Tried; *Unavailable* when the driver refuses | Read when the kernel shows the disk as NVMe or SATA |
| Hardware RAID volume | *Unavailable* (the driver refuses) | *Unavailable* (behind a RAID controller) |
| SAS, Fibre Channel, iSCSI | *Unavailable* | *Unavailable* |
| USB | *Unavailable* | *Unavailable* |
| SD and MMC cards, Storage Spaces | *Unsupported* | *Unsupported* |
| A virtual machine's emulated disks | *Unsupported* | *Unsupported* |
| A disk passed through to a virtual machine | Read, as what it is | Read, as what it is |
| Any disk, agent in a container | — | *Unavailable* |

* The agent sends a fixed list of read-only ATA and NVMe commands, with the
  operating system's own timeouts. It changes nothing on the disk and runs
  no self-tests.
* **An emulated disk whose model was changed by hand** is read as what it
  claims to be. QEMU, for one, makes its values up (the same temperature
  every time, no wear), so such a disk can show *Healthy*.
* A device whose agent is older than this feature, or has not read its disks
  yet (the first reading is 2 minutes after the agent starts), shows
  **Not reported**.

## In the console

* **A device's Hardware tab**: the **Disks** card shows each disk's
  firmware and health with when it was read. Disks no longer reported stay
  on the card below the others, marked missing. Selecting a disk opens its
  panel: every fact with its state, the ATA attribute table, the last 30
  days (worst state, highest temperature, wear and error counts per day)
  and the disk's open alerts.
* **Devices**: the **Disk health** column shows each device's worst disk
  (*Failing*, *Warning*, *Unknown*, *Healthy*), with the disks that are
  *Unavailable* or *Unsupported* counted after it (*Healthy, 3 disks
  unavailable*). A device with none in the first four shows *Unavailable*
  or *Unsupported* with its count; one that sent no reading shows *Not
  reported*. The filter offers all seven; *Unavailable* and *Unsupported*
  find every device with a disk in that state.
* Reading disk health needs `device.view` at the device's site, as the
  rest of its inventory does: Read-Only included. Serial numbers are shown
  to everyone who can see the device. Readings are not audited.

## Alerts

Five shared policies watch disk health; only **Disk failing** is turned on
in a new or upgraded installation. Each raises one alert per disk. See
[Disk health policies](alerts.md#disk-health-policies) for the checks, when
they open and resolve, and what happens to the alerts of a disk that
disappears.

## History and retention

* The latest reading of each disk is kept for as long as the disk is
  reported, and for 14 days after the device's disk readings stop listing
  it.
* Every reading is kept for `EASYRMM_METRICS_RETENTION` (default `168h`, 7
  days). After that the hourly purge keeps one row per disk and UTC day:
  the day's worst state, highest temperature, and last counts and wear.
  Those are kept for `EASYRMM_HARDWARE_RETENTION` (default `17520h`, 730
  days; at least `EASYRMM_METRICS_RETENTION`, or the server refuses to
  start). Disks wear over years, and two years shows the trend.
* **Size**: about 0.3 MiB per disk at the defaults (about 300 bytes a
  reading with its index: 336 readings for the week and 730 days); 1,000
  devices with two disks each take about 0.6 GiB of database space, and the
  [backups](backup-restore.md) grow by the same.
* Removing a device removes its disks' readings and history.

## Troubleshooting

| What you see | What to check |
|---|---|
| *Not reported* on a device with the agent | The agent is older than this feature, or started less than 2 minutes ago. `easyrmm-agent status` shows the agent's version |
| Every disk of a server *Unavailable* | Most servers keep their disks behind a RAID controller; read them with the controller's own tools for now |
| *Unknown: asleep, not woken* | Normal for a disk that spins down. It is read at least once a day |
| *Unknown: timed out* | The disk or its cable may be failing; the agent leaves it alone for a day. Check the operating system's log |
| *Unavailable: the agent is not allowed to query the disk* on Linux | The agent's service lost `CAP_SYS_ADMIN`, for example through a drop-in that limits capabilities |
| A replaced disk still listed as *Missing* | It goes 14 days after the device's disk readings stopped listing it, with its alerts (*Disk gone*); resolve them by hand meanwhile |
