# ADR-0065: Hardware diagnostics and health monitoring

* Status: Proposed (2026-11-21). Not implemented.
* Nothing here was decided by the owner. Everything marked as decided
  was decided in review, and the owner can overturn it; the
  [owner questions](#owner-questions) list what is the owner's.
* Amends: [ADR-0018](0018-inventory-and-telemetry.md) (a hardware report
  of its own beside the hashed inventory; each disk's firmware in the
  inventory; the rule that every new fact carries its state) and
  [ADR-0019](0019-monitoring-and-alerts.md) (an alert kind,
  `disk_health`, with a check per policy; alerts with a subject, one
  per disk). Each gains an *Amended by ADR-0065* line when this is
  implemented. It asks two amendments of proposed ADRs, made in them
  before the slices that would build otherwise (as the
  [plan](../feature-plan-msp.md#what-this-plan-asks-of-the-earlier-adrs)
  requires): [ADR-0053](0053-one-notification-sender.md), whose condition
  filter gains `disk_health` and whose incident and `key` gain the
  alert's subject, before ADR-0053's slice 4 (device alert rules and
  incidents) is built; and [ADR-0060](0060-collecting-logs.md), whose
  `log` policies name their detection in the `check` column this ADR
  adds (at the plan's step 12, before ADR-0060's step 26) rather than in
  a column of their own.
* Builds on: [ADR-0009](0009-agent-protocol.md) (its section "Evolving
  the protocol"), [ADR-0020](0020-windows-agent.md) (the Windows agent
  and the versions it supports), [ADR-0027](0027-agent-updates.md)
  (builds by hash, which can hold a fleet on the build before),
  [ADR-0037](0037-one-licence.md) (permissive dependencies only),
  [ADR-0050](0050-removing-a-device.md) (a device's rows go with it),
  [ADR-0051](0051-hardening-linux-computers.md) (the machine harness,
  `internal/vmtest`),
  [ADR-0064](0064-remote-powershell-management.md) (accepted, not
  built: its slice 1, the plan's step 6, makes the agent keep the
  protocol level of its last heartbeat answer, which this ADR uses; its
  Windows test job runs the agent's tests as LocalSystem on CI's
  runners), and these proposed ADRs:
  [ADR-0054](0054-hardening-windows-computers-and-servers.md) (Windows
  machines under KVM; tests run as LocalSystem),
  [ADR-0058](0058-signed-settings-that-reach-the-agent.md) (settings
  per organization, for later). ADR-0063 (who sees job output) is on a
  branch of its own and not merged, so it is cited without a link; the
  on-demand diagnostics (slice 7) follow its rule for job output.
* Requirements: feature 10, "Hardware Diagnostics and Health
  Monitoring", of the owner's requirements of 2026-11-21
  ([verbatim](../requirements/2026-11-21-msp-features.md#10-hardware-diagnostics-and-health-monitoring)),
  and item 7 of its *Overall Feature Expectations* (healthy, unhealthy,
  unknown, unsupported and unavailable kept apart). Every bullet is
  placed in [The requirements](#the-requirements). The
  [plan for the twelve MSP features](../feature-plan-msp.md#10-hardware-diagnostics-and-health-monitoring)
  lists this as feature 10, step 12 of its
  [order](../feature-plan-msp.md#order), with F1's first part. This ADR
  differs from the plan in five places, each argued where it is
  decided:
  * the states use the requirement's five words, not the plan's "ok,
    warning, failing, unsupported or unreadable": *unhealthy* carries a
    level (*warning* or *failing*), and *unreadable* is split into
    *unknown* and *unavailable*;
  * a virtual machine's disks are judged one by one, by what each disk
    is, not all *unsupported* because the machine is virtual; a
    container's disks are *unavailable*, not *unsupported*;
  * disk temperature comes from the drive's own data on both systems,
    not from Linux's `hwmon`;
  * the alert key gains a subject (one alert per disk), the choice the
    plan left to this ADR;
  * readings come every 30 minutes and are kept for 7 days, then one a
    day for 730 days, where the plan said daily samples only.

## Context
Each claim about the code was checked on `main` at `1c21f6e` for this
ADR. External facts were checked on 2026-11-21 against the sources
linked; what could not be checked says *to be confirmed*.

### What EasyRMM has

* **Disks in the inventory, without health.** The inventory lists each
  disk's name, model, serial, size, kind (`ssd`, `hdd`, `nvme`) and
  whether it is removable, at most 64
  (`internal/agentproto/inventory.go:18,92-101`). The agent collects it
  at start, every hour and after each job, hashes it, and uploads it
  only when the hash differs from the server's
  (`agent/runner/runner.go:103-106,251-280`). The body may be 4 MiB with
  up to 20,000 packages (`internal/agentproto/inventory.go:14-16`).
* **On Windows** the agent opens `\\.\PhysicalDrive0` to `63` with
  `GENERIC_READ` and reads `STORAGE_DEVICE_DESCRIPTOR` and the seek
  penalty through `IOCTL_STORAGE_QUERY_PROPERTY`
  (`agent/inventory/windows.go:124-197`, the open at `:152`). It reads
  the descriptor's vendor, product, serial and bus type, at offsets 12,
  16, 24 and 28, but not the product revision at 20
  (`agent/inventory/windows_parse.go:82-109`). Bus types it names are
  USB, SD, MMC and NVMe (`windows_parse.go:67-73`). The inventory "needs
  no WMI and no PowerShell" (`agent/inventory/windows.go:30-31`), and
  its byte parsers are plain Go, "tested on every platform"
  (`windows_parse.go:11-12`).
* **On Linux** it reads `/sys/block`, skipping loop, RAM, device-mapper,
  MD, optical and similar devices, and takes `device/model` and
  `device/serial` (`agent/inventory/inventory.go:215-252`). It names a
  container from systemd's marker or a container file, and a
  hypervisor from the firmware's strings
  (`agent/inventory/inventory.go:73-90`;
  `agent/inventory/collector.go:49-66`).
* **The rule today is "what cannot be read is left empty"**
  (`agent/inventory/collector.go:6-7`).
* **Privileges.** The Linux agent runs as root from a systemd unit with
  no `User=` and no capability bounds (`agent/host/service.go:135-148`);
  the Windows agent runs as LocalSystem
  ([ADR-0020](0020-windows-agent.md)), which supports Windows 10 and
  Windows Server 2016 and later (ADR-0020, *One agent, built for
  Windows*).
* **The protocol.** The heartbeat carries facts and metrics
  (`internal/agentproto/agentproto.go:125-136`); the server states
  protocol level 2 (`:145-151`). Under ADR-0009's amendment an agent
  sends a request field added after level 2 only while its last
  heartbeat answer came from a server of level 2 or higher, and an
  endpoint the server lacks answers 404, which the agent reads as "not
  supported here" (ADR-0009, *Evolving the protocol*). The agent API's
  catch-all answers 404 (`server/internal/httpapi/agentapi/agentapi.go:218`).
  Signed requests are limited per device to one a second with bursts of
  120, inventories to one in 10 minutes with bursts of 6 (`:76-79`).
* **The server's copy.** `device_inventory` keeps one JSON row per
  device, overwritten on each upload (`server/migrations/00005_inventory.sql:8-15`).
  `cleanInventory` keeps only the fields it knows, so every new agent
  field needs a server change in the same release
  (`server/internal/inventory/service.go:163-239`). Metrics are kept as
  one sample per heartbeat for `EASYRMM_METRICS_RETENTION`, 7 days by
  default (`00005_inventory.sql:45-57`;
  `server/internal/config/config.go:190`). Inventory has no history
  (`IMPLEMENTATION_STATUS.md:150`; ADR-0018, *Consequences*).
* **Alerts.** Policies have four kinds, fixed by a `CHECK`: `offline`,
  `cpu`, `memory` and `disk` (space)
  (`server/migrations/00006_monitoring.sql:19`); a threshold from 1 to
  100, absent only for `offline` (`:20,29`); minutes from 1 to 1,440; a
  severity. Alerts copy the kind (`:94`) and keep a value and the latest
  value, with no other detail (`:101-102`). **At most one unresolved
  alert per policy and device** (`alerts_active_key`, `:117-118`). The
  evaluator runs every minute under an advisory lock
  (`server/internal/monitoring/service.go:20-21`;
  `server/internal/monitoring/evaluate.go:15-17,35-104`); with no
  measurements an alert stays as it is
  (`evaluate.go:271-273`). Policies are written with
  `monitoring.manage` (Site Administrators and above); alerts are read
  with `alert.view` and acknowledged with `alert.manage` (Technicians
  and above) (`server/internal/rbac/rbac.go:48-51,122-150`).
* **Notifications.** EasyRMM's own alerts are not emailed or sent to
  webhooks yet (`IMPLEMENTATION_STATUS.md:148`). ADR-0053 (proposed)
  sends them through device alert rules whose condition filter lists
  offline, processor, memory, disk and *agent removed without a
  request* (ADR-0053, *Device alert rules*), with an incident ID carried
  across a policy change "on the same policy and device, with the same
  kind", and a `key` "the same for every alert of one condition on one
  device". The plan builds ADR-0053's slices 1 to 7 at step 10, before
  this feature's step 12.
* **The console.** The device's Hardware tab has a *Disks* card with
  name, model, type, size and serial
  (`web/src/pages/devices/DeviceHardware.tsx:85-123`). Devices has a
  hardening column and filter, a precedent for a per-device summary
  (`web/src/pages/devices/DevicesPage.tsx:13-14,30`;
  `server/internal/devices/devices.go:153-155,223-234`). The *Device
  health* report covers processor, memory and filesystem use
  (`server/internal/reports/definitions.go:164-181`).
* **Nothing about disk health, sensors, batteries or hardware errors**
  exists in either agent or the server. The survey for the plan searched
  for SMART, NVMe health, `hwmon`, `power_supply`, EDAC, WHEA, battery
  and temperature, and found none.
* **Licences.** CI's licence job allows Go modules under MIT,
  Apache-2.0, BSD-2-Clause, BSD-3-Clause, ISC and MPL-2.0
  (`.github/workflows/security.yml:57-70`). `golang.org/x/sys` is
  already a dependency (`go.mod:17`).
* **Harnesses.** CI's *Agent tests on Windows* runs on `windows-latest`
  (`.github/workflows/backend-tests.yml:63-65`). The machine harness
  boots each distribution's cloud image under QEMU with one
  `virtio-blk` disk and a QMP socket
  (`internal/vmtest/qemu.go:49-90`, the disk at `:70-71`), in CI's
  *Machines* jobs for eight images (`.github/workflows/ci.yml:609-617`).

### What the disks offer

* **NVMe.** The SMART / Health Information log is log page 02h, 512
  bytes. The Linux kernel declares it as `struct nvme_smart_log`:
  critical warning, composite temperature, available spare and its
  threshold, percentage used, data units read and written, host
  commands, busy time, power cycles, power-on hours, unsafe shutdowns,
  media and data integrity errors, error log entries, time over the
  warning and critical temperatures, and eight sensor temperatures; the
  counters are 128-bit little-endian
  ([`include/linux/nvme.h`](https://github.com/torvalds/linux/blob/master/include/linux/nvme.h)).
  The critical warning's bits are spare below threshold (0),
  temperature (1), reliability degraded (2), read-only (3) and volatile
  memory backup failed (4) (same file, `NVME_SMART_CRIT_*`). The
  temperature is in kelvins: the kernel converts it with
  `kelvin_to_millicelsius`
  ([`drivers/nvme/host/hwmon.c`](https://github.com/torvalds/linux/blob/master/drivers/nvme/host/hwmon.c));
  the NVMe specification's own text was not read (*to be confirmed*,
  as is whether percentage used may exceed 100 and the size of a data
  unit). Identify Controller holds the serial, model and firmware
  revision (`sn`, `mn`, `fr`) and the warning and critical composite
  temperature thresholds (`wctemp`, `cctemp`) (`struct nvme_id_ctrl`,
  same file).
* **ATA.** SMART is command B0h. READ DATA (D0h) returns the attribute
  table and READ ATTRIBUTE THRESHOLDS (D1h) the thresholds
  ([`include/linux/ata.h`](https://github.com/torvalds/linux/blob/master/include/linux/ata.h),
  `ATA_SMART_READ_VALUES`, `ATA_SMART_READ_THRESHOLDS`). RETURN STATUS
  (DAh) answers in the LBA Mid and High registers: 4Fh and C2h when no
  threshold is exceeded, F4h and 2Ch when one is
  ([smartmontools `atacmds.cpp`](https://github.com/smartmontools/smartmontools/blob/master/smartmontools/atacmds.cpp),
  `SRET_STATUS_*`; the kernel's `ATA_SMART_LBAM_PASS` and
  `ATA_SMART_LBAH_PASS`). The 512 bytes of SMART data carry a checksum:
  all 512 bytes sum to zero modulo 256 (`checksum()` in the same
  file). IDENTIFY DEVICE says whether SMART is supported (word 82 bit
  0, valid when word 83's bits 15:14 are `01`) and enabled (word 85
  bit 0, valid when word 87's are `01`) (`ataSmartSupport`,
  `ataIsSmartEnabled`, same file). CHECK POWER MODE (E5h,
  `ATA_CMD_CHK_POWER`) answers 00h for standby and FFh for active or
  idle (`ataCheckPowerMode`'s comment, same file). The Device Statistics
  log (log 04h) has standard pages: temperature (05h, with *Current
  Temperature* and *Specified Maximum Operating Temperature*), rotating
  media (03h, *Number of Reallocated Logical Sectors*), general errors
  (04h, *Number of Reported Uncorrectable Errors*) and solid state (07h,
  *Percentage Used Endurance Indicator*)
  ([smartmontools `ataprint.cpp`](https://github.com/smartmontools/smartmontools/blob/master/smartmontools/ataprint.cpp)'s
  table; the ACS standard itself was not read, *to be confirmed*). The
  meaning of an attribute's raw value is the vendor's.
* **Polling and sleep.** smartd checks disks every 1,800 seconds by
  default
  ([`smartd.8.in`](https://github.com/smartmontools/smartmontools/blob/master/smartmontools/smartd.8.in)),
  and its `-n standby` skips a disk in standby or sleep because a check
  "may cause a disk which is spun-down to be spun-up", with a limit on
  how many checks it skips
  ([`smartd.conf.5.in`](https://github.com/smartmontools/smartmontools/blob/master/smartmontools/smartd.conf.5.in)).

**Windows routes**, with no driver of EasyRMM's:

* **NVMe through `IOCTL_STORAGE_QUERY_PROPERTY`.** Microsoft's
  [Working with NVMe drives](https://learn.microsoft.com/en-us/windows/win32/fileio/working-with-nvme-devices)
  ("Applies to: Windows 10, Windows Server 2016") reads the health log
  with `StorageDeviceProtocolSpecificProperty`, `ProtocolTypeNvme`,
  `NVMeDataTypeLogPage` and `NVME_LOG_PAGE_HEALTH_INFO`, and Identify
  with `NVMeDataTypeIdentify`
  ([`STORAGE_PROTOCOL_NVME_DATA_TYPE`](https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ne-winioctl-storage_protocol_nvme_data_type)),
  through the inbox `StorNVMe.sys`. The page says nothing about vendor
  drivers or the handle's access rights. Its pass-through,
  `IOCTL_STORAGE_PROTOCOL_COMMAND`, "should only be used for
  vendor-specific commands".
* **ATA through `IOCTL_ATA_PASS_THROUGH`.** "Applications do not
  require administrative privileges to send a pass-through request to
  a device, but they must have read/write access to the device", and
  the port driver returns the device's output registers in
  `CurrentTaskFile`
  ([IOCTL](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddscsi/ni-ntddscsi-ioctl_ata_pass_through),
  [`ATA_PASS_THROUGH_EX`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddscsi/ns-ntddscsi-_ata_pass_through_ex)).
  `IOCTL_STORAGE_QUERY_PROPERTY` also takes `ProtocolTypeAta` with
  `AtaDataTypeIdentify` and `AtaDataTypeLogPage`
  ([`STORAGE_PROTOCOL_ATA_DATA_TYPE`](https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ne-winioctl-storage_protocol_ata_data_type)),
  which covers IDENTIFY and log pages but not SMART READ DATA or RETURN
  STATUS, which are not log pages.
* **Older routes.** `SMART_RCV_DRIVE_DATA` returns identify data,
  thresholds or attributes from drivers that support it
  ([`SENDCMDINPARAMS`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntdddisk/ns-ntdddisk-_sendcmdinparams)).
  `IOCTL_STORAGE_PREDICT_FAILURE` returns a yes or no and 512
  vendor-specific bytes
  ([IOCTL](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddstor/ni-ntddstor-ioctl_storage_predict_failure)).
* **Temperature.** `StorageDeviceTemperatureProperty` returns sensors
  in degrees Celsius with warning and critical temperatures
  ([`STORAGE_TEMPERATURE_DATA_DESCRIPTOR`](https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ns-winioctl-storage_temperature_data_descriptor));
  Microsoft documents it for NVMe, not for ATA.
* **WMI.** `MSFT_StorageReliabilityCounter` (namespace
  `Root\Microsoft\Windows\Storage`) has temperature, wear, read and
  write error counts, start-stop and load cycles, power-on hours and
  latencies, and **no reallocated or pending sectors**
  ([class](https://learn.microsoft.com/en-us/windows-hardware/drivers/storage/msft-storagereliabilitycounter));
  `Get-StorageReliabilityCounter` is its cmdlet
  ([cmdlet](https://learn.microsoft.com/en-us/powershell/module/storage/get-storagereliabilitycounter)).
  `MSStorageDriver_FailurePredictStatus` in `root\wmi` has no Microsoft
  reference page; the disk class driver sample registers the failure
  prediction GUIDs behind it
  ([`diskwmi.c`](https://github.com/microsoft/Windows-driver-samples/blob/main/storage/class/disk/src/diskwmi.c)).
* **The bus.** `STORAGE_DEVICE_DESCRIPTOR`'s `BusType` is a
  `STORAGE_BUS_TYPE`: SCSI 1, ATA 3, USB 7, RAID 8, iSCSI 9, SAS 10,
  SATA 11, SD 12, MMC 13, Virtual 14, FileBackedVirtual 15, Spaces 16,
  NVMe 17
  ([enum](https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ne-winioctl-storage_bus_type),
  counted from Unknown = 0). Its `ProductRevisionOffset` points at the
  product revision, zero when there is none
  ([descriptor](https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ns-winioctl-storage_device_descriptor)).

**Linux routes:**

* **NVMe** through `NVME_IOCTL_ADMIN_CMD` on the controller's device
  (`/dev/nvmeN`), with Get Log Page (opcode 02h)
  ([`nvme_ioctl.h`](https://github.com/torvalds/linux/blob/master/include/uapi/linux/nvme_ioctl.h)).
  Get Log Page needs `CAP_SYS_ADMIN`: since 6.2 the kernel lets
  unprivileged callers send only some Identify commands
  (`nvme_admin_cmd_allowed` in
  [`drivers/nvme/host/ioctl.c`](https://github.com/torvalds/linux/blob/master/drivers/nvme/host/ioctl.c)).
  `/sys/class/nvme/nvmeX/firmware_rev` holds the firmware "as reported
  in the Identify Controller data structure"
  ([`sysfs-nvme`](https://github.com/torvalds/linux/blob/master/Documentation/ABI/stable/sysfs-nvme)).
* **SATA** through `SG_IO` with ATA PASS-THROUGH (16), opcode 85h,
  which libata translates (`ata_scsi_pass_thru` in
  [`libata-scsi.c`](https://github.com/torvalds/linux/blob/master/drivers/ata/libata-scsi.c);
  `ATA_16` in
  [`scsi_proto.h`](https://github.com/torvalds/linux/blob/master/include/scsi/scsi_proto.h));
  the check-condition bit returns the registers RETURN STATUS answers
  in, as the kernel's own SMART ioctl sets it (same file). A SATA
  disk's `device/rev` is only the last four of its eight firmware
  characters; `device/vpd_pg89` holds the whole IDENTIFY data from byte
  60, and `device/vpd_pg80` the serial page, each only when the page
  exists (`libata-scsi.c`;
  [`scsi_sysfs.c`](https://github.com/torvalds/linux/blob/master/drivers/scsi/scsi_sysfs.c)).
* **`hwmon`.** The kernel's NVMe driver publishes the composite
  temperature since 5.5, behind the `NVME_HWMON` option, reading the
  same health log (`hwmon.c`, above). `drivetemp` (5.6) reads SATA
  temperatures through SCT or SMART and "may reset the spin down timer
  on some drives"
  ([`drivetemp.rst`](https://github.com/torvalds/linux/blob/master/Documentation/hwmon/drivetemp.rst));
  that it is not loaded on its own is an inference from its source
  (*to be confirmed*).
* **`virtio-blk`** has no SCSI, SMART or ioctl path for health
  ([`virtio_blk.c`](https://github.com/torvalds/linux/blob/master/drivers/block/virtio_blk.c)).

**Libraries and tools:**

* **smartmontools** is GPL-2.0-or-later (`atacmds.cpp`'s SPDX line) and
  has printed JSON since 7.0 (2018-12-30)
  ([`NEWS`](https://github.com/smartmontools/smartmontools/blob/master/smartmontools/NEWS)).
  Its drive database is part of it, under the same licence.
* **Go libraries.** [`anatol/smart.go`](https://github.com/anatol/smart.go)
  is MIT and reads SATA, SCSI and NVMe on Linux and NVMe on macOS
  through cgo, and nothing on Windows.
  [`dswarbrick/smart`](https://github.com/dswarbrick/smart) is
  Apache-2.0, Linux only, "in the early stages of development", last
  changed 2023-06-25.

**Emulated disks** (QEMU
[v11.1.3](https://github.com/qemu/qemu/tree/v11.1.3)):

* **NVMe** (`-device nvme`) answers the health log with a critical
  warning, a composite temperature of 323 K, data units, host commands
  and power-on hours since the device started; available spare,
  percentage used and media errors are always zero
  ([`hw/nvme/ctrl.c`](https://github.com/qemu/qemu/blob/v11.1.3/hw/nvme/ctrl.c),
  `nvme_smart_info`). `smart_critical_warning` is a property that
  `qom-set` changes on a running machine (same file; commit
  [`4714791`](https://github.com/qemu/qemu/commit/4714791b66ae39bea6b6e3c3e84aaed8dcb005c7)).
  Its default model is *QEMU NVMe Ctrl*, which the `model` property
  changes
  ([`nvme.rst`](https://github.com/qemu/qemu/blob/v11.1.3/docs/system/devices/nvme.rst)).
* **ATA** (`ide-hd` on an AHCI controller) answers SMART READ DATA,
  READ THRESHOLDS, RETURN STATUS and READ LOG 01h, with attributes 1,
  3, 4, 5, 9, 12 and 190 (31 °C), and CHECK POWER MODE; RETURN STATUS
  always passes and nothing injects a failure; there is no READ LOG EXT
  ([`hw/ide/core.c`](https://github.com/qemu/qemu/blob/v11.1.3/hw/ide/core.c)).
  Its default model is *QEMU HARDDISK*, which `model` changes
  ([`ide-dev.h`](https://github.com/qemu/qemu/blob/v11.1.3/include/hw/ide/ide-dev.h)).
* **`scsi-disk`** and `usb-storage` refuse ATA PASS-THROUGH with
  *invalid opcode*
  ([`hw/scsi/scsi-disk.c`](https://github.com/qemu/qemu/blob/v11.1.3/hw/scsi/scsi-disk.c)).
* **CI's runners.** GitHub documents the runners' disks only as "SSD"
  of a size; what model and bus Windows sees there is not documented
  (*to be confirmed* on the runner). Linux runners may run on AWS or
  Azure; KVM is usable after a udev rule
  ([runners](https://docs.github.com/en/actions/concepts/runners/github-hosted-runners);
  [changelog](https://github.blog/changelog/2024-04-02-github-actions-hardware-accelerated-android-virtualization-now-available/)).

## Decision

### In short
* **Slice 1 reads disk health, read-only**: the NVMe health log and
  ATA SMART on Windows and Linux, from the agent's own Go code through
  the operating system's storage interfaces: on Windows
  `IOCTL_STORAGE_QUERY_PROPERTY` for NVMe and `IOCTL_ATA_PASS_THROUGH`
  for ATA; on Linux `NVME_IOCTL_ADMIN_CMD` and `SG_IO` with ATA
  PASS-THROUGH (16). No WMI, no PowerShell, no smartctl, no driver, no
  new library. One parser serves both systems.
* **Every fact has one of five states**, *healthy*, *unhealthy*
  (*warning* or *failing*), *unknown*, *unsupported* or *unavailable*,
  each with a reason, and a fact EasyRMM does not judge is *reported*.
  A disk is *healthy* only after a complete, checked reading in the
  last two hours that finds nothing. This is F1's rule, which every
  part of F1 uses.
* **Readings every 30 minutes**, in a report of their own to a new
  endpoint, never in the heartbeat or the hashed inventory. Sleeping
  disks are not woken, except once a day.
* **The server judges**: the agent reports what it read; the server
  applies one table of rules, so the rules change without an agent
  update.
* **History**: every reading for 7 days, then one a day per disk for
  730 days.
* **Alerts**: a new kind, `disk_health`, with four checks (failing,
  errors, wear, temperature), one alert per disk through a subject on
  `alerts_active_key`; notifications through ADR-0053.
* **Disk firmware** in the inventory, as F1's first fact under its
  rule.
* **The console**: health on the Disks card, each disk's facts and
  history, a column and filter on Devices.

### The five states (F1's rule)
*Decided in review.*

The requirement asks that healthy, unhealthy, unknown, unsupported and
unavailable be kept apart, and that no drive read as healthy because
its data could not be read. These are the states for every fact
EasyRMM reports from now on: each health fact, each disk, and each new
fact of F1's later parts (SMBIOS identifiers, TPM and Secure Boot, the
domain-controller role).

| State | When | Example reasons |
|---|---|---|
| **Healthy** | Read in this reading, checked, and within every rule | — |
| **Unhealthy**, *warning* | Read and checked, and a rule for degradation holds | Pending sectors 8; 91% of rated endurance used; 61 °C, over the drive's 60 °C |
| **Unhealthy**, *failing* | Read and checked, and the drive's own verdict fails | SMART status: threshold exceeded; NVMe: media in read-only mode |
| **Reported** | Read, and EasyRMM does not judge it | Firmware, power-on hours, data written |
| **Unknown** | EasyRMM could read it here, and this time it could not tell | Timed out; I/O error; checksum wrong; asleep, not woken; not read for over 2 hours |
| **Unsupported** | The disk, by what it is, has no such data | A virtual disk; an SD card; a USB bridge that refuses SMART commands; the drive does not keep this attribute |
| **Unavailable** | The data exists, but EasyRMM cannot reach it from where the agent runs | Behind a hardware RAID controller; a storage driver that refuses health queries; the agent runs in a container; SMART turned off on the drive; SAS, not read yet |

* **The difference between the last three** is what can change it:
  *unknown* may clear at the next reading; *unavailable* needs
  something else in place (the controller's own tools, another driver,
  a later slice of EasyRMM); *unsupported* never changes for that disk.
* **A disk's state** is the worst of its judged facts, in the order
  *failing*, *warning*, *unknown*, *healthy*, unless the disk as a
  whole was *unsupported* or *unavailable*, which then is its state. A
  fact the drive does not keep (an NVMe drive has no pending sectors)
  is *unsupported* and does not make the disk *unknown*. A judged fact
  that could not be read does: a disk whose verdict could not be read
  is *unknown*, never *healthy*, whatever else was read.
* **Healthy needs the verdict.** For NVMe it is the critical warning
  of the health log. For ATA it is SMART RETURN STATUS or, where a
  path does not return the registers, the attribute values against
  their thresholds, as smartmontools falls back; without either the
  disk is *unknown*.
* **Stale is unknown.** The server shows a disk whose last complete
  reading is more than 2 hours old (four missed readings) as *unknown:
  not read since …*, with its last values and their time. An offline
  device's disks become *unknown* the same way; the offline alert is
  ADR-0019's business.
* **On the wire** a fact is an object, `{"state": …, "reason": …,
  "value": …}`. Reasons are fixed codes from a list the server knows
  (`virtual_disk`, `raid_controller`, `storage_driver`, `container`,
  `smart_off`, `usb_bridge`, `protocol_not_read`, `not_kept`, `asleep`,
  `timeout`, `io_error`, `access_denied`, `bad_checksum`, `stale` and
  the like), shown in words by the console. The health report may add
  a short detail (a Windows error number); the inventory never does, so
  its hash stays stable.
* **Old fields keep the old rule.** The inventory's existing fields
  stay as they are, empty when unread; changing their encoding would
  break every older server. New facts follow this rule.

### Which disks, and what each is
*Decided in review.*

The agent reads the disks the inventory lists, and decides first, per
disk, whether there is health to read. **A virtual machine's disks are
judged one by one**, not all *unsupported* because the machine is
virtual as the plan had it: a physical NVMe drive passed through to a
virtual machine has a real health log, and calling it *unsupported*
would hide it.

| The disk | State before any read | How it is known |
|---|---|---|
| Any disk, when the agent runs in a container | *Unavailable* (`container`) | The inventory's container detection (`inventory.go:73-90`) |
| A hypervisor's emulated disk | *Unsupported* (`virtual_disk`) | Windows bus types Virtual (14) and FileBackedVirtual (15); Linux `virtio_blk` and Xen's `xvd` devices; models of emulated disks (*QEMU HARDDISK*, *QEMU NVMe Ctrl*, *Msft Virtual Disk*, *VMware Virtual*, *VBOX HARDDISK* and the like, a list in the agent) |
| A Storage Spaces virtual disk (Windows bus type 16) | *Unsupported* (`storage_spaces`) | Bus type; whether its member disks are still visible to be read is *to be confirmed* |
| A logical volume of a hardware RAID controller | *Unavailable* (`raid_controller`) | Windows bus type RAID (8); on Linux, a SCSI host driven by a RAID driver (`megaraid_sas`, `hpsa`, `smartpqi`, `aacraid` and the like, a list in the agent; the sysfs attribute that names the driver is *to be confirmed*) |
| SAS, Fibre Channel, iSCSI and other SCSI disks | *Unavailable* (`protocol_not_read`) | Bus type, or a SCSI disk that refuses ATA PASS-THROUGH; SCSI's own health pages are a later slice |
| SD and MMC cards | *Unsupported* | Windows bus types 12 and 13; Linux `mmcblk` |
| NVMe | Read (below) | Windows bus type 17; Linux `nvme` devices |
| SATA and ATA, also behind a host bus adapter | Read | Windows bus types 3 and 11; on Linux a disk behind libata or an HBA that answers ATA PASS-THROUGH |
| USB disks | Read where the bridge passes ATA commands; otherwise *unsupported* (`usb_bridge`) | The bridge's answer: an *invalid opcode* is a definite no |

* **After a read fails**, the answer decides: "not supported" from the
  driver or the device makes the disk *unsupported* (a device's own
  refusal) or *unavailable* (a driver on the way refused); any other
  error makes it *unknown*. On a machine the inventory names as
  virtual, a failed read makes the disk *unsupported*
  (`virtual_machine`), never *unknown*, for hypervisors the list does
  not name.
* **An emulated disk with a model changed by hand** is read as what it
  says it is. QEMU's values are made up (the same temperature always,
  wear always zero), so such a disk could read as *healthy*. The guide
  says so; the machine tests use exactly this to read through the
  kernel (*Testing*), and say they do.

### Reading on Windows
*Decided in review.*

* **NVMe**: `IOCTL_STORAGE_QUERY_PROPERTY` with
  `StorageDeviceProtocolSpecificProperty`, `ProtocolTypeNvme`, as
  Microsoft's page shows: `NVMeDataTypeLogPage` for the health log,
  `NVMeDataTypeIdentify` (controller) for the temperature thresholds and
  the drive's own model and serial. The page names
  `StorageAdapterProtocolSpecificProperty` for requests to the
  controller; slice 1 uses the form the page's example uses and tries
  the adapter form only where the device form is refused, recording
  which answered, so the choice rests on real drivers' answers.
* **ATA**: `IOCTL_ATA_PASS_THROUGH` on a handle opened for reading and
  writing, which LocalSystem can open, carrying only the read-only
  commands listed below. The same commands, and the same 512-byte
  answers, as on Linux.
* **Why not the others**:
  * **WMI** (`MSFT_StorageReliabilityCounter`): the inventory's rule is
    no WMI (`windows.go:30-31`; the plan's F1), the plan allows one
    exception and only for BitLocker's class (feature 8), and the class
    has no reallocated or pending sectors, which the requirement names.
    It would be a second, poorer source beside the IOCTLs for NVMe.
  * **PowerShell** (`Get-StorageReliabilityCounter`): a process every 30
    minutes on every computer, the same class's data, and against the
    plan's rule for routine facts.
  * **`SMART_RCV_DRIVE_DATA`** gives attributes but not the RETURN
    STATUS registers, and depends on each driver keeping an old
    interface; **`IOCTL_STORAGE_PREDICT_FAILURE`** gives only a yes or
    no and vendor bytes; **`ProtocolTypeAta`** gives IDENTIFY and logs
    but not SMART READ DATA. One pass-through path carries all of them.
  * **`StorageDeviceTemperatureProperty`** is a second source for a
    temperature the health log and Device Statistics already hold.
* **What stays unverified** until real computers show it: whether the
  protocol-specific query needs more than the inventory's read-only
  handle; which vendor NVMe drivers (Samsung's, Intel RST and its VMD
  mode, common on recent laptops) answer it; whether `IOCTL_ATA_PASS_THROUGH`
  passes through Intel RST in RAID mode and through USB bridges on
  Windows. Each driver that refuses makes its disks *unavailable*
  (`storage_driver`) with the driver's error, never *unknown* every
  half hour.

### Reading on Linux
*Decided in review.*

* **NVMe**: `NVME_IOCTL_ADMIN_CMD` on `/dev/nvmeN`, the controller of
  each `nvmeNnM` the inventory lists, with Get Log Page 02h for the
  whole controller and Identify Controller. Root holds `CAP_SYS_ADMIN`;
  should the agent's unit ever drop it, Get Log Page fails with
  `EACCES`, which is *unavailable* (`access_denied`), and the guide
  says why.
* **SATA**: `SG_IO` with ATA PASS-THROUGH (16) and the check-condition
  bit, on the disk's `/dev/sdX`. Disks behind an HBA in pass-through
  (IT) mode answer the same way.
* **Not `hwmon`.** The plan said temperature from `hwmon`. The NVMe
  sensor there reads the health log the agent already reads, behind a
  kernel option; `drivetemp` covers SATA only where it is loaded and may
  reset a drive's spin-down timer. The drive's own data gives the same
  value on both systems from one parser, so `hwmon` would be a second
  path for it. `hwmon` comes with the thermal slice, for what only it
  holds.
* **Not smartctl** now: it is a package most installations lack, its
  JSON would be a third parser, and the IOCTLs already reach every disk
  smartctl reaches without a controller's own pass-through. Where it
  adds reach, behind RAID controllers (`-d megaraid`, `-d cciss`), it
  is weighed with RAID in a later slice, used only where an operator
  installed it, never bundled.

### One parser, and no library
*Decided in review.*

* **The agent's own Go code**, in a package of its own (`agent/hardware`,
  which later slices extend), with `golang.org/x/sys`, already a
  dependency. The transports are small (a few IOCTLs on each system);
  the parsers read fixed structures: the 512-byte health log, Identify
  Controller's few fields, IDENTIFY DEVICE, the 512 bytes of SMART data
  and thresholds, and Device Statistics pages. They are plain Go,
  tested on every platform with captured bytes, as the inventory's
  `parseSMBIOS` is.
* **Not `anatol/smart.go`** (MIT, so allowed): it has no Windows, so
  Windows would need its own reader anyway, and the same bytes would
  then be parsed by two codes. **Not `dswarbrick/smart`**: Linux only,
  early, not maintained since 2023. **Never smartmontools' code or its
  drive database** (GPL).
* **Read-only commands only, enforced.** The transport accepts only
  this list and refuses anything else, tested: ATA IDENTIFY DEVICE
  (ECh), CHECK POWER MODE (E5h), SMART READ DATA (B0h/D0h), SMART READ
  ATTRIBUTE THRESHOLDS (B0h/D1h), SMART RETURN STATUS (B0h/DAh), SMART
  READ LOG (B0h/D5h) for the summary error log, READ LOG EXT (2Fh) for
  the log directory and Device Statistics; NVMe Identify (06h) and Get
  Log Page (02h). Never SMART ENABLE, self-tests, SCT (which writes a
  log to send its command), Set Features, or anything that writes.
* **Every command has a deadline**: 10 seconds in `SG_IO`'s and NVMe's
  timeout fields and `ATA_PASS_THROUGH_EX`'s; Windows' protocol-specific
  query has none, so it runs on a goroutine of its own and the disk is
  *unknown* (`timeout`) after 30 seconds. A disk whose call has not
  returned is not asked again until it does.

### What is read
*Decided in review.*

| Fact | NVMe | ATA | Judged |
|---|---|---|---|
| Verdict | Critical warning bits 0, 2, 3, 4 | SMART RETURN STATUS; attributes against thresholds where status is not returned | Yes: *failing* |
| Temperature (°C) | Composite temperature | Device Statistics *Current Temperature*, else attribute 194 or 190's low byte | Yes |
| The drive's temperature limit (°C) | `wctemp` from Identify Controller | Device Statistics *Specified Maximum Operating Temperature* | Used by the temperature rule |
| Wear (% of rated endurance used) | Percentage used | Device Statistics *Percentage Used Endurance Indicator* | Yes |
| Available spare and its threshold (%) | Health log | — | Through bit 0 |
| Media errors | Media and data integrity errors | — | Yes |
| Reallocated sectors | — | Attribute 5, or Device Statistics' count | Yes |
| Pending sectors | — | Attribute 197 | Yes |
| Uncorrectable sectors | — | Attribute 198 | Yes |
| Reported drive errors | Error information log entries | The summary SMART error log's count (its offset *to be confirmed* against ACS) | Reported |
| Power-on hours | Health log | Device Statistics, else attribute 9 | Reported |
| Data written | Data units written | — | Reported |
| Unsafe shutdowns | Health log | — | Reported |
| Every attribute | — | ID, flags, value, worst, threshold, raw (48 bits) | Pre-fail ones in the verdict |
| Model, serial | Identify Controller | IDENTIFY DEVICE | Identity |

* **Raw values are read only where their meaning is common to the
  makers** (the counts of 5, 197 and 198, 194 and 190's temperature, 9's
  hours), and the attribute table is shown whole for the rest. Vendors'
  own attributes for SSD wear (Samsung's, Intel's, Micron's) are not
  interpreted in slice 1: a SATA SSD without the Device Statistics page
  shows wear as *unsupported* (`not_kept`). Interpreting them later is
  done from each vendor's documents, never from smartmontools' GPL
  database.
* **Firmware** is the inventory's (below), not the report's, so it has
  one source.

### The disk's state: the server's rules
*Decided in review.*

The agent reports facts and how each was read; **the server judges**,
with one table, so that a rule changes without an agent update and is
tested once. The defaults of the alert policies (below) are the same
numbers.

| Level | Rule |
|---|---|
| *Failing* | NVMe critical warning bit 0 (spare below threshold), 2 (reliability degraded), 3 (read-only) or 4 (volatile memory backup failed); ATA SMART status *threshold exceeded*, or a pre-fail attribute at or below its non-zero threshold |
| *Warning* | Any reallocated, pending or uncorrectable sector, or any NVMe media error; wear at 90% or more; temperature at or above the drive's own limit, or NVMe critical warning bit 1; an ATA attribute that is not pre-fail at or below its threshold |
| *Healthy* | The verdict read, every judged fact the drive keeps read, none of the above |

### When it reads
*Decided in review.*

* **Every 30 minutes**, smartd's default, with up to a minute of jitter,
  and once 2 minutes after the agent starts. Counters change slowly; a
  temperature alert needs more than one reading (below).
* **On a goroutine of its own**, not in the heartbeat's loop, so a slow
  disk never delays a heartbeat.
* **Sleeping disks are not woken.** An ATA disk that CHECK POWER MODE
  says is in standby is skipped: *unknown* (`asleep`), and the server
  keeps showing its last values with their time. After 24 hours of
  skipping, the agent reads it once, waking it, so a disk that always
  sleeps (a backup disk) is still checked daily. NVMe drives have no
  spin-up; a read may bring one out of a low-power state for a moment,
  as smartd's does.
* **No queue.** A reading that cannot be sent is dropped; the next one
  is 30 minutes later. History has a gap while the device is offline,
  shown as one.

### The report
*Decided in review.*

* **A report of its own**: `POST /api/agent/v1/hardware`, signed like
  every agent request, with the disks and their facts (later slices add
  batteries, sensors and errors to the same report). Not in the
  heartbeat, which stays small and whose failures stay as they are;
  **not in the hashed inventory**, whose hash would then change every
  half hour and send up to 4 MiB again.
* **Size.** About 0.8 KiB for an NVMe disk and 2.5 KiB for an ATA disk
  with 30 attributes (estimates, measured in slice 1); at most 64
  disks, so the body limit is 256 KiB. The heartbeat gains nothing; the
  inventory gains about 40 bytes a disk. A device with two disks sends
  about 5 KiB every 30 minutes, 240 KiB a day; 10,000 devices send
  about 5.6 reports a second, against 167 heartbeats a second.
* **A limit per device** beside the existing ones: one report in 10
  minutes with bursts of 6, as inventories have.
* **ADR-0009.** A new endpoint: a server without it answers 404, and
  the agent drops that reading and tries again at the next. The body
  is new, so no level rule applies to it; a later agent's new facts are
  named entries the server ignores when it does not know them. The
  server's protocol level stays 2. Nothing is sent to the agent, so no
  instruction or capability is needed.
* **Agents that report nothing** (older ones, or before the first
  reading) show *Not reported* with the agent's version, never a guess.
* **The server cleans every report** as `cleanInventory` does: text cut
  to size, numbers held to physical bounds (a temperature from −40 to
  150 °C, a percentage from 0 to 255, counts within 2⁶²), unknown states
  and reasons made *unknown* (`invalid_report`). The disk's identity
  for alerts is made on the server: the first 16 bytes of the SHA-256 of
  the drive's model and serial, in hex; a disk without a serial gets
  one from its name, marked as unstable.

### Disk firmware in the inventory (F1's first part)
*Decided in review.*

* **Each disk gains `firmware`**, a fact under the rule above, in the
  hashed inventory, since it changes only with a firmware update:
  * Windows: the descriptor's `ProductRevisionOffset` (byte 20), beside
    the offsets already read;
  * Linux NVMe: `/sys/class/nvme/nvmeX/firmware_rev`;
  * Linux SATA: the eight characters in `device/vpd_pg89`'s IDENTIFY
    data, not `device/rev`'s four; other SCSI disks: `device/rev`.
  Whether the descriptor gives a SATA drive's whole revision on Windows
  is *to be confirmed* on a real disk.
* **The serial gap on Linux**: where `device/serial` is missing, the
  serial comes from `vpd_pg89` (SATA) or `vpd_pg80` (other SCSI), as
  the plan's survey suspected; *to be confirmed* on a real SATA disk.
* `cleanInventory` keeps the field in the same release; the agent sends
  it only while its last heartbeat answer was of level 2 or higher
  (ADR-0009), using the level ADR-0064's slice 1 makes the agent keep.
  Every device uploads its inventory once after the update, since its
  document changed.

### Data model and retention
*Decided in review.*

* **`device_disk_health`**: the latest reading per disk: the device, the
  disk's identity and name, protocol, model and serial, the state, level
  and reason, the facts as JSON, when the agent read it and when the
  server received it. The disks a report no longer lists are deleted
  with it (a disk removed or replaced).
* **`device_disk_health_samples`**: one row per disk per reading, with
  the state and level, temperature, wear, the error counts and power-on
  hours. Kept at full resolution for `EASYRMM_METRICS_RETENTION` (7
  days by default), then thinned by the hourly purge to one row per
  disk per day (the day's last, in UTC, with the day's highest
  temperature), kept for `EASYRMM_HARDWARE_RETENTION`, **730 days by
  default**, at least 30. Disks wear over years; two years shows a
  trend and a replacement.
* **Size**, estimated at about 200 bytes a row with its index: 336 rows
  for the week and 730 for the two years, about 0.2 MiB per disk;
  1,000 devices with two disks about 0.4 GiB. Measured with
  `tools/agentsim` in slice 1, the numbers in its pull request.
* **Row-level security** as the inventory's: read through the device
  (`00005_inventory.sql:62-68`), written only by the agent API and the
  purge with the system scope.
* **A device's removal** removes its rows (`ON DELETE CASCADE`,
  ADR-0050). Keeping a disk's history past its device is feature 1's
  asset record, not this.

### Alerts
*Decided in review.*

* **A new kind, `disk_health`**, with a **check** per policy, in a new
  column `check` on policies (`NULL` for the other kinds), copied to
  the alert:

  | Check | Opens when | Threshold | Default shared policy |
  |---|---|---|---|
  | `failing` | The disk's level is *failing* | None | *Disk failing*, critical |
  | `errors` | Reallocated, pending or uncorrectable sectors, or media errors, at or above the threshold | A count, 1 to 100 | *Disk errors*, 1, warning |
  | `wear` | Wear at or above the threshold | A percentage, 1 to 100 | *Disk wearing out*, 90, warning |
  | `temperature` | Every reading in the policy's minutes at or above the threshold, at least two | °C, 1 to 100, or none for the drive's own limit | *Disk too hot*, the drive's limit, 60 minutes, warning |

  The existing threshold column (1 to 100) fits all four; its `CHECK`
  that only `offline` has no threshold gains `failing` and the
  temperature check's *drive's own limit*. Minutes apply to temperature
  only (at least 30, the reading interval).
* **One alert per disk.** `alerts_active_key` allows one open alert per
  policy and device (`00006_monitoring.sql:117-118`), so two failing
  disks would share one alert, and acknowledging a worn disk would
  silence a failing one beside it. **Alerts gain a subject**: `subject`
  (the disk's identity, empty for the other kinds), `subject_label`
  ("PhysicalDrive1 · Samsung SSD 870 EVO 1TB") and `detail` ("Pending
  sectors 8, reallocated 0"), and the key becomes (policy, device,
  subject). The plan left this choice to this ADR for every new kind
  ([Notifications](../feature-plan-msp.md#notifications-for-every-new-alert-kind));
  feature 12's detection counted per domain and account needs a subject
  either way. This ADR builds the columns and the key; alerts without a
  device, which feature 12's needs, are that feature's change.
* **The value** is the count, percentage or temperature that opened the
  alert (1 for `failing`), updated as for other kinds.
* **Resolving.** A fresh reading where the condition no longer holds
  resolves it (`cleared`). A disk that a report no longer lists
  resolves it as `subject_gone`, a new resolution. An *unknown*,
  *unavailable* or stale reading changes nothing: the alert stays as
  it is, as metric alerts do without measurements
  (`evaluate.go:271-273`), and nothing opens on one.
* **Counters do not go down.** A disk with reallocated sectors keeps
  them; resolving its alert by hand opens it again at the next
  evaluation while the count holds. The console says to acknowledge it
  instead; rising counts are slice 6's degradation alerts.
* **Evaluated in `monitoring.Evaluate`**, each minute, under its lock,
  from `device_disk_health` and the samples, with the policies'
  coverage and reconciliation as for every kind.
* **Added by a migration** as shared policies, turned on, as migration
  00006 added the first four (owner question 2).

### Notifications
*Decided in review.*

* **Through ADR-0053's rules**, built at the plan's step 10, before
  this. Its condition filter gains `disk_health`, with the check as a
  second choice ("any", or a list of checks), as ADR-0060 adds `log`
  and its detection.
* **ADR-0053's incident and `key` gain the subject**: an incident
  carries over "on the same policy and device, with the same kind" and
  subject; `key` is the same for every alert of one condition on one
  device and subject. ADR-0053 is amended so before its slice 4 (device
  alert rules, the planner and incidents) is built, at the plan's step
  10, so its planner is built with subjects rather than changed after.
* **Content** follows ADR-0053's rules: the subject label and detail
  are agent text, cleaned, clipped and defanged; no serial number in a
  message (the console shows it).
* **Until ADR-0053's slice 4**, if this is built first, the alerts show
  in the console only.

### Permissions, audit and tenants
*Decided in review.*

* **Reading health** needs `device.view` at the device's site, as its
  inventory does: Read-Only included. It holds no secret; serials are
  already shown.
* **Policies** need `monitoring.manage` at their level; **alerts**
  `alert.view` and `alert.manage`, as now. No new permission in slice 1.
* **Audit**: policy changes are recorded as they are now. A reading is
  not recorded, as an inventory upload is not: the agent does it on its
  own, read-only. On-demand diagnostics (slice 7) are actions on a
  device and are recorded.
* **Tenants**: every new table is scoped through its device under
  row-level security; alerts and notifications are scoped as now.

### The console
*Decided in review.*

* **The Disks card** gains *Firmware* and *Health*: a state with its
  level and reason ("Unavailable: behind a RAID controller"), and when
  it was read.
* **A disk's panel**: every fact with its state and reason, the ATA
  attribute table, the last 30 days (highest temperature, wear and
  error counts per day), and the disk's open alerts. Charts are slice 6.
* **Devices** gains a *Disk health* column, the device's worst disk,
  and a filter (*Failing*, *Warning*, *Unknown*, *Healthy*, *Not
  read*), as hardening's.
* **The policy form** gains the kind and its check, with the threshold
  each check takes.
* **Words for every state**, the same in the console and the guide; a
  page in the operations guide lists what each system supports and
  what each reason means, with "many servers show *Unavailable* until
  RAID controllers are read" said plainly.

### Not chosen
*Decided in review.*

* **WMI or PowerShell on Windows**: above.
* **smartctl now**, or **smartmontools bundled**: above; bundling is
  ruled out by its licence.
* **A Go SMART library**: none covers Windows.
* **`hwmon` for disk temperatures**: a second path for the same value.
* **Health in the heartbeat**: a minute's cadence for half-hourly data,
  and a heavier heartbeat for every device.
* **Health in the hashed inventory**: a changed hash every reading.
* **The agent judging**: rules would need an agent update to change,
  and two versions would judge differently.
* **Every disk of a virtual machine *unsupported***: hides passed-through
  drives.
* **One alert per policy and device naming every disk**: an
  acknowledgement would cover disks it was never about.
* **Waking sleeping disks at every reading**: spins up disks every half
  hour.
* **A switch to turn readings off** in slice 1: no setting reaches the
  agent before ADR-0058; until then an MSP that must stop them holds
  its agents on the build before through ADR-0027's builds by hash.
  ADR-0058's catalogue gains a key when it is built.

### What this does not fix
* **Disks behind hardware RAID** stay *unavailable* until a later slice
  reads them through their controllers; on servers that is most disks.
* **SAS and other SCSI disks** stay *unavailable* until SCSI's own
  pages are read.
* **Vendor storage drivers that refuse** the queries leave their disks
  *unavailable*; EasyRMM does not replace drivers.
* **SMART predicts some failures, not all**: a *healthy* disk can still
  fail without warning. The guide says so.
* **A hypervisor's disk with a changed model** reads as what it claims.

## The requirements
Feature 10, bullet by bullet. Slices are those [below](#slices).

| Requirement | Where | Status after this ADR |
|---|---|---|
| **Storage**: SMART health information | Slice 1 | ATA verdict and attributes; NVMe health log |
| Drive temperature | Slice 1 | From the drive, both systems |
| Drive model and serial number | Exists (inventory); slice 1 | The drive's own identity in the report; Linux's empty SATA serials filled |
| Drive firmware | Slice 1 | In the inventory, under F1's rule |
| Reported drive errors | Slice 1 | NVMe error log entries; ATA error log count; reported, judged when rising (slice 6) |
| Media errors | Slice 1 | NVMe media errors; ATA uncorrectable sectors |
| Reallocated sectors where available | Slice 1 | ATA; *unsupported* on NVMe |
| Pending sectors where available | Slice 1 | ATA; *unsupported* on NVMe |
| NVMe health information | Slice 1 | The whole health log |
| NVMe percentage used | Slice 1 | Judged at 90% |
| SSD wear indicators | Slice 1 | NVMe percentage used and spare; SATA Device Statistics; vendors' own attributes later |
| Identify drives reporting warnings or failures | Slice 1 | States, `disk_health` alerts, Devices filter |
| **Memory**: installed memory information | Exists; slice 2 | Total today; modules in slice 2 |
| Memory module details | Slice 2 | SMBIOS type 17 |
| Memory capacity and speed | Slice 2 | Per module |
| Memory hardware error reporting | Slice 4 | EDAC counts; WHEA counts |
| Windows hardware error reporting | Slice 4 | WHEA events counted, linked to feature 9 |
| ECC error information where available | Slices 2 and 4 | ECC type from SMBIOS type 16; corrected and uncorrected counts from EDAC |
| **Thermal**: CPU temperature where exposed | Slice 5 | Linux `hwmon`; Windows *unavailable* without a driver (owner question 3) |
| GPU temperature where available | Slice 5 | Linux `hwmon` where the GPU's driver publishes it; Windows through the display driver's interface if a service can read it; otherwise *unavailable* |
| System temperature | Slice 5; slice 8 on servers | Thermal zones, `hwmon`; management controllers |
| Thermal throttling indicators | Slice 5 | Linux's Intel throttle counters; Windows only what is exposed without a driver |
| Fan health and speed where available | Slice 5; slice 8 on servers | `hwmon` fans; management controllers |
| **Battery**: health, design and full-charge capacity, wear, cycles, charging status | Slice 3 | Both systems |
| Batteries approaching end-of-life | Slice 3 | A `battery` alert kind |
| **General**: CPU model, core count, BIOS version and date, manufacturer and model | Exists | `internal/agentproto/inventory.go:62-81` |
| Memory configuration | Slice 2 | Modules, slots, ECC |
| Motherboard information | Slice 2 | SMBIOS type 2 |
| Firmware versions | Exists (BIOS); slice 1 (disks); later | TPM's with feature 8's F1 part; controllers' with slice 8 |
| **Considerations**: availability varies by maker and model | Every slice | Five states with reasons |
| SMART not equally available | Slice 1 | Classification of disks |
| Elevated privileges | Slice 1 | Root and LocalSystem already; what each read needs, above |
| Distinguish unavailable from failures | Slice 1 | F1's rule |
| No drive healthy because SMART could not be read | Slice 1 | Healthy only after a complete, checked, recent reading |
| Track historical health changes | Slice 1; slice 6 | Samples and daily history from slice 1; charts in slice 6 |
| Alerts for significant degradation | Slice 1; slice 6 | Thresholds now; rising counts and falling capacity in slice 6 |

Power supplies, vendor tools and on-demand diagnostics are not named in
the requirement's bullets; they serve its goal ("identify failing or
degrading hardware before it causes an outage") and are slices 7 and 8.

## Slices
Each merges and is verified on its own, at every level it touches.
Slice 1 is step 12 of the plan's order; the rest are its step 28, in
this order, each when its inputs exist.

1. **Disk health, read-only, with F1's first part.** Everything under
   *Decision*: the five states and their encoding, disk firmware in the
   inventory, the readers on both systems, the report and its endpoint,
   the tables and retention, `disk_health` with its four checks and
   subjects on alerts, the console's card, panel, column, filter and
   policy form, and the guide. First because a failing disk is the
   failure most worth predicting, it works on both systems, and it
   needs no driver and nothing from outside. Two pull requests: the
   server, protocol and console (tested with the simulated agent),
   then the agent's readers.
2. **SMBIOS details.** Memory modules (type 17: size, speed, type,
   maker, part number, slot), the memory array and its ECC type (16),
   the baseboard (2) and processors (4), through F1's parser, which
   feature 4's and feature 1's slices extend first (the plan's step
   14); on Linux from `/sys/firmware/dmi/tables/DMI`. Slow facts, in
   the hashed inventory, under F1's rule.
3. **Battery.** Design and full-charge capacity, wear, cycles, charging
   status and AC power: on Windows `IOCTL_BATTERY_QUERY_INFORMATION`
   (`BATTERY_INFORMATION`: designed and full-charged capacity, cycle
   count, zero when not counted) and `IOCTL_BATTERY_QUERY_STATUS`
   (charging, discharging, on line) after enumerating
   `GUID_DEVCLASS_BATTERY`
   ([information](https://learn.microsoft.com/en-us/windows/win32/power/battery-information-str),
   [status](https://learn.microsoft.com/en-us/windows/win32/power/battery-status-str),
   [enumeration](https://learn.microsoft.com/en-us/windows/win32/power/enumerating-battery-devices));
   on Linux `power_supply`'s `energy_full_design`, `energy_full` or
   their `charge_` forms, `cycle_count` and `status`
   ([class](https://www.kernel.org/doc/Documentation/power/power_supply_class.rst),
   [ABI](https://docs.kernel.org/admin-guide/abi-testing.html)). A
   `battery` alert kind for wear, a subject per battery. In the
   hardware report.
4. **Hardware errors as numbers.** Linux EDAC's corrected and
   uncorrected counts per memory controller and DIMM
   ([RAS](https://docs.kernel.org/admin-guide/RAS/main.html)); Windows
   WHEA-Logger events counted per kind from the System log through the
   event log API, not WMI, with the latest of each, linking to feature
   9 for the events (which event IDs mean what is *to be confirmed*
   against Microsoft's documents). A `hardware_errors` alert kind. Not
   waiting for ADR-0060, which keeps only Error-level events by
   default.
5. **Thermal.** Linux `hwmon` temperatures and fans, with fan faults
   ([ABI](https://www.kernel.org/doc/Documentation/ABI/testing/sysfs-class-hwmon)),
   thermal zones, and Intel's throttle counters
   ([throttling](https://docs.kernel.org/admin-guide/thermal/intel_thermal_throttle.html),
   Intel only). On Windows, **no kernel driver** (owner question 3):
   processor temperatures are *unavailable*; GPU temperature from
   `D3DKMT_ADAPTER_PERFDATA` (tenths of a degree, Windows 10 1803 and
   later) where the display driver fills it, if a service in session 0
   can read it (*to be confirmed*)
   ([structure](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/d3dkmthk/ns-d3dkmthk-_d3dkmt_adapter_perfdata),
   [version](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/d3dkmddi/ne-d3dkmddi-_dxgk_queryadapterinfotype));
   ACPI thermal zones only if a documented interface a service can use
   is found: the WMI class and performance counters often used for them
   have no Microsoft documentation. GPUs whose driver publishes nothing
   (NVIDIA's on Linux, for example) are *unavailable*, never zero.
   Readings here change by the minute, so this slice decides whether
   they go with the heartbeat's metrics.
6. **Trends.** Charts of temperature, wear and counts; degradation
   alerts (sectors reallocated since the last reading, wear rising
   faster than a rate, battery capacity falling); health columns in the
   *Device health* report and a disk report, with CSV (ADR-0029).
7. **On-demand diagnostics.** *Read now* for one device (a field in the
   answer to the agent's job poll, as ADR-0064 tells the agent which runs
   are watched; read at most once in 5 minutes); drive self-tests (SMART short and extended,
   NVMe device self-test), `chkdsk /scan` and the Windows memory test
   as feature 11's maintenance tasks and the plan's F2 job kinds, under
   a permission of their own, recorded, their output under ADR-0063's
   rule. Self-tests write a command to the drive, so they never run on
   their own: a person or a schedule asks.
8. **Servers' management controllers, RAID and vendor tools**, only
   where they give data without installing a driver: in-band IPMI
   through Linux's own drivers (`ipmi_si`, `ipmi_devintf`,
   [IPMI](https://docs.kernel.org/driver-api/ipmi.html)); Redfish from
   the host over the management controller's host interface, where it
   offers one and its credentials can be bootstrapped
   ([DSP0270 1.3.1](https://www.dmtf.org/sites/default/files/standards/documents/DSP0270_1.3.1.pdf));
   Windows' IPMI only through WMI (`Microsoft_IPMI`, an
   [archived page](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/ipmiprv/microsoft-ipmi)),
   which would be a second exception to the no-WMI rule and is decided
   then. Vendors' tools already on a server are read, never installed:
   Dell's iDRAC Service Module (Dell OpenManage Server Administrator had
   its final release in 2024 and is in sustenance until 2027,
   [Dell](https://www.dell.com/support/kbdoc/en-us/000224826/omsa-eol-landing-page)),
   Dell Command | Monitor's `DCIM_Battery` and `DCIM_NumericSensor` on
   Dell clients
   ([guide](https://dl.dell.com/topicspdf/command-monitor_reference-guide_en-us.pdf),
   WMI again), HPE's Agentless Management Service, which talks to iLO
   over its own driver
   ([HPE](https://buy.hpe.com/us/en/software/server-management-software/server-ilo-management/hpe-agentless-management/p/5219980)),
   and Lenovo's XClarity Controller's Redfish
   ([Lenovo](https://pubs.lenovo.com/xcc/rest_api)). Disks behind RAID
   through the controller's pass-through, or `smartctl` where an
   operator installed it. Power supplies and servers' fans and
   temperatures come from here. Its own ADR amendment first: it
   weighs WMI, credentials and which controllers.

## Consequences
* Technicians see each disk's health, why it is what it is, and its
  history, on both systems, and are alerted to failing, erroring, worn
  and hot disks, one alert per disk.
* Nothing is ever *healthy* because it could not be read; servers show
  many *unavailable* disks until slice 8.
* The agent sends read-only ATA and NVMe commands to every disk it
  classifies as readable, every 30 minutes; a sleeping disk is woken
  once a day.
* The inventory's disks gain `firmware`, under a rule every new fact
  follows; every device uploads its inventory once after the update.
* The agent API gains `POST /api/agent/v1/hardware` and a limit per
  device; the server gains two tables, `EASYRMM_HARDWARE_RETENTION`, and
  about 0.2 MiB per disk at the defaults.
* Policies gain `disk_health` and `check`; alerts gain `subject`,
  `subject_label`, `detail` and the resolution `subject_gone`, and
  `alerts_active_key` includes the subject. ADR-0053's planner keys on
  the subject; ADR-0060's detections use `check`.
* Existing installations gain four shared policies on upgrade (owner
  question 2).
* Windows paths stay marked unverified until real computers or
  ADR-0054's Windows machines show them.

## Testing
* **Parsers, on every platform**: the health log, Identify Controller,
  IDENTIFY DEVICE, SMART data with its checksum (a byte changed fails
  it), thresholds, the log directory and Device Statistics pages, the
  summary error log; each from bytes captured from real drives (serial
  numbers replaced) and from QEMU (named as such); truncated and
  oversized answers refused. The command allow-list refusing every
  command not on it.
* **Classification**: each bus type, driver, model and answer of the
  table above to its state and reason, the virtual-machine fallback
  included.
* **Server integration tests** in Go against real PostgreSQL
  (`testdb`), no mocks: the endpoint with requests signed by the real
  agent client; cleaning and bounds; every rule of the server's table,
  each state and level; stale readings becoming *unknown*; a disk
  dropped by a report deleted and its alert resolved `subject_gone`;
  two disks giving two alerts, one acknowledged; each check opening and
  resolving, temperature needing two readings, *unknown* readings
  changing nothing; the purge thinning to one row a day and removing
  past retention; row-level security for every role, Read-Only seeing
  health, another organization seeing nothing; the Devices column and
  filter; the inventory's `firmware` kept by `cleanInventory`; a level-1
  heartbeat answer keeping the agent from sending it.
* **Agent tests**: the reading loop's interval and jitter, the
  sleeping-disk skip and its daily read, a stuck call's deadline, the
  404 from an older server dropping the reading.
* **Linux machine tests** (`internal/vmtest`), on each image of CI's
  *Machines* jobs: the harness gains, for this test, an NVMe disk
  (`-device nvme`) and a SATA disk on AHCI (`-device ahci` and
  `ide-hd`), beside its `virtio-blk` disk.
  * With QEMU's own models, the agent reports both *unsupported*
    (`virtual_disk`) and the `virtio-blk` disk too, and the server
    shows them so: the real classification.
  * With the models set to neutral names (named in the test as stand-ins
    for real drives), the agent reads both through the real kernel
    paths, as root: the NVMe log's 50 °C and power-on hours; setting
    `smart_critical_warning` to 04h through QMP makes the disk
    *failing* on the server and opens a `failing` alert, and clearing it
    resolves it; SMART data with a valid checksum, attribute 190's
    31 °C, a passing status, CHECK POWER MODE's answer, and READ LOG
    EXT refused, so Device Statistics' facts are *unsupported*.
  * What emulation cannot give, a real *failing* ATA disk and non-zero
    wear or media errors, is tested from captured bytes only, and said
    so. Whether the runners' QEMU has `smart_critical_warning` is *to
    be confirmed*; the test fails loudly if it does not.
* **CI's Windows runners, as LocalSystem**, in the job ADR-0064 adds (a
  scheduled task, `windows-latest` and `windows-11-arm`): the
  readers on whatever disks the runner has, whose bus and model are
  printed in the job's log for the pull request; the invariant that no
  disk is *healthy* without a checked reading and every other state
  has a reason; no call outlives its deadline; a VHD attached in the
  job (FileBackedVirtual) reported *unsupported* (whether the runner
  allows attaching one is *to be confirmed*).
* **Windows machines under KVM**, when ADR-0054's W1 builds them: QEMU's
  NVMe and AHCI disks under Windows' own `stornvme` and `storahci`, read
  through both IOCTLs: stand-ins for real drives, named so.
* **Page tests** for the card, panel, column, filter, policy form and
  every state's words; the **browser end-to-end test** with the
  simulated agent (`web/e2e/agent.ts`) taught the report: a failing
  disk's alert, a Read-Only user seeing health without acting.
* **Real computers**, before the guide calls a path verified, from the
  plan's [harnesses](../feature-plan-msp.md#test-harnesses): a SATA
  hard disk (left to sleep, not woken), a SATA SSD (Device Statistics'
  wear), NVMe on Microsoft's driver and on a vendor's, a laptop with
  Intel RST or VMD, a USB disk on a bridge that passes SMART and one
  that does not, a server behind hardware RAID (*unavailable*), SATA
  disks behind an HBA on Linux, Linux's SATA serial and firmware, and a
  disk with real reallocated or pending sectors if one can be found.
  Until then each is marked unverified.
* The coverage floors in `scripts/ci/check-coverage.sh` hold for the
  packages touched.

## Owner questions
1. **Test hardware for feature 10** (the plan's question 9): which of
   the real computers under *Testing* can be provided, and a disk with
   real reallocated or pending sectors if one exists, since emulation
   cannot make a failing ATA disk. Until then the Windows and real-disk
   paths stay unverified.
2. **The new policies on upgrade.** Slice 1 adds four shared
   `disk_health` policies, turned on, to every existing installation,
   as migration 00006 did for new ones. With ADR-0053 built, rules
   whose condition filter is *any* will then notify about disks with,
   for example, a single reallocated sector. On, as decided in review,
   or added turned off for each MSP to turn on?
3. **No kernel driver** (the plan's question 10, decided in review, to
   confirm or overturn): processor temperatures on Windows stay
   *unavailable* (slice 5), because the tools that show them load a
   ring-0 driver.
</content>
</invoke>
