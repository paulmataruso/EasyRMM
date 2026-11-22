# ADR-0065: Hardware diagnostics and health monitoring

* Status: Accepted (2026-11-21, after an independent review); slice 1
  implemented in PR #86, the later slices not yet.
* Revised after an independent review (2026-11-21): commands allowed
  whole rather than by opcode, kernel default timeouts, failing disks
  that stay in view, and the review's other findings, each in its
  section.
* Amended 2026-11-21, decided in review while slice 1 was built: a
  missing disk's alerts resolve `subject_gone` once it has been missing
  for 14 days and no hardware report since lists it, compared with the
  hardware reports rather than with when the inventory arrived. The
  agent uploads its inventory only when it changes, so after a disk is
  swapped while the device is off, the inventory arrives before the
  report that leaves the disk out and never after it, and the rule as
  first written would never have resolved the alert. See *Disks that
  disappear*.
* Amended 2026-11-22, decided in review while slice 1 was built: the
  sizes measured, and the hardware report's body limit raised from 256
  to 512 KiB, because the largest report an agent can build (64 disks,
  each fact and the attribute table at their longest) is 267 KiB. See
  *Size*.
* Nothing here was decided by the owner. Everything marked as decided
  was decided in review, and the owner can overturn it; the
  [owner questions](#owner-questions) list what is the owner's.
* Amends: [ADR-0018](0018-inventory-and-telemetry.md) (a hardware report
  of its own beside the hashed inventory; each disk's firmware in the
  inventory; the rule that every new fact carries its state) and
  [ADR-0019](0019-monitoring-and-alerts.md) (an alert kind,
  `disk_health`, with a check per policy; alerts with a subject, one
  per disk). Each gains an *Amended by ADR-0065* line when this is
  implemented. It amends two proposed ADRs before the slices that would
  build otherwise (as the
  [plan](../feature-plan-msp.md#what-this-plan-asks-of-the-earlier-adrs)
  requires): [ADR-0053](0053-one-notification-sender.md), whose condition
  filter gains `disk_health` and its checks, and whose incident and
  `key` gain the alert's check and subject, before ADR-0053's slice 4
  (device alert rules and incidents) is built; this change adds the
  dated amendment line to ADR-0053's header. And
  [ADR-0060](0060-collecting-logs.md), whose `log` policies name their
  detection in the `check_name` column this ADR adds (at the plan's step 12,
  before ADR-0060's step 26) rather than in a column of their own.
* Builds on: [ADR-0009](0009-agent-protocol.md) (its section "Evolving
  the protocol"), [ADR-0020](0020-windows-agent.md) (the Windows agent
  and the versions it supports), [ADR-0027](0027-agent-updates.md)
  (builds by hash, which can hold a fleet on the build before),
  [ADR-0037](0037-one-licence.md) (permissive dependencies only),
  [ADR-0050](0050-removing-a-device.md) (a device's rows go with it),
  [ADR-0051](0051-hardening-linux-computers.md) (the machine harness,
  `internal/vmtest`),
  [ADR-0064](0064-remote-powershell-management.md) (accepted, not
  built: its Windows test job, the plan's step 6, runs the agent's tests
  as LocalSystem on CI's runners; nothing else of it is needed here),
  and these proposed ADRs:
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

**Emulated disks**, in QEMU 8.2.2, the version CI's Ubuntu 24.04
installs (1:8.2.2+ds-0ubuntu1.16 on 2026-11-21,
[Ubuntu](https://packages.ubuntu.com/noble/qemu-system-x86)); the
model names and `scsi-disk` were checked in
[v11.1.3](https://github.com/qemu/qemu/tree/v11.1.3):

* **NVMe** (`-device nvme`) answers the health log with a critical
  warning, a composite temperature of 323 K, data units, host commands
  and power-on hours since the device started; available spare,
  percentage used and media errors are always zero
  ([`hw/nvme/ctrl.c`](https://github.com/qemu/qemu/blob/v8.2.2/hw/nvme/ctrl.c),
  `nvme_smart_info`). `smart_critical_warning` is a property with a
  setter, which `qom-set` changes on a running machine (same file;
  commit
  [`4714791`](https://github.com/qemu/qemu/commit/4714791b66ae39bea6b6e3c3e84aaed8dcb005c7)).
  Its default model is *QEMU NVMe Ctrl*, which the `model` property
  changes
  ([`nvme.rst`](https://github.com/qemu/qemu/blob/v11.1.3/docs/system/devices/nvme.rst)).
* **ATA** (`ide-hd` on an AHCI controller) answers SMART READ DATA,
  READ THRESHOLDS, RETURN STATUS and READ LOG 01h, with attributes 1,
  3, 4, 5, 9, 12 and 190 (31 °C), and CHECK POWER MODE ("device active
  or idle"); RETURN STATUS always passes and nothing injects a failure;
  there is no READ LOG EXT
  ([`hw/ide/core.c`](https://github.com/qemu/qemu/blob/v8.2.2/hw/ide/core.c)).
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
* **Only whole commands on a list are sent**, every field fixed: one
  NVMe log page, read so that it changes nothing on the drive, Identify
  Controller, and seven ATA commands that only read, limited to three
  logs. ATA PASS-THROUGH (16) only. The kernel's own timeouts; a disk
  that timed out is left alone for a day.
* **Every fact has one of five states**, *healthy*, *unhealthy*
  (*warning* or *failing*), *unknown*, *unsupported* or *unavailable*,
  each with a reason, and a fact EasyRMM does not judge is *reported*.
  A disk is *healthy* only after a complete, checked reading in the
  last two hours that finds nothing. A *failing* or *warning* disk stays
  so, with the time it was last read, until a complete reading says
  otherwise; a disk that disappears stays in view. This is F1's rule,
  which every part of F1 uses.
* **Readings every 30 minutes**, in a report of their own to a new
  endpoint, never in the heartbeat or the hashed inventory. Sleeping
  disks are not woken, except once a day. USB disks are *unavailable*
  in slice 1.
* **The server judges**: the agent reports what it read; the server
  applies one table of rules, so the rules change without an agent
  update.
* **History**: every reading for 7 days, then one a day per disk, with
  the day's worst level, for 730 days.
* **Alerts**: a new kind, `disk_health`, with five checks (failing,
  errors, pending, wear, temperature), one alert per disk through a
  subject on `alerts_active_key`, resolved only after two clear
  readings; notifications through ADR-0053. Only *Disk failing* is
  turned on at upgrade.
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
| **Unknown** | EasyRMM could read it here, and this time it could not tell | Timed out; I/O error; checksum wrong; asleep, not woken; a healthy disk not read for over 2 hours; a disk missing from the last report |
| **Unsupported** | The disk, by what it is, has no such data | A virtual disk; a Storage Spaces disk; an SD card; the drive does not keep this attribute |
| **Unavailable** | The data exists, but EasyRMM cannot reach it from where the agent runs | Behind a hardware RAID controller; a storage driver that refuses health queries; a USB disk (slice 1); the agent runs in a container; SMART turned off on the drive; SAS, not read yet |

* **The difference between the last three** is what can change it:
  *unknown* may clear at the next reading; *unavailable* needs
  something else in place (the controller's own tools, another driver,
  a later slice of EasyRMM); *unsupported* never changes for that disk.
* **A reading's level** is the worst of its judged facts, in the order
  *failing*, *warning*, *unknown*, *healthy*, unless the disk as a
  whole was *unsupported* or *unavailable*, which then is its state. A
  fact the drive does not keep (an NVMe drive has no pending sectors)
  is *unsupported* and does not make the disk *unknown*. A judged fact
  that could not be read does: a disk whose verdict could not be read
  is *unknown*, never *healthy*, whatever else was read.
* **Healthy needs the verdict.** For NVMe it is the critical warning
  of the health log. For ATA it is SMART RETURN STATUS or, where a
  path does not return the registers, the attribute values against
  their thresholds (see *What is read* for how far that fallback
  goes); without either the disk is *unknown*.
* **What the console shows for a disk**, in this order, the first that
  applies:
  1. **Missing**: the device's latest report does not list the disk.
     *Unknown* (`missing`), with "missing since …" and the last level
     it was read with ("Missing since 3 May; last read Failing, 2 May
     14:30"). See *Disks that disappear*, below.
  2. **Unsupported** or **unavailable**: the disk as a whole, from its
     latest reading.
  3. **Failing** or **warning**: the level of the disk's latest judged
     reading (one that read the verdict, and found this level),
     whenever it was, with "last read …". **Age never turns a failing
     or warning disk into *unknown***, and nor do later readings that
     could not tell (a timeout, a sleeping disk, the device offline):
     those show as a note ("the 3 readings since timed out"). Only a
     newer judged reading changes the level.
  4. **Healthy**: the latest judged reading was complete and healthy
     and is at most 2 hours old (four missed readings).
  5. **Unknown**: anything else: a healthy reading older than 2 hours
     (`stale`, "not read since …", with its last values), or no judged
     reading yet (the latest reading's reason). An offline
     device's healthy disks become *unknown* this way; the offline alert
     is ADR-0019's business.
* **Disks that disappear.** A report that no longer lists a disk with a
  row marks it *missing* at that report's time; its row, its history and
  its open alerts stay, and nothing new opens on it. A later report that
  lists it again ends that. A missing disk's alerts resolve:
  * **by hand**, by someone with `alert.manage`; they stay resolved,
    since nothing opens on a missing disk; or
  * **on their own** as `subject_gone`, a new resolution, at the first
    evaluation at which both hold: the disk has been missing for at
    least 14 days (by the server's clock, from the first report that
    left it out), and no hardware report since then lists a disk with
    its identity (model and serial, or name where it has no serial); a
    report that lists it ends its being missing. Its row goes then too;
    its samples stay until their retention. Until both hold, nothing
    happens on its own. *(Amended 2026-11-21, decided in review: the
    rule first compared with the device's inventory, which an agent
    sends only when it changes, so it could arrive before the report
    that left the disk out and never after it.)*

  A device that stops reporting marks nothing missing: only a report
  that leaves a disk out does. A disk that died and dropped off the bus
  therefore stays in view, with its last level, until someone looks.
* **A device's disk health**, for the Devices column, its filter and
  its sorting:
  * its **label** is the highest of its disks' shown states in the
    order *failing*, *warning*, *unknown*, *healthy*, with the disks in
    the other two states counted after it ("Healthy, 3 disks
    unavailable"; "Failing, 1 disk unsupported"); a device with no disk
    in those four is *Unavailable* if any disk is, else *Unsupported*,
    with its count ("Unavailable, 4 disks"); a device that has sent no
    report is *Not reported*;
  * **sorting** by the column ranks *failing*, *warning*, *unknown*,
    *unavailable*, *healthy*, *unsupported*, *not reported*, by label;
  * the **filter** offers each of the seven; *Unavailable* and
    *Unsupported* match a device with any disk in that state, so
    "Healthy, 3 disks unavailable" is found under both *Healthy* and
    *Unavailable*.
* **On the wire**, from the agent, a fact is an object, `{"state": …,
  "reason": …, "value": …}` whose state is `read` (with a value),
  `unknown`, `unsupported` or `unavailable`: the agent judges nothing.
  The server's API and the console carry **six values for a judged
  fact**, `healthy`, `warning`, `failing`, `unknown`, `unsupported` and
  `unavailable` (*unhealthy* is sent as its level), and `reported` for
  a fact EasyRMM does not judge. Reasons are fixed codes from a list the
  server knows (`virtual_disk`, `virtual_machine`, `storage_spaces`,
  `raid_controller`, `storage_driver`, `container`, `smart_off`,
  `usb_bridge`, `protocol_not_read`, `not_kept`, `asleep`, `timeout`,
  `timed_out_recently`, `io_error`, `access_denied`, `bad_checksum`,
  `agent_error`, `stale`, `missing`, `invalid_report` and the like),
  shown in words by the console. The health report may add a short
  detail (a Windows error number); the inventory never does, so its
  hash stays stable.
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
| A Storage Spaces virtual disk (Windows bus type 16) | *Unsupported* (`storage_spaces`) | Bus type; whether its member disks are still visible to be read on their own is *to be confirmed* |
| A logical volume of a hardware RAID controller, on Linux | *Unavailable* (`raid_controller`) | A SCSI host driven by a hardware RAID driver (`megaraid_sas`, `hpsa`, `smartpqi`, `aacraid` and the like, a list in the agent; the sysfs attribute that names the driver is *to be confirmed*) |
| A disk on Windows bus type RAID (8) | Read first (below); if refused, *unavailable* (`storage_driver`) | Bus type 8 covers hardware RAID volumes and also single drives behind Intel RST or VMD on laptops, which may answer; the answer is recorded |
| SAS, Fibre Channel, iSCSI and other SCSI disks | *Unavailable* (`protocol_not_read`) | Bus type, or a SCSI disk that refuses ATA PASS-THROUGH; SCSI's own health pages are a later slice |
| USB disks | *Unavailable* (`usb_bridge`), nothing sent | Windows bus type USB (7); on Linux a disk whose sysfs device path runs through a USB device (`usb-storage` or `uas`). Probing bridges is slice 9 |
| SD and MMC cards | *Unsupported* | Windows bus types 12 and 13; Linux `mmcblk` |
| NVMe | Read (below) | Windows bus type 17; Linux `nvme` devices |
| SATA and ATA, also behind a host bus adapter | Read | Windows bus types 3 and 11; on Linux a disk behind libata or an HBA that answers ATA PASS-THROUGH |

* **USB disks are not read in slice 1.** A USB bridge decides what
  becomes of an ATA command, and some cannot handle one: the Linux
  kernel flags such bridges `US_FL_NO_ATA_1X`, "Cannot handle ATA_12
  or ATA_16 CDBs", and refuses to pass the command to them (slice 9
  cites it). Reading USB disks safely needs a memory per bridge (its
  USB vendor and product IDs) of what it answered, and the kernel's
  list honoured; that is slice 9.
* **On Windows bus type RAID (8)** the agent tries the NVMe query
  first, which needs no access rights (below), then ATA IDENTIFY
  DEVICE; the first answer decides the protocol, and a refusal of both
  makes the disk *unavailable* (`storage_driver`) with the driver's
  error. Windows cannot tell a hardware RAID volume from a single drive
  behind Intel RST by bus type, so the reason is the driver's refusal,
  not a guess at a controller.
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
  * **Opened with no access rights** (`dwDesiredAccess` 0).
    `IOCTL_STORAGE_QUERY_PROPERTY` needs none: its code, 0x2D1400
    (Microsoft's
    [windows-rs constant](https://microsoft.github.io/windows-docs-rs/doc/windows/Win32/System/Ioctl/constant.IOCTL_STORAGE_QUERY_PROPERTY.html)),
    carries `FILE_ANY_ACCESS` in its access bits. And with
    `FILE_FLAG_OVERLAPPED`, so that a query has a deadline (below).
  * **RAE and LSP.** Windows builds the Get Log Page command itself.
    `ProtocolDataRequestSubValue4` carries Retain Asynchronous Event and
    the Log Specific Field
    ([`STORAGE_PROTOCOL_DATA_SUBVALUE_GET_LOG_PAGE`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddstor/ns-ntddstor-storage_protocol_data_subvalue_get_log_page),
    documented from Windows Server 2022); the agent sets RAE to 1 and
    LSP to 0 there. On earlier versions the inbox driver fills those
    bits itself; what it sends there, and so whether a read can clear
    an event, is *to be confirmed* on Windows 10 and Server 2016 and
    2019, and the guide says so until it is.
* **ATA**: `IOCTL_ATA_PASS_THROUGH`, carrying only the commands of the
  list below; the same commands, and the same 512-byte answers, as on
  Linux.
  * **Read and write access only here**, as the IOCTL requires: its
    code, 0x4D02C
    ([windows-rs](https://microsoft.github.io/windows-docs-rs/doc/windows/Win32/Storage/IscsiDisc/constant.IOCTL_ATA_PASS_THROUGH.html)),
    carries read and write access, and Microsoft's page says callers
    "must have read/write access to the device". LocalSystem can open
    it so.
  * **The power state first.** Before that handle is opened, the agent
    opens the disk for query only (access 0) and asks
    [`GetDevicePowerState`](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-getdevicepowerstate);
    a disk not in the working state is skipped as *asleep*, with no
    pass-through. smartmontools does the same, because "opening for
    SMART r/w operations can already spin up the disk"
    (`win_ata_device::is_powered_down` in
    [`os_win32.cpp`](https://github.com/smartmontools/smartmontools/blob/master/smartmontools/os_win32.cpp)).
    Whether a drive that spun down on its own timer shows as not
    working there is *to be confirmed*; CHECK POWER MODE follows on
    the open handle either way.
  * **Synchronous**, as Microsoft requires: "Applications must not
    attempt to send a pass-through request asynchronously"
    ([IOCTL](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddscsi/ni-ntddscsi-ioctl_ata_pass_through)).
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
  protocol-specific query answers on a handle with no access rights
  (the access bits say it may; the drivers decide); which vendor NVMe
  drivers (Samsung's, Intel RST and its VMD mode, common on recent
  laptops) answer it; whether `IOCTL_ATA_PASS_THROUGH` passes through
  Intel RST in RAID mode. Each driver that refuses makes its disks
  *unavailable* (`storage_driver`) with the driver's error, never
  *unknown* every half hour.

### Reading on Linux
*Decided in review.*

* **NVMe**: `NVME_IOCTL_ADMIN_CMD` on the controller's character
  device, `/dev/nvmeZ`, with Get Log Page 02h for the whole controller
  and Identify Controller. Root holds `CAP_SYS_ADMIN`; should the
  agent's unit ever drop it, Get Log Page fails with `EACCES`, which is
  *unavailable* (`access_denied`), and the guide says why.
  * **The controller is found through sysfs, never from the name.**
    Under native multipath the block device `nvmeXnY` is a namespace
    head whose X is the *subsystem's* number, not a controller's; its
    paths `nvmeXcZnY` are hidden disks whose parent is controller
    `nvmeZ`, linked from the head's `multipath` directory (the
    kernel's `nvme_alloc_ns` in
    [`core.c`](https://github.com/torvalds/linux/blob/master/drivers/nvme/host/core.c),
    `nvme_mpath_add_sysfs_link` in
    [`multipath.c`](https://github.com/torvalds/linux/blob/master/drivers/nvme/host/multipath.c)).
    The agent follows the head's `multipath` links where they exist,
    else the disk's `device` link, reads the first controller found
    that answers, and reads a controller once however many namespaces
    it serves. No stable ABI document describes this layout, so the
    machine tests check the agent's walk on every image, and a unit
    test checks it against a multipath tree captured from a kernel.
* **SATA**: `SG_IO` with ATA PASS-THROUGH (16) and the check-condition
  bit, on the disk's `/dev/sdX`. Disks behind an HBA in pass-through
  (IT) mode answer the same way. CHECK POWER MODE comes first, and a
  disk in standby is skipped (*When it reads*).
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
* **Each reading is isolated.** Each disk is read on a goroutine of
  its own, under `recover`: a panic in a parser makes that disk
  *unknown* (`agent_error`), is logged, and the others go on. The
  round waits for each disk at most its deadline (below) plus 30
  seconds and sends what it has; the heartbeat has its own loop
  (`agent/runner/runner.go:168-249`) and never waits for a reading.

### The commands: whole commands, every field fixed
*Decided in review.*

An opcode is not enough to make a command harmless. Get Log Page with
RAE cleared clears a pending asynchronous event for that log on
success; log 07h with its LSP bit set makes the drive capture
telemetry; log 0Dh with an LSP action establishes or releases a
persistent-event context (NVM Express Base Specification 2.0c, figures
197, 214 and 223,
[PDF](https://nvmexpress.org/wp-content/uploads/NVM-Express-Base-Specification-2.0c-2022.10.04-Ratified.pdf)).
So the transport accepts **only the commands below, each with every
field fixed**, builds them itself from a name ("NVMe health log",
"SMART read log 01h"), and refuses anything else before it reaches the
operating system. A table-driven test changes each fixed field of each
command, one at a time, and every opcode, feature, log address and
page not listed, and expects every one refused.

| Command | Fields fixed | Why |
|---|---|---|
| NVMe Identify (06h) | CNS 01h (Identify Controller); NSID 0; CNTID 0; CNS-specific identifier 0; CSI 0; UUID index 0; 4,096 bytes | Model, serial, firmware revision, `wctemp` and `cctemp`. Not CNS 00h (Identify Namespace): nothing in slice 1 uses a namespace's data, sizes come from the inventory and the health log is read for the controller |
| NVMe Get Log Page (02h) | LID 02h only; NSID FFFFFFFFh, which "hosts should use … to request the controller log page"; LSP 0; **RAE 1**; NUMDL 127 and NUMDU 0 (512 bytes); offset 0; UUID index 0; CSI 0 | The SMART / Health log. It holds the number of error information log entries (bytes 191:176), so log 01h is not read. RAE 1 leaves any event for the log pending for the driver that owns events |
| ATA IDENTIFY DEVICE (ECh) | Features 0; count 1; LBA 0; PIO data-in; 512 bytes | Whether SMART is supported and enabled; model, serial and firmware |
| ATA CHECK POWER MODE (E5h) | Every field 0; non-data; registers returned | A disk in standby is skipped |
| SMART READ DATA (B0h, feature D0h) | LBA mid 4Fh, LBA high C2h, LBA low 0; count 1; PIO data-in; 512 bytes | The attribute table |
| SMART READ ATTRIBUTE THRESHOLDS (B0h, D1h) | As READ DATA | The fallback verdict only (*What is read*) |
| SMART RETURN STATUS (B0h, DAh) | LBA mid 4Fh, LBA high C2h; every other field 0; non-data; registers returned | The drive's verdict |
| SMART READ LOG (B0h, D5h) | LBA mid 4Fh, LBA high C2h; log address (LBA low) 00h or 01h with count 1, or 04h with count 1 to 8 as the directory gives its size; PIO data-in | 00h, the SMART log directory: which logs exist and how long. 01h, the summary error log: the drive's error count. 04h, Device Statistics, where only this directory lists it |
| READ LOG EXT (2Fh) | Log address 00h, page 0; or 04h, page 00h, 03h, 04h, 05h or 07h; count 1; features 0; PIO data-in; 48-bit | 00h, the general-purpose log directory. 04h, Device Statistics: the list of pages, rotating media, general errors, temperature, solid state |

* **ATA PASS-THROUGH (16) only, never (12).** Operation code A1h,
  PASS-THROUGH (12), is also BLANK, an MMC command for optical drives
  (T10's [operation code list](https://www.t10.org/lists/op-num.htm)),
  and the Linux kernel relays every command but ATA_16 to an ATAPI
  device as it is (`__ata_scsi_queuecmd` in
  [`libata-scsi.c`](https://github.com/torvalds/linux/blob/master/drivers/ata/libata-scsi.c)).
  On Linux the agent sends `ATA_16` with protocol PIO data-in (4) for
  reads and non-data (3), with the check-condition bit, for CHECK POWER
  MODE and RETURN STATUS; the direction bit from the device; the
  extend bit only for READ LOG EXT. Never DMA, never data-out. On
  Windows: `ATA_FLAGS_DATA_IN` for reads and no data flag otherwise,
  `ATA_FLAGS_48BIT_COMMAND` only for READ LOG EXT, never
  `ATA_FLAGS_DATA_OUT` or `ATA_FLAGS_USE_DMA`
  ([`ATA_PASS_THROUGH_EX`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddscsi/ns-ntddscsi-_ata_pass_through_ex)).
* **Without a directory.** A drive may refuse a log directory. Then
  the agent reads log 01h only if the SMART data says the drive keeps
  an error log, and Device Statistics only through a directory that
  lists it; nothing is tried blind.
* **Never** SMART ENABLE or DISABLE, self-tests, SCT (which writes a log
  to send its command), Set Features, a log or page not listed, or
  anything that writes.

### Deadlines
*Decided in review.*

A short deadline of EasyRMM's own would do harm: on Linux an admin
command that times out makes the NVMe driver reset the controller
("Shutdown the controller immediately and schedule a reset … if this
is the admin queue", `nvme_timeout` in
[`pci.c`](https://github.com/torvalds/linux/blob/master/drivers/nvme/host/pci.c)),
and a disk may need its spin-up time to answer. So:

* **Linux NVMe**: `timeout_ms` 0, which leaves the request the admin
  queue's own timeout (`nvme_user_cmd` in
  [`ioctl.c`](https://github.com/torvalds/linux/blob/master/drivers/nvme/host/ioctl.c),
  `blk_add_timer` in
  [`blk-timeout.c`](https://github.com/torvalds/linux/blob/master/block/blk-timeout.c)):
  the `admin_timeout` module parameter, 60 seconds unless an operator
  changed it ([`core.c`](https://github.com/torvalds/linux/blob/master/drivers/nvme/host/core.c)).
  smartmontools leaves it there too ("Kernel default for NVMe admin
  commands is 60 seconds", `os_linux.cpp`).
* **Linux SATA**: `SG_IO` with 60,000 ms. A timeout of 0 would mean
  the device's `sg_timeout`, else `BLK_DEFAULT_SG_TIMEOUT`, 60 seconds
  (`scsi_fill_sghdr_rq` in
  [`scsi_ioctl.c`](https://github.com/torvalds/linux/blob/master/drivers/scsi/scsi_ioctl.c));
  the agent states 60 seconds itself, as smartmontools does
  (`SCSI_TIMEOUT_DEFAULT`, "longer than the spin up time of a disk",
  [`scsicmds.h`](https://github.com/smartmontools/smartmontools/blob/master/smartmontools/scsicmds.h)).
* **Windows NVMe**: the query is sent overlapped; after 60 seconds the
  agent calls
  [`CancelIoEx`](https://learn.microsoft.com/en-us/windows/win32/fileio/cancelioex-func).
  Cancelling does not wait and may not take, and the `OVERLAPPED` and
  buffers must not be freed until the request completes (same page),
  so they are allocated outside Go's heap and kept until then; each
  later round checks them with `GetOverlappedResult` without waiting.
  No goroutine waits on a cancelled query.
* **Windows ATA**: `TimeOutValue` 60 (seconds,
  [`ATA_PASS_THROUGH_EX`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddscsi/ns-ntddscsi-_ata_pass_through_ex)),
  which the port driver applies. Pass-through must be synchronous, so
  overlapped I/O is not allowed here: the call runs on a goroutine
  locked to its thread, and if it has not returned 30 seconds after
  its timeout the agent calls
  [`CancelSynchronousIo`](https://learn.microsoft.com/en-us/windows/win32/fileio/cancelsynchronousio-func)
  on that thread. If the driver still does not return, that one
  goroutine waits for it; the disk is not asked again meanwhile, so
  there is at most one per disk.
* **After a timeout** the disk is *unknown* (`timeout`) and is not
  asked again for 24 hours, whatever the cause; the readings between
  say so (`timed_out_recently`), and a *failing* or *warning* disk keeps
  its level meanwhile (*The five states*). A disk with a call still out
  is not asked again until that call has returned and the 24 hours
  have passed.

### What is read
*Decided in review.*

| Fact | NVMe | ATA | Judged |
|---|---|---|---|
| Verdict | Critical warning, every bit | SMART RETURN STATUS; attributes against thresholds where status is not returned | Yes |
| Temperature (°C) | Composite temperature, in kelvins | Device Statistics *Current Temperature*, else attribute 194 or 190's low byte | Yes |
| The drive's temperature limit (°C) | `wctemp` from Identify Controller; 0 means none | Device Statistics *Specified Maximum Operating Temperature* | Used by the temperature rule |
| Wear (% of rated endurance used) | Percentage used, which may exceed 100 and is 255 above 254 | Device Statistics *Percentage Used Endurance Indicator* | Yes |
| Available spare and its threshold (%) | Health log | — | Through bit 0 |
| Media errors | Media and data integrity errors | — | Yes |
| Reallocated sectors | — | Attribute 5, or Device Statistics' count | Yes |
| Pending sectors | — | Attribute 197 | Yes, apart from reallocated ones |
| Uncorrectable sectors | — | Attribute 198 | Yes, with pending ones |
| Reported drive errors | Number of error information log entries (bytes 191:176) | The summary SMART error log's count, bytes 452–453 | Reported |
| Power-on hours | Health log | Attribute 9 | Reported |
| Data written | Data units written, in thousands of 512-byte units | — | Reported |
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
* **NVMe's units**, from the specification (2.0c, figure 207): the
  composite temperature is "a temperature in Kelvins"; percentage used
  "is allowed to exceed 100. Percentages greater than 254 shall be
  represented as 255"; a data unit is "1,000 units of 512 bytes". The
  critical warning's bit 5 is "the Persistent Memory Region has become
  read-only or unreliable" and bits 7:6 are reserved; the kernel's
  `nvme.h` names only bits 0 to 4. A WCTEMP of 0h means "no warning
  temperature threshold value is reported" (figure 275).
* **The ATA fallback is partial, and says so.** Where a path does not
  return RETURN STATUS's registers, the verdict comes from the
  attribute values against READ ATTRIBUTE THRESHOLDS. That command may
  be obsolete in current ATA standards (smartmontools' `atacmds.h` says
  only that some SMART subcommands "are obsolete as of ATA-7", without
  naming them; which ones is *to be confirmed*), and a drive may not
  answer it or answer with a bad checksum. Then the verdict is
  *unknown* (`no_verdict`), never inferred from the attributes alone.
* **Device Statistics' flags are honoured.** Each statistic is 8 bytes
  whose top byte holds flags: bit 63 *supported*, bit 62 *valid*. An
  unsupported statistic is *unsupported* (`not_kept`); a supported one
  without a valid value is *unknown* (`not_valid`), never 0
  (`print_device_statistics_page` in
  [`ataprint.cpp`](https://github.com/smartmontools/smartmontools/blob/master/smartmontools/ataprint.cpp)
  skips the first and prints the second as "-").
* **The summary error log's count** is the 16-bit value at bytes 452
  and 453: after a revision byte, a pointer byte and five 90-byte
  entries (`struct ata_smart_errorlog` in
  [`atacmds.h`](https://github.com/smartmontools/smartmontools/blob/master/smartmontools/atacmds.h)).
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
| *Warning* | Any reallocated sector or NVMe media error; any pending or offline-uncorrectable sector; wear at 90% or more; temperature at or above the drive's own limit; NVMe critical warning bit 1 (temperature), bit 5 (persistent memory region) or any bit the specification reserves today; an ATA attribute that is not pre-fail at or below its threshold |
| *Healthy* | The verdict read, every judged fact the drive keeps read, none of the above |

* **No limit, no limit rule.** A drive that reports no temperature limit
  (NVMe WCTEMP 0h; ATA without the Device Statistics maximum, or with it
  not valid) has its temperature *reported*, not judged, by the
  drive's-own-limit rule; a policy with a temperature in °C still
  applies to it, and NVMe's own bit 1 still makes it *warning*.
* **Reserved bits count.** A critical-warning bit the specification
  reserves today means a newer drive is warning of something; it is
  *warning*, named by its number, rather than ignored.

### When it reads
*Decided in review.*

* **Every 30 minutes**, smartd's default, with up to a minute of jitter,
  and once 2 minutes after the agent starts. Counters change slowly; a
  temperature alert needs more than one reading (below).
* **On a goroutine of its own**, not in the heartbeat's loop, so a slow
  disk never delays a heartbeat.
* **Sleeping disks are not woken.** An ATA disk that Windows'
  `GetDevicePowerState` says is not working, or that CHECK POWER MODE
  says is in standby, is skipped: *unknown* (`asleep`), and the server
  keeps showing its last values with their time (and its level, if it
  was failing or warning). After 24 hours of
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
* **Size.** About 1.0 KiB for an NVMe disk and 3.1 KiB for an ATA disk
  with 30 attributes (measured in slice 1 from `tools/agentsim`'s
  reports; first estimated at 0.8 and 2.5 KiB); at most 64 disks, so
  the body limit is 512 KiB. *(Amended 2026-11-22, decided in review:
  first 256 KiB, but the largest report an agent can build, 64 disks
  with every fact and the attribute table at their longest, is 267 KiB;
  a test holds it under the limit.)* The heartbeat gains nothing; the
  inventory gains about 40 bytes a disk. A device with two disks sends
  about 4 KiB every 30 minutes, 200 KiB a day; 10,000 devices send
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
* **No protocol level needed.** The server decodes an inventory with
  `json.Unmarshal` into its own type, which ignores fields it does not
  know, and hashes the body as sent
  (`server/internal/inventory/service.go:62-72`); an older server
  therefore stores the inventory without `firmware` and still matches
  the agent's hash. `cleanInventory` keeps the field from the release
  that adds it. The agent sends it to every server.
* **A one-time upload.** The field changes every device's inventory
  document, so its hash, once: every device uploads its inventory once
  after the agent update, within the limit of one in 10 minutes per
  device (`agentapi.go:76-79`).

### Data model and retention
*Decided in review.*

* **`device_disk_health`**: the latest reading per disk: the device, the
  disk's identity and name, protocol, model and serial, the state, level
  and reason, the facts as JSON, when the agent read it and when the
  server received it; and, kept apart so that later readings cannot
  overwrite them, the level and time of the last complete reading and
  `missing_since`. A disk a report no longer lists keeps its row,
  marked missing, until the rule in *Disks that disappear* removes it.
* **`device_disk_health_samples`**: one row per disk per reading, with
  the state and level, temperature, wear, the error counts and power-on
  hours. Kept at full resolution for `EASYRMM_METRICS_RETENTION` (7
  days by default), then thinned by the hourly purge to one row per
  disk per day, in UTC, holding **the day's worst level** (a day with
  one *failing* reading stays *failing*), its highest temperature, and
  the day's last counts and wear (which only rise, or for pending
  sectors, are as of the end of the day). Kept for
  `EASYRMM_HARDWARE_RETENTION`, a duration like the other retentions
  (`config.go:186-192`), **17520h (730 days) by default**, refused at
  start below `EASYRMM_METRICS_RETENTION`, as the other minimums are
  (`config.go:376-388`). Disks wear over years; two years shows a trend
  and a replacement.
* **Size**, estimated at about 200 bytes a row with its index: 336 rows
  for the week and 730 for the two years, about 0.2 MiB per disk;
  1,000 devices with two disks about 0.4 GiB. Measured with
  `tools/agentsim` in slice 1, the numbers in its pull request. The
  backups grow by the same amount, since they copy the database: the
  backup guide states it beside the metrics' share.
* **Row-level security** as the inventory's: read through the device
  (`00005_inventory.sql:62-68`), written only by the agent API and the
  purge with the system scope.
* **A device's removal** removes its rows (`ON DELETE CASCADE`,
  ADR-0050). Keeping a disk's history past its device is feature 1's
  asset record, not this.

### Alerts
*Decided in review.*

* **A new kind, `disk_health`**, with a **check** per policy, in a new
  column `check_name` on policies (`NULL` for the other kinds; `check`
  itself is a reserved word in PostgreSQL), copied to the alert. Every
  check opens on complete readings only and **resolves only after two
  complete readings in a row that clear it**, by a margin where the
  value is a measurement: an hour at the reading interval, as
  `ResolveWindow` holds a metric alert until 5 minutes below its
  threshold (`evaluate.go:19-22`).

  | Check | Opens when | Threshold | Resolves after two complete readings | Default shared policy |
  |---|---|---|---|---|
  | `failing` | The reading's level is *failing* | None | Not *failing* | *Disk failing*, critical, **on** |
  | `errors` | Reallocated sectors plus NVMe media errors at or above the threshold: counts that only rise | A count, 1 to 100 | Below the threshold | *Disk errors*, 1, warning, off |
  | `pending` | Pending plus offline-uncorrectable sectors at or above the threshold: counts that fall again | A count, 1 to 100 | Below the threshold | *Disk sectors pending*, 1, warning, off |
  | `wear` | Wear at or above the threshold | A percentage, 1 to 100 | Below the threshold | *Disk wearing out*, 90, warning, off |
  | `temperature` | Every complete reading in the policy's minutes at or above the threshold, at least two | °C, 1 to 100, or none for the drive's own limit | At least 5 °C below the threshold or limit | *Disk too hot*, the drive's limit, 60 minutes, warning, off |

  The existing threshold column (1 to 100) fits all five; its `CHECK`
  that only `offline` has no threshold gains `failing` and the
  temperature check's *drive's own limit*. Minutes apply to temperature
  only (at least 30, the reading interval).
* **Pending sectors are judged apart** from reallocated ones because
  they go down: smartd's manual says the count of pending sectors
  drops "when all pending sectors have been reallocated or could be
  read again", and that "some disks do not reset this attribute when a
  bad sector is reallocated" (`-C` and `-U` in
  [`smartd.conf.5.in`](https://github.com/smartmontools/smartmontools/blob/master/smartmontools/smartd.conf.5.in)).
  A `pending` alert can therefore resolve; an `errors` or `wear` alert
  in practice resolves only when its threshold is raised (a policy
  change) or the disk is replaced (*Disks that disappear*).
* **One alert per disk.** `alerts_active_key` allows one open alert per
  policy and device (`00006_monitoring.sql:117-118`), so two failing
  disks would share one alert, and acknowledging a worn disk would
  silence a failing one beside it. **Alerts gain a subject**: `subject`
  (the disk's identity, empty for the other kinds), `subject_label`
  ("PhysicalDrive1 · Samsung SSD 870 EVO 1TB") and `detail` ("Pending
  sectors 8, reallocated 0"), and the key becomes (policy, device,
  subject). `subject` is `NOT NULL DEFAULT ''`, so that the other
  kinds' alerts, whose subject is empty, still allow one per policy
  and device (a `NULL` would make every row distinct in a unique
  index); `evaluate.go:75`'s `ON CONFLICT (policy_id, device_id)` names
  the new key's columns, and `reconcile`'s `policy_changed`
  (`evaluate.go:127`) also compares `check_name`, so changing a
  policy's check resolves its alerts as changing its kind does. The
  plan left this choice to this ADR for every new kind
  ([Notifications](../feature-plan-msp.md#notifications-for-every-new-alert-kind));
  feature 12's detection counted per domain and account needs a subject
  either way. This ADR builds the columns and the key; alerts without a
  device, which feature 12's needs, are that feature's change.
* **The value** is the count, percentage or temperature that opened the
  alert (1 for `failing`), updated as for other kinds.
* **Resolving.** Two complete readings that clear it resolve an alert
  (`cleared`). A missing disk's alerts resolve only by hand or by the
  14-day rule (`subject_gone`, a new resolution added to the `CHECK` at
  `00006_monitoring.sql:112`; *Disks that disappear*). An *unknown*, *unavailable* or stale reading, or a
  missing disk, changes nothing: the alert stays as it is, as metric
  alerts do without measurements (`evaluate.go:271-273`), and nothing
  opens on one.
* **Resolving by hand** a present disk's alert while its condition
  holds opens it again at the next evaluation, as for every kind. For
  counts that only rise the console says to acknowledge instead; rising
  counts are slice 6's degradation alerts.
* **Evaluated in `monitoring.Evaluate`**, each minute, under its lock,
  from `device_disk_health` and the samples, with the policies'
  coverage and reconciliation as for every kind.
* **Added by a migration** as five shared policies, **only *Disk
  failing* turned on**, the other four added turned off for each MSP
  to turn on (owner question 2 asks the owner to confirm this
  default). A failing drive is worth a message everywhere; a single
  reallocated sector, 90% wear or a warm drive is a judgement each MSP
  makes. The same migration runs on new installations, so they start
  the same way.
  * **Names already taken.** Policy names are unique per scope, case
    aside (`alert_policies_name_key`, `00006_monitoring.sql:33`), and a
    super administrator may already have a platform policy called
    *Disk failing*. Each insert is `ON CONFLICT DO NOTHING`; one that
    conflicted is tried once more with " (disk health)" appended, again
    `ON CONFLICT DO NOTHING`. An installation that has both names has
    chosen its own, and gets no default for that check; the release
    notes say so.

### Notifications
*Decided in review.*

* **Through ADR-0053's rules**, built at the plan's step 10, before
  this. Its condition filter gains `disk_health`, with the check as a
  second choice ("any", or a list of checks), as ADR-0060 adds `log`
  and its detection.
* **ADR-0053's incident and `key` gain the check and the subject**: an
  incident carries over "on the same policy and device, with the same
  kind", check and subject; `key` is the same for every alert of one
  condition on one device and subject. ADR-0053 is amended so before
  its slice 4 (device alert rules, the planner and incidents) is built,
  at the plan's step 10, so its planner is built with subjects rather
  than changed after; this change adds the dated amendment line to
  ADR-0053's header.
* **One item per alert.** ADR-0053's generic webhooks carry every alert,
  "split into deliveries of at most 100", because "a PSA tool opens a
  ticket per alert" (ADR-0053, *Digests*). With one alert per disk, a
  server with three failing disks opens three tickets, one per disk to
  replace, which is the point; ADR-0053's grouping of a site's outage is
  unchanged.
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
  it was read ("Failing, last read 2 May 14:30"). Missing disks stay on
  the card, marked so, below the present ones.
* **A disk's panel**: every fact with its state and reason, the ATA
  attribute table, the last 30 days (highest temperature, wear and
  error counts per day), and the disk's open alerts. Charts are slice 6.
* **Devices** gains a *Disk health* column with the device's label,
  sorting and filter as *A device's disk health* defines them (*Failing*,
  *Warning*, *Unknown*, *Healthy*, *Unavailable*, *Unsupported*, *Not
  reported*), as hardening's column and filter are built
  (`server/internal/devices/devices.go:153-155,223-234`).
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
* **A deadline shorter than the kernel's**: on Linux it would reset a
  slow NVMe controller that the kernel would have waited for.
* **Overlapped ATA pass-through on Windows**: Microsoft forbids it;
  `CancelSynchronousIo` is the documented way to stop one.
* **Commands allowed by opcode**: a Get Log Page or SMART READ LOG can
  change state depending on its other fields.
* **Probing USB bridges in slice 1**: some must never get ATA
  pass-through, and knowing which needs a memory per bridge (slice 9).
* **Letting age or a missing disk turn *failing* into *unknown***: the
  disk most likely to die is the one most likely to stop answering.
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
* **USB disks** stay *unavailable* until slice 9.
* **A Windows ATA call the driver never returns** keeps one goroutine
  per disk waiting; nothing in Windows can free it short of the driver
  answering.
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
| Reported drive errors | Slice 1 | NVMe's count of error log entries; ATA's summary error log count; reported, judged when rising (slice 6) |
| Media errors | Slice 1 | NVMe media errors (`errors` check); ATA uncorrectable sectors (`pending` check) |
| Reallocated sectors where available | Slice 1 | ATA (`errors` check); *unsupported* on NVMe |
| Pending sectors where available | Slice 1 | ATA (`pending` check, which can resolve); *unsupported* on NVMe |
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
| SMART not equally available | Slice 1; slice 9 | Classification of disks; USB bridges in slice 9 |
| Elevated privileges | Slice 1 | Root and LocalSystem already; what each read needs, above |
| Distinguish unavailable from failures | Slice 1 | F1's rule |
| No drive healthy because SMART could not be read | Slice 1 | Healthy only after a complete, checked, recent reading; a failing or missing disk never fades to *unknown* by age |
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
   the tables and retention, `disk_health` with its five checks and
   subjects on alerts, ADR-0053's amendment, the console's card, panel,
   column, filter and policy form, and the guide. First because a
   failing disk is the
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
   answer to the agent's job poll, as ADR-0064 tells the agent which
   runs are watched; read at most once in 5 minutes, and never a disk
   inside its 24 hours after a timeout); drive self-tests (SMART short
   and extended, NVMe device self-test), `chkdsk /scan` and the Windows
   memory test
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
9. **USB disks.** ATA pass-through to USB bridges that take it, with a
   memory per bridge (its USB vendor and product IDs) of what it
   answered, so that a bridge that refused or misbehaved once is never
   asked again, and the Linux kernel's own list honoured: bridges
   flagged `US_FL_NO_ATA_1X`, "Cannot handle ATA_12 or ATA_16 CDBs",
   which `uas` and `usb-storage` refuse to pass on
   ([`usb_usual.h`](https://github.com/torvalds/linux/blob/master/include/linux/usb_usual.h);
   [`uas.c`](https://github.com/torvalds/linux/blob/master/drivers/usb/storage/uas.c)).
   On Windows, where EasyRMM knows of no such list, the memory per
   bridge is the guard. Its own ADR amendment first, on which bridges are tried
   and how a misbehaving one is recognised.

## Consequences
* Technicians see each disk's health, why it is what it is, and its
  history, on both systems, and are alerted to failing disks, and,
  where an MSP turns them on, to erroring, pending, worn and hot ones,
  one alert per disk.
* Nothing is ever *healthy* because it could not be read, and a failing
  or vanished disk never fades from view; servers show many
  *unavailable* disks until slice 8, USB disks until slice 9.
* The agent sends a fixed list of read-only ATA and NVMe commands to
  every disk it classifies as readable, every 30 minutes, with the
  kernel's timeouts; a sleeping disk is woken once a day, a disk that
  timed out is left alone for a day.
* The inventory's disks gain `firmware`, under a rule every new fact
  follows; every device uploads its inventory once after the update.
* The agent API gains `POST /api/agent/v1/hardware` and a limit per
  device; the server gains two tables, `EASYRMM_HARDWARE_RETENTION`, and
  about 0.2 MiB per disk at the defaults, in the database and in its
  backups.
* Policies gain `disk_health` and `check_name`; alerts gain `check_name`,
  `subject`, `subject_label`, `detail` and the resolution
  `subject_gone`, and `alerts_active_key` includes the subject.
  ADR-0053's incidents and planner key on the check and subject (its
  header carries the amendment); ADR-0060's detections use
  `check_name`.
* Every installation gains five shared policies, only *Disk failing*
  turned on (owner question 2).
* Windows paths stay marked unverified until real computers or
  ADR-0054's Windows machines show them.

## Testing
* **Parsers, on every platform**: the health log, Identify Controller,
  IDENTIFY DEVICE, SMART data with its checksum (a byte changed fails
  it), thresholds, the log directory and Device Statistics pages, the
  summary error log; each from bytes captured from real drives (serial
  numbers replaced) and from QEMU (named as such); truncated and
  oversized answers refused; Device Statistics entries without their
  *supported* or *valid* flag; NVMe's reserved warning bits and a
  WCTEMP of 0.
* **Fuzz tests for every parser** (health log, Identify Controller,
  IDENTIFY DEVICE, SMART data and thresholds, each log directory,
  Device Statistics, the summary error log, and the report's server-side
  decoder), seeded with the captured bytes, as `FuzzVerify` does for
  Authenticode (`server/internal/agents/authenticode/authenticode_test.go:153`):
  no input panics or reads past its buffer.
* **The command list**: a table-driven test that changes each fixed
  field of each allowed command, one at a time, and sends every opcode,
  SMART feature, log address and page not listed, and expects each
  refused before any system call; ATA_12 never built.
* **Classification**: each bus type, driver, model and answer of the
  table above to its state and reason, the virtual-machine fallback,
  USB disks and Windows bus type 8 included.
* **Server integration tests** in Go against real PostgreSQL
  (`testdb`), no mocks: the endpoint with requests signed by the real
  agent client; cleaning and bounds; every rule of the server's table,
  each state and level; a healthy disk's stale reading becoming
  *unknown* and a failing one staying *failing*, "last read …", through
  age, timeouts and an offline device; a disk dropped by a report kept
  as *missing* with its alert open, resolved by hand and staying so, and
  resolved `subject_gone` only after 14 days missing, not after 13
  days, not when a report lists it again, and a disk that comes back
  after it opening a new alert; two disks giving
  two alerts, one acknowledged; each check opening, and resolving only
  after two clearing readings (temperature 5 °C below), a `pending`
  alert resolving when the count falls; changing a policy's check
  resolving its alerts `policy_changed`; *unknown* readings changing
  nothing; the upgrade migration on a database that already has a
  platform policy named *Disk failing*, and on one that has both names;
  the purge thinning to one row a day keeping the day's worst level,
  and removing past retention; the retention refused below the metrics
  retention; row-level security for every role, Read-Only seeing
  health, another organization seeing nothing; the Devices label,
  sorting and each filter; the inventory's `firmware` kept by
  `cleanInventory`, and an inventory with `firmware` accepted by the
  release before's decoder with its hash unchanged.
* **Agent tests**: the reading loop's interval and jitter; the
  sleeping-disk skip and its daily read; a stuck call held to its
  deadline while the other disks and the heartbeat go on; a disk left
  alone for 24 hours after a timeout; a panicking parser making one disk
  *unknown*; the 404 from an older server dropping the reading.
* **Linux machine tests** (`internal/vmtest`), on each image of CI's
  *Machines* jobs, which run on `ubuntu-24.04` and install its
  `qemu-system-x86` (`.github/workflows/ci.yml:609-631`), version
  1:8.2.2+ds-0ubuntu1.16 on 2026-11-21
  ([Ubuntu](https://packages.ubuntu.com/noble/qemu-system-x86)), so
  QEMU 8.2.2: the harness gains, for this test, an NVMe disk
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
    resolves it after two readings; SMART data with a valid checksum,
    attribute 190's 31 °C, a passing status, CHECK POWER MODE's answer,
    the summary error log's count through log 01h, and READ LOG EXT
    refused, so Device Statistics' facts are *unsupported*. QEMU 8.2.2
    has all of it:
    `nvme_smart_info` reports 323 K and a settable
    `smart_critical_warning` property
    ([`hw/nvme/ctrl.c`](https://github.com/qemu/qemu/blob/v8.2.2/hw/nvme/ctrl.c)),
    and the IDE model the same SMART commands, attributes and power
    answer as later versions
    ([`hw/ide/core.c`](https://github.com/qemu/qemu/blob/v8.2.2/hw/ide/core.c)).
  * What emulation cannot give, a real *failing* ATA disk and non-zero
    wear or media errors, is tested from captured bytes only, and said
    so.
* **CI's Windows runners, as LocalSystem**, in the job ADR-0064 adds (a
  scheduled task, `windows-latest` and `windows-11-arm`): the
  readers on whatever disks the runner has, whose bus and model are
  printed in the job's log for the pull request. The test **fails
  unless at least one disk was actually read through an IOCTL** (NVMe
  or ATA) or refused by its driver with the refusal recorded, so that a
  classification that skipped everything cannot pass; and it checks the
  invariant that no disk is *healthy* without a checked reading and
  every other state has a reason, and that no call outlives its
  deadline. A VHD attached in the job (FileBackedVirtual) is reported
  *unsupported* (whether the runner allows attaching one is *to be
  confirmed*).
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
2. **The new policies' default: confirm.** Slice 1 adds five shared
   `disk_health` policies to every installation, and, as decided in
   review, turns on only *Disk failing*; *Disk errors*, *Disk sectors
   pending*, *Disk wearing out* and *Disk too hot* are added turned
   off. With ADR-0053 built, a rule whose condition filter is *any*
   then notifies about failing disks everywhere, and about the rest only
   where an MSP turns them on. Confirm this default, or turn more on.
3. **No kernel driver** (the plan's question 10, decided in review, to
   confirm or overturn): processor temperatures on Windows stay
   *unavailable* (slice 5), because the tools that show them load a
   ring-0 driver.
