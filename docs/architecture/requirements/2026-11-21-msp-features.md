* **Source**: the owner's requirements for EasyRMM's next twelve features,
  given on 2026-11-21 and committed here verbatim, so that the
  [plan](../feature-plan-msp.md) and each feature's ADR can cite them by
  number and heading (for example "requirement 8, Recovery key
  management").
* **What is verbatim**: everything from the heading *EasyRMM – Additional
  Feature Requirements* to the sentence that ends *in one unified
  product.* Nothing inside it was added, corrected or reworded.
* **Added**: this header, and the [addendum](#addendum-the-keystore)
  after the requirements, which quotes the owner's two later messages
  about a keystore.
* **The owner's instruction on the twelve**: "Add this to the plan, and
  start doing them one by one".

---

# EasyRMM – Additional Feature Requirements

I want to expand EasyRMM with the following features. These are functional requirements describing what each feature should do and the capabilities it should provide.

Before implementing anything, review the existing EasyRMM project, documentation, functionality, and current feature set. Understand what already exists so that new functionality complements the existing product rather than duplicating it.

**Important instructions:**
- These are feature descriptions and functional requirements, not architectural or design specifications.
- Do not assume a particular implementation approach.
- Do not unnecessarily prescribe technologies, frameworks, database structures, APIs, or UI layouts.
- Follow the existing project's conventions and functionality.
- Features must support EasyRMM's multi-tenant environment, including appropriate organization, site, group, and device-level permissions.
- All remote operations must have appropriate security, authorization, and auditability.
- Consider both Windows and Linux where applicable. Some features will necessarily be Windows-specific.
- These features should be suitable for a production-grade MSP RMM platform.

---

## 1. Hardware Warranty and Lifecycle Management

Provide centralized hardware warranty tracking and lifecycle management for managed endpoints.

### Required functionality

- Automatically collect hardware manufacturer, model, serial number, service tag, and other identifying information.
- Retrieve warranty information from hardware manufacturers where supported.
- Support Dell, Lenovo, HP, and other major manufacturers.
- Display warranty start and expiration dates.
- Track warranty status, including active, expired, unknown, and nearing expiration.
- Generate notifications when warranties are approaching expiration.
- Allow configurable notification intervals, such as 30, 60, and 90 days.
- Track hardware purchase dates where available.
- Track hardware age and estimated lifecycle.
- Identify hardware approaching end-of-life.
- Identify operating systems that are approaching or have reached end-of-support.
- Maintain historical hardware information when a device is upgraded or replaced.
- Provide organization-wide warranty and hardware lifecycle reports.

### Special considerations

- Manufacturer warranty lookup services may require API access, authentication, or external integrations.
- Warranty lookup must account for different manufacturer identification systems.
- Some manufacturers may not expose complete warranty information.
- The system should clearly distinguish verified warranty information from estimated or manually entered information.
- Allow technicians to manually correct or enter warranty information when automated lookup is unavailable.

---

## 2. Endpoint Security Posture Monitoring

Provide centralized visibility into the security configuration and overall security health of managed endpoints.

### Required functionality

Collect and report on endpoint security controls, including:

**Antivirus and endpoint protection**
- Microsoft Defender installation and operational status.
- Antivirus real-time protection status.
- Antivirus definition update status.
- Last successful antivirus scan.
- Recent threat detections.
- Third-party antivirus products where detectable.
- Windows Security Center status.

**Disk encryption**
- BitLocker status.
- Encryption percentage.
- Encryption method.
- Protection status.
- Identify drives that are not encrypted.

**Windows security**
- Windows Firewall status for all profiles.
- Secure Boot status.
- TPM availability and status.
- Windows Defender features and configuration.
- User Account Control status.
- Remote Desktop exposure.
- SMBv1 status.
- Windows security update status.

**Account security**
- Local administrator accounts.
- Identify unexpected or unauthorized administrator accounts.
- Identify disabled or inactive accounts.
- Report on accounts with potentially insecure configurations.

**Linux security**
- Firewall status.
- Disk encryption status where detectable.
- SSH configuration and exposure.
- Root and privileged account information.
- Security update status.
- Important security configuration checks.

### Security scoring and compliance

- Provide an overall security posture score for each device.
- Identify which security controls are passing or failing.
- Explain exactly why a device has a reduced security score.
- Allow security policies to be configured at the organization, site, group, and device level.
- Identify devices that do not meet their assigned security requirements.
- Generate security compliance reports.
- Track security posture changes over time.
- Generate alerts when important security controls become disabled or noncompliant.

### Special considerations

- Security scoring should be transparent and explainable.
- A device should not receive a passing score simply because security information is unavailable.
- Distinguish between unsupported, unknown, not configured, and failed checks.
- Do not expose sensitive security information to users without appropriate permissions.

---

## 3. Visual Automation Engine

Provide the ability to create automated workflows that respond to events, device conditions, and scheduled triggers.

The goal is to allow MSP technicians to automate common troubleshooting and maintenance tasks without manually intervening every time an issue occurs.

### Required functionality

**Workflow triggers**

Support triggers such as:

- Device comes online.
- Device goes offline.
- Device checks in.
- CPU utilization exceeds a configured threshold.
- Memory utilization exceeds a configured threshold.
- Disk space falls below a configured threshold.
- A service stops running.
- A Windows event is generated.
- A patch installation fails.
- A device becomes noncompliant.
- A new device is enrolled.
- A device changes organizations or groups.
- A scheduled time or recurring schedule is reached.
- An alert is generated.
- A technician manually initiates a workflow.

**Workflow actions**

Support actions such as:

- Execute PowerShell scripts.
- Execute shell scripts.
- Restart a Windows service.
- Stop or start a service.
- Restart a device.
- Shut down a device.
- Install software.
- Uninstall software.
- Run a maintenance task.
- Collect diagnostic information.
- Generate an alert.
- Send a notification.
- Create a ticket through an integration.
- Modify supported device settings.
- Execute another workflow.

**Conditional logic**

- Support if/then conditions.
- Support multiple conditions.
- Support success and failure branches.
- Support checking the result of an action before proceeding.
- Support delays between actions.
- Support retry attempts.
- Support stopping a workflow when a condition is not met.
- Support collecting output and execution results.

**Workflow management**

- Create, edit, duplicate, enable, and disable workflows.
- Assign workflows to organizations, sites, device groups, or individual devices.
- Provide reusable workflow templates.
- Maintain workflow execution history.
- Show execution status and results.
- Allow technicians to manually execute workflows.
- Report on failed and successful executions.

### Special considerations

- Workflows must not execute indefinitely.
- Prevent accidental execution loops.
- Destructive operations should have appropriate authorization and safeguards.
- Technicians must be able to see what actions a workflow performed.
- Execution output and errors must be available for troubleshooting.
- Support appropriate approval requirements for sensitive actions.
- Workflow execution must respect device availability and maintenance restrictions.

---

## 4. Customer Documentation and Asset Records

Provide centralized customer documentation and IT asset management.

The goal is to give technicians a complete picture of each customer's IT environment without having to search through separate documentation systems.

### Required functionality

**Customer information**
- Customer name and contact information.
- Customer locations and physical addresses.
- Primary and secondary contacts.
- Emergency contacts.
- Business hours.
- Customer-specific notes.
- Customer-specific custom fields.

**Infrastructure documentation**
- Servers.
- Workstations.
- Network equipment.
- Firewalls.
- Switches.
- Wireless access points.
- Printers.
- UPS systems.
- Internet connections.
- Virtualization hosts.
- Storage systems.
- Other infrastructure assets.

**Network documentation**
- IP address assignments.
- Subnets.
- VLANs.
- DNS information.
- DHCP information.
- Gateway information.
- ISP information.
- Circuit identifiers.
- Network equipment details.
- Network diagrams and attachments.

**Asset records**
- Manufacturer.
- Model.
- Serial number.
- Purchase date.
- Warranty expiration.
- Assigned user.
- Physical location.
- Asset status.
- Replacement history.
- Associated documentation.

**Documentation management**
- Allow technicians to create and edit documentation.
- Support notes and rich-text documentation.
- Allow file attachments.
- Associate documentation with customers, sites, devices, and assets.
- Support searchable documentation.
- Maintain documentation revision history.
- Record who created or modified documentation.
- Allow organization-specific documentation.

### Special considerations

- Documentation must be isolated between organizations.
- Sensitive information must have appropriate access restrictions.
- Credentials and secrets should not be casually stored in general documentation fields.
- Support references or integrations with dedicated password management systems.
- Documentation should remain accessible even when the associated device is offline.

---

## 5. Software Catalog and Deployment Policies

Provide centralized software catalog management and automated software deployment.

The goal is to allow MSPs to standardize software installations across customer environments.

### Required functionality

**Software catalog**
- Create and maintain a catalog of approved software.
- Store software name, vendor, version, description, and supported operating systems.
- Support MSI, EXE, MSIX, ZIP, and other appropriate package formats.
- Support silent installation parameters.
- Support silent uninstall parameters.
- Support installation and detection rules.
- Support software dependencies.
- Track available software versions.

**Software deployment**
- Install software on individual devices.
- Deploy software to device groups.
- Deploy software to entire organizations or sites.
- Schedule software installations.
- Track installation progress.
- Report installation success and failure.
- Retry failed installations.
- Support software upgrades.
- Support software removal.
- Support installation rollback where possible.

**Deployment policies**
- Create reusable software bundles.
- Assign bundles to organizations, sites, groups, or devices.
- Automatically install assigned software on newly enrolled devices.
- Enforce approved software versions.
- Identify missing required software.
- Identify unauthorized or prohibited software.
- Generate software compliance reports.

**Example use case**

An MSP creates a standard workstation software bundle containing:

- Google Chrome.
- Microsoft 365 applications.
- 7-Zip.
- Adobe Acrobat Reader.
- VPN client.
- Remote support utilities.

When a new workstation is enrolled and assigned to a customer, the appropriate software bundle is automatically deployed.

### Special considerations

- Installation packages must be verified before execution.
- Track package hashes and versions.
- Handle applications requiring reboots.
- Avoid repeated installations when software is already installed and compliant.
- Report applications that fail to install or install incorrectly.
- Support different software versions and policies for different customers.
- Provide visibility into software installation history.

---

## 6. Remote PowerShell Management

Provide technicians with the ability to execute PowerShell commands and scripts remotely on managed Windows devices.

### Required functionality

- Execute individual PowerShell commands remotely.
- Execute multi-line PowerShell scripts.
- Support interactive PowerShell sessions where feasible.
- Support elevated execution with appropriate authorization.
- Display command output in real time where supported.
- Display standard output and error output separately.
- Return process exit codes.
- Support script execution timeouts.
- Allow technicians to save reusable scripts.
- Maintain command and script execution history.
- Record execution timestamps and the technician responsible.
- Allow execution against individual devices or selected groups.
- Support execution results and status reporting.
- Allow technicians to download command output.

### Special considerations

- Support both Windows PowerShell and PowerShell 7 where installed.
- Clearly identify the PowerShell version being used.
- Support appropriate execution privileges.
- Prevent unauthorized execution of commands.
- All remote command execution must be auditable.
- Sensitive output must not be exposed to unauthorized technicians.
- Handle long-running commands and disconnected devices gracefully.

---

## 7. Remote Windows Registry Editor

Provide technicians with the ability to remotely inspect and modify the Windows Registry.

### Required functionality

- Browse registry keys and subkeys.
- View registry values.
- View registry value types.
- Create registry keys.
- Create registry values.
- Modify existing registry values.
- Delete registry values.
- Delete registry keys.
- Search registry keys and values.
- Export registry keys.
- Import registry data.
- Refresh registry information.
- Support common registry types, including REG_SZ, REG_DWORD, REG_QWORD, REG_BINARY, REG_MULTI_SZ, and REG_EXPAND_SZ.

**Registry locations**

Support access to relevant registry hives:

- HKEY_LOCAL_MACHINE.
- HKEY_CURRENT_USER.
- HKEY_USERS.
- HKEY_CLASSES_ROOT.
- HKEY_CURRENT_CONFIG.

### Special considerations

- Support 32-bit and 64-bit registry views.
- Clearly identify which registry view is being accessed.
- Respect Windows registry permissions.
- Handle inaccessible keys and access-denied errors.
- Provide appropriate safeguards before deleting or modifying important keys.
- Allow exporting a key before modifying it.
- Record registry modifications in the audit history.
- Clearly identify the target device before executing changes.

---

## 8. BitLocker Management

Provide centralized management and visibility into BitLocker disk encryption on Windows devices.

### Required functionality

- Detect whether BitLocker is installed and available.
- Identify encrypted and unencrypted volumes.
- Display encryption status.
- Display encryption percentage.
- Display encryption method.
- Display protection status.
- Identify suspended protection.
- Identify volumes that require attention.
- Initiate BitLocker encryption where supported.
- Suspend and resume BitLocker protection where authorized.
- Decrypt volumes where authorized.
- Retrieve BitLocker recovery information.
- Identify missing or improperly backed-up recovery information.
- Monitor encryption status over time.
- Generate encryption compliance reports.
- Alert when encryption is disabled or protection is unexpectedly suspended.

**Recovery key management**

- Provide authorized technicians with access to recovery keys.
- Allow recovery keys to be retrieved when needed for troubleshooting.
- Display the associated device and volume.
- Record recovery key access in the audit log.
- Support recovery key backup and escrow verification.

### Special considerations

- BitLocker recovery keys are extremely sensitive information.
- Access must be tightly restricted and explicitly permission-controlled.
- Recovery keys must never be exposed in ordinary logs, notifications, or diagnostic output.
- Every recovery key access should be auditable.
- Support TPM-based and password-based protection where applicable.
- Clearly distinguish between encryption being enabled and actual protection being active.
- Account for Windows editions and hardware that do not support all BitLocker capabilities.

---

## 9. Remote Windows Event Viewer and Event Log Management

Provide technicians with the ability to remotely inspect and search Windows Event Logs without having to establish a remote desktop session.

This should provide functionality comparable to Windows Event Viewer, with additional capabilities useful to MSP technicians.

### Required functionality

**Event log browsing**

Support the following logs:

- Application.
- System.
- Security.
- Setup.
- Forwarded Events.
- Microsoft-Windows operational and diagnostic logs.

Allow technicians to browse available event logs and inspect their contents.

**Event searching and filtering**

- Filter by event ID.
- Filter by severity.
- Filter by event source/provider.
- Filter by event category.
- Filter by date and time.
- Filter by keyword.
- Filter by log name.
- Support multiple filter conditions.
- Search across multiple logs.
- Support custom time ranges.

**Event details**

Display:

- Event ID.
- Event level.
- Event source/provider.
- Event timestamp.
- Event log name.
- Event description.
- Event data.
- Associated user where available.
- Computer name.
- XML event details.

**Technician functionality**

- Refresh event logs.
- Search historical events.
- Export selected events.
- Export filtered results.
- View raw XML.
- Copy event details.
- Save frequently used searches.
- Identify recurring event IDs.
- Compare event occurrences over time.

**Useful diagnostic capabilities**

Make it easy to identify common problems, including:

- Unexpected shutdowns.
- Blue screen events.
- Disk and storage errors.
- Windows Update failures.
- Service crashes.
- Application crashes.
- Authentication failures.
- Driver errors.
- Hardware errors.
- Network connectivity problems.
- WHEA hardware errors.

### Special considerations

- Security event logs may require elevated privileges.
- Large event logs must be handled without causing excessive resource consumption.
- Searching should support pagination or other ways to handle large result sets.
- Preserve the original event timestamp and event details.
- Clearly distinguish between events that could not be retrieved and events that do not exist.
- Support Windows event log access on supported Windows versions.

---

## 10. Hardware Diagnostics and Health Monitoring

Provide deeper hardware diagnostics beyond standard CPU, memory, and disk utilization monitoring.

The goal is to help technicians identify failing or degrading hardware before it causes an outage.

### Required functionality

**Storage diagnostics**
- SMART health information.
- Drive temperature.
- Drive model and serial number.
- Drive firmware.
- Reported drive errors.
- Media errors.
- Reallocated sectors where available.
- Pending sectors where available.
- NVMe health information.
- NVMe percentage used.
- SSD wear indicators.
- Identify drives reporting warnings or failures.

**Memory diagnostics**
- Installed memory information.
- Memory module details.
- Memory capacity and speed.
- Memory hardware error reporting.
- Windows hardware error reporting.
- ECC error information where available.

**Thermal monitoring**
- CPU temperature where exposed by hardware.
- GPU temperature where available.
- System temperature.
- Thermal throttling indicators.
- Fan health and speed where available.

**Battery diagnostics**
- Battery health.
- Design capacity.
- Current full-charge capacity.
- Battery wear percentage.
- Charge cycles where available.
- Battery charging status.
- Identify batteries approaching end-of-life.

**General hardware information**
- CPU model.
- CPU core count.
- Memory configuration.
- Motherboard information.
- BIOS version.
- BIOS date.
- Firmware versions.
- Hardware manufacturer and model.

### Special considerations

- Hardware sensor availability varies significantly by manufacturer and model.
- SMART information is not equally available across all storage devices.
- Some hardware information requires elevated privileges.
- Clearly distinguish unavailable information from actual hardware failures.
- Do not report a drive as healthy simply because SMART information could not be retrieved.
- Track historical hardware health changes.
- Generate alerts for significant hardware degradation.

---

## 11. Scheduled Maintenance Tasks

Provide centralized scheduling of recurring maintenance and administrative tasks across managed endpoints.

### Required functionality

- Create scheduled tasks.
- Execute tasks on individual devices.
- Execute tasks on device groups.
- Execute tasks across entire organizations.
- Schedule tasks at specific dates and times.
- Support recurring schedules.
- Support daily, weekly, monthly, and custom recurrence intervals.
- Support maintenance windows.
- Support scheduled PowerShell scripts.
- Support scheduled shell scripts.
- Support software installation and updates.
- Support device restarts.
- Support shutdown operations.
- Support service restarts.
- Support other supported RMM maintenance actions.

**Task management**

- View upcoming scheduled tasks.
- View completed tasks.
- View failed tasks.
- View execution history.
- Edit scheduled tasks.
- Pause and resume scheduled tasks.
- Cancel scheduled tasks.
- Retry failed tasks.
- Configure notifications for failures.
- Report execution results.

**Execution controls**

- Allow tasks to run only within configured maintenance windows.
- Allow tasks to require devices to be online.
- Support retry attempts when devices are offline.
- Support staggered execution across groups of devices.
- Avoid simultaneous restarts of all devices in an organization.
- Support optional technician approval for sensitive actions.

### Special considerations

- Handle time zones correctly at the organization and site level.
- Account for daylight saving time.
- Define what happens when a scheduled task is missed because a device was offline.
- Prevent duplicate execution of the same scheduled task.
- Handle overlapping tasks appropriately.
- Maintain a complete execution history.

---

## 12. Active Directory Health Monitoring

Provide centralized monitoring and diagnostics for Microsoft Active Directory environments.

The goal is to allow MSP technicians to identify domain controller, DNS, replication, authentication, and directory health problems without manually logging into each domain controller.

### Required functionality

**Domain controller monitoring**

- Discover domain controllers.
- Identify domain controller names and IP addresses.
- Monitor domain controller availability.
- Monitor CPU, memory, and disk utilization.
- Monitor critical Active Directory services.
- Identify stopped or unhealthy services.
- Monitor domain controller uptime.
- Monitor operating system versions.
- Monitor domain controller disk capacity.

**Active Directory replication**

- Monitor replication health.
- Identify replication failures.
- Identify replication delays.
- Report replication errors.
- Identify domain controllers that are not replicating correctly.
- Display last successful replication.
- Identify replication partners.
- Report replication-related problems.

**DNS health**

- Monitor Active Directory-integrated DNS.
- Check domain DNS resolution.
- Check SRV records.
- Verify domain controller DNS registration.
- Identify missing or incorrect records.
- Monitor DNS service availability.
- Identify DNS configuration problems affecting domain operations.

**SYSVOL and Group Policy**

- Monitor SYSVOL availability.
- Monitor SYSVOL replication.
- Identify replication failures.
- Monitor NETLOGON availability.
- Identify Group Policy processing problems.
- Report SYSVOL-related errors.

**FSMO role monitoring**

- Identify which domain controllers hold FSMO roles.
- Monitor availability of FSMO role holders.
- Report potential FSMO-related problems.

**Time synchronization**

- Monitor domain time synchronization.
- Identify domain controllers with incorrect time.
- Monitor Windows Time service status.
- Identify time differences that could affect Kerberos authentication.

**User and account monitoring**

- Monitor account lockouts.
- Identify repeated authentication failures.
- Report expired user accounts.
- Identify accounts approaching password expiration.
- Identify disabled accounts.
- Identify stale user accounts.
- Report privileged accounts and group membership changes.
- Monitor Domain Admins membership changes.

**Domain health reporting**

Provide a consolidated Active Directory health report containing:

- Overall domain health.
- Domain controller availability.
- Replication health.
- DNS health.
- SYSVOL health.
- FSMO role status.
- Time synchronization status.
- Critical service status.
- Recent significant errors.
- Outstanding problems requiring attention.

### Special considerations

- Support environments with multiple domain controllers.
- Support multiple Active Directory domains and forests where applicable.
- Clearly identify the domain controller associated with each problem.
- Distinguish between warnings and critical failures.
- Avoid reporting a domain as healthy when a critical diagnostic could not be completed.
- Provide actionable diagnostic details rather than simply displaying a failed status.
- Support scheduled health checks and historical reporting.
- Respect domain-level permissions and security boundaries.

---

# Overall Feature Expectations

All of these capabilities should provide a consistent experience within EasyRMM.

The following expectations apply across the feature set:

1. Features should support multi-tenant operation and appropriate permission boundaries.
2. Technicians should be able to see relevant execution history and results.
3. Remote operations should report success, failure, and meaningful error information.
4. Where applicable, features should support organization, site, group, and individual device targeting.
5. Features should support reporting and notifications where appropriate.
6. Sensitive operations should require appropriate permissions and generate audit records.
7. Information should clearly distinguish between healthy, unhealthy, unknown, unsupported, and unavailable states.
8. Features should work reliably when endpoints temporarily go offline and reconnect.
9. Where functionality depends on operating system capabilities, clearly identify supported and unsupported environments.
10. All functionality should be suitable for real-world MSP operations and not merely demonstrations.

**The objective is to expand EasyRMM into a comprehensive MSP management platform that provides endpoint management, security visibility, infrastructure diagnostics, customer documentation, automation, and technician productivity tools in one unified product.**

---

# Addendum: the keystore

Not part of the requirements above. The owner's own words, 2026-11-21,
after the twelve:

> I think we should also create a highly secure keystore, to backup bitlocker keys for client devices as well

Then, about Linux LUKS recovery keys:

> yah it can hold LUKS to thats fine

So the keystore holds BitLocker and LUKS recovery keys. How it is built
is in the [plan](../feature-plan-msp.md#the-keystore-for-bitlocker-and-luks-recovery-keys).
