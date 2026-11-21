# Alerts

EasyRMM raises an **alert** when a device stops checking in, runs short
of processor, memory or disk, or has a disk whose health is failing or
wearing. **Alert policies** decide what counts as trouble. The design is
in [ADR-0019](../architecture/adr/0019-monitoring-and-alerts.md); disk
health's in [ADR-0065](../architecture/adr/0065-hardware-health.md).

Alerts show in the console only for now. E-mail and webhook notifications
are not built yet.

## Policies

A policy watches one condition on the devices it covers:

| Condition | Raises an alert when | Resolves when |
|---|---|---|
| **Device offline** | The device has not checked in for N minutes (3 to 1,440) | The device checks in |
| **Processor use** | Every measurement in the last N minutes (1 to 1,440) is at or above the percentage | Every measurement of the last 5 minutes (or N, when shorter) is below it |
| **Memory use** | The same, for memory in use | The same |
| **Disk use** | The same, for the fullest filesystem | The same |
| **Disk health** | One of five checks holds on a disk: see [Disk health policies](#disk-health-policies) | Two readings in a row clear it |

* A device **checks in** while its EasyRMM agent or MeshAgent is connected,
  so the offline condition works on every device.
* Processor, memory and disk come from the EasyRMM agent's measurements,
  sent once a minute (see [Inventory and health](inventory.md)). A policy
  needs at least half its minutes measured before it raises an alert, so a
  device that has just come back does not trip on one reading.
* A device that stops sending measurements keeps its processor, memory and
  disk alerts as they are. Whether it is offline is the offline policy's
  business.
* Each policy has a severity, **warning** or **critical**, and can be
  turned off without deleting it.

A policy covers **every device** (shared), **one organization's devices**
or **one site's devices**. Several policies can cover a device; each raises
its own alert.

New installations start with nine shared policies:

| Policy | Condition | Severity | On |
|---|---|---|---|
| Device offline | No check-in for 15 minutes | Critical | Yes |
| Disk almost full | A disk 90% full or more for 5 minutes | Critical | Yes |
| High memory use | Memory at 95% or more for 15 minutes | Warning | Yes |
| High processor use | Processor at 95% or more for 15 minutes | Warning | Yes |
| Disk failing | A disk's own verdict says it is failing | Critical | Yes |
| Disk errors | 1 reallocated sector or NVMe media error or more | Warning | No |
| Disk sectors pending | 1 sector pending or offline-uncorrectable or more | Warning | No |
| Disk wearing out | 90% of rated endurance used or more | Warning | No |
| Disk too hot | Every reading of an hour at or above the drive's own limit | Warning | No |

Change or delete them like any other policy. An upgrade adds the five
disk health policies the same way, only **Disk failing** turned on: a
failing drive is worth an alert everywhere, while a single reallocated
sector, 90% wear or a warm drive is each MSP's call.

**Names already taken.** Policy names are unique at each level, case
aside. Where a shared policy already has one of these names (*Disk
failing*, say), the upgrade adds the new one as *Disk failing (disk
health)*; where both names are taken, it adds no policy for that check,
and you add one yourself if you want it.

### Disk health policies

The EasyRMM agent reads each disk's health every 30 minutes, and the
server judges what it read ([Disk health](disk-health.md)). A disk
health policy watches **one check** on every disk of the devices it
covers, with **one alert per disk**: two failing disks on one server are
two alerts, and acknowledging one leaves the other open.

| Check | Raises an alert when | Threshold | Resolves after two readings in a row |
|---|---|---|---|
| **Failing** | The disk's reading is failing: SMART status *threshold exceeded*, a pre-fail attribute at or below its threshold, or an NVMe critical warning about spare, reliability, read-only media or volatile memory backup | None | That are not failing |
| **Errors** | Reallocated sectors plus NVMe media errors are at or above the count | A count, 1 to 100 | Below the count |
| **Pending** | Pending plus offline-uncorrectable sectors are at or above the count | A count, 1 to 100 | Below the count |
| **Wear** | Rated endurance used is at or above the percentage | 1 to 100% | Below it |
| **Temperature** | Every reading of the policy's minutes (30 to 1,440, at least two readings) is at or above the temperature | 1 to 100 °C, or each drive's own limit | At least 5 °C below it |

* Only **complete readings** count: readings that read the drive's own
  verdict and the facts the check watches. A disk that was asleep, timed
  out, or could not be read changes nothing: its alert stays as it is, and
  nothing opens on it.
* With **the drive's own limit**, a temperature check judges only drives
  that report one (NVMe's warning temperature, ATA's specified maximum);
  give a temperature in °C to cover the others.
* The alert names the disk (*nvme0n1 · Samsung SSD 980 1TB*, never its
  serial) and says what holds (*Pending sectors 8, uncorrectable sectors
  0*). Its value is the count, percentage or temperature, or 1 for
  failing.
* **Counts that only rise.** Reallocated sectors, media errors and wear do
  not go down, so an errors or wear alert resolves only when its
  threshold is raised or the disk is replaced. Acknowledge it rather than
  resolve it: resolved by hand while the condition holds, it opens again
  within a minute. Pending sectors do fall again (smartmontools:
  "when all pending sectors have been reallocated or could be read
  again"), so a pending alert can resolve on its own.
* **A disk that disappears** from the device's readings keeps its alerts:
  a disk that died and dropped off the bus stays in view until someone
  looks. Resolve them by hand, or they resolve on their own (*Disk gone*)
  once the disk has been missing for 14 days: no disk reading of the
  device has listed it since. A disk listed again before then is no
  longer missing, and its alerts carry on; one that comes back after
  them gets new ones if its condition holds.

## Restarts and upgrades

A restart or an upgrade of the server stops every device's check-ins for
a while, and agents then wait up to 5 minutes between attempts. So that
this raises no alert, offline policies count every device as seen no
earlier than 5 minutes after the server began serving agents: after it
started, or after the updater stopped holding it
([ADR-0052](../architecture/adr/0052-the-host-updater.md)). A device that
is really down raises its offline alert that much later after a restart:
with the default 15-minute policy, 20 minutes after the server is back.
The rule only delays openings: an offline alert that was already open
stays open, and resolves only when the device checks in. While the
updater holds the server, no offline alert opens.

## Working with alerts

The server checks every enabled policy once a minute. An alert is
**open**, **acknowledged** or **resolved**:

* **Acknowledge** says someone is on it. The alert stays active and
  resolves on its own when the condition clears.
* **Resolve** closes it by hand. If the condition still holds, the next
  check opens a new alert within a minute; acknowledge instead to quiet it.
* Alerts also resolve when their policy is turned off, deleted or given a
  different condition (kind, check, threshold or minutes), or when the
  device moves out of the policy's organization or site, and a disk health
  alert when its disk is gone (see above). The **Status** column says
  which.

Changing a policy's name or severity carries over to its active alerts.
Resolved alerts keep the name and condition they had.

In the console:

* **Alerts** in the menu shows how many alerts are active, in red when one
  is critical. The page lists active alerts (or resolved, or all), newest
  first, filtered by organization, severity or device. The **Policies**
  tab lists the policies that apply to you and lets administrators add,
  change, turn off and delete them.
* The device page's **Alerts** card lists that device's active alerts.
  **History** opens all of its alerts.
* The dashboard counts active alerts and lists the most pressing ones,
  critical first, under **Needs attention**.

## Who can do what

| Permission | Allows | Roles |
|---|---|---|
| `alert.view` | See alerts on the devices you can see | Every role |
| `alert.manage` | Acknowledge and resolve them | Technician and above |
| `monitoring.view` | See the policies that apply to you | Every role |
| `monitoring.manage` | Add, change and delete policies at your level | Site administrator and above |

Shared policies are written by Super Administrators, organization
policies by organization administrators, and site policies by site
administrators. Adding, changing and deleting policies and acknowledging
and resolving alerts are audited. Alerts the server opens and resolves on
its own are not; the alert itself is the record.

## Retention

Active alerts stay until they resolve. Resolved alerts are kept for
`EASYRMM_ALERT_RETENTION` (default `2160h`, 90 days; at least `24h`) and
removed hourly after that. Deleting a device removes its alerts.

Conditions are evaluated from the measurements kept for charts, so a
policy can watch at most 24 hours (`EASYRMM_METRICS_RETENTION` is at
least a day). Disk health checks read every disk reading kept for
`EASYRMM_METRICS_RETENTION`; a disk not read for longer opens and
resolves nothing until it is read again.

## Troubleshooting

| What you see | What to check |
|---|---|
| No processor, memory or disk alerts on a device | The device needs the EasyRMM agent (Windows or Linux); MeshAgent alone sends no measurements. Check its **Health** card |
| An alert reopens right after **Resolve** | The condition still holds. Acknowledge it instead, fix the cause, or change the policy |
| An offline alert on a device that is up | Neither agent is connected. Check `sudo easyrmm-agent status` on the device and the **Last seen** time on its page |
| Nothing at all is alerting | Check the **Policies** tab: the policies may be turned off. The server logs `monitoring: evaluating alert policies failed` if checks fail |
