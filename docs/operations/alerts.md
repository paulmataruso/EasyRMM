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
| **Remote access down** | The EasyRMM agent checks in, but MeshAgent has not been connected to MeshCentral for N minutes (3 to 1,440) | MeshCentral sees MeshAgent connected |
| **EasyRMM agent silent** | MeshCentral sees MeshAgent connected, but the EasyRMM agent has not checked in for N minutes (3 to 1,440) | The EasyRMM agent checks in |

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

New installations start with eleven shared policies:

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
| Remote access down | MeshAgent not connected for 15 minutes, the agent checking in | Critical | Yes |
| EasyRMM agent silent | No EasyRMM check-in for 15 minutes, MeshAgent connected | Critical | Yes |

Change or delete them like any other policy. An upgrade adds the five
disk health policies the same way, only **Disk failing** turned on: a
failing drive is worth an alert everywhere, while a single reallocated
sector, 90% wear or a warm drive is each MSP's call.

**Names already taken.** Policy names are unique at each level, case
aside. Where a shared policy already has one of these names (*Disk
failing*, say), the upgrade adds the new one as *Disk failing (disk
health)*; where both names are taken, it adds no policy for that check,
and you add one yourself if you want it.

### Remote access policies

*Remote access down* and *EasyRMM agent silent* are about a device whose
two agents disagree
([ADR-0069](../architecture/adr/0069-recovery-agent-logs-and-one-device-tree.md)).
An operator can change their minutes or turn them off, and add
organization or site policies of the same kinds.

* Neither opens for a device that is being removed (its removal asked for,
  or its EasyPatch agent being removed or opted out); an alert open when
  the device starts to leave resolves as *Device left the policy's scope*.
* Nothing is judged while EasyRMM's own connection to MeshCentral is down,
  or within 15 minutes after it returns, so an outage of MeshCentral, or a
  restart of the server, opens no alert on every device. Open alerts stay
  as they are meanwhile. Without remote access on the server, their alerts
  resolve.
* *Remote access down* needs the site to have a MeshCentral device group,
  and the EasyRMM agent to be checking in. Its alert says why MeshAgent is
  not connected, in the watchdog's words (see
  [Remote access](remote-access.md#why-remote-access-is-not-connected)),
  and its card lists the repairs tried since it opened.
* *EasyRMM agent silent* waits as the offline policy does after the server
  starts, since agents cannot check in before it serves them.

### Repair failed

*Repair failed* is a warning that belongs to no policy
([ADR-0069](../architecture/adr/0069-recovery-agent-logs-and-one-device-tree.md)):
EasyRMM raises it when an automatic repair of MeshAgent, the EasyPatch
agent or the EasyRMM agent (through patching) ends with the agent still broken. Its details are the last step's
diagnostics, and its card lists the repairs tried (see
[Automatic repairs](remote-access.md#automatic-repairs)). A device has one
for each agent until the agent is back, when it resolves; acknowledging and
resolving by hand work as for any alert. A device being removed has none.

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
| **Temperature** | Every reading of the policy's minutes (60 to 1,440, at least two readings) is at or above the temperature | 1 to 100 °C, or each drive's own limit | At least 5 °C below it |

* Only **complete readings** count: readings that read the drive's own
  verdict and the facts the check watches. A disk that was asleep, timed
  out, or could not be read changes nothing: its alert stays as it is, and
  nothing opens on it.
* An alert opens only on a complete reading **from the last day**, which
  a disk that sleeps is still read within, and resolves only on readings
  taken **after it opened**.
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

### An alert's card

Select an alert's name, on the **Alerts** page, in a device's **Alerts**
card, under **Needs attention** or in a disk's panel, for everything
EasyRMM recorded about it. The card has its own address (`?alert=` and
the alert's ID on the page you were on), so you can send it to someone
who can see the alert. **Close** and Escape close it, however you
reached it, as does the browser's **Back** when you opened it from a
list.

| Section | Shows |
|---|---|
| **Summary** | Severity, state and kind; the device (and whether it is online now), its site and organization, each linked; for disk health, the disk and what holds |
| **Why it opened** | The condition the alert opened under, its policy by name (with its scope and description, and the condition it has now if it changed since; the **Policies** tab lists every policy), the value when it opened and the latest. For an offline alert, when the device was last seen |
| **Measurements** | Processor, memory and disk use alerts: the measurement from the policy's minutes before the alert opened until it resolved (or now), with the threshold as a dashed line and the time it was open shaded. **Show as a table** lists the points. Measurements are kept for `EASYRMM_METRICS_RETENTION` (7 days by default): for an alert older than that, the chart starts at the oldest measurement kept and says that earlier ones are no longer kept |
| **The disk** and **Facts** | Disk health alerts: the disk's state now and its facts, as its panel on the **Hardware** tab shows them |
| **Times** | When it opened, how long it has been or was open, when it was acknowledged and by whom, and when and how it resolved |
| **What it means** and **What to do next** | What holds while it is active, what to check, and links to the device's tabs that show more |
| **History** | The policy's other alerts on the device (for disk health, on the same disk), newest first, up to 20, each opening its own card: an alert resolved by hand that opened again shows here as a new one |
| **Raw details** | The alert as the API returns it, folded, with **Copy** |

Alerts hold no notes, and record no change between opening and resolving
other than the acknowledgement and the latest value, so the card shows
none. Patching alerts have a card of their own under **Patching →
Alerts** (see [Patching alerts](patching.md#alerts)).

### What pulses in red

So that what needs attention stands out while the console is open all
day, these pulse slowly between their normal colour and red:

* On a device's page, every **active** alert (open or acknowledged) in its
  **Alerts** card, and the number of active alerts beside the card's
  title; and the same in a disk's panel on the **Hardware** tab, under
  **Open alerts**. Each alert keeps its severity badge, so the pulse means
  *active*, not *critical*.
* On the **Alerts** page, the name of a device that has an active
  **critical** alert, in every row of that device, whatever the page is
  showing. The name carries the critical icon beside it.
* In the menu's **Alerts** tree, the name of a device that has an active
  critical alert, beside its red count.

The pulse takes 1.8 seconds, well under the three flashes a second that
can trigger seizures, and changes only text colour and a soft tint, never
a large area. Red is never the only sign: the severity badge, the critical
icon and the counts say the same in words, and screen readers hear them
once, not on every pulse. With **reduce motion** turned on in the
operating system or browser, nothing pulses: the same places show a
steady red instead.

The pulse lasts as long as the alert, so anyone can stop it: **Stop
flashing** at the top of the **Alerts** page, or beside **History** on a
device's **Alerts** card, holds every pulse in the same steady red, and
**Flash active alerts** starts it again. The choice applies everywhere in
the console and is kept in this browser, as the theme is (the console has
no per-user preferences yet); another browser, or a cleared one, flashes
again.

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

## API

Every route answers only for devices the caller may see: an alert on
another organization's or site's device is `404`, as is one that does
not exist.

| Route | Needs | Does |
|---|---|---|
| `GET /api/v1/alerts` | `alert.view` | Alerts newest first. `status` (`active`, the default, `resolved` or `all`), `organizationId`, `siteId`, `deviceId`, `severity`, `policyId` (one policy's alerts), `subject` (a disk's identity, for disk health), `limit` (1 to 500) and `before` (the `next` of the page before) |
| `GET /api/v1/alerts/summary` | `alert.view` | Active, critical, warning and acknowledged counts, and how many devices have an active alert |
| `GET /api/v1/alerts/devices` | `alert.view` | Each device with an active alert: its active and critical counts |
| `GET /api/v1/alerts/{id}` | `alert.view` | One alert, with `canManage` |
| `GET /api/v1/alerts/{id}/metrics` | `alert.view` and `device.view` on the device | A processor, memory or disk use alert's measurement: `metric`, `threshold`, `from` and `to` (the policy's minutes before it opened until it resolved or now, with a quarter of that either side, at least 15 minutes and at most 6 hours; never before the oldest measurement kept, `EASYRMM_METRICS_RETENTION` ago, and never past now), `trimmed` (`true` when `from` is later than that window's start because earlier measurements are no longer kept), `bucketSeconds` (the narrowest width from 1 minute to 1 day, or whole days past that, that gives at most 240 points for any window) and `samples` (`at`, the average `value`). `409 alert_has_no_metrics` for offline and disk health alerts |
| `POST /api/v1/alerts/{id}/acknowledge`, `…/resolve` | `alert.manage` | Acknowledges or resolves it; `409 alert_resolved` once resolved |
| `GET`, `POST /api/v1/alert-policies`; `GET`, `PATCH`, `DELETE …/{id}` | `monitoring.view`; `monitoring.manage` to change | The policies that apply to the caller |

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
