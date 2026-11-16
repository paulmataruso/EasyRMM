# Alerts

EasyRMM raises an **alert** when a device stops checking in or runs short
of processor, memory or disk. **Alert policies** decide what counts as
trouble. The design is in
[ADR-0019](../architecture/adr/0019-monitoring-and-alerts.md).

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

New installations start with four shared policies, all turned on:

| Policy | Condition | Severity |
|---|---|---|
| Device offline | No check-in for 15 minutes | Critical |
| Disk almost full | A disk 90% full or more for 5 minutes | Critical |
| High memory use | Memory at 95% or more for 15 minutes | Warning |
| High processor use | Processor at 95% or more for 15 minutes | Warning |

Change or delete them like any other policy.

## Working with alerts

The server checks every enabled policy once a minute. An alert is
**open**, **acknowledged** or **resolved**:

* **Acknowledge** says someone is on it. The alert stays active and
  resolves on its own when the condition clears.
* **Resolve** closes it by hand. If the condition still holds, the next
  check opens a new alert within a minute; acknowledge instead to quiet it.
* Alerts also resolve when their policy is turned off, deleted or given a
  different condition, or when the device moves out of the policy's
  organization or site. The **Status** column says which.

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
least a day).

## Troubleshooting

| What you see | What to check |
|---|---|
| No processor, memory or disk alerts on a device | The device needs the EasyRMM agent (Linux for now); MeshAgent alone sends no measurements. Check its **Health** card |
| An alert reopens right after **Resolve** | The condition still holds. Acknowledge it instead, fix the cause, or change the policy |
| An offline alert on a device that is up | Neither agent is connected. Check `sudo easyrmm-agent status` on the device and the **Last seen** time on its page |
| Nothing at all is alerting | Check the **Policies** tab: the policies may be turned off. The server logs `monitoring: evaluating alert policies failed` if checks fail |
