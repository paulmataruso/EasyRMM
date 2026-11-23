# Agent logs

The device page's **Logs** tab shows what the agents on a computer are doing,
without signing in to it: the EasyRMM agent's own log, and new lines from the
EasyPatch agent's log and from MeshAgent's, each tagged with its source
([ADR-0069](../architecture/adr/0069-recovery-agent-logs-and-one-device-tree.md),
Part L).

## Who can do what

| Action | Permission |
|---|---|
| Read a device's logs, follow them live, download them | `log.view`: Technicians and above (Read-Only does not hold it) |
| Turn verbose logging on or off for a device or a group | `device.edit` |

Both apply where the role is. Downloads and verbose changes are recorded in
the audit log (*Downloaded agent logs*, *Verbose logging on*, *Verbose logging
off*); reading the tab is not, as reading is the point of a log.

## What the agent sends

* **Levels.** The EasyRMM agent logs at Info. In **verbose** mode it logs at
  Debug. Verbose mode is set for 1 to 24 hours (2 by default) from the tab's
  *Verbose for…*, on the device or on its group, and ends by itself: the
  agent returns to Info at the end time even if it hears nothing from the
  server.
* **Batches.** The agent keeps its records in a file under its state folder
  (`logs/shipping.buf`, at most 20 MB; the oldest are dropped first and the
  next batch says how many). It sends up to 500 records at a time, signed like
  its heartbeat, to `POST /api/agent/v1/agent-logs` every 30 seconds, and
  every 2 seconds while someone has the tab open. The server answers with the
  highest sequence number it took care of, and the agent drops what was
  acknowledged. A batch sent twice stores nothing twice.
* **Following.** The console's read with `follow=true` marks the device as
  watched for 20 seconds. The agent learns it from the next heartbeat answer
  or batch answer (`logs.followUntil`), so the first 2-second sends can start
  up to a minute after the tab is opened. ADR-0069 names this message
  `logs.follow` on the agent channel (ADR-0059); the channel is not built
  yet, and the message will move there.
* **Other agents' logs.** The agent reads new lines from the EasyPatch
  agent's `agent.log` (`C:\ProgramData\EasyPatch\logs` on Windows,
  `/var/lib/easypatch/logs` on Linux) and from `meshagent.log` in MeshAgent's
  folder where MeshAgent keeps one. It remembers where it stopped, so a
  restart neither skips nor repeats lines. Verbose mode does not change the
  EasyPatch agent's own level yet.
* **Secrets.** Before a record leaves the computer, and again on the server
  before it is stored, the values of fields named like secrets (token,
  password, secret, key, authorization, cookie), anything shaped like an
  EasyRMM enrollment token (`ert_`) or an EasyPatch token (`ept_`), bearer
  tokens and PEM blocks are replaced. The two sides share one set of rules
  (`internal/logredact`). Records can still hold host names, user names and
  paths; see [PRIVACY.md](../../PRIVACY.md).

## What the server keeps

* One table, `agent_log_records`, with the device's row-level security.
* **Retention**: 14 days by default, `EASYRMM_AGENT_LOG_RETENTION_DAYS`, 1 to
  90 ([configuration](../deployment/docker.md)). The server's hourly
  maintenance deletes older records in batches of 5,000, so a short retention
  after a long one does not hold a long transaction.
* **Cap**: at most 200,000 records per device per UTC day. Records past the
  cap are not stored and the log says so in a record of the server's own;
  likewise for records the agent dropped. Expect a few hundred records a day
  per device at Info and up to about 50,000 a day in verbose mode.

## Using the tab

* **Live tail** shows new records as they arrive (the page asks every 2
  seconds) and stays at the bottom unless you scroll up. *Pause live tail*
  stops asking, and the agent returns to sending every 30 seconds.
* **Filters** by source, level (a level and above), time (the last 15 minutes
  to 7 days) and text (messages and details, any case).
* **Download** gives the records that match the filters, oldest first, as text
  (one record per line) or JSON lines, up to 200,000 records.
* **Verbose for…** asks for 1 to 24 hours on the device, or on every device in
  its group, including devices added to the group meanwhile.
