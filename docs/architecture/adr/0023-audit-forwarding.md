# ADR-0023: Forwarding the audit log over syslog

* Status: Accepted (2026-11-16).

## Context
EasyRMM's audit log is append-only and hash-chained (ADR-0007), but it
lives on the server it describes. Someone who takes over that server, or
its database, can stop recording, or delete the log and the chain with it.
MSPs, and their customers' auditors, expect a copy that leaves the host as
records are written, in their SIEM or log server. The common denominator
of those is syslog.

## Decision
* **What goes.** Every audit record, of every organization, in id order,
  from the moment forwarding is turned on (either every record still kept,
  or only new ones). Settings are platform-wide and need `settings.manage`
  everywhere (super administrators); changing them and sending a test
  message are audited.
* **Format: RFC 5424.** `<PRI>1 TIMESTAMP HOSTNAME easyrmm - MSGID
  [origin software="EasyRMM" swVersion="…"] MSG`:
  * PRI: the chosen facility (log audit, 13, by default; auth, authpriv
    or local0–7) and a severity from the outcome: informational for
    success, notice for failure, warning for denied.
  * TIMESTAMP: when the action happened, UTC, microseconds.
  * HOSTNAME: the server's public host name (`EASYRMM_PUBLIC_URL`).
  * MSGID: the action, such as `device.remote_session`.
  * MSG: the record as JSON, the same fields as the console API's audit
    entries, plus `prevHash` and `entryHash`, so the collector holds the
    chain and can tell a missing or altered record. No byte order mark
    (RFC 5424's MSG-ANY), which is what JSON-parsing collectors expect.
  * Only IANA-registered structured data is used (`origin`): EasyRMM has
    no private enterprise number for SD-IDs of its own, and the JSON
    carries the fields.
* **Transports.** TLS (RFC 5425, TLS 1.2 or later, the default), TCP
  (RFC 6587 octet counting) or UDP (RFC 5426). TLS checks the collector's
  certificate against the system's authorities, or only against a CA
  certificate the administrator pastes; a client certificate and key are
  optional, the key sealed with the server's secret key (`EASYRMM_SECRET_KEY`) and
  never returned. UDP datagrams are capped at 8 KiB: a larger record goes
  without its details (`{"truncated": true, "size": n}`); stream messages
  are capped at 64 KiB, which no record reaches (details are at most
  16 KiB).
* **Delivery: in order, at least once, resumable.** One row
  (`audit_forwarding`) holds the settings and the id of the last record
  handed to the collector. Records are appended under an advisory lock
  (ADR-0007), so ids become visible in order and a cursor on the id misses
  none. Every two seconds (at once while there is a backlog) the forwarder
  takes its own advisory lock, so that only one server forwards, reads up
  to 500 records after the cursor, sends them over a kept-open connection,
  and moves the cursor in the same transaction. Before each round it checks
  that the collector has not closed the connection, and after connecting it
  waits half a second for the collector to turn the connection away (TLS 1.3
  refuses a client certificate only after the client's handshake is done).
  A failure leaves the cursor where it was, is recorded with its time, and
  is retried with back-off up to a minute; a record can therefore arrive
  twice, never out of order and never skipped.
* **Retention waits.** While forwarding is on, audit retention does not
  delete records the collector has not received.
* **Turning it off is forwarded.** The change that turns forwarding off is
  the last record sent: the forwarder delivers everything up to it, then
  stops. A collector that stops hearing from EasyRMM can see why.
* **Console.** Settings → Audit forwarding: the destination, a test
  message with the unsaved settings, and the state: forwarding, failing
  (with the error in words), catching up, sending its last records, or off;
  when it last sent, how many records wait and how old the oldest is.

## Consequences
* TCP and TLS confirm that bytes left the server, not that the collector
  stored them: records written just before a collector crashes can be lost
  from its copy. RELP (application-level acknowledgements) would close that
  gap and is not implemented; the hash chain shows the collector what it
  is missing.
* UDP gives no delivery confirmation and no encryption; the console says
  so and recommends TLS.
* A collector that is down for longer than the audit retention keeps the
  log growing on the server until it comes back or forwarding is turned
  off.
* Sending a test message makes the server connect to any address a super
  administrator types, which they could already do in other ways
  (MeshCentral, scripts); it is audited.
