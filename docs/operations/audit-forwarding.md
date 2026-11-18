# Forwarding the audit log

EasyRMM can send a copy of every audit record to your syslog server or SIEM
as it is written, so that the record of who did what survives even if the
EasyRMM server does not. The design is in
[ADR-0023](../architecture/adr/0023-audit-forwarding.md).

## Turning it on
Super administrators find it under **Settings → Audit forwarding**.

1. Enter the collector's host name or IP address and choose the transport:
   * **TLS** (RFC 5425, port 6514): encrypted, and the collector's
     certificate is checked. Recommended.
   * **TCP** (RFC 6587, octet counting, usually port 514): not encrypted.
   * **UDP** (RFC 5426, port 514): not encrypted and no confirmation that
     anything arrived. Use it only on a network you trust.
2. For TLS, paste the certificate of the authority that signed the
   collector's certificate if it is a private one. Left empty, the
   authorities the server trusts are used. If the collector requires
   client certificates, paste one and its unencrypted private key; the key
   is stored encrypted with the server's secret key and never shown again.
3. Choose a facility (log audit, 13, unless your collector routes on
   another one).
4. **Send test message** sends one message with the settings as they are
   in the form, saved or not, and says what happened: connection refused,
   certificate problems and timeouts are reported in words.
5. Choose where to start: every record the server still keeps, or only
   records written from now on. Then **Save**.

The status beside the form shows whether forwarding is working, when it
last sent, how many records are waiting and the latest error.

## What arrives
One RFC 5424 message per audit record:

```
<110>1 2026-11-16T08:24:19.032999Z rmm.example.com easyrmm - device.remote_session [origin software="EasyRMM" swVersion="1.4.0"] {"id":144,"occurredAt":"2026-11-16T08:24:19.032999Z","actorType":"user","actorId":"…","actorLabel":"tech@msp.example","organizationId":"…","siteId":"…","deviceId":"…","action":"device.remote_session","targetType":"device","targetId":"…","outcome":"success","sourceIp":"203.0.113.7","userAgent":"Mozilla/5.0 …","details":{"kind":"desktop","device":"FRONT-DESK"},"prevHash":"…","entryHash":"…"}
```

* **Severity** follows the outcome: informational (success), notice
  (failure, such as a wrong password) or warning (denied).
* **Message ID** is the action; the console's **Audit log** lists them.
* **Message** is the record as JSON: the fields of `GET /api/v1/audit`, plus
  `prevHash` and `entryHash`. Each record's `prevHash` is the previous
  record's `entryHash`, so a collector can tell when a record is missing or
  was changed.
* Over UDP, a record whose message would exceed 8 KiB is sent without its
  details (`{"truncated": true, "size": n}`); the full record stays in
  EasyRMM.

## Delivery
* Records go in order, at most two seconds after they are written, in
  batches of up to 500 while there is a backlog.
* After an outage (of the collector, the network or EasyRMM) forwarding
  resumes from the first record the collector has not received. A record
  can arrive twice after a failure; its `id` tells the copies apart.
* While forwarding is on, audit retention (`EASYRMM_AUDIT_RETENTION`) keeps
  records the collector has not received yet.
* Turning forwarding off is itself recorded and forwarded: it is the last
  message the collector receives.
* With several EasyRMM servers on one database, one of them forwards at a
  time.
* TCP and TLS confirm that the server sent the bytes, not that the collector
  stored them; a collector that crashes can lose the last records it was
  sent. Compare `id`s and hashes to find gaps.

## Example: rsyslog
This configuration receives all three transports and writes each record's
JSON to a file of its own (tested with rsyslog 8.2504):

```
global(
  DefaultNetstreamDriverCAFile="/etc/rsyslog-tls/ca.pem"
  DefaultNetstreamDriverCertFile="/etc/rsyslog-tls/server.pem"
  DefaultNetstreamDriverKeyFile="/etc/rsyslog-tls/server.key"
  maxMessageSize="64k"
)
module(load="imudp")
module(load="imtcp")
input(type="imudp" port="514" ruleset="easyrmm")
input(type="imtcp" port="514" ruleset="easyrmm")
input(type="imtcp" port="6514" ruleset="easyrmm"
      streamDriver.name="gtls" streamDriver.mode="1" streamDriver.authMode="anon")

template(name="easyrmm-json" type="string" string="%msg%\n")
ruleset(name="easyrmm") {
  if $app-name == "easyrmm" then {
    action(type="omfile" file="/var/log/easyrmm-audit.jsonl" template="easyrmm-json")
  }
}
```

TLS needs the `rsyslog-gnutls` package. `maxMessageSize` matters for TCP and
TLS: rsyslog's default of 8 KiB would cut records with large details. To
require client certificates, use `streamDriver.authMode="x509/certvalid"`
and give EasyRMM a client certificate from the same authority.

## Troubleshooting
| Message | What to check |
|---|---|
| Connection refused: nothing accepts … connections on host:port | The collector is not listening on that port, or listens on another address |
| The collector's certificate is not signed by a trusted certificate authority | Paste the authority's certificate in **CA certificate** |
| The collector's certificate is not valid for *host* | The host name you entered is not in the certificate; use the name the certificate was issued for |
| The collector closed the connection as soon as it was opened | A firewall or allow list on the collector, or (TLS) a required client certificate |
| The collector refused the TLS connection (…) | The collector requires a client certificate, or does not accept this one |
| Timed out reaching host:port | A firewall drops the traffic, or the host is down |
| The stored client key cannot be opened | `EASYRMM_SECRET_KEY` changed without the old key in `EASYRMM_SECRET_KEYS_PREVIOUS`; paste the key again |
| EasyRMM does not connect to *address* | The host is, or resolves to, a link-local address (`169.254.0.0/16`, `fe80::/10`) or a cloud provider's instance metadata address. EasyRMM never connects there, so that settings cannot reach instance credentials. Use the collector's regular address; loopback and private addresses work |
