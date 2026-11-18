# Alerts and notifications

EasyPatch watches for conditions that need attention, such as endpoints that stopped checking in
or security updates that stay missing. It shows them as **alerts** and, if you set up channels,
sends **notifications** by email or webhook (Slack, Microsoft Teams, or a signed JSON webhook
for PSA and ticketing systems).

* Everyone can see the alerts of the organizations they have access to, on the **Alerts** page,
  the dashboard and the badge in the navigation.
* Admins and super administrators can **acknowledge** alerts.
* Only super administrators can manage alert rules (**Settings → Alert rules**) and
  notifications (**Settings → Notifications**).

## How alerts work

The worker evaluates the enabled rules every two minutes.

* **Open.** An alert opens when a rule matches a subject: an endpoint, or an organization for
  enrollment requests. Each rule and subject has at most one unresolved alert, and later
  evaluations update its title, details and *last seen* time.
* **Resolve.** An alert resolves by itself after **two consecutive evaluations** in which the
  condition no longer holds, so a single flapping check-in does not close and reopen it. If the
  condition returns within an hour of resolving, the same alert reopens without a new
  notification.
* **Offline endpoints** raise only the *Endpoint offline* alert. While an endpoint is offline its
  data is not current, so the other rules do not open new alerts for it.
* **Acknowledge** marks an alert as being handled. It stays visible until the condition clears,
  and no reminders are sent for it. Acknowledging is recorded in the audit log.
* **Closed without notification.** Alerts close silently when their rule is disabled, deleted or
  has its condition or scope changed, or when their organization is archived or their endpoint
  is removed or revoked.

### Default rules

The installation (or upgrade) creates these rules. They are enabled, but they have no channels,
so they show alerts in the console only until you add channels.

| Rule | Opens when | Severity | Default threshold |
|---|---|---|---|
| Endpoint offline | An endpoint has not checked in for longer than the threshold. | Warning | 24 hours (1-720) |
| Update installation failed | An endpoint has updates whose last installation attempt failed. | Warning | — |
| Security update missing | A required security update is still missing this many days after it became required. With a rollout delay, "required" starts when the delay ends. | Critical | 14 days (0-365) |
| Scan stale | An endpoint has had no successful update scan for longer than its policy's *scan stale after* setting. | Warning | — |
| Restart pending | An endpoint has been waiting for a restart for longer than the threshold. EasyPatch never restarts endpoints by itself: restart them, or set a restart schedule. | Info | 7 days (1-90) |
| Enrollment waiting for approval | Computers enrolled with a deployment code wait for approval. One alert per organization. | Info | — |
| Operating system unsupported | The OS no longer receives security updates, or its support ends within the threshold. 0 alerts only after the end. | Warning | 30 days (0-365) |
| Known-exploited vulnerability unpatched | An endpoint is missing an allowed update that fixes a vulnerability in the CISA Known Exploited Vulnerabilities catalog (required, or still inside its rollout delay). See [compliance.md](compliance.md#vulnerabilities-and-known-exploited-updates). | Critical | — |
| Update on hold | An update that endpoints of the organization still miss (or failed to install) is on hold, by the rollout guard or an administrator, so EasyPatch does not install it automatically. One alert per organization. See [architecture.md](architecture.md#update-holds-and-the-rollout-guard). | Warning | — |

You can edit, disable or delete these rules, and add more. A rule can be limited to one
organization and to endpoints with a tag (for example a stricter *Security update missing*
rule for the tag "Servers" with severity Critical and a 3-day threshold). Rules of the same type
work independently: an endpoint matched by two rules has two alerts.

## Setting up notifications

1. **Settings → Notifications → Email server (SMTP)** (for email channels): server, port,
   encryption (STARTTLS on 587, or TLS on connect on 465), user name and password if the server
   requires sign-in, and the sender address. The password is stored encrypted and never shown
   again. If the server has a certificate the containers do not trust (for example a
   self-signed certificate on an internal relay), you can turn on **Skip certificate
   validation**: the connection stays encrypted, but the server's identity is no longer checked
   (see [security.md](security.md#notifications-and-webhooks)).
2. **Channels → New channel**:
   * **Email**: up to 20 recipient addresses.
   * **Webhook, Slack**: a Slack incoming webhook URL (`https://hooks.slack.com/services/…`).
   * **Webhook, Microsoft Teams**: in Teams, add the **Workflows** app to the channel and create a
     flow from the template *Post to a channel when a webhook request is received*. Paste the URL
     it gives you. EasyPatch posts an Adaptive Card in the format that Workflows expects.
   * **Webhook, Generic**: any HTTPS endpoint. EasyPatch shows a **signing secret** once after
     saving. Use it to verify requests (see below).
3. Click **Test** on the channel. The test goes through the worker like a real notification. The
   result appears in the channel's *Last delivery* and under *Recent deliveries* within a
   minute. Tests are limited to one every 30 seconds per channel.
4. **Settings → Alert rules**: edit the rules and select the channels they should notify.
   Options per rule:
   * **Also notify when alerts resolve.**
   * **Reminder**: notify again every N hours while an alert is open and not acknowledged
     (0 = no reminders).

Webhook URLs must use `https://`. By default they may only point to public internet addresses.
If your PSA or chat server is on a private network, turn on **Allow webhooks to private network
addresses** in the SMTP card. Loopback, link-local (including cloud metadata), multicast and
reserved addresses, and the EasyPatch server's own networks, are always refused. Redirects are
not followed. See [security.md](security.md#notifications-and-webhooks).

### What gets sent

Notifications are grouped. Each evaluation sends **at most one message per channel and kind**:

* new alerts;
* resolved alerts (only from rules with *Also notify when alerts resolve*);
* reminders.

A message lists up to 25 alerts, most severe first, followed by "…and N more". A single alert
gets its own subject, for example `[EasyPatch] Warning: PC-042 has been offline for over 24
hours`. Several alerts get a count, for example `[EasyPatch] 7 new alerts`. Each line links to
the endpoint in the console. Messages contain host names, organization names and alert texts,
and nothing else.

Links use the server's public URL (`EasyPatch:PublicUrl`, set from `EASYPATCH_DOMAIN` by
`docker-compose.yml`).

### Delivery and retries

* **Who sends.** The worker sends queued notifications every 30 seconds.
* **Retries.** A failed delivery is retried after 1, 2, 4, 8… minutes (at most an hour apart),
  for up to 24 hours, then marked failed. Test notifications give up after 3 attempts.
* **Disabled or deleted channels.** Queued notifications fail if their channel is disabled.
  They are discarded if their channel is deleted.
* **Error messages.** The delivery log shows the last error in a form without URLs or secrets,
  for example `The SMTP server refused the user name or password.` or
  `hooks.example.com answered HTTP 404.`

Resolved alerts and sent or failed deliveries are deleted after the *Endpoint activity events*
retention period (**Settings → Server settings → Data retention**).

## Generic webhook format

`POST` with `Content-Type: application/json` and these headers:

| Header | Value |
|---|---|
| `X-EasyPatch-Event` | `alerts.opened`, `alerts.resolved`, `alerts.reminder` or `test` |
| `X-EasyPatch-Signature` | `t=<unix seconds>,v1=<hex HMAC-SHA256>` |
| `User-Agent` | `EasyPatch/<server version>` |

Body:

```json
{
  "event": "alerts.opened",
  "deliveryId": "0196d6c5-6f1e-7a8b-9c0d-1e2f3a4b5c6d",
  "sentAt": "2026-11-14T10:02:00.0000000+00:00",
  "subject": "[EasyPatch] 2 new alerts",
  "summary": "2 new alerts were opened.",
  "alerts": [
    {
      "id": "0196d6c5-6f1e-7a8b-9c0d-000000000001",
      "severity": "Critical",
      "title": "SRV-SQL01: 2 security updates missing for over 14 days",
      "organization": "Contoso",
      "details": "2026-10 Cumulative Update for Windows Server 2022 (KB5044281); 2026-10 Security Update for .NET (KB5044099)",
      "url": "https://patch.example.com/endpoints/0196d6c5-…",
      "at": "2026-11-14T10:02:00.0000000+00:00"
    }
  ],
  "moreCount": 0,
  "consoleUrl": "https://patch.example.com/alerts"
}
```

* **Retries.** `deliveryId` stays the same when a delivery is retried, so receivers can drop
  duplicates.
* **Alert IDs.** An alert `id` is stable from opening to resolving, so a PSA can update or close
  the ticket it created.
* **Response.** Any `2xx` response counts as delivered. Other responses, timeouts (30 seconds)
  and redirects are retried.

### Verifying the signature

`v1` is the lowercase hex HMAC-SHA256, keyed with the channel's signing secret, of
`<t>.<raw request body>`. Verify it in constant time over the exact bytes received, and reject
requests whose `t` is more than a few minutes old. For example, in Python:

```python
import hashlib, hmac, time

def verify(secret: str, header: str, body: bytes, tolerance: int = 300) -> bool:
    parts = dict(p.split("=", 1) for p in header.split(","))
    t, v1 = parts.get("t", ""), parts.get("v1", "")
    if not t.isdigit() or abs(time.time() - int(t)) > tolerance:
        return False
    expected = hmac.new(secret.encode(), t.encode() + b"." + body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, v1)
```

**New secret** on the channel replaces the secret immediately; update the receiver at the same
time.

## Troubleshooting

| Message | Meaning |
|---|---|
| `SMTP is not configured (Settings → Notifications).` | Enter the SMTP server and the sender address. |
| `The SMTP server refused the user name or password.` | Wrong credentials, or the account needs an app password or SMTP AUTH enabled (Microsoft 365: *Authenticated SMTP* per mailbox). |
| `TLS connection to the SMTP server failed …` | The server's certificate is not trusted by the container (expired, self-signed, issued by a private CA, or for a different host name), or the port and encryption do not match (587 = STARTTLS, 465 = TLS on connect). Prefer a trusted certificate on the server; on a trusted network, **Skip certificate validation** accepts it anyway. |
| `Cannot connect to the SMTP server host:port (…)` | DNS, firewall or port. Only the `worker` container needs outbound access. |
| `Webhook to host refused: private network addresses are not allowed …` | The host resolves to a private address. Allow private addresses, or use the public URL. |
| `Webhook to host refused: loopback, link-local …` | The address is never allowed. |
| `host answered HTTP 403` / `404` | The webhook URL was revoked or is wrong. Edit the channel and paste a new URL. |
| `A stored notification secret cannot be decrypted …` | The Data Protection keys (`dpkeys` volume) changed or are missing in the worker. Check that the worker mounts `dpkeys`, or enter the secret again. |

The worker logs each failed attempt (`Notification <id> to channel <name> failed …`) with the
same sanitized message.
