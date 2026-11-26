# Notification channels

EasyRMM sends its notifications through channels: an email to a list of
people, or a signed webhook for another system. This is the part of
[ADR-0053](../architecture/adr/0053-one-notification-sender.md) built so far
(slice 3): the channels, the sender, notices and the address policy. Rules
that decide what each channel is told come with device alert rules.

## Who manages what

* An organization's channels are its administrators' (`notification.manage`
  in that organization), under the organization's **Notifications** tab.
* The platform's channels are super administrators', under **Settings →
  Notifications**. A platform channel is used by an organization only once a
  super administrator has shared it with that organization; its
  administrators see its name and kind and nothing else.
* Every change, test, share, approval and view of a secret is in the audit
  log. The log holds a webhook's host and port, never its address or secret.

## Email channels

One to 20 recipients. EasyRMM sends one message to each, through the mail
server in **Settings → Notifications → Mail server**. A retry goes only to
the recipients who did not accept the message. Notification mail stops at
80% of the mail server's day so that invitations and password resets always
have room (see [Mail](mail.md)).

## Webhooks

A webhook receives `POST` requests with a JSON body and these headers:

| Header | Value |
|---|---|
| `X-EasyRMM-Signature` | `t=<unix seconds>,v1=<hex HMAC-SHA256>` of `t`, a dot and the raw body, keyed by the channel's signing secret (the text, as UTF-8) |
| `X-EasyRMM-Event` | The event, such as `test` or `notices.opened` |
| `X-EasyRMM-Delivery` | The delivery's ID, the same on every attempt: a receiver that sees it twice may drop the copy |

A receiver should compare the signature in constant time and refuse a `t`
more than five minutes from its clock. **Show secret** shows the address and
the secret again (and is recorded); **Replace secret** replaces it at once.

The body has `event`, `deliveryId`, `sentAt`, `subject`, `summary`, `alerts`
(empty for notices), `moreCount`, `consoleUrl` and `source` (`easyrmm`), and
`notice` for a notice.

Any answer in the `2xx` range is success. `408`, `425`, `429` (its
`Retry-After` is honored, up to an hour) and `5xx` are tried again, from a
minute, doubling to an hour, for 24 hours. `401`, `403`, `404` and `410` mark
the channel failing at once; other `4xx` answers fail that message. A redirect
is a failure: use the final address.

## The address policy

An organization's webhook is an outbound connection the server makes on its
administrators' say, so it is checked on every address dialed, after the name
is resolved, and the connection goes to the address that was checked.

* **Refused always**: loopback, link-local (cloud metadata), multicast,
  reserved, documentation and similar ranges, every cloud metadata address,
  the server's own addresses and its own names. An IPv4 address carried inside
  IPv6 (mapped, NAT64, 6to4) is checked as both.
* **Refused until a super administrator approves it for that channel**:
  private addresses (`10/8`, `172.16/12`, `192.168/16`, CGNAT, ULA), every
  network on the server's own interfaces, and every destination the server
  routes other than by its default route. The channel says it is waiting for
  approval, and super administrators see the request with the addresses the
  host resolves to; they may widen a single address to a network. Changing the
  host or port clears the approval.
* HTTPS only, TLS 1.2 or later, the host name verified; no proxy, no redirects.
  A receiver with a private certificate is trusted through the channel's own
  certificate authority (a self-signed certificate is its own authority). There
  is no "do not verify".

The platform's own destinations keep the older rule: loopback and private
addresses are allowed; link-local and metadata addresses are refused.

## Limits

Per organization, changed by a super administrator: 20 channels, 20 tests an
hour and 600 messages an hour (a webhook is one message, an email one per
recipient). Messages over the hour wait for room, up to 24 hours, and the
organization is told. A channel takes one test every 30 seconds.

## Notices

A channel that has failed for 15 minutes without a success, given up on a
message, or been answered permanently shows as failing, with a notice; so do
messages not sent, a quota reached and a destination waiting for approval.
They are acknowledged on the channels page.
