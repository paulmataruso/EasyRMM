# Mail

EasyRMM sends invitations, password resets and test messages through one
mail server, and gives the same mail server to the patching engine, which
sends patching's email channels and monthly reports with it. Without a
mail server, invitation and password links come back to the administrator
to pass on, and password reset is not offered on the sign-in page. The
design is in
[ADR-0053](../architecture/adr/0053-one-notification-sender.md).

## Where the mail server comes from
One mail server is in force at a time, and **Settings → Notifications →
Mail server** says which:

* **`.env`**: when `EASYRMM_SMTP_HOST` is set, the `EASYRMM_SMTP_*`
  settings are the mail server. The console shows them read-only and can
  still send a test message; changing them means changing `.env` and
  restarting the server. Remove `EASYRMM_SMTP_HOST` to hand the mail server
  to the console. Every EasyRMM server must have the same `EASYRMM_SMTP_*`
  settings (see [The patching engine](#the-patching-engine)). A password
  longer than 512 characters, or a sender's name longer than 100, as the
  patching engine counts them (UTF-16 units), does not stop the server
  from starting or sending, so that a deployment that had one survives an
  upgrade; but the engine cannot be given it, so the server logs an error
  at start and the page shows it. Shorten it and restart. Write a sender
  with a name in double quotes:

  ```sh
  EASYRMM_SMTP_FROM="EasyRMM <rmm@example.com>"
  ```

  Unquoted reads the same. Inside double quotes, write `\"` for a quote,
  `\\` for a backslash and `$$` for a `$`; inside single quotes, everything
  is as written but `\'`, a quote. `.env` is read by Compose's rules
  ([the updater's guide](updater.md#env)).
* **The console**: otherwise, the mail server a super administrator sets
  under Settings → Notifications. It applies at once, without a restart.
* **None**: neither is set.

The limits below are set in the console in either case.

## Setting it in the console
Super administrators find it under **Settings → Notifications → Mail
server**.

1. **Server** and **Port**: the mail server's host name or IP address, and
   its submission port. The port follows the security while it is the
   usual one: 587 for STARTTLS, 465 for TLS, 25 for none.
2. **Security**:
   * **STARTTLS** (port 587): the connection starts plain and must switch
     to TLS before anything is sent. A server that does not offer STARTTLS
     is refused, never used without encryption.
   * **TLS** (port 465): TLS from the first byte.
   * **None**: only to a relay on the same machine (`localhost` or a
     loopback address), such as a local Postfix that relays onwards. The
     address actually connected to must be loopback too, so a `localhost`
     that resolves elsewhere is refused.

   EasyRMM checks the mail server's certificate against the authorities
   the server's image trusts, and uses TLS 1.2 or later. A mail server with
   a certificate from a private authority cannot be used yet (see
   [What is not built yet](#what-is-not-built-yet)); use a relay on the
   same machine for it.
3. **Sign in**: with a user name and password (`AUTH PLAIN`, only over an
   encrypted connection or to loopback), or not at all for a relay that
   takes mail by the sender's address. The password is stored encrypted
   with the server's secret key (`EASYRMM_SECRET_KEY`) and never shown or
   returned again; it is at most 512 characters, as the patching engine,
   which gets it too, allows. To keep it, leave the field empty: it is
   kept while the server, the port, the security and the user name stay
   the same, so that it never goes to another server or over another
   kind of connection. Changing any of them asks for it again.
4. **Send from** and **Sender's name**: the address messages come from,
   and the name shown with it (by default `EasyRMM`, at most 100
   characters). The mail server must
   let the signed-in user send as that address.
5. **Send test message** sends a short message, in EasyRMM's own words,
   with the settings as they are in the form, saved or not, to the address
   entered (your own at first). It says what the mail server answered:
   the reply that took the message, or the step that failed and why
   (connection, STARTTLS, certificate, sign-in, sender, recipient). One
   test message goes every 30 seconds across the platform.
6. **Save**. Invitations and password resets use it from the next message,
   on every server, and password reset is offered on the sign-in page
   (within five seconds on EasyRMM's other servers, which keep the answer
   that long).

**Remove** clears the console's mail server and its stored password.
Invitations and password links then come back to the administrator, and
password reset stops being offered.

While `.env`'s mail server is in force, the page still shows a mail server
saved in the console before, as **Saved in the console, not in use**. Its
**Remove** deletes those settings and the stored password, and changes
nothing that is sent: `.env`'s mail server stays in force.

Mail server errors name the host only. A mail server's reply is shown to
super administrators on the test message and in the server's log.

## Limits
**Limits**, on the same page, cap the messages EasyRMM sends through
whichever mail server is in force, counted per recipient over the last
minute and the last 24 hours, across all of EasyRMM's servers. By default
30 a minute and 9,000 a day: Exchange Online rejects submissions above 30
a minute and stops a mailbox that sends to more than 10,000 recipients in
24 hours. Set your own mail server's limits.

* **Invitations and password resets go first.** They wait up to a minute
  for room under the minute's limit, and other mail on every server
  stands back while one waits.
* **Password resets people ask for** may use the whole day's limit, but
  are limited by the hour, on the whole platform and per organization
  (below), so that they cannot use it up.
* **Invitations and password links administrators send** stop at 90% of
  the day's limit, so that the last 10% is kept for resets people ask for
  whatever administrators send.
* **Other mail** (today, the test message) does not wait, and stops at 80%
  of the day's limit, so that the rest is kept for invitations and password
  resets.
* A message the mail server refuses does not count.
* The page shows the last minute's and the last 24 hours' counts, how
  many of them were invitations and password resets, and the limits below
  at the day's limit set.

### Limits on invitations and password emails
Whatever the mail server's limits, invitations and password emails are also
limited, so that no one administrator, organization or attacker can use
up the platform's mail. Each limit, except the account's own, is the
smaller of a fixed number and a share of the day's limit, and at least 1,
so that a low day's limit cannot be used up by one of them either. All of
them are counted in the database, across all of EasyRMM's servers.

| Limit | The smaller of | At 9,000 a day (the default) | At 500 a day |
|-------|----------------|------------------------------|--------------|
| One administrator's invitations and password links, an hour | 60, a 150th of the day | 60 | 3 |
| Invitations and password links to one organization's accounts, a day | 500, an 18th of the day | 500 | 27 |
| Password emails to one account, of any kind | 3 at once, then one every 20 minutes | 3, then 1 every 20 minutes | 3, then 1 every 20 minutes |
| Password resets people ask for, on the whole platform, an hour | 60, a 300th of the day | 30 | 1 |
| Password resets people ask for to one organization's accounts, an hour | a third of the platform's hour | 10 | 1 |

Apart from the day's limit on all mail, no limit a day holds password
resets people ask for, only these limits by the hour, so that no one can
keep them refused for a day (decided in review of #82).

Why these numbers (decided in review of #82):

* **One administrator**: one a minute for an hour is more than anyone
  inviting a team or sending links by hand needs. Kept up all day, it is
  24 hours × a 150th, 16% of the day, so one administrator, a script or a
  stolen session cannot use up the day.
* **One organization**: enough to bring on a customer of several hundred
  people in a day, and at most 5.6% of the day, so that no customer's
  administrators can use up the platform's mail. A super administrator's
  invitations and links are not counted against an organization, only
  against their own hourly limit.
* **One account**: a person who has forgotten their password needs one
  email, and a few more if one goes astray. Three at once, then one every
  20 minutes (a token bucket, worked out from the account's emails in the
  database), is at most 75 a day. Resets the person asks for and links
  administrators email count together.
* **Resets, platform-wide**: kept up all day, resets are at most 24 hours
  × the hour's limit. At a day's limit of 300 or more, that is
  24 × a 300th, 8% of the day, less than the 10% kept for resets, so
  resets, however many addresses someone knows or made, never use up the
  day, or the room kept for them. Below 300 a day, the hour's limit is 1,
  so resets are at most 24 a day: a larger share of a day that small.
* **Resets, per organization**: a third of the platform's hour, so that
  the rest is there for the others. An organization admin who invites a
  hundred addresses they control and has each of them reset, or someone
  who knows a customer's addresses, spends at most that. Accounts in no
  organization, or in several, count together as one organization here.

What holds against someone who asks for resets to addresses they know,
and what does not:

* **They can delay resets by the hour, never by the day.** Asking for an
  organization's hour of resets (10 at the default day's limit) to a
  customer's accounts, or to accounts in no organization, they keep that
  organization's resets refused while they go on, and for at most an
  hour after they stop. Knowing addresses in three or more
  organizations, they can use up the platform's hour the same way. No
  count by the day is theirs to use up.
* **One account**: asking every 20 minutes, they keep its owner's own
  requests refused while they go on, but each reset they ask for is sent
  to the owner, whose newest link works. 20 minutes after they stop, the
  owner can ask again.
* **The day**: resets never use more than the hour's limits allow
  (above). At a day's limit of 300 or more, they cannot use up the day,
  or the 10% kept for them, or keep administrators' invitations and
  links from going. Below 300 a day, they can use 24 of it.
* An administrator's links to an account past its limit still come back
  to the administrator, to pass on (below).

Resets are also limited per client address on each server.

How each is refused:

* **A reset someone asks for** past a limit is not sent; the answer on the
  sign-in page is the same as ever, and the refusal is in the audit log
  (`auth.password_reset_request`, `denied`, with the limit).
* **An invitation or a password link** past the administrator's own hourly
  limit is refused before anything is made: `429 admin_mail_limited`, with
  `Retry-After` and a message that says when to try again; the refusal is
  in the audit log, at most once a minute per administrator and limit.
* Past **the account's or the organization's limit**, the invitation or
  link is still made, and comes back to the administrator unsent, with
  the reason, to pass on, as when there is no mail server: anyone who
  can ask for resets to an account must not be able to keep an
  administrator from helping its owner.
* Without a mail server, links come back to the administrator and nothing
  limits them.

Patching's email and monthly reports are sent by the patching engine
itself, and are not counted (see below).

## The patching engine
The patching engine sends patching's email channels and monthly reports
through the mail server in force. EasyRMM gives it the mail server at start
and at once after every change, without restarting anything; a change
made on another EasyRMM server reaches it within a minute. Removing the
mail server leaves the engine without one too. Settings → Patching →
Notifications shows the mail server the engine has, and says so when there
is none. The engine sends monthly reports only over STARTTLS or TLS.

EasyRMM is the mail server's one source. Every minute it compares the
engine's mail settings with its own and gives them again when they differ,
so **a mail server set in the engine itself is overwritten** within a
minute. The engine's switch for webhooks to private networks carries the
mail server with it, and EasyRMM sends its own mail server in force with
that switch, never the engine's copy back. When EasyRMM cannot read its
own mail server then, the switch still changes, the engine keeps the mail
server it has, and Settings → Patching → Notifications says why, until a
pass can give it again. Each call to the engine for its mail settings
gives up after 10 seconds, so an engine that hangs does not hold up the
switch or the passes.

With several EasyRMM servers, **one at a time gives the engine its mail
server**: whichever holds a PostgreSQL advisory lock, on a connection of
its own. When it stops, or its connection drops, another takes over at
its next pass. A connection that dies without a word (a server lost, the
network cut) is noticed within about 30 seconds, by TCP keepalives on
both ends of it. The lock needs a session that stays on one connection to
PostgreSQL: a pooler in transaction mode, such as PgBouncer's
`pool_mode = transaction`, is not supported
([Docker deployment](../deployment/docker.md#operations)).

The server that gives the engine its mail server records, in the
database, an HMAC-SHA-256 of it, keyed by a key derived from
`EASYRMM_SECRET_KEY`, never the mail server or its password; someone who
can read the database cannot guess the password from it. Each other
server compares its own mail server with it, and when they differ (for
example, `.env` set differently on one server), it logs an error once per
change, and its Settings → Patching → Notifications says so; the engine
keeps the one it was given. Give every server the same `EASYRMM_SMTP_*`
settings, and the same secret key, as they need anyway: while the key is
being rotated, a server on the other key says its mail server differs
until every server has been restarted with the new one. The webhook
switch, changed on a server that does not give the engine its mail
server, keeps the engine's mail settings as they are, its password
included, and changes only the switch. Each server reads and changes the
engine's mail settings (a pass, the removal below, the webhook switch)
holding one advisory lock shared by all of them, so that one server's
change never falls between another's reading and writing them.

When EasyRMM cannot give the engine its mail server three passes in a row
(a pass runs every minute, and at once after a change), because it cannot
read its own (for example, a stored password that the secret key no
longer opens) or the engine refuses it, it removes the engine's mail
server rather than leave the engine sending through one EasyRMM may no
longer have. Patching's email and monthly reports then stop, the server
logs an error, and Settings → Patching → Notifications says why. The first
pass that works gives the mail server back.

## Audit
Each change is in the audit log, under **Mail server**:

| Action | When |
|--------|------|
| `mail_server.update` | The console's mail server is set or changed: each setting from and to, and whether the password changed, by a new one or the stored one removed (never the password) |
| `mail_server.delete` | The console's mail server is removed, and whether it was in force (not while `.env`'s was) |
| `mail_server.limits_update` | The limits are changed, from and to |
| `mail_server.test` | A test message: to whom, through which server, from `.env` or the console, as which sender (address, name, sign-in and user name; never the password), and the error when it did not go |
| `user.invite`, `user.password_link` (denied) | An invitation or a password link refused under the administrator's own limit, with the limit; at most once a minute per administrator and limit. A failure when the limits could not be read |
| `auth.password_reset_request` (denied) | A reset someone asked for, not sent under a limit on account mail, with the limit |

## API
Super administrators (`settings.manage` on the platform):

| Route | Does |
|-------|------|
| `GET /api/v1/settings/mail-server` | Which mail server is in force (`env`, `console` or `none`), `.env`'s and the console's (without passwords: `passwordSet` says whether one is stored), the limits and their usage |
| `PUT /api/v1/settings/mail-server` | Sets the console's mail server; an empty `password` keeps the stored one while `host`, `port`, `security` and `username` stay the same. `409 mail_server_from_env` while `.env` sets one |
| `DELETE /api/v1/settings/mail-server` | Removes the console's mail server and its stored password; `404` when there is none. Allowed while `.env` sets one, which stays in force |
| `PUT /api/v1/settings/mail-server/limits` | `perMinute` (1 to 10,000) and `perDay` (1 to 1,000,000, at least `perMinute`) |
| `POST /api/v1/settings/mail-server/test` | `to`, and `server` with the form's settings to test them before saving (refused with `409` while `.env` sets the mail server). `429 test_rate_limited` within 30 seconds of the last test |

The view's `limits.account` holds the limits on invitations and password
emails at the day's limit set, and `envProblem` what of `.env`'s mail
server the patching engine cannot be given. An invitation
(`POST /api/v1/users`) or a password link
(`POST /api/v1/users/{id}/password-link`) that comes back unsent has
`emailed: false`, the `link`, `mailProblem` (`no_mail_server` or
`not_sent`) and, when a limit stopped it, `mailReason` in words. Every
`429` EasyRMM answers carries `Retry-After`, in seconds.

## Troubleshooting

| Symptom | What to check |
|---------|---------------|
| An invitation shows its link with "EasyRMM has no mail server" | No mail server is in force. Set one under Settings → Notifications |
| An invitation shows its link with "The mail server did not take the message" | Send a test message to the same address: it says which step failed. The server's log has the mail server's reply |
| Password reset is not on the sign-in page | No mail server is in force |
| The test message fails at the certificate | The mail server's certificate is not from a public authority, or does not name the host entered. Use the name on the certificate |
| `is not an SMTP server` | Something else answers on that host and port (what it said is not shown). Check the port: 587 for STARTTLS, 465 for TLS |
| `does not offer STARTTLS` | The port is for TLS from the first byte (465), or the server offers no encryption. Choose TLS, or a relay on the same machine |
| Sign-in refused (`535`) | The user name or password, and that the mailbox may sign in over SMTP. Exchange Online is retiring passwords over SMTP ([ADR-0053](../architecture/adr/0053-one-notification-sender.md)); a relay on the same machine is the way until signing in with an application comes |
| `Not sent: the limit of … messages a day is reached` | Raise the limit, or wait until the oldest of them is 24 hours old |
| An invitation or a password link is refused with "the most one administrator may" | The administrator's own hourly limit (see [Limits on invitations and password emails](#limits-on-invitations-and-password-emails)); the message says when to try again |
| An invitation or a password link comes back with "It was not emailed:" and a limit | The account's or the organization's limit; send the link yourself, or wait as the message says |
| A password reset someone asked for does not arrive | The audit log's `auth.password_reset_request` (denied) says which limit stopped it |
| The server logs "This server's mail server … is not the one another of EasyRMM's servers gives the patching engine" | The servers' `EASYRMM_SMTP_*` settings differ. Make them the same and restart the one that differs |
| "EASYRMM_SMTP_PASSWORD is longer than 512 characters" at start | The engine cannot be given `.env`'s mail server; shorten the password or the sender's name and restart |
| Patching's email does not arrive but test messages do | Settings → Patching → Notifications shows the engine's mail server, or why the engine has none; check the channel's last message there |
| A mail server set in the patching engine went back | EasyRMM is the mail server's one source and overwrites the engine's within a minute. Set it under Settings → Notifications |

## What is not built yet
These come with later slices of
[ADR-0053](../architecture/adr/0053-one-notification-sender.md):

* Signing in to Microsoft 365 with an application (XOAUTH2).
* A certificate authority to trust for a mail server with a private
  certificate.
* Notifications for device alerts, and their channels and rules, under
  Settings → Notifications.
* Patching's email and monthly reports sent by EasyRMM, and counted
  against the limits.
