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
  to the console.
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
* **Password resets people ask for** may use the whole day's limit.
* **Invitations and password links administrators send** stop at 90% of
  the day's limit, so that the last 10% is kept for resets people ask for
  whatever administrators send. They are also limited, whatever the
  mail server's limits:
  * **60 an hour per administrator**: one a minute for an hour is more than
    anyone inviting a team or sending links by hand needs, and it stops a
    script or a stolen session at 1,440 a day.
  * **500 a day per organization**, counting the account's organization,
    whoever sends: enough to bring on a customer of several hundred people
    in a day, and under 6% of the default 9,000 a day, so that no customer
    can use up the platform's mail.
  * **The account's own limit**: a password link counts against the limit
    password reset has on one account (three, then one every 20 minutes),
    which the person's own resets share.

  Past one of them, the invitation or link is refused before anything is
  made (`429` with `admin_mail_limited`, `organization_mail_limited` or
  `account_mail_limited`, and a message that says when to try again), and
  the refusal is in the audit log, at most once a minute per administrator
  and limit. Without a mail server, links come back to the administrator
  and nothing limits them.
* **Other mail** (today, the test message) does not wait, and stops at 80%
  of the day's limit, so that the rest is kept for invitations and password
  resets.
* A message the mail server refuses does not count.
* The page shows the last minute's and the last 24 hours' counts, and how
  many of them were invitations and password resets.

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
that switch, never the engine's copy back.

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
| `user.invite`, `user.password_link` (denied) | An invitation or a password link refused under the limits on account mail, with the limit; at most once a minute per administrator and limit |

## API
Super administrators (`settings.manage` on the platform):

| Route | Does |
|-------|------|
| `GET /api/v1/settings/mail-server` | Which mail server is in force (`env`, `console` or `none`), `.env`'s and the console's (without passwords: `passwordSet` says whether one is stored), the limits and their usage |
| `PUT /api/v1/settings/mail-server` | Sets the console's mail server; an empty `password` keeps the stored one while `host`, `port`, `security` and `username` stay the same. `409 mail_server_from_env` while `.env` sets one |
| `DELETE /api/v1/settings/mail-server` | Removes the console's mail server and its stored password; `404` when there is none. Allowed while `.env` sets one, which stays in force |
| `PUT /api/v1/settings/mail-server/limits` | `perMinute` (1 to 10,000) and `perDay` (1 to 1,000,000, at least `perMinute`) |
| `POST /api/v1/settings/mail-server/test` | `to`, and `server` with the form's settings to test them before saving (refused with `409` while `.env` sets the mail server). `429 test_rate_limited` with `Retry-After` within 30 seconds of the last test |

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
| An invitation or a password link is refused with "the most one administrator may" or "the most one organization may" | The limits on administrators' account mail (see [Limits](#limits)); the message says when to try again. Without a mail server, links come back instead |
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
