# ADR-0024: Installing agents that wait for approval

* Status: Accepted (2026-11-16).
* Refines: ADR-0015 (agent enrollment).

## Context
A deployment token (ADR-0015) names its site: every computer that runs its
install command joins that site. That fits a rollout to one office. It
does not fit an MSP rolling out across many customers with one tool (an
RMM migration, a GPO, an Intune script, a technician's USB stick), where
they want one command for every computer and to decide afterwards where
each one belongs, looking at its name.

## Decision
* **Approval tokens.** A second kind of token, created on **Devices → Add
  devices** with **Wait for approval**: a name, an expiry (1 to 90 days)
  and an optional device limit, like a deployment token, but no site. It
  uses the same `ert_` format and the same install commands, so the
  installers, the agent's command line and the console's install steps do
  not change. The server looks a token up among deployment tokens first,
  then among approval tokens. Only a hash is kept; the secret is shown once.
* **Who decides.** A device that waits belongs to no organization yet, so
  creating approval tokens, listing waiting devices and deciding on them
  need `enrollment.manage` platform-wide (super administrators). An
  organization administrator sees neither the tokens nor the devices. The
  session tells the console which permissions are platform-wide
  (`globalPermissions`).
* **Asking.** The agent generates its key as usual and enrolls with the
  token. For an approval token the server records a request keyed by the
  device's public key (host name, operating system, architecture, agent
  version, source address, the token) and answers **202 Accepted** with a
  device code: the first 5 bytes of the SHA-256 of the public key in
  base32, `ABCD-EFGH`. The agent prints the code, saves its key and the
  request (`pending.json`, owner-only like the rest of its state) and the
  installer installs the service as usual.
* **Waiting.** The service asks again with the same token and key. The
  server holds each question open for up to 25 seconds and answers as soon
  as the request is decided (an in-process wake-up by public key), so an
  approved device enrolls within a second or two. A server restart or a
  network error makes the agent back off, from 5 seconds to 5 minutes; it
  never gives up on its own. An expired or revoked token does not stop a
  device that already asks: its request stands until decided.
* **Approving.** The console's **Devices → Waiting for approval** page
  lists waiting devices with their code (to tell machines with the same
  name apart), system, address, token, whether the agent is asking now,
  and existing devices with the same name (a reinstall comes back as a new
  device). One or many are approved into a site and optionally a device
  group; each becomes a device named after its host name, and its agent's
  next answer is **201 Created** with the device id and job key, as for a
  deployment token. The agent then turns the request into its enrollment,
  forgets the token and carries on as an enrolled agent. The main menu and
  the devices tree show how many wait.
* **Rejecting.** A rejection is final: the agent is answered **403
  `enrollment_rejected`**, records that it stopped and idles until the
  service stops. It does not exit, because the service manager would start
  it again and again (systemd `Restart=always`, the Windows service's
  recovery). Uninstalling and installing again asks anew, with a new key.
  `easyrmm-agent status` shows the code and whether the agent waits or
  stopped, and why.
* **Limits.** Asking is rate limited per address like enrollment, more
  strictly for new devices and unknown tokens; a known device may ask about
  every 2 seconds. At most 10,000 requests wait at once (**429**, retry in
  5 minutes, beyond that); a decision covers at most 500 devices; a list at
  most 2,000.
* **Forgetting.** Waiting requests whose agent has not asked for 7 days
  are removed; rejected ones after 30 days; approved ones once the device
  has been heard from.
* **Audit.** `approval_token.create` and `.revoke`,
  `enrollment_request.create` (the device asking, as the agent),
  `.approve` (with the organization and site) and `.reject`.

## Consequences
* One command can be pushed to every computer an MSP manages; nothing
  joins a customer's site until a person with platform-wide rights puts it
  there.
* An approval token is less dangerous to leak than a deployment token:
  holding it only puts computers on the waiting list. It can still fill
  that list (bounded above), so it should be revoked after the rollout.
* Waiting agents hold one HTTP request open each. 10,000 waiting agents
  are 10,000 idle connections at most, which the server's Go HTTP stack
  carries; a larger rollout should be done in waves.
* The waiting list lives in one server process's memory only for the
  wake-ups; the requests themselves are in PostgreSQL, so a restart costs
  a waiting agent one retry, not its place.
