# ADR-0047: Deployment and approval tokens can be shown again

* Status: Accepted (2026-11-20).
* Amends: [ADR-0015](0015-enrollment-and-meshagent-delivery.md) and
  [ADR-0024](0024-enrollment-approval.md), which showed a token once and
  kept only its hash.

## Context
A deployment token's install command was shown once, when the token was
created. Someone who came back for it, say to add a computer that was off
during the rollout, had to create another token, and the list filled with
near-duplicates nobody remembered to revoke. On the first real deployment
the owner asked for it plainly: if a token can still add devices, the
person who manages it should be able to see its install command again.

What showing once protected against: a copy of the database alone giving
working tokens. Every token is limited already: one site (or approval in
the console), an expiry of at most 90 days, an optional device limit, and
revocation; and people who can see the token list can create a new token
for the same site anyway.

## Decision
* **Kept, sealed.** A new token's secret is kept beside its hash, sealed
  with the server's encryption key (`EASYRMM_SECRET_KEY`, AES-256-GCM, as
  the server's other secrets), bound to the token's kind and id, so a value
  copied into another row does not open. Agents are still checked against
  the hash; the sealed secret is only read to show it.
* **Who, when.** `POST /api/v1/enrollment-tokens/{id}/reveal` and
  `POST /api/v1/approval-tokens/{id}/reveal` return the token with its
  secret, as creating it does, to callers who manage it
  (`enrollment.manage` for the site; for approval tokens, everywhere), and
  only while it can still add devices. An expired, used-up or revoked token
  answers 409 `token_inactive`. Responses are `Cache-Control: no-store`.
* **Audited.** Every reveal is an audit event (`enrollment_token.reveal`,
  `approval_token.reveal`) naming who saw which token.
* **Checked.** The opened secret must hash to the stored hash; a mismatch is
  an error, never a wrong command shown.
* **Older tokens.** Tokens created before this keep only their hash and
  answer 409 `token_not_kept`; the console says so on the token's row.

## Consequences
* The encryption key now also protects tokens: someone with the database
  and the key can enroll devices with active tokens until they expire or are
  revoked. The key was already enough to read every other sealed secret.
* The console's install panel no longer says the token is not shown again;
  it says to keep the command to the people installing the agent, and that
  the token list shows it again while it is usable.
* Rotating the encryption key works as for other sealed values: old keys
  stay listed for reading.
