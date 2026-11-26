# ADR-0082: Endpoint security posture shares the compliance engine's words and score

* Status: Accepted (2026-11-26, decided in review). Slice P1 is built; the later slices are not.
* Builds on: [ADR-0078](0078-compliance-engine.md) (the compliance engine: states, wording,
  freshness and the roll-up), [ADR-0051](0051-hardening-linux-computers.md) and
  [ADR-0054](0054-hardening-windows-computers-and-servers.md) (hardening results),
  [ADR-0019](0019-monitoring-and-alerts.md) (alerts), [ADR-0053](0053-one-notification-sender.md)
  (notices), `server/internal/devscope`.
* Source: feature 2, "Endpoint security posture monitoring", in
  [feature-plan-msp.md](../feature-plan-msp.md).

## Context

The feature plan names its own main risk: a second scoring system. Integration now has the
compliance engine (ADR-0078, slices C1 to C4) with a result for each control on each computer, one
vocabulary (`in_place`, `partly`, `not_in_place`, `not_applicable`, `managed_elsewhere`,
`not_supported`, `half_applied`, `failed`, `unknown` and the computed `stale`), a freshness window
for each organization (`compliance_org_settings.freshness_days`, 30 days by default), a roll-up that
treats unknown and stale as not passing (`rollup.judge`, `rollup.EffectiveState`) and the three
words "meets", "does not meet" and "cannot tell" (`compliance.ResultWord`). What it lacked is a
weighted score with its reasons.

Hardening keeps the last state of each module on each computer (`device_hardening`), and the
patching engine says each computer's update status over HTTP.

## Decision

### 1. Posture is a view, not a scorer

Posture keeps no results of its own and collects nothing. It reads the sources that exist, turns each
into a result of the compliance vocabulary, and hands the results to the compliance roll-up.

| Source | Becomes | Read from |
|---|---|---|
| Linux hardening, one control for each module (ADR-0051) | the module's state, as it is | `device_hardening` |
| Windows hardening, one control for each module (ADR-0054) | the module's state; a module another owner manages takes that owner's stated value, as `rollup.judge` does | `device_hardening` |
| Patching, one control called `patching`, on a computer the engine patches | Compliant is `in_place`; RebootRequired `partly`; MissingUpdates `not_in_place`; FailedUpdates `failed`; ScanStale, NeverScanned and any word we do not know `unknown` | `posture_patching` |
| A computer with no hardening result at all | one control, `hardening`, `unknown` | nothing |

Posture covers computers with the EasyRMM agent on Linux or Windows, as hardening does. For any
other computer it says nothing, and the console shows a dash.

The same sources reach the compliance results too: a compliance scan runs hardening's checks and
stores each setting as a result. Posture reads the hardening tables directly, because posture is the
state of the module as the last check left it, and a scan is a separate act. Neither is a copy of
the other's score: both judge a state with `rollup.judge`.

### 2. One vocabulary, one score

* **States and words** are ADR-0078's, unchanged. Posture adds none. `unknown` and `stale` never pass.
* **Stale** is a result older than the organization's freshness window, the same setting the
  compliance screens use (30 days when the organization has not set one). A copy of the patching
  engine's answer that the server stopped refreshing goes stale like any other result.
* **The score** is one function, `rollup.ScoreOf`, in the compliance roll-up package. It is
  the weight of the controls that pass over the weight of the controls that apply. A control
  that does not apply (`not_applicable`) leaves both. Failing, unknown, stale and not supported
  stay in the denominator and are not in the numerator. No weight is ever dropped to improve the
  score. A computer's percent is rounded down, and is absent when nothing applies.
* **The word** for a computer is "meets" only when every control that applies passes, "does not
  meet" when one fails, and otherwise "cannot tell". A computer whose only gap is unknown cannot
  be told to meet and is not said to fail.
* **The reasons** are the failing controls, then the controls that cannot be told, the heaviest
  first, each with its state, its word and what the source says (what is missing, why it failed).
* **Weights** are fixed in code for now: 3 for patching, firewall, SSH, Defender and BitLocker, 2 for
  a few others, 1 for the rest. The case where all weights are equal is today's "N of M in place".
  Policies that change the weights are slice P4.
* The compliance screens may show the same score by calling `rollup.ScoreOf` over their stored
  results. P1 does not change them, so that a framework's "checked: does not meet" is not altered
  by a new number.

### 3. Wording

"Meets its security policy", "Does not meet its security policy" and "Cannot tell whether it meets
its security policy". Never "compliant" (ADR-0054, ADR-0078 section 9). The column and report test for the
word.

### 4. One column and one report

* The Devices list has one **Security** column and one **Security** filter (meets, does not meet,
  cannot tell). They answer for C2's leftover column and filter too: there is no second column
  for compliance. The existing "Compliance: failing" filter stays, since it asks something else
  (a stored framework result that does not meet).
* The Reports page has one **Security** report, with a CSV. Its rows read the posture the column reads (the same
  function, `posture.Load`), and it adds a column that counts the computer's compliance
  results that do not meet. This is C2's leftover Reports row.
* A computer's Hardening tab has a **Security posture** card with the score and its reasons.
* Everything needs `device.view`; the report needs `report.view` as well. The patching control
  is shown under `device.view`, since the engine's word is not sensitive (*decided in review*).

### 5. The compliance alerts (C2's leftovers)

`compliance.fix_failed` and `compliance.scan_stale` are built as alerts of no policy, as Repair
failed is, through the same alerts table:

* **Compliance fix failed** (`compliance_fix_failed`), a warning on a computer, one for each control, open while a fix
  queue item is in the `failed` state, resolved when it is not.
* **Compliance results out of date** (`compliance_scan_stale`), a warning, one for each computer whose newest result is older
  than the organization's window, resolved when a newer result arrives.

Amended 2026-11-26 (decided in review): the kinds are written with an underscore, not a dot,
because the alerts table's kind is a lower-case word with underscores and a dot needs a change to
a rule every kind shares for no gain. ADR-0078 section 7 says the kinds would "use the existing alert and
policy levels"; they have no policy, because a policy would only choose a severity and a threshold neither has.
An organization that has not turned the compliance module on raises neither.

### 6. The organization guard

Every automatic behaviour here asks `devscope.Allowed(organization)`: the alerts pass, the
refresh of the patching copy, and the posture itself, so the Devices column, the Security report and a
computer's posture show nothing for an organization outside the scope while it is set.

### 7. The patching copy

The engine answers over HTTP; the list, the report and the alerts need a query. A job copies each
linked computer's compliance word and the time it was read into `posture_patching` every 15 minutes.
A computer the engine could not be read for keeps its last copy and goes stale. This is not new
collection: it is a copy of what the engine already reports.

## Slices

* **P1 (built)**: sections 1 to 7 above.
* **P2 to P5** are as the feature plan has them. P2 and P3 add controls (they only add sources to
  section 1), P4 adds policies, history and the noncompliant event, P5 adds threat detections. None
  changes the words, the freshness rule or the score.

## Tests

Integration tests against PostgreSQL for the words, weights, stale and unknown rules, managed-elsewhere, the
patching copy and its staleness, the dev-scope guard, the Devices list column and filter, the Security
report and its CSV, and both alerts (open, no duplicate, resolve, not covered). Unit tests of
`rollup.ScoreOf`. Vitest and a browser spec for the column, the filter, the card and the report.

## Consequences

* One score exists. A future change to the freshness rule or to what counts as passing is made in the
  roll-up package and reaches posture and compliance together.
* A computer with a failing control in compliance and a passing hardening module can read differently on
  the two screens, because they judge different controls. The Security report shows both counts side by side.
* Neither alert is configurable per organization yet; both follow the compliance module's switch.
