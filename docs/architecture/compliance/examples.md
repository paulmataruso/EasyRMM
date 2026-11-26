# Compliance engine: worked examples

Appendix to [ADR-0078](../adr/0078-compliance-engine.md). The two controls are
**illustrations of the format and of the independence rule**, written for
this document from vendor documentation. They are not yet reviewed library
entries; C1 and C3 review and ship them. Nothing here is copied from a
benchmark, a Wazuh file or any third-party check. Identifiers in angle
brackets are looked up from the pinned data files at build time
(`server/internal/jobs/hardening/controls/data/`), not typed from memory.

## 7. A Windows check

**Password history** (the number of previous passwords a local account
cannot reuse).

```json
{
  "id": "win.accounts.password-history",
  "version": 1,
  "title": "Local accounts cannot reuse recent passwords",
  "description": "The computer remembers a number of each account's previous passwords and refuses a new password that matches one. Without this, a forced password change can be undone by typing the old one again.",
  "platforms": {"os": "windows", "editions": ["workstation", "member_server"]},
  "scopes": ["workstation", "member_server"],
  "severity": "medium",
  "executor": "hardening",
  "executor_ref": {"module": "accounts", "setting": "accounts-history"},
  "detect": {
    "summary": "Export the local security policy and read PasswordHistorySize. Report managed_elsewhere when Group Policy or MDM sets it, and judge the owner's value.",
    "source": "secedit /export of the [System Access] area, key PasswordHistorySize (not language dependent)"
  },
  "expected": {"op": ">=", "value": 24, "param": "min_generations", "bounds": [1, 24]},
  "applicability": {"not_when": ["domain_controller"], "reason_on_dc": "the domain's policy decides, not the local one (checked by C4)"},
  "remediation_text": "Open Local Security Policy, Account Policies, Password Policy, and raise the number of remembered passwords to the expected value. On a computer managed by Group Policy, change the policy object instead: a local change is overwritten.",
  "apply_supported": true,
  "undo_kind": "restore_backup",
  "risk_tier": "T1",
  "warning_id": "w.accounts.password-history.v1",
  "needs_restart": false,
  "preconditions": [],
  "references": [
    {"kind": "ms_baseline", "ref": "Microsoft security baseline for the Windows release, password policy"},
    {"kind": "stig", "ref": "<rule id from stig-win11-v2r11.csv for 'password history'>", "meets": "meets"},
    {"kind": "vendor_doc", "ref": "Microsoft Learn: Enforce password history"}
  ],
  "author": "EasyRMM",
  "licence_class": "ORIGINAL",
  "provenance": {
    "author": "EasyRMM", "method": "written from Microsoft documentation and observed behaviour",
    "sources": [{"source_id": "ms-learn-password-policy", "locator": "Enforce password history"}],
    "derived_from_content": false
  }
}
```

The fix warning (our words, `w.accounts.password-history.v1`): *"Existing
passwords keep working. From the next password change, users cannot choose a
password they used among their last 24. Accounts whose passwords are set by a
script that reuses a fixed value will fail the next time that script runs."*

How it runs:

* **Detect.** The hardening script's `accounts` module in check mode returns
  the setting by its id. The ingester stores `observed: 4`, `expected: >= 24`,
  state `not_in_place`.
* **Fix.** The T1 agreement writes the value through the module's apply,
  reads it back, and the value in the backup makes undo possible. The control
  does not write registry values itself.
* **Verify.** A single-control re-scan is queued; only its `in_place` result
  moves the requirement's objective.
* **Domain-joined or managed.** The ownership reader returns
  `managed_elsewhere` with the owner (Group Policy) and whether *its* value
  meets the control. No write is offered.

## 8. A Linux check

The Linux finding carries free-text `Missing`, `Changes` and `Done` lists
and, since ADR-0078 slice C0, a typed `settings` list: each setting by its id
in `server/internal/jobs/hardening/linux-settings.json`, with its state,
current value and wanted value (the Windows shape). The id below
(`ssh-permit-root-login`) is a real one. The script reports `prohibit-password`
as in place and wants it; this control is stricter and compares the reported
current value itself.

**Root cannot sign in over SSH.**

```json
{
  "id": "linux.ssh.permit-root-login",
  "version": 1,
  "title": "SSH refuses direct root sign-in",
  "description": "The SSH server refuses a sign-in as root, so every remote administrator is a named account and the log shows who acted before they became root.",
  "platforms": {"os": "linux", "families": ["debian", "ubuntu", "rhel"], "requires": ["sshd"]},
  "scopes": ["any"],
  "severity": "high",
  "executor": "hardening",
  "executor_ref": {"module": "ssh", "setting": "ssh-permit-root-login"},   // an id in linux-settings.json (slice C0)
  "detect": {
    "summary": "Ask the running SSH server for its effective settings and read permitrootlogin. Do not parse the file: include files and Match blocks change the effective value.",
    "command_shape": "sshd -T (effective settings, as the daemon sees them)"
  },
  "expected": {"op": "in", "value": ["no"]},
  "applicability": {"requires": "sshd installed and its service present"},
  "remediation_text": "Set PermitRootLogin to no in a drop-in file under the SSH configuration directory, check the configuration with sshd -t, and reload the service. Before you do, make sure another account can sign in and use sudo.",
  "apply_supported": true,
  "undo_kind": "restore_backup",
  "risk_tier": "T3",
  "warning_id": "w.ssh.permit-root-login.v1",
  "needs_restart": false,
  "preconditions": [
    {"id": "other_admin", "text": "A non-root account in the sudo or wheel group can sign in over SSH (a key is installed, or password sign-in is on)."},
    {"id": "config_valid", "text": "sshd -t passes after the change, before the reload."}
  ],
  "author": "EasyRMM",
  "licence_class": "ORIGINAL",
  "provenance": {
    "author": "EasyRMM", "method": "written from sshd_config(5) and the distributions' defaults",
    "sources": [{"source_id": "man-sshd-config", "locator": "PermitRootLogin"}],
    "derived_from_content": false
  }
}
```

The warning (ours): *"If root is the only account you can sign in with, this
locks you out of SSH. EasyRMM checks first that another administrator account
can sign in, and refuses if it cannot find one. Undo restores the previous
file."* The precondition check runs on the server's rule and again in the
script; if the script cannot confirm the other account, the item is blocked,
not warned. The precondition protects the undo path and the operator's own access, so it is
a *technical* block: it is not one of the policy guards a typed agreement can
lift (ADR-0078 section 13).

## 9. One check, three frameworks

Mapping the password-history control (deliverable 9). The mapping pack rows,
in our words:

```json
{"mappings": [
 {"framework_key":"nist-800-171r2","framework_version":"r2","req_id":"3.5.8","obj_id":"3.5.8[b]",
  "control_id":"win.accounts.password-history","relation":"satisfies_objective",
  "note":"Shows that reuse is prohibited for the configured number of generations on a local account. Does not show that the number was chosen and documented (3.5.8[a]): that needs a policy statement."},
 {"framework_key":"nist-800-171r2","framework_version":"r2","req_id":"3.5.8","obj_id":"3.5.8[a]",
  "control_id":"win.accounts.password-history","relation":"evidence_for",
  "note":"The configured number is evidence of the specified value; the specification itself is the organization's."},
 {"framework_key":"cmmc-l2","framework_version":"2.0","req_id":"IA.L2-3.5.8","obj_id":"3.5.8[b]",
  "control_id":"win.accounts.password-history","relation":"satisfies_objective",
  "note":"CMMC Level 2 uses the 800-171 r2 requirement unchanged (32 CFR 170.14)."},
 {"framework_key":"cis-benchmark-xref","framework_version":"win11-enterprise-3.0.0","req_id":"1.1.1",
  "control_id":"win.accounts.password-history","relation":"related",
  "note":"Cross-reference by recommendation number only. EasyRMM's check is independently written; it is not CIS content."}
]}
```

What this shows:

* **One check, no duplicates.** `win.accounts.password-history` exists once.
  Three packs point at it. Adding HIPAA's `164.312(d)` or a STIG rule is one
  more row.
* **Each framework keeps its own criteria.** 800-171A splits 3.5.8 in two
  objectives; the control satisfies only [b]. The requirement is *met* only
  when [a] is also met by an attestation or a document (C5). The same single
  passing result gives CMMC the same objective, because CMMC Level 2 adopts
  the 800-171 requirement, not because the check "satisfies CMMC".
* **The CIS row is `related`**, so it can never make a CIS recommendation
  "checked" on its own, and it carries no CIS title or text. The number
  `1.1.1` and the benchmark version here are taken from a third-party file
  seen during research and **have not been checked against a licensed copy of
  the benchmark**; a person with access verifies every cross-reference
  number before the pack's review state moves from `needed`.
* **A host that fails** shows the item in the fix queue, and the requirement
  list shows 3.5.8 as *does not meet* for that host's organization until a
  later scan passes.
* **What the console says** for this row: "Password history: this computer
  does not meet the expected value (4, expected 24 or more). Helps with: NIST
  SP 800-171 3.5.8 (one of its two objectives), CMMC IA.L2-3.5.8 (the same
  objective), CIS cross-reference 1.1.1. Assessment aid, not an assessment."
