# gpo1: Group Policy management and the read-only view of every setting (ADR-0083, slice 1)

## Changelog lines
- Group Policy on a domain controller's Roles tab: the GPOs with status, versions, links, WMI filter and owner; the link tree (domain, OUs and sites, with link order, enforced, enabled and blocked inheritance); security filtering and delegation; WMI filters; and every setting of a GPO, computer and user, by extension, read-only, from Microsoft's own `Get-GPOReport`. Tabs read by themselves from the stored result and keep fresh; a skeleton shows until the first result.
- Group Policy changes, through Microsoft's GroupPolicy cmdlets and the GPMC COM model only (EasyRMM never writes SYSVOL or a GPO's directory attributes): create, copy, rename, delete, link, unlink, link order, enabled and enforced, block inheritance, which parts of a GPO apply, security filtering, WMI filter, back up and restore. Each asks for a step-up and a typed reason, a delete, unlink, security-filtering removal and restore also for the GPO's name, and each is audited with its before and after.
- A backup of a GPO is taken before every change, kept on the server (newest 20 per GPO and anything under 90 days old) and restored from the console; a GPO whose backup is too large to keep stops the change.
- Two-person approval: a change to a Default policy, or a link, unlink or inheritance block at the domain root, the Domain Controllers OU or a site, or an edit of a GPO linked there, waits for a second administrator with `gpo.edit`, who reviews it and runs it under their name. The Default policies are never deleted, renamed, unlinked or disabled, and need their name typed in full for any other change. An organization can turn the rules off (audited) or require approval for everything.
- New permissions `gpo.view` (Technician and above), `gpo.edit`, `gpo.link` and `gpo.manage` (Organization Administrator and Super Administrator), and a "Group Policy" card on the organization Overview.
- New agent role `gpmc`: a domain controller with the Group Policy Management tools.

## Implementation-status rows
- ADR-0083 slice 1 reads (`group_policy.status`, `gpo_list`, `gpo_get`, `link_tree`, `wmi_filters`, `gpo_report` and its parser): built; parser tested on sample XML on Linux and in the Windows CI job; scripts not run on a real controller.
- ADR-0083 slice 1 changes (`gpo_create`, `gpo_copy`, `gpo_rename`, `gpo_delete`, `gpo_status`, `sec_filter_add`, `sec_filter_remove`, `wmi_set`, `gpo_backup`, `gpo_restore_stage`, `gpo_restore`, `link_add`, `link_remove`, `link_order`, `link_enabled`, `link_enforced`, `inheritance_block`): built; guards, approval, backups and permissions tested against real PostgreSQL; scripts not run on a real controller. The go or no-go (can SYSTEM on a controller write?) is open.
- ADR-0083 amendments for slice 1 (backup size 36,000 bytes and chunked restore, no credential fallback, `GpoStatus` setter, 12 KiB audit diff, approval scope, `gpmc` on controllers only): recorded in the ADR.
- Not in slice 1: RSoP and modeling, "computers affected", delegation changes, a member server as management host, any content editor (slices 2 to 7).

## Privacy notes
- A GPO's backup (its settings, scripts and the security filtering names) is stored on the server in `gpo_backups`, readable with `gpo.view` for the list and `gpo.manage` for the bytes and the download (downloads are audited). Retention: the newest 20 per GPO and anything under 90 days old.
- A change request holds the change's parameters (a GPO's identifier, a target's distinguished name, a reason) and the names of the two people.
- Settings read from a GPO are shown, never stored: the report is parsed from the controller's answer, and the snapshot holds the parsed tree for the module's normal retention. A stored Group Policy Preferences password (`cpassword`) is never shown; the view says a finding exists.
- Group Policy is on by default for every organization once a controller reports the role; the module toggle turns it off per organization or site.

## Smoke steps for the owner (all inside a test OU; nothing touches a Default policy, the domain root, the Domain Controllers OU or a site)

You need: a domain controller with GPMC, enrolled, running this build; two Organization Administrator accounts (A and B); the ability to use the Group Policy Management Console (GPMC) and Active Directory Users and Computers; and a throw-away test OU, made by hand: `OU=EasyRMM-GPO-Test,<a disposable parent>`, with one test group and, if you want the WMI step, one WMI filter made in GPMC (`SELECT * FROM Win32_ComputerSystem`). Use the controller the AD card says changes go through.

Keep the stdout of each step if you can: the output of a script run is what replaces the hand-written samples in `server/internal/winmod/grouppolicy/testdata/sample`. The job's output is scrubbed after it is read, so capture it by running the same script in Windows PowerShell 5.1 on the controller with the same JSON on standard input if a step fails.

**A. Reads (change nothing)**
1. As A: open the controller, Roles, Group Policy. Expect no read button and a skeleton, then the domain card (GPO count, not linked anywhere, never saved). Expect the GPO list with status, versions, link count, WMI filter and owner.
2. Links: the tree lists the domain, the OUs (your test OU among them) and the sites, with order, enforced and disabled marks, and "reaches many" on the domain root, the Domain Controllers OU and the sites.
3. Settings: pick one of your own non-default GPOs; expect Computer and User halves, the extensions, the search box, and Software Installation (if it has any) marked read-only. Compare a few settings with GPMC's Settings tab.
4. WMI filters (needs gpo.manage): your filter and its query are listed.
5. Open Details of any GPO: delegation and security filtering match GPMC's Delegation tab.

**B. The identity question (the go or no-go)**
6. Create a GPO `EasyRMM-Smoke-1` (reason, then the step-up). Expect success. If it fails with "access_denied" (SYSTEM on the controller may not create GPOs), stop: report it, and do not go on; the module is read-only until a way to act as an administrator is decided (ADR-0083 amendment 2). Check in GPMC that the GPO exists, and in its Details that the computer and user versions are 0.

**C. Changes, in this order**
7. Back up `EasyRMM-Smoke-1`. Expect it in Backups, downloadable; open the zip and look for `manifest.xml` and a `{GUID}` folder. Record its size.
8. Rename to `EasyRMM-Smoke-2`. Expect the GPO renamed in GPMC, an automatic backup (kind "automatic", before "gpo rename") and, in the audit log, `winmod.group_policy.gpo_rename.change` with the reason, before and after, and the backup's id.
9. Link it to the test OU (Link, DN of the test OU, enabled, not enforced). Check GPMC. Then change its order, disable and re-enable it, enforce and release it (each its own step and backup). Check the link tree after each.
10. Block inheritance on the test OU, then allow it again.
11. Status: set "User settings disabled", then back to "Enabled". Check GPMC's GPO Status.
12. Security filtering: add the test group (its SID is in the Directory view). Then remove Authenticated Users keeping Read. Then try to remove the test group without keeping Read: expect the refusal "no_reader" (nothing else has Apply). Add Authenticated Users back if you want.
13. WMI filter: set your filter, check GPMC's WMI Filtering box, then set it to None. This is the first run of the GPMC COM calls: note any error.
14. Versions: in Details, the computer and user versions show a single number (directory and SYSVOL agree). In GPMC add one Administrative Templates setting to `EasyRMM-Smoke-2` and reload Details: the version moved by one and still agree.
15. Concurrency: open Details in the console, then change the GPO in GPMC (add another setting), then rename in the console. Expect "changed by someone else" (`changed_meanwhile`) and nothing written.
16. Settings view of `EasyRMM-Smoke-2`: the setting you added in GPMC shows under Registry with its state and value.
17. Restore: in Backups restore the backup from step 8 (reason, the GPO's name). Expect the settings you added in GPMC to be gone, and the links, security filtering, WMI filter and status to be as before the restore (note any that are not: that is the question ADR-0083 section 4 asks about what import keeps). Expect an automatic backup of the state just before the restore.
18. Delete `EasyRMM-Smoke-2` (reason, the typed name). Then restore its last backup from Backups: note whether the GPO comes back with the same identifier or a new one, and whether it is unlinked.

**D. Two people, still inside the test OU**
19. As A, Group Policy, Approvals, Approval rules: turn on "Two people for every Group Policy change". As A, rename (or create) a test GPO: expect "A second person must approve this"; ask for approval. A sees "Waiting for another administrator" and no Review button.
20. As B (another Organization Administrator): Approvals, Review, read the parameters, approve with a reason, confirm the step-up. Expect the change to run under B's name, an audit row for the request (A), the approval (B) and the job (B), and the request closed. Approve it a second time: refused.
21. As A, submit a request for a change at the domain root (Link `EasyRMM-Smoke-1` to the domain root DN; **do not approve it**). As B: Reject it with a reason. Confirm no job ran and the domain root has no new link. Never approve a link at the domain root, the Domain Controllers OU or a site in this test.
22. Turn "Two people for every change" off again (it is audited).

**E. Default policies: look, do not touch**
23. Open Details of the Default Domain Policy: expect no Delete and no Rename, and the banner about its name. Do not run any change on it.

**F. Clean up**
24. Unlink and delete the test GPOs (the console or GPMC), delete the test OU, and confirm in the console that nothing links outside the test OU. Check the audit log for every step.

Also record, for the follow-up: the real size of each GPO's backup (the cap is 36,000 bytes zipped), how long the GPO list takes to read on your domain, and whether the link tree and the list were "walked" (the walk is skipped above 600 containers).
