# Machine tests

Hardening Linux computers ([ADR-0051](../architecture/adr/0051-hardening-linux-computers.md#testing))
is tested on whole machines: each distribution's official cloud image boots
under QEMU, and a test drives it as root. The harness is `internal/vmtest`;
its own smoke test (`internal/vmtest/smoke_vm_test.go`, build tag `vm`)
boots each image, runs scripts, writes a file and reads it back, reaches
the guest's sshd through a forwarded port, restarts the machine and runs a
script again.

The hardening script's machine test
(`server/internal/jobs/hardening_vm_test.go`) runs `check all` on each
image. Its result must be one the server accepts, for the machine's own
release with full support. No module may fail, and no module that a
container rules out may be not applicable. Nothing under `/etc`,
`/usr/local` or the script's own state may change.

## Running them

You need `qemu-system-x86_64` and `qemu-img`, `xorriso` for Rocky Linux 8
(Debian and Ubuntu: `apt install qemu-system-x86 qemu-utils xorriso`), and
about 10 GB free under `/var/tmp`.

```bash
make test-vm                               # every image, two at a time
EASYRMM_VM_IMAGE=debian-12 make test-vm    # one image
EASYRMM_VM_IMAGE=debian-12,rocky-9 make test-vm VM_PARALLEL=2
```

| Setting | Default | |
|---|---|---|
| `EASYRMM_VM_IMAGE` | every image | Images to boot, by name, separated by commas: `debian-12`, `debian-13`, `ubuntu-22.04`, `ubuntu-24.04`, `rocky-8`, `rocky-9`, `alma-9`, `fedora-45` |
| `EASYRMM_VM_CACHE` | `/var/tmp/easyrmm-vmtest` | Downloaded images (`images/`) and the running machines' disks (`run/`). Keep it off `/tmp`, which is often a small tmpfs |
| `EASYRMM_VM_LOG_DIR` | none | When set, each machine's serial console log is copied there when it stops |
| `VM_PARALLEL` (make) | 2 | Machines booting at once |
| `VM_TEST_TIMEOUT` (make) | 3h | The whole run |

The first run downloads each image (0.3 to 2 GB) and checks it against the
digest pinned in `internal/vmtest/images.go`; later runs check the cached
copy again and reuse it. Each machine boots from a qcow2 overlay that is
deleted when its test ends.

**Without KVM it is slow.** When `/dev/kvm` can be opened QEMU uses it;
otherwise it emulates the processor (TCG) and gives each machine four
processors instead of two. On a 16-core workstation without KVM, with
two processors per machine and three or four machines at once, a first
boot took 4½ minutes (Debian 13) to 18 minutes (Rocky Linux 9, whose
kdump builds its initramfs on first boot), and a restart 3 to 10
minutes. Emulated, slow services can outlast systemd's 90-second start
timeout: Ubuntu 24.04 has come up "degraded" with polkit and udisks2
failed, which the smoke test reports as a failure. To use KVM as a
normal user, add yourself to the `kvm` group.

When a test fails, its output ends with the last lines of the machine's
serial console, QEMU's own messages and the requests the machine made for
its cloud-init seed.

## How it works

* **Network.** QEMU's user networking only, never a bridge or a tap
  device. The machine reaches the host as `10.0.2.2`; the host reaches the
  guest ports a test asks for (`vmtest.Options{Forward: []int{22}}`) on
  `127.0.0.1`, at `vm.HostPort(22)`. Tests with two machines will join them
  with QEMU's socket networking.
* **Driving the machine.** A test's scripts do not go over the machine's
  network, which the test may firewall or ban: they go over a virtio-serial
  port (`org.easyrmm.harness`) to a small `sh` runner
  (`internal/vmtest/runner.sh`), which runs each as root under `timeout`
  and answers with its output and exit code. A script sent before a
  restart is refused after it.
* **First boot.** cloud-init installs the runner. Its NoCloud seed comes
  over HTTP from the test process, named in the machine's SMBIOS serial
  number, so no seed disk is built. Rocky Linux 8's cloud-init (23.4) looks
  for that name on the kernel command line only, so its seed is a CD-ROM
  labeled `cidata`, built with `xorriso`. The seed creates no account and
  sets no password. It also tells cloud-init not to fetch the seed again
  on later boots, and `Restart` fails if it does, so that a firewall
  cannot hold up a restart.

```go
vm := vmtest.Boot(t, "debian-12", vmtest.Options{Forward: []int{22}})
stdout, stderr, exit, err := vm.Run(ctx, "sshd -T | grep -i ^permitrootlogin")
err = vm.WriteFile(ctx, "/etc/ssh/sshd_config.d/50-test.conf", conf, 0o600)
err = vm.Restart(ctx) // a clean reboot; returns when systemd has started
```

## Updating an image

Take the new file's URL and digest from the vendor's checksum file (and
check that file's signature where the vendor signs it), never from the
downloaded image, and use a dated or versioned file rather than "latest".
Update the comment above the entry, which names the checksum file and the
image's cloud-init version. The version decides the seed: `nocloud` for
cloud-init 24.4 and later, `nocloud-net` for Debian 12's 22.4, and a
CD-ROM (`SeedISO`) for Rocky Linux 8's 23.4. CI's image cache is keyed on
`images.go`, so the change downloads the images again.

## In CI

The **Machines** jobs in `ci.yml` run `make test-vm` once per image, in
parallel, on GitHub's Ubuntu runners with KVM. They run when the harness,
the hardening script or its server side, `go.mod` or the `Makefile`
change, and on the merge queue and manual runs.
Images are kept between runs with `actions/cache`; a failed job uploads
the serial console log.

## Windows

Hardening Windows computers ([ADR-0054](../architecture/adr/0054-hardening-windows-computers-and-servers.md#testing))
is tested in two places. CI's job *Windows hardening as LocalSystem*
(`backend-tests.yml`) runs the Go tests named `AsSystem` on GitHub's
`windows-2025`, `windows-2022` and `windows-11-arm` runners, each test
binary started as LocalSystem by `scripts/ci/run-as-system.ps1`:

* `internal/winpolicy` (`query_windows_test.go`): the ownership reader
  started on its own with a request file, as the agent will start it.
* `internal/winpolicy` (`planted_windows_test.go`): owners the runners do
  not have, planted as each leaves its sign and removed afterwards, with
  the reader's answer before and after: an MDM enrolment (and one that
  cannot be read), the audit policy extension's history and copy, the
  local Group Policy object's `Registry.pol`, another vendor's filtering
  platform provider with an inbound filter (in a dynamic session, which
  Windows removes when it ends), a stand-in for OSConfig's module in Program
  Files, in a folder Users may change and outside the trusted folders,
  and Azure machine configuration's service.
* `server/internal/jobs` (`hardening_windows_test.go`): the hardening
  script's `check all`, its result read as the server reads it, and the
  Hardening folder's refusals; and every value of the registry keys check
  reads, the security policy (`secedit /export`) and the audit policy
  (`auditpol /backup`), the same before and after `check all`.

CI's job *Agent tests on Windows* runs the tests named `OnWindows` as the
runner's administrator: the reader's functions and the hardening
script's one by one (`functions_windows_test.go`,
`hardening_functions_windows_test.go`), on what is hard to make in a
whole run: `Registry.pol` files, filtering platform states, text with
control characters, a service that cannot be read, registry links to keys
that do not exist, auditpol backups not in its form, a computer whose
role Windows does not report, and failed sign-ins (made with
`LogonUser`) for the exposure rule.

Runners have no domain, so the domain scenario runs on Windows guests
under KVM, not on GitHub yet (ADR-0054 says why, and what CI should do).
W1 ran it on a Proxmox VE host with Windows Server 2025's evaluation media:

1. Two guests, each with 2 CPUs, 2 GiB, an AHCI disk and an e1000e card,
   installed unattended with Server Core. One is promoted to a test
   forest's domain controller; the other joins it.
2. On the controller, as a Domain Admin,
   `internal/winpolicy/testdata/domain-gpos.ps1` makes and links the
   test's policies; then `gpupdate /target:computer /force` on the member.
3. On the member and on the controller, both `AsSystem` test binaries,
   cross-compiled (`GOOS=windows go test -c`), run as LocalSystem through
   `run-as-system.ps1`. On the member they run with `EASYRMM_TEST_DOMAIN=1`
   as well, which runs `TestQueryDomainAsSystem`: each owner the reader
   names must be the policy the script made. The reader's tests that
   expect no domain policy (`TestQueryAsSystem`, and the planted MDM,
   local Group Policy object, DSC, Azure machine configuration and
   OSConfig owners) skip on a computer in a domain, where the domain's
   policies hold the values they ask about and its preference items make
   the rest *cannot tell*.
4. With `EasyRMM-W1-RSoPOff` linked and the member refreshed, the same
   test expects *cannot tell* with `group_policy_record_off`. Windows
   keeps the last record in WMI after it is turned off; the reader must
   not use it.
5. On the member, OSConfig's module from the PowerShell Gallery and its
   member-server baseline, then the reader and `check all` again; then
   the member back to the snapshot taken before.

W1 ran it twice on 2026-11-22. The first run, between about 02:00 and
03:50 UTC, built its tests from the work in progress, fixing what it
found as it went; its last builds were of e1ad681's reader, hardening
script and tests, unchanged until the first review's fixes (c27b0b4).
The domain was rebuilt
and the scenario run again at 3d8bfb6, whose reader and hardening script
are those of 5682775, the second review's fixes:

| Scenario | At 3d8bfb6 |
|---|---|
| Hardening `AsSystem` tests, member and controller | Passed (the first try found that the unreadable-keys test took UAC's setting as missing on Server Core, where UAC's module does not apply; fixed in 3d8bfb6) |
| Reader `AsSystem` tests, member and controller | Passed: Defender for Endpoint's onboarding and another vendor's firewall; the tests that expect no domain policy skip (the first try ran them, and the domain's policies held their values, as they should) |
| `TestQueryDomainAsSystem`, every policy linked | Passed: each policy named, Default Domain Policy's too |
| The same with the record turned off | Passed |
| OSConfig's member-server baseline applied (module 1.4.16, scenario 2610.2, 341 settings) | The reader listed the scenario and gave `osconfig` for every value Group Policy did not hold, Group Policy's owner for the rest; `check all` gave 28 settings *check only*, each with `osconfig`; the hardening `AsSystem` tests passed |

The first run alone showed two more: with `EasyRMM-W1-Preferences`
unlinked its history is emptied and the reason `group_policy_preferences`
goes (the domain test, which expects it linked, fails as it should); and
`gpresult /x` names the advanced audit policy extension without its
settings, so the reader takes them from the extension's own record.

`server/internal/jobs/testdata/windows-hardening-check.txt` is the
member's `check all` output from the run at 3d8bfb6, before OSConfig;
the server's integration tests read it. Its accounts module reads the
Security log back to 16:26 UTC, after the run: the log's first records
were written while the new guest's clock ran 8 hours ahead, before its
time zone and time were set. The script now gives no time where the
oldest record read is dated after the check, but why (`sinceReason`);
the fixture, from before that change, keeps the time it gave, which the
server still accepts.

Delete the guests when done: the evaluation media expire after 180 days,
and a domain left running holds memory others need.
