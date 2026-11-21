# ADR-0051: Hardening Linux computers

* Status: Accepted (2026-11-21), revised twice after review the same day.
  Check is implemented (H1); apply and undo (H2) and the console (H3) are
  not yet.
* Builds on: [ADR-0017](0017-scripts-and-jobs.md) (scripts and jobs) and
  [ADR-0028](0028-software-deployment.md) (a fixed script compiled into
  the server, its input as arguments).

## Context
MSPs harden the Linux servers they manage against the same short list
every time: SSH settings, a firewall, brute-force bans, kernel
parameters, audit rules, file permissions, services nobody should run.
Done by hand it is slow and uneven, and the person doing it has to know
each distribution's tools. The owner asked for hardening in one click:
pick some or all of a set of modules and apply them, with what each one
changes shown first.

[ultimate-sys-hardening](https://github.com/Kal1010101/ultimate-sys-hardening)
does this as a Bash tool run on the machine. Its free tier is MIT; its
Pro and Enterprise tiers are commercial and not published. We studied the
free tier for which settings matter and how it stays safe (back up before
changing, validate before reloading, roll back on failure, undo), and
found what EasyRMM must do differently:

* **It runs unattended, on computers the operator may not be logged in
  to.** A firewall that allows only port 22 cuts off an sshd on another
  port and every other inbound service; turning off IP forwarding breaks
  Docker, Kubernetes, VPN and router hosts; stopping `snmpd` ends SNMP
  monitoring; removing SUID bits breaks rootless containers and snaps. The
  upstream tool does all of these by default or in its automatic mode.
* **Some settings conflict with EasyRMM's own choices.** Forced periodic
  password changes go against NIST SP 800-63B, which EasyRMM's own
  password policy follows. Operating system updates are the patching
  engine's job.
* **Its undo is partial.** It does not start services again, restore file
  ownership, or remove what it installed.
* **Its checks read the wrong source**: the main `sshd_config` instead of
  the effective configuration (`sshd -T`), file modes compared as decimal
  numbers.

A review of the first version of this ADR found that it would have failed
or done harm on common servers: the SSH module on every fresh Ubuntu
24.04 (socket-activated `ssh`, no `/run/sshd` for `sshd -t`), the firewall
on keepalived pairs, NFS servers, Proxmox hosts and Kubernetes nodes (a
snapshot of listening ports is not an allow-list), kernel settings on
RHEL (loosening `rp_filter`) and Calico nodes, `usb-storage` on computers
that boot from USB. This version answers each of those.

## Decision

### The job
* **Hardening is a job.** It goes through the job pipeline of ADR-0017
  unchanged: signed, delivered at the next poll, run once as root,
  reported, cancellable. Jobs gain the kind `hardening`, with
  `{mode, modules, options}`. The script is EasyRMM's: one POSIX `sh`
  script compiled into the server (`server/internal/jobs/hardening/linux.sh`);
  the mode, module names and options reach it as arguments, never as
  script text, and the server accepts only known module names and options
  of a fixed form (port numbers, CIDR ranges, a few named switches). Each
  job keeps a copy of the script it ran and its hash. The agent does not
  change. The job's timeout is 30 minutes; AIDE's baseline, which can take
  longer, runs outside the job (see `integrity`).
* **Three modes:**
  * **Check** changes nothing. For each module it reports *in place*,
    *partly in place* (which settings are missing), *not in place*, *not
    applicable* (with the reason, for example no SSH server or a
    container), *managed elsewhere* (see the firewall), or *not supported
    on this version* (see Platforms). It reads what is in effect: `sshd -T`,
    live `sysctl` values, `systemctl is-enabled` and `is-active`, file
    modes as bits. It also lists what **apply** would change on this
    computer: the settings, and for the firewall the ports it would leave
    open.
  * **Apply** applies the chosen modules, then checks them.
  * **Undo** reverses the chosen modules from EasyRMM's own records, then
    checks them.

  Each job ends with one JSON line of results, which the server keeps per
  device and module (`device_hardening`): the last check, when, by which
  job, and what apply would change. A device's **Hardening** tab shows
  them, and **Devices** gains a hardening column and filter, so drift
  across a fleet shows.
* **Only tighter.** A module never writes a value looser than the one in
  effect: a mode is a maximum (bits are only removed), a kernel parameter
  is only raised towards the safer value, an SSH setting the system has
  set stricter is left alone.

### The modules
*Recommended* ones are preselected; the others must be chosen one by one,
with their risk stated beside them.

| Module | What it does | Recommended |
|---|---|---|
| `ssh` | See **SSH** below | Yes |
| `firewall` | See **Firewall** below | Yes |
| `fail2ban` | See **fail2ban** below | Yes |
| `kernel` | See **Kernel parameters** below | Yes |
| `audit` | auditd installed and running, with EasyRMM's rules in a file of their own, `/etc/audit/rules.d/60-easyrmm-hardening.rules`, loaded with `augenrules --load`: changes to accounts, sudoers, SSH and PAM configuration, time, the kernel's modules and mounts, and commands run with raised privileges (one `execve` rule for `euid=0` where `uid` differs, not a list of SUID files). Never `-e 2` (immutable), never `-f 2` (panic), never auditd.conf's halt actions. If the rules are already immutable, the module reports that its rules load at the next restart, and that undo cannot unload them before one. Log collection will keep its rules in another file | Yes |
| `permissions` | The modes of account files (`passwd`, `group`, `shadow`, `gshadow`), `sshd_config`, cron's files and the boot loader's configuration, as maxima: bits are only removed, so RHEL's `0000` on `shadow` stays, and each distribution's owner and group are kept (`root:shadow` on Debian). The boot loader's file is `/boot/grub/grub.cfg` (Debian, Ubuntu), `/boot/grub2/grub.cfg` (RHEL, Fedora), or on RHEL 8 with UEFI the file on the EFI partition, which is FAT: there the mount's `umask` is checked and reported, not changed. `update-grub` writes `grub.cfg` again on kernel updates: a later check reports the drift. `cron.allow` and `at.allow` are never created | Yes |
| `services` | Turns off plaintext and legacy network services that are installed, one service at a time: in `/etc/xinetd.d/` (`disable = yes` for that service, never stopping xinetd, which may host others), in `/etc/inetd.conf` (that line commented out), or its systemd unit or socket (`telnet.socket`). Telnet, rsh, rlogin, rexec, finger, talk and the NIS server (`ypserv`; never `ypbind`, which NIS sign-in needs). TFTP is reported, not turned off: PXE and configuration backup servers use it on purpose. Not `snmpd`, `cups`, NFS or `rpcbind` | Yes |
| `kernel-modules` | Keeps rarely used network protocols (DCCP, SCTP, RDS, TIPC) and filesystems (cramfs, freevxfs, hfs, hfsplus, jffs2) from loading. A module that is loaded when the job runs is left alone and reported (Oracle RAC uses RDS). Not squashfs (snaps, AppImages) or udf (ISO images) | Yes |
| `sudo` | `/etc/sudoers.d/easyrmm-hardening` (no dot in the name, which sudo would skip; mode 0440): commands run in a pseudo-terminal and are logged to `/var/log/sudo.log`, with a logrotate entry for it. Checked with `visudo -c` before it is put in place. Where sudo is `sudo-rs` (Ubuntu 25.10 and later), *not supported on this version* until tested | Yes |
| `time` | A time synchronisation service running: the one there (chrony, systemd-timesyncd, ntpd, ntpsec, openntpd, or ptp4l), else `systemd-timesyncd` or chrony, whichever the distribution ships | Yes |
| `shared-memory` | `/dev/shm` mounted `nodev,nosuid,noexec`, in `/etc/fstab` (the new file checked with `findmnt --verify --tab-file` before it replaces the old one) and remounted. Some programs run code from shared memory | No |
| `usb-storage` | USB mass storage kept from loading. USB disks and backup drives stop working. Refused when any mounted filesystem or swap is on a USB disk (`lsblk -o TRAN`): the setting reaches the initramfs, and such a computer would not boot | No |
| `mac` | SELinux from permissive to enforcing (never from disabled, which needs a relabel and a restart), refused when there were AVC denials in the last 7 days (`ausearch -m AVC`) or sshd listens on a port without the `ssh_port_t` label. AppArmor: profiles in complain mode are listed, not changed; enforcing them all at once would turn on experimental profiles | No |
| `integrity` | AIDE installed, a baseline built and checked daily (the distribution's timer where it has one, else EasyRMM's). The baseline runs as its own transient unit (`systemd-run`) outside the job's timeout, and the job reports that it started; the next check reports whether it finished. `/var/lib/docker` and `/var/lib/containers` are left out | No |

Not offered: operating system updates (the patching engine), password
ageing (NIST SP 800-63B), removing SUID bits, restricting compilers, a
boot loader password (an unattended restart would stop at it), rootkit
scanners, putting `/etc` in Git (secrets would be kept in its history),
web application firewalls, Docker's settings, and forwarding logs (the
log collection feature will).

### SSH
* **Where.** A drop-in, `/etc/ssh/sshd_config.d/00-easyrmm-hardening.conf`:
  sshd takes the first value it reads, and distributions ship their own
  drop-ins (`50-cloud-init.conf` and `60-cloudimg-settings.conf` on
  Ubuntu's cloud images, `50-redhat.conf` on RHEL 9 and Fedora), so
  EasyRMM's file sorts first. Where the main file has no `Include` (RHEL
  8), one line including EasyRMM's file is added at the very top of the
  main file, before its own settings and any `Match` block.
* **Settings**: `PermitRootLogin prohibit-password`, `PermitEmptyPasswords
  no`, `LoginGraceTime 30`, `X11Forwarding no`, and dead connections
  closed (`ClientAliveInterval 300`, `ClientAliveCountMax 3`; this closes
  connections whose other end is gone, not idle sessions). `MaxAuthTries`
  is left at sshd's 6: each key in a technician's agent counts as a try,
  and with fewer, fail2ban would ban the MSP's own office. Ciphers, key
  exchanges and MACs are set only where the system has no crypto policy
  of its own; on RHEL and Fedora the check reads `update-crypto-policies
  --show` for them instead of `sshd -T`, which there shows sshd's
  built-in defaults.
* **Root with a password.** If the authentication log or journal shows
  `Accepted password for root` in the last 30 days (backup software often
  signs in that way), apply leaves `PermitRootLogin` as it is and says
  why, unless the option `root-password-off` is given.
* **Password sign-in off** is a separate option, off by default. It sets
  `PasswordAuthentication no` and `KbdInteractiveAuthentication no` (or
  passwords still work through PAM), and is refused unless at least one
  account that may sign in has a key in its `AuthorizedKeysFile`, or sshd
  has an `AuthorizedKeysCommand`.
* **Checking and reloading.** `/run/sshd` is created if missing before
  any `sshd -T` or `sshd -t`, in every mode and module that runs them (on
  Ubuntu with socket activation both fail without it). The configuration
  is tested with `sshd -t`; the service (`ssh` on Debian and Ubuntu,
  `sshd` on RHEL and Fedora) is reloaded only if it is running; with
  socket activation, the new configuration applies at the next connection.
  If the test or the reload fails, the previous files are put back.
* **`Match` blocks** in the configuration are reported: `sshd -T` does not
  show what they change.

### Firewall
* **EasyRMM's own nftables table, `inet easyrmm`, on the input hook
  only.** Forwarded traffic and output are never filtered: containers,
  VPN gateways and routers are unaffected, and so are the agent,
  MeshAgent and the EasyPatch agent, which only connect out.
* **What it drops: new TCP connections and UDP packets** to ports not
  allowed. Everything else is accepted: established and related traffic,
  loopback, ICMP and ICMPv6 (echo included, so uptime monitors keep
  working), and other protocols (VRRP, ESP, GRE, OSPF).
* **Allowed ports**: every port sshd listens on (`sshd -T`; if sshd is
  installed and `sshd -T` fails, the module refuses), every TCP and UDP
  port something listens on outside loopback when the job runs, and ports
  and ranges the operator adds. The check lists them before apply, with
  services that are enabled but not running as *ports unknown* (they
  would be cut off when they start: the operator adds their ports or
  starts them first), and the result records them.
* **Managed elsewhere**, left alone and reported: an active ufw or
  firewalld (EasyRMM never turns either on: ufw drops forwarded traffic by
  default, and firewalld started after Docker breaks container
  networking until Docker restarts); another ruleset, in nftables or in
  legacy iptables (Ubuntu 20.04's default, which `nft` cannot see), for
  either address family, with a dropping policy or a final DROP or REJECT
  rule; CSF; CrowdSec's firewall bouncer; Proxmox VE (`pve-firewall`);
  Kubernetes nodes (`kubelet`); hosts running keepalived, an NFS server,
  an FTP server (passive ports) or a SIP server such as Asterisk (media
  ports), whose ports move.
* **Docker.** Ports published by containers reach them through Docker's
  own rules, not the input hook: the check lists them as *open through
  Docker*, not as protected.
* **Kept across restarts** by EasyRMM's own unit, `easyrmm-firewall.service`,
  loading `/etc/easyrmm-hardening/firewall.nft`, which only creates and
  replaces its own table. Never `flush ruleset`, and the distribution's
  `nftables.service` is not enabled (Debian's configuration flushes every
  ruleset, Docker's included). The rules are loaded and checked before the
  unit is enabled.

### fail2ban
* **Where it comes from.** On Debian and Ubuntu, the distribution. On RHEL
  and its rebuilds it is only in EPEL: the module adds EPEL only with the
  option `epel` (adding a repository is the customer's decision, and it
  widens what the patching engine updates); without it the module is *not
  applicable*. Package lists are refreshed first.
* **The jail**: sshd, 5 failures in 10 minutes, banned for an hour, longer
  for repeat offenders; loopback and the ranges the operator lists are
  never banned. The log source is the journal (`backend = systemd`) where
  there is no `auth.log` or `secure` file (Debian 12, Fedora). The ban
  action matches the firewall in use (EasyRMM's table or nftables, ufw,
  firewalld, legacy iptables).
* **Checked** with `fail2ban-client status sshd` once started; if the jail
  is not running, the module fails and is put back. Whether the filter
  matches this distribution's sshd messages (OpenSSH 9.8 and later logs
  as `sshd-session`, which needs fail2ban 1.1) is proved by the tests,
  which sign in wrongly on every tested release until banned.

### Kernel parameters
`/etc/sysctl.d/60-easyrmm-hardening.conf`, applied with `sysctl -p` on that
file only (never `sysctl --system`, which would apply every other file
again), and named so that later files from applications still win.

| Parameter | Value | Rule |
|---|---|---|
| `net.ipv4.conf.{all,default}.accept_redirects`, `send_redirects`, `accept_source_route`, IPv6 `accept_redirects`, `accept_source_route` | 0 | |
| `net.ipv4.tcp_syncookies` | 1 | |
| `net.ipv4.conf.{all,default}.log_martians` | 1 | |
| `net.ipv4.conf.{all,default}.rp_filter` | 2 | Only raised from 0. Never lowered from 1 (RHEL's strict default: the kernel uses the higher of `all` and each interface). Not set on Kubernetes nodes (Calico refuses to run with it loose) |
| `kernel.dmesg_restrict` | 1 | |
| `kernel.kptr_restrict` | 1 | Not 2, which blinds root's `perf` and `bpftrace` |
| `kernel.yama.ptrace_scope` | 1 | Not 3, which cannot be undone until a restart |
| `kernel.unprivileged_bpf_disabled` | 2 | 1 (locked until a restart) counts as in place |
| `fs.protected_hardlinks`, `fs.protected_symlinks` | 1 | |
| `fs.protected_fifos`, `fs.protected_regular` | 1 | |

IP forwarding is never written, on or off: a persisted 0 would break Docker
or Kubernetes installed later.

### Backups, undo and interruptions
* **Where.** `/var/lib/easyrmm-hardening/` (mode 700), apart from the
  agent's state, which uninstalling the agent removes. Removing a device
  (ADR-0050) leaves the hardening in place, and the guide says so.
* **What is recorded**, per module, in a manifest with a format version
  (so that a later release can undo what an earlier one applied): each
  file's original (or that it did not exist) and its hash after apply;
  each mode and owner before and after; each live kernel value before;
  each service's enabled and running state before; the firewall table's
  hash after; the packages it installed.
* **Undo** puts every one back if it is still as apply left it: files it
  created are removed, files it changed are restored, modes, owners and
  kernel values reset, services enabled and started again, the firewall
  table and unit removed. Anything changed since (an administrator's
  edit, a rule added to the table) is left and the result says so.
  Packages it installed are removed only if removing them would remove
  nothing else (simulated first with `apt-get -s` or `dnf --assumeno`), and
  auditd is kept, running, while another EasyRMM rules file (log
  collection's) is in `/etc/audit/rules.d/`.
  A successful undo consumes the record; the next apply takes fresh
  copies, so a later undo never brings back a file older than the
  administrator's last edit. Applying a module twice changes nothing the
  second time.
* **Interruptions.** The job can be killed (timeout, cancel). Each module
  writes its intent to its manifest before changing anything and marks it
  done after; a later check reports a module left half-applied, and undo
  reverses what was recorded.
* **Without the agent.** Apply and undo (not check, which writes nothing)
  copy the script to `/var/lib/easyrmm-hardening/easyrmm-hardening.sh`,
  so that undo can be
  run on the computer (`sh /var/lib/easyrmm-hardening/easyrmm-hardening.sh
  undo all`) from MeshCentral's terminal, a console, or after the agent
  is gone.

### Lock-out guards
Beyond the firewall's and each module's rules above: a module that fails
to validate is put back and the others go on; SSH is only reloaded after
`sshd -t` succeeds; the firewall's unit is enabled only once its rules,
with the SSH and listening ports, are loaded. Settings that act at boot
(`usb-storage`, `shared-memory`, `mac`) are refused where they could stop
the computer from booting or sshd from starting. If access is lost anyway,
EasyRMM's terminal (MeshCentral, connecting out) still reaches the
computer, and **Undo** works through the agent or on the computer itself.

### Containers
In a container (LXC or Docker, as `systemd-detect-virt --container` says)
the kernel, its modules, the audit subsystem, mandatory access control,
`/dev/shm` and the clock belong to the host: `kernel` (except the network
settings, which are the container's own), `kernel-modules`, `usb-storage`,
`time`, `audit`, `mac` and `shared-memory` report *not applicable*.

### Platforms
Apply and undo run on the versions this script has been tested on, listed
in the guide: Debian 12 and 13, Ubuntu 22.04, 24.04 and 26.04, Rocky Linux
and AlmaLinux 8, 9 and 10 (and so RHEL 8 to 10), and the Fedora releases
current when it was tested. On a newer release of these, every module is
*not supported on this version*: check runs, apply and undo do not, until
it is tested and added. Releases out of their standard support (Debian
11, Ubuntu 20.04) are check only: a computer that no longer gets security
updates needs upgrading before hardening. Oracle Linux and other
distributions are reported as not supported. Windows is not covered: a
later ADR.

### Who
* **Check** changes nothing: it needs `script.run` (Technicians and above),
  like any script.
* **Apply and undo** need a new permission, `device.harden` (Site
  Administrators and above). Technicians already have a root terminal;
  what this guards is how many computers one click can change.
* As for software jobs, every device needs the permission, an EasyRMM
  agent and a supported platform, or nothing runs. Viewing results needs
  `device.view`.

### The rest
* **Audit**: `device.hardening` for each device, with the mode, modules,
  options and job.
* **API**: `POST /api/v1/jobs/hardening`; `GET /api/v1/devices/{id}/hardening`.
  Devices report `canHarden` and `canCheckHardening`.
* **Benchmarks.** Settings name the DISA STIG rule they follow, by its ID,
  in the script's comments, where one exists; each ID is checked against
  the published STIG. CIS Benchmark numbers are not given, since they could
  not be checked against the benchmark itself. No benchmark text is copied,
  and EasyRMM does not claim compliance with any benchmark.
  *Amended 2026-11-21:* CIS numbers are also left out for a licence reason
  found in [ADR-0054](0054-hardening-windows-computers-and-servers.md):
  CIS's terms for non-members forbid exploiting its benchmarks for any
  purpose, deriving works from them or claiming consistency with them,
  and putting them in a product needs a paid Product Vendor Membership and
  certification before sale, so none are added unless the owner buys
  both. ADR-0054's *Related controls* panel (NIST SP 800-53, SP 800-171
  and ISO/IEC 27001:2022, from the STIG rules' CCIs) can be built for
  these modules from the RHEL 9 STIG IDs already cited, as a follow-up.
* **Upstream.** No code or text is taken from ultimate-sys-hardening, so
  no notice is owed. If any is taken later, its MIT notice goes in
  THIRD_PARTY_NOTICES.md. Features of its commercial tiers are not
  reproduced from their descriptions.

## Testing
* **Virtual machines are the main test**, from the first module on, because
  containers only exercise the container path. CI's Linux runners have
  KVM: each distribution's cloud image boots with a cloud-init seed under
  QEMU, its network through QEMU's user networking with forwarded ports
  (no bridge), so that traffic really arrives from outside. The harness
  drives each machine over its serial console, not SSH, so that a ban or
  a firewall cannot cut it off. One job per distribution, in parallel. For each module: check, apply, check, apply
  again (no change), restart the machine (settings persist), undo,
  restart, every file, mode and value as before.
* **Scenario machines** for the guards: Ubuntu 24.04 with socket-activated
  SSH; Rocky Linux 8 (no `Include`); Debian 12 without rsyslog; Docker with
  published ports, with Docker's userland proxy on and off; firewalld
  started after Docker; an active ufw; Ubuntu 22.04 with a legacy
  iptables rule that drops; a k3s node with Calico (the firewall steps
  aside, `rp_filter` is left alone); a Proxmox VE host; an NFS server; FTP
  and SIP servers; keepalived; a WireGuard gateway forwarding to a second
  machine (two machines joined by QEMU's socket networking, no bridge);
  SELinux enforcing with sshd on port 2222; a key-less account with
  password sign-in off refused; on every tested release, fail2ban banning
  real failed sign-ins from outside, and in a second run with the outside
  address (QEMU's 10.0.2.2) listed, not banning it; an emulated USB disk
  that stops working with `usb-storage`, and a USB root disk that refuses
  it.
* **Containers** (`--network none`, so firewall rules stay in their own
  namespace) for what applies in containers and for the *not applicable*
  reports.
* **Packages** that modules install come from a local package repository
  baked into each test image, as the bundle test's host image does.
* **Static checks**: `shellcheck -s sh` on the script in CI, and a test that
  fails when a module, mode and distribution family has no case.
* Before it is called complete it is run on a real server.

## Consequences
* An operator can harden a fleet of Linux servers in one job, see per
  module what is in place, see across the fleet where it drifted, and undo
  it module by module, through the agent or on the computer.
* Choosing safety over strictness leaves some settings looser than a
  benchmark asks: loose reverse-path filtering, forwarding left as it is,
  every listening port left open, `MaxAuthTries` at 6, password sign-in to
  SSH left on unless chosen, root password sign-in left on where it is
  used. The check reports what is in place; it is not an audit against a
  benchmark.
* Firewalls are skipped on hosts whose ports move or that run their own
  (keepalived, NFS servers, Proxmox, Kubernetes): those need a firewall
  their owner designs.
* The script changes with EasyRMM releases. Undo reads the manifest's
  format version, so a later release can undo what an earlier one applied.
