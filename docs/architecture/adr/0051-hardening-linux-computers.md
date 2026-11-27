# ADR-0051: Hardening Linux computers

* Status: Accepted (2026-11-21), revised twice after review the same day.
  Check (H1), apply and undo (H2), and the console for check (H3: a
  device's **Hardening** tab, and the column and filter in **Devices**)
  are implemented; the console does not yet start apply or undo.
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
  longer, runs outside the job (see `integrity`). *Amended 2026-11-22
  (decided in review):* a check keeps 30 minutes; apply and undo get 60,
  because one module's package steps may take 10 minutes to refresh the
  package lists and 25 to install, and its rollback 15 more to remove what
  it installed, which 30 minutes cannot hold. On CI's machines, under KVM
  with the distributions' mirrors, no apply or undo of one module took more
  than 35 seconds (AIDE's or the firewall's installation; run 44987598440),
  and a whole release's machine job, every module applied, applied again
  and undone with two restarts, took 7 to 10 minutes; emulated on a loaded
  host, one purge of AIDE's configuration took more than 15. The limit is
  set by the package steps' own limits, not by the fast case. The machine
  test logs how long each run takes against its limit, and fails one that
  takes longer.
  The server gives the script its job's limit (`time-limit=SECONDS`), and
  the script works to a deadline 20 seconds short of it, kept for its
  result: changes stop a sixth of the limit before that (at most 5
  minutes), which is kept for a rollback; every step it runs is cut to
  the time left; a module does not start with less than a minute left,
  nor a package step with less than its minimum (5 minutes to install, 2
  to remove or to recover the package database, 3 to rebuild an
  initramfs), and the module then fails with *not enough of the job's
  time was left*, and is put back. The modules after it are not run:
  their outcome is `not_run`, and the server keeps what it knew of them.
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
| `integrity` | AIDE installed, a baseline built and checked daily (the distribution's timer where it has one, else EasyRMM's). The baseline runs as its own unit (`easyrmm-aide-init.service`, installed by apply, run only while no baseline exists, started at boot and at apply, so a restart does not lose it) outside the job's timeout, and the job reports that it started; the next check reports whether it finished. `/var/lib/docker` and `/var/lib/containers` are left out | No |

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
  why, unless the option `root-password-off` is given. *Amended
  2026-11-22 (decided in review):* of the journal, only entries that
  sshd's processes (`sshd`, `sshd-session`) wrote as root count
  (`_UID=0` and `_COMM`, fields journald takes from the sending process):
  a user's `logger -t sshd`, or a copy of logger named `sshd`, writes
  neither. The log files (`auth.log`, `secure`) are still read, for what
  a journal kept in memory does not reach back to, and there anyone can
  write such a line with `logger`. That only keeps root's password
  sign-in on, the safe direction, and is left so.
* **Password sign-in off** is a separate option, off by default. It sets
  `PasswordAuthentication no` and `KbdInteractiveAuthentication no` (or
  passwords still work through PAM), and is refused unless at least one
  account that may sign in has a key in its `AuthorizedKeysFile`, or sshd
  has an `AuthorizedKeysCommand`. *Amended 2026-11-22 (decided in
  review):* any line of any user's file that was not a comment counted,
  so a user without sudo could make password-off go through with a stray
  word. Now sshd must take keys (`PubkeyAuthentication`), and the account
  must be root (where `PermitRootLogin` lets it in with a key) or an
  administrator (in `sudo`, `wheel` or `admin`), with a login shell, not
  expired, not locked where sshd does not use PAM (with PAM, a key gets
  into an account whose password is locked), and allowed by sshd
  (`AllowUsers` and the like). The key must be a line that parses as one:
  options without a forced command (`command=`), a known key type
  (Ed25519, RSA, ECDSA, and their security-key forms), and that type's key
  in valid base64, whose blob names the same type.
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
  *Amended 2026-11-26 (decided in review):* apply still leaves open every
  UDP socket listening when it runs, ephemeral range included (WireGuard,
  Tailscale and Mosh listen there; closing them would cut the server off).
  Only the check's "open in the table" comparison skips UDP ports in the
  local ephemeral range (`net.ipv4.ip_local_port_range`; port 68 still
  counts), since they may be client sockets that come and go and made the
  check flap. The trade-off: a UDP service started after apply on such a
  port is not reported as cut off.
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
  applicable*. Package lists are refreshed first. *Amended 2026-11-21:*
  EPEL is added (`epel-release`) on Rocky Linux and AlmaLinux only. On
  RHEL itself `epel-release` is not in the distribution's repositories
  and EPEL also needs the CodeReady Builder repository from the
  subscription, so apply refuses there and says that EPEL is added by
  hand. Packages are installed without the packages they only recommend:
  fail2ban's and AIDE's would bring a mail server, a new service
  listening.
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
  *Amended 2026-11-21:* check and apply also ask for the jail's ban
  actions (`fail2ban-client get sshd actions`). A jail without one lists
  the addresses it bans and blocks none of them; fail2ban 1.1 (Debian 13)
  leaves the jail so when a reload changes its ban action, as apply's did
  where installing the package had started fail2ban with the
  distribution's own action. Apply and undo therefore restart fail2ban
  instead of reloading it, and apply fails, and is put back, when the
  jail still has no action.

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
  hash after; the packages it installed. *Amended 2026-11-21:* and,
  outside the record because log collection (ADR-0060) shares it,
  `/var/lib/easyrmm/auditd-installed`, written when the audit module
  installs auditd and only then: the packages that installation added.
* **Undo** puts every one back if it is still as apply left it: files it
  created are removed, files it changed are restored, modes, owners and
  kernel values reset, services enabled and started again, the firewall
  table and unit removed. Anything changed since (an administrator's
  edit, a rule added to the table) is left and the result says so.
  Packages it installed are removed only if removing them would remove
  nothing else (simulated first with `apt-get -s` or `dnf --assumeno`), and
  auditd is kept, running, while another EasyRMM rules file (log
  collection's) is in `/etc/audit/rules.d/`. *Amended 2026-11-21:* on
  RHEL and Fedora the simulation is `rpm -e --test` and the removal
  `rpm -e`, because `dnf remove` also removes dependencies it judges
  unused, which this rule forbids. On Debian and Ubuntu the packages are
  purged, so that their configuration files go too, except a package
  whose configuration files were left from an earlier removal, which is
  only removed. A package an installation upgraded as a dependency stays
  upgraded: it was there before. A removal the package manager fails
  leaves the packages, and the result gives its reason. *Amended
  2026-11-22:* a module that fails after installing packages removes them
  by the same rule as it is put back, and its failure names the packages
  that stay and why, rather than saying that everything was put back.
  *Amended 2026-11-22 (decided in review):* the record names each package
  an installation added with its version and install time, and a package
  counts as there before in any installed state (half configured,
  unpacked), so that one an installation only finished is never taken for
  one it added. Undo removes a package only while it has the version and
  install time apply recorded: one upgraded or installed again since is
  left, and the result says so. On Debian and Ubuntu, the configuration
  files of each package apply installed are recorded with their MD5 sums
  as installed; undo purges a package only while they are unchanged, and
  otherwise removes it, keeping them, and says which were kept. An
  installation never removes a package: `apt-get` runs with `--no-remove`
  and `dnf` without `--allowerasing`, so one that would (a conflict) fails,
  and is put back. *Amended 2026-11-22 (decided in review):* undo, and the
  rollback of a failed apply, remove packages and never purge them, on
  every module and family; this replaces the purges above. A purge runs
  the package's own scripts, which delete what is the computer's, not the
  installation's: auditd's deletes `/var/log/audit`, the audit trail;
  fail2ban's its logs and its ban database; aide-common's every
  configuration file, edited or not, which `ucf` manages, not dpkg (Debian
  12's aide-common has no dpkg configuration files at all, so recording
  those could not guard them). On Debian and Ubuntu, a removed package's
  configuration files (dpkg's and `ucf`'s), logs and data stay; dpkg lists
  it as removed with its configuration kept (`rc`), and the result names
  those packages with the command that purges them (`apt-get purge`). A
  package that dpkg forgets when it removes it (no configuration files and
  no `postrm` script) leaves nothing of dpkg's to purge, and the result
  says nothing more of it. On RHEL and Fedora, `rpm -e` leaves the files a
  package did not ship (its logs, its data) and keeps a configuration file
  changed since installation as `.rpmsave`, and the result says so. The
  record and the marker no longer list configuration files. As CI's
  machines then found on Ubuntu 22.04, a package removed, not purged, can
  keep an init script (a configuration file) from which systemd still
  makes its unit, so a link `systemctl enable` made for the unit, which
  points at the unit file the package took away, now goes whether or not
  the unit is still there. What a removal keeps is a line of the result
  of its own, since a line holds 300 characters.
  *Amended 2026-11-22,* as CI's machines found: on Ubuntu 22.04,
  aide-common depends on a mailx, and bsd-mailx, apt's choice, on a mail
  server, which would listen, so AIDE comes with mailutils, which needs
  none; a dnf module stream an installation enabled (RHEL 8's python36,
  for fail2ban from EPEL) is recorded, and undo removes its file before
  the packages; and a link `systemctl enable` made for a unit that came
  with a package undo removed goes too, where removing the package leaves
  it pointing nowhere (Ubuntu 22.04's fail2ban). *Amended 2026-11-22,* as
  CI's machines found on the releases added to them: dracut (Ubuntu 26.04,
  RHEL and Fedora) takes the kernel module's `/etc/sysctl.d` file into an
  initramfs rebuilt after apply and applies it at boot, so undo of `kernel`
  rebuilds an initramfs that holds it, as `kernel-modules`' undo does; audit
  4 (RHEL 10 and its rebuilds, Fedora) keeps `auditctl`, `augenrules` and
  `/etc/audit/rules.d` in `audit-rules`, which AlmaLinux 10's image leaves
  out, so the audit module installs it with `audit`; and the time module
  reads a running service by its own name, not an alias's
  (`chronyd.service` is `chrony.service`'s on Ubuntu 26.04, and
  `systemctl is-enabled` answers `alias` for it). And on AlmaLinux 10,
  whose image has `audit` without `audit-rules`: `audit-rules` makes
  `/etc/audit/rules.d/audit.rules` when it is installed, a copy of the base
  rules it ships (the package lists the file without contents), so that
  copy, unchanged, counts as shipped and does not keep auditd; a marker
  that names `audit-rules` alone leaves auditd's unit to go back as any
  other unit does; and rpm gives a directory a package ships the
  package's mode and owner though it was there before (`audit-rules` made
  `/etc/audit` 0750) and leaves them when it removes the package, so an
  installation records each directory under `/etc`, two levels down, that
  was there before and that it changed, and the directory gets its mode
  and owner back once all of that installation's packages are gone (by
  undo, or by the rollback of a failed apply), if they are still as the
  installation left them; otherwise the result says it was left. rpm
  also leaves the files a package lists without contents (its ghosts,
  which its scriptlets make: `audit-rules`' two `audit.rules`), so an
  installation records each one under `/etc`, three levels down, that it
  made, and it goes once that installation's packages are gone, with the
  directory the installation made it in, if it is still as made. *Amended 2026-11-22
  (decided in review):* the stream's file goes after the packages, not
  before, and only when all of them went; a stream file that was there
  before and that the installation changed is put back as it was.
  Undo removes auditd only where `/var/lib/easyrmm/auditd-installed` says
  EasyRMM installed it, and only when no rules file is left in
  `/etc/audit/rules.d/` but those the audit package shipped, unchanged:
  then its packages and the marker go. A rules file from anyone else (log
  collection's among them) keeps auditd installed and running, and the
  marker stays, so that whoever removes the last of those files can
  remove auditd; without the marker, hardening's own record alone would
  forget it. An auditd that was installed before apply gets no marker and
  is never removed. *Amended 2026-11-22 (decided in review):* the marker
  is written and read only in a directory that is not a link, is root's,
  and only root may write; the marker also records the packages'
  configuration files, as the record does. Its package names are read as
  words, never patterns, and only in the record's form: otherwise auditd
  is left, and the result says why. Hardening's rules carry keys starting
  `easyrmm-hardening-`, and its check does not count loaded rules whose
  keys start `easyrmm-` otherwise, since those come and go with another
  feature.
  A successful undo consumes the record; the next apply takes fresh
  copies, so a later undo never brings back a file older than the
  administrator's last edit. Applying a module twice changes nothing the
  second time. *Amended 2026-11-22 (decided in review):* files a program
  that apply started made (AIDE's baseline, built after the job ends, and
  `audit.rules.prev`, which `augenrules` makes) are recorded with their
  SHA-256 (the baseline's by the command that builds it, beside the
  record), and undo removes one only while it is as made; otherwise it is
  left, and the result says so. A file apply changes that is a symbolic
  link stays one: apply and undo write the file it points to. Where
  SELinux labels files, apply keeps a file's label (`chcon --reference`),
  the record keeps the label it had, and undo sets that label again with
  `chcon`, not `restorecon`, which would give the policy's label in place
  of one set by hand.
* **Firewall and fail2ban.** *Added 2026-11-22 (decided in review):*
  fail2ban bans with the firewall in use, which may be EasyRMM's table
  and the nftables the firewall module installed. Undo therefore refuses
  the firewall alone while fail2ban's applied record remains: undone
  alone, fail2ban's bans could silently do nothing. The result names
  fail2ban (`undoWith`) for the console to choose with it; undo of both
  runs fail2ban's first (the modules run last first).
* **Interruptions.** The job can be killed (timeout, cancel). Each module
  writes its intent to its manifest before changing anything and marks it
  done after; a later check reports a module left half-applied, and undo
  reverses what was recorded. *Amended 2026-11-22 (decided in review):* a
  cancel or the job's time limit sends SIGTERM to the script's process
  group, then SIGKILL 10 seconds later; the steps the script runs through
  `timeout` are in process groups of their own, which neither reaches. The
  script therefore runs each step in the background and waits for it,
  and on SIGTERM, SIGINT or SIGHUP stops every step's group (SIGTERM, up to
  5 seconds, then SIGKILL) and releases its lock before it exits. Each
  step is registered in the lock with its process group and start time: a
  run killed outright (SIGKILL) leaves its steps running, and the lock
  counts as held while any of them runs, so that no later run starts a
  package step beside one left over. The lock also names the boot it was
  taken in: nothing from before a restart runs. *Amended 2026-11-22
  (decided in review):* a cancel or the time limit (SIGTERM) during an
  installation records, once the step is stopped and before the lock is
  released, the packages the installation had added (against the list
  taken before it, each package query cut to 3 seconds, inside the 10
  seconds before SIGKILL), with what else it changed and, for the audit
  module, the marker, in place of the note that an installation was under
  way: undo removes them as any others. A run killed outright (SIGKILL)
  leaves only the note, and undo says to remove that installation's
  packages by hand. *Amended 2026-11-22 (decided in review):* a
  package step cut short leaves the package database unusable, and every
  later package step then fails: dpkg is left interrupted, on which apt
  refuses everything until `dpkg --configure -a` runs; and on RHEL 8, an
  rpm killed while it writes leaves its Berkeley DB environment failing
  every rpm and dnf command (`DB_RUNRECOVERY`). So before each package step
  of apply and undo the script checks the database. While a process still
  uses it (holds `/var/lib/dpkg/lock-frontend` or `lock`, or has rpm's
  environment mapped), it waits as apt waits for its lock, 5 minutes, and
  never touches it; then the module fails, naming the process. Otherwise it
  recovers the database: `dpkg --configure -a`, with
  `DEBIAN_FRONTEND=noninteractive`, keeping changed configuration files,
  for at most 10 minutes (what one step left, inside a job of 30 minutes
  that the step it guards needs too; a recovery stopped there is resumed by
  the next run); on RHEL 8, removing the environment, `/var/lib/rpm/__db.*`,
  which rpm makes again (the database is in other files; `rpm --rebuilddb`
  fails on such a database too). *Amended 2026-11-22 (decided in review):*
  `dpkg --configure -a` configures every package dpkg left half installed,
  whichever run or administrator left it, running their maintainer
  scripts: the result names them (`dpkg --audit`'s list, read before the
  recovery, at most 50 names and 2,000 characters) in `packageRecovery`'s
  `packages`, which the server accepts only as package names and audits.
  On RHEL 8, a process uses the environment when it maps those files
  themselves, by device and inode (a file of the same name elsewhere, such
  as a container's, is another file), and once they are removed,
  `rpm --rebuilddb` rebuilds the indexes a killed rpm may have left half
  written. It ends by renaming the database's directory, which an overlay
  filesystem (a Docker container's) may refuse; rpm then keeps the
  database it had, and the recovery stands when rpm reads it, the result
  saying that the rebuild failed. Each module's result records it in a
  field of its own, `packageRecovery` (recovered or failed, and why), and a
  recovery that fails fails the module with its reason, once: later
  package steps of the run fail with it. An undo that fails this way puts
  back what it changed and keeps the record. RHEL 9 and Fedora keep rpm's
  database in SQLite, which a killed rpm leaves usable (the next command
  finds a package it was removing still installed), and need nothing;
  `yum-complete-transaction` is yum 3's (RHEL 7), and dnf has no
  transaction to finish.
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
*Amended 2026-11-22 (decided in review):* `usb-storage` is refused also
where `/etc/fstab` mounts a filesystem or swap on a USB disk at boot
without `nofail`, mounted now or not (found with `blkid` and
`lsblk -s -o TRAN`). fail2ban's longer bans for repeat offenders stop at a
day (`bantime.maxtime`, or the jail's own longer `bantime` or maximum),
where fail2ban sets no limit: a technician's office banned by mistake is
banned for a day at most.

### Containers
In a container (LXC or Docker, as `systemd-detect-virt --container` says)
the kernel, its modules, the audit subsystem, mandatory access control,
`/dev/shm` and the clock belong to the host: `kernel` (except the network
settings, which are the container's own), `kernel-modules`, `usb-storage`,
`time`, `audit`, `mac` and `shared-memory` report *not applicable*.
*Amended 2026-11-22:* where `systemd-detect-virt` does not know Docker and
says `none` (systemd 239, RHEL 8), the files Docker and Podman leave
(`/.dockerenv`, `/run/.containerenv`) say.

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
later ADR. *Amended 2026-11-22 (decided in review):* "tested" means CI's
machine tests apply and undo every module on that release: Debian 12 and
13, Ubuntu 22.04, 24.04 and 26.04, Rocky Linux 8, 9 and 10, AlmaLinux 9 and
10, and Fedora 45, exactly. A unit test fails when the script's table and
the machine images differ. The other releases in their support (AlmaLinux
8, RHEL 8 to 10, Fedora 43 and 44) are check only, with the reason *apply
and undo are not tested on this release*, until a machine image tests
them.

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
  options and job. *Amended 2026-11-22 (decided in review):* and
  `device.package_recovery`, by the device's agent, when a run's result
  reports a package database recovery: each module's outcome and reason,
  the mode and the job; a failure when one failed.
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

### What this does not fix
*Added 2026-11-22 (decided in review):* there is no dead-man's switch: no
change that reverts itself unless the server confirms, within some
minutes, that it can still reach the computer. The guards above make one
unneeded. The firewall leaves open every port sshd listens on and every
port in use when it runs, and filters input only; the agent, MeshAgent
and the EasyPatch agent connect out, so the channel that confirms a job
and carries an undo never depends on a port apply closes; sshd is
reloaded only after `sshd -t`; settings that act at boot are refused
where they could stop it; and undo also runs on the computer, from
MeshCentral's terminal or a console. A dead-man's switch would add its
own failure: a server outage, or an agent that polls late, would revert
hardening the operator wanted, unseen.

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
  reports. *Amended 2026-11-22 (decided in review):* and for the guards
  above, each with a test that fails without it: a cancel stopping the
  step it interrupts, the job's time limit, package versions and
  configuration files, a package already half installed, an installation
  that would remove one, the marker's directory, generated files, links,
  the firewall undone without fail2ban, and a USB disk in `/etc/fstab`.
  *Amended 2026-11-22 (decided in review):* and undo leaving what a
  package's purge would delete (its configuration files, files its
  scripts made, a log directory, its data), a cancel during an
  installation and a run killed during one, the keys and accounts that
  let password sign-in go off, and which journal entries tell that root
  signed in with a password (with stand-ins for `sshd -T` and the
  journal). The machines check that the audit trail, and fail2ban's log
  where it writes one, are still there after undo; on Debian and Ubuntu they then purge the
  packages undo left as `rc`, each of which its result must name, before
  comparing the machine with its state before apply.
* **Packages** that modules install come from a local package repository
  baked into each test image, as the bundle test's host image does.
  *Amended 2026-11-21:* that repository is not built yet. Until it is, the
  machine test installs from each distribution's own mirrors through
  QEMU's user networking: it needs the internet, and a mirror that is down
  fails it.
* **Static checks**: `shellcheck -s sh` on the script in CI, and a test that
  fails when a module, mode and distribution family has no case.
  *Amended 2026-11-22 (decided in review):* CI checked only the machine
  harness's runner; it now runs ShellCheck 0.11.0, pinned by digest, on
  both, as releases before 0.10 report the functions a trap runs as
  unreachable. A test fails when CI's machine jobs (`ci.yml`'s matrix)
  are not the pinned images, in their order.
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
