# ADR-0051: Hardening Linux computers

* Status: Accepted (2026-11-21). Not implemented yet.
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

## Decision
* **Hardening is a job.** It goes through the job pipeline of ADR-0017
  unchanged: signed, delivered at the next poll, run once as root,
  reported, cancellable. Jobs gain the kind `hardening`, with
  `{mode, modules, options}`. The script is EasyRMM's: one POSIX `sh`
  script compiled into the server (`server/internal/jobs/hardening/linux.sh`);
  the mode, module names and options reach it as arguments, never as
  script text, and the server accepts only known module names and options
  of a fixed form (port numbers, CIDR ranges). Each job keeps a copy of
  the script it ran and its hash. The agent does not change.
* **Three modes:**
  * **Check** changes nothing. For each module it reports *in place*,
    *partly in place* (which settings are missing), *not in place*, *not
    applicable* (for example no SSH server), or *managed elsewhere* (see
    the firewall). It reads what is in effect: `sshd -T`, live `sysctl`
    values, `systemctl is-enabled`, file modes as bits.
  * **Apply** applies the chosen modules, then checks them.
  * **Undo** reverses the chosen modules from EasyRMM's own backups, then
    checks them.

  Each job ends with one JSON line of results, which the server keeps per
  device and module (`device_hardening`): the last check, when, by which
  job. A device's **Hardening** tab shows them, and what each module
  changes, before anything is applied.
* **The modules.** *Recommended* ones are preselected; the others must be
  chosen one by one, with their risk stated beside them.

  | Module | What it does | Recommended |
  |---|---|---|
  | `ssh` | A drop-in in `sshd_config.d` (or the main file where there is no `Include`): no root login with a password (`prohibit-password`), no empty passwords, `MaxAuthTries 4`, `LoginGraceTime 30`, idle sessions closed, no X11 forwarding; strong ciphers, key exchanges and MACs only where the system has no crypto policy of its own. Checked with `sshd -t`, then reloaded, not restarted; restored if either fails. **Password sign-in off** is a separate option, off by default | Yes |
  | `firewall` | Inbound traffic denied by default, except: established connections, loopback, the ICMP that IPv4 and IPv6 need, every port sshd listens on (`sshd -T`), every TCP and UDP port something listens on outside loopback when the job runs, and ports the operator adds. Outbound is not filtered, so the agent, MeshAgent and the EasyPatch agent are unaffected. Uses firewalld or ufw if installed, else an nftables table of EasyRMM's own. **Managed elsewhere** when a firewall is already active (ufw or firewalld enabled, or another ruleset with a dropping input policy): EasyRMM leaves it alone | Yes |
  | `fail2ban` | Installed, with a jail for sshd (5 tries, 1 hour, longer for repeat offenders) that never bans loopback or the ranges the operator lists | Yes |
  | `kernel` | A `sysctl.d` file: no ICMP redirects or source routing, SYN cookies, logged martians, loose reverse-path filtering, restricted `dmesg`, kernel pointers and `ptrace`, unprivileged BPF off (the setting that can be turned back on), protected links and FIFOs. IP forwarding is turned off only where it is off already; it is never turned off on a host that forwards | Yes |
  | `audit` | auditd installed and running, with rules (not immutable) for changes to accounts, sudoers, SSH and PAM configuration, time, the kernel's modules, mounts and privileged commands | Yes |
  | `permissions` | The modes of account files (`passwd`, `group`, `shadow`, `gshadow`), `sshd_config`, cron's files and the boot loader's configuration, keeping each distribution's owner and group (`shadow` stays `root:shadow` on Debian) | Yes |
  | `services` | Stops and disables plaintext and legacy network services that are installed: telnet, rsh, rlogin, rexec, tftp, xinetd, finger, talk, NIS. Not `snmpd`, `cups`, NFS or `rpcbind`, which managed computers often need | Yes |
  | `kernel-modules` | Keeps rarely used network protocols (DCCP, SCTP, RDS, TIPC) and filesystems (cramfs, freevxfs, hfs, hfsplus, jffs2) from loading. Not squashfs (snaps, AppImages) or udf (ISO images) | Yes |
  | `sudo` | A `sudoers.d` drop-in: commands run in a pseudo-terminal and are logged to a file. Checked with `visudo -c` | Yes |
  | `time` | A time synchronisation service running: the one there, else `systemd-timesyncd` or chrony | Yes |
  | `shared-memory` | `/dev/shm` mounted `nodev,nosuid,noexec`. Some programs run code from shared memory | No |
  | `usb-storage` | USB mass storage kept from loading. USB disks and backup drives stop working | No |
  | `mac` | AppArmor profiles in complain mode set to enforce; SELinux from permissive to enforcing. Never SELinux from disabled, which needs a relabel and a restart | No |
  | `integrity` | AIDE installed, a baseline built, checked daily. The baseline takes minutes and a lot of disk reads | No |

  Not offered: operating system updates (the patching engine), password
  ageing (NIST SP 800-63B), removing SUID bits, restricting compilers, a
  boot loader password (an unattended restart would stop at it),
  rootkit scanners, putting `/etc` in Git (secrets would be kept in its
  history), web application firewalls, Docker's settings, and forwarding
  logs (the log collection feature will).
* **Backups and undo.** Before a module changes a file, the script copies
  it to `/var/lib/easyrmm/hardening/originals/` (mode 700); the first copy
  of a file is kept for good. It records what it changes that is not a
  file: live sysctl values, whether each service was enabled and running,
  the firewall's state, the mount options, the packages it installed.
  Undo puts every one back: files it created are removed, files it edited
  are restored if nobody changed them since (otherwise they are left and
  the result says so), services are enabled and started again, and
  packages it installed are removed. Applying a module twice changes
  nothing the second time.
* **Lock-out guards.** Beyond the firewall's rules above, a module that
  fails to validate is left as it was and the others go on; SSH is only
  reloaded after `sshd -t` succeeds; a firewall is enabled only once its
  rules for the SSH and listening ports are loaded. If SSH access is lost
  anyway, EasyRMM's terminal (MeshCentral, connecting outbound) still
  reaches the computer, and **Undo** works through the agent.
* **Containers.** In a container (LXC or Docker, as `systemd-detect-virt
  --container` says), the kernel's parameters, its modules and the clock
  belong to the host: `kernel` (except the network settings, which are the
  container's own), `kernel-modules`, `usb-storage` and `time` report *not
  applicable*.
* **Platforms.** Debian 11 and later, Ubuntu 20.04 and later, and RHEL 8
  and later with its rebuilds (Rocky Linux, AlmaLinux, Oracle Linux) and
  Fedora. Other distributions are reported as not supported and nothing is
  applied. Windows is not covered: a later ADR.
* **Who.** A new permission, `device.harden`, for Site Administrators and
  above: hardening can cut off access and services, so technicians do not
  have it. Viewing the results needs `device.view`. As for software jobs,
  every device needs the permission, an EasyRMM agent and a supported
  platform, or nothing runs.
* **Audit**: `device.hardening` for each device, with the mode, modules,
  options and job.
* **API**: `POST /api/v1/jobs/hardening`; `GET /api/v1/devices/{id}/hardening`.
  Devices report `canHarden`.
* **Benchmarks.** Settings name the CIS Benchmark recommendation or DISA
  STIG they follow in the script's comments; no benchmark text is copied,
  and EasyRMM does not claim compliance with either.
* **Upstream.** No code or text is taken from ultimate-sys-hardening, so
  no notice is owed. If any is taken later, its MIT notice goes in
  THIRD_PARTY_NOTICES.md. Features of its commercial tiers are not
  reproduced from their descriptions.

## Consequences
* An operator can harden a fleet of Linux servers in one job, see per
  module what is in place, and undo it module by module.
* Choosing safety over strictness leaves some settings looser than a
  benchmark asks: loose reverse-path filtering, forwarding left on where
  it is used, every listening port left open, password sign-in to SSH left
  on unless chosen. The check reports what is in place; it is not an
  audit against a benchmark.
* The script is tested in containers of each family (Debian, Ubuntu,
  Rocky Linux, Fedora) with systemd, each with a network namespace of its
  own so that firewall rules stay inside it: check, apply, check, apply
  again without changes, undo, and every file back as it was; and the
  guards: an sshd on another port, a listening service, a host that
  forwards, an active firewall. The modules that belong to the host are
  tested in virtual machines on CI's runners, which have KVM. Before it is
  called complete it is run on a real server.
* The script changes with EasyRMM releases. Undo uses the backups on the
  computer, so a later release can undo what an earlier one applied.
