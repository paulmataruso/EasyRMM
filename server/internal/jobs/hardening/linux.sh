#!/bin/sh
# EasyRMM hardening for Linux computers (ADR-0051), run by the EasyRMM agent
# as root, or by hand from the copy apply leaves on the computer:
#   sh /var/lib/easyrmm-hardening/easyrmm-hardening.sh undo all
#
# Three modes:
#   check  reports for each chosen module whether its settings are in effect
#          and what apply would change on this computer, and changes nothing
#          (see "What check writes" below);
#   apply  applies the chosen modules, keeping a record of what it changed,
#          then checks them;
#   undo   reverses the chosen modules from that record, then checks them.
# Apply and undo run only on the releases CI's machine tests run this script
# on (FULL_SUPPORT below); elsewhere every module is reported as not
# supported, and apply and undo refuse with the reason.
#
# Arguments, which are never part of this script's text. The EasyRMM server
# accepts only the names and forms below, and this script checks them again:
#   check|apply|undo <modules> [option ...]
#   <modules>           all, or a comma-separated list of ssh, firewall,
#                       fail2ban, kernel, audit, permissions, services,
#                       kernel-modules, sudo, time, shared-memory,
#                       usb-storage, mac and integrity
#   allow-tcp=LIST      ports or ranges (8080,9000-9100) the firewall leaves
#   allow-udp=LIST      open besides those in use
#   trusted=LIST        IPv4 or IPv6 addresses or CIDR ranges fail2ban never
#                       bans
#   root-password-off   turn root's password sign-in to SSH off even if it was
#                       used in the last 30 days
#   password-off        turn password sign-in to SSH off
#   epel                let fail2ban come from EPEL on Rocky Linux and
#                       AlmaLinux (on RHEL itself EPEL must be there already)
#   time-limit=SECONDS  the job's time limit, which the server gives every
#                       mode (see "Time" below); without it (by hand), none
# Undo takes no option but time-limit.
#
# Output: progress lines, then as the last line of stdout
#   EASYRMM-HARDENING-RESULT-V1 {"version":1,"mode":"check",...}
# kept under 64 KiB. Apply and undo add to each module what they did
# ("outcome", "outcomeReason", "done"), and every mode says whether
# EasyRMM's record of the module is on the computer ("recorded"). The exit
# status is 0 whenever the result was printed, whatever it says; 2 for a
# usage error, 3 when not run as root.
#
# What check writes: nothing, with one exception ADR-0051 requires. On Debian
# and Ubuntu, sshd -T fails when /run/sshd is missing (socket-activated ssh
# on Ubuntu never creates it), so /run/sshd is created first. It is an empty
# directory on a tmpfs, which sshd itself creates when it starts. Elsewhere it
# is created only if sshd -T fails for want of it. Check uses no temporary
# files (not even here-documents, which some shells keep in /tmp), takes no
# locks, starts and loads nothing, and reads kernel state only where the
# reading cannot load a module.
#
# The record apply and undo keep, which check reads (ADR-0051, "Backups,
# undo and interruptions"), away from the agent's own state:
#   /var/lib/easyrmm-hardening/                      mode 700
#     easyrmm-hardening.sh     a copy of this script
#     lock/                    held while apply or undo runs
#     tx/                      this run's copies, to put a module back
#     modules/<module>/
#       intent                 written before apply or undo changes anything
#                              in the module
#       done                   written when it finished
#       manifest               "format 1", then a record of each change, in
#                              order, fields separated by tabs (see "The
#                              record" below)
#       files/                 the originals of the files it changed
# A module with an intent and no done mark was interrupted (a timeout or a
# cancel killed the job): check reports it as half_applied, and undo
# reverses what it recorded.
#
# Time: the agent stops a job at its time limit (SIGTERM to the script's
# process group, SIGKILL 10 seconds later), as it does a cancel. Every
# command that could take long runs through t, with a limit of its own and
# never past the job's: apply's and undo's steps stop WORK_RESERVE before
# the end, which a rollback and the result may use; a package step is not
# started without its minimum left. A module that runs out of time fails,
# and those after it are reported as not run (outcome not_run). On SIGTERM
# the steps running through t, each in a process group of its own
# (timeout's), are stopped with the script, and the lock released.
#
# Benchmarks: comments name the DISA Red Hat Enterprise Linux 9 STIG rule a
# setting follows, by its ID, where one exists; each ID was checked against
# the published STIG. CIS Benchmark numbers are not given: they could not be
# checked here. EasyRMM claims compliance with neither, and where ADR-0051 is
# looser than a benchmark on purpose the comment says so.

set -u
# Not set -e: a check that cannot read something reports that and goes on,
# and the result line must always be printed.
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
LC_ALL=C
export PATH LC_ALL
unset CDPATH

RESULT_TAG=EASYRMM-HARDENING-RESULT-V1
# The modules in the order they are checked and reported.
ALL_MODULES='ssh firewall fail2ban kernel audit permissions services kernel-modules sudo time shared-memory usb-storage mac integrity'
STATE_DIR=/var/lib/easyrmm-hardening
# EasyRMM's own files, which apply writes and undo removes.
SSH_DROPIN=/etc/ssh/sshd_config.d/00-easyrmm-hardening.conf
FW_DIR=/etc/easyrmm-hardening
FW_FILE=$FW_DIR/firewall.nft
FW_UNIT=easyrmm-firewall.service
FW_UNIT_FILE=/etc/systemd/system/$FW_UNIT
F2B_FILE=/etc/fail2ban/jail.d/easyrmm-hardening.local
SYSCTL_FILE=/etc/sysctl.d/60-easyrmm-hardening.conf
AUDIT_FILE=/etc/audit/rules.d/60-easyrmm-hardening.rules
# Where augenrules keeps the rules it replaces.
AUDIT_PREV=/etc/audit/audit.rules.prev
# Written when the audit module installs auditd, and only then: the packages
# that installation added. Shared with log collection (ADR-0060), so outside
# hardening's own state: whoever removes auditd last removes them and it.
AUDITD_MARKER=/var/lib/easyrmm/auditd-installed
SUDO_FILE=/etc/sudoers.d/easyrmm-hardening
SUDO_LOG=/var/log/sudo.log
SUDO_ROTATE=/etc/logrotate.d/easyrmm-hardening-sudo
MODULES_FILE=/etc/modprobe.d/60-easyrmm-hardening.conf
USB_FILE=/etc/modprobe.d/60-easyrmm-usb-storage.conf
# Debian's aide.conf includes only files whose names have no dot.
AIDE_DEB_FILE=/etc/aide/aide.conf.d/99_easyrmm_hardening
AIDE_UNIT=easyrmm-aide-check
AIDE_INIT_UNIT=easyrmm-aide-init

nl='
'
tab=$(printf '\t')

# The platforms apply and undo run on (ADR-0051, "Platforms"): exactly the
# releases CI's machine tests apply and undo every module on, one
# distribution a line: its ID in os-release, then its releases. A release
# without a dot matches every point release of it (Rocky Linux 9.4 is 9).
FULL_SUPPORT='
debian 12 13
ubuntu 22.04 24.04 26.04
rocky 8 9 10
almalinux 9 10
fedora 45
'
# Releases in their standard support that CI does not test, which check
# reports on but apply and undo refuse; and so are newer releases of the
# distributions here and above, until they are tested.
UNTESTED='
almalinux 8
rhel 8 9 10
fedora 43 44
'
# Releases out of their standard support, which check reports on but apply
# and undo refuse: they need upgrading before hardening.
OUT_OF_SUPPORT='
debian 11
ubuntu 20.04
'

say() { printf '%s\n' "$*"; }

usage() {
	printf 'linux.sh: %s\n' "$1" >&2
	printf 'Usage: sh linux.sh check|apply|undo <all|module,...> [allow-tcp=LIST] [allow-udp=LIST] [trusted=LIST] [root-password-off] [password-off] [epel] [time-limit=SECONDS]\n' >&2
	exit 2
}

have() { command -v "$1" >/dev/null 2>&1; }
# text_has TEXT GREP-OPTION... PATTERN: whether a line of TEXT matches.
# grep -q stops at the first match; where SIGPIPE is ignored (systemd's
# default for services) printf would then complain about the closed pipe.
text_has() {
	th_text=$1
	shift
	printf '%s\n' "$th_text" 2>/dev/null | grep -q "$@"
}

# The job's time (see "Time" above), in seconds since the epoch: JOB_END
# leaves END_RESERVE for the result, WORK_END WORK_RESERVE before that for
# a rollback. T_END is the end t keeps commands to: WORK_END while apply or
# undo changes a module, JOB_END otherwise (a check, a rollback). All empty
# without time-limit.
START_S=$(date +%s)
END_RESERVE=20
# At most this much, and a sixth of the job's time, is kept for a rollback.
WORK_RESERVE=300
JOB_END=
WORK_END=
T_END=
# The least time a module, and each kind of step, starts with.
MODULE_MIN=60
PKG_INSTALL_MIN=300
PKG_REMOVE_MIN=120
PKG_RECOVER_MIN=120
INITRAMFS_MIN=180
# Set once a step found too little time left, or was stopped at the job's
# end: the modules after it are not run.
OUT_OF_TIME=no
# The module undo needs to undo with this one (undo_module), for the result.
M_UNDO_WITH=
# Whether t's last command (in this shell) was stopped at the job's end
# rather than at its own limit.
T_CAPPED=no
# The step t runs now (in this shell), until it ends: its timeout's PID.
T_PID=
LOCK_HELD=no
LOCK_DIR=$STATE_DIR/lock
# t's command while the lock is held: it records its own PID and start
# (its /proc stat line) in the lock, then becomes timeout, which puts
# itself in a process group of its own; so a step is never out of sight of
# the trap that stops it, or of a later run's lock.
# shellcheck disable=SC2016 # expanded by the sh that runs it
T_RUN='d=$1; shift; read -r s </proc/$$/stat; printf "%s\n" "$s" >"$d/t.$$" 2>/dev/null; exec timeout -k 5 "$@"'

# t SECONDS COMMAND...: runs a command that could hang (a stuck daemon, a
# hung network mount, a package manager) with a time limit, never past
# T_END: a command that would start with no time left does not start, and
# fails as a command out of time does (124).
t() {
	t_s=$1
	shift
	T_CAPPED=no
	if [ -n "$T_END" ]; then
		t_left=$((T_END - $(date +%s)))
		if [ "$t_left" -lt 1 ]; then
			T_CAPPED=yes
			OUT_OF_TIME=yes
			return 124
		fi
		if [ "$t_s" -gt "$t_left" ]; then
			t_s=$t_left
			T_CAPPED=yes
		fi
	fi
	if ! have timeout; then
		"$@"
		return
	fi
	# In the background, so that a signal reaches the trap while it runs;
	# set here, so that a subshell (a command substitution, a pipeline)
	# stops its own step too.
	trap on_signal TERM INT HUP
	if [ "$LOCK_HELD" = yes ]; then
		sh -c "$T_RUN" sh "$LOCK_DIR" "$t_s" "$@" &
	else
		timeout -k 5 "$t_s" "$@" &
	fi
	T_PID=$!
	wait "$T_PID"
	t_rc=$?
	[ "$LOCK_HELD" = no ] || rm -f "$LOCK_DIR/t.$T_PID"
	T_PID=
	if [ "$T_CAPPED" = yes ] && [ "$t_rc" -eq 124 ]; then
		OUT_OF_TIME=yes
	else
		T_CAPPED=no
	fi
	return "$t_rc"
}

# time_left: the seconds left until T_END, or nothing without a time limit.
time_left() {
	[ -z "$T_END" ] || printf '%s' $((T_END - $(date +%s)))
}
# minutes SECONDS: "N minutes" or "N seconds", for reasons.
minutes() {
	if [ "$1" -ge 120 ]; then printf '%s minutes' $(($1 / 60)); else printf '%s seconds' "$1"; fi
}
# need_time SECONDS WHAT: whether at least SECONDS are left for WHAT; if
# not, PKG_ERR says so, and the run is out of time.
need_time() {
	nt_left=$(time_left)
	[ -n "$nt_left" ] && [ "$nt_left" -lt "$1" ] || return 0
	[ "$nt_left" -ge 0 ] || nt_left=0
	OUT_OF_TIME=yes
	PKG_ERR="not enough of the job's time was left to $2 ($(minutes "$nt_left") left, at least $(minutes "$1") needed)"
	return 1
}

# shellcheck disable=SC2329 # stop_steps runs it, from the trap
# proc_stat_field PID N: field N of /proc/PID/stat, counted after the
# command's name (state is 3, the process group 5, the start time 22).
proc_stat_field() {
	sed -n 's/^.*) //p' "/proc/$1/stat" 2>/dev/null | awk -v n="$2" '{ print $(n - 2) }'
}
# group_runs PGID START: whether a process, not a zombie, of that process
# group runs that started no earlier than START (its leader's start: a
# group whose leader is gone, or a PID used again, does not count before).
group_runs() {
	for gr_s in /proc/[0-9]*/stat; do
		sed -n 's/^.*) //p' "$gr_s" 2>/dev/null
	done | awk -v g="$1" -v s="$2" '$1 != "Z" && $3 == g && $20 >= s { f = 1; exit } END { exit !f }'
}
# t_steps: "PGID START" of each step t runs in the lock's sight, one a line.
t_steps() {
	for ts_f in "$LOCK_DIR"/t.*; do
		[ -f "$ts_f" ] || continue
		ts_p=${ts_f##*/t.}
		case $ts_p in '' | *[!0-9]*) continue ;; esac
		ts_s=$(sed -n 's/^.*) //p' "$ts_f" 2>/dev/null | awk '{ print $20 }')
		case $ts_s in '' | *[!0-9]*) continue ;; esac
		printf '%s %s\n' "$ts_p" "$ts_s"
	done
}
# stop_steps: on SIGTERM, SIGINT or SIGHUP (a cancel, or the job's time
# limit), stops the steps running through t, each a process group of its
# own: SIGTERM, up to 5 seconds, then SIGKILL (the agent's own SIGKILL
# comes 10 seconds after its SIGTERM).
# shellcheck disable=SC2329 # the trap runs it
stop_steps() {
	ss_g=
	if [ "$LOCK_HELD" = yes ]; then
		ss_g=$(t_steps | while read -r ss_p ss_s; do
			# Only a group still led by the step that started it.
			[ "$(proc_stat_field "$ss_p" 22)" != "$ss_s" ] || printf '%s ' "$ss_p"
		done)
	fi
	[ -z "$T_PID" ] || in_words "$T_PID" "$ss_g" || ss_g="$ss_g $T_PID"
	[ -n "${ss_g# }" ] || return 0
	for ss_p in $ss_g; do kill -TERM -"$ss_p" 2>/dev/null || kill -TERM "$ss_p" 2>/dev/null; done
	ss_n=0
	while [ "$ss_n" -lt 5 ]; do
		ss_live=no
		for ss_p in $ss_g; do
			[ "$(proc_stat_field "$ss_p" 3)" = Z ] || [ ! -e "/proc/$ss_p" ] || ss_live=yes
		done
		[ "$ss_live" = yes ] || break
		sleep 1
		ss_n=$((ss_n + 1))
	done
	for ss_p in $ss_g; do kill -KILL -"$ss_p" 2>/dev/null; done
	return 0
}
# shellcheck disable=SC2329 # the trap runs it
on_signal() {
	# A subshell stops its own step; the run itself stops every step, and
	# releases the lock.
	os_self=
	read -r os_self _ </proc/self/stat 2>/dev/null
	if [ -n "$os_self" ] && [ "$os_self" != "$$" ]; then
		LOCK_HELD=no
		stop_steps
		exit 143
	fi
	stop_steps
	release
	exit 143
}

# in_words WORD LIST: whether WORD is one of the space-separated LIST.
in_words() {
	case " $2 " in *" $1 "*) return 0 ;; esac
	return 1
}

# ---------------------------------------------------------------------------
# Arguments

[ $# -ge 1 ] || usage 'no mode given.'
MODE=$1
case $MODE in
check | apply | undo) ;;
*) usage "unknown mode: $MODE (modes: check, apply, undo)." ;;
esac
[ $# -ge 2 ] || usage 'no modules given.'
MODULES_ARG=$2
shift 2
# Undo reverses what the record says, whatever the options were: it takes
# the job's time limit only.
if [ "$MODE" = undo ]; then
	for arg in "$@"; do
		case $arg in time-limit=*) ;; *) usage 'undo takes no options: it reverses what EasyRMM recorded.' ;; esac
	done
fi

valid_port() {
	case $1 in '' | 0* | *[!0-9]*) return 1 ;; esac
	[ ${#1} -le 5 ] && [ "$1" -le 65535 ]
}

# A comma-separated list of ports and ranges, as in 8080,9000-9100.
valid_ports() {
	case $1 in '' | ,* | *, | *,,*) return 1 ;; esac
	vp_rest=$1,
	while [ -n "$vp_rest" ]; do
		vp_p=${vp_rest%%,*}
		vp_rest=${vp_rest#*,}
		case $vp_p in
		*-*) vp_a=${vp_p%%-*} vp_b=${vp_p#*-} ;;
		*) vp_a=$vp_p vp_b=$vp_p ;;
		esac
		valid_port "$vp_a" && valid_port "$vp_b" && [ "$vp_a" -le "$vp_b" ] || return 1
	done
}

valid_ipv4() {
	case $1 in *[!0-9.]* | .* | *. | *..*) return 1 ;; esac
	v4_rest=$1.
	v4_n=0
	while [ -n "$v4_rest" ]; do
		v4_o=${v4_rest%%.*}
		v4_rest=${v4_rest#*.}
		case $v4_o in '' | 0?* | ????*) return 1 ;; esac
		[ "$v4_o" -le 255 ] || return 1
		v4_n=$((v4_n + 1))
	done
	[ "$v4_n" -eq 4 ]
}

# Hexadecimal groups only: forms with a dotted IPv4 tail are not accepted.
valid_ipv6() {
	case $1 in *[!0-9a-fA-F:]* | '' | *:::* | *::*::*) return 1 ;; esac
	case $1 in :[!:]* | *[!:]:) return 1 ;; esac
	v6_rest=$1
	v6_double=no
	case $v6_rest in *::*) v6_double=yes ;; esac
	v6_n=0
	# Split at colons; empty groups come only from the double colon.
	v6_rest=$v6_rest:
	while [ -n "$v6_rest" ]; do
		v6_g=${v6_rest%%:*}
		v6_rest=${v6_rest#*:}
		[ -n "$v6_g" ] || continue
		case $v6_g in ?????*) return 1 ;; esac
		v6_n=$((v6_n + 1))
	done
	if [ "$v6_double" = yes ]; then [ "$v6_n" -le 7 ]; else [ "$v6_n" -eq 8 ]; fi
}

# An address, or an address with a prefix length: 10.0.0.0/8, 2001:db8::/32.
valid_cidr() {
	case $1 in */*/*) return 1 ;; esac
	vc_a=${1%/*}
	vc_p=
	case $1 in */*) vc_p=${1#*/} ;; esac
	if valid_ipv4 "$vc_a"; then
		vc_max=32
	elif valid_ipv6 "$vc_a"; then
		vc_max=128
	else
		return 1
	fi
	case $1 in */*)
		case $vc_p in '' | 0?* | *[!0-9]* | ????*) return 1 ;; esac
		[ "$vc_p" -le "$vc_max" ] || return 1
		;;
	esac
	return 0
}

valid_cidrs() {
	case $1 in '' | ,* | *, | *,,*) return 1 ;; esac
	vcs_rest=$1,
	while [ -n "$vcs_rest" ]; do
		valid_cidr "${vcs_rest%%,*}" || return 1
		vcs_rest=${vcs_rest#*,}
	done
}

OPT_ALLOW_TCP=
OPT_ALLOW_UDP=
OPT_TRUSTED=
OPT_ROOT_PASSWORD_OFF=no
OPT_PASSWORD_OFF=no
OPT_EPEL=no
OPT_TIME_LIMIT=
# A list option given twice adds to the first.
add_opt() {
	eval "ao_old=\$$1"
	if [ -n "$ao_old" ]; then eval "$1=\$ao_old,\$2"; else eval "$1=\$2"; fi
}
for arg in "$@"; do
	case $arg in
	allow-tcp=*)
		valid_ports "${arg#*=}" || usage "allow-tcp takes ports and ranges from 1 to 65535, such as 8080,9000-9100: ${arg#*=}"
		add_opt OPT_ALLOW_TCP "${arg#*=}"
		;;
	allow-udp=*)
		valid_ports "${arg#*=}" || usage "allow-udp takes ports and ranges from 1 to 65535, such as 53,5060-5061: ${arg#*=}"
		add_opt OPT_ALLOW_UDP "${arg#*=}"
		;;
	trusted=*)
		valid_cidrs "${arg#*=}" || usage "trusted takes IPv4 and IPv6 addresses or CIDR ranges, such as 10.0.0.0/8,2001:db8::/32: ${arg#*=}"
		add_opt OPT_TRUSTED "${arg#*=}"
		;;
	time-limit=*)
		# A minute to four hours: the time limits the agent accepts.
		case ${arg#*=} in '' | 0* | *[!0-9]* | ??????*) usage "time-limit takes seconds, from 60 to 14400: ${arg#*=}" ;; esac
		[ "${arg#*=}" -ge 60 ] && [ "${arg#*=}" -le 14400 ] || usage "time-limit takes seconds, from 60 to 14400: ${arg#*=}"
		OPT_TIME_LIMIT=${arg#*=}
		;;
	root-password-off) OPT_ROOT_PASSWORD_OFF=yes ;;
	password-off) OPT_PASSWORD_OFF=yes ;;
	epel) OPT_EPEL=yes ;;
	*) usage "unknown option: $arg" ;;
	esac
done

if [ -n "$OPT_TIME_LIMIT" ]; then
	JOB_END=$((START_S + OPT_TIME_LIMIT - END_RESERVE))
	[ "$WORK_RESERVE" -le $((OPT_TIME_LIMIT / 6)) ] || WORK_RESERVE=$((OPT_TIME_LIMIT / 6))
	WORK_END=$((JOB_END - WORK_RESERVE))
	T_END=$JOB_END
fi
trap on_signal TERM INT HUP

SELECTED=
case $MODULES_ARG in
all) SELECTED=$ALL_MODULES ;;
'' | ,* | *, | *,,*) usage "modules must be all or a comma-separated list of: $ALL_MODULES" ;;
*)
	ma_rest=$MODULES_ARG,
	ma_chosen=
	while [ -n "$ma_rest" ]; do
		ma_m=${ma_rest%%,*}
		ma_rest=${ma_rest#*,}
		in_words "$ma_m" "$ALL_MODULES" || usage "unknown module: $ma_m (modules: all, or $ALL_MODULES)"
		ma_chosen="$ma_chosen $ma_m"
	done
	for ma_m in $ALL_MODULES; do
		if in_words "$ma_m" "$ma_chosen"; then SELECTED="$SELECTED $ma_m"; fi
	done
	;;
esac

if [ "$(id -u 2>/dev/null)" != 0 ]; then
	printf 'linux.sh: EasyRMM hardening must run as root.\n' >&2
	exit 3
fi

# ---------------------------------------------------------------------------
# What this computer is

OS_RELEASE=/etc/os-release
[ -r "$OS_RELEASE" ] || OS_RELEASE=/usr/lib/os-release

# os_field KEY: one value from os-release, read as text (the file is never
# run, as sourcing it would).
os_field() {
	[ -r "$OS_RELEASE" ] || return 0
	sed -n "s/^$1=//p" "$OS_RELEASE" | head -n 1 | sed -e 's/^"\(.*\)"$/\1/' -e "s/^'\\(.*\\)'\$/\\1/"
}

OS_ID=$(os_field ID)
OS_VERSION=$(os_field VERSION_ID)
OS_LIKE=$(os_field ID_LIKE)
OS_MAJOR=${OS_VERSION%%.*}

case $OS_ID in
debian | ubuntu) FAMILY=debian ;;
rhel | rocky | almalinux | centos | ol) FAMILY=rhel ;;
fedora) FAMILY=fedora ;;
*)
	case " $OS_LIKE " in
	*" rhel "* | *" centos "*) FAMILY=rhel ;;
	*" fedora "*) FAMILY=fedora ;;
	*" debian "* | *" ubuntu "*) FAMILY=debian ;;
	*) FAMILY=other ;;
	esac
	;;
esac

# ver_ge A B: whether version A is B or later, compared number by number.
ver_ge() {
	awk -v a="$1" -v b="$2" 'BEGIN {
		na = split(a, x, "."); nb = split(b, y, "."); n = (na > nb) ? na : nb
		for (i = 1; i <= n; i++) {
			if ((x[i] + 0) > (y[i] + 0)) exit 0
			if ((x[i] + 0) < (y[i] + 0)) exit 1
		}
		exit 0
	}'
}

# support_of TABLE: whether this release is in TABLE (prints "in"), newer than
# every release there ("newer"), or neither (nothing). TABLE may name a
# distribution on more than one line.
support_of() {
	so_line=$(printf '%s\n' "$1" | awk -v id="$OS_ID" '$1 == id { for (i = 2; i <= NF; i++) printf "%s ", $i }')
	[ -n "$so_line" ] && [ -n "$OS_VERSION" ] || return 0
	so_newer=yes
	for so_v in $so_line; do
		case $so_v in
		*.*) so_have=$OS_VERSION ;;
		*) so_have=$OS_MAJOR ;;
		esac
		if [ "$so_have" = "$so_v" ]; then
			printf in
			return 0
		fi
		ver_ge "$OS_VERSION" "$so_v" || so_newer=no
	done
	[ "$so_newer" = no ] || printf newer
}

case $OS_VERSION in *[!0-9.]*) OS_VERSION_OK=no ;; *) OS_VERSION_OK=yes ;; esac
SUPPORT=unsupported
# Why apply and undo refuse here.
SUPPORT_WHY="This distribution or release is not supported: apply and undo run on the releases EasyRMM's tests apply and undo them on."
if [ "$OS_VERSION_OK" = yes ]; then
	if [ "$(support_of "$FULL_SUPPORT")" = in ]; then
		SUPPORT=full
		SUPPORT_WHY=
	elif case $(support_of "$FULL_SUPPORT$UNTESTED") in in | newer) true ;; *) false ;; esac then
		SUPPORT=check_only
		SUPPORT_WHY='This release is checked only: apply and undo are not tested on this release.'
	elif [ "$(support_of "$OUT_OF_SUPPORT")" = in ]; then
		SUPPORT=check_only
		SUPPORT_WHY='This release is checked only: it is out of its standard support, and needs upgrading before hardening.'
	fi
fi

# systemd-detect-virt where it is installed; its "container-other" (older
# systemd, for an image that sets container=oci) is narrowed by the files
# Docker and Podman leave.
detect_container() {
	if have systemd-detect-virt; then
		dc_v=$(systemd-detect-virt --container 2>/dev/null)
		case $dc_v in
		# none from systemd 239 (RHEL 8) too, which does not know Docker:
		# the files below say.
		'' | none) ;;
		container-other)
			if [ -e /run/.containerenv ]; then
				printf podman
			elif [ -e /.dockerenv ]; then
				printf docker
			else
				printf other
			fi
			return 0
			;;
		*)
			printf '%s' "$dc_v"
			return 0
			;;
		esac
	fi
	if [ -e /run/.containerenv ]; then
		printf podman
	elif [ -e /.dockerenv ]; then
		printf docker
	else
		dc_v=$(tr '\000' '\n' </proc/1/environ 2>/dev/null | sed -n 's/^container=//p' | head -n 1)
		[ -n "$dc_v" ] || dc_v=$(head -n 1 /run/systemd/container 2>/dev/null)
		printf '%s' "${dc_v:-none}"
	fi
}
case $(detect_container) in
none) CONTAINER=none ;;
lxc | lxc-libvirt) CONTAINER=lxc ;;
docker) CONTAINER=docker ;;
podman) CONTAINER=podman ;;
*) CONTAINER=other ;;
esac
IN_CONTAINER=yes
[ "$CONTAINER" != none ] || IN_CONTAINER=no

SYSTEMD_UP=no
[ -d /run/systemd/system ] && SYSTEMD_UP=yes

# Every process's name, once (comm, cut to 15 characters by the kernel).
PROCS=$(cat /proc/[0-9]*/comm 2>/dev/null | sort -u)
proc_running() { text_has "$PROCS" -xF "$1"; }

# unit_ask VERB UNIT: the first line systemctl VERB UNIT prints. Nothing
# for a unit whose file is there means systemd did not answer in time (busy
# reloading, or slow under load): it is asked twice more, with a minute
# each, so that a slow answer is not taken for a unit that is off or
# missing, in a finding or in apply's record.
unit_ask() {
	for uq_s in 20 60 60; do
		uq_out=$(t "$uq_s" systemctl "$1" "$2" 2>/dev/null | head -n 1)
		if [ -n "$uq_out" ] || ! unit_on_disk "$2"; then
			[ -z "$uq_out" ] || printf '%s\n' "$uq_out"
			return 0
		fi
	done
}
# unit_on_disk UNIT: whether UNIT's file (or its template's) is where
# systemd looks for units.
unit_on_disk() {
	uo_t=$1
	case $1 in *@?*.*) uo_t=${1%%@*}@.${1##*.} ;; esac
	for uo_d in /etc/systemd/system /run/systemd/system /run/systemd/transient /run/systemd/generator.early /run/systemd/generator /run/systemd/generator.late /usr/local/lib/systemd/system /usr/lib/systemd/system /lib/systemd/system; do
		if [ -e "$uo_d/$1" ] || [ -e "$uo_d/$uo_t" ]; then return 0; fi
	done
	return 1
}
# unit_file_state UNIT: what systemctl is-enabled says (it reads unit files,
# so it works without systemd running), or nothing.
unit_file_state() {
	have systemctl || return 0
	unit_ask is-enabled "$1"
}
unit_enabled() {
	case $(unit_file_state "$1") in enabled | enabled-runtime) return 0 ;; esac
	return 1
}
unit_exists() {
	case $(unit_file_state "$1") in '' | not-found) return 1 ;; esac
	return 0
}
unit_active() {
	[ "$SYSTEMD_UP" = yes ] || return 1
	case $(unit_ask is-active "$1") in active | reloading | activating) return 0 ;; esac
	return 1
}
# svc_on NAME...: whether any NAME runs or starts at boot: a unit (NAME ends
# in .service or .socket) enabled or active, or else a process of that name.
svc_on() {
	for so_n in "$@"; do
		case $so_n in
		*.service | *.socket)
			unit_active "$so_n" && return 0
			unit_enabled "$so_n" && return 0
			;;
		*) proc_running "$so_n" && return 0 ;;
		esac
	done
	return 1
}

# Kubernetes nodes: the firewall steps aside and rp_filter is left alone
# (Calico refuses to run with it loose). k3s, RKE2 and MicroK8s run the kubelet
# inside their own binaries.
IS_K8S=unknown
is_k8s_node() {
	if [ "$IS_K8S" = unknown ]; then
		IS_K8S=no
		if svc_on kubelet.service k3s.service k3s-agent.service rke2-server.service rke2-agent.service \
			snap.microk8s.daemon-kubelite.service kubelet k3s k3s-server k3s-agent kubelite ||
			[ -e /var/lib/kubelet/config.yaml ] || [ -e /etc/kubernetes/kubelet.conf ]; then
			IS_K8S=yes
		fi
	fi
	[ "$IS_K8S" = yes ]
}

# ---------------------------------------------------------------------------
# sshd's settings in effect, read once with sshd -T.

SSHD_T_DONE=no
SSHD_T=
SSHD_T_RC=0
SSHD_T_ERR=
sshd_run_t() {
	SSHD_T=$(t 30 sshd -T 2>/dev/null)
	SSHD_T_RC=$?
	# Keys in lower case: OpenSSH 10.5 (Fedora 45) prints them as the
	# configuration file spells them (Port, PermitRootLogin), earlier
	# releases in lower case.
	SSHD_T=$(printf '%s\n' "$SSHD_T" | awk '{ print tolower($1) substr($0, length($1) + 1) }')
}
# sshd_effective: runs sshd -T once; fails if it failed (SSHD_T_ERR says why).
sshd_effective() {
	if [ "$SSHD_T_DONE" = no ]; then
		SSHD_T_DONE=yes
		# ADR-0051: /run/sshd is created if missing before sshd -T. Debian and
		# Ubuntu build OpenSSH with it as the privilege separation directory.
		if [ "$FAMILY" = debian ] && [ ! -e /run/sshd ] && [ -d /run ]; then
			mkdir -m 0755 /run/sshd 2>/dev/null
		fi
		sshd_run_t
		if [ "$SSHD_T_RC" -ne 0 ] && [ ! -e /run/sshd ] && [ -d /run ] &&
			t 30 sshd -T 2>&1 >/dev/null | grep -q '/run/sshd'; then
			mkdir -m 0755 /run/sshd 2>/dev/null && sshd_run_t
		fi
		if [ "$SSHD_T_RC" -ne 0 ]; then
			SSHD_T_ERR=$(t 30 sshd -T 2>&1 >/dev/null | head -n 2 | tr '\n' ' ')
			[ -n "$SSHD_T_ERR" ] || SSHD_T_ERR="exit status $SSHD_T_RC"
		fi
	fi
	[ "$SSHD_T_RC" -eq 0 ]
}
# sshd_val KEY: the first value of KEY (in lower case) in sshd -T's output.
sshd_val() { printf '%s\n' "$SSHD_T" | sed -n "s/^$1 //p" | head -n 1; }
# sshd_vals KEY: every value of KEY, one a line.
sshd_vals() { printf '%s\n' "$SSHD_T" | sed -n "s/^$1 //p"; }
# sshd_ports: the TCP ports sshd listens on, one a line.
sshd_ports() {
	{
		sshd_vals port
		# ListenAddress host:port, [v6]:port or a bare address (Port applies).
		sshd_vals listenaddress | sed -n -e 's/^\[.*\]:\([0-9][0-9]*\)$/\1/p' -e 's/^[^:]*:\([0-9][0-9]*\)$/\1/p'
	} | grep -x '[0-9][0-9]*' | sort -nu
}

# ---------------------------------------------------------------------------
# One module's result while it is checked, then kept per module.

begin_module() {
	CUR=$1
	M_STATE=
	M_REASON=
	M_MISSING=
	M_CHANGES=
	M_OK=0
	M_BAD=0
	M_TCP=
	M_UDP=
	M_DOCKER=
	M_UNKNOWN=
	M_NOTE=
	# What apply would do, as each check found it (read by the module's
	# apply).
	M_TODO=
}

# keep NAME VALUE and kept NAME: set and read a variable whose name is made
# up (NAME is always letters, digits and underscores from this script).
keep() { eval "$1=\$2"; }
kept() { eval "printf '%s' \"\${$1-}\""; }

# append LISTVAR ITEM: adds ITEM to a newline-separated list, as one line.
append() {
	ap_i=$2
	case $ap_i in *"$nl"* | *"$(printf '\r')"*) ap_i=$(printf '%s' "$ap_i" | tr '\n\r' '  ') ;; esac
	[ -n "$ap_i" ] || return 0
	eval "ap_l=\$$1"
	if [ -n "$ap_l" ]; then eval "$1=\$ap_l\$nl\$ap_i"; else eval "$1=\$ap_i"; fi
}
# A setting that is in effect.
in_place() { M_OK=$((M_OK + 1)); }
# A setting that is not in effect: what it should be, and what it is now.
missing() {
	M_BAD=$((M_BAD + 1))
	append M_MISSING "$1"
}
# What apply would change, or (starting "Left as it is" or "Refused") what it
# would not, and why.
change() { append M_CHANGES "$1"; }
# What apply is to do, in the module's own terms (see each apply_ function).
todo() { append M_TODO "$1"; }
reason() { M_REASON=$(printf '%s' "$1" | tr '\n\r' '  '); }
not_applicable() {
	M_STATE=not_applicable
	reason "$1"
}
failed() {
	M_STATE=failed
	reason "$1"
}

# settle_state: the module's state from what its check found.
settle_state() {
	if [ -z "$M_STATE" ]; then
		if [ "$M_BAD" -eq 0 ]; then
			M_STATE=in_place
		elif [ "$M_OK" -eq 0 ]; then
			M_STATE=not_in_place
		else
			M_STATE=partly
		fi
	fi
	if [ -z "$M_REASON" ]; then
		case $M_STATE in
		in_place) reason 'Everything this module checks is in place.' ;;
		partly) reason "$M_OK of $((M_OK + M_BAD)) settings are in place; the others are listed as missing." ;;
		not_in_place) reason 'None of the settings this module checks is in place.' ;;
		esac
	fi
	# Something the module could not check, said after its state (ssh's
	# Match blocks).
	[ -z "$M_NOTE" ] || reason "${M_REASON%.};$M_NOTE"
	# An apply or undo of this module that was interrupted (see the record).
	if [ -e "$STATE_DIR/modules/$CUR/intent" ] && [ ! -e "$STATE_DIR/modules/$CUR/done" ]; then
		M_STATE=half_applied
		reason 'An apply or undo of this module was interrupted before it finished; undo reverses what it recorded.'
	fi
}

finish_module() {
	settle_state
	# Kept as S_ssh, MI_kernel_modules and so on until the result is written.
	fm_v=$(printf '%s' "$CUR" | tr '-' '_')
	keep "S_$fm_v" "$M_STATE"
	keep "R_$fm_v" "$M_REASON"
	keep "MI_$fm_v" "$M_MISSING"
	keep "CH_$fm_v" "$M_CHANGES"
	keep "PT_$fm_v" "$M_TCP"
	keep "PU_$fm_v" "$M_UDP"
	keep "PD_$fm_v" "$M_DOCKER"
	keep "PK_$fm_v" "$M_UNKNOWN"
	fm_rec=no
	[ ! -s "$STATE_DIR/modules/$CUR/manifest" ] || fm_rec=yes
	keep "RC_$fm_v" "$fm_rec"
	say "$CUR: $M_STATE. $M_REASON"
}

# ---------------------------------------------------------------------------
# ssh

# Weak algorithms, removed where the system has no crypto policy of its own:
# ciphers, key exchanges and MACs. hmac-sha1 stays:
# it is not broken as a MAC and old clients still need it.
WEAK_CIPHERS='-cbc($|@)|^arcfour'
WEAK_KEX='sha1'
WEAK_MACS='^hmac-md5|^hmac-ripemd160|^hmac-sha1-96|^umac-64'

# ssh_algorithms KEY NAME WEAK: one algorithm list in sshd -T, without the
# entries the extended regular expression WEAK matches.
ssh_algorithms() {
	sa_now=$(sshd_val "$1")
	sa_weak=$(printf '%s\n' "$sa_now" | tr ',' '\n' | grep -E -- "$3" | tr '\n' ' ')
	sa_weak=${sa_weak% }
	if [ -z "$sa_weak" ]; then
		in_place
	else
		missing "$2 without weak algorithms (now also $sa_weak)"
		change "$2: remove $sa_weak"
		todo "$2 $(printf '%s\n' "$sa_now" | tr ',' '\n' | grep -Ev -- "$3" | tr '\n' ',' | sed 's/,$//')"
	fi
}

# root_password_used: whether root signed in to SSH with a password in the
# last 30 days, from the journal and auth.log or secure. Returns 0 yes, 1 no,
# 2 when there was nothing to read.
root_password_used() {
	rp_read=no
	rp_pattern='Accepted (password|keyboard-interactive/pam) for root '
	if have journalctl; then
		rp_out=$(t 120 journalctl -q --no-pager -o cat --since=-30d SYSLOG_IDENTIFIER=sshd SYSLOG_IDENTIFIER=sshd-session 2>/dev/null)
		rp_rc=$?
		if [ "$rp_rc" -eq 0 ]; then
			rp_read=yes
			text_has "$rp_out" -E "$rp_pattern" && return 0
		fi
	fi
	# Log files written in the last 30 days. They may also hold older lines,
	# which only makes the answer err towards leaving root's sign-in alone.
	for rp_f in /var/log/auth.log /var/log/auth.log.* /var/log/secure /var/log/secure-* /var/log/secure.*; do
		[ -f "$rp_f" ] || continue
		[ -n "$(find "$rp_f" -mtime -31 2>/dev/null)" ] || continue
		rp_read=yes
		case $rp_f in
		*.gz) gzip -dc "$rp_f" 2>/dev/null | grep -Eq "$rp_pattern" && return 0 ;;
		*) grep -Eq "$rp_pattern" "$rp_f" 2>/dev/null && return 0 ;;
		esac
	done
	[ "$rp_read" = yes ] && return 1
	return 2
}

# user_may_sign_in USER: whether sshd's AllowUsers, DenyUsers, AllowGroups and
# DenyGroups let USER in (from some address: user@host patterns count).
user_may_sign_in() {
	um_u=$1
	um_groups=" $(id -Gn "$um_u" 2>/dev/null) "
	for um_p in $(sshd_vals denyusers); do
		# shellcheck disable=SC2254 # sshd's patterns are shell-style patterns
		case $um_u in ${um_p%%@*}) return 1 ;; esac
	done
	for um_p in $(sshd_vals denygroups); do
		for um_g in $um_groups; do
			# shellcheck disable=SC2254
			case $um_g in $um_p) return 1 ;; esac
		done
	done
	um_allow=$(sshd_vals allowusers)
	if [ -n "$um_allow" ]; then
		um_ok=no
		for um_p in $um_allow; do
			# shellcheck disable=SC2254
			case $um_u in ${um_p%%@*}) um_ok=yes ;; esac
		done
		[ "$um_ok" = yes ] || return 1
	fi
	um_allow=$(sshd_vals allowgroups)
	if [ -n "$um_allow" ]; then
		for um_p in $um_allow; do
			for um_g in $um_groups; do
				# shellcheck disable=SC2254
				case $um_g in $um_p) return 0 ;; esac
			done
		done
		return 1
	fi
	return 0
}

# expand_tokens PATTERN HOME USER UID: AuthorizedKeysFile's %h, %u, %U and %%.
expand_tokens() {
	et_in=$1
	et_out=
	while [ -n "$et_in" ]; do
		case $et_in in
		%h*) et_out=$et_out$2 et_in=${et_in#%h} ;;
		%u*) et_out=$et_out$3 et_in=${et_in#%u} ;;
		%U*) et_out=$et_out$4 et_in=${et_in#%U} ;;
		%%*) et_out=$et_out% et_in=${et_in#%%} ;;
		*)
			et_c=${et_in%"${et_in#?}"}
			et_out=$et_out$et_c
			et_in=${et_in#?}
			;;
		esac
	done
	case $et_out in /*) ;; *) et_out=$2/$et_out ;; esac
	printf '%s' "$et_out"
}

# key_sign_in_possible: whether sshd has an AuthorizedKeysCommand, or some
# local account that may sign in (a login shell, allowed by sshd; root only if
# PermitRootLogin would let it in with a key) has a key in its authorized keys
# file. ADR-0051 refuses password-off otherwise.
key_sign_in_possible() {
	# sshd's patterns and file names are words here, never globs.
	set -f
	key_sign_in_possible_ "$1"
	kp_rc=$?
	set +f
	return "$kp_rc"
}
key_sign_in_possible_() {
	case $(sshd_val authorizedkeyscommand) in '' | none) ;; *) return 0 ;; esac
	kp_files=$(sshd_val authorizedkeysfile)
	[ -n "$kp_files" ] && [ "$kp_files" != none ] || return 1
	kp_root=$1
	while IFS=: read -r kp_u _ kp_uid _ _ kp_home kp_shell; do
		case $kp_shell in */nologin | */false | */sync | */shutdown | */halt) continue ;; esac
		[ -n "$kp_home" ] || continue
		if [ "$kp_uid" = 0 ] && [ "$kp_root" = no ]; then continue; fi
		user_may_sign_in "$kp_u" || continue
		for kp_p in $kp_files; do
			kp_f=$(expand_tokens "$kp_p" "$kp_home" "$kp_u" "$kp_uid")
			# A key is a line that is neither empty nor a comment; the time
			# limit is for home directories on a network that does not answer.
			t 10 grep -Eq '^[[:space:]]*[^#[:space:]]' "$kp_f" 2>/dev/null && return 0
		done
	done </etc/passwd
	return 1
}

# Match blocks in the main file and every file it includes, as
# "Match User x (file)", one a line.
ssh_match_blocks() {
	smb_files=/etc/ssh/sshd_config
	smb_inc=$(sed -n 's/^[[:space:]]*[Ii][Nn][Cc][Ll][Uu][Dd][Ee][[:space:]][[:space:]]*//p' /etc/ssh/sshd_config 2>/dev/null)
	# Each pattern is made absolute (relative ones are under /etc/ssh)
	# before it is expanded.
	set -f
	for smb_p in $smb_inc; do
		case $smb_p in /*) ;; *) smb_p=/etc/ssh/$smb_p ;; esac
		set +f
		for smb_f in $smb_p; do
			[ -f "$smb_f" ] && smb_files="$smb_files $smb_f"
		done
		set -f
	done
	set +f
	for smb_f in $smb_files; do
		sed -n 's/^[[:space:]]*\([Mm][Aa][Tt][Cc][Hh][[:space:]].*\)$/\1/p' "$smb_f" 2>/dev/null |
			sed -e 's/[[:space:]]*$//' -e "s|\$| ($smb_f)|"
	done
}

check_ssh() {
	if ! have sshd; then
		not_applicable 'No SSH server is installed.'
		return
	fi
	if ! sshd_effective; then
		failed "sshd -T, which shows the settings in effect, failed: $SSHD_T_ERR"
		return
	fi
	cs_changes=no

	# PermitRootLogin prohibit-password. Benchmarks ask for no, which
	# ADR-0051 leaves to the administrator: keys stay usable for root.
	cs_prl=$(sshd_val permitrootlogin)
	cs_root_after=$cs_prl
	case $cs_prl in
	prohibit-password | without-password | forced-commands-only | no) in_place ;;
	*)
		missing "PermitRootLogin prohibit-password (now $cs_prl)"
		root_password_used
		cs_rp=$?
		if [ "$cs_rp" -eq 1 ] || [ "$OPT_ROOT_PASSWORD_OFF" = yes ]; then
			change 'PermitRootLogin prohibit-password'
			todo 'PermitRootLogin prohibit-password'
			cs_changes=yes
			cs_root_after=prohibit-password
		elif [ "$cs_rp" -eq 0 ]; then
			change "Left as it is: PermitRootLogin $cs_prl, because root signed in with a password in the last 30 days (the root-password-off option changes it anyway)"
		else
			change "Left as it is: PermitRootLogin $cs_prl, because no sign-in log could be read to tell whether root signs in with a password (the root-password-off option changes it anyway)"
		fi
		;;
	esac

	# PermitEmptyPasswords no.
	cs_v=$(sshd_val permitemptypasswords)
	if [ "$cs_v" = no ]; then in_place; else
		missing "PermitEmptyPasswords no (now $cs_v)"
		change 'PermitEmptyPasswords no'
		todo 'PermitEmptyPasswords no'
		cs_changes=yes
	fi

	# LoginGraceTime 30 or less, never 0, which is no limit.
	cs_v=$(sshd_val logingracetime)
	case $cs_v in '' | *[!0-9]*) cs_n=0 ;; *) cs_n=$cs_v ;; esac
	if [ "$cs_n" -ge 1 ] && [ "$cs_n" -le 30 ]; then in_place; else
		missing "LoginGraceTime 30 (now $cs_v)"
		change 'LoginGraceTime 30'
		todo 'LoginGraceTime 30'
		cs_changes=yes
	fi

	# X11Forwarding no.
	cs_v=$(sshd_val x11forwarding)
	if [ "$cs_v" = no ]; then in_place; else
		missing "X11Forwarding no (now $cs_v)"
		change 'X11Forwarding no'
		todo 'X11Forwarding no'
		cs_changes=yes
	fi

	# Dead connections closed: ClientAliveInterval 300 and ClientAliveCountMax
	# 3, or shorter; 0 turns either off.
	cs_v=$(sshd_val clientaliveinterval)
	case $cs_v in '' | *[!0-9]*) cs_n=0 ;; *) cs_n=$cs_v ;; esac
	if [ "$cs_n" -ge 1 ] && [ "$cs_n" -le 300 ]; then in_place; else
		missing "ClientAliveInterval 300 (now $cs_v)"
		change 'ClientAliveInterval 300'
		todo 'ClientAliveInterval 300'
		cs_changes=yes
	fi
	cs_v=$(sshd_val clientalivecountmax)
	case $cs_v in '' | *[!0-9]*) cs_n=0 ;; *) cs_n=$cs_v ;; esac
	if [ "$cs_n" -ge 1 ] && [ "$cs_n" -le 3 ]; then in_place; else
		missing "ClientAliveCountMax 3 (now $cs_v)"
		change 'ClientAliveCountMax 3'
		todo 'ClientAliveCountMax 3'
		cs_changes=yes
	fi

	# MaxAuthTries is left at sshd's 6 on purpose (ADR-0051): every key in a
	# technician's agent is a try, and fewer would get the MSP's office banned.

	# Ciphers, key exchanges and MACs. On RHEL and Fedora the system's crypto
	# policy sets them, and sshd -T shows sshd's built-in defaults there.
	cs_policy=
	if [ "$FAMILY" = rhel ] || [ "$FAMILY" = fedora ]; then
		have update-crypto-policies && cs_policy=$(t 20 update-crypto-policies --show 2>/dev/null | head -n 1)
	fi
	if [ -n "$cs_policy" ]; then
		case ":$cs_policy:" in
		:LEGACY:* | *:SHA1:*)
			missing "A crypto policy without weak ciphers, key exchanges and MACs (now $cs_policy)"
			change "Left as it is: the system's crypto policy $cs_policy, which sets SSH's algorithms here; change it with update-crypto-policies"
			;;
		*) in_place ;;
		esac
	else
		cs_before=$M_BAD
		ssh_algorithms ciphers Ciphers "$WEAK_CIPHERS"
		ssh_algorithms kexalgorithms KexAlgorithms "$WEAK_KEX"
		ssh_algorithms macs MACs "$WEAK_MACS"
		[ "$M_BAD" -eq "$cs_before" ] || cs_changes=yes
	fi

	# Password sign-in off, only with the password-off option. Keyboard-
	# interactive goes too, or passwords still work through PAM.
	if [ "$OPT_PASSWORD_OFF" = yes ]; then
		cs_kbd=kbdinteractiveauthentication
		cs_kbd_name=KbdInteractiveAuthentication
		if [ -z "$(sshd_val $cs_kbd)" ]; then
			cs_kbd=challengeresponseauthentication
			cs_kbd_name=ChallengeResponseAuthentication
		fi
		cs_pw=$(sshd_val passwordauthentication)
		cs_kv=$(sshd_val $cs_kbd)
		cs_pw_missing=no
		if [ "$cs_pw" = no ]; then in_place; else
			missing "PasswordAuthentication no (now $cs_pw)"
			cs_pw_missing=yes
		fi
		if [ "$cs_kv" = no ]; then in_place; else
			missing "$cs_kbd_name no (now $cs_kv)"
			cs_pw_missing=yes
		fi
		if [ "$cs_pw_missing" = yes ]; then
			case $cs_root_after in prohibit-password | without-password | yes) cs_root_key=yes ;; *) cs_root_key=no ;; esac
			if key_sign_in_possible "$cs_root_key"; then
				change 'PasswordAuthentication no'
				change "$cs_kbd_name no"
				todo 'PasswordAuthentication no'
				todo "$cs_kbd_name no"
				cs_changes=yes
			else
				change 'Refused: password sign-in stays on, because no account that may sign in has a key in its authorized keys file and sshd has no AuthorizedKeysCommand'
			fi
		fi
	fi

	# Where apply would write: a drop-in that sorts before the distribution's
	# own (sshd keeps the first value it reads). Without an Include of it
	# before the first Match block (RHEL 8), one line at the very top.
	if [ "$cs_changes" = yes ]; then
		cs_covered=no
		cs_inc=$(awk 'tolower($1) == "match" { exit } tolower($1) == "include" { for (i = 2; i <= NF; i++) print $i }' /etc/ssh/sshd_config 2>/dev/null)
		# The patterns are matched against the drop-in's name, not expanded.
		set -f
		for cs_p in $cs_inc; do
			case $cs_p in /*) ;; *) cs_p=/etc/ssh/$cs_p ;; esac
			# shellcheck disable=SC2254 # Include takes a glob
			case $SSH_DROPIN in $cs_p) cs_covered=yes ;; esac
		done
		set +f
		change "The settings go in $SSH_DROPIN; the configuration is tested with sshd -t and sshd reloaded only if it is running"
		if [ "$cs_covered" = no ]; then
			change "Add 'Include $SSH_DROPIN' at the top of /etc/ssh/sshd_config, which includes no drop-ins before its first Match block"
			todo include
		fi
	fi

	cs_match=$(ssh_match_blocks | tr '\n' ';' | sed -e 's/;$//' -e 's/;/, /g')
	[ -z "$cs_match" ] || M_NOTE=" Match blocks are not checked, as sshd -T does not show what they change: $cs_match."
}

# ---------------------------------------------------------------------------
# firewall

# Whether the kernel's nftables is loaded or built in. When it is neither,
# no nftables ruleset exists, and running nft would load it.
nf_tables_present() {
	[ -d /sys/module/nf_tables ] && return 0
	grep -qs '/nf_tables\.ko' "/lib/modules/$(uname -r)/modules.builtin"
}

# nft_input_drops: chains on nftables' input hook, other than EasyRMM's own
# table, whose policy drops or whose last rule drops or rejects everything.
nft_input_drops() {
	printf '%s\n' "$1" | awk '
	function verdict(r) {
		sub(/^counter( packets [0-9]+ bytes [0-9]+)? */, "", r)
		sub(/ *# handle [0-9]+$/, "", r)
		return (r ~ /^(log( [^;]*)? )?(drop|reject)( .*)?$/)
	}
	{
		line = $0
		sub(/^[ \t]+/, "", line)
		if (line ~ /^#/) next
		if (depth == 0 && line ~ /^table /) { split(line, a, " "); fam = a[2]; tab = a[3] }
		if (depth == 1 && line ~ /^chain /) { split(line, a, " "); chain = a[2]; inchain = 1; hook = 0; pol = ""; last = "" }
		else if (inchain && depth == 2 && line != "}") {
			if (line ~ /hook input /) hook = 1
			if (line ~ /^type /) { if (line ~ /policy drop;/) pol = "drop" }
			else if (line != "") last = line
		}
		o = gsub(/\{/, "{", line); c = gsub(/\}/, "}", line); depth += o - c
		if (inchain && depth < 2) {
			if (hook && !(fam == "inet" && tab == "easyrmm")) {
				if (pol == "drop") print "nftables " fam " " tab " chain " chain " drops by policy"
				else if (verdict(last)) print "nftables " fam " " tab " chain " chain " ends in " last
			}
			inchain = 0
		}
	}'
}

# xt_input_drops SAVE-OUTPUT LABEL: the same for iptables-save's output.
xt_input_drops() {
	printf '%s\n' "$1" | awk -v label="$2" '
	/^:INPUT (DROP|REJECT) / { print label " INPUT drops by policy" }
	/^-A INPUT / { last = $0 }
	END { if (last ~ /^-A INPUT -j (DROP|REJECT)( |$)/) print label " INPUT ends in " substr(last, 4) }'
}

# fw_rulesets: other firewalls' rulesets that drop on input, one a line, or
# the line "unreadable" when nftables has rules that cannot be read.
fw_rulesets() {
	if nf_tables_present; then
		if have nft; then
			fr_out=$(t 30 nft list ruleset 2>/dev/null) || {
				echo unreadable
				return 0
			}
			nft_input_drops "$fr_out"
		else
			fr_read=no
			for fr_save in iptables-nft-save ip6tables-nft-save; do
				have "$fr_save" || continue
				fr_read=yes
				xt_input_drops "$(t 30 "$fr_save" -t filter 2>/dev/null)" "$fr_save"
			done
			[ "$fr_read" = yes ] || echo unreadable
		fi
	fi
	# Legacy iptables (Ubuntu 20.04's default), which nft cannot see. Only
	# where its filter table is loaded already: reading it never loads it.
	for fr_fam in ip ip6; do
		grep -qsx filter "/proc/net/${fr_fam}_tables_names" || continue
		fr_tool=${fr_fam}tables
		if have "$fr_tool-legacy-save"; then
			fr_save=$fr_tool-legacy-save
		elif have "$fr_tool-save" && ! "$fr_tool-save" --version 2>/dev/null | grep -q nf_tables; then
			fr_save=$fr_tool-save
		else
			continue
		fi
		xt_input_drops "$(t 30 "$fr_save" -t filter 2>/dev/null)" "$fr_tool (legacy)"
	done
}

# fw_elsewhere: why another program manages this computer's firewall, one
# reason a line, or nothing.
fw_elsewhere() {
	if grep -Eqs '^[[:space:]]*ENABLED[[:space:]]*=[[:space:]]*yes' /etc/ufw/ufw.conf; then
		echo 'ufw is turned on'
	fi
	svc_on firewalld.service && echo 'firewalld is on'
	fe_rules=$(fw_rulesets)
	printf '%s\n' "$fe_rules" | grep -v '^unreadable$' | sed -n 's/^\(..*\)$/another ruleset drops what it does not allow: \1/p'
	{ [ -d /etc/csf ] || have csf; } && echo 'CSF (ConfigServer Security & Firewall) is installed'
	svc_on crowdsec-firewall-bouncer.service && echo "CrowdSec's firewall bouncer is on"
	{ have pve-firewall || unit_exists pve-firewall.service; } && echo 'this is a Proxmox VE host (pve-firewall)'
	is_k8s_node && echo 'this is a Kubernetes node'
	svc_on keepalived.service keepalived && echo 'keepalived runs here'
	svc_on nfs-server.service nfs-kernel-server.service nfsd && echo 'this is an NFS server'
	svc_on vsftpd.service proftpd.service pure-ftpd.service vsftpd proftpd pure-ftpd && echo 'an FTP server runs here (its passive ports move)'
	svc_on asterisk.service freeswitch.service kamailio.service opensips.service asterisk freeswitch kamailio opensips &&
		echo 'a SIP server runs here (its media ports move)'
	text_has "$fe_rules" '^unreadable$' && echo 'UNREADABLE'
	return 0
}

# listening: "tcp PORT" and "udp PORT" for every socket listening outside
# loopback, from the kernel's socket tables (what ss -lntu shows). ISC
# dhclient binds an unused UDP socket to a random port besides 68, another
# one at each start: a client's, which nothing reaches, so it is left out.
listening() {
	li_dhcp=$(dhclient_sockets)
	for li_f in tcp tcp6 udp udp6; do
		[ -r "/proc/net/$li_f" ] || continue
		case $li_f in tcp*) li_state=0A ;; *) li_state=07 ;; esac
		awk -v proto="${li_f%6}" -v want="$li_state" -v dhcp=" $li_dhcp " '
		function hex(h,  i, n) { n = 0; h = toupper(h); for (i = 1; i <= length(h); i++) n = n * 16 + index("0123456789ABCDEF", substr(h, i, 1)) - 1; return n }
		NR > 1 && $4 == want {
			split($2, a, ":"); addr = toupper(a[1])
			if (length(addr) == 8 && substr(addr, 7, 2) == "7F") next
			if (addr == "00000000000000000000000001000000") next
			if (length(addr) == 32 && substr(addr, 1, 24) == "0000000000000000FFFF0000" && substr(addr, 31, 2) == "7F") next
			port = hex(a[2])
			if (proto == "udp" && port != 68 && index(dhcp, " " $10 " ")) next
			print proto, port
		}' "/proc/net/$li_f"
	done | sort -u
}
# dhclient_sockets: the inodes of the sockets dhclient holds, separated by
# spaces.
dhclient_sockets() {
	for ds_d in /proc/[0-9]*; do
		[ "$(cat "$ds_d/comm" 2>/dev/null)" = dhclient ] || continue
		for ds_fd in "$ds_d"/fd/*; do
			readlink "$ds_fd" 2>/dev/null
		done | sed -n 's/^socket:\[\([0-9]*\)\]$/\1/p'
	done | tr '\n' ' '
}

# docker_published: "tcp/8443" for each port Docker publishes outside
# loopback (with its userland proxy off, nothing listens on them).
DOCKER_UNREAD=no
docker_published() {
	have docker || return 0
	[ -S /run/docker.sock ] || [ -S /var/run/docker.sock ] || return 0
	dp_out=$(t 20 docker ps --format '{{.Ports}}' 2>/dev/null) || {
		proc_running dockerd && DOCKER_UNREAD=yes
		return 0
	}
	printf '%s\n' "$dp_out" | tr ',' '\n' | sed -n 's/^ *\(.*\):\([0-9][0-9-]*\)->[0-9-]*\/\([a-z]*\)$/\1 \2 \3/p' |
		while read -r dp_host dp_port dp_proto; do
			case $dp_host in 127.* | '[::1]' | ::1) continue ;; esac
			printf '%s/%s\n' "$dp_proto" "$dp_port"
		done | sort -u
}

# unknown_units: services that start at boot but are not running now, whose
# ports cannot be known until they start. Oneshot jobs, services started by
# a socket, timer or path, and services whose conditions keep them off here
# are left out.
unknown_units() {
	[ "$SYSTEMD_UP" = yes ] || return 0
	uu_list=$(t 30 systemctl list-unit-files --type=service --state=enabled --no-legend --no-pager 2>/dev/null |
		awk '$1 !~ /@\.service$/ { print $1 }')
	[ -n "$uu_list" ] || return 0
	# shellcheck disable=SC2086 # unit names, one word each
	t 60 systemctl show -p Id -p Type -p ActiveState -p ConditionResult -p TriggeredBy --no-pager $uu_list 2>/dev/null | awk '
	function flush() {
		if (id != "" && type != "oneshot" && trig == "" && cond != "no" && act != "active" && act != "reloading" && act != "activating") print id
		id = type = act = cond = trig = ""
	}
	/^$/ { flush(); next }
	{ k = substr($0, 1, index($0, "=") - 1); v = substr($0, index($0, "=") + 1) }
	k == "Id" { id = v }
	k == "Type" { type = v }
	k == "ActiveState" { act = v }
	k == "ConditionResult" { cond = v }
	k == "TriggeredBy" { trig = v }
	END { flush() }' | sort -u
}

# port_list PROTO SOURCES: the ports apply would leave open for PROTO, sorted.
# SOURCES has lines "L proto port" (listening), "S proto port" (sshd),
# "A proto port-or-range" (the operator's) and "D proto port-or-range"
# (published by Docker, which does not go through the input hook). Listening
# ports Docker publishes are listed under Docker, not here.
port_list() {
	printf '%s\n' "$2" | awk -v proto="$1" '
	$2 != proto { next }
	$1 == "D" { n = split($3, r, "-"); lo[++d] = r[1]; hi[d] = (n > 1) ? r[2] : r[1]; next }
	{ src[++k] = $1; port[k] = $3 }
	END {
		for (i = 1; i <= k; i++) {
			if (src[i] == "L") {
				skip = 0
				for (j = 1; j <= d; j++) if (port[i] + 0 >= lo[j] + 0 && port[i] + 0 <= hi[j] + 0) skip = 1
				if (skip) continue
			}
			print port[i]
		}
	}' | sort -t- -k1,1n -k2,2n -u
}

# fw_table_ports TABLE PROTO: the ports and ranges EasyRMM's table (as nft -n
# lists it) lets PROTO through to, one a line ("22", "9000-9100").
fw_table_ports() {
	printf '%s\n' "$1" | awk -v proto="$2" '
	$1 == proto && $2 == "dport" {
		s = $0; sub(/^.*dport[ \t]*/, "", s); sub(/[ \t]*accept[ \t]*$/, "", s)
		gsub(/[{},]/, " ", s); n = split(s, p, " ")
		for (i = 1; i <= n; i++) if (p[i] ~ /^[0-9]+(-[0-9]+)?$/) print p[i]
	}'
}

# fw_table_allows TABLE PROTO PORT-OR-RANGE: whether the table lets all of it
# through.
fw_table_allows() {
	fw_table_ports "$1" "$2" | awk -v want="$3" '
	BEGIN { n = split(want, w, "-"); lo = w[1] + 0; hi = (n > 1) ? w[2] + 0 : lo }
	{ n = split($0, r, "-"); a = r[1] + 0; b = (n > 1) ? r[2] + 0 : a; if (lo >= a && hi <= b) f = 1 }
	END { exit !f }'
}

check_firewall() {
	cf_else=$(fw_elsewhere)
	cf_unreadable=no
	if text_has "$cf_else" '^UNREADABLE$'; then
		cf_unreadable=yes
		cf_else=$(printf '%s\n' "$cf_else" | grep -v '^UNREADABLE$')
	fi
	if [ -n "$cf_else" ]; then
		M_STATE=managed_elsewhere
		reason "EasyRMM leaves this computer's firewall alone: $(printf '%s\n' "$cf_else" | tr '\n' ';' | sed -e 's/;$//' -e 's/;/; /g')."
		return
	fi

	# The ports apply would leave open. If sshd is installed and its ports
	# cannot be read, apply refuses.
	cf_src=
	if have sshd; then
		if ! sshd_effective; then
			failed "sshd is installed but sshd -T failed, so the ports it listens on are unknown and apply would refuse: $SSHD_T_ERR"
			return
		fi
		cf_src=$(sshd_ports | sed 's/^/S tcp /')
	fi
	cf_src="$cf_src$nl$(listening | sed 's/^/L /')"
	cf_docker=$(docker_published)
	cf_src="$cf_src$nl$(printf '%s\n' "$cf_docker" | sed -n 's/^\([a-z]*\)\/\(.*\)$/D \1 \2/p')"
	for cf_p in $(printf '%s' "$OPT_ALLOW_TCP" | tr ',' ' '); do cf_src="$cf_src${nl}A tcp $cf_p"; done
	for cf_p in $(printf '%s' "$OPT_ALLOW_UDP" | tr ',' ' '); do cf_src="$cf_src${nl}A udp $cf_p"; done
	M_TCP=$(port_list tcp "$cf_src")
	M_UDP=$(port_list udp "$cf_src")
	M_DOCKER=$cf_docker
	M_UNKNOWN=$(unknown_units)
	cf_n=$(printf '%s' "$M_TCP" | grep -c .)
	[ "$cf_n" -le 50 ] || change "$cf_n TCP ports would stay open; the first 50 are listed"
	cf_n=$(printf '%s' "$M_UDP" | grep -c .)
	[ "$cf_n" -le 50 ] || change "$cf_n UDP ports would stay open; the first 50 are listed"

	# EasyRMM's own table, its file and the unit that loads it at boot.
	cf_nft=no
	have nft && cf_nft=yes
	if [ "$cf_nft" = yes ] && nf_tables_present && cf_table=$(t 30 nft -n list table inet easyrmm 2>/dev/null); then
		in_place
		# Every port apply would leave open must be open in the table: a
		# service that started listening since is cut off until it is.
		for cf_pr in tcp udp; do
			if [ "$cf_pr" = tcp ]; then cf_want=$M_TCP; else cf_want=$M_UDP; fi
			for cf_p in $cf_want; do
				if fw_table_allows "$cf_table" "$cf_pr" "$cf_p"; then in_place; else
					missing "$cf_pr port $cf_p open in table inet easyrmm (it is dropped now)"
				fi
			done
		done
	else
		missing 'nftables table inet easyrmm loaded'
	fi
	if [ -f "$FW_FILE" ]; then in_place; else missing "$FW_FILE"; fi
	if unit_enabled "$FW_UNIT"; then in_place; else missing "$FW_UNIT enabled"; fi

	if [ "$M_BAD" -gt 0 ]; then
		[ "$cf_nft" = yes ] || change 'Install nftables'
		change 'Load nftables table inet easyrmm on the input hook only: new TCP connections and UDP packets to ports not listed are dropped; established traffic, loopback, ICMP and other protocols pass, and forwarded and outgoing traffic is not filtered'
		change "Keep it across restarts with $FW_UNIT, loading $FW_FILE (never flush ruleset; the distribution's nftables.service is left alone)"
		[ -z "$M_UNKNOWN" ] || change "Services that start at boot but are not running have ports EasyRMM cannot know; they would be cut off when they start: add their ports or start them first (listed as unknown)"
		[ -z "$M_DOCKER" ] || change "Ports Docker publishes stay open through Docker's own rules, not this table (listed under Docker)"
	fi
	[ "$DOCKER_UNREAD" = no ] || change 'Docker runs, but the ports it publishes could not be read'
	if [ "$cf_unreadable" = yes ]; then
		reason "The kernel's nftables is loaded, but nft is not here or could not read it, so whether another ruleset already drops what it does not allow is unknown; apply reads it before loading anything."
	fi
}

# ---------------------------------------------------------------------------
# fail2ban

# epel_enabled: whether a repository called epel is configured and on.
epel_enabled() {
	for ee_f in /etc/yum.repos.d/*.repo; do
		[ -f "$ee_f" ] || continue
		ee_section=$(sed -n '/^\[epel\][[:space:]]*$/,/^\[/p' "$ee_f")
		[ -n "$ee_section" ] || continue
		text_has "$ee_section" -Ei '^[[:space:]]*enabled[[:space:]]*=[[:space:]]*(0|false|no)[[:space:]]*$' || return 0
	done
	return 1
}

# canon_net ADDRESS[/PREFIX]: the form fail2ban prints: host bits cleared, no
# prefix on a single address, IPv6 in lower case with the longest run of zero
# groups shortened.
canon_net() {
	printf '%s\n' "$1" | awk '
	function hex(h,  i, n) { n = 0; h = tolower(h); for (i = 1; i <= length(h); i++) n = n * 16 + index("0123456789abcdef", substr(h, i, 1)) - 1; return n }
	function mask(v, bits, width,  keep) { if (bits >= width) return v; if (bits <= 0) return 0; keep = 2 ^ width - 2 ^ (width - bits); return and_(v, keep, width) }
	function and_(a, b, width,  r, i, p) { r = 0; p = 1; for (i = 0; i < width; i++) { if ((int(a / p) % 2) && (int(b / p) % 2)) r += p; p *= 2 }; return r }
	{
		n = split($0, parts, "/"); addr = parts[1]; plen = (n > 1) ? parts[2] + 0 : -1
		if (addr ~ /^[0-9.]+$/) {
			if (plen < 0) plen = 32
			split(addr, o, "."); out = ""
			for (i = 1; i <= 4; i++) { bits = plen - (i - 1) * 8; out = out (i > 1 ? "." : "") mask(o[i] + 0, bits, 8) }
			print (plen == 32) ? out : out "/" plen
			next
		}
		if (plen < 0) plen = 128
		# Expand to eight groups.
		nh = split(addr, h, "::")
		cl = (h[1] == "") ? 0 : split(h[1], left, ":")
		cr = (nh < 2 || h[2] == "") ? 0 : split(h[2], right, ":")
		for (i = 1; i <= 8; i++) g[i] = 0
		for (i = 1; i <= cl; i++) g[i] = hex(left[i])
		for (i = 1; i <= cr; i++) g[8 - cr + i] = hex(right[i])
		for (i = 1; i <= 8; i++) g[i] = mask(g[i], plen - (i - 1) * 16, 16)
		# The longest run of two or more zero groups becomes "::".
		bs = 0; bl = 0; s = 0; l = 0
		for (i = 1; i <= 8; i++) {
			if (g[i] == 0) { if (l == 0) s = i; l++; if (l > bl) { bl = l; bs = s } } else l = 0
		}
		out = ""
		for (i = 1; i <= 8; i++) {
			if (bl >= 2 && i == bs) { out = out "::"; i += bl - 1; continue }
			if (out != "" && out !~ /::$/) out = out ":"
			out = out sprintf("%x", g[i])
		}
		print (plen == 128) ? out : out "/" plen
	}'
}

# The firewall fail2ban would ban with: the one in use.
f2b_banaction() {
	if grep -Eqs '^[[:space:]]*ENABLED[[:space:]]*=[[:space:]]*yes' /etc/ufw/ufw.conf; then
		printf 'ufw'
	elif unit_active firewalld.service; then
		printf 'firewalld'
	elif nf_tables_present || ! grep -qsx filter /proc/net/ip_tables_names; then
		printf "nftables (EasyRMM's table, or nftables of its own)"
	else
		printf 'legacy iptables'
	fi
}

f2b_changes() {
	fc_trusted='127.0.0.1/8, ::1'
	[ -z "$OPT_TRUSTED" ] || fc_trusted="$fc_trusted, $(printf '%s' "$OPT_TRUSTED" | sed 's/,/, /g')"
	change 'Jail sshd: 5 failures in 10 minutes bans the address for an hour, longer for repeat offenders, up to a day'
	change "Never banned: $fc_trusted"
	if [ ! -e /var/log/auth.log ] && [ ! -e /var/log/secure ]; then
		change 'Read failed sign-ins from the journal (backend = systemd): there is no auth.log or secure file'
	fi
	change "Ban with $(f2b_banaction)"
}

# f2b_jail_actions: the running sshd jail's ban actions, one a line.
f2b_jail_actions() {
	t 20 fail2ban-client get sshd actions 2>/dev/null |
		grep -v -e '^No actions' -e 'has the following actions' | tr ',' '\n' | sed 's/^[[:space:]]*//; s/[[:space:]]*$//' | grep .
}

check_fail2ban() {
	if ! have sshd; then
		not_applicable 'No SSH server is installed, and the jail is for SSH.'
		return
	fi
	ck_installed=no
	have fail2ban-client && ck_installed=yes
	if [ "$ck_installed" = no ] && [ "$FAMILY" = rhel ] && [ "$OPT_EPEL" = no ] && ! epel_enabled; then
		not_applicable 'fail2ban comes only from EPEL on RHEL and its rebuilds, and adding a repository is the epel option.'
		return
	fi
	if [ "$ck_installed" = no ]; then
		missing 'fail2ban installed and running'
		missing 'An sshd jail'
		if [ "$FAMILY" = rhel ] && ! epel_enabled; then
			change 'Add the EPEL repository (epel-release); the patching engine then updates its packages too'
		fi
		change 'Refresh the package lists and install fail2ban'
		f2b_changes
		return
	fi

	ck_fix=no
	if unit_enabled fail2ban.service; then in_place; else
		missing 'fail2ban starts at boot'
		ck_fix=yes
	fi
	if ! t 20 fail2ban-client ping >/dev/null 2>&1; then
		missing 'fail2ban running'
		missing 'An sshd jail running'
		change 'Start fail2ban'
		f2b_changes
		return
	fi
	in_place
	if ! t 20 fail2ban-client status sshd >/dev/null 2>&1; then
		missing 'An sshd jail running'
		f2b_changes
		return
	fi
	in_place

	# Each value as strict as the jail's, or stricter.
	ck_v=$(t 20 fail2ban-client get sshd maxretry 2>/dev/null | tail -n 1)
	case $ck_v in '' | *[!0-9]*) ck_n=999 ;; *) ck_n=$ck_v ;; esac
	if [ "$ck_n" -le 5 ]; then in_place; else
		missing "sshd jail maxretry 5 (now $ck_v)"
		ck_fix=yes
	fi
	ck_v=$(t 20 fail2ban-client get sshd findtime 2>/dev/null | tail -n 1)
	case $ck_v in '' | *[!0-9]*) ck_n=0 ;; *) ck_n=$ck_v ;; esac
	if [ "$ck_n" -ge 600 ]; then in_place; else
		missing "sshd jail findtime 600 seconds (now $ck_v)"
		ck_fix=yes
	fi
	ck_v=$(t 20 fail2ban-client get sshd bantime 2>/dev/null | tail -n 1)
	case $ck_v in -[0-9]*) ck_n=999999999 ;; '' | *[!0-9]*) ck_n=0 ;; *) ck_n=$ck_v ;; esac
	if [ "$ck_n" -ge 3600 ]; then in_place; else
		missing "sshd jail bantime 3600 seconds (now $ck_v)"
		ck_fix=yes
	fi
	ck_v=$(t 20 fail2ban-client get sshd bantime.increment 2>/dev/null | tail -n 1)
	case $ck_v in
	True | true | 1) in_place ;;
	False | false | 0)
		missing 'Longer bans for repeat offenders (bantime.increment)'
		ck_fix=yes
		;;
	*) change 'Whether repeat offenders get longer bans could not be read from this fail2ban' ;;
	esac
	# A jail without a ban action lists its bans and blocks nothing.
	if [ -n "$(f2b_jail_actions)" ]; then in_place; else
		missing 'The sshd jail bans with an action (it has none)'
		ck_fix=yes
	fi
	# The trusted ranges, compared in the form fail2ban prints them.
	if [ -n "$OPT_TRUSTED" ]; then
		ck_ign=$(t 20 fail2ban-client get sshd ignoreip 2>/dev/null | sed -n 's/^[|`]- *//p')
		ck_ign_canon=
		for ck_i in $ck_ign; do ck_ign_canon="$ck_ign_canon $(canon_net "$ck_i")"; done
		for ck_t in $(printf '%s' "$OPT_TRUSTED" | tr ',' ' '); do
			if in_words "$(canon_net "$ck_t")" "$ck_ign_canon"; then in_place; else
				missing "sshd jail never bans $ck_t"
				ck_fix=yes
			fi
		done
	fi
	[ "$ck_fix" = no ] || f2b_changes
}

# ---------------------------------------------------------------------------
# kernel

# The parameters, with the rule each value follows:
#   eq  must be the value
#   ge  the value or higher (higher is stricter)
#   le  the value or lower (IPv6 accept_source_route -1 refuses more than 0)
#   rp  rp_filter: only raised from 0, never lowered from 1 (RHEL's strict
#       default; the kernel takes the higher of "all" and each interface)
# then N for a network parameter (the container's own in a container), K for
# the kernel's.
KERNEL_PARAMS='
net.ipv4.conf.all.accept_redirects 0 eq N
net.ipv4.conf.default.accept_redirects 0 eq N
net.ipv4.conf.all.send_redirects 0 eq N
net.ipv4.conf.default.send_redirects 0 eq N
net.ipv4.conf.all.accept_source_route 0 eq N
net.ipv4.conf.default.accept_source_route 0 eq N
net.ipv6.conf.all.accept_redirects 0 eq N
net.ipv6.conf.default.accept_redirects 0 eq N
net.ipv6.conf.all.accept_source_route 0 le N
net.ipv6.conf.default.accept_source_route 0 le N
net.ipv4.tcp_syncookies 1 ge N
net.ipv4.conf.all.log_martians 1 ge N
net.ipv4.conf.default.log_martians 1 ge N
net.ipv4.conf.all.rp_filter 2 rp N
net.ipv4.conf.default.rp_filter 2 rp N
kernel.dmesg_restrict 1 ge K
kernel.kptr_restrict 1 ge K
kernel.yama.ptrace_scope 1 ge K
kernel.unprivileged_bpf_disabled 2 bpf K
fs.protected_hardlinks 1 ge K
fs.protected_symlinks 1 ge K
fs.protected_fifos 1 ge K
fs.protected_regular 1 ge K
'
# Benchmarks: rp_filter is usually asked to be strict (1); ADR-0051 sets the
# loose 2, so that asymmetric routes and VPNs keep working. ptrace_scope
# STIG RHEL-09-213080; dmesg_restrict STIG RHEL-09-213010; kptr_restrict
# RHEL-09-213025; unprivileged_bpf_disabled RHEL-09-213075;
# protected_hardlinks RHEL-09-213030; protected_symlinks RHEL-09-213035.
# protected_fifos and protected_regular have no STIG rule and follow the
# kernel's own hardening advice. kptr_restrict stays 1, not 2, which
# blinds root's perf and bpftrace; ptrace_scope 1, not 3, which cannot be
# undone until a restart; unprivileged_bpf_disabled 1, which locks it until a
# restart, counts as in place. IP forwarding is never read or written: a
# persisted 0 would break Docker or Kubernetes installed later.

# kernel_value_ok RULE NOW WANT
kernel_value_ok() {
	case $1 in
	eq) [ "$2" -eq "$3" ] ;;
	ge) [ "$2" -ge "$3" ] ;;
	le) [ "$2" -le "$3" ] ;;
	rp | bpf) [ "$2" -ge 1 ] ;;
	*) return 1 ;;
	esac
}

check_kernel() {
	ck_skipped=
	ck_set=no
	for ck_line in $(printf '%s' "$KERNEL_PARAMS" | tr ' ' ':'); do
		ck_name=${ck_line%%:*}
		ck_rest=${ck_line#*:}
		ck_want=${ck_rest%%:*}
		ck_rest=${ck_rest#*:}
		ck_rule=${ck_rest%%:*}
		ck_kind=${ck_rest#*:}
		# In a container only the network settings are its own.
		if [ "$IN_CONTAINER" = yes ] && [ "$ck_kind" = K ]; then continue; fi
		if [ "$ck_rule" = rp ] && is_k8s_node; then
			change "Left as it is: $ck_name, because this is a Kubernetes node (Calico refuses to run with it loose)"
			continue
		fi
		ck_path=/proc/sys/$(printf '%s' "$ck_name" | tr '.' '/')
		if [ ! -r "$ck_path" ]; then
			ck_skipped="$ck_skipped $ck_name"
			continue
		fi
		ck_now=$(head -n 1 "$ck_path" 2>/dev/null)
		case $ck_now in '' | *[!0-9-]* | ?*-*) ck_skipped="$ck_skipped $ck_name" && continue ;; esac
		if kernel_value_ok "$ck_rule" "$ck_now" "$ck_want"; then
			in_place
		else
			missing "$ck_name = $ck_want (now $ck_now)"
			change "$ck_name = $ck_want"
			todo "$ck_name $ck_want"
			ck_set=yes
		fi
	done
	[ -z "$ck_skipped" ] || change "Left as it is: this kernel has no${ck_skipped}"
	[ "$ck_set" = no ] || change "The values go in $SYSCTL_FILE, applied with sysctl -p on that file only; IP forwarding is never written"
	if [ "$IN_CONTAINER" = yes ] && [ "$M_OK" -eq 0 ] && [ "$M_BAD" -eq 0 ]; then
		not_applicable "In a container ($CONTAINER) the kernel belongs to the host, and its network settings could not be read."
	elif [ "$IN_CONTAINER" = yes ] && [ "$M_BAD" -eq 0 ]; then
		reason "In a container ($CONTAINER) only the network settings are its own, and they are in place."
	elif [ "$IN_CONTAINER" = yes ]; then
		reason "In a container ($CONTAINER) only the network settings are its own: $M_OK of $((M_OK + M_BAD)) are in place."
	fi
}

# ---------------------------------------------------------------------------
# audit

# The rules apply loads, by what they watch, with a pattern that finds an
# equivalent rule in auditctl -l, whoever loaded it.
AUDIT_RULES='
the account files (/etc/passwd, /etc/group, /etc/shadow, /etc/gshadow)|(-w |path=)/etc/(passwd|group|g?shadow)( |$)
sudoers (/etc/sudoers, /etc/sudoers.d)|(-w |path=|dir=)/etc/sudoers(\.d/?)?( |$)
the SSH server configuration (/etc/ssh/sshd_config)|(-w |path=|dir=)/etc/ssh/sshd_config(\.d/?)?( |$)
PAM configuration (/etc/pam.d)|(-w |dir=)/etc/pam\.d/?( |$)
changes to the time (adjtimex, settimeofday, clock_settime)|(-S |,)(adjtimex|settimeofday|clock_settime)(,| |$)
loading kernel modules (init_module, finit_module, delete_module)|(-S |,)(init_module|finit_module)(,| |$)
mounts (mount)|(-S |,)mount(,| |$)
commands run with raised privileges (execve where euid is 0 and uid is not)|-S ([a-z_0-9]+,)*execve.*(uid!=euid.*euid=0|euid=0.*uid!=euid)
'

check_audit() {
	if [ "$IN_CONTAINER" = yes ]; then
		not_applicable "In a container ($CONTAINER) the audit subsystem belongs to the host."
		return
	fi
	if ! have auditctl; then
		missing 'auditd installed and running'
		missing "EasyRMM's audit rules"
		change 'Install auditd and start it at boot'
		change "Add rules for accounts, sudoers, SSH and PAM configuration, time, kernel modules, mounts and commands run with raised privileges in $AUDIT_FILE, loaded with augenrules --load (never immutable, never panic)"
		todo install
		todo start
		todo rules
		return
	fi
	if unit_active auditd.service && unit_enabled auditd.service; then in_place; else
		missing 'auditd running and started at boot'
		change 'Start auditd and start it at boot'
		todo start
	fi
	# Rules of other EasyRMM features (their keys start easyrmm- too) come
	# and go with them: they do not count here.
	ca_live=$(t 20 auditctl -l 2>/dev/null | awk '!/key=easyrmm-/ || /key=easyrmm-hardening-/')
	ca_status=$(t 20 auditctl -s 2>/dev/null)
	ca_missing=
	ca_oifs=$IFS
	IFS=$nl
	set -f
	for ca_rule in $AUDIT_RULES; do
		set +f
		IFS=$ca_oifs
		ca_what=${ca_rule%%|*}
		ca_re=${ca_rule#*|}
		if text_has "$ca_live" -E -- "$ca_re"; then in_place; else
			missing "Audit rules for $ca_what"
			ca_missing=yes
		fi
		IFS=$nl
	done
	set +f
	IFS=$ca_oifs
	if [ -n "$ca_missing" ]; then
		change "Add the missing rules in $AUDIT_FILE, loaded with augenrules --load (never immutable, never panic)"
		todo rules
		if text_has "$ca_status" '^enabled 2'; then
			change 'Left as it is until the next restart: the loaded rules are immutable (enabled 2), so the new rules load at the next restart, and undo cannot unload them before one'
		fi
	fi
}

# ---------------------------------------------------------------------------
# permissions

# perm_max PATH MAX: PATH's mode has no bit MAX lacks. Bits are only ever
# removed, so a stricter mode (RHEL's 0000 on shadow) stays as it is; owners
# and groups are left alone.
perm_max() {
	[ -e "$1" ] || return 0
	pm_m=$(stat -L -c %a "$1" 2>/dev/null)
	case $pm_m in '' | *[!0-7]*)
		missing "$1 at most $2 (its mode could not be read)"
		return
		;;
	esac
	pm_extra=$((0$pm_m & ~0$2 & 07777))
	if [ "$pm_extra" -eq 0 ]; then in_place; else
		pm_new=$(printf '%04o' $((0$pm_m & 0$2)))
		pm_now=$(printf '%04o' $((0$pm_m)))
		missing "$1 mode $2 or stricter (now $pm_now)"
		change "$1: mode $pm_now to $pm_new"
		todo "$1 $pm_new"
	fi
}

check_permissions() {
	perm_max /etc/passwd 0644
	perm_max /etc/group 0644
	perm_max /etc/shadow 0640
	perm_max /etc/gshadow 0640
	perm_max /etc/ssh/sshd_config 0600
	# cron.allow and at.allow are never created.
	perm_max /etc/crontab 0600
	for cp_d in /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /etc/cron.d; do
		perm_max "$cp_d" 0700
	done
	# The boot loader's configuration. update-grub writes it
	# again on kernel updates: a later check reports the drift.
	cp_efi=no
	if [ "$FAMILY" = rhel ] && [ "$OS_MAJOR" = 8 ] && [ -d /sys/firmware/efi ]; then
		for cp_f in /boot/efi/EFI/*/grub.cfg; do
			[ -f "$cp_f" ] && cp_efi=$cp_f
		done
	fi
	if [ "$cp_efi" != no ]; then
		# On FAT the mode comes from the mount: checked and reported, not changed.
		cp_opts=$(awk '$2 == "/boot/efi" { o = $4 } END { print o }' /proc/self/mounts)
		cp_mask=$(printf '%s\n' "$cp_opts" | tr ',' '\n' | sed -n 's/^fmask=//p;s/^umask=//p' | tail -n 1)
		case $cp_mask in '' | *[!0-7]*) cp_mask=0022 ;; esac
		if [ $((0$cp_mask & 077)) -eq $((077)) ]; then in_place; else
			missing "$cp_efi readable by root only: /boot/efi mounted with fmask=0077 (now $cp_opts)"
			change "Left as it is: $cp_efi is on the FAT EFI partition, whose modes come from the mount; set fmask=0077 for /boot/efi in /etc/fstab"
		fi
	else
		case $FAMILY in
		debian) cp_cfg=/boot/grub/grub.cfg ;;
		rhel | fedora) cp_cfg=/boot/grub2/grub.cfg ;;
		*)
			cp_cfg=/boot/grub/grub.cfg
			[ -e "$cp_cfg" ] || cp_cfg=/boot/grub2/grub.cfg
			;;
		esac
		perm_max "$cp_cfg" 0600
	fi
	if [ "$M_OK" -eq 0 ] && [ "$M_BAD" -eq 0 ]; then
		not_applicable 'None of the files this module checks exists here.'
	fi
}

# ---------------------------------------------------------------------------
# services

# Plaintext and legacy network services, with their systemd units and their
# names in xinetd and inetd. ypbind, which NIS sign-in
# needs, is not one of them; snmpd, cups, NFS and rpcbind are left alone.
LEGACY_SERVICES='
telnet|telnet.socket telnetd.service inetutils-telnetd.service|telnet
rsh|rsh.socket|shell
rlogin|rlogin.socket|login
rexec|rexec.socket|exec
finger|finger.socket|finger
talk|talk.socket ntalk.socket|talk ntalk
the NIS server (ypserv)|ypserv.service|
'
# TFTP is reported, not turned off: PXE and configuration backup servers use
# it on purpose.
TFTP_SERVICE='TFTP|tftp.socket tftp.service tftpd-hpa.service atftpd.service|tftp'

# xinetd_on NAME: whether xinetd would serve NAME (its "disable" is not yes).
xinetd_on() {
	{ have xinetd || [ -x /usr/sbin/xinetd ]; } || return 1
	for xo_f in /etc/xinetd.d/* /etc/xinetd.conf; do
		[ -f "$xo_f" ] || continue
		awk -v name="$1" '
		$1 == "service" { insvc = ($2 == name); dis = 0; next }
		insvc && $1 == "disable" { v = $0; sub(/^[^=]*=[ \t]*/, "", v); dis = (v ~ /^yes/) }
		insvc && $1 == "}" { if (!dis) found = 1; insvc = 0 }
		END { exit(found ? 0 : 1) }' "$xo_f" && return 0
	done
	return 1
}

# inetd_on NAME: whether an inetd has a line for NAME that is not commented out.
inetd_on() {
	{ have inetd || have inetutils-inetd || have xinetd-inetd; } || return 1
	[ -f /etc/inetd.conf ] || return 1
	grep -Eq "^[[:space:]]*$1[[:space:]]" /etc/inetd.conf
}

# service_on ENTRY: how the service in a LEGACY_SERVICES ENTRY is on (its
# unit, "xinetd" or "inetd"), or nothing.
service_on() {
	so_rest=${1#*|}
	so_units=${so_rest%%|*}
	so_names=${so_rest#*|}
	for so_u in $so_units; do
		if unit_active "$so_u" || unit_enabled "$so_u"; then
			printf '%s' "$so_u"
			return 0
		fi
	done
	for so_x in $so_names; do
		if xinetd_on "$so_x"; then
			printf 'xinetd (%s)' "$so_x"
			return 0
		fi
		if inetd_on "$so_x"; then
			printf '/etc/inetd.conf (%s)' "$so_x"
			return 0
		fi
	done
	return 0
}

check_services() {
	cv_oifs=$IFS
	IFS=$nl
	set -f
	for cv_e in $LEGACY_SERVICES; do
		set +f
		IFS=$cv_oifs
		cv_name=${cv_e%%|*}
		cv_how=$(service_on "$cv_e")
		if [ -n "$cv_how" ]; then
			missing "$cv_name off (on through $cv_how)"
			change "Turn $cv_name off: $cv_how"
		fi
		IFS=$nl
	done
	set +f
	IFS=$cv_oifs
	[ "$M_BAD" -gt 0 ] || {
		in_place
		reason 'None of telnet, rsh, rlogin, rexec, finger, talk or the NIS server is on.'
	}
	cv_how=$(service_on "$TFTP_SERVICE")
	[ -z "$cv_how" ] || change "Left as it is: TFTP is on ($cv_how); PXE and configuration backup servers use it on purpose"
}

# ---------------------------------------------------------------------------
# kernel-modules and usb-storage

MODPROBE_C=
MODPROBE_READ=no
modprobe_config() {
	if [ "$MODPROBE_READ" = no ]; then
		MODPROBE_READ=yes
		MODPROBE_C=$(t 30 modprobe -c 2>/dev/null)
	fi
}
# kept_from_loading MODULE: an install directive that runs false or true in
# its place (blacklist alone does not stop an explicit modprobe).
kept_from_loading() {
	text_has "$MODPROBE_C" -E "^install $1 (/usr)?/bin/(false|true)([[:space:]]|\$)"
}
module_loaded() { grep -q "^$1 " /proc/modules 2>/dev/null; }

# Rarely used network protocols and filesystems. squashfs (snaps, AppImages) and udf (ISO images) are left alone.
KERNEL_MODULES='dccp sctp rds tipc cramfs freevxfs hfs hfsplus jffs2'

check_kernel_modules() {
	if [ "$IN_CONTAINER" = yes ]; then
		not_applicable "In a container ($CONTAINER) kernel modules belong to the host."
		return
	fi
	if ! have modprobe; then
		failed 'modprobe is not installed, so how modules load cannot be read.'
		return
	fi
	modprobe_config
	km_set=
	for km in $KERNEL_MODULES; do
		if kept_from_loading "$km"; then
			in_place
			continue
		fi
		km_file=$(t 20 modinfo -F filename "$km" 2>/dev/null | head -n 1)
		if [ -z "$km_file" ]; then
			# Not on this kernel at all, so it cannot load.
			in_place
		elif [ "$km_file" = '(builtin)' ]; then
			change "Left as it is: $km is built into this kernel"
		elif module_loaded "$km"; then
			missing "$km kept from loading (it is loaded now)"
			change "Left as it is: $km is loaded now, so something uses it (Oracle RAC uses rds)"
		else
			missing "$km kept from loading"
			km_set="$km_set $km"
		fi
	done
	[ -z "$km_set" ] || change "Keep from loading:$km_set (an install directive in /etc/modprobe.d)"
	M_TODO=$km_set
}

# usb_disks_in_use: USB disks with a mounted filesystem or swap on them, or
# on anything built on them (partitions, LVM, encryption).
usb_disks_in_use() {
	lsblk -dnpP -o NAME,TRAN 2>/dev/null | sed -n 's/^NAME="\([^"]*\)" TRAN="usb"$/\1/p' | while read -r ud_d; do
		lsblk -nrp -o MOUNTPOINT "$ud_d" 2>/dev/null | grep -q . && printf '%s\n' "$ud_d"
	done
}
# usb_fstab: the entries of /etc/fstab mounted at boot without nofail (a
# filesystem or swap the boot waits for) on a USB disk, mounted now or not:
# "SPEC (MOUNTPOINT)". A device named by UUID, label or the like is found
# with blkid; what it is built on (a partition's disk, LVM's and
# encryption's devices) with lsblk -s.
usb_fstab() {
	[ -r /etc/fstab ] || return 0
	awk '$1 !~ /^#/ && NF >= 2 && $4 !~ /(^|,)(noauto|nofail)(,|$)/ { print $1, $2 }' /etc/fstab |
		while read -r uf_spec uf_mp; do
			uf_dev=
			case $uf_spec in
			UUID=* | LABEL=* | PARTUUID=* | PARTLABEL=*)
				have blkid && uf_dev=$(blkid -l -o device -t "$uf_spec" 2>/dev/null | head -n 1)
				;;
			/dev/*) uf_dev=$(readlink -f "$uf_spec" 2>/dev/null) ;;
			esac
			[ -n "$uf_dev" ] || continue
			lsblk -nrspo TRAN "$uf_dev" 2>/dev/null | grep -qx usb && printf '%s (%s)\n' "$uf_spec" "$uf_mp"
		done
}

check_usb_storage() {
	if [ "$IN_CONTAINER" = yes ]; then
		not_applicable "In a container ($CONTAINER) kernel modules belong to the host."
		return
	fi
	if ! have modprobe; then
		failed 'modprobe is not installed, so how modules load cannot be read.'
		return
	fi
	modprobe_config
	if kept_from_loading usb_storage || kept_from_loading usb-storage; then
		in_place
		return
	fi
	us_file=$(t 20 modinfo -F filename usb_storage 2>/dev/null | head -n 1)
	if [ "$us_file" = '(builtin)' ]; then
		missing 'usb-storage kept from loading'
		change 'Left as it is: usb-storage is built into this kernel'
		return
	fi
	missing 'usb-storage kept from loading'
	# Refused where a mounted filesystem or swap is on a USB disk: the setting
	# reaches the initramfs, and such a computer would not boot.
	if ! have lsblk; then
		change 'Refused: lsblk is not installed to tell whether a mounted filesystem or swap is on a USB disk'
		return
	fi
	us_disks=$(usb_disks_in_use | tr '\n' ' ')
	us_fstab=$(usb_fstab | tr '\n' ';' | sed -e 's/;$//' -e 's/;/; /g')
	if [ -n "$us_disks" ]; then
		change "Refused: a mounted filesystem or swap is on a USB disk (${us_disks% }), and the computer would not boot without usb-storage"
	elif [ -n "$us_fstab" ]; then
		change "Refused: /etc/fstab mounts a filesystem or swap on a USB disk at boot, without nofail ($us_fstab), and the computer would not boot without usb-storage"
	else
		change 'Keep usb-storage from loading, in /etc/modprobe.d and the initramfs: USB disks and backup drives stop working'
		todo usb-storage
	fi
}

# ---------------------------------------------------------------------------
# sudo

# sudoers_lines: /etc/sudoers with the files it includes in their place, as
# sudo reads them. Files in an included directory are skipped if their names
# contain a dot or end in ~, as sudo skips them.
sudoers_lines() {
	sl_depth=${1:-0}
	sl_file=${2:-/etc/sudoers}
	[ "$sl_depth" -le 4 ] || return 0
	while IFS= read -r sl_line || [ -n "$sl_line" ]; do
		case $sl_line in
		'#includedir '* | '@includedir '*)
			sl_dir=${sl_line#* }
			sl_dir=${sl_dir%"${sl_dir##*[![:space:]]}"}
			for sl_f in "$sl_dir"/*; do
				case ${sl_f##*/} in *.* | *~) continue ;; esac
				[ -f "$sl_f" ] && sudoers_lines $((sl_depth + 1)) "$sl_f"
			done
			;;
		'#include '* | '@include '*)
			sl_f=${sl_line#* }
			sl_f=${sl_f%"${sl_f##*[![:space:]]}"}
			[ -f "$sl_f" ] && sudoers_lines $((sl_depth + 1)) "$sl_f"
			;;
		*) printf '%s\n' "$sl_line" ;;
		esac
	done <"$sl_file"
}

check_sudo() {
	if ! have sudo; then
		not_applicable 'sudo is not installed.'
		return
	fi
	cu_real=$(readlink -f "$(command -v sudo)" 2>/dev/null)
	cu_ver=$(t 10 sudo --version 2>/dev/null | head -n 1)
	case "$cu_real $cu_ver" in *sudo-rs*)
		M_STATE=not_supported
		reason 'sudo here is sudo-rs, which EasyRMM has not been tested with yet.'
		return
		;;
	esac
	if [ ! -r /etc/sudoers ]; then
		failed '/etc/sudoers cannot be read.'
		return
	fi
	# The global Defaults in force, the last one winning, as sudo applies them.
	cu_defaults=$(sudoers_lines | sed -n 's/^[[:space:]]*Defaults[[:space:]][[:space:]]*//p' | tr ',' '\n' |
		sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')
	# use_pty is on by default from sudo 1.9.14 on.
	cu_version=$(printf '%s\n' "$cu_ver" | sed -n 's/^Sudo version \([0-9.]*\).*/\1/p')
	cu_pty=no
	[ -n "$cu_version" ] && ver_ge "$cu_version" 1.9.14 && cu_pty=yes
	cu_logfile=
	cu_oifs=$IFS
	IFS=$nl
	set -f
	for cu_d in $cu_defaults; do
		case $cu_d in
		use_pty) cu_pty=yes ;;
		'!use_pty') cu_pty=no ;;
		logfile=* | logfile[[:space:]]*=*)
			cu_logfile=${cu_d#*=}
			cu_logfile=$(printf '%s' "$cu_logfile" | sed -e 's/^[[:space:]]*//' -e 's/^"\(.*\)"$/\1/')
			;;
		'!logfile') cu_logfile= ;;
		esac
	done
	set +f
	IFS=$cu_oifs
	# Commands run in a pseudo-terminal.
	if [ "$cu_pty" = yes ]; then in_place; else
		missing 'sudo runs commands in a pseudo-terminal (use_pty)'
		change 'Defaults use_pty'
		todo use_pty
	fi
	# Commands logged to a file of their own, with a logrotate
	# entry for it.
	if [ -n "$cu_logfile" ]; then
		in_place
		if grep -Fqs "$cu_logfile" /etc/logrotate.conf /etc/logrotate.d/*; then in_place; else
			missing "A logrotate entry for $cu_logfile"
			change "Add a logrotate entry for $cu_logfile"
			todo "logrotate $cu_logfile"
		fi
	else
		missing "sudo logs commands to $SUDO_LOG (logfile)"
		missing "A logrotate entry for $SUDO_LOG"
		change "Defaults logfile=$SUDO_LOG, with a logrotate entry for it"
		todo logfile
		todo "logrotate $SUDO_LOG"
	fi
	if [ -e "$SUDO_FILE" ]; then
		cu_mode=$(stat -c %a "$SUDO_FILE" 2>/dev/null)
		[ "$cu_mode" = 440 ] || {
			missing "$SUDO_FILE mode 0440 (now $cu_mode)"
			change "$SUDO_FILE: mode 0440"
			todo mode
		}
	fi
	if [ "$M_BAD" -gt 0 ]; then
		change "The settings go in $SUDO_FILE (mode 0440), checked with visudo -c before it is put in place"
		cu_refused=
		if ! grep -Eq '^[#@]includedir[[:space:]]+/etc/sudoers\.d/?[[:space:]]*$' /etc/sudoers; then
			cu_refused='/etc/sudoers does not include /etc/sudoers.d'
		elif ! have visudo; then
			cu_refused='visudo, which checks sudoers files, is not installed'
		elif ! t 20 visudo -c -q >/dev/null 2>&1; then
			cu_refused='the sudoers files have errors now (visudo -c fails)'
		fi
		[ -z "$cu_refused" ] || {
			change "Refused: $cu_refused"
			M_TODO="refused $cu_refused"
		}
	fi
}

# ---------------------------------------------------------------------------
# time

# The time services that may already be there, as units.
TIME_UNITS='chronyd.service chrony.service systemd-timesyncd.service ntpd.service ntp.service ntpsec.service openntpd.service ptp4l.service'

check_time() {
	if [ "$IN_CONTAINER" = yes ]; then
		not_applicable "In a container ($CONTAINER) the clock belongs to the host."
		return
	fi
	if [ "$SYSTEMD_UP" = no ]; then
		failed 'systemd is not running, so whether a time service runs cannot be read.'
		return
	fi
	ct_running=
	ct_installed=
	for ct_u in $TIME_UNITS; do
		if unit_active "$ct_u"; then
			# By its own name, not an alias's (chronyd.service is
			# chrony.service's on Debian and Ubuntu), which is-enabled
			# reports as "alias".
			ct_running=$(t 20 systemctl show -p Id --value "$ct_u" 2>/dev/null | head -n 1)
			case $ct_running in *.service) ;; *) ct_running=$ct_u ;; esac
			break
		fi
		[ -n "$ct_installed" ] || ! unit_exists "$ct_u" || ct_installed=$ct_u
	done
	if [ -n "$ct_running" ]; then
		in_place
		if unit_enabled "$ct_running"; then in_place; else
			missing "$ct_running started at boot"
			change "Start $ct_running at boot"
			M_TODO="unit $ct_running"
		fi
		reason "$ct_running keeps the time."
		[ "$M_BAD" -eq 0 ] || reason "$ct_running keeps the time but is not started at boot."
		return
	fi
	missing 'A time synchronisation service running'
	if [ -n "$ct_installed" ]; then
		change "Start $ct_installed, and start it at boot"
		M_TODO="unit $ct_installed"
	else
		case $FAMILY in
		rhel | fedora) M_TODO='install chrony chronyd.service' ;;
		*) M_TODO='install systemd-timesyncd systemd-timesyncd.service' ;;
		esac
		ct_p=${M_TODO#install }
		change "Install ${ct_p%% *}, and start it at boot"
	fi
}

# ---------------------------------------------------------------------------
# shared-memory

check_shared_memory() {
	if [ "$IN_CONTAINER" = yes ]; then
		not_applicable "In a container ($CONTAINER) /dev/shm is set up by the host's container runtime."
		return
	fi
	# nodev, nosuid and noexec: in effect now, and in /etc/fstab for the
	# next boot.
	cm_live=$(awk '$2 == "/dev/shm" { o = $4 } END { print o }' /proc/self/mounts)
	cm_tab=$(awk '$1 !~ /^#/ && $2 == "/dev/shm" { o = $4 } END { print o }' /etc/fstab 2>/dev/null)
	cm_fix=no
	for cm_o in nodev nosuid noexec; do
		case ",$cm_live," in
		*",$cm_o,"*) in_place ;;
		*)
			missing "/dev/shm mounted $cm_o (now ${cm_live:-not mounted})"
			cm_fix=yes
			;;
		esac
	done
	case ",$cm_tab," in
	*,nodev,*) case ",$cm_tab," in *,nosuid,*) case ",$cm_tab," in *,noexec,*) cm_tabok=yes ;; *) cm_tabok=no ;; esac ;; *) cm_tabok=no ;; esac ;;
	*) cm_tabok=no ;;
	esac
	if [ "$cm_tabok" = yes ]; then in_place; else
		missing "/etc/fstab mounts /dev/shm nodev,nosuid,noexec (now ${cm_tab:-no entry})"
		cm_fix=yes
	fi
	if [ "$cm_fix" = yes ]; then
		change 'Mount /dev/shm nodev,nosuid,noexec in /etc/fstab (the new file checked with findmnt --verify first) and remount it; programs that run code from shared memory stop working'
		todo shm
	fi
}

# ---------------------------------------------------------------------------
# mac

# avc_denials: 0 when there were AVC denials in the last 7 days, 1 when there
# were none, 2 when the audit log could not be searched.
avc_denials() {
	have ausearch || return 2
	ad_out=$(t 120 ausearch -m AVC,USER_AVC -ts week-ago --input-logs 2>&1 >/dev/null)
	ad_rc=$?
	[ "$ad_rc" -eq 0 ] && return 0
	text_has "$ad_out" '<no matches>' && return 1
	return 2
}

check_mac() {
	if [ "$IN_CONTAINER" = yes ]; then
		not_applicable "In a container ($CONTAINER) mandatory access control belongs to the host."
		return
	fi
	if [ -d /sys/fs/selinux ] || [ -f /etc/selinux/config ]; then
		# SELinux enforcing. Never from disabled,
		# which needs a relabel and a restart.
		cm_mode=disabled
		if [ -r /sys/fs/selinux/enforce ]; then
			case $(cat /sys/fs/selinux/enforce 2>/dev/null) in 1) cm_mode=enforcing ;; 0) cm_mode=permissive ;; esac
		fi
		cm_cfg=$(sed -n 's/^[[:space:]]*SELINUX=[[:space:]]*\([a-z]*\).*/\1/p' /etc/selinux/config 2>/dev/null | tail -n 1)
		case $cm_mode in
		enforcing)
			in_place
			if [ "$cm_cfg" = enforcing ]; then in_place; else
				missing "SELINUX=enforcing in /etc/selinux/config (now ${cm_cfg:-not set})"
				change 'SELINUX=enforcing in /etc/selinux/config'
				todo config
			fi
			;;
		disabled)
			missing 'SELinux enforcing (now disabled)'
			change 'Left as it is: SELinux is disabled, and turning it on needs a relabel and a restart'
			;;
		permissive)
			missing 'SELinux enforcing (now permissive)'
			cm_refused=
			avc_denials
			case $? in
			0) cm_refused='there were AVC denials in the last 7 days (ausearch -m AVC)' ;;
			2) cm_refused='the audit log could not be searched for AVC denials' ;;
			esac
			if [ -z "$cm_refused" ] && have sshd && sshd_effective; then
				cm_labels=
				for cm_p in $(sshd_ports); do
					[ "$cm_p" = 22 ] && continue
					if [ -z "$cm_labels" ]; then
						have semanage || {
							cm_refused="sshd listens on port $cm_p and semanage, which reads port labels, is not installed"
							break
						}
						cm_labels=$(t 60 semanage port -l 2>/dev/null | sed -n 's/^ssh_port_t[[:space:]][[:space:]]*tcp[[:space:]][[:space:]]*//p' | tr -d ' ' | tr ',' '\n')
						[ -n "$cm_labels" ] || cm_labels=22
					fi
					cm_ok=no
					for cm_l in $cm_labels; do
						case $cm_l in
						*-*) [ "$cm_p" -ge "${cm_l%-*}" ] && [ "$cm_p" -le "${cm_l#*-}" ] && cm_ok=yes ;;
						*) [ "$cm_p" = "$cm_l" ] && cm_ok=yes ;;
						esac
					done
					if [ "$cm_ok" = no ]; then
						cm_refused="sshd listens on port $cm_p, which is not labelled ssh_port_t"
						break
					fi
				done
			fi
			if [ -n "$cm_refused" ]; then
				change "Refused: $cm_refused"
			else
				change 'SELinux enforcing now (setenforce 1) and in /etc/selinux/config'
				todo enforce
				todo config
			fi
			;;
		esac
		[ "$cm_mode" = enforcing ] || [ "$cm_cfg" = enforcing ] || missing "SELINUX=enforcing in /etc/selinux/config (now ${cm_cfg:-not set})"
		return
	fi
	if [ "$(cat /sys/module/apparmor/parameters/enabled 2>/dev/null)" = Y ]; then
		# AppArmor: profiles in complain mode are
		# listed, not enforced; enforcing them all at once would turn on
		# experimental ones.
		in_place
		cm_prof=/sys/kernel/security/apparmor/profiles
		if [ -r "$cm_prof" ]; then
			cm_complain=$(sed -n 's/^\(.*\) (complain)$/\1/p' "$cm_prof" | sort)
			if [ -n "$cm_complain" ]; then
				cm_oifs=$IFS
				IFS=$nl
				set -f
				for cm_p in $cm_complain; do missing "AppArmor profile $cm_p enforcing (now complain)"; done
				set +f
				IFS=$cm_oifs
				change 'Left as it is: AppArmor profiles in complain mode are listed, not enforced; enforcing them all at once would turn on experimental profiles'
			fi
			reason "AppArmor is on, with $(grep -c ' (enforce)$' "$cm_prof") profiles enforcing."
			[ -z "$cm_complain" ] || reason "AppArmor is on, with $(grep -c ' (enforce)$' "$cm_prof") profiles enforcing and $(printf '%s\n' "$cm_complain" | grep -c .) in complain mode."
		else
			change 'Which AppArmor profiles are in complain mode could not be read'
		fi
		return
	fi
	missing 'SELinux or AppArmor on'
	change 'Left as it is: turning SELinux or AppArmor on needs the boot configuration changed and a restart'
}

# ---------------------------------------------------------------------------
# integrity

check_integrity() {
	# AIDE installed, a baseline, a daily check. Debian's aide comes without
	# its configuration and aideinit, which are aide-common's.
	if ! have aide || { [ "$FAMILY" = debian ] && ! have aideinit; }; then
		missing 'AIDE installed'
		missing 'An AIDE baseline'
		missing 'A daily AIDE check'
		change 'Install AIDE'
		todo install
		for ci_d in /var/lib/docker /var/lib/containers; do
			[ -d "$ci_d" ] || continue
			change "Leave $ci_d out of AIDE's checks"
			todo "exclude $ci_d"
		done
		change "Build the baseline in a unit of its own (systemd-run), outside the job's time limit; the next check reports whether it finished"
		change "Check daily, with the distribution's timer where it has one"
		todo baseline
		todo daily
		return
	fi
	in_place
	for ci_d in /var/lib/docker /var/lib/containers; do
		[ -d "$ci_d" ] || continue
		if grep -Eqs "^[[:space:]]*!$ci_d" /etc/aide/aide.conf /etc/aide/aide.conf.d/* /etc/aide.conf; then in_place; else
			missing "AIDE leaves out $ci_d"
			change "Leave $ci_d out of AIDE's checks"
			todo "exclude $ci_d"
		fi
	done
	ci_db=no
	for ci_f in /var/lib/aide/aide.db /var/lib/aide/aide.db.gz; do
		[ -s "$ci_f" ] && ci_db=yes
	done
	if [ "$ci_db" = yes ]; then in_place; else
		case $(unit_states "$AIDE_INIT_UNIT.service") in
		*' active')
			missing 'An AIDE baseline (being built now)'
			;;
		*)
			if [ "$SYSTEMD_UP" = yes ] && t 20 systemctl is-failed "$AIDE_INIT_UNIT.service" >/dev/null 2>&1; then
				missing "An AIDE baseline (the last build failed: journalctl -u $AIDE_INIT_UNIT)"
			else
				missing 'An AIDE baseline'
			fi
			change "Build the baseline in a unit of its own (systemd-run), outside the job's time limit; the next check reports whether it finished"
			todo baseline
			;;
		esac
	fi
	ci_daily=no
	if have systemctl && t 20 systemctl list-unit-files --no-legend --state=enabled '*aide*.timer' 2>/dev/null | grep -q .; then
		ci_daily=yes
	elif grep -qs aide /etc/crontab /etc/cron.d/* /etc/cron.daily/*; then
		ci_daily=yes
	fi
	if [ "$ci_daily" = yes ]; then in_place; else
		missing 'A daily AIDE check'
		change "Check daily, with the distribution's timer where it has one"
		todo daily
	fi
}

# ---------------------------------------------------------------------------
# The record (apply and undo only; check reads it and writes nothing)
#
# Each module's manifest starts "format 1" and then has one record a line,
# fields separated by tabs, in the order apply made the changes; undo
# reverses them in the opposite order. "-" stands for nothing (no file, no
# copy), "?" for not known yet (the job was killed between a change and its
# record).
#   file PATH ORIGINAL ORIGINAL-SHA256 AFTER-SHA256 CONTEXT
#       a file apply wrote; ORIGINAL is its copy under files/, or "-" when
#       apply created it; CONTEXT its SELinux context then ("-" without
#       SELinux), which undo puts back with chcon. A symbolic link stays
#       one: apply and undo write the file it points to.
#   dir PATH                     a directory apply created
#   line PATH TEXT               a line apply added at the top of PATH
#   mode PATH BEFORE OWNER AFTER a mode apply narrowed (owners never change)
#   sysctl NAME BEFORE AFTER     a kernel parameter's live value
#   unit UNIT ENABLED ACTIVE ENABLED-AFTER ACTIVE-AFTER
#       a systemd unit's state before apply changed it, and after
#   pkg TOKEN...                 the packages an installation added, each
#                                with its version and install time (PKG_TOKEN)
#   conffile PACKAGE PATH MD5    a configuration file of one, as installed
#   pkgdir TOKENS PATH MODE OWNER MODE-AFTER OWNER-AFTER
#       a directory under /etc that was there before the installation of
#       TOKENS (the pkg record's, as one field) and that it gave another
#       mode or owner (UID:GID); put back once its packages are gone
#   stream PATH ORIGINAL ORIGINAL-SHA256 AFTER-SHA256
#       a dnf module stream's file an installation made or changed
#   pending PACKAGE...           an installation that did not finish
#   table inet-easyrmm SHA256    the firewall table as apply loaded it
#   gen PATH SHA256              a file that a program apply started made,
#                                as it made it ("?": not known when apply
#                                ended; see undo_gen)
#   selinux - BEFORE AFTER       SELinux's mode (permissive, enforcing)
#   mount PATH BEFORE AFTER      a mount's options
# The first apply of a module keeps each original; a later one adds only
# what it changes for the first time, so undo goes back to the computer as
# it was before EasyRMM changed it. Undo puts back only what is still as
# apply left it, and then removes the module's record: the next apply
# takes fresh copies.

FORMAT=1
MD=
MANIFEST=
INTENT=no
TX_DIR=$STATE_DIR/tx
TX_STACK=
TX_SAVED=
TX_N=0
TX_HAD=no
PKG_REFRESHED=no
PKG_ERR=
# How long a package step waits for another package manager to finish
# (apt's DPkg::Lock::Timeout), in seconds.
PKG_LOCK_WAIT=300
# How long dpkg --configure -a may take to finish a dpkg run stopped part
# way (pkg_ready): what one step left, inside a job of 30 minutes that the
# step it guards needs too. A recovery stopped at its limit is resumed by
# the next run.
PKG_RECOVER_LIMIT=600
# Why the package database stays unusable, once a recovery failed in this
# run: later package steps fail with it rather than wait or try again.
PKG_STUCK=
# The module's package database recovery (pkg_ready): recovered or failed,
# and what it found and did.
M_RECOV=
M_RECOV_WHY=
# The packages pkg_install added, as tokens (PKG_TOKEN), and the pkgdir
# records of the directories that installation changed (pkg_dirs).
PKG_NEW=
PKG_DIRS=
# After pkg_remove_alone: the directories it put back (pkg_dirs_back), one
# a line, for did.
PKG_DIRS_BACK=
# The packages dpkg had left half installed that its recovery configured.
M_RECOV_PKGS=
# After pkg_remove_alone: what it left and why, one a line; whether a
# package stays (a module stream it needs stays too).
PKG_NOTES=
PKG_KEPT=no
# Where pkg_remove_alone reads conffile records: the module's record, or
# the auditd marker.
PKG_CONF_SRC=
# Set while undo of audit runs: auditd's packages and unit are the
# marker's (undo_audit_after).
AUDIT_UNDO=no
# Set while undo runs: whether it stopped AIDE's baseline being built
# (undo_integrity_before); the generated files it left (undo_gen).
GEN_STOPPED=no
GEN_LEFT=

now_utc() { date -u '+%Y-%m-%dT%H:%M:%SZ'; }

# did MESSAGE: something apply or undo did, for the result.
did() { append M_DONE "$1"; }
# left MESSAGE: something undo left as it is, and why.
left() {
	append M_DONE "Left as it is: $1"
	M_LEFT=yes
}

# sha PATH: the file's SHA-256, or "-" where there is no file.
sha() {
	if [ -f "$1" ]; then
		sha256sum <"$1" | cut -c1-64
	else
		printf -
	fi
}

# relabel PATH: SELinux's label for a file EasyRMM wrote, where SELinux is.
relabel() {
	! have restorecon || restorecon "$1" 2>/dev/null
	return 0
}

# module_record MODULE: the module whose record the functions below keep.
module_record() {
	MD=$STATE_DIR/modules/$1
	MANIFEST=$MD/manifest
	INTENT=no
}

rec_has() {
	[ -f "$MANIFEST" ] && awk -F "$tab" -v t="$1" -v k="$2" '$1 == t && $2 == k { f = 1; exit } END { exit !f }' "$MANIFEST"
}
rec_add() { printf '%s\n' "$1" >>"$MANIFEST"; }
# rec_set TYPE KEY N VALUE: sets field N of the record TYPE KEY.
rec_set() {
	awk -F "$tab" -v OFS="$tab" -v t="$1" -v k="$2" -v n="$3" -v v="$4" \
		'$1 == t && $2 == k && !d { $n = v; d = 1 } { print }' "$MANIFEST" >"$MANIFEST.new" &&
		mv -f "$MANIFEST.new" "$MANIFEST"
}

# intent: written before the module's first change in this run, so that a
# job killed from here on leaves the module half applied.
intent() {
	[ "$INTENT" = yes ] && return 0
	mkdir -p "$MD/files" && rm -f "$MD/done" || return 1
	[ -s "$MANIFEST" ] || printf 'format %s\n' "$FORMAT" >"$MANIFEST" || return 1
	printf '%s %s\n' "$MODE" "$(now_utc)" >"$MD/intent" || return 1
	INTENT=yes
}
# mark_done: the module finished; its record is whole.
mark_done() {
	[ "$INTENT" = yes ] || return 0
	printf '%s %s\n' "$MODE" "$(now_utc)" >"$MD/done"
}

# What this run changed, to put the module back as it was before the run
# when it fails: copies of the files under tx/, and a stack of commands
# (EasyRMM's own words: paths, units, values, never anything given to the
# job) run last first.
tx_begin() {
	TX_STACK=
	TX_SAVED=
	TX_N=0
	TX_HAD=no
	rm -rf "$TX_DIR" && mkdir -p "$TX_DIR/record" || return 1
	[ -d "$MD" ] || return 0
	TX_HAD=yes
	for tb_f in manifest intent 'done'; do
		[ ! -e "$MD/$tb_f" ] || cp -p "$MD/$tb_f" "$TX_DIR/record/$tb_f" || return 1
	done
}
tx_push() { TX_STACK=$1$nl$TX_STACK; }
# tx_save PATH: PATH as it was before this run, once.
tx_save() {
	case "$nl$TX_SAVED$nl" in *"$nl$1$nl"*) return 0 ;; esac
	TX_SAVED=$TX_SAVED$nl$1
	if [ -e "$1" ]; then
		TX_N=$((TX_N + 1))
		cp -p "$1" "$TX_DIR/$TX_N" || return 1
		tx_push "put_copy $TX_DIR/$TX_N $1 $(file_context "$1")"
	else
		tx_push "rm -f $(real_path "$1")"
	fi
}
# tx_rollback: puts back what this run changed, and the record as it was.
# TX_LEFT names the packages this run installed that stay, and why:
# removing them would remove others, or the package manager failed (one
# this run stopped part way leaves dpkg interrupted).
tx_rollback() {
	TX_LEFT=
	PKG_KEPT=no
	# A rollback may use the time kept for it.
	tr_end=$T_END
	T_END=$JOB_END
	tr_oifs=$IFS
	IFS=$nl
	set -f
	for tr_c in $TX_STACK; do
		IFS=$tr_oifs
		set +f
		PKG_ERR=
		eval "$tr_c" >/dev/null 2>&1 && tr_rc=0 || tr_rc=$?
		case $tr_c in
		'pkg_remove_alone '*)
			# shellcheck disable=SC2086 # tokens, one word each
			tr_p=$(pkg_token_names ${tr_c#pkg_remove_alone } | tr '\n' ' ' | sed 's/ $//')
			case $tr_rc in
			0) ;;
			1) TX_LEFT="${TX_LEFT:+$TX_LEFT; }the packages it installed ($tr_p) stay, because removing them would remove other packages too" ;;
			*) TX_LEFT="${TX_LEFT:+$TX_LEFT; }the packages it installed ($tr_p) stay: the package manager could not remove them$(pkg_why)" ;;
			esac
			[ -z "$PKG_NOTES" ] || TX_LEFT="${TX_LEFT:+$TX_LEFT; }left as it is: $(printf '%s' "$PKG_NOTES" | tr '\n' ';' | sed 's/;/; /g')"
			;;
		'stream_back '*)
			[ "$tr_rc" -eq 0 ] || [ -z "$STREAM_NOTE" ] || TX_LEFT="${TX_LEFT:+$TX_LEFT; }$STREAM_NOTE stays"
			;;
		esac
		IFS=$nl
		set -f
	done
	set +f
	IFS=$tr_oifs
	TX_STACK=
	T_END=$tr_end
	if [ "$TX_HAD" = no ]; then
		rm -rf "$MD"
	else
		for tr_f in manifest intent 'done'; do
			if [ -e "$TX_DIR/record/$tr_f" ]; then
				cp -p "$TX_DIR/record/$tr_f" "$MD/$tr_f"
			else
				rm -f "$MD/$tr_f"
			fi
		done
	fi
	INTENT=no
}
# sentence TEXT: TEXT ending in one full stop.
sentence() { printf '%s' "$1" | sed 's/[[:space:].]*$/./'; }
# tx_left_note: after a rollback that left packages, says so.
tx_left_note() { [ -z "$TX_LEFT" ] || sentence " What this run changed was put back, but $TX_LEFT"; }

# abort REASON [COMMAND]: the module failed; what this run changed is put
# back (then COMMAND runs, to reload what reads the files put back).
abort() {
	tx_rollback
	[ $# -lt 2 ] || eval "$2" >/dev/null 2>&1
	M_DONE=
	M_OUTCOME=failed
	M_WHY=$(sentence "$1; what this run changed was put back${TX_LEFT:+, but $TX_LEFT}")
}
# refuse REASON: a guard refused the module; nothing is left changed but
# packages its rollback could not remove.
refuse() {
	tx_rollback
	M_DONE=
	M_OUTCOME=refused
	M_WHY=$1$(tx_left_note)
}

# real_path PATH: the file PATH names: the one a symbolic link points to,
# so that writing it keeps the link a link.
real_path() {
	if [ -L "$1" ]; then readlink -f "$1"; else printf '%s' "$1"; fi
}
selinux_on() { [ -e /sys/fs/selinux/enforce ]; }
# file_context PATH: the SELinux context of the file PATH names, or "-"
# (no SELinux, no file).
file_context() {
	fc_c=
	! selinux_on || fc_c=$(stat -L -c %C "$1" 2>/dev/null)
	case $fc_c in '' | '?' | *[!A-Za-z0-9_.:,-]*) printf - ;; *) printf '%s' "$fc_c" ;; esac
}
# set_context PATH CONTEXT: puts a recorded context back ("-": SELinux's
# label for a new file, where SELinux is).
set_context() {
	if [ "${2:--}" = - ]; then
		relabel "$1"
	elif have chcon; then
		chcon "$2" "$1" 2>/dev/null || relabel "$1"
	fi
	return 0
}
# put_copy COPY PATH [CONTEXT]: puts a kept copy back, with its mode and
# owner, and the SELinux context it had (CONTEXT, recorded with it).
put_copy() {
	pc_p=$(real_path "$2")
	if cp -p "$1" "$pc_p.easyrmm-new" && mv -f "$pc_p.easyrmm-new" "$pc_p"; then
		set_context "$pc_p" "${3:--}"
		return 0
	fi
	rm -f "$pc_p.easyrmm-new"
	return 1
}
# put_file PATH MODE CONTENT: writes a file of EasyRMM's own, owned by root,
# whole or not at all, with the context of the file it replaces, if any.
put_file() {
	pf_p=$(real_path "$1")
	rm -f "$pf_p.easyrmm-new"
	if (umask 077 && printf '%s' "$3" >"$pf_p.easyrmm-new") && chown root:root "$pf_p.easyrmm-new" &&
		chmod "$2" "$pf_p.easyrmm-new" && keep_context "$pf_p" && mv -f "$pf_p.easyrmm-new" "$pf_p"; then
		[ "$KC_KEPT" = yes ] || relabel "$pf_p"
		return 0
	fi
	rm -f "$pf_p.easyrmm-new"
	return 1
}
# replace_with PATH: puts PATH.easyrmm-new in the place of the file PATH
# names, with its mode, owner and SELinux context.
replace_with() {
	rw_p=$(real_path "$1")
	[ "$rw_p" = "$1" ] || mv -f "$1.easyrmm-new" "$rw_p.easyrmm-new" || {
		rm -f "$1.easyrmm-new"
		return 1
	}
	if chown --reference="$rw_p" "$rw_p.easyrmm-new" && chmod --reference="$rw_p" "$rw_p.easyrmm-new" &&
		keep_context "$rw_p" && mv -f "$rw_p.easyrmm-new" "$rw_p"; then
		[ "$KC_KEPT" = yes ] || relabel "$rw_p"
		return 0
	fi
	rm -f "$rw_p.easyrmm-new"
	return 1
}
# keep_context PATH: PATH.easyrmm-new gets the SELinux context of PATH, if
# there is one; KC_KEPT says whether.
keep_context() {
	KC_KEPT=no
	selinux_on && [ -e "$1" ] && have chcon || return 0
	chcon --reference="$1" "$1.easyrmm-new" 2>/dev/null && KC_KEPT=yes
	return 0
}

# rec_file PATH: before apply changes PATH. Its original is kept the first
# time; its state before this run, every time.
rec_file() {
	intent && tx_save "$1" || return 1
	rec_has file "$1" && return 0
	rf_id=$(printf '%s' "$1" | sha256sum | cut -c1-16)
	if [ -e "$1" ]; then
		cp -p "$1" "$MD/files/$rf_id" || return 1
		tx_push "rm -f $MD/files/$rf_id"
		rec_add "file$tab$1${tab}files/$rf_id$tab$(sha "$1")$tab?$tab$(file_context "$1")"
	else
		rec_add "file$tab$1$tab-$tab-$tab?$tab-"
	fi
}
after_file() { rec_set file "$1" 5 "$(sha "$1")"; }
# write_own PATH MODE CONTENT: one of EasyRMM's own files, recorded.
write_own() { rec_file "$1" && put_file "$1" "$2" "$3" && after_file "$1"; }
# write_edit PATH: PATH.easyrmm-new, made by the caller, replaces a file
# EasyRMM does not own, recorded.
write_edit() {
	if rec_file "$1" && replace_with "$1" && after_file "$1"; then return 0; fi
	rm -f "$1.easyrmm-new"
	return 1
}

# make_dir PATH: a directory apply needs, created and recorded if missing.
make_dir() {
	[ -d "$1" ] && return 0
	intent && mkdir -m 0755 "$1" || return 1
	tx_push "rmdir $1"
	rec_has dir "$1" || rec_add "dir$tab$1"
	relabel "$1"
}

# add_top_line PATH TEXT: TEXT as PATH's first line, recorded so that undo
# removes that line only.
add_top_line() {
	intent && tx_save "$1" || return 1
	rec_has line "$1" || rec_add "line$tab$1$tab$2"
	{ printf '%s\n' "$2" && cat "$1"; } >"$1.easyrmm-new" && replace_with "$1"
}

# narrow_mode PATH MODE: PATH's mode set to MODE, recorded (of the file a
# symbolic link points to, as chmod does).
narrow_mode() {
	intent || return 1
	nm_b=$(stat -L -c %a "$1") && nm_o=$(stat -L -c %U:%G "$1") || return 1
	tx_push "chmod $nm_b $1"
	rec_has mode "$1" || rec_add "mode$tab$1$tab$nm_b$tab$nm_o$tab?"
	chmod "$2" "$1" && rec_set mode "$1" 5 "$(stat -L -c %a "$1")"
}

# Kernel parameters, read and written in /proc/sys.
sysctl_path() { printf '/proc/sys/%s' "$(printf '%s' "$1" | tr '.' '/')"; }
sysctl_now() { head -n 1 "$(sysctl_path "$1")" 2>/dev/null; }
sysctl_put() { printf '%s\n' "$2" >"$(sysctl_path "$1")"; }
rec_sysctl() {
	intent || return 1
	rs_b=$(sysctl_now "$1")
	tx_push "sysctl_put $1 $rs_b"
	rec_has sysctl "$1" || rec_add "sysctl$tab$1$tab$rs_b$tab?"
}
after_sysctl() { rec_set sysctl "$1" 4 "$(sysctl_now "$1")"; }

# unit_states UNIT: "ENABLED ACTIVE": what systemctl is-enabled says (or
# not-found), then active or inactive.
unit_states() {
	us_e=$(unit_file_state "$1")
	[ -n "$us_e" ] || us_e=not-found
	if unit_active "$1"; then us_a=active; else us_a=inactive; fi
	printf '%s %s' "$us_e" "$us_a"
}
# unit_put UNIT ENABLED ACTIVE: puts a unit in that state; "-" leaves either
# as it is.
unit_put() {
	case $(unit_file_state "$1"):$2 in
	masked:masked | *:-) ;;
	masked:*) t 60 systemctl unmask "$1" ;;
	esac >/dev/null 2>&1
	[ "$3" != inactive ] || t 120 systemctl stop "$1" >/dev/null 2>&1
	case $2 in
	enabled | enabled-runtime) t 60 systemctl enable "$1" ;;
	disabled | not-found) t 60 systemctl disable "$1" ;;
	masked) t 60 systemctl mask "$1" ;;
	esac >/dev/null 2>&1
	[ "$3" != active ] || t 120 systemctl start "$1" >/dev/null 2>&1
	unit_gone "$1"
	return 0
}
# unit_gone UNIT: a unit whose file is gone (its package removed) keeps no
# failed state, as before its package came.
unit_gone() {
	[ "$SYSTEMD_UP" = no ] || [ -n "$(unit_file_state "$1")" ] || t 30 systemctl reset-failed "$1" >/dev/null 2>&1
	return 0
}
# rec_unit UNIT: before apply changes a unit's state.
rec_unit() {
	intent || return 1
	ru_s=$(unit_states "$1")
	tx_push "unit_put $1 $ru_s"
	rec_has unit "$1" || rec_add "unit$tab$1$tab${ru_s% *}$tab${ru_s#* }$tab?$tab?"
}
after_unit() {
	au_s=$(unit_states "$1")
	rec_set unit "$1" 5 "${au_s% *}" && rec_set unit "$1" 6 "${au_s#* }"
}
# turn_on UNIT: started now and at boot, recorded.
turn_on() {
	rec_unit "$1" || return 1
	unit_put "$1" enabled active
	after_unit "$1"
	unit_active "$1" && unit_enabled "$1"
}
daemon_reload() { [ "$SYSTEMD_UP" = no ] || t 120 systemctl daemon-reload >/dev/null 2>&1; }

# Packages. pkg_names lists those installed, one a line, by name and
# architecture (name:arch on Debian and Ubuntu, name.arch elsewhere), so
# that a package an installation upgraded is not taken for one it added;
# an imported signing key, which has no architecture, by its full name.
# Installed means in any state but not installed: dpkg's half-installed,
# unpacked and half-configured packages too (iU, iF and the like), so that
# one a stopped run left is never taken for one an installation added.
# pkg_names rc lists those removed with their configuration files left
# (Debian and Ubuntu only).
pkg_names() {
	case $FAMILY in
	debian)
		# shellcheck disable=SC2016 # dpkg-query's fields, not the shell's
		dpkg-query -W -f='${db:Status-Abbrev} ${binary:Package}\n' 2>/dev/null | awk -v rc="${1:-}" '
		{ s = substr($1, 2, 1) }
		rc == "" && s != "n" && s != "c" { print $2 }
		rc != "" && s == "c" { print $2 }'
		;;
	*) [ $# -gt 0 ] || rpm -qa --qf '%{NAME}%|ARCH?{.%{ARCH}}:{-%{VERSION}-%{RELEASE}}|\n' 2>/dev/null ;;
	esac | sort -u
}
pkg_installed() {
	case $FAMILY in
	debian) [ "$(dpkg-query -W -f='${db:Status-Abbrev}' "$1" 2>/dev/null)" = 'ii ' ] ;;
	*) rpm -q "$1" >/dev/null 2>&1 ;;
	esac
}
# pkg_stamp NAME: the installed package's version and when it was installed
# (seconds since the epoch), "VERSION/TIME": dpkg's version and the time it
# last unpacked the package (its file list, which dpkg writes then), rpm's
# epoch, version and release and its install time. Nothing when it is not
# installed. Apply records each package it installed with its stamp; undo
# removes only a package whose stamp is the same (not upgraded or installed
# again since).
pkg_stamp() {
	case $FAMILY in
	debian)
		# shellcheck disable=SC2016
		ps_v=$(dpkg-query -W -f='${Version}' "$1" 2>/dev/null) || return 0
		ps_t=$(stat -c %Y "/var/lib/dpkg/info/$1.list" 2>/dev/null) || ps_t=0
		;;
	*)
		ps_v=$(rpm -q --qf '%|EPOCH?{%{EPOCH}:}:{}|%{VERSION}-%{RELEASE} %{INSTALLTIME}\n' "$1" 2>/dev/null | head -n 1) || return 0
		ps_t=${ps_v##* }
		ps_v=${ps_v% *}
		;;
	esac
	[ -n "$ps_v" ] || return 0
	printf '%s/%s' "$ps_v" "$ps_t"
}
# A package as a record names it, "NAME/VERSION/TIME" (pkg_stamp), then
# "=rc" for one whose configuration files were left from an earlier removal
# (undo keeps them). Read back from a record, a token must match this, or
# nothing of the record is used: the record is root's alone, but a token is
# a word the script runs a package manager with.
PKG_TOKEN='[A-Za-z0-9][A-Za-z0-9.+_:-]*/[A-Za-z0-9.+~:^_-]+/[0-9]+(=rc)?'
# pkg_tokens_ok TOKEN...: whether every token is one.
pkg_tokens_ok() {
	[ $# -gt 0 ] || return 1
	printf '%s\n' "$@" | grep -Evqx "$PKG_TOKEN" && return 1
	return 0
}
# pkg_conffiles NAME...: the configuration files dpkg keeps for the
# packages (Debian and Ubuntu), as records: "conffile NAME PATH MD5", with
# the MD5 of the file as it is now ("-" where there is none). Undo purges a
# package only while each is as apply left it.
pkg_conffiles() {
	[ "$FAMILY" = debian ] || return 0
	for pc_n in "$@"; do
		# shellcheck disable=SC2016
		dpkg-query -W -f='${Conffiles}\n' "$pc_n" 2>/dev/null | awk '$1 ~ /^\// && $NF != "obsolete" { print $1 }' |
			while IFS= read -r pc_f; do
				pc_m=-
				[ ! -f "$pc_f" ] || pc_m=$(md5sum <"$pc_f" | cut -c1-32)
				printf 'conffile%s%s%s%s%s%s\n' "$tab" "$pc_n" "$tab" "$pc_f" "$tab" "$pc_m"
			done
	done
}
# pkg_why: why the last installation or removal failed, for a reason (""
# or ": ...").
pkg_why() { [ -z "$PKG_ERR" ] || printf ': %s' "$PKG_ERR"; }
# pkg_failed EXIT MINUTES: PKG_ERR for a package manager that exited EXIT,
# from $TX_DIR/pkg.log or from its time limit.
pkg_failed() {
	case $T_CAPPED:$1 in
	yes:124 | yes:137)
		PKG_ERR="the package manager was stopped at the end of the job's time"
		[ "$FAMILY" != debian ] || PKG_ERR="$PKG_ERR (the next package step runs dpkg --configure -a to finish what it left)"
		;;
	*:124 | *:137)
		PKG_ERR="the package manager did not finish in $2 minutes and was stopped"
		[ "$FAMILY" != debian ] || PKG_ERR="$PKG_ERR (the next package step runs dpkg --configure -a to finish what it left)"
		;;
	*)
		PKG_ERR=$(grep -E '^E: |^[Ee]rror|No match|^Problem' "$TX_DIR/pkg.log" | head -n 1 | cut -c1-160)
		[ -n "$PKG_ERR" ] || PKG_ERR=$(tail -n 1 "$TX_DIR/pkg.log" | cut -c1-160)
		;;
	esac
}

# The package database, left unusable by a package step stopped part way
# (by its time limit, or the job's), fails every later step:
# * dpkg leaves its journal of status changes in /var/lib/dpkg/updates, on
#   which apt refuses everything ("dpkg was interrupted, you must manually
#   run 'dpkg --configure -a'"). A dpkg that runs keeps one too.
# * rpm on RHEL 8, killed while it writes, leaves its Berkeley DB
#   database's environment (/var/lib/rpm/__db.*: locks and caches, not the
#   database) failing every rpm and dnf command (DB_RUNRECOVERY) until those
#   files are removed, and rpm makes them again (rpm --rebuilddb fails too
#   until then; after, it rebuilds what the killed rpm may have left).
#   RHEL 9 and Fedora keep the database in SQLite, which a killed rpm leaves
#   usable: the next rpm or dnf command runs, and finds a package it was
#   removing still installed. Nothing there needs recovering.
pkgdb_interrupted() {
	case $FAMILY in
	debian)
		for pk_f in /var/lib/dpkg/updates/*; do
			case ${pk_f##*/} in *[!0-9]*) ;; *) return 0 ;; esac
		done
		return 1
		;;
	*)
		[ -e /var/lib/rpm/__db.001 ] || return 1
		pk_out=$(t 60 rpm -q rpm 2>&1) && return 1
		text_has "$pk_out" -F DB_RUNRECOVERY
		;;
	esac
}
# pkgdb_users: the processes using the package database now, "NAME (PID
# N)", separated by commas: those holding dpkg's locks (apt and dpkg lock
# them with fcntl, which /proc/locks lists by inode, and keep them open),
# or with rpm's database environment mapped: the files themselves, by
# device and inode (a file of the same name elsewhere, or in a container's
# own /var/lib/rpm, is another file).
pkgdb_users() {
	case $FAMILY in
	debian)
		for pu_f in /var/lib/dpkg/lock-frontend /var/lib/dpkg/lock; do
			pu_i=$(stat -c %i "$pu_f" 2>/dev/null) || continue
			awk -v i="$pu_i" '$2 != "->" && $5 ~ /^[0-9]+$/ { n = split($6, d, ":"); if (d[n] == i) print $5 }' /proc/locks 2>/dev/null |
				while read -r pu_p; do
					for pu_d in /proc/"$pu_p"/fd/*; do
						if [ "$(readlink "$pu_d" 2>/dev/null)" = "$pu_f" ]; then
							printf '%s\n' "$pu_p"
							break
						fi
					done
				done
		done
		;;
	*)
		pu_files=$(stat -c '%d %i' /var/lib/rpm/__db.[0-9]* 2>/dev/null)
		[ -z "$pu_files" ] || grep -l '__db\.' /proc/[0-9]*/maps 2>/dev/null | while read -r pu_m; do
			# maps gives the device as major:minor in hexadecimal; stat, the
			# number the kernel makes of them.
			awk -v files="$pu_files" '
			function hex(h,   i, n) { n = 0; h = tolower(h); for (i = 1; i <= length(h); i++) n = n * 16 + index("0123456789abcdef", substr(h, i, 1)) - 1; return n }
			BEGIN { n = split(files, f, "\n"); for (i = 1; i <= n; i++) want[f[i]] = 1 }
			{
				split($4, d, ":"); maj = hex(d[1]); mn = hex(d[2])
				dev = (mn % 256) + maj * 256 + int(mn / 256) * 1048576
				if ((dev " " $5) in want) { found = 1; exit }
			}
			END { exit !found }' "$pu_m" 2>/dev/null && printf '%s\n' "$pu_m" | cut -d/ -f3
		done
		;;
	esac | sort -un | while read -r pu_p; do
		printf '%s (PID %s)\n' "$(cat "/proc/$pu_p/comm" 2>/dev/null)" "$pu_p"
	done | tr '\n' ',' | sed -e 's/,$//' -e 's/,/, /g'
}
# pkg_ready: before a package step, recovers a package database left
# unusable (pkgdb_interrupted). A process still using it (apt,
# unattended-upgrades, dnf) is waited for as apt waits for its lock, and
# never touched. Once none is, dpkg --configure -a finishes what dpkg left,
# keeping changed configuration files: it configures every package dpkg left
# half installed, whichever run left it, running their maintainer scripts;
# M_RECOV_PKGS names them (dpkg --audit's list, before). On RHEL 8 the
# environment's files go, and rpm --rebuilddb rebuilds the indexes the
# killed rpm may have left half written. M_RECOV says that recovery ran,
# and how it ended. Returns 1 (PKG_ERR says why) while the database stays
# unusable.
pkg_ready() {
	pkgdb_interrupted || return 0
	if [ -n "$PKG_STUCK" ]; then
		PKG_ERR=$PKG_STUCK
		return 1
	fi
	case $FAMILY in
	debian)
		py_what='dpkg was interrupted'
		py_fix='dpkg --configure -a'
		py_use='held its lock'
		;;
	*)
		py_what="rpm's database needed recovering (DB_RUNRECOVERY)"
		py_fix='removing /var/lib/rpm/__db.* and rpm --rebuilddb'
		py_use='had it open'
		;;
	esac
	py_w=0
	while py_u=$(pkgdb_users) && [ -n "$py_u" ]; do
		if [ "$py_w" -ge "$PKG_LOCK_WAIT" ]; then
			PKG_STUCK="$py_what, and $py_u still $py_use after $py_w seconds; it was left to finish"
			PKG_ERR=$PKG_STUCK
			return 1
		fi
		need_time "$PKG_RECOVER_MIN" "recover the package database ($py_what; $py_u $py_use)" || return 1
		sleep 5
		py_w=$((py_w + 5))
		# What used it may have recovered it (unattended-upgrades runs
		# dpkg --configure -a).
		pkgdb_interrupted || return 0
	done
	need_time "$PKG_RECOVER_MIN" "recover the package database ($py_what)" || return 1
	: >"$TX_DIR/pkg.log"
	M_RECOV_PKGS=
	py_rb=0
	case $FAMILY in
	debian)
		M_RECOV_PKGS=$(dpkg_audit_names)
		py_lim=$PKG_RECOVER_LIMIT
		t "$py_lim" env DEBIAN_FRONTEND=noninteractive dpkg --force-confdef --force-confold --configure -a </dev/null
		;;
	*)
		py_lim=$PKG_RECOVER_LIMIT
		# rpm --rebuilddb ends by renaming the database's directory, which
		# an overlay filesystem (a Docker container's) refuses: rpm then
		# keeps the database it had, which reads without the environment.
		rm -f /var/lib/rpm/__db.[0-9]* && {
			t "$py_lim" rpm --rebuilddb || py_rb=$?
			t 60 rpm -q rpm
		}
		;;
	esac >"$TX_DIR/pkg.log" 2>&1 && py_rc=0 || py_rc=$?
	py_did=
	[ -z "$M_RECOV_PKGS" ] || py_did="; it configured the packages dpkg had left half installed, running their maintainer scripts: $(printf '%s' "$M_RECOV_PKGS" | sed 's/ /, /g')"
	if [ "$py_rc" -eq 0 ]; then
		M_RECOV=recovered
		M_RECOV_WHY="$py_what: $py_fix put it right before the package step$py_did"
		if [ "$py_rb" -ne 0 ]; then
			py_e=$(grep -E '^error' "$TX_DIR/pkg.log" | head -n 1 | cut -c1-160)
			M_RECOV_WHY="$py_what: removing /var/lib/rpm/__db.* put it right before the package step (rpm --rebuilddb then failed${py_e:+: $py_e}; rpm reads the database without it)"
		fi
		did "$M_RECOV_WHY"
		return 0
	fi
	case $T_CAPPED:$py_rc in
	yes:124 | yes:137) py_why="it was stopped at the end of the job's time" ;;
	*:124 | *:137) py_why="it did not finish in $py_lim seconds and was stopped" ;;
	*)
		py_why=$(grep -E '^(dpkg: |E: |error)' "$TX_DIR/pkg.log" | head -n 1 | cut -c1-160)
		[ -n "$py_why" ] || py_why=$(tail -n 1 "$TX_DIR/pkg.log" | cut -c1-160)
		;;
	esac
	M_RECOV=failed
	PKG_STUCK="$py_what, and $py_fix did not put it right: $py_why"
	M_RECOV_WHY=$PKG_STUCK$py_did
	PKG_ERR=$PKG_STUCK
	return 1
}
# dpkg_audit_names: the packages dpkg --audit lists (left half installed,
# unpacked, awaiting triggers and the like), separated by spaces: at most
# 50 names and 2,000 characters, each a package name.
dpkg_audit_names() {
	t 60 dpkg --audit 2>/dev/null | sed -n 's/^ \([a-z0-9][a-z0-9+.-]*\(:[a-z0-9-]*\)\{0,1\}\) .*/\1/p' |
		awk '!s[$0]++ && n < 50 && l + length($0) + 1 <= 2000 { printf "%s%s", (n ? " " : ""), $0; n++; l += length($0) + 1 }'
}

# pkg_install PACKAGE...: installs them, refreshing the package lists first,
# and records every package that installation added (a token each, see
# PKG_TOKEN) and, on Debian and Ubuntu, their configuration files as they
# are now (pkg_conffiles). It never removes a package: an installation that
# would (a conflict) fails, as apt-get --no-remove and dnf without
# --allowerasing do.
pkg_install() {
	PKG_ERR=
	pkg_ready || return 1
	need_time "$PKG_INSTALL_MIN" "install $*" || return 1
	intent || return 1
	pkg_names >"$TX_DIR/before" && pkg_names rc >"$TX_DIR/rc" || return 1
	pkg_dirs >"$TX_DIR/dirs-before"
	pkg_streams_before
	rec_add "pending$tab$*"
	pi_rc=0
	pi_min=10
	if [ "$PKG_REFRESHED" = no ]; then
		case $FAMILY in
		debian) t 600 apt-get -q -o DPkg::Lock::Timeout="$PKG_LOCK_WAIT" update ;;
		*) t 600 dnf -q -y makecache ;;
		esac >"$TX_DIR/pkg.log" 2>&1 || pi_rc=$?
		PKG_REFRESHED=yes
	fi
	# Without recommended packages: fail2ban's and AIDE's would bring a mail
	# server, a new service listening. The limit is generous: stopping a
	# package manager half way leaves packages half configured (aide-common
	# alone sets up some 150 configuration files).
	if [ "$pi_rc" -eq 0 ]; then
		pi_min=25
		case $FAMILY in
		debian)
			t 1500 env DEBIAN_FRONTEND=noninteractive apt-get -q -y -o DPkg::Lock::Timeout="$PKG_LOCK_WAIT" --no-install-recommends \
				--no-remove -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold install "$@"
			;;
		*) t 1500 dnf -q -y --setopt=install_weak_deps=False install "$@" ;;
		esac >>"$TX_DIR/pkg.log" 2>&1 || pi_rc=$?
	fi
	pkg_names >"$TX_DIR/after"
	PKG_NEW=
	for pi_n in $(comm -13 "$TX_DIR/before" "$TX_DIR/after"); do
		pi_s=$(pkg_stamp "$pi_n")
		pi_tok="$pi_n/${pi_s:-0/0}"
		grep -qxF -- "$pi_n" "$TX_DIR/rc" && pi_tok="$pi_tok=rc"
		pkg_tokens_ok "$pi_tok" || pi_tok="$pi_n/unknown/0"
		PKG_NEW="${PKG_NEW:+$PKG_NEW }$pi_tok"
	done
	awk -F "$tab" -v p="pending$tab$*" '$0 == p && !d { d = 1; next } { print }' "$MANIFEST" >"$MANIFEST.new" &&
		mv -f "$MANIFEST.new" "$MANIFEST"
	# A module stream dnf enabled or changed for a package (RHEL 8's
	# python36, for fail2ban): recorded before the packages, so that undo
	# puts it back after removing them, and only if it removed them all.
	pkg_streams_after
	PKG_DIRS=
	if [ -n "$PKG_NEW" ]; then
		pkg_dirs >"$TX_DIR/dirs-after"
		PKG_DIRS=$(awk -v t="$tab" -v k="$PKG_NEW" '
			{ p = substr($0, length($1) + length($2) + 3) }
			FILENAME == ARGV[1] { b[p] = $1 t $2; next }
			(p in b) && b[p] != $1 t $2 { print "pkgdir" t k t p t b[p] t $1 t $2 }' "$TX_DIR/dirs-before" "$TX_DIR/dirs-after")
		rec_add "pkg$tab$PKG_NEW"
		# shellcheck disable=SC2046,SC2086 # tokens and names, one word each
		pkg_conffiles $(pkg_token_names $PKG_NEW) >>"$MANIFEST"
		[ -z "$PKG_DIRS" ] || printf '%s\n' "$PKG_DIRS" >>"$MANIFEST"
		tx_push "pkg_remove_alone $PKG_NEW"
	fi
	[ "$pi_rc" -eq 0 ] || {
		pkg_failed "$pi_rc" "$pi_min"
		return 1
	}
}
# pkg_token_names TOKEN...: the packages' names, one a line.
pkg_token_names() { printf '%s\n' "$@" | cut -d/ -f1; }
# pkg_dirs: the directories under /etc, two levels down, not links, as
# "MODE UID:GID PATH", one a line: pkg_install compares them before and
# after an installation. rpm gives a directory a package ships the
# package's mode and owner, though it was there before (audit-rules makes
# /etc/audit 0750), and leaves them when it removes the package. A glob,
# not find.
pkg_dirs() {
	set --
	for pd_d in /etc/*/ /etc/*/*/; do
		pd_d=${pd_d%/}
		case $pd_d in *"$tab"* | *"$nl"*) continue ;; esac
		[ -d "$pd_d" ] && [ ! -L "$pd_d" ] && set -- "$@" "$pd_d"
	done
	[ $# -eq 0 ] || stat -c '%a %u:%g %n' -- "$@" 2>/dev/null
}

# dnf's module streams: the files under /etc/dnf/modules.d that say which
# stream of a module is enabled (or disabled); none on Debian and Ubuntu. A
# glob, not find: a minimal installation may have no findutils.
pkg_modules() {
	[ "$FAMILY" != debian ] || return 0
	for pm_f in /etc/dnf/modules.d/*.module; do
		[ ! -f "$pm_f" ] || [ -L "$pm_f" ] || printf '%s\n' "$pm_f"
	done | LC_ALL=C sort
}
# pkg_streams_before: each stream file as it is before an installation,
# kept in the run's directory ("PATH SHA" in streams, the copies beside).
pkg_streams_before() {
	rm -rf "$TX_DIR/streams" && mkdir -p "$TX_DIR/streams" || return 0
	pb_n=0
	for pb_f in $(pkg_modules); do
		pb_n=$((pb_n + 1))
		cp -p "$pb_f" "$TX_DIR/streams/$pb_n" && printf '%s %s %s\n' "$pb_f" "$(sha "$pb_f")" "$pb_n" >>"$TX_DIR/streams/list"
	done
}
# pkg_streams_after: records each stream file the installation made or
# changed ("stream PATH ORIGINAL ORIGINAL-SHA AFTER-SHA", ORIGINAL its copy
# under files/ or "-" when it made it), and what puts it back if the run
# fails.
pkg_streams_after() {
	for pa_f in $(pkg_modules); do
		pa_line=$(awk -v f="$pa_f" '$1 == f' "$TX_DIR/streams/list" 2>/dev/null)
		pa_now=$(sha "$pa_f")
		if [ -z "$pa_line" ]; then
			tx_push "stream_back $pa_f - $pa_now"
			rec_has stream "$pa_f" || rec_add "stream$tab$pa_f$tab-$tab-$tab$pa_now"
			continue
		fi
		# shellcheck disable=SC2086 # a path, a sum and a number
		set -- $pa_line
		[ "$2" != "$pa_now" ] || continue
		tx_push "stream_back $pa_f $TX_DIR/streams/$3 $pa_now"
		rec_has stream "$pa_f" && continue
		pa_id=$(printf '%s' "$pa_f" | sha256sum | cut -c1-16)
		cp -p "$TX_DIR/streams/$3" "$MD/files/$pa_id" && rec_add "stream$tab$pa_f${tab}files/$pa_id$tab$2$tab$pa_now"
	done
}
# stream_back PATH COPY AFTER-SHA: a module stream's file put back as it was
# before an installation (COPY, or none: "-"), if it is still as the
# installation left it, and the packages that installation added are gone
# (PKG_KEPT: some stayed, which need the stream). Says what it did, or why
# it left it, in STREAM_NOTE.
stream_back() {
	STREAM_NOTE=
	if [ "$PKG_KEPT" = yes ]; then
		STREAM_NOTE="$1, the module stream the packages that stay need"
		return 1
	fi
	if [ "$(sha "$1")" != "$3" ]; then
		STREAM_NOTE="$1, changed since apply"
		return 1
	fi
	if [ "$2" = - ]; then
		rm -f "$1" && STREAM_NOTE="Removed $1"
	else
		put_copy "$2" "$1" && STREAM_NOTE="Put back $1"
	fi
}
# pkg_removable PACKAGE...: whether removing them would remove nothing else
# (simulated: apt-get -s, rpm -e --test). Names without =rc. Returns 1 when
# it would, 2 when the simulation failed (PKG_ERR says why).
pkg_removable() {
	PKG_ERR=
	case $FAMILY in
	debian)
		if ! t 120 apt-get -s -o Debug::NoLocking=1 remove "$@" >"$TX_DIR/pkg.log" 2>&1; then
			PKG_ERR=$(grep '^E: ' "$TX_DIR/pkg.log" | head -n 1 | cut -c1-160)
			return 2
		fi
		pr_rm=$(sed -n 's/^Remv \([^ ]*\) .*/\1/p' "$TX_DIR/pkg.log")
		for pr_p in $pr_rm; do
			pr_ok=no
			for pr_q in "$@"; do
				[ "${pr_q%%:*}" = "${pr_p%%:*}" ] && pr_ok=yes
			done
			[ "$pr_ok" = yes ] || return 1
		done
		;;
	*)
		t 120 rpm -e --test "$@" >"$TX_DIR/pkg.log" 2>&1 && return 0
		grep -q 'Failed dependencies' "$TX_DIR/pkg.log" && return 1
		PKG_ERR=$(grep '^error' "$TX_DIR/pkg.log" | head -n 1 | cut -c1-160)
		return 2
		;;
	esac
}
# pkg_remove PURGE PACKAGE...: removes them; on Debian and Ubuntu, then
# purges the configuration files of those in PURGE (one word, names
# separated by commas), which were not there before apply. PKG_ERR says why
# it failed.
pkg_remove() {
	pr_purge=$1
	shift
	PKG_ERR=
	pr_rc=0
	pr_min=15
	case $FAMILY in
	debian)
		t 900 env DEBIAN_FRONTEND=noninteractive apt-get -q -y -o DPkg::Lock::Timeout="$PKG_LOCK_WAIT" remove "$@" || pr_rc=$?
		# The purge gets the installation's limit: aide-common's undoes, one
		# file at a time, what its configuration did.
		if [ "$pr_rc" -eq 0 ] && [ -n "$pr_purge" ]; then
			pr_min=25
			# shellcheck disable=SC2046 # package names, one word each
			t 1500 dpkg --purge $(printf '%s' "$pr_purge" | tr ',' ' ') || pr_rc=$?
		fi
		;;
	*) t 900 rpm -e "$@" || pr_rc=$? ;;
	esac >"$TX_DIR/pkg.log" 2>&1
	[ "$pr_rc" -eq 0 ] || {
		pkg_failed "$pr_rc" "$pr_min"
		return 1
	}
}
# pkg_remove_alone TOKEN...: removes the packages the tokens (PKG_TOKEN)
# name that are still installed as the installation left them, if that
# removes nothing else. NAME=rc keeps its configuration files; so, on Debian
# and Ubuntu, does a package one of whose configuration files changed since
# apply (pkg_conf_changed): removed, not purged. A package upgraded or
# installed again since (another stamp) is left. PKG_NOTES says, one a
# line, what it left and why; PKG_KEPT is yes once a package stays. Returns
# 1 when removing them would remove other packages, 2 when the package
# manager failed or the tokens are not ones, 3 when the package database
# could not be used or too little of the job's time was left (PKG_ERR says
# why): first, as on RHEL 8 rpm lists nothing until it is recovered.
pkg_remove_alone() {
	PKG_ERR=
	PKG_NOTES=
	PKG_REMOVED=
	if ! pkg_tokens_ok "$@"; then
		PKG_ERR='the record names its packages in a form this script does not know'
		PKG_KEPT=yes
		return 2
	fi
	if ! pkg_ready; then
		PKG_KEPT=yes
		return 3
	fi
	pa_have=
	pa_purge=
	pa_conf=
	pa_kept=no
	PKG_DIRS_BACK=
	pa_now=$(pkg_names)
	for pa_t in "$@"; do
		pa_n=${pa_t%%/*}
		text_has "$pa_now" -xF "$pa_n" || continue
		pa_s=${pa_t#*/}
		pa_s=${pa_s%=rc}
		pa_cur=$(pkg_stamp "$pa_n")
		if [ "$pa_cur" != "$pa_s" ]; then
			if [ "${pa_cur%/*}" != "${pa_s%/*}" ]; then
				pkg_note "the package $pa_n, upgraded since apply (now ${pa_cur%/*}, then ${pa_s%/*})"
			else
				pkg_note "the package $pa_n, installed again since apply"
			fi
			PKG_KEPT=yes
			pa_kept=yes
			continue
		fi
		pa_have="$pa_have $pa_n"
		[ "${pa_t%=rc}" = "$pa_t" ] || continue
		pa_ch=$(pkg_conf_changed "$pa_n")
		if [ -n "$pa_ch" ]; then
			pa_conf="$pa_conf${nl}the configuration files of $pa_n, changed since apply ($pa_ch): the package was removed and they were kept"
		else
			pa_purge="$pa_purge,$pa_n"
		fi
	done
	if [ -z "$pa_have" ]; then
		[ "$pa_kept" = yes ] || pkg_dirs_back "$*"
		return 0
	fi
	if ! need_time "$PKG_REMOVE_MIN" "remove$pa_have"; then
		PKG_KEPT=yes
		return 3
	fi
	# shellcheck disable=SC2086 # package names, one word each
	pkg_removable $pa_have && pa_rc=0 || pa_rc=$?
	if [ "$pa_rc" -ne 0 ]; then
		PKG_KEPT=yes
		return "$pa_rc"
	fi
	# shellcheck disable=SC2086
	if ! pkg_remove "${pa_purge#,}" $pa_have; then
		PKG_KEPT=yes
		return 2
	fi
	PKG_REMOVED=${pa_have# }
	[ "$pa_kept" = yes ] || pkg_dirs_back "$*"
	[ -z "$pa_conf" ] || pkg_note "${pa_conf#"$nl"}"
	return 0
}
pkg_note() { PKG_NOTES="${PKG_NOTES:+$PKG_NOTES$nl}$1"; }
# pkg_dirs_back TOKENS: once none of an installation's packages is left,
# puts back the mode and owner of each directory it changed (pkgdir
# records in PKG_CONF_SRC for TOKENS, as one word) that is as it left
# them. PKG_DIRS_BACK says what it put back, PKG_NOTES what it left.
pkg_dirs_back() {
	awk -F "$tab" -v k="$1" '$1 == "pkgdir" && $2 == k && NF == 7 { print $3 "\t" $4 "\t" $5 "\t" $6 "\t" $7 }' \
		"${PKG_CONF_SRC:-$MANIFEST}" >"$TX_DIR/pkgdirs" 2>/dev/null || return 0
	while IFS=$tab read -r pb_p pb_m pb_o pb_ma pb_oa; do
		case $pb_p in /*) ;; *) continue ;; esac
		# Modes and owners as stat wrote them: words chmod and chown get.
		printf '%s %s %s %s\n' "$pb_m" "$pb_o" "$pb_ma" "$pb_oa" | grep -Eqx '[0-7]{3,4} [0-9]+:[0-9]+ [0-7]{3,4} [0-9]+:[0-9]+' || continue
		[ -d "$pb_p" ] && [ ! -L "$pb_p" ] || continue
		pb_now=$(stat -c '%a %u:%g' "$pb_p") || continue
		[ "$pb_now" != "$pb_m $pb_o" ] || continue
		if [ "$pb_now" != "$pb_ma $pb_oa" ]; then
			pkg_note "the mode and owner of $pb_p, changed since apply"
			continue
		fi
		pb_what=
		[ "$pb_ma" = "$pb_m" ] || pb_what=", mode $(printf '%04o' "0$pb_ma") back to $(printf '%04o' "0$pb_m")"
		[ "$pb_oa" = "$pb_o" ] || pb_what="$pb_what, owner $pb_oa back to $pb_o"
		# Five digits: GNU chmod keeps a directory's set-group-ID bit unless
		# told.
		if chown "$pb_o" "$pb_p" && chmod "$(printf '%05o' "0$pb_m")" "$pb_p"; then
			PKG_DIRS_BACK="${PKG_DIRS_BACK:+$PKG_DIRS_BACK$nl}$pb_p:${pb_what#,}"
		else
			pkg_note "the mode and owner of $pb_p, which could not be put back"
		fi
	done <"$TX_DIR/pkgdirs"
}
# pkg_dirs_did: says what pkg_dirs_back put back.
pkg_dirs_did() {
	pd_oifs=$IFS
	IFS=$nl
	for pd_l in $PKG_DIRS_BACK; do did "$pd_l"; done
	IFS=$pd_oifs
}
# pkg_conf_changed NAME: the package's configuration files that are not as
# apply recorded them (conffile records in PKG_CONF_SRC), separated by
# commas. One removed since counts as unchanged: nothing of it is left to
# keep.
pkg_conf_changed() {
	awk -F "$tab" -v n="$1" '$1 == "conffile" && $2 == n && NF == 4 { print $3 "\t" $4 }' "${PKG_CONF_SRC:-$MANIFEST}" 2>/dev/null |
		while IFS=$tab read -r pc_f pc_m; do
			case $pc_f in /*) ;; *) continue ;; esac
			[ -f "$pc_f" ] || continue
			[ "$(md5sum <"$pc_f" | cut -c1-32)" = "$pc_m" ] || printf '%s\n' "$pc_f"
		done | tr '\n' ',' | sed -e 's/,$//' -e 's/,/, /g'
}

# Mounts: mount_options PATH is the options PATH is mounted with now;
# mount_flags_added NOW BEFORE lists which of nodev, nosuid and noexec NOW
# has and BEFORE had not; mount_flags_back NOW BEFORE the options that take
# those away again (dev, suid, exec).
mount_options() { awk -v m="$1" '$2 == m { o = $4 } END { print o }' /proc/self/mounts; }
mount_flags_added() {
	ma_out=
	for ma_f in nodev nosuid noexec; do
		case ",$1," in *",$ma_f,"*)
			case ",$2," in *",$ma_f,"*) ;; *) ma_out="$ma_out,$ma_f" ;; esac
			;;
		esac
	done
	printf '%s' "${ma_out#,}"
}
mount_flags_back() { mount_flags_added "$1" "$2" | sed 's/no//g'; }

selinux_mode() {
	case $(cat /sys/fs/selinux/enforce 2>/dev/null) in
	1) printf enforcing ;;
	0) printf permissive ;;
	*) printf disabled ;;
	esac
}

fw_table_sha() { t 30 nft -n list table inet easyrmm 2>/dev/null | sha256sum | cut -c1-64; }

# Undo of each kind of record. Each says what it did with did, or why it
# left something with left; one already as it was says nothing.
undo_file() {
	uf_now=$(sha "$1")
	[ "$uf_now" = "$3" ] && return 0
	if [ "$4" != '?' ] && [ "$uf_now" != "$4" ]; then
		left "$1, changed since apply"
		return 0
	fi
	tx_save "$1" || return 1
	if [ "$2" = - ]; then
		rm -f "$(real_path "$1")" && did "Removed $1"
	else
		put_copy "$MD/$2" "$1" "$5" && did "Put back $1"
	fi
}
undo_dir() {
	[ -d "$1" ] || return 0
	if rmdir "$1" 2>/dev/null; then
		tx_push "mkdir -m 0755 $1"
		did "Removed $1"
	else
		left "$1, which is not empty"
	fi
}
undo_line() {
	[ -f "$1" ] || return 0
	if [ "$(head -n 1 "$1")" = "$2" ]; then
		tx_save "$1" || return 1
		sed '1d' "$1" >"$1.easyrmm-new" && replace_with "$1" && did "Removed '$2' from $1"
	elif grep -qxF -- "$2" "$1"; then
		left "'$2' in $1, moved from the top since apply"
	fi
}
undo_mode() {
	[ -e "$1" ] || return 0
	um_m=$(stat -L -c %a "$1")
	[ "$um_m" = "$2" ] && return 0
	if [ "$4" != '?' ] && { [ "$um_m" != "$4" ] || [ "$(stat -L -c %U:%G "$1")" != "$3" ]; }; then
		left "the mode of $1, changed since apply"
		return 0
	fi
	tx_push "chmod $um_m $1"
	chmod "$2" "$1" && did "$1: mode $(printf '%04o' "0$um_m") back to $(printf '%04o' "0$2")"
}
undo_sysctl() {
	us_now=$(sysctl_now "$1")
	[ -n "$us_now" ] && [ "$us_now" != "$2" ] || return 0
	if [ "$3" != '?' ] && [ "$us_now" != "$3" ]; then
		left "$1 = $us_now, changed since apply"
		return 0
	fi
	tx_push "sysctl_put $1 $us_now"
	if sysctl_put "$1" "$2" 2>/dev/null; then
		did "$1 back to $2"
	else
		left "$1, which could not be set back to $2"
	fi
}
undo_unit() {
	# auditd, installed by EasyRMM: removed with its packages, or kept. A
	# marker that names only audit-rules (auditd was there before, without
	# it) leaves the unit to go back as any other.
	if [ "$AUDIT_UNDO" = yes ] && [ "$1" = auditd.service ] && [ -f "$AUDITD_MARKER" ] && marker_has_auditd; then
		return 0
	fi
	ut_now=$(unit_states "$1")
	ut_ne=${ut_now% *}
	ut_na=${ut_now#* }
	# A unit whose package undo removed is gone, as it was. A link that
	# systemctl enable made for it, which removing the package does not
	# take away where the package did not make it (Ubuntu 22.04's
	# fail2ban), points nowhere: it goes.
	if [ "$ut_ne" = not-found ]; then
		if [ "$2" = not-found ]; then
			for ut_l in /etc/systemd/system/*.wants/"$1" /etc/systemd/system/*.requires/"$1"; do
				[ -L "$ut_l" ] && [ ! -e "$ut_l" ] || continue
				tx_push "ln -s $(readlink "$ut_l") $ut_l"
				rm -f "$ut_l" && did "Removed $ut_l, a link to $1, gone with its package"
			done
		fi
		unit_gone "$1"
		return 0
	fi
	ut_want=$2
	[ "$ut_want" != not-found ] || ut_want=disabled
	ut_e=-
	ut_a=-
	if [ "$ut_ne" != "$ut_want" ]; then
		if [ "$4" != '?' ] && [ "$ut_ne" != "$4" ]; then
			left "whether $1 starts at boot ($ut_ne), changed since apply"
		else
			ut_e=$ut_want
		fi
	fi
	if [ "$ut_na" != "$3" ]; then
		if [ "$5" != '?' ] && [ "$ut_na" != "$5" ]; then
			left "whether $1 runs ($ut_na), changed since apply"
		else
			ut_a=$3
		fi
	fi
	[ "$ut_e$ut_a" != -- ] || return 0
	if [ "$AUDIT_UNDO" = yes ] && [ "$1" = auditd.service ]; then
		ut_fo=$(audit_foreign)
		if [ -n "$ut_fo" ]; then
			left "auditd running and starting at boot: other rules files need it ($ut_fo)"
			return 0
		fi
	fi
	tx_push "unit_put $1 $ut_now"
	unit_put "$1" "$ut_e" "$ut_a"
	did "$1 back to $(unit_states "$1" | sed 's/ /, /')"
}
undo_pkg() {
	up_names=$(pkg_token_names "$@" | tr '\n' ' ' | sed 's/ $//')
	if ! pkg_tokens_ok "$@"; then
		left "the packages it installed: the record names them in a form this script does not know"
		return 0
	fi
	if [ "$AUDIT_UNDO" = yes ]; then
		[ -f "$AUDITD_MARKER" ] || left "the packages it installed ($up_names): $AUDITD_MARKER, which says EasyRMM installed auditd, is gone"
		return 0
	fi
	PKG_CONF_SRC=$MANIFEST
	pkg_remove_alone "$@" && up_rc=0 || up_rc=$?
	case $up_rc in
	0)
		[ -z "$PKG_REMOVED" ] || did "Removed the packages it installed: $PKG_REMOVED"
		pkg_dirs_did
		;;
	1) left "the packages it installed ($up_names), because removing them would remove other packages too" ;;
	2) left "the packages it installed ($up_names): the package manager could not remove them$(pkg_why)" ;;
	# Kept, with the record, for an undo once the package database works
	# (or with more time).
	*) abort "the packages it installed ($up_names) could not be removed$(pkg_why)" daemon_reload ;;
	esac
	pkg_left_notes
}
# pkg_left_notes: says what pkg_remove_alone left, and why.
pkg_left_notes() {
	[ -n "$PKG_NOTES" ] || return 0
	[ -z "$M_OUTCOME" ] || return 0
	pl_oifs=$IFS
	IFS=$nl
	for pl_n in $PKG_NOTES; do left "$pl_n"; done
	IFS=$pl_oifs
}
# undo_stream PATH ORIGINAL ORIGINAL-SHA AFTER-SHA: after the packages.
undo_stream() {
	[ "$(sha "$1")" != "$3" ] || return 0
	if [ "$2" = - ]; then us_c=-; else us_c=$MD/$2; fi
	if stream_back "$1" "$us_c" "$4"; then
		did "$STREAM_NOTE"
	else
		left "$STREAM_NOTE"
	fi
}
# undo_gen PATH SHA: a file a program apply started made, removed if it is
# as that program made it. AIDE's baseline, built after apply ended, is
# "?": its sums, which the command that built it wrote, say (gen_sum); one
# still being built when undo stopped it is removed as it is.
undo_gen() {
	[ -e "$1" ] || return 0
	ug_want=$2
	[ "$ug_want" != '?' ] || ug_want=$(gen_sum "$1")
	if [ -n "$ug_want" ] && [ "$ug_want" != '?' ]; then
		if [ "$(sha "$1")" != "$ug_want" ]; then
			GEN_LEFT="$GEN_LEFT $1"
			left "$1, changed since apply made it"
			return 0
		fi
	elif [ "$GEN_STOPPED" != yes ]; then
		GEN_LEFT="$GEN_LEFT $1"
		left "$1: whether it changed since apply made it is not known"
		return 0
	fi
	rm -f "$1" && did "Removed $1"
}
# gen_sum PATH: the SHA-256 the gen-sums file records for PATH.
gen_sum() { awk -v f="$1" '$2 == f && $1 ~ /^[0-9a-f]+$/ && length($1) == 64 { s = $1 } END { print s }' "$MD/files/gen-sums" 2>/dev/null; }

undo_table() {
	have nft && t 30 nft list table inet easyrmm >/dev/null 2>&1 || return 0
	if [ "$1" != '?' ] && [ "$(fw_table_sha)" != "$1" ]; then
		left 'table inet easyrmm, changed since apply (it stays loaded until the next restart: nft delete table inet easyrmm removes it)'
		return 0
	fi
	printf 'table inet easyrmm\ndelete table inet easyrmm\n%s\n' "$(t 30 nft list table inet easyrmm)" >"$TX_DIR/table.nft"
	tx_push "nft -f $TX_DIR/table.nft"
	t 30 nft delete table inet easyrmm && did 'Removed table inet easyrmm'
}
undo_selinux() {
	sl_now=$(selinux_mode)
	[ "$sl_now" != "$1" ] || return 0
	if [ "$2" != '?' ] && [ "$sl_now" != "$2" ]; then
		left "SELinux's mode ($sl_now), changed since apply"
		return 0
	fi
	case $1 in permissive) sl_n=0 ;; *) sl_n=1 ;; esac
	tx_push "setenforce $(case $sl_now in permissive) echo 0 ;; *) echo 1 ;; esac)"
	setenforce "$sl_n" && did "SELinux back to $1"
}
undo_mount() {
	mt_now=$(mount_options "$1")
	mt_back=$(mount_flags_back "$mt_now" "$2")
	[ -n "$mt_back" ] || return 0
	if [ "$3" != '?' ] && [ "$mt_now" != "$3" ]; then
		left "the options $1 is mounted with, changed since apply"
		return 0
	fi
	tx_push "mount -o remount,$(mount_flags_added "$mt_now" "$2") $1"
	t 30 mount -o "remount,$mt_back" "$1" && did "Mounted $1 $mt_back again"
}

# undo_records: reverses every record of the module, last first.
undo_records() {
	ur_oifs=$IFS
	IFS=$nl
	set -f
	# shellcheck disable=SC2013 # IFS is a line feed: one record a line
	for ur_line in $(sed '1d' "$MANIFEST" | awk '{ l[NR] = $0 } END { for (i = NR; i > 0; i--) print l[i] }'); do
		IFS=$tab
		# shellcheck disable=SC2086 # fields separated by tabs, none empty
		set -- $ur_line
		IFS=$ur_oifs
		set +f
		case $1:$# in
		file:6) undo_file "$2" "$3" "$4" "$5" "$6" ;;
		dir:2) undo_dir "$2" ;;
		line:3) undo_line "$2" "$3" ;;
		mode:5) undo_mode "$2" "$3" "$4" "$5" ;;
		sysctl:4) undo_sysctl "$2" "$3" "$4" ;;
		unit:6) undo_unit "$2" "$3" "$4" "$5" "$6" ;;
		pkg:2)
			# Words, never patterns (undo_pkg checks each is a token).
			set -f
			# shellcheck disable=SC2086 # tokens, one word each
			set -- $2
			set +f
			undo_pkg "$@"
			;;
		# Read by undo_pkg.
		conffile:4 | pkgdir:7) ;;
		stream:5) undo_stream "$2" "$3" "$4" "$5" ;;
		pending:2) left "the packages of an installation that was interrupted ($2): remove them by hand if they are not wanted" ;;
		table:3) undo_table "$3" ;;
		gen:3) undo_gen "$2" "$3" ;;
		selinux:4) undo_selinux "$3" "$4" ;;
		mount:4) undo_mount "$2" "$3" "$4" ;;
		*) left "a record this script does not know ($1)" ;;
		esac
		# A package step that failed the undo (undo_pkg) put back the rest.
		[ -z "$M_OUTCOME" ] || break
		IFS=$nl
		set -f
	done
	set +f
	IFS=$ur_oifs
}

# ---------------------------------------------------------------------------
# Apply and undo, module by module
#
# Each apply_<module> runs after the module's check, reads what the check
# left in M_TODO (and the firewall's ports), makes the changes through the
# record functions above, and says what it did with did. On a failure it
# calls abort, which puts back what the run changed; a guard that says no
# calls refuse. Each undo_<module>_before and undo_<module>_after runs
# around undo_records: what a module needs reloaded once its files are back.
# A module without one needs nothing.

# ssh

# ssh_unit: the SSH server's unit: ssh on Debian and Ubuntu, sshd elsewhere.
ssh_unit() {
	for su_u in ssh.service sshd.service; do
		if unit_exists "$su_u"; then
			printf '%s' "$su_u"
			return 0
		fi
	done
}
# ssh_test: sshd -t, with /run/sshd made first where sshd needs it; prints
# what it found wrong.
ssh_test() {
	[ "$FAMILY" != debian ] || [ -e /run/sshd ] || [ ! -d /run ] || mkdir -m 0755 /run/sshd 2>/dev/null
	st_out=$(t 30 sshd -t 2>&1) && return 0
	if [ ! -e /run/sshd ] && [ -d /run ] && text_has "$st_out" '/run/sshd'; then
		mkdir -m 0755 /run/sshd 2>/dev/null && st_out=$(t 30 sshd -t 2>&1) && return 0
	fi
	printf '%s' "$st_out" | head -n 2 | tr '\n' ' '
	return 1
}
# ssh_reload: reloads sshd if it runs; with socket activation, or stopped,
# the configuration applies when it next starts.
ssh_reload() {
	sr_u=$(ssh_unit)
	if [ -n "$sr_u" ] && unit_active "$sr_u"; then
		t 60 systemctl reload "$sr_u" >/dev/null 2>&1 || return 1
		did "Reloaded $sr_u"
	else
		did 'sshd was not running: the configuration applies when it next starts (with socket activation, at the next connection)'
	fi
}

apply_ssh() {
	as_want=$(printf '%s\n' "$M_TODO" | grep -v '^include$')
	[ -n "$as_want" ] || return 0
	# The drop-in's settings: those already in it, then those added now; a
	# keyword given again keeps its new value.
	as_old=
	[ ! -f "$SSH_DROPIN" ] || as_old=$(grep -v '^[[:space:]]*#' "$SSH_DROPIN")
	as_lines=$(printf '%s\n%s\n' "$as_old" "$as_want" |
		awk 'NF { k = tolower($1); if (!(k in v)) o[++n] = k; v[k] = $0 } END { for (i = 1; i <= n; i++) print v[o[i]] }')
	if ! make_dir /etc/ssh/sshd_config.d ||
		! write_own "$SSH_DROPIN" 0600 "# EasyRMM hardening (ADR-0051): written by EasyRMM and removed by its undo.$nl# sshd keeps the first value it reads; this file sorts before the distribution's own.$nl$as_lines$nl"; then
		abort "$SSH_DROPIN could not be written"
		return
	fi
	did "Wrote $SSH_DROPIN: $(printf '%s\n' "$as_want" | tr '\n' ';' | sed -e 's/;$//' -e 's/;/; /g')"
	if text_has "$M_TODO" -x include; then
		if ! add_top_line /etc/ssh/sshd_config "Include $SSH_DROPIN"; then
			abort '/etc/ssh/sshd_config could not be changed'
			return
		fi
		did "Added 'Include $SSH_DROPIN' at the top of /etc/ssh/sshd_config"
	fi
	if ! as_err=$(ssh_test); then
		abort "sshd -t found the new configuration invalid: $as_err"
		return
	fi
	if ! ssh_reload; then
		abort "$(ssh_unit) could not be reloaded" ssh_reload
	fi
}
undo_ssh_after() {
	have sshd || return 0
	if ! ua_err=$(ssh_test); then
		abort "sshd -t found the configuration without EasyRMM's files invalid: $ua_err"
		return
	fi
	ssh_reload || abort "$(ssh_unit) could not be reloaded" ssh_reload
}

# firewall

# fw_ruleset TCP UDP: the rules file, for the ports (one a line) to let in.
fw_ruleset() {
	fr_t=$(printf '%s\n' "$1" | grep . | tr '\n' ',' | sed -e 's/,$//' -e 's/,/, /g')
	fr_u=$(printf '%s\n' "$2" | grep . | tr '\n' ',' | sed -e 's/,$//' -e 's/,/, /g')
	printf '# EasyRMM hardening (ADR-0051): the firewall, loaded at boot by %s.\n' "$FW_UNIT"
	printf '# Written by EasyRMM and removed by its undo. It creates or replaces this table only.\n'
	printf 'table inet easyrmm\ndelete table inet easyrmm\n'
	printf 'table inet easyrmm {\n\tchain input {\n\t\ttype filter hook input priority filter; policy accept;\n'
	printf '\t\tct state established,related accept\n\t\tiifname "lo" accept\n'
	[ -z "$fr_t" ] || printf '\t\ttcp dport { %s } accept\n' "$fr_t"
	[ -z "$fr_u" ] || printf '\t\tudp dport { %s } accept\n' "$fr_u"
	printf '\t\tmeta l4proto tcp ct state new drop\n\t\tmeta l4proto udp drop\n\t}\n}\n'
}
fw_unit() {
	printf '# EasyRMM hardening (ADR-0051): written by EasyRMM and removed by its undo.\n'
	printf '[Unit]\nDescription=EasyRMM hardening: firewall table inet easyrmm\n'
	printf 'DefaultDependencies=no\nWants=network-pre.target\nBefore=network-pre.target shutdown.target\nConflicts=shutdown.target\n\n'
	printf '[Service]\nType=oneshot\nRemainAfterExit=yes\nExecStart=%s -f %s\n\n' "$(command -v nft)" "$FW_FILE"
	printf '[Install]\nWantedBy=sysinit.target\n'
}

apply_firewall() {
	if [ "$SYSTEMD_UP" = no ]; then
		refuse 'systemd is not running, so the firewall could not be kept across restarts.'
		return
	fi
	if ! have nft; then
		if ! pkg_install nftables; then
			abort "nftables could not be installed$(pkg_why)"
			return
		fi
		did 'Installed nftables'
	fi
	# Read again now that nft is here: another firewall may drop already.
	af_else=$(fw_elsewhere)
	if text_has "$af_else" '^UNREADABLE$'; then
		refuse 'nft could not read the rules loaded now, so whether another ruleset drops what it does not allow is unknown.'
		return
	fi
	if [ -n "$af_else" ]; then
		tx_rollback
		M_DONE=
		M_OUTCOME=skipped
		M_WHY="EasyRMM leaves this computer's firewall alone: $(printf '%s\n' "$af_else" | tr '\n' ';' | sed -e 's/;$//' -e 's/;/; /g').$(tx_left_note)"
		return
	fi
	if have sshd && [ -z "$(sshd_ports)" ]; then
		refuse 'sshd is installed, but the ports it listens on could not be read.'
		return
	fi
	# The ports the check found, and those the table lets in already: a
	# later apply never closes a port.
	af_tcp=$M_TCP
	af_udp=$M_UDP
	if [ -f "$FW_FILE" ]; then
		af_old=$(cat "$FW_FILE")
		af_tcp=$(printf '%s\n%s\n' "$af_tcp" "$(fw_table_ports "$af_old" tcp)" | grep . | sort -t- -k1,1n -k2,2n -u)
		af_udp=$(printf '%s\n%s\n' "$af_udp" "$(fw_table_ports "$af_old" udp)" | grep . | sort -t- -k1,1n -k2,2n -u)
	fi
	if ! make_dir "$FW_DIR" || ! write_own "$FW_FILE" 0600 "$(fw_ruleset "$af_tcp" "$af_udp")$nl"; then
		abort "$FW_FILE could not be written"
		return
	fi
	if ! af_err=$(t 30 nft -c -f "$FW_FILE" 2>&1); then
		abort "nft refused the rules: $(printf '%s' "$af_err" | head -n 2 | tr '\n' ' ')"
		return
	fi
	# Loaded and checked before the unit that loads it at boot is enabled.
	if af_prev=$(t 30 nft list table inet easyrmm 2>/dev/null); then
		printf 'table inet easyrmm\ndelete table inet easyrmm\n%s\n' "$af_prev" >"$TX_DIR/table.nft"
		tx_push "nft -f $TX_DIR/table.nft"
	else
		tx_push 'nft delete table inet easyrmm'
	fi
	rec_has table inet-easyrmm || rec_add "table${tab}inet-easyrmm$tab?"
	if ! af_err=$(t 30 nft -f "$FW_FILE" 2>&1); then
		abort "nft could not load the rules: $(printf '%s' "$af_err" | head -n 2 | tr '\n' ' ')"
		return
	fi
	rec_set table inet-easyrmm 3 "$(fw_table_sha)"
	af_live=$(t 30 nft -n list table inet easyrmm 2>/dev/null)
	for af_p in $(sshd_ports); do
		if ! fw_table_allows "$af_live" tcp "$af_p"; then
			abort "the loaded table does not let in sshd's port $af_p"
			return
		fi
	done
	did "Loaded table inet easyrmm: new TCP connections and UDP packets are dropped except to TCP $(printf '%s\n' "$af_tcp" | grep . | tr '\n' ' ')and UDP $(printf '%s\n' "$af_udp" | grep . | tr '\n' ' ' | sed 's/ $//')"
	tx_push daemon_reload
	if ! write_own "$FW_UNIT_FILE" 0644 "$(fw_unit)$nl"; then
		abort "$FW_UNIT_FILE could not be written"
		return
	fi
	daemon_reload
	if ! turn_on "$FW_UNIT"; then
		abort "$FW_UNIT could not be enabled and started"
		return
	fi
	did "Enabled $FW_UNIT, which loads $FW_FILE at boot"
}
undo_firewall_after() { daemon_reload; }

# fail2ban

# f2b_known DUMP KEY: the sshd jail's KEY in fail2ban-client -d's dump.
f2b_known() {
	printf '%s\n' "$1" | sed -n "s/^\\['set', 'sshd', '$2', '\\{0,1\\}\\([^']*\\)'\\{0,1\\}\\]\$/\\1/p" | tail -n 1
}
# f2b_ignored DUMP: the addresses and ranges the sshd jail never bans, as
# words (the dump has one addignoreip command for each, or one for all).
f2b_ignored() {
	printf '%s\n' "$1" | sed -n "s/^\\['set', 'sshd', 'addignoreip', //p" | tr -d "[]',"
}
# f2b_seconds TIME: fail2ban's time (600, 10m, 1h, 1d, 1w) in seconds, or
# nothing when it is another form; -1 (banned for ever) stays -1.
f2b_seconds() {
	printf '%s\n' "$1" | awk '
	/^-1$/ { print -1; exit }
	/^[0-9]+(s|m|h|d|w)?$/ {
		n = $0 + 0; u = substr($0, length($0))
		if (u == "m") n *= 60; else if (u == "h") n *= 3600; else if (u == "d") n *= 86400; else if (u == "w") n *= 604800
		print n }'
}
# f2b_actions: the ban action and the one for all ports, for the firewall in
# use; nftables's needs nft.
f2b_actions() {
	if grep -Eqs '^[[:space:]]*ENABLED[[:space:]]*=[[:space:]]*yes' /etc/ufw/ufw.conf; then
		printf 'ufw ufw'
	elif unit_active firewalld.service; then
		printf 'firewallcmd-rich-rules firewallcmd-rich-rules'
	elif nf_tables_present || ! grep -qsx filter /proc/net/ip_tables_names; then
		printf 'nftables-multiport nftables-allports'
	else
		printf 'iptables-multiport iptables-allports'
	fi
}

apply_fail2ban() {
	af_pk=
	if ! have fail2ban-client; then
		if [ "$FAMILY" = rhel ] && ! epel_enabled; then
			if [ "$OS_ID" = rhel ]; then
				refuse 'On Red Hat Enterprise Linux itself EPEL is added by hand (it needs the CodeReady Builder repository); EasyRMM adds it on Rocky Linux and AlmaLinux only.'
				return
			fi
			af_pk=epel-release
		fi
		case $FAMILY in
		debian) af_pk="$af_pk fail2ban" ;;
		*) af_pk="$af_pk fail2ban-server" ;;
		esac
	fi
	af_backend=
	if [ ! -e /var/log/auth.log ] && [ ! -e /var/log/secure ]; then
		af_backend=systemd
		pkg_installed python3-systemd || af_pk="$af_pk python3-systemd"
	fi
	# shellcheck disable=SC2046 # two words
	set -- $(f2b_actions)
	af_ban=$1
	af_all=$2
	case $af_ban in nftables-*) have nft || af_pk="$af_pk nftables" ;; esac
	# Recorded before an installation, which on Debian starts the service.
	if ! rec_unit fail2ban.service; then
		abort 'the record could not be written'
		return
	fi
	if [ -n "$af_pk" ]; then
		case $af_pk in *epel-release*)
			if ! pkg_install epel-release; then
				abort "EPEL could not be added$(pkg_why)"
				return
			fi
			did 'Added the EPEL repository (epel-release); the patching engine now updates its packages too'
			af_pk=${af_pk#*epel-release}
			;;
		esac
		# shellcheck disable=SC2086 # package names, one word each
		if ! pkg_install $af_pk; then
			abort "$(printf '%s' "$af_pk" | sed 's/^ *//') could not be installed$(pkg_why)"
			return
		fi
		did "Installed$af_pk"
	fi
	sshd_effective
	af_ports=$(sshd_ports | tr '\n' ',' | sed 's/,$//')
	af_head="# EasyRMM hardening (ADR-0051): written by EasyRMM and removed by its undo.${nl}[sshd]${nl}enabled = true${nl}port = ${af_ports:-ssh}$nl"
	af_tail="banaction = $af_ban${nl}banaction_allports = $af_all$nl"
	[ -z "$af_backend" ] || af_tail="backend = $af_backend$nl$af_tail"
	# Those an earlier apply wrote stay never banned: a later apply never
	# bans more.
	af_ignore='127.0.0.1/8 ::1'
	[ ! -f "$F2B_FILE" ] || af_ignore="$af_ignore $(sed -n 's/^ignoreip = //p' "$F2B_FILE")"
	# The jail on without EasyRMM's values first, to read what the rest of
	# the configuration gives it.
	if ! write_own "$F2B_FILE" 0644 "$af_head$af_tail"; then
		abort "$F2B_FILE could not be written"
		return
	fi
	# Each value as strict as the one configured, or stricter.
	af_dump=$(t 60 fail2ban-client -d 2>/dev/null)
	af_max=$(f2b_known "$af_dump" maxretry)
	case $af_max in '' | *[!0-9]*) af_max=5 ;; *) [ "$af_max" -ge 1 ] && [ "$af_max" -le 5 ] || af_max=5 ;; esac
	af_find=$(f2b_seconds "$(f2b_known "$af_dump" findtime)")
	case $af_find in '' | -*) af_find=600 ;; *) [ "$af_find" -ge 600 ] || af_find=600 ;; esac
	af_time=$(f2b_seconds "$(f2b_known "$af_dump" bantime)")
	case $af_time in -1) ;; '' | -*) af_time=3600 ;; *) [ "$af_time" -ge 3600 ] || af_time=3600 ;; esac
	# Repeat offenders' bans grow (bantime.increment) up to a day, or the
	# longer time configured: without a cap they grow without end, and an
	# office behind one address that mistypes a password now and then is
	# locked out for weeks.
	af_maxt=86400
	[ "$af_time" = -1 ] || [ "$af_time" -le "$af_maxt" ] || af_maxt=$af_time
	af_cmax=$(f2b_seconds "$(f2b_known "$af_dump" bantime.maxtime)")
	case $af_cmax in '' | -*) ;; *) [ "$af_cmax" -le "$af_maxt" ] || af_maxt=$af_cmax ;; esac
	# Never banned: loopback, what the configuration already leaves alone,
	# the ranges given now and those an earlier apply wrote.
	af_ignore="$af_ignore $(f2b_ignored "$af_dump")"
	[ -z "$OPT_TRUSTED" ] || af_ignore="$af_ignore $(printf '%s' "$OPT_TRUSTED" | tr ',' ' ')"
	# shellcheck disable=SC2086 # addresses and ranges, one word each
	af_ignore=$(printf '%s\n' $af_ignore | awk '!s[$0]++' | tr '\n' ' ' | sed 's/ $//')
	af_conf="${af_head}maxretry = $af_max${nl}findtime = $af_find${nl}bantime = $af_time${nl}bantime.increment = true${nl}bantime.maxtime = $af_maxt$nl"
	af_conf="${af_conf}ignoreip = $af_ignore$nl$af_tail"
	if ! write_own "$F2B_FILE" 0644 "$af_conf"; then
		abort "$F2B_FILE could not be written"
		return
	fi
	if ! af_err=$(t 120 fail2ban-client -t 2>&1); then
		abort "fail2ban's configuration test failed: $(printf '%s\n' "$af_err" | grep -i error | head -n 2 | tr '\n' ' ')"
		return
	fi
	did "Wrote $F2B_FILE: jail sshd on port ${af_ports:-ssh}, $af_max failures in $af_find seconds bans for $af_time seconds, longer for repeat offenders up to $af_maxt seconds; never banned: $af_ignore; banned with $af_ban"
	unit_put fail2ban.service enabled -
	# Restarted, not reloaded: fail2ban 1.1 (Debian 13) reloads a jail whose
	# ban action changed into one with no action at all.
	if unit_active fail2ban.service; then
		t 120 systemctl restart fail2ban.service >/dev/null 2>&1
	else
		t 120 systemctl start fail2ban.service >/dev/null 2>&1
	fi
	after_unit fail2ban.service
	# The jail, once fail2ban has read its logs, and its ban action, which
	# fail2ban adds to the jail after the jail itself.
	af_n=0
	af_act=
	until t 20 fail2ban-client status sshd >/dev/null 2>&1 && af_act=$(f2b_jail_actions | tr '\n' ' ' | sed 's/ $//') && [ -n "$af_act" ]; do
		af_n=$((af_n + 1))
		if [ "$af_n" -gt 60 ] || [ "$OUT_OF_TIME" = yes ]; then
			if t 20 fail2ban-client status sshd >/dev/null 2>&1; then
				abort 'the sshd jail started with no ban action (journalctl -u fail2ban says why)' 'unit_active fail2ban.service && t 120 systemctl restart fail2ban.service'
			else
				abort 'the sshd jail did not start (journalctl -u fail2ban says why)' 'unit_active fail2ban.service && t 120 systemctl restart fail2ban.service'
			fi
			return
		fi
		sleep 2
	done
	did "fail2ban runs and starts at boot; the sshd jail is running and bans with $af_act"
}
undo_fail2ban_after() {
	# Restarted, as apply does.
	! unit_active fail2ban.service || t 120 systemctl restart fail2ban.service >/dev/null 2>&1
	return 0
}

# kernel

apply_kernel() {
	[ -n "$M_TODO" ] || return 0
	# Docker mounts /proc/sys read-only: a container's network settings are
	# set when it is created.
	ak_first=$(printf '%s\n' "$M_TODO" | head -n 1)
	if [ ! -w "$(sysctl_path "${ak_first%% *}")" ]; then
		if [ "$IN_CONTAINER" = yes ]; then
			refuse "In this container ($CONTAINER) /proc/sys is read-only: its network settings are set when the container is created."
		else
			refuse '/proc/sys is read-only here.'
		fi
		return
	fi
	# The file: the parameters already in it, then those set now.
	ak_old=
	[ ! -f "$SYSCTL_FILE" ] || ak_old=$(grep '=' "$SYSCTL_FILE" | grep -v '^[[:space:]]*[#;]' | sed 's/[[:space:]]*=[[:space:]]*/ /')
	ak_lines=$(printf '%s\n%s\n' "$ak_old" "$M_TODO" |
		awk 'NF == 2 { if (!($1 in v)) o[++n] = $1; v[$1] = $2 } END { for (i = 1; i <= n; i++) print o[i] " = " v[o[i]] }')
	for ak_n in $(printf '%s\n' "$M_TODO" | cut -d' ' -f1); do
		if ! rec_sysctl "$ak_n"; then
			abort 'the record could not be written'
			return
		fi
	done
	if ! write_own "$SYSCTL_FILE" 0644 "# EasyRMM hardening (ADR-0051): written by EasyRMM and removed by its undo.$nl# Later files in /etc/sysctl.d still win. IP forwarding is never set here.$nl$ak_lines$nl"; then
		abort "$SYSCTL_FILE could not be written"
		return
	fi
	ak_err=$(t 60 sysctl -q -p "$SYSCTL_FILE" 2>&1)
	ak_bad=
	for ak_n in $(printf '%s\n' "$M_TODO" | cut -d' ' -f1); do
		after_sysctl "$ak_n"
		ak_want=$(printf '%s\n' "$M_TODO" | awk -v n="$ak_n" '$1 == n { print $2; exit }')
		[ "$(sysctl_now "$ak_n")" = "$ak_want" ] || ak_bad="$ak_bad $ak_n"
	done
	if [ -n "$ak_bad" ]; then
		abort "sysctl -p did not set$ak_bad: $(printf '%s' "$ak_err" | head -n 1)"
		return
	fi
	did "Set $(printf '%s\n' "$M_TODO" | sed 's/ / = /' | tr '\n' ';' | sed -e 's/;$//' -e 's/;/; /g') in $SYSCTL_FILE, applied with sysctl -p on that file only"
}

# audit

# The rules, by the keys the check's patterns find.
audit_rules() {
	printf '## EasyRMM hardening (ADR-0051): written by EasyRMM and removed by its undo.\n'
	printf '## Never immutable (-e 2), never panic (-f 2).\n'
	for ar_f in /etc/passwd /etc/group /etc/shadow /etc/gshadow; do
		printf -- '-w %s -p wa -k easyrmm-hardening-accounts\n' "$ar_f"
	done
	printf -- '-w /etc/sudoers -p wa -k easyrmm-hardening-sudoers\n-w /etc/sudoers.d -p wa -k easyrmm-hardening-sudoers\n'
	printf -- '-w /etc/ssh/sshd_config -p wa -k easyrmm-hardening-sshd\n'
	[ ! -d /etc/ssh/sshd_config.d ] || printf -- '-w /etc/ssh/sshd_config.d -p wa -k easyrmm-hardening-sshd\n'
	printf -- '-w /etc/pam.d -p wa -k easyrmm-hardening-pam\n'
	for ar_a in b64 b32; do
		printf -- '-a always,exit -F arch=%s -S adjtimex,settimeofday,clock_settime -k easyrmm-hardening-time\n' "$ar_a"
		printf -- '-a always,exit -F arch=%s -S init_module,finit_module,delete_module -k easyrmm-hardening-modules\n' "$ar_a"
		printf -- '-a always,exit -F arch=%s -S mount -F auid!=unset -k easyrmm-hardening-mounts\n' "$ar_a"
		printf -- '-a always,exit -F arch=%s -S execve -C uid!=euid -F euid=0 -k easyrmm-hardening-privileged\n' "$ar_a"
	done
}
audit_immutable() { t 20 auditctl -s 2>/dev/null | grep -q '^enabled 2'; }
# audit_foreign: the rules files in /etc/audit/rules.d that keep auditd,
# separated by spaces: all but those auditd's packages shipped, unchanged.
# Undo asks after removing hardening's own, so that one counts only when
# undo left it (an administrator changed it).
audit_foreign() {
	fo_list=
	for fo_f in /etc/audit/rules.d/*.rules; do
		[ -f "$fo_f" ] || continue
		audit_shipped "$fo_f" || fo_list="$fo_list $fo_f"
	done
	printf '%s' "${fo_list# }"
}
# audit_shipped PATH: whether auditd's packages shipped PATH and it is as
# shipped (dpkg's MD5 of its configuration files, RPM's SHA-256 digests).
# audit 4's audit-rules ships /etc/audit/rules.d/audit.rules without
# contents (a ghost) and makes it when it is installed, a copy of the base
# rules it ships under /usr/share/audit-rules: as that copy, it is shipped.
audit_shipped() {
	case $FAMILY in
	debian)
		# shellcheck disable=SC2016 # dpkg-query's field, not the shell's
		ah_sum=$(t 30 dpkg-query -W -f='${Conffiles}\n' auditd 2>/dev/null | awk -v f="$1" '$1 == f { print $2 }')
		[ ${#ah_sum} -eq 32 ] && [ "$(md5sum <"$1" | cut -c1-32)" = "$ah_sum" ]
		;;
	*)
		ah_sum=$(t 30 rpm -q --qf '[%{FILENAMES} %{FILEDIGESTS}\n]' audit audit-rules 2>/dev/null | awk -v f="$1" '
			$1 == f && $2 != "" { s = $2 }
			$1 == "/usr/share/audit-rules/10-base-config.rules" { b = $2 }
			END { if (s == "" && f == "/etc/audit/rules.d/audit.rules") s = b; print s }')
		[ ${#ah_sum} -eq 64 ] && [ "$(sha256sum <"$1" | cut -c1-64)" = "$ah_sum" ]
		;;
	esac
}
# audit_mark TOKEN...: the marker, after the audit module installed auditd:
# the packages, as tokens (PKG_TOKEN), then their configuration files
# (pkg_conffiles) and the directories the installation changed (PKG_DIRS).
# Written only into a directory of root's alone (marker_dir_ok).
audit_mark() {
	mk_dir=${AUDITD_MARKER%/*}
	if [ ! -e "$mk_dir" ] && [ ! -L "$mk_dir" ]; then
		mkdir -m 0755 "$mk_dir" || return 1
		tx_push "rmdir $mk_dir"
	fi
	marker_dir_ok || return 1
	tx_push "rm -f $AUDITD_MARKER"
	mk_names=$(pkg_token_names "$@")
	# shellcheck disable=SC2086 # package names, one word each
	{
		printf '# EasyRMM hardening (ADR-0051) installed auditd with these packages. Whoever removes\n# auditd last (when no other rules file needs it) removes them and this file.\n%s\n' "$*" &&
			pkg_conffiles $mk_names &&
			if [ -n "$PKG_DIRS" ]; then printf '%s\n' "$PKG_DIRS"; fi
	} >"$AUDITD_MARKER.new" && mv -f "$AUDITD_MARKER.new" "$AUDITD_MARKER"
}
# marker_dir_ok: whether the marker's directory is a directory, not a
# symbolic link, owned by root and written by root alone: anyone else could
# put a link in its place, or another file.
marker_dir_ok() {
	md_d=${AUDITD_MARKER%/*}
	[ -d "$md_d" ] && [ ! -L "$md_d" ] || return 1
	md_s=$(stat -c '%u:%g %a' "$md_d" 2>/dev/null) || return 1
	[ "${md_s% *}" = 0:0 ] || return 1
	case ${md_s#* } in *[2367]? | *[2367]) return 1 ;; esac
	return 0
}
# marker_tokens: the marker's package tokens, one a line.
marker_tokens() { sed -n '/^#/d; /^conffile	/d; /^pkgdir	/d; p' "$AUDITD_MARKER" 2>/dev/null | tr ' ' '\n' | grep .; }
# marker_has_auditd: whether the marker's packages hold auditd (auditd on
# Debian and Ubuntu, audit elsewhere).
marker_has_auditd() { marker_tokens | cut -d/ -f1 | grep -Eqx 'auditd(:[a-z0-9]+)?|audit\.[A-Za-z0-9_]+'; }
audit_load() { t 120 augenrules --load >/dev/null 2>&1; }

apply_audit() {
	[ -n "$M_TODO" ] || return 0
	if text_has "$M_TODO" -x install; then
		# audit 4 (RHEL 10 and its rebuilds, Fedora) keeps auditctl,
		# augenrules and /etc/audit/rules.d in audit-rules, which an image
		# may leave out.
		case $FAMILY:${OS_VERSION%%.*} in
		debian:*) aa_p=auditd ;;
		fedora:* | rhel:1[0-9]) aa_p='audit audit-rules' ;;
		*) aa_p=audit ;;
		esac
		# shellcheck disable=SC2086 # package names, one word each
		if ! rec_unit auditd.service || ! pkg_install $aa_p; then
			abort "$aa_p could not be installed$(pkg_why)"
			return
		fi
		# shellcheck disable=SC2086 # tokens, one word each
		if [ -n "$PKG_NEW" ] && ! audit_mark $PKG_NEW; then
			abort "$AUDITD_MARKER could not be written (${AUDITD_MARKER%/*} must be a directory, not a link, that root owns and root alone may write)"
			return
		fi
		did "Installed $aa_p; $AUDITD_MARKER says EasyRMM did"
	fi
	if ! unit_active auditd.service || ! unit_enabled auditd.service; then
		if ! turn_on auditd.service; then
			abort 'auditd could not be started'
			return
		fi
		did 'auditd runs and starts at boot'
	fi
	text_has "$M_TODO" -x rules || return 0
	# Put back on a failure: the rules file first, then the rules loaded
	# again, then $AUDIT_PREV, where augenrules keeps the rules it
	# replaces, gone if this apply made it.
	aa_prev=no
	if [ ! -e "$AUDIT_PREV" ]; then
		aa_prev=yes
		tx_push "rm -f $AUDIT_PREV"
	fi
	tx_push audit_load
	if ! write_own "$AUDIT_FILE" 0640 "$(audit_rules)$nl"; then
		abort "$AUDIT_FILE could not be written"
		return
	fi
	# Undo removes $AUDIT_PREV where this apply made it, as it made it.
	[ "$aa_prev" = no ] || rec_has gen "$AUDIT_PREV" || rec_add "gen$tab$AUDIT_PREV$tab?"
	if audit_immutable; then
		did "Wrote $AUDIT_FILE; the loaded rules are immutable, so these load at the next restart (and undo cannot unload them before one)"
		return
	fi
	if ! audit_load || ! t 20 auditctl -l 2>/dev/null | grep -q 'key=easyrmm-hardening-'; then
		abort 'augenrules --load did not load the rules'
		return
	fi
	[ "$aa_prev" = no ] || [ ! -f "$AUDIT_PREV" ] || rec_set gen "$AUDIT_PREV" 3 "$(sha "$AUDIT_PREV")"
	did "Wrote $AUDIT_FILE and loaded it with augenrules --load: changes to accounts, sudoers, SSH and PAM configuration, the time, kernel modules, mounts, and commands run with raised privileges"
}
undo_audit_after() {
	if have augenrules; then
		# Loading the rules makes $AUDIT_PREV again: one undo left (changed
		# since apply) is kept as it is.
		ua_keep=no
		if in_words "$AUDIT_PREV" "$GEN_LEFT" && [ -f "$AUDIT_PREV" ]; then
			cp -p "$AUDIT_PREV" "$TX_DIR/audit.rules.prev" && ua_keep=yes
		fi
		if audit_immutable; then
			did 'The loaded audit rules are immutable: they stay loaded until the next restart'
		elif ! audit_load; then
			left 'the audit rules loaded now: augenrules --load failed'
		fi
		if [ "$ua_keep" = yes ]; then
			put_copy "$TX_DIR/audit.rules.prev" "$AUDIT_PREV"
		elif rec_has gen "$AUDIT_PREV" && ! in_words "$AUDIT_PREV" "$GEN_LEFT"; then
			rm -f "$AUDIT_PREV"
		fi
	fi
	# auditd, if EasyRMM installed it and no other rules file needs it. An
	# auditd that was there before is never removed.
	[ -f "$AUDITD_MARKER" ] || return 0
	ua_fo=$(audit_foreign)
	if [ -n "$ua_fo" ]; then
		left "auditd, which EasyRMM installed: other rules files need it ($ua_fo); $AUDITD_MARKER stays, for whoever removes the last of them"
		return 0
	fi
	if ! marker_dir_ok; then
		left "auditd, which EasyRMM installed: ${AUDITD_MARKER%/*} is not a directory, not a link, that root owns and root alone may write, so $AUDITD_MARKER is not read"
		return 0
	fi
	# Split into words with globbing off: words, never patterns.
	set -f
	# shellcheck disable=SC2046 # tokens, one word each
	set -- $(marker_tokens)
	set +f
	if ! pkg_tokens_ok "$@"; then
		left "auditd, which EasyRMM installed: $AUDITD_MARKER names its packages in a form this script does not know, so they were left"
		return 0
	fi
	ua_pk=$(pkg_token_names "$@" | tr '\n' ' ' | sed 's/ $//')
	PKG_CONF_SRC=$AUDITD_MARKER
	pkg_remove_alone "$@" && ua_rc=0 || ua_rc=$?
	case $ua_rc in
	0)
		rm -f "$AUDITD_MARKER"
		rmdir "${AUDITD_MARKER%/*}" 2>/dev/null
		did "Removed the packages EasyRMM installed for auditd${PKG_REMOVED:+: $PKG_REMOVED}, and $AUDITD_MARKER"
		pkg_dirs_did
		;;
	1) left "auditd, which EasyRMM installed: removing its packages ($ua_pk) would remove other packages too" ;;
	2) left "auditd, which EasyRMM installed: the package manager could not remove its packages ($ua_pk)$(pkg_why)" ;;
	*) abort "the packages EasyRMM installed for auditd ($ua_pk) could not be removed$(pkg_why)" audit_load ;;
	esac
	pkg_left_notes
}

# permissions

apply_permissions() {
	ap_oifs=$IFS
	IFS=$nl
	for ap_l in $M_TODO; do
		IFS=$ap_oifs
		ap_b=$(stat -L -c %a "${ap_l% *}")
		if ! narrow_mode "${ap_l% *}" "${ap_l##* }"; then
			abort "the mode of ${ap_l% *} could not be changed"
			return
		fi
		did "${ap_l% *}: mode $(printf '%04o' "0$ap_b") to ${ap_l##* }"
		IFS=$nl
	done
	IFS=$ap_oifs
}

# services

# reload_first UNIT...: reloads the first of the units that runs.
reload_first() {
	for rf_u in "$@"; do
		if unit_active "$rf_u"; then
			t 60 systemctl reload "$rf_u" >/dev/null 2>&1 || t 60 systemctl restart "$rf_u" >/dev/null 2>&1
			return
		fi
	done
}
reload_inetd() {
	reload_first xinetd.service
	reload_first openbsd-inetd.service inetutils-inetd.service inetd.service
}

apply_services() {
	[ "$M_BAD" -gt 0 ] || return 0
	sv_oifs=$IFS
	IFS=$nl
	set -f
	for sv_e in $LEGACY_SERVICES; do
		IFS=$sv_oifs
		set +f
		sv_name=${sv_e%%|*}
		sv_rest=${sv_e#*|}
		for sv_u in ${sv_rest%%|*}; do
			unit_active "$sv_u" || unit_enabled "$sv_u" || continue
			if ! rec_unit "$sv_u"; then
				abort 'the record could not be written'
				return
			fi
			unit_put "$sv_u" disabled inactive
			after_unit "$sv_u"
			if unit_active "$sv_u" || unit_enabled "$sv_u"; then
				abort "$sv_u could not be stopped and disabled"
				return
			fi
			did "Turned $sv_name off: stopped and disabled $sv_u"
		done
		for sv_x in ${sv_rest#*|}; do
			for sv_f in /etc/xinetd.d/* /etc/xinetd.conf; do
				{ [ -f "$sv_f" ] && xinetd_on "$sv_x"; } || continue
				awk -v name="$sv_x" '
				$1 == "service" { insvc = ($2 == name); seen = 0 }
				insvc && $1 == "disable" { print "\tdisable\t\t= yes"; seen = 1; next }
				insvc && $1 == "}" { if (!seen) print "\tdisable\t\t= yes"; insvc = 0 }
				{ print }' "$sv_f" >"$sv_f.easyrmm-new"
				[ "$(sha "$sv_f")" != "$(sha "$sv_f.easyrmm-new")" ] || {
					rm -f "$sv_f.easyrmm-new"
					continue
				}
				if ! write_edit "$sv_f"; then
					abort "$sv_f could not be changed"
					return
				fi
				did "Turned $sv_name off in xinetd: disable = yes in $sv_f"
			done
			if inetd_on "$sv_x"; then
				sed "s/^\\([[:space:]]*${sv_x}[[:space:]]\\)/#<off by EasyRMM># \\1/" /etc/inetd.conf >/etc/inetd.conf.easyrmm-new
				if ! write_edit /etc/inetd.conf; then
					abort '/etc/inetd.conf could not be changed'
					return
				fi
				did "Turned $sv_name off in /etc/inetd.conf (its line commented out)"
			fi
		done
		IFS=$nl
		set -f
	done
	set +f
	IFS=$sv_oifs
	tx_push reload_inetd
	reload_inetd
}
undo_services_after() { reload_inetd; }

# kernel-modules and usb-storage

# modprobe_file MODULE...: install directives that keep them from loading.
modprobe_file() {
	printf '# EasyRMM hardening (ADR-0051): written by EasyRMM and removed by its undo.\n'
	for mf_m in "$@"; do
		printf 'install %s /bin/false\nblacklist %s\n' "$mf_m" "$mf_m"
	done
}

apply_kernel_modules() {
	[ -n "$M_TODO" ] || return 0
	ak_mods=
	[ ! -f "$MODULES_FILE" ] || ak_mods=$(sed -n 's/^install \([^ ]*\) .*/\1/p' "$MODULES_FILE" | tr '\n' ' ')
	for ak_m in $M_TODO; do
		in_words "$ak_m" "$ak_mods" || ak_mods="$ak_mods $ak_m"
	done
	# shellcheck disable=SC2086 # module names, one word each
	if ! write_own "$MODULES_FILE" 0644 "$(modprobe_file $ak_mods)$nl"; then
		abort "$MODULES_FILE could not be written"
		return
	fi
	MODPROBE_READ=no
	modprobe_config
	for ak_m in $M_TODO; do
		if ! kept_from_loading "$ak_m"; then
			abort "modprobe does not read $MODULES_FILE as expected ($ak_m)"
			return
		fi
	done
	did "Kept from loading:$M_TODO ($MODULES_FILE)"
}
# undo_kernel_after: an initramfs rebuilt since apply (by usb-storage's
# apply, or a kernel's update) may hold the kernel parameters' file, which
# dracut takes in and applies at boot before /etc is read.
undo_kernel_after() {
	text_has "$M_DONE" -xF "Removed $SYSCTL_FILE" || return 0
	initramfs_holds "$SYSCTL_FILE" || return 0
	if initramfs_update; then
		did "Rebuilt the initramfs, which held $SYSCTL_FILE"
	else
		left "the initramfs, which holds $SYSCTL_FILE and could not be rebuilt ($IU_ERR): run $iu_cmd"
	fi
}
undo_kernel_modules_after() {
	# Apply leaves the initramfs alone, but one rebuilt since (by
	# usb-storage's apply, or a kernel's update) took the file in.
	text_has "$M_DONE" -xF "Removed $MODULES_FILE" || return 0
	initramfs_holds "$MODULES_FILE" || return 0
	if initramfs_update; then
		did "Rebuilt the initramfs, which held $MODULES_FILE"
	else
		left "the initramfs, which holds $MODULES_FILE and could not be rebuilt ($IU_ERR): run $iu_cmd"
	fi
}

# initramfs_update: the initramfs of every kernel, rebuilt with
# /etc/modprobe.d as it is now; IU_ERR says why it failed.
initramfs_update() {
	case $FAMILY in
	debian) iu_cmd='update-initramfs -u -k all' ;;
	*) iu_cmd='dracut -f --regenerate-all' ;;
	esac
	iu_rc=0
	if ! have "${iu_cmd%% *}"; then
		iu_rc=127
	elif ! need_time "$INITRAMFS_MIN" "rebuild the initramfs"; then
		IU_ERR=$PKG_ERR
		return 1
	else
		# shellcheck disable=SC2086 # the command and its arguments
		t 1200 $iu_cmd >"$TX_DIR/initramfs.log" 2>&1 || iu_rc=$?
	fi
	case $T_CAPPED:$iu_rc in
	*:0) IU_ERR= ;;
	yes:124 | yes:137) IU_ERR="$iu_cmd was stopped at the end of the job's time" ;;
	*:124 | *:137) IU_ERR="$iu_cmd did not finish in 20 minutes and was stopped" ;;
	*:127) IU_ERR="${iu_cmd%% *} is not installed" ;;
	*) IU_ERR="$iu_cmd failed: $(tail -n 1 "$TX_DIR/initramfs.log" | cut -c1-160)" ;;
	esac
	[ "$iu_rc" -eq 0 ]
}
# initramfs_put_back: a rollback's rebuild, after the file is back, where
# the run began one (IU_TRIED).
# shellcheck disable=SC2329 # tx_rollback runs it, from the stack
initramfs_put_back() { [ "$IU_TRIED" = no ] || initramfs_update; }
# initramfs_holds FILE: whether the initramfs of a kernel, one
# initramfs_update rebuilds, holds FILE.
initramfs_holds() {
	for ih_i in /boot/initrd.img-* /boot/initramfs-*.img; do
		case $ih_i in *'*'* | *kdump.img | */initramfs-0-rescue-*) continue ;; esac
		if have lsinitramfs; then
			t 300 lsinitramfs "$ih_i"
		elif have lsinitrd; then
			t 300 lsinitrd "$ih_i"
		fi 2>/dev/null | grep -qF "${1#/}" && return 0
	done
	return 1
}

apply_usb_storage() {
	text_has "$M_TODO" -x usb-storage || return 0
	# Put back on a failure: the file first, then the initramfs rebuilt
	# again if this run began rebuilding it (a failure part way can leave
	# some kernels' rebuilt).
	IU_TRIED=no
	tx_push initramfs_put_back
	if ! write_own "$USB_FILE" 0644 "$(modprobe_file usb-storage)$nl"; then
		abort "$USB_FILE could not be written"
		return
	fi
	MODPROBE_READ=no
	modprobe_config
	if ! kept_from_loading usb_storage && ! kept_from_loading usb-storage; then
		abort "modprobe does not read $USB_FILE as expected"
		return
	fi
	IU_TRIED=yes
	if ! initramfs_update; then
		abort "the initramfs could not be rebuilt: $IU_ERR"
		return
	fi
	did "Kept usb-storage from loading ($USB_FILE) and rebuilt the initramfs: USB disks and drives stop working"
	! module_loaded usb_storage || did 'usb-storage is loaded now: it stays loaded until the next restart'
}
undo_usb_storage_after() {
	# Only when undo removed the file.
	text_has "$M_DONE" -xF "Removed $USB_FILE" || return 0
	if initramfs_update; then
		did 'Rebuilt the initramfs'
	else
		left "the initramfs, which could not be rebuilt ($IU_ERR): run $iu_cmd"
	fi
}

# sudo

apply_sudo() {
	case $M_TODO in
	'') return 0 ;;
	refused\ *)
		refuse "${M_TODO#refused }."
		return
		;;
	esac
	au_lines=
	[ ! -f "$SUDO_FILE" ] || au_lines=$(grep -v '^[[:space:]]*#' "$SUDO_FILE")
	text_has "$M_TODO" -x use_pty && au_lines="$au_lines${nl}Defaults use_pty"
	text_has "$M_TODO" -x logfile && au_lines="$au_lines${nl}Defaults logfile=$SUDO_LOG"
	au_lines=$(printf '%s\n' "$au_lines" | grep . | awk '!s[$0]++')
	if text_has "$M_TODO" -Ex 'use_pty|logfile|mode'; then
		au_new="# EasyRMM hardening (ADR-0051): written by EasyRMM and removed by its undo.$nl$au_lines$nl"
		printf '%s' "$au_new" >"$TX_DIR/sudoers"
		if ! au_err=$(t 20 visudo -c -q -f "$TX_DIR/sudoers" 2>&1); then
			refuse "visudo -c refused the new sudoers file: $au_err"
			return
		fi
		if ! write_own "$SUDO_FILE" 0440 "$au_new"; then
			abort "$SUDO_FILE could not be written"
			return
		fi
		if ! t 20 visudo -c -q >/dev/null 2>&1; then
			abort 'visudo -c failed with the new file in place'
			return
		fi
		did "Wrote $SUDO_FILE (mode 0440, checked with visudo -c): $(printf '%s\n' "$au_lines" | tr '\n' ';' | sed -e 's/;$//' -e 's/;/; /g')"
	fi
	au_log=$(printf '%s\n' "$M_TODO" | sed -n 's/^logrotate //p')
	[ -n "$au_log" ] || return 0
	case $au_log in /*) ;; *)
		did "Left as it is: sudo's log file $au_log, which is not a full path, so no logrotate entry was added"
		return 0
		;;
	esac
	case $au_log in *[!A-Za-z0-9/._-]*)
		did "Left as it is: no logrotate entry for $au_log, whose name has characters logrotate would read otherwise"
		return 0
		;;
	esac
	if ! write_own "$SUDO_ROTATE" 0644 "# EasyRMM hardening (ADR-0051): written by EasyRMM and removed by its undo.$nl$au_log {${nl}	monthly${nl}	rotate 12${nl}	compress${nl}	delaycompress${nl}	missingok${nl}	notifempty${nl}	create 0600 root root$nl}$nl"; then
		abort "$SUDO_ROTATE could not be written"
		return
	fi
	did "Wrote $SUDO_ROTATE: $au_log rotated monthly, a year kept"
}

# time

apply_time() {
	case $M_TODO in
	'') return 0 ;;
	install\ *)
		at_r=${M_TODO#install }
		if ! rec_unit "${at_r#* }" || ! pkg_install "${at_r%% *}"; then
			abort "${at_r%% *} could not be installed$(pkg_why)"
			return
		fi
		did "Installed ${at_r%% *}"
		at_u=${at_r#* }
		;;
	*) at_u=${M_TODO#unit } ;;
	esac
	if ! turn_on "$at_u"; then
		abort "$at_u could not be started"
		return
	fi
	did "$at_u runs and starts at boot"
}

# shared-memory

apply_shared_memory() {
	[ -n "$M_TODO" ] || return 0
	if [ ! -f /etc/fstab ]; then
		refuse '/etc/fstab does not exist.'
		return
	fi
	# The /dev/shm line with nodev, nosuid and noexec added, or a new line.
	awk '
	!/^[ \t]*#/ && $2 == "/dev/shm" && NF >= 4 {
		o = $4
		if (("," o ",") !~ /,nodev,/) o = o ",nodev"
		if (("," o ",") !~ /,nosuid,/) o = o ",nosuid"
		if (("," o ",") !~ /,noexec,/) o = o ",noexec"
		$4 = o; found = 1
	}
	{ print }
	END { if (!found) print "tmpfs /dev/shm tmpfs defaults,nodev,nosuid,noexec 0 0" }' /etc/fstab >/etc/fstab.easyrmm-new
	# The new file is checked before it replaces the old: no new errors.
	as_old=$(t 30 findmnt --verify --tab-file /etc/fstab 2>&1 | grep -ci 'error')
	as_new=$(t 30 findmnt --verify --tab-file /etc/fstab.easyrmm-new 2>&1)
	if [ "$(printf '%s\n' "$as_new" | grep -ci 'error')" -gt "$as_old" ]; then
		rm -f /etc/fstab.easyrmm-new
		refuse "findmnt --verify found errors in the new /etc/fstab: $(printf '%s\n' "$as_new" | grep -i error | head -n 1)"
		return
	fi
	# Put back on a failure: /etc/fstab first, then systemd reloads it.
	tx_push daemon_reload
	if ! write_edit /etc/fstab; then
		abort '/etc/fstab could not be changed'
		return
	fi
	daemon_reload
	did 'Mounted /dev/shm nodev,nosuid,noexec in /etc/fstab'
	am_before=$(mount_options /dev/shm)
	if ! intent; then
		abort 'the record could not be written'
		return
	fi
	rec_has mount /dev/shm || rec_add "mount$tab/dev/shm$tab$am_before$tab?"
	am_add=$(mount_flags_added nodev,nosuid,noexec "$am_before")
	if [ -n "$am_add" ]; then
		tx_push "mount -o remount,$(mount_flags_back nodev,nosuid,noexec "$am_before") /dev/shm"
		if ! t 30 mount -o "remount,$am_add" /dev/shm; then
			abort "/dev/shm could not be remounted $am_add"
			return
		fi
		did "Remounted /dev/shm $am_add"
	fi
	rec_set mount /dev/shm 4 "$(mount_options /dev/shm)"
}
undo_shared_memory_after() { daemon_reload; }

# mac

apply_mac() {
	[ -n "$M_TODO" ] || return 0
	if text_has "$M_TODO" -x enforce; then
		mc_b=$(selinux_mode)
		if ! intent; then
			abort 'the record could not be written'
			return
		fi
		rec_has selinux - || rec_add "selinux$tab-$tab$mc_b$tab?"
		tx_push 'setenforce 0'
		if ! setenforce 1 2>/dev/null; then
			abort 'setenforce 1 failed'
			return
		fi
		rec_set selinux - 4 "$(selinux_mode)"
		did 'SELinux enforcing now (setenforce 1)'
	fi
	if text_has "$M_TODO" -x config; then
		if grep -q '^[[:space:]]*SELINUX=' /etc/selinux/config; then
			sed 's/^[[:space:]]*SELINUX=.*/SELINUX=enforcing/' /etc/selinux/config >/etc/selinux/config.easyrmm-new
		else
			{ cat /etc/selinux/config && printf 'SELINUX=enforcing\n'; } >/etc/selinux/config.easyrmm-new
		fi
		if ! write_edit /etc/selinux/config; then
			abort '/etc/selinux/config could not be changed'
			return
		fi
		did 'SELINUX=enforcing in /etc/selinux/config'
	fi
}

# integrity

apply_integrity() {
	[ -n "$M_TODO" ] || return 0
	if text_has "$M_TODO" -x install; then
		# Debian's aide has neither its configuration nor aideinit without
		# aide-common, which only recommends it.
		case $FAMILY in
		debian) ai_pk='aide aide-common' ;;
		*) ai_pk=aide ;;
		esac
		# Ubuntu 22.04's aide-common depends on a mailx, and bsd-mailx, apt's
		# choice, on a mail server, which would listen: mailutils, the other
		# mailx, needs none.
		[ "$OS_ID $OS_VERSION" != 'ubuntu 22.04' ] || ai_pk="$ai_pk mailutils"
		# shellcheck disable=SC2086 # package names, one word each
		if ! pkg_install $ai_pk; then
			abort "AIDE could not be installed$(pkg_why)"
			return
		fi
		did "Installed AIDE ($ai_pk)"
	fi
	ai_ex=$(printf '%s\n' "$M_TODO" | sed -n 's/^exclude //p')
	if [ -n "$ai_ex" ]; then
		if [ -d /etc/aide/aide.conf.d ]; then
			ai_old=
			[ ! -f "$AIDE_DEB_FILE" ] || ai_old=$(grep '^!' "$AIDE_DEB_FILE")
			ai_lines=$(printf '%s\n%s\n' "$ai_old" "$(printf '%s\n' "$ai_ex" | sed 's/^/!/')" | grep . | awk '!s[$0]++')
			write_own "$AIDE_DEB_FILE" 0644 "# EasyRMM hardening (ADR-0051): written by EasyRMM and removed by its undo.$nl$ai_lines$nl"
		elif [ -f /etc/aide.conf ]; then
			{ cat /etc/aide.conf && printf '%s\n' "$ai_ex" | sed 's/^/!/'; } >/etc/aide.conf.easyrmm-new && write_edit /etc/aide.conf
		else
			false
		fi || {
			abort "AIDE's configuration could not be changed to leave out $(printf '%s' "$ai_ex" | tr '\n' ' ')"
			return
		}
		did "AIDE leaves out $(printf '%s\n' "$ai_ex" | tr '\n' ' ' | sed 's/ $//')"
	fi
	if text_has "$M_TODO" -x daily; then
		ai_timer=$(t 20 systemctl list-unit-files --no-legend '*aide*.timer' 2>/dev/null | awk '$1 != "'"$AIDE_UNIT"'.timer" { print $1; exit }')
		if [ -z "$ai_timer" ]; then
			ai_timer=$AIDE_UNIT.timer
			tx_push daemon_reload
			if ! write_own "/etc/systemd/system/$AIDE_UNIT.service" 0644 "# EasyRMM hardening (ADR-0051): written by EasyRMM and removed by its undo.${nl}[Unit]${nl}Description=EasyRMM hardening: the daily AIDE check${nl}${nl}[Service]${nl}Type=oneshot${nl}Nice=19${nl}IOSchedulingClass=idle${nl}ExecStart=$(command -v aide) --check$nl# AIDE's exit status counts what changed (1 to 7); only 14 and up are errors.${nl}SuccessExitStatus=1 2 3 4 5 6 7$nl" ||
				! write_own "/etc/systemd/system/$AIDE_UNIT.timer" 0644 "# EasyRMM hardening (ADR-0051): written by EasyRMM and removed by its undo.${nl}[Unit]${nl}Description=EasyRMM hardening: the daily AIDE check${nl}${nl}[Timer]${nl}OnCalendar=daily${nl}RandomizedDelaySec=1h${nl}Persistent=true${nl}${nl}[Install]${nl}WantedBy=timers.target$nl"; then
				abort "EasyRMM's daily AIDE check could not be written"
				return
			fi
			daemon_reload
		fi
		if ! turn_on "$ai_timer"; then
			abort "$ai_timer could not be enabled"
			return
		fi
		did "AIDE checks daily ($ai_timer)"
	fi
	text_has "$M_TODO" -x baseline || return 0
	# Outside the job: the baseline can take longer than the job may run.
	# The files the baseline makes are recorded as "?": the command that
	# builds them writes their sums beside the record once it has (undo_gen).
	ai_dbs='/var/lib/aide/aide.db /var/lib/aide/aide.db.gz /var/lib/aide/aide.db.new /var/lib/aide/aide.db.new.gz'
	for ai_db in $ai_dbs; do
		[ -e "$ai_db" ] || rec_has gen "$ai_db" || rec_add "gen$tab$ai_db$tab?"
	done
	case $FAMILY in
	debian) ai_cmd=$(command -v aideinit) && ai_cmd="$ai_cmd --yes --force" ;;
	*) ai_cmd=$(command -v aide) && ai_cmd="$ai_cmd --init && mv -f /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz" ;;
	esac || {
		abort "the baseline could not be started: $(if [ "$FAMILY" = debian ]; then echo aideinit; else echo aide; fi) is missing"
		return
	}
	ai_sums=$MD/files/gen-sums
	ai_cmd="$ai_cmd && for f in $ai_dbs; do [ ! -f \"\$f\" ] || printf '%s %s\\n' \"\$(sha256sum <\"\$f\" | cut -c1-64)\" \"\$f\"; done >$ai_sums.new && mv -f $ai_sums.new $ai_sums"
	t 30 systemctl reset-failed "$AIDE_INIT_UNIT.service" >/dev/null 2>&1
	if ! t 60 systemd-run --unit="$AIDE_INIT_UNIT" --description='EasyRMM hardening: the AIDE baseline' \
		--property=Nice=19 --property=IOSchedulingClass=idle sh -c "$ai_cmd" >/dev/null 2>&1; then
		abort 'the baseline could not be started (systemd-run)'
		return
	fi
	did "Started building AIDE's baseline in $AIDE_INIT_UNIT, outside the job's time limit; the next check reports whether it finished"
}
# A baseline still being built is stopped: what it made so far is apply's
# (GEN_STOPPED), and goes.
undo_integrity_before() {
	[ "$SYSTEMD_UP" = no ] && return 0
	! unit_active "$AIDE_INIT_UNIT.service" || GEN_STOPPED=yes
	{
		t 120 systemctl stop "$AIDE_INIT_UNIT.service"
		t 30 systemctl reset-failed "$AIDE_INIT_UNIT.service"
	} >/dev/null 2>&1
	return 0
}
undo_integrity_after() { daemon_reload; }

# ---------------------------------------------------------------------------
# Running the modules

# check_module MODULE: the module's check, from begin_module on.
check_module() {
	begin_module "$1"
	case $1 in
	ssh) check_ssh ;;
	firewall) check_firewall ;;
	fail2ban) check_fail2ban ;;
	kernel) check_kernel ;;
	audit) check_audit ;;
	permissions) check_permissions ;;
	services) check_services ;;
	kernel-modules) check_kernel_modules ;;
	sudo) check_sudo ;;
	time) check_time ;;
	shared-memory) check_shared_memory ;;
	usb-storage) check_usb_storage ;;
	mac) check_mac ;;
	integrity) check_integrity ;;
	esac
}

# What is read once per check, read again after a module changed it.
fresh_reads() {
	SSHD_T_DONE=no
	MODPROBE_READ=no
	DOCKER_UNREAD=no
	PROCS=$(cat /proc/[0-9]*/comm 2>/dev/null | sort -u)
}

# finish_change [recheck]: the module's result with what the run did; with
# recheck, from a check made after the change.
finish_change() {
	fc_out=$M_OUTCOME
	fc_why=$M_WHY
	fc_done=$M_DONE
	if [ $# -gt 0 ]; then
		fresh_reads
		check_module "$CUR"
	fi
	finish_module
	fc_v=$(printf '%s' "$CUR" | tr '-' '_')
	keep "O_$fc_v" "$fc_out"
	keep "W_$fc_v" "$fc_why"
	keep "D_$fc_v" "$fc_done"
	keep "PR_$fc_v" "$M_RECOV"
	keep "PW_$fc_v" "$M_RECOV_WHY"
	keep "PK_$fc_v" "$M_RECOV_PKGS"
	keep "UW_$fc_v" "$M_UNDO_WITH"
	M_RECOV=
	M_RECOV_WHY=
	M_RECOV_PKGS=
	M_UNDO_WITH=
	say "$CUR: $fc_out. $fc_why"
}

# time_ran_out: a module that failed once the job's time ran out says so.
time_ran_out() {
	[ "$OUT_OF_TIME" = yes ] && [ "$M_OUTCOME" = failed ] || return 0
	case $M_WHY in *"job's time"*) ;; *) M_WHY="The job's time ran out: $M_WHY" ;; esac
}
# not_run MODULE: a module not run because the job's time ran out; nothing
# was checked, so the server keeps what it knew of it.
not_run() {
	begin_module "$1"
	M_STATE=failed
	reason "Not checked: the job's time ran out before this module."
	M_OUTCOME=not_run
	M_WHY="Not run: the job's time ran out before this module; run $MODE again for it."
	M_DONE=
	finish_change
}

# check_said PREFIX: the first of the check's changes that starts with
# PREFIX ("Refused: " or "Left as it is: "), without it.
check_said() { printf '%s\n' "$M_CHANGES" | sed -n "s/^$1//p" | head -n 1; }

apply_module() {
	module_record "$1"
	check_module "$1"
	settle_state
	M_OUTCOME=
	M_WHY=
	M_DONE=
	case $M_STATE in
	not_applicable | managed_elsewhere | not_supported)
		M_OUTCOME=skipped
		M_WHY=$M_REASON
		;;
	failed)
		M_OUTCOME=refused
		M_WHY="The check failed: $M_REASON"
		;;
	*)
		if [ "$M_BAD" -gt 0 ]; then
			if ! tx_begin; then
				M_OUTCOME=failed
				M_WHY="$TX_DIR could not be written."
			else
				# The changes stop where the time kept for a rollback starts.
				T_END=$WORK_END
				case $1 in
				ssh) apply_ssh ;;
				firewall) apply_firewall ;;
				fail2ban) apply_fail2ban ;;
				kernel) apply_kernel ;;
				audit) apply_audit ;;
				permissions) apply_permissions ;;
				services) apply_services ;;
				kernel-modules) apply_kernel_modules ;;
				sudo) apply_sudo ;;
				time) apply_time ;;
				shared-memory) apply_shared_memory ;;
				usb-storage) apply_usb_storage ;;
				mac) apply_mac ;;
				integrity) apply_integrity ;;
				esac
				T_END=$JOB_END
				time_ran_out
			fi
		fi
		if [ -z "$M_OUTCOME" ]; then
			# What the check said apply leaves, and why.
			am_ref=$(check_said 'Refused: ')
			am_left=$(check_said 'Left as it is: ')
			if [ -n "$M_DONE" ]; then
				M_OUTCOME=applied
			elif [ -n "$am_ref" ]; then
				M_OUTCOME=refused
				M_WHY="Refused: $am_ref."
			else
				M_OUTCOME=unchanged
				[ -z "$am_left" ] || M_WHY="Left as it is: $am_left."
			fi
			if [ "$M_OUTCOME" = applied ]; then
				printf '%s\n' "$M_CHANGES" | grep -E '^(Refused|Left as it is): ' >"$TX_DIR/left" 2>/dev/null
				while IFS= read -r am_l; do did "$am_l"; done <"$TX_DIR/left"
			fi
			# A record left by a run that was cut short is whole again once
			# the module is as apply leaves it.
			[ -e "$MD/done" ] || [ ! -e "$MD/intent" ] || INTENT=yes
			mark_done
		fi
		;;
	esac
	case $M_OUTCOME in
	skipped | refused) finish_change ;;
	*) finish_change recheck ;;
	esac
}

undo_module() {
	module_record "$1"
	M_OUTCOME=
	M_WHY=
	M_DONE=
	M_LEFT=no
	um_format=$(sed -n '1s/^format \([0-9][0-9]*\)$/\1/p' "$MANIFEST" 2>/dev/null)
	if [ ! -s "$MANIFEST" ]; then
		M_OUTCOME=nothing_to_undo
		M_WHY='EasyRMM has no record of applying this module here.'
		# An apply cut short before its first record left only its intent.
		rm -rf "$MD"
	elif [ -z "$um_format" ] || [ "$um_format" -gt "$FORMAT" ]; then
		M_OUTCOME=refused
		M_WHY="The record was written by a later release of this script (format ${um_format:-unknown}); undo with that release."
	elif [ "$1" = firewall ] && [ -s "$STATE_DIR/modules/fail2ban/manifest" ]; then
		# Undo runs the modules last first: fail2ban, chosen too, is undone
		# by now, and its record gone.
		M_OUTCOME=refused
		M_WHY="fail2ban, which EasyRMM applied too, bans with the firewall this module set up (nftables, which its apply may have installed): undone alone, fail2ban's bans could silently do nothing. Undo fail2ban with it."
		M_UNDO_WITH=fail2ban
	elif ! tx_begin || ! intent; then
		M_OUTCOME=failed
		M_WHY="$STATE_DIR could not be written."
	else
		AUDIT_UNDO=no
		PKG_KEPT=no
		GEN_STOPPED=no
		GEN_LEFT=
		case $1 in
		integrity) undo_integrity_before ;;
		audit) AUDIT_UNDO=yes ;;
		esac
		T_END=$WORK_END
		undo_records
		[ -n "$M_OUTCOME" ] || case $1 in
		ssh) undo_ssh_after ;;
		firewall) undo_firewall_after ;;
		fail2ban) undo_fail2ban_after ;;
		kernel) undo_kernel_after ;;
		audit) undo_audit_after ;;
		services) undo_services_after ;;
		kernel-modules) undo_kernel_modules_after ;;
		usb-storage) undo_usb_storage_after ;;
		shared-memory) undo_shared_memory_after ;;
		integrity) undo_integrity_after ;;
		esac
		T_END=$JOB_END
		time_ran_out
		if [ -z "$M_OUTCOME" ]; then
			# Undone: the record is used up, and the next apply takes
			# fresh copies.
			rm -rf "$MD"
			M_OUTCOME=undone
			[ "$M_LEFT" = no ] || M_OUTCOME=partly_undone
			[ -n "$M_DONE" ] || did 'Everything EasyRMM recorded was already as it was before apply; the record was removed'
		fi
	fi
	CUR=$1
	finish_change recheck
}

# Apply and undo run one at a time on a computer. The lock names the run
# that holds it: its process ID and start time (so that a later process
# given the same ID does not hold it), and the boot it ran in; and each
# step t runs (t.PID, see T_RUN), which may outlive a run killed outright.
# proc_start PID: the process's start time, if it runs (a zombie does not).
proc_start() {
	sed -n 's/^.*) \([^ ]*\)\( [^ ]*\)\{18\} \([0-9]*\) .*$/\1 \3/p' "/proc/$1/stat" 2>/dev/null | awk '$1 != "Z" { print $2 }'
}
boot_id() { cat /proc/sys/kernel/random/boot_id 2>/dev/null; }
take_lock() {
	if ! mkdir "$LOCK_DIR" 2>/dev/null; then
		! lock_busy || return 1
		rm -rf "$LOCK_DIR" && mkdir "$LOCK_DIR" 2>/dev/null || return 1
	fi
	LOCK_HELD=yes
	printf '%s %s %s\n' "$$" "$(proc_start $$)" "$(boot_id)" >"$LOCK_DIR/pid"
}
# lock_busy: whether the run that holds the lock still runs, or a step it
# started through t does: a run killed outright (SIGKILL) leaves its steps
# running, each in a process group of its own, until they end.
lock_busy() {
	lb_pid=
	lb_start=
	lb_boot=
	read -r lb_pid lb_start lb_boot <"$LOCK_DIR/pid" 2>/dev/null
	case $lb_pid:$lb_start in
	*[!0-9:]* | :* | *:)
		# Taken a moment ago, or by a run killed before it wrote its
		# number: stale after ten minutes.
		[ -n "$(find "$LOCK_DIR" -maxdepth 0 -mmin +10 2>/dev/null)" ] || return 0
		return 1
		;;
	esac
	# Nothing from before a restart runs.
	[ -z "$lb_boot" ] || [ "$lb_boot" = "$(boot_id)" ] || return 1
	[ "$(proc_start "$lb_pid")" != "$lb_start" ] || return 0
	t_steps | {
		while read -r lb_g lb_s; do
			! group_runs "$lb_g" "$lb_s" || exit 0
		done
		exit 1
	}
}
release() {
	[ "$LOCK_HELD" = yes ] || return 0
	rm -rf "$TX_DIR"
	# Nothing recorded any more: nothing of EasyRMM's is left here.
	if [ -z "$(ls -A "$STATE_DIR/modules" 2>/dev/null)" ]; then
		rm -rf "$STATE_DIR"
	else
		rm -rf "$LOCK_DIR"
	fi
	LOCK_HELD=no
}

# change_all: apply or undo every chosen module (undo last first).
change_all() {
	ca_mods=$SELECTED
	if [ "$MODE" = undo ]; then
		# shellcheck disable=SC2086 # module names, one word each
		ca_mods=$(printf '%s\n' $SELECTED | awk '{ l[NR] = $0 } END { for (i = NR; i > 0; i--) print l[i] }')
	fi
	ca_why=$SUPPORT_WHY
	if [ -z "$ca_why" ]; then
		if ! (umask 077 && mkdir -p "$STATE_DIR/modules") || ! chmod 700 "$STATE_DIR"; then
			ca_why="$STATE_DIR could not be created."
		elif ! take_lock; then
			ca_why='Another EasyRMM hardening run is changing this computer; try again when it has finished.'
		fi
	fi
	if [ -n "$ca_why" ]; then
		# Not supported here: nothing is checked either. Otherwise each
		# module is checked, and changes nothing.
		for ca_m in $SELECTED; do
			M_OUTCOME=refused
			M_WHY=$ca_why
			M_DONE=
			CUR=$ca_m
			if [ "$SUPPORT" = full ]; then
				finish_change recheck
			else
				begin_module "$ca_m"
				M_STATE=not_supported
				reason "$ca_why"
				M_OUTCOME=skipped
				finish_change
			fi
		done
		return
	fi
	trap 'release' EXIT
	# A copy of this script, for undo on the computer without the agent.
	if [ -f "$0" ] && [ "$(sha "$0")" != "$(sha "$STATE_DIR/easyrmm-hardening.sh")" ]; then
		cp "$0" "$STATE_DIR/easyrmm-hardening.sh.new" && chmod 700 "$STATE_DIR/easyrmm-hardening.sh.new" &&
			mv -f "$STATE_DIR/easyrmm-hardening.sh.new" "$STATE_DIR/easyrmm-hardening.sh"
	fi
	for ca_m in $ca_mods; do
		# A module starts with at least MODULE_MIN of the job's time left.
		if [ -n "$WORK_END" ] && [ $((WORK_END - $(date +%s))) -lt "$MODULE_MIN" ]; then
			OUT_OF_TIME=yes
		fi
		if [ "$OUT_OF_TIME" = yes ]; then
			not_run "$ca_m"
			continue
		fi
		case $MODE in
		apply) apply_module "$ca_m" ;;
		undo) undo_module "$ca_m" ;;
		esac
	done
	release
	trap - EXIT
}

# ---------------------------------------------------------------------------
# The result

# JSON strings: backslash, quote and control characters escaped; at most
# LEN bytes of each.
AWK_ESC='
BEGIN { for (i = 1; i < 32; i++) ctl[sprintf("%c", i)] = sprintf("\\u%04x", i) }
function esc(s,   o, i, c, n) {
	o = ""
	n = length(s)
	for (i = 1; i <= n; i++) {
		c = substr(s, i, 1)
		if (c == "\\") o = o "\\\\"
		else if (c == "\"") o = o "\\\""
		else if (c in ctl) o = o ctl[c]
		else o = o c
	}
	return "\"" o "\""
}
'
# jstr STRING LEN
jstr() { printf '%s\n' "$1" | awk -v len="$2" "$AWK_ESC"'NR == 1 { print esc(substr($0, 1, len)) }'; }
# jarr LIST MAX LEN MORE: a JSON array of the first MAX lines of LIST; with
# MORE "yes", a cut list ends in "and N more". Nothing for an empty list.
jarr() {
	[ -n "$1" ] && [ "$2" -gt 0 ] || return 0
	printf '%s\n' "$1" | awk -v max="$2" -v len="$3" -v more="$4" "$AWK_ESC"'
	$0 != "" { n++; if (n <= max) item[n] = $0 }
	END {
		if (n == 0) exit
		k = n
		if (n > max) k = (more == "yes") ? max - 1 : max
		out = ""
		for (i = 1; i <= k; i++) out = out (i > 1 ? "," : "") esc(substr(item[i], 1, len))
		if (k < n && more == "yes") out = out (k > 0 ? "," : "") esc("and " (n - k) " more")
		printf "[%s]", out
	}'
}

# render_module MODULE MAX LEN
render_module() {
	rm_v=$(printf '%s' "$1" | tr '-' '_')
	rm_state=$(kept "S_$rm_v")
	rm_reason=$(kept "R_$rm_v")
	rm_out="{\"module\":\"$1\",\"state\":\"$rm_state\""
	[ -z "$rm_reason" ] || rm_out="$rm_out,\"reason\":$(jstr "$rm_reason" 300)"
	rm_a=$(jarr "$(kept "MI_$rm_v")" "$2" "$3" yes)
	[ -z "$rm_a" ] || rm_out="$rm_out,\"missing\":$rm_a"
	rm_a=$(jarr "$(kept "CH_$rm_v")" "$2" "$3" yes)
	[ -z "$rm_a" ] || rm_out="$rm_out,\"changes\":$rm_a"
	if [ "$1" = firewall ]; then
		case $rm_state in in_place | partly | not_in_place | half_applied)
			rm_p=
			for rm_k in tcp:PT udp:PU docker:PD unknown:PK; do
				rm_a=$(jarr "$(kept "${rm_k#*:}_$rm_v")" "$2" "$3" no)
				[ -z "$rm_a" ] || rm_p="$rm_p,\"${rm_k%:*}\":$rm_a"
			done
			[ -z "$rm_p" ] || rm_out="$rm_out,\"ports\":{${rm_p#,}}"
			;;
		esac
	fi
	# What apply or undo did.
	rm_o=$(kept "O_$rm_v")
	if [ -n "$rm_o" ]; then
		rm_out="$rm_out,\"outcome\":\"$rm_o\""
		rm_a=$(kept "W_$rm_v")
		[ -z "$rm_a" ] || rm_out="$rm_out,\"outcomeReason\":$(jstr "$rm_a" 300)"
		rm_a=$(jarr "$(kept "D_$rm_v")" "$2" "$3" yes)
		[ -z "$rm_a" ] || rm_out="$rm_out,\"done\":$rm_a"
		# The package database's recovery before a package step (pkg_ready).
		rm_a=$(kept "PR_$rm_v")
		if [ -n "$rm_a" ]; then
			rm_out="$rm_out,\"packageRecovery\":{\"outcome\":\"$rm_a\",\"reason\":$(jstr "$(kept "PW_$rm_v")" 300)"
			# shellcheck disable=SC2046 # package names, one word each
			rm_a=$(jarr "$(printf '%s\n' $(kept "PK_$rm_v"))" "$2" 64 no)
			[ -z "$rm_a" ] || rm_out="$rm_out,\"packages\":$rm_a"
			rm_out="$rm_out}"
		fi
		# The modules to undo with this one (undo_module).
		rm_a=$(kept "UW_$rm_v")
		[ -z "$rm_a" ] || rm_out="$rm_out,\"undoWith\":[\"$rm_a\"]"
	fi
	[ "$(kept "RC_$rm_v")" != yes ] || rm_out="$rm_out,\"recorded\":true"
	printf '%s}' "$rm_out"
}

# render MAX LEN: the whole result.
render() {
	rr_p="\"family\":\"$FAMILY\",\"container\":\"$CONTAINER\",\"support\":\"$SUPPORT\""
	[ -z "$OS_VERSION" ] || rr_p="\"versionId\":$(jstr "$OS_VERSION" 300),$rr_p"
	[ -z "$OS_ID" ] || rr_p="\"id\":$(jstr "$OS_ID" 300),$rr_p"
	rr_m=
	for rr_mod in $SELECTED; do
		rr_m="$rr_m,$(render_module "$rr_mod" "$1" "$2")"
	done
	printf '{"version":1,"mode":"%s","platform":{%s},"modules":[%s]}' "$MODE" "$rr_p" "${rr_m#,}"
}

# ---------------------------------------------------------------------------
# Check, apply or undo

say "EasyRMM hardening $MODE: ${OS_ID:-unknown} ${OS_VERSION:-} ($FAMILY family; container: $CONTAINER; support: $SUPPORT)."
case $SUPPORT in
check_only) say 'This release is checked only: apply and undo do not run on it.' ;;
unsupported) say 'This distribution or release is not supported: apply and undo do not run on it.' ;;
esac

if [ "$MODE" = check ]; then
	for mod in $SELECTED; do
		check_module "$mod"
		finish_module
	done
else
	change_all
fi

# The last line: within 64 KiB, with fewer and shorter list entries if the
# full lists would not fit. The last attempt has no lists, only reasons.
for lim in '50 300' '20 200' '10 120' '3 80' '0 0'; do
	# shellcheck disable=SC2086 # two numbers
	RESULT=$(render $lim)
	[ ${#RESULT} -lt 65000 ] && break
done
printf '%s %s\n' "$RESULT_TAG" "$RESULT"
exit 0
