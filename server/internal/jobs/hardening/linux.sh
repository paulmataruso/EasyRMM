#!/bin/sh
# EasyRMM hardening for Linux computers (ADR-0051), run by the EasyRMM agent
# as root. This release has one mode, check: for each chosen module it reports
# whether the module's settings are in effect and what apply would change on
# this computer, and it changes nothing (see "What check writes" below).
#
# Arguments, which are never part of this script's text. The EasyRMM server
# accepts only the names and forms below, and this script checks them again:
#   check <modules> [option ...]
#   <modules>           all, or a comma-separated list of ssh, firewall,
#                       fail2ban, kernel, audit, permissions, services,
#                       kernel-modules, sudo, time, shared-memory,
#                       usb-storage, mac and integrity
#   allow-tcp=LIST      ports or ranges (8080,9000-9100) the firewall would
#   allow-udp=LIST      leave open besides those in use
#   trusted=LIST        IPv4 or IPv6 addresses or CIDR ranges fail2ban would
#                       never ban
#   root-password-off   turn root's password sign-in to SSH off even if it was
#                       used in the last 30 days
#   password-off        turn password sign-in to SSH off
#   epel                let fail2ban come from EPEL on RHEL and its rebuilds
#
# Output: progress lines, then as the last line of stdout
#   EASYRMM-HARDENING-RESULT-V1 {"version":1,"mode":"check",...}
# kept under 64 KiB. The exit status is 0 whenever the check ran, whatever it
# found; 2 for a usage error, 3 when not run as root.
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
# The journal, written by apply and undo (H2) and read here:
#   /var/lib/easyrmm-hardening/                      mode 700
#   /var/lib/easyrmm-hardening/modules/<module>/intent
#       written before apply or undo changes anything in that module
#   /var/lib/easyrmm-hardening/modules/<module>/done
#       written after it finished
# A module with an intent and no done mark was interrupted (a timeout or a
# cancel killed the job): check reports it as half_applied.
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
# EasyRMM's own files, which apply (H2) writes.
SSH_DROPIN=/etc/ssh/sshd_config.d/00-easyrmm-hardening.conf
FW_FILE=/etc/easyrmm-hardening/firewall.nft
FW_UNIT=easyrmm-firewall.service
SYSCTL_FILE=/etc/sysctl.d/60-easyrmm-hardening.conf
AUDIT_FILE=/etc/audit/rules.d/60-easyrmm-hardening.rules
SUDO_FILE=/etc/sudoers.d/easyrmm-hardening

nl='
'

# The platforms apply and undo are tested on (ADR-0051, "Platforms"), one
# distribution a line: its ID in os-release, then its releases. A release
# without a dot matches every point release of it (Rocky Linux 9.4 is 9).
FULL_SUPPORT='
debian 12 13
ubuntu 22.04 24.04 26.04
rocky 8 9 10
almalinux 8 9 10
rhel 8 9 10
fedora 43 44 45
'
# Releases out of their standard support, which check reports on but apply
# and undo refuse. Newer releases of the distributions above are check only
# as well, until they are tested.
CHECK_ONLY='
debian 11
ubuntu 20.04
'

say() { printf '%s\n' "$*"; }

usage() {
	printf 'linux.sh: %s\n' "$1" >&2
	printf 'Usage: sh linux.sh check <all|module,...> [allow-tcp=LIST] [allow-udp=LIST] [trusted=LIST] [root-password-off] [password-off] [epel]\n' >&2
	exit 2
}

have() { command -v "$1" >/dev/null 2>&1; }

# t SECONDS COMMAND...: runs a command that could hang (a stuck daemon, a
# hung network mount) with a time limit.
t() {
	t_s=$1
	shift
	if have timeout; then
		timeout -k 5 "$t_s" "$@"
	else
		"$@"
	fi
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
check) ;;
*) usage "unknown mode: $MODE (this release has check only)." ;;
esac
[ $# -ge 2 ] || usage 'no modules given.'
MODULES_ARG=$2
shift 2

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
	root-password-off) OPT_ROOT_PASSWORD_OFF=yes ;;
	password-off) OPT_PASSWORD_OFF=yes ;;
	epel) OPT_EPEL=yes ;;
	*) usage "unknown option: $arg" ;;
	esac
done

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
# every release there ("newer"), or neither (nothing).
support_of() {
	so_line=$(printf '%s\n' "$1" | sed -n "s/^$OS_ID //p" | head -n 1)
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
if [ "$OS_VERSION_OK" = yes ]; then
	case $(support_of "$FULL_SUPPORT") in
	in) SUPPORT=full ;;
	newer) SUPPORT=check_only ;;
	*) [ "$(support_of "$CHECK_ONLY")" != in ] || SUPPORT=check_only ;;
	esac
fi

# systemd-detect-virt where it is installed; its "container-other" (older
# systemd, for an image that sets container=oci) is narrowed by the files
# Docker and Podman leave.
detect_container() {
	if have systemd-detect-virt; then
		dc_v=$(systemd-detect-virt --container 2>/dev/null)
		case $dc_v in
		'') ;;
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
proc_running() { printf '%s\n' "$PROCS" | grep -qxF "$1"; }

# unit_file_state UNIT: what systemctl is-enabled says (it reads unit files,
# so it works without systemd running), or nothing.
unit_file_state() {
	have systemctl || return 0
	t 20 systemctl is-enabled "$1" 2>/dev/null | head -n 1
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
	case $(t 20 systemctl is-active "$1" 2>/dev/null) in active | reloading | activating) return 0 ;; esac
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
# sshd_val KEY: the first value of KEY in sshd -T's output (keys are lower case).
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
reason() { M_REASON=$(printf '%s' "$1" | tr '\n\r' '  '); }
not_applicable() {
	M_STATE=not_applicable
	reason "$1"
}
failed() {
	M_STATE=failed
	reason "$1"
}

finish_module() {
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
	# An apply or undo of this module that was interrupted (see the journal).
	if [ -e "$STATE_DIR/modules/$CUR/intent" ] && [ ! -e "$STATE_DIR/modules/$CUR/done" ]; then
		M_STATE=half_applied
		reason 'An apply or undo of this module was interrupted before it finished; undo reverses what it recorded.'
	fi
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
			printf '%s\n' "$rp_out" | grep -Eq "$rp_pattern" && return 0
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
		cs_changes=yes
	fi

	# LoginGraceTime 30 or less, never 0, which is no limit.
	cs_v=$(sshd_val logingracetime)
	case $cs_v in '' | *[!0-9]*) cs_n=0 ;; *) cs_n=$cs_v ;; esac
	if [ "$cs_n" -ge 1 ] && [ "$cs_n" -le 30 ]; then in_place; else
		missing "LoginGraceTime 30 (now $cs_v)"
		change 'LoginGraceTime 30'
		cs_changes=yes
	fi

	# X11Forwarding no.
	cs_v=$(sshd_val x11forwarding)
	if [ "$cs_v" = no ]; then in_place; else
		missing "X11Forwarding no (now $cs_v)"
		change 'X11Forwarding no'
		cs_changes=yes
	fi

	# Dead connections closed: ClientAliveInterval 300 and ClientAliveCountMax
	# 3, or shorter; 0 turns either off.
	cs_v=$(sshd_val clientaliveinterval)
	case $cs_v in '' | *[!0-9]*) cs_n=0 ;; *) cs_n=$cs_v ;; esac
	if [ "$cs_n" -ge 1 ] && [ "$cs_n" -le 300 ]; then in_place; else
		missing "ClientAliveInterval 300 (now $cs_v)"
		change 'ClientAliveInterval 300'
		cs_changes=yes
	fi
	cs_v=$(sshd_val clientalivecountmax)
	case $cs_v in '' | *[!0-9]*) cs_n=0 ;; *) cs_n=$cs_v ;; esac
	if [ "$cs_n" -ge 1 ] && [ "$cs_n" -le 3 ]; then in_place; else
		missing "ClientAliveCountMax 3 (now $cs_v)"
		change 'ClientAliveCountMax 3'
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
	printf '%s\n' "$fe_rules" | grep -q '^unreadable$' && echo 'UNREADABLE'
	return 0
}

# listening: "tcp PORT" and "udp PORT" for every socket listening outside
# loopback, from the kernel's socket tables (what ss -lntu shows).
listening() {
	for li_f in tcp tcp6 udp udp6; do
		[ -r "/proc/net/$li_f" ] || continue
		case $li_f in tcp*) li_state=0A ;; *) li_state=07 ;; esac
		awk -v proto="${li_f%6}" -v want="$li_state" '
		function hex(h,  i, n) { n = 0; h = toupper(h); for (i = 1; i <= length(h); i++) n = n * 16 + index("0123456789ABCDEF", substr(h, i, 1)) - 1; return n }
		NR > 1 && $4 == want {
			split($2, a, ":"); addr = toupper(a[1])
			if (length(addr) == 8 && substr(addr, 7, 2) == "7F") next
			if (addr == "00000000000000000000000001000000") next
			if (length(addr) == 32 && substr(addr, 1, 24) == "0000000000000000FFFF0000" && substr(addr, 31, 2) == "7F") next
			print proto, hex(a[2])
		}' "/proc/net/$li_f"
	done | sort -u
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

check_firewall() {
	cf_else=$(fw_elsewhere)
	cf_unreadable=no
	if printf '%s\n' "$cf_else" | grep -q '^UNREADABLE$'; then
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
	if [ "$cf_nft" = yes ] && nf_tables_present && t 30 nft list table inet easyrmm >/dev/null 2>&1; then
		in_place
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
		printf '%s\n' "$ee_section" | grep -Eiq '^[[:space:]]*enabled[[:space:]]*=[[:space:]]*(0|false|no)[[:space:]]*$' || return 0
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
	change 'Jail sshd: 5 failures in 10 minutes bans the address for an hour, longer for repeat offenders'
	change "Never banned: $fc_trusted"
	if [ ! -e /var/log/auth.log ] && [ ! -e /var/log/secure ]; then
		change 'Read failed sign-ins from the journal (backend = systemd): there is no auth.log or secure file'
	fi
	change "Ban with $(f2b_banaction)"
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
		return
	fi
	if unit_active auditd.service && unit_enabled auditd.service; then in_place; else
		missing 'auditd running and started at boot'
		change 'Start auditd and start it at boot'
	fi
	ca_live=$(t 20 auditctl -l 2>/dev/null)
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
		if printf '%s\n' "$ca_live" | grep -Eq -- "$ca_re"; then in_place; else
			missing "Audit rules for $ca_what"
			ca_missing=yes
		fi
		IFS=$nl
	done
	set +f
	IFS=$ca_oifs
	if [ -n "$ca_missing" ]; then
		change "Add the missing rules in $AUDIT_FILE, loaded with augenrules --load (never immutable, never panic)"
		if printf '%s\n' "$ca_status" | grep -q '^enabled 2'; then
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
	printf '%s\n' "$MODPROBE_C" | grep -Eq "^install $1 (/usr)?/bin/(false|true)([[:space:]]|\$)"
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
}

# usb_disks_in_use: USB disks with a mounted filesystem or swap on them, or
# on anything built on them (partitions, LVM, encryption).
usb_disks_in_use() {
	lsblk -dnpP -o NAME,TRAN 2>/dev/null | sed -n 's/^NAME="\([^"]*\)" TRAN="usb"$/\1/p' | while read -r ud_d; do
		lsblk -nrp -o MOUNTPOINT "$ud_d" 2>/dev/null | grep -q . && printf '%s\n' "$ud_d"
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
	if [ -n "$us_disks" ]; then
		change "Refused: a mounted filesystem or swap is on a USB disk (${us_disks% }), and the computer would not boot without usb-storage"
	else
		change 'Keep usb-storage from loading, in /etc/modprobe.d and the initramfs: USB disks and backup drives stop working'
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
	fi
	# Commands logged to a file of their own, with a logrotate
	# entry for it.
	if [ -n "$cu_logfile" ]; then
		in_place
		if grep -Fqs "$cu_logfile" /etc/logrotate.conf /etc/logrotate.d/*; then in_place; else
			missing "A logrotate entry for $cu_logfile"
			change "Add a logrotate entry for $cu_logfile"
		fi
	else
		missing 'sudo logs commands to /var/log/sudo.log (logfile)'
		missing 'A logrotate entry for /var/log/sudo.log'
		change 'Defaults logfile=/var/log/sudo.log, with a logrotate entry for it'
	fi
	if [ -e "$SUDO_FILE" ]; then
		cu_mode=$(stat -c %a "$SUDO_FILE" 2>/dev/null)
		[ "$cu_mode" = 440 ] || {
			missing "$SUDO_FILE mode 0440 (now $cu_mode)"
			change "$SUDO_FILE: mode 0440"
		}
	fi
	if [ "$M_BAD" -gt 0 ]; then
		change "The settings go in $SUDO_FILE (mode 0440), checked with visudo -c before it is put in place"
		if ! grep -Eq '^[#@]includedir[[:space:]]+/etc/sudoers\.d/?[[:space:]]*$' /etc/sudoers; then
			change 'Refused: /etc/sudoers does not include /etc/sudoers.d'
		elif have visudo && ! t 20 visudo -c -q >/dev/null 2>&1; then
			change 'Refused: the sudoers files have errors now (visudo -c fails)'
		fi
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
			ct_running=$ct_u
			break
		fi
		[ -n "$ct_installed" ] || ! unit_exists "$ct_u" || ct_installed=$ct_u
	done
	if [ -n "$ct_running" ]; then
		in_place
		if unit_enabled "$ct_running"; then in_place; else
			missing "$ct_running started at boot"
			change "Start $ct_running at boot"
		fi
		reason "$ct_running keeps the time."
		[ "$M_BAD" -eq 0 ] || reason "$ct_running keeps the time but is not started at boot."
		return
	fi
	missing 'A time synchronisation service running'
	if [ -n "$ct_installed" ]; then
		change "Start $ct_installed, and start it at boot"
	else
		case $FAMILY in
		rhel | fedora) change 'Install chrony, and start it at boot' ;;
		*) change 'Install systemd-timesyncd, and start it at boot' ;;
		esac
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
	printf '%s\n' "$ad_out" | grep -q '<no matches>' && return 1
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
	# AIDE installed, a baseline, a daily check.
	if ! have aide; then
		missing 'AIDE installed'
		missing 'An AIDE baseline'
		missing 'A daily AIDE check'
		change 'Install AIDE'
		change "Build the baseline in a unit of its own (systemd-run), outside the job's time limit; the next check reports whether it finished"
		change "Check daily, with the distribution's timer where it has one"
		[ -d /var/lib/docker ] || [ -d /var/lib/containers ] && change 'Leave /var/lib/docker and /var/lib/containers out'
		return
	fi
	in_place
	ci_db=no
	for ci_f in /var/lib/aide/aide.db /var/lib/aide/aide.db.gz; do
		[ -s "$ci_f" ] && ci_db=yes
	done
	if [ "$ci_db" = yes ]; then in_place; else
		if [ "$SYSTEMD_UP" = yes ] && t 20 systemctl list-units --no-legend --plain --state=active 'easyrmm-aide*' 2>/dev/null | grep -q .; then
			missing 'An AIDE baseline (being built now)'
		else
			missing 'An AIDE baseline'
			change "Build the baseline in a unit of its own (systemd-run), outside the job's time limit"
		fi
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
	fi
	for ci_d in /var/lib/docker /var/lib/containers; do
		[ -d "$ci_d" ] || continue
		if grep -Eqs "^[[:space:]]*!$ci_d" /etc/aide/aide.conf /etc/aide/aide.conf.d/* /etc/aide.conf; then in_place; else
			missing "AIDE leaves out $ci_d"
			change "Leave $ci_d out of AIDE's checks"
		fi
	done
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
	printf '{"version":1,"mode":"check","platform":{%s},"modules":[%s]}' "$rr_p" "${rr_m#,}"
}

# ---------------------------------------------------------------------------
# Check

say "EasyRMM hardening check: ${OS_ID:-unknown} ${OS_VERSION:-} ($FAMILY family; container: $CONTAINER; support: $SUPPORT)."
case $SUPPORT in
check_only) say 'This release is checked only: apply and undo do not run on it.' ;;
unsupported) say 'This distribution or release is not supported: apply and undo do not run on it.' ;;
esac

for mod in $SELECTED; do
	begin_module "$mod"
	case $mod in
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
	finish_module
done

# The last line: within 64 KiB, with fewer and shorter list entries if the
# full lists would not fit. The last attempt has no lists, only reasons.
for lim in '50 300' '20 200' '10 120' '3 80' '0 0'; do
	# shellcheck disable=SC2086 # two numbers
	RESULT=$(render $lim)
	[ ${#RESULT} -lt 65000 ] && break
done
printf '%s %s\n' "$RESULT_TAG" "$RESULT"
exit 0
