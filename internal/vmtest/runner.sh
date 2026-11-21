#!/bin/sh
# The runner of EasyRMM's machine test harness (internal/vmtest). cloud-init
# installs it on test machines only; it is not part of any release.
#
# It answers requests on the virtio-serial port named as its argument (on
# standard input and output without one), so that tests reach the machine
# whatever its firewall or network does. Requests:
#
#   P <id>
#       answered "P <id> <boot id>";
#   X <id> <boot id> <seconds> <length>, a line feed, <length> bytes of a
#   base64 script and a line feed
#       runs the script as root with sh, standard input /dev/null, under
#       timeout(1) (exit code 124: the time ran out), and answers
#       "R <id> <exit code> <stdout, base64> <stderr, base64>".
#
# A script sent for another boot is refused with "E <id> stale <boot id>",
# so one sent before a restart never runs after it. Other refusals are
# "E <id> <reason>". Lines it does not understand are skipped. Scripts run
# one at a time.
set -u
set -f

if [ $# -gt 0 ]; then
	exec <>"$1" >&0
fi
work=${EASYRMM_HARNESS_DIR:-/run/easyrmm-harness}
umask 077
mkdir -p "$work" || exit 1
boot=$(cat /proc/sys/kernel/random/boot_id) || exit 1

encode() {
	base64 <"$1" | tr -d '\n'
}

while :; do
	# The port reads as end of file while no host is connected.
	if ! IFS= read -r line; then
		sleep 1
		continue
	fi
	# shellcheck disable=SC2086 # split into fields; globbing is off
	set -- $line
	case ${1:-}:$# in
	P:2)
		printf 'P %s %s\n' "$2" "$boot"
		;;
	X:5)
		id=$2
		case $4:$5 in
		*[!0-9:]* | :* | *:)
			printf 'E %s request\n' "$id"
			continue
			;;
		esac
		# head -c reads no further than the script, so the next request
		# stays unread.
		head -c "$5" >"$work/script.b64"
		got=$(wc -c <"$work/script.b64")
		if ! IFS= read -r end || [ -n "$end" ] || [ "$((got))" -ne "$5" ]; then
			printf 'E %s framing\n' "$id"
			continue
		fi
		if [ "$3" != "$boot" ]; then
			printf 'E %s stale %s\n' "$id" "$boot"
			continue
		fi
		if ! base64 -d <"$work/script.b64" >"$work/script" 2>/dev/null; then
			printf 'E %s base64\n' "$id"
			continue
		fi
		(cd / && exec timeout -k 10 "$4" sh "$work/script") </dev/null >"$work/stdout" 2>"$work/stderr"
		code=$?
		printf 'R %s %s ' "$id" "$code"
		encode "$work/stdout"
		printf ' '
		encode "$work/stderr"
		printf '\n'
		;;
	esac
done
