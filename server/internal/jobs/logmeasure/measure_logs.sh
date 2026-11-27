#!/bin/sh
# EasyRMM log measurement (ADR-0060, slice 1), for Linux. Reads what the
# computer's logs hold for the last DAYS days (the first argument, default
# 7) and prints one JSON document: per source, per code and per
# subcategory, the events and the estimated bytes, in all and as the
# collector's default filters would keep them. It changes nothing.
#
# Bytes are an estimate of one raw event as the store would keep it, its
# fields as JSON without the rendered message: 250 bytes for the envelope
# plus the length of the message and of its identifiers. Names are reduced
# to letters, digits and a few punctuation marks, so the output needs no
# JSON escaping. Output schema: easyrmm.logmeasure/1. Run as root: auditd's
# log and the whole journal need it.
set -eu

days=${1:-7}
case $days in
'' | *[!0-9]*)
	echo "usage: measure_logs.sh [days]" >&2
	exit 2
	;;
esac
[ "$days" -ge 1 ] || days=1

work=$(mktemp -d "${TMPDIR:-/tmp}/easyrmm-logmeasure.XXXXXX")
trap 'rm -rf "$work"' EXIT HUP INT TERM
tab=$(printf '\t')

now=$(date +%s)
cutoff=$((now - days * 86400))
cutdate=$(date -d "@$cutoff" +%Y-%m-%d)
cutmd=$(date -d "@$cutoff" +%m%d)
todaymd=$(date -d "@$now" +%m%d)
host=$(hostname 2>/dev/null || cat /etc/hostname 2>/dev/null || echo unknown)
host=$(printf '%s' "$host" | tr -c 'A-Za-z0-9._-' '_')
generated=$(date -u +%Y-%m-%dT%H:%M:%SZ)
notroot=0
[ "$(id -u)" -eq 0 ] || notroot=1

summary="$work/sources.tsv"
rows="$work/rows.tsv"
: >"$summary"
: >"$rows"

# source <name> <present 0|1> <paths> <note>
source_line() { printf 'S\t%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" >>"$summary"; }

# The codes the journal's messages get (ADR-0060, Codes): a name for the
# messages the server's parser knows, else the program's identifier.
classify='
function classify(id, msg) {
	if (id == "sshd") {
		if (index(msg, "Accepted ")) return "sshd.accepted"
		if (index(msg, "Failed ")) return "sshd.failed"
		if (index(msg, "Invalid user")) return "sshd.invalid_user"
		return "sshd"
	}
	if (id == "sudo") {
		if (index(msg, "COMMAND=")) return "sudo.command"
		if (index(msg, "NOT in sudoers") || index(msg, "incorrect password") || index(msg, "authentication failure")) return "sudo.denied"
		return "sudo"
	}
	if (id == "su" || id == "su-l") {
		if (index(msg, "FAILED") || index(msg, "authentication failure")) return "su.failed"
		return id
	}
	if (id == "") return "(none)"
	return id
}
function clean(s) { gsub(/[^A-Za-z0-9 ._:@=+(),#<>\/-]/, "_", s); if (s == "") s = "(none)"; return s }
function add(src, kind, name, b, kept) {
	k = src "\t" kind "\t" clean(name)
	ev[k]++; by[k] += b
	if (kept) { kev[k]++; kby[k] += b }
}
function dump(   k) {
	for (k in ev) printf "C\t%s\t%d\t%.0f\t%d\t%.0f\n", k, ev[k], by[k], kev[k] + 0, kby[k] + 0
}
'

# ---- The journal: linux.auth, linux.system and linux.av ----
journal_ok=0
journal_note=""
if command -v journalctl >/dev/null 2>&1; then
	if journalctl --no-pager -q -n 1 -o cat >"$work/probe" 2>/dev/null && [ -s "$work/probe" ]; then
		journal_ok=1
	else
		journal_note="The journal is empty or cannot be read."
	fi
else
	journal_note="journalctl is not installed."
fi
[ "$notroot" -eq 0 ] || journal_note="$journal_note Not run as root: the journal shows only this user's own entries."

if [ "$journal_ok" -eq 1 ]; then
	journalctl --no-pager -q -o export --since "$days days ago" 2>/dev/null |
		awk "$classify"'
		function flush(   b, auth, av, u) {
			if (!seen) return
			b = 250 + length(msg) + length(id) + length(unit)
			add("linux.system", "code", id != "" ? id : unit, b, pri != "" && pri + 0 <= 3)
			add("linux.system", "sub", "priority " (pri == "" ? "unknown" : pri), b, pri != "" && pri + 0 <= 3)
			auth = (fac == "4" || fac == "10" || unit == "systemd-logind.service")
			if (auth) {
				add("linux.auth", "code", classify(id, msg), b, 1)
				add("linux.auth", "sub", unit == "systemd-logind.service" ? "systemd-logind" : (fac == "10" ? "authpriv" : "auth"), b, 1)
			}
			av = (unit == "mdatp.service" || unit == "clamav-daemon.service" || unit == "clamav-freshclam.service" || unit ~ /^clamd@.*\.service$/)
			if (av) {
				add("linux.av", "code", classify(id, msg), b, 1)
				add("linux.av", "sub", unit, b, 1)
			}
			fac = ""; pri = ""; id = ""; unit = ""; msg = ""; seen = 0
		}
		/^$/ { flush(); next }
		{ seen = 1 }
		/^SYSLOG_FACILITY=/ { fac = substr($0, 17); next }
		/^PRIORITY=/ { pri = substr($0, 10); next }
		/^SYSLOG_IDENTIFIER=/ { id = substr($0, 19); next }
		/^_SYSTEMD_UNIT=/ { unit = substr($0, 15); next }
		/^MESSAGE=/ { msg = substr($0, 9); next }
		END { flush(); dump() }
		' >"$work/journal.tsv" 2>/dev/null || journal_note="$journal_note The journal could not be read to its end."
	cat "$work/journal.tsv" >>"$rows"
fi

journal_paths=""
[ "$journal_ok" -eq 0 ] || journal_paths="journald"
for s in linux.auth linux.system linux.av; do
	present=$journal_ok
	if [ "$s" = linux.av ] && [ "$journal_ok" -eq 1 ] && ! grep -q "^C${tab}linux.av${tab}" "$rows"; then
		present=0
		source_line "$s" 0 "$journal_paths" "No Defender for Endpoint or ClamAV unit logged in the period."
		continue
	fi
	source_line "$s" "$present" "$journal_paths" "$journal_note"
done

# ---- auditd's log: linux.audit ----
# The two names below can be set to read other files (the tests do).
logfile=${LOGMEASURE_AUDIT_LOG:-/var/log/audit/audit.log}
if [ -z "${LOGMEASURE_AUDIT_LOG:-}" ] && [ -r /etc/audit/auditd.conf ]; then
	configured=$(awk -F= '/^[ \t]*log_file[ \t]*=/ { gsub(/[ \t]/, "", $2); print $2 }' /etc/audit/auditd.conf 2>/dev/null | tail -n 1)
	[ -z "$configured" ] || logfile=$configured
fi
audit_files=""
for f in "$logfile" "$logfile.1"; do
	[ -r "$f" ] && audit_files="$audit_files $f"
done
if [ -n "$audit_files" ]; then
	# shellcheck disable=SC2086 # the file names hold no spaces or globs
	cat $audit_files | awk -v cutoff="$cutoff" "$classify"'
	{
		if (!match($0, /audit\([0-9]+/)) next
		t = substr($0, RSTART + 6, RLENGTH - 6) + 0
		if (t < cutoff) next
		type = $1; sub(/^type=/, "", type)
		kept = 0
		if (index($0, "key=\"easyrmm-logs-") || index($0, "key=\"easyrmm-hardening-")) kept = 1
		else if (type ~ /^(DAEMON_|ANOM_)/) kept = 1
		else if (type ~ /^(LOGIN|USER_LOGIN|USER_AUTH|USER_CMD|ADD_USER|DEL_USER|ADD_GROUP|DEL_GROUP|USER_MGMT|GRP_MGMT|USER_CHAUTHTOK|CONFIG_CHANGE|AVC|USER_AVC)$/) kept = 1
		b = 250 + length($0)
		add("linux.audit", "code", "audit." type, b, kept)
	}
	END { dump() }
	' >>"$rows"
	if grep -q "^C${tab}linux.audit${tab}" "$rows"; then
		source_line linux.audit 1 "$audit_files" ""
	else
		source_line linux.audit 1 "$audit_files" "auditd's log holds no record in the period."
	fi
elif [ -e "$logfile" ]; then
	source_line linux.audit 0 "$logfile" "auditd's log exists but cannot be read; run as root."
else
	source_line linux.audit 0 "$logfile" "auditd's log does not exist."
fi

# ---- /var/log/auth.log or /var/log/secure: linux.file ----
# Collected only where the journal keeps nothing; elsewhere it repeats it.
authfile=""
for f in ${LOGMEASURE_AUTH_FILE:-/var/log/auth.log /var/log/secure}; do
	if [ -r "$f" ]; then
		authfile=$f
		break
	fi
done
if [ -n "$authfile" ]; then
	applies=$((1 - journal_ok))
	awk -v authfile="$authfile" -v cutdate="$cutdate" -v cutmd="$cutmd" -v todaymd="$todaymd" -v applies="$applies" "$classify"'
	BEGIN { split("Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec", mn, " "); for (i = 1; i <= 12; i++) mon[mn[i]] = i }
	{
		if ($1 ~ /^[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]/) {
			if (substr($1, 1, 10) < cutdate) next
			ident = $3
		} else {
			if (!($1 in mon)) next
			md = mon[$1] * 100 + $2
			if (cutmd + 0 <= todaymd + 0) { if (md < cutmd + 0 || md > todaymd + 0) next }
			else if (md < cutmd + 0 && md > todaymd + 0) next
			ident = $5
		}
		sub(/\[.*/, "", ident); sub(/:$/, "", ident)
		b = 250 + length($0)
		add("linux.file", "code", classify(ident, $0), b, applies + 0)
		add("linux.file", "sub", authfile, b, applies + 0)
	}
	END { dump() }
	' "$authfile" >>"$rows"
	if [ "$applies" -eq 1 ]; then
		source_line linux.file 1 "$authfile" ""
	else
		source_line linux.file 1 "$authfile" "The journal is read, so the default filter keeps none of this file: it repeats the journal."
	fi
else
	source_line linux.file 0 "/var/log/auth.log /var/log/secure" "Neither file exists or can be read."
fi

# ---- The JSON ----
{
	printf 'H\t%s\t%s\t%s\n' "$host" "$days" "$generated"
	cat "$summary"
	# Biggest first within each source and kind.
	sort -t "$tab" -k2,2 -k3,3 -k6,6nr "$rows"
} | awk -F '\t' -v maxcodes=300 '
function clean(s) { gsub(/[^A-Za-z0-9 ._:@=+(),#<>\/-]/, "_", s); return s }
function paths(list,   n, a, i, out) {
	n = split(list, a, " ")
	out = ""
	for (i = 1; i <= n; i++) out = out (i > 1 ? "," : "") "\"" clean(a[i]) "\""
	return out
}
function row(kind, name, e, b, ke, kb) {
	return "{\"" (kind == "code" ? "code" : "name") "\":\"" name "\",\"events\":" e ",\"bytes\":" sprintf("%.0f", b) ",\"filteredEvents\":" ke ",\"filteredBytes\":" sprintf("%.0f", kb) "}"
}
$1 == "H" { host = $2; days = $3; gen = $4; next }
$1 == "S" { n++; order[n] = $2; present[$2] = $3; pth[$2] = $4; note[$2] = $5; next }
$1 == "C" {
	s = $2; kind = $3
	if (kind == "code") {
		tot[s, "e"] += $5; tot[s, "b"] += $6; tot[s, "ke"] += $7; tot[s, "kb"] += $8
		if (++cnt[s] > maxcodes) { omitted[s]++; next }
		codes[s] = codes[s] (codes[s] == "" ? "" : ",") row("code", $4, $5, $6, $7, $8)
	} else {
		subs[s] = subs[s] (subs[s] == "" ? "" : ",") row("name", $4, $5, $6, $7, $8)
	}
	next
}
END {
	printf "{\"schema\":\"easyrmm.logmeasure/1\",\"platform\":\"linux\",\"hostname\":\"%s\",\"days\":%d,\"generatedAt\":\"%s\",", clean(host), days, gen
	printf "\"bytesModel\":\"250 bytes plus the length of the message and its identifiers\",\"sources\":["
	for (i = 1; i <= n; i++) {
		s = order[i]
		printf "%s{\"source\":\"%s\",\"present\":%s,\"channels\":[%s],\"truncated\":false,\"notes\":[", (i > 1 ? "," : ""), s, (present[s] == 1 ? "true" : "false"), paths(pth[s])
		nt = note[s]; gsub(/^ +| +$/, "", nt)
		if (nt != "") printf "\"%s\"", clean(nt)
		printf "],\"events\":%d,\"bytes\":%.0f,\"filteredEvents\":%d,\"filteredBytes\":%.0f,", tot[s, "e"], tot[s, "b"], tot[s, "ke"], tot[s, "kb"]
		printf "\"codes\":[%s],\"codesOmitted\":%d,\"subcategories\":[%s]}", codes[s], omitted[s] + 0, subs[s]
	}
	print "]}"
}
'
