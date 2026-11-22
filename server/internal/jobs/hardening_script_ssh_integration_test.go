//go:build integration

package jobs

// The SSH module's guards (ADR-0051), in the containers of
// TestCheckInContainers, with stand-ins for sshd (its sshd -T) and
// journalctl (a journal of entries with their fields): what may turn
// password sign-in off, and what tells whether root signs in with a
// password.

import (
	"bytes"
	"encoding/base64"
	"slices"
	"strings"
	"testing"
)

// sshdDump is what the stand-in sshd -T prints, but for overrides.
const sshdDump = `port 22
permitrootlogin no
passwordauthentication yes
kbdinteractiveauthentication yes
pubkeyauthentication yes
usepam yes
authorizedkeysfile /etc/easyrmm-test-keys/%u
authorizedkeyscommand none
`

// testJournalctl stands in for journalctl: it prints the message of each
// entry in /tmp/easyrmm-test-journal ("FIELD=VALUE ...", a tab, the
// message) that the arguments' matches select, as journalctl does: matches
// of one field are alternatives, those of different fields all apply.
const testJournalctl = `#!/bin/sh
m=
for a; do case $a in [A-Z_]*=*) m="$m $a" ;; esac; done
while IFS='	' read -r f msg; do
	ok=yes
	for k in $(printf '%s\n' $m | cut -d= -f1 | sort -u); do
		hit=no
		for a in $m; do
			[ "${a%%=*}" = "$k" ] || continue
			case " $f " in *" $a "*) hit=yes ;; esac
		done
		[ "$hit" = yes ] || ok=no
	done
	[ "$ok" = no ] || printf '%s\n' "$msg"
done </tmp/easyrmm-test-journal
`

// scriptSSHGuards: password-off needs an administrator who may sign in
// with a key, a line that is one, and root's password sign-in is told
// from what sshd's own processes, as root, wrote to the journal: a line
// any user writes (logger -t sshd, or a copy of logger named sshd) does
// not count.
func scriptSSHGuards(t *testing.T, c *scriptContainer) {
	if c.has(t, "sshd") {
		return
	}
	blob := append([]byte{0, 0, 0, 11}, "ssh-ed25519"...)
	blob = append(append(blob, 0, 0, 0, 32), bytes.Repeat([]byte{7}, 32)...)
	key := "ssh-ed25519 " + base64.StdEncoding.EncodeToString(blob) + " admin@example"
	const user = "easyrmm-kt"
	c.sh(t, `cp -p /etc/passwd /tmp/easyrmm-test-passwd && cp -p /etc/shadow /tmp/easyrmm-test-shadow && cp -p /etc/group /tmp/easyrmm-test-group &&
mkdir -p /etc/easyrmm-test-keys && printf '%s\n' '#!/bin/sh' 'if [ "$1" = -T ]; then cat /tmp/easyrmm-test-sshd-T; fi' >/usr/local/sbin/sshd && chmod 0755 /usr/local/sbin/sshd`)

	type account struct {
		admin                 bool
		shell, password, till string
	}
	admin := account{admin: true, shell: "/bin/sh", password: "$6$x"}
	pwOff := "PasswordAuthentication no"
	refused := "Refused: password sign-in stays on, because no account that may sign in has a key in its authorized keys file and sshd has no AuthorizedKeysCommand"
	for _, tc := range []struct {
		name             string
		a                account
		userKey, rootKey string
		sshd             string
		want             string
	}{
		{"no keys", admin, "", "", "", refused},
		{"a line that is not a key", admin, "not a key at all", "", "", refused},
		{"a key that is not base64", admin, "ssh-ed25519 AAAA!!!! admin@example", "", "", refused},
		{"a key of another type than it says", admin, "ssh-rsa" + strings.TrimPrefix(key, "ssh-ed25519"), "", "", refused},
		{"a key with a forced command", admin, `command="/bin/true" ` + key, "", "", refused},
		{"a commented-out key", admin, "# " + key, "", "", refused},
		{"a key", admin, key, "", "", pwOff},
		{"a key with options", admin, `no-pty,from="192.0.2.0/24" ` + key, "", "", pwOff},
		{"not an administrator", account{shell: "/bin/sh", password: "$6$x"}, key, "", "", refused},
		{"no login shell", account{admin: true, shell: "/usr/sbin/nologin", password: "$6$x"}, key, "", "", refused},
		{"expired", account{admin: true, shell: "/bin/sh", password: "$6$x", till: "1"}, key, "", "", refused},
		{"locked, sshd with PAM", account{admin: true, shell: "/bin/sh", password: "!$6$x"}, key, "", "", pwOff},
		{"locked, sshd without PAM", account{admin: true, shell: "/bin/sh", password: "!$6$x"}, key, "", "usepam no", refused},
		{"denied by sshd", admin, key, "", "denyusers " + user, refused},
		{"keys off in sshd", admin, key, "", "pubkeyauthentication no", refused},
		{"root with a key", account{shell: "/bin/sh", password: "$6$x"}, "", key, "permitrootlogin prohibit-password", pwOff},
		{"root with a key, PermitRootLogin no", account{shell: "/bin/sh", password: "$6$x"}, "", key, "", refused},
		{"an AuthorizedKeysCommand", account{shell: "/bin/sh"}, "", "", "authorizedkeyscommand /bin/true", pwOff},
	} {
		groups := ""
		if tc.a.admin {
			groups = `awk -F: -v OFS=: '$1 == "sudo" || $1 == "wheel" { $4 = $4 == "" ? "` + user + `" : $4 ",` + user + `" } { print }' /tmp/easyrmm-test-group >/etc/group && `
		}
		c.sh(t, "cp -p /tmp/easyrmm-test-passwd /etc/passwd && cp -p /tmp/easyrmm-test-shadow /etc/shadow && cp -p /tmp/easyrmm-test-group /etc/group && "+groups+
			"printf '%s\\n' '"+user+":x:4242:100::/home/"+user+":"+tc.a.shell+"' >>/etc/passwd && "+
			"printf '%s\\n' '"+user+":"+tc.a.password+":19000:0:99999:7::"+tc.a.till+":' >>/etc/shadow && "+
			"rm -f /etc/easyrmm-test-keys/* && "+
			"if [ -n '"+tc.userKey+"' ]; then printf '%s\\n' '"+tc.userKey+"' >/etc/easyrmm-test-keys/"+user+"; fi && "+
			"if [ -n '"+tc.rootKey+"' ]; then printf '%s\\n' '"+tc.rootKey+"' >/etc/easyrmm-test-keys/root; fi && "+
			"printf '%s\\n%s\\n' '"+tc.sshd+"' '"+strings.TrimSuffix(sshdDump, "\n")+"' | sed '/^$/d' >/tmp/easyrmm-test-sshd-T")
		m := scriptModule(t, parseScriptResult(t, c.script(t, "check", "ssh", "password-off"), []string{"ssh"}), "ssh")
		other := refused
		if tc.want == refused {
			other = pwOff
		}
		if !slices.Contains(m.Changes, tc.want) || slices.Contains(m.Changes, other) {
			t.Errorf("%s: %+v, want %q", tc.name, m.Changes, tc.want)
		}
	}

	// Root's password sign-in: the journal (and no log file, here).
	c.sh(t, "cp -p /tmp/easyrmm-test-passwd /etc/passwd && cp -p /tmp/easyrmm-test-shadow /etc/shadow && cp -p /tmp/easyrmm-test-group /etc/group && "+
		"cat >/usr/local/sbin/journalctl <<'EOF'\n"+testJournalctl+"EOF\nchmod 0755 /usr/local/sbin/journalctl && "+
		"printf 'permitrootlogin yes\\n%s' '"+sshdDump+"' >/tmp/easyrmm-test-sshd-T")
	const forged = "Accepted password for root from 192.0.2.7 port 4242 ssh2"
	const kept = "Left as it is: PermitRootLogin yes, because root signed in with a password in the last 30 days (the root-password-off option changes it anyway)"
	for _, tc := range []struct {
		name, journal, want string
	}{
		{"what users wrote as sshd", "_UID=1000 _COMM=logger SYSLOG_IDENTIFIER=sshd\t" + forged + "\n" +
			"_UID=1000 _COMM=sshd SYSLOG_IDENTIFIER=sshd\t" + forged + "\n" +
			"_UID=0 _COMM=sshd SYSLOG_IDENTIFIER=sshd\tAccepted publickey for root from 192.0.2.7 port 4243 ssh2: ED25519 SHA256:x\n",
			"PermitRootLogin prohibit-password"},
		{"what sshd wrote", "_UID=0 _COMM=sshd-session SYSLOG_IDENTIFIER=sshd-session\t" + forged + "\n", kept},
	} {
		c.sh(t, "printf '%s' '"+tc.journal+"' >/tmp/easyrmm-test-journal")
		m := scriptModule(t, parseScriptResult(t, c.script(t, "check", "ssh"), []string{"ssh"}), "ssh")
		if !slices.Contains(m.Changes, tc.want) {
			t.Errorf("root's password sign-in, %s: %+v, want %q", tc.name, m.Changes, tc.want)
		}
	}
	c.sh(t, "rm -rf /usr/local/sbin/sshd /usr/local/sbin/journalctl /etc/easyrmm-test-keys /tmp/easyrmm-test-sshd-T /tmp/easyrmm-test-journal "+
		"/tmp/easyrmm-test-passwd /tmp/easyrmm-test-shadow /tmp/easyrmm-test-group")
}
