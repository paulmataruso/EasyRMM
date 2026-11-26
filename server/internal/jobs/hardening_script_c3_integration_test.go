//go:build integration

package jobs

import (
	"strings"
	"testing"
)

// The Linux checks of ADR-0078's C3, in the containers of
// TestCheckInContainers: SSH's session limit (with a stand-in for sshd -T)
// and account lockout (pam_faillock), which only report.

func settingOf(m HardeningModuleResult, id string) *HardeningSetting {
	for i := range m.Settings {
		if m.Settings[i].ID == id {
			return &m.Settings[i]
		}
	}
	return nil
}

func scriptC3Linux(t *testing.T, c *scriptContainer) {
	if !c.has(t, "sshd") {
		c.sh(t, `printf '%s\n' '#!/bin/sh' 'if [ "$1" = -T ]; then cat /tmp/easyrmm-test-sshd-T; fi' >/usr/local/sbin/sshd && chmod 0755 /usr/local/sbin/sshd`)
		for _, tc := range []struct {
			dump, state string
		}{
			{"maxsessions 10", "in_place"}, {"maxsessions 4", "in_place"}, {"maxsessions 20", "not_in_place"},
			{"maxsessions 0", "not_in_place"}, {"", "not_in_place"},
		} {
			c.sh(t, "printf '%s\\n%s' '"+tc.dump+"' '"+sshdDump+"' | sed '/^$/d' >/tmp/easyrmm-test-sshd-T")
			m := scriptModule(t, parseScriptResult(t, c.script(t, "check", "ssh"), []string{"ssh"}), "ssh")
			if s := settingOf(m, "ssh-max-sessions"); s == nil || s.State != tc.state {
				t.Errorf("sshd -T %q: ssh-max-sessions %+v, want %s", tc.dump, s, tc.state)
			}
		}
		c.sh(t, "rm -f /usr/local/sbin/sshd /tmp/easyrmm-test-sshd-T")
	}

	// Lockout, from files as pam_faillock's own documentation shows them.
	const pam = "/etc/pam.d/zz-easyrmm-test"
	c.sh(t, "[ ! -f /etc/security/faillock.conf ] || cp -p /etc/security/faillock.conf /tmp/easyrmm-test-faillock.conf; mkdir -p /etc/security")
	for _, tc := range []struct {
		name, pam, conf  string
		active, deny     string
		wantDenyContains string
	}{
		{"no faillock", "auth required pam_unix.so\n", "", "not_in_place", "not_in_place", ""},
		{"faillock, its default of 3", "auth required pam_faillock.so preauth silent\nauth required pam_unix.so\n", "", "in_place", "in_place", "3"},
		{"deny in the configuration", "auth required pam_faillock.so preauth silent\n", "# deny = 99\ndeny = 6\n", "in_place", "in_place", "6"},
		{"deny on the line", "auth [default=die] pam_faillock.so authfail deny=5 unlock_time=900\n", "deny = 20\n", "in_place", "in_place", "5"},
		{"deny too high", "auth required pam_faillock.so preauth silent\n", "deny = 20\n", "in_place", "not_in_place", "20"},
		{"deny 0 turns it off", "auth required pam_faillock.so preauth silent deny=0\n", "", "in_place", "not_in_place", "0"},
		{"faillock commented out", "# auth required pam_faillock.so preauth\n", "", "not_in_place", "not_in_place", ""},
	} {
		c.sh(t, "rm -f /etc/security/faillock.conf; printf '%s' '"+tc.pam+"' >"+pam+"; if [ -n '"+strings.TrimSpace(tc.conf)+"' ]; then printf '%s' '"+tc.conf+"' >/etc/security/faillock.conf; fi")
		m := scriptModule(t, parseScriptResult(t, c.script(t, "check", "lockout"), []string{"lockout"}), "lockout")
		a, d := settingOf(m, "lockout-faillock-active"), settingOf(m, "lockout-deny-threshold")
		if a == nil || d == nil || a.State != tc.active || d.State != tc.deny || !strings.Contains(d.Value, tc.wantDenyContains) {
			t.Errorf("%s: %+v %+v, want %s and %s (%s)", tc.name, a, d, tc.active, tc.deny, tc.wantDenyContains)
		}
	}
	// It only reports: apply changes no file of the sign-in stack.
	before := c.sh(t, "cat "+pam+" /etc/security/faillock.conf 2>&1; true")
	c.script(t, "apply", "lockout")
	if after := c.sh(t, "cat "+pam+" /etc/security/faillock.conf 2>&1; true"); after != before {
		t.Errorf("apply changed the sign-in stack:\n%s\nthen\n%s", before, after)
	}
	c.sh(t, "rm -f "+pam+" /etc/security/faillock.conf; [ ! -f /tmp/easyrmm-test-faillock.conf ] || mv /tmp/easyrmm-test-faillock.conf /etc/security/faillock.conf")
}
