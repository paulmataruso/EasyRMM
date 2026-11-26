//go:build windows

package jobs

import (
	"testing"

	"golang.org/x/sys/windows/registry"
)

// ADR-0078's C3 checks on a real Windows, as LocalSystem (see
// hardeningSystemTest): the registry settings read what is planted, and the
// readers of rights, time, application control and Office answer without
// failing the module.

// plantDWord and plantString write a value under HKLM for the test and put
// the key back as it was: the old value, or none, and no key where the test
// made it.
func plantDWord(t *testing.T, path, name string, v uint32) {
	t.Helper()
	k, existed, err := registry.CreateKey(registry.LOCAL_MACHINE, path, registry.ALL_ACCESS)
	if err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	_, _, before := k.GetIntegerValue(name)
	hadValue := before == nil
	var old uint64
	if hadValue {
		old, _, _ = k.GetIntegerValue(name)
	}
	if err := k.SetDWordValue(name, v); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if hadValue {
			_ = k.SetDWordValue(name, uint32(old))
		} else {
			_ = k.DeleteValue(name)
		}
		_ = k.Close()
		if !existed {
			_ = registry.DeleteKey(registry.LOCAL_MACHINE, path)
		}
	})
}

func plantString(t *testing.T, path, name, v string) {
	t.Helper()
	k, existed, err := registry.CreateKey(registry.LOCAL_MACHINE, path, registry.ALL_ACCESS)
	if err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	old, _, getErr := k.GetStringValue(name)
	if err := k.SetStringValue(name, v); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if getErr == nil {
			_ = k.SetStringValue(name, old)
		} else {
			_ = k.DeleteValue(name)
		}
		_ = k.Close()
		if !existed {
			_ = registry.DeleteKey(registry.LOCAL_MACHINE, path)
		}
	})
}

func TestWindowsC3ChecksAsSystem(t *testing.T) {
	hardeningSystemTest(t)
	const (
		system    = `SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`
		terminal  = `SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services`
		removable = `SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices\{53f5630d-b6bf-11d0-94f2-00a0c91efb8b}`
		wsh       = `SOFTWARE\Microsoft\Windows Script Host\Settings`
		credui    = `SOFTWARE\Policies\Microsoft\Windows\CredUI`
	)
	plantDWord(t, system, "InactivityTimeoutSecs", 600)
	plantString(t, system, "LegalNoticeCaption", "Authorized use only")
	plantString(t, system, "LegalNoticeText", "  ")
	plantDWord(t, terminal, "MaxIdleTime", 600000)
	plantDWord(t, terminal, "MaxDisconnectionTime", 3600000)
	plantDWord(t, removable, "Deny_Write", 1)
	plantDWord(t, wsh, "Enabled", 0)
	plantDWord(t, credui, "DisablePasswordReveal", 0)

	r := checkAll(t)
	for _, c := range []struct{ module, id, state string }{
		{"session", "session-inactivity-lock", "in_place"},
		{"session", "session-legal-caption", "in_place"},
		{"session", "session-legal-text", "not_in_place"},
		{"session", "session-credential-feedback", "not_in_place"},
		{"rdp", "rdp-idle-limit", "in_place"},
		{"rdp", "rdp-disconnected-limit", "not_in_place"},
		{"removable", "removable-deny-write", "in_place"},
		{"mobile-code", "mobile-code-script-host", "in_place"},
	} {
		s := setting(r, c.module, c.id)
		// A policy owner other than the planted value turns not in place into
		// managed elsewhere; a runner has none.
		if s == nil || s.State != c.state {
			t.Errorf("%s: %+v, want %s", c.id, s, c.state)
		}
	}
	// The readers that answer from Windows itself: they answer, and none
	// fails its module.
	for _, id := range []string{"rights-debug", "rights-take-ownership", "rights-load-driver", "rights-act-as-os", "rights-remote-logon",
		"rights-security-log", "rights-audit-generate", "rights-local-admins"} {
		s := setting(r, "rights", id)
		if s == nil || s.State == "unknown" {
			t.Errorf("%s: %+v", id, s)
		}
	}
	if s := setting(r, "rights", "rights-local-admins"); s != nil && s.Value == "" {
		t.Errorf("no count of administrators: %+v", s)
	}
	for _, c := range [][2]string{{"time", "time-service-running"}, {"time", "time-source-configured"}, {"time", "time-synchronized"},
		{"app-control", "app-control-enforced"}, {"office", "office-internet-macros"}} {
		if s := setting(r, c[0], c[1]); s == nil {
			t.Errorf("%s is not in the result", c[1])
		} else {
			t.Logf("%s: %s %q", c[1], s.State, s.Value)
		}
	}
	for _, m := range r.Modules {
		switch m.Module {
		case "session", "removable", "mobile-code", "rights", "time", "app-control", "office":
			if m.State == HardeningFailed || m.State == HardeningNotSupported {
				t.Errorf("module %s: %s (%s)", m.Module, m.State, m.Reason)
			}
		}
	}
}
