package rolekit

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/paulmataruso/easyrmm/server/internal/modules"
	"github.com/paulmataruso/easyrmm/server/internal/monitoring"
)

func TestParsers(t *testing.T) {
	for s, want := range map[string]bool{"192.0.2.1": true, "0.0.0.0": true, "192.0.2.256": false, "192.0.2": false, "::1": false,
		"::ffff:192.0.2.1": false, "01.2.3.4": false, "1.2.3.4 ": false, "": false} {
		if IPv4(s) != want {
			t.Errorf("IPv4(%q) != %v", s, want)
		}
	}
	for s, want := range map[string]bool{"2001:db8::1": true, "::1": true, "fe80::1%eth0": false, "::ffff:192.0.2.1": false, "192.0.2.1": false} {
		if IPv6(s) != want {
			t.Errorf("IPv6(%q) != %v", s, want)
		}
	}
	for s, want := range map[string]bool{"00-11-22-33-44-55": true, "aa:bb:cc:dd:ee:ff": true, "001122334455": true,
		"00-11:22-33:44-55": false, "00-11-22-33-44": false, "00-11-22-33-44-5g": false, "": false} {
		if MAC(s) != want {
			t.Errorf("MAC(%q) != %v", s, want)
		}
	}
	o := DNSOpts{At: true, Wildcard: true}
	for s, want := range map[string]bool{"@": true, "www": true, "*.apps": true, "a.*": false, "_ldap._tcp": true, "host.example.com.": true,
		"-a": false, "a-": false, "a..b": false, "": false, "a b": false, "é": false, strings.Repeat("a", 64): false,
		strings.Repeat("a.", 126) + "a": true, strings.Repeat("a.", 127) + "a": false} {
		if DNSName(s, o) != want {
			t.Errorf("DNSName(%q) != %v", s, want)
		}
	}
	if DNSName("@", DNSOpts{}) || DNSName("*.x", DNSOpts{}) {
		t.Error("@ and * are options")
	}
}

func TestServiceStoppedKind(t *testing.T) {
	state := func(data json.RawMessage) (string, error) {
		var v struct{ S string }
		return v.S, json.Unmarshal(data, &v)
	}
	k := ServiceStoppedKind(modules.DNS, "x_service_stopped", "X service stopped", "x.status", state)
	if !k.Grace || k.Module != modules.DNS || k.Action != "x.status" {
		t.Errorf("%+v", k)
	}
	for data, want := range map[string]bool{`{"S":"stopped"}`: true, `{"S":"running"}`: false, `{"S":"start_pending"}`: false} {
		v, err := k.Eval(json.RawMessage(data), nil)
		if err != nil || v.Holds != want {
			t.Errorf("%s: %+v %v", data, v, err)
		}
	}
	for _, data := range []string{`{"S":""}`, `nope`} {
		if _, err := k.Eval(json.RawMessage(data), nil); !errors.Is(err, monitoring.ErrUnknown) {
			t.Errorf("%s: %v", data, err)
		}
	}
	d := ServiceStoppedDefault("k", "N", "x_service_stopped", 10, monitoring.SeverityCritical, true)
	if d.Minutes != 10 || !d.Enabled || d.Kind != "x_service_stopped" {
		t.Errorf("%+v", d)
	}
}
