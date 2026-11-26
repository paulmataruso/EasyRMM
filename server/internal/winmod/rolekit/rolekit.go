// Package rolekit is what the server-role modules of ADR-0076 share: the
// parsers their guards use, the refusal helpers, and the one alert kind all
// five roles have (the role's service has stopped). A role's package (dns,
// dhcp, and the others) supplies only its actions and its own rules.
package rolekit

import (
	"encoding/json"
	"net/netip"
	"strings"

	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/modules"
	"github.com/paulmataruso/easyrmm/server/internal/monitoring"
)

// Invalid is a refusal of a parameter's value: a 422 naming the parameter.
func Invalid(param, msg string) error { return apperr.Invalid("params."+param, msg) }

// Refuse is a refusal by a module's rule (protected_record, protected_zone
// and the like): a 409 with a stable code, before any job exists.
func Refuse(code, msg string) error { return apperr.Conflict(code, msg) }

// Str reads a text parameter from a Guard's canonical values.
func Str(p map[string]any, name string) string {
	s, _ := p[name].(string)
	return s
}

// Int reads a whole-number parameter from a Guard's canonical values.
func Int(p map[string]any, name string) (int64, bool) {
	n, ok := p[name].(int64)
	return n, ok
}

// IPv4 says whether s is a dotted-quad IPv4 address (no zone, no leading
// zeros, no mapped form).
func IPv4(s string) bool {
	a, err := netip.ParseAddr(s)
	return err == nil && a.Is4()
}

// IPv6 says whether s is an IPv6 address without a zone.
func IPv6(s string) bool {
	a, err := netip.ParseAddr(s)
	return err == nil && a.Is6() && !a.Is4In6() && a.Zone() == ""
}

// MAC says whether s is a 48-bit hardware address written as twelve hex
// digits, with or without - or : between the bytes.
func MAC(s string) bool {
	h := strings.NewReplacer("-", "", ":", "").Replace(s)
	if len(h) != 12 || (len(h) != len(s) && len(s) != 17) {
		return false
	}
	if len(s) == 17 {
		for i := 2; i < 17; i += 3 {
			if s[i] != s[2] || (s[i] != '-' && s[i] != ':') {
				return false
			}
		}
	}
	for _, r := range h {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') && (r < 'A' || r > 'F') {
			return false
		}
	}
	return true
}

// DNSOpts says what a DNS name may hold beyond letters, digits and hyphens.
type DNSOpts struct {
	// At allows the single name "@" (the zone's apex).
	At bool
	// Wildcard allows "*" as the whole first label.
	Wildcard bool
}

// DNSName says whether s is a DNS name of labels of 1 to 63 letters, digits,
// hyphens and underscores (service names start with one), 253 characters at
// most, with an optional trailing dot.
func DNSName(s string, o DNSOpts) bool {
	if s == "@" {
		return o.At
	}
	s = strings.TrimSuffix(s, ".")
	if s == "" || len(s) > 253 {
		return false
	}
	for i, l := range strings.Split(s, ".") {
		if l == "*" && o.Wildcard && i == 0 {
			continue
		}
		if l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return false
		}
		for _, r := range l {
			if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') && r != '-' && r != '_' {
				return false
			}
		}
	}
	return true
}

// ServiceState reads the role's service state from a snapshot's data:
// "running", "stopped" or another state the service is in.
type ServiceState func(data json.RawMessage) (string, error)

// ServiceStoppedKind is the alert kind "the role's service has stopped"
// every role has: it holds while the snapshot says the service is stopped,
// and the policy's minutes are the grace period (ADR-0076 section 9).
func ServiceStoppedKind(m modules.Module, name, label, action string, state ServiceState) monitoring.ModuleKind {
	return monitoring.ModuleKind{
		Name: name, Label: label, Module: m, Action: action, Grace: true,
		Eval: func(data json.RawMessage, _ *int) (monitoring.Verdict, error) {
			st, err := state(data)
			if err != nil || st == "" {
				return monitoring.Verdict{}, monitoring.ErrUnknown
			}
			return monitoring.Verdict{Holds: st == "stopped", Value: 1, Detail: "The service is " + st + "."}, nil
		},
	}
}

// ServiceStoppedDefault is its default policy: critical or warning, on or
// off, with a grace period.
func ServiceStoppedDefault(key, name, kind string, minutes int, severity string, enabled bool) monitoring.DefaultPolicy {
	return monitoring.DefaultPolicy{
		Key: key, Name: name, Kind: kind, Minutes: minutes, Severity: severity, Enabled: enabled,
		Description: "The role's service has been stopped for the grace period.",
	}
}
