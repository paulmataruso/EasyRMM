//go:build integration

package main

import (
	"bytes"
	"strings"
	"testing"
)

// easyrmm-server tls check: nothing to check without ACME, a usage error for
// anything but "check", a configuration error, and, in ACME mode against the
// real database, a report per name that exits 1 on an error.
func TestTLSCheckCommand(t *testing.T) {
	setEnv(t)
	if got := run([]string{"migrate"}); got != 0 {
		t.Fatalf("migrate = %d", got)
	}
	var out, errs bytes.Buffer
	check := func(args ...string) int {
		out.Reset()
		errs.Reset()
		return tlsCommand(args, &out, &errs)
	}

	for _, args := range [][]string{nil, {"bogus"}, {"check", "extra"}} {
		if got := check(args...); got != 2 || !strings.Contains(errs.String(), "usage: easyrmm-server tls check") {
			t.Errorf("%v: %d %q", args, got, errs.String())
		}
	}

	if got := check("check"); got != 0 || !strings.Contains(out.String(), "TLS mode is offload") {
		t.Fatalf("offload: %d %q %q", got, out.String(), errs.String())
	}

	// A name that does not resolve is a warning, not a failure.
	t.Setenv("EASYRMM_TLS_MODE", "acme")
	t.Setenv("EASYRMM_PUBLIC_URL", "https://rmm.invalid")
	if got := check("check"); got != 0 || !strings.Contains(out.String(), "rmm.invalid\n") || !strings.Contains(out.String(), "[warn]") {
		t.Fatalf("unresolvable: %d %q %q", got, out.String(), errs.String())
	}

	// Names that resolve to this host with nothing listening: warnings, each
	// with its fix.
	t.Setenv("EASYRMM_PUBLIC_URL", "https://rmm.localhost")
	if got := check("check"); got != 0 || !strings.Contains(out.String(), "[ok  ]") || !strings.Contains(out.String(), "fix: Check that the port is forwarded") || errs.Len() != 0 {
		t.Fatalf("resolving names: %d %q %q", got, out.String(), errs.String())
	}

	// A database that cannot be reached is an error, not a report.
	t.Setenv("EASYRMM_DATABASE_URL", "postgres://x:y@127.0.0.1:1/none?sslmode=disable&connect_timeout=1")
	if got := check("check"); got != 1 || !strings.Contains(errs.String(), "tls check: ") {
		t.Fatalf("no database: %d %q", got, errs.String())
	}

	// A configuration that does not load.
	t.Setenv("EASYRMM_PUBLIC_URL", "")
	if got := check("check"); got != 1 || !strings.Contains(errs.String(), "configuration error") {
		t.Fatalf("config: %d %q", got, errs.String())
	}
}
