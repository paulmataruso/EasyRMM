//go:build integration

package tlscert

import (
	"context"
	"errors"
	"net/http"
	"net/netip"
	"testing"
	"time"
)

// The checks against a server answering on its own ports: a name that resolves
// to this server passes, a token is served only while a name is being checked,
// a name whose AAAA record points elsewhere fails, one that does not resolve
// warns, and a name is checked at most once every ten seconds.
func TestChecks(t *testing.T) {
	pb := startPebble(t, 3600)
	here, elsewhere := netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("2001:db8::1")
	f := newFixture(t, pb, []string{"chk.test", "v6.test", "nores.test"}, func(s *Settings) {
		s.CheckHTTPPort, s.CheckHTTPSPort = s.HTTPPort, s.TLSPort
		s.CAAResolvers = []string{fakeDNS(t, nil, nil)}
		s.Lookup = func(_ context.Context, h string) ([]netip.Addr, error) {
			switch h {
			case "nores.test":
				return nil, errors.New("no such host")
			case "v6.test":
				return []netip.Addr{here, elsewhere}, nil
			}
			return []netip.Addr{here}, nil
		}
	})
	if err := f.svc.Start(f.ctx); err != nil {
		t.Fatal(err)
	}
	f.serve(f.svc)
	f.until(f.svc, "chk.test's certificate", 90*time.Second, func() bool { return f.row(f.svc, "chk.test").HasCertificate() })

	status := func(cs []Check, id string) string {
		for _, c := range cs {
			if c.ID == id {
				return c.Status
			}
		}
		return "missing"
	}
	cs, err := f.svc.Check(f.ctx, "chk.test")
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"resolves", "records", "caa", "port80", "port443"} {
		if status(cs, id) != CheckOK {
			t.Errorf("%s: %s; all %+v", id, status(cs, id), cs)
		}
	}
	if _, err := f.svc.Check(f.ctx, "chk.test"); err == nil {
		t.Fatal("a second check within ten seconds")
	} else if soon := new(ErrTooSoon); !errors.As(err, &soon) || soon.RetryAfter <= 0 {
		t.Fatalf("the refusal: %v", err)
	}
	// The token was removed with the check, and is served for no one else.
	for _, path := range []string{"/.well-known/easyrmm-check/abc"} {
		req, _ := http.NewRequest("GET", "http://127.0.0.1:"+pb.HTTPPort+path, nil)
		req.Host = "chk.test"
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("a token outside a check: %d", resp.StatusCode)
		}
	}

	cs, err = f.svc.Check(f.ctx, "v6.test")
	if err != nil {
		t.Fatal(err)
	}
	if status(cs, "records") != CheckFail || status(cs, "port80") != CheckWarn {
		t.Errorf("an AAAA record that points elsewhere: %+v", cs)
	}
	cs, err = f.svc.Check(f.ctx, "nores.test")
	if err != nil {
		t.Fatal(err)
	}
	if status(cs, "resolves") != CheckWarn || status(cs, "port80") != "missing" {
		t.Errorf("a name that does not resolve: %+v", cs)
	}
	if _, err := f.svc.Check(f.ctx, "unmanaged.test"); !errors.Is(err, ErrNoName) {
		t.Fatalf("an unmanaged name: %v", err)
	}
}

// Order anyway orders for a name the server cannot resolve, without waiting
// for DNS; the scheduler alone waits and shows "waiting for DNS".
func TestOrderAnywayForANameThatDoesNotResolve(t *testing.T) {
	pb := startPebble(t, 3600)
	f := newFixture(t, pb, []string{"split.test"}, func(s *Settings) {
		s.Lookup = func(context.Context, string) ([]netip.Addr, error) { return nil, errors.New("no such host") }
	})
	if err := f.svc.Start(f.ctx); err != nil {
		t.Fatal(err)
	}
	f.serve(f.svc)
	f.tick(f.svc)
	r := f.row(f.svc, "split.test")
	if r.WaitingDNSSince.IsZero() || r.HasCertificate() || !r.LastAttemptAt.IsZero() {
		t.Fatalf("the scheduler did not wait for DNS: %+v", r)
	}
	if st, _ := f.svc.Status(f.ctx); st.Names[0].State != StateWaitingDNS {
		t.Fatalf("state %s", st.Names[0].State)
	}
	if err := f.svc.OrderAnyway(f.ctx, admin, "split.test"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the certificate", 90*time.Second, func() bool { return f.row(f.svc, "split.test").HasCertificate() })
	if f.auditCount("tls.order_anyway") != 1 || f.row(f.svc, "split.test").OrderAnyway {
		t.Fatal("audit or flag after the order")
	}
}
