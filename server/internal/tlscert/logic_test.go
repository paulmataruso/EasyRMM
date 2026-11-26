package tlscert

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"
)

var t0 = time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)

func TestRetryDelayFollowsTheGuide(t *testing.T) {
	for i, want := range []time.Duration{time.Minute, 10 * time.Minute, 100 * time.Minute, 24 * time.Hour, 24 * time.Hour} {
		if got := retryDelay(i+1, 0); got != want {
			t.Errorf("after %d failures: %s, want %s", i+1, got, want)
		}
	}
	// Capped at a tenth of the renewal window: a short-lived certificate still gets several attempts.
	if got := retryDelay(3, 600*time.Second); got != 60*time.Second {
		t.Errorf("capped: %s", got)
	}
}

func TestBudget(t *testing.T) {
	fails := []time.Time{t0.Add(-50 * time.Minute), t0.Add(-30 * time.Minute), t0.Add(-10 * time.Minute)}
	if ok, at := withinBudget(fails, autoBudget, t0); ok || !at.Equal(t0.Add(10*time.Minute)) {
		t.Errorf("automatic: %v %s", ok, at)
	}
	if ok, _ := withinBudget(fails, retryBudget, t0); !ok {
		t.Error("Retry now allowed a fourth")
	}
	if ok, _ := withinBudget(fails, autoBudget, t0.Add(11*time.Minute)); !ok {
		t.Error("the oldest failure did not age out")
	}
}

func TestThresholdsAreFractionsOfTheLifetime(t *testing.T) {
	for _, life := range []time.Duration{90 * 24 * time.Hour, 45 * 24 * time.Hour, 10 * time.Minute} {
		r := Row{Serial: "1", NotBefore: t0, NotAfter: t0.Add(life), MissingSince: t0}
		due, w := renewalWindow(r)
		if !due.Equal(t0.Add(life*2/3)) && due.Sub(t0.Add(life*2/3)).Abs() > time.Second {
			t.Errorf("%s: due %s", life, due)
		}
		if lv, _ := alertFor(r, t0.Add(life/2)); lv != LevelNone {
			t.Errorf("%s: alert before renewal is due: %s", life, lv)
		}
		// Failing for a quarter of W (or a day) after it became due: a warning.
		r.FailingSince = due
		warnAt := due.Add(min(w/4, 24*time.Hour))
		if lv, _ := alertFor(r, warnAt.Add(-time.Second)); lv != LevelNone {
			t.Errorf("%s: early warning %s", life, lv)
		}
		if lv, _ := alertFor(r, warnAt.Add(time.Second)); lv != LevelWarning {
			t.Errorf("%s: no warning, got %s", life, lv)
		}
		// Less than a quarter of W left: critical.
		if lv, _ := alertFor(r, r.NotAfter.Add(-w/4+time.Second)); lv != LevelCritical {
			t.Errorf("%s: not critical near expiry: %s", life, lv)
		}
		if lv, why := alertFor(r, r.NotAfter.Add(time.Second)); lv != LevelCritical || !strings.Contains(why, "expired") {
			t.Errorf("%s: expired: %s %s", life, lv, why)
		}
	}
}

func TestAlertCases(t *testing.T) {
	if lv, _ := alertFor(Row{MissingSince: t0}, t0.Add(59*time.Minute)); lv != LevelNone {
		t.Error("alert before an hour")
	}
	if lv, why := alertFor(Row{MissingSince: t0, WaitingDNSSince: t0}, t0.Add(61*time.Minute)); lv != LevelWarning || !strings.Contains(why, "resolve") {
		t.Errorf("waiting for DNS: %s %s", lv, why)
	}
	if lv, why := alertFor(Row{MissingSince: t0}, t0.Add(61*time.Minute)); lv != LevelWarning || !strings.Contains(why, "failing") {
		t.Errorf("failing: %s %s", lv, why)
	}
	r := Row{Serial: "1", NotBefore: t0, NotAfter: t0.Add(90 * 24 * time.Hour), FailingSince: t0.Add(60 * 24 * time.Hour), AriMoved: true}
	if lv, _ := alertFor(r, t0.Add(61*24*time.Hour)); lv != LevelCritical {
		t.Error("a renewal failing after the ARI window moved earlier is critical")
	}
	r = Row{Serial: "1", NotBefore: t0, NotAfter: t0.Add(90 * 24 * time.Hour), PendingSerial: "2", PendingReadyAt: t0}
	if lv, _ := alertFor(r, t0.Add(16*time.Minute)); lv != LevelWarning {
		t.Error("a swap pending past its cap")
	}
}

func TestMeshSlotRules(t *testing.T) {
	cert := func() *tls.Certificate {
		return &tls.Certificate{Leaf: &x509.Certificate{NotAfter: t0.Add(24 * time.Hour)}}
	}
	m := &MeshSlot{}
	a, b, c := cert(), cert(), cert()
	m.Offer(a, "a", t0, false)
	if m.Served() != a {
		t.Fatal("the first certificate waits")
	}
	// A read at T makes a swap at T+1m wait until T+3m.
	m.RecordRead(t0)
	m.Offer(b, "b", t0.Add(time.Minute), false)
	if m.Tick(t0.Add(time.Minute)) || m.Served() != a {
		t.Fatal("swapped one minute after a read")
	}
	if m.Tick(t0.Add(179 * time.Second)) {
		t.Fatal("swapped before three minutes")
	}
	if !m.Tick(t0.Add(3*time.Minute)) || m.Served() != b {
		t.Fatal("not swapped three minutes after the read")
	}
	if s, p, _ := m.State(); s != "b" || p != "" {
		t.Fatalf("state %s %s", s, p)
	}
	// Reads every minute still swap fifteen minutes after ready.
	ready := t0.Add(10 * time.Minute)
	m.Offer(c, "c", ready, false)
	for i := 1; i < 15; i++ {
		now := ready.Add(time.Duration(i) * time.Minute)
		m.RecordRead(now)
		if m.Tick(now) {
			t.Fatalf("swapped %d minutes after ready", i)
		}
	}
	m.RecordRead(ready.Add(15 * time.Minute))
	if !m.Tick(ready.Add(15 * time.Minute)) {
		t.Fatal("not swapped at the cap")
	}
	// An ARI revocation signal swaps at once; an offer already known is ignored.
	d := cert()
	m.RecordRead(t0.Add(time.Hour))
	m.Offer(d, "d", t0.Add(time.Hour), true)
	m.Offer(d, "d", t0.Add(time.Hour), true)
	if !m.Tick(t0.Add(time.Hour)) || m.Served() != d {
		t.Fatal("urgent swap")
	}
	// Never later than the served certificate's expiry.
	e := cert()
	m.Offer(e, "e", t0.Add(25*time.Hour), false)
	m.RecordRead(t0.Add(25 * time.Hour))
	if !m.Tick(t0.Add(25*time.Hour)) && m.Served() != e {
		t.Fatal("kept an expired certificate")
	}
	// A restart remembers the last read.
	n := &MeshSlot{}
	n.SetLastRead(t0)
	n.SetLastRead(t0.Add(-time.Hour))
	n.Offer(a, "a", t0, false)
	n.Offer(b, "b", t0, false)
	if n.Tick(t0.Add(time.Minute)) {
		t.Fatal("the stored read was forgotten")
	}
}

func TestMeshListenerServesWhateverNameAndRecordsReads(t *testing.T) {
	want := &tls.Certificate{}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	reads := make(chan time.Time, 8)
	done := make(chan error, 1)
	// A real certificate for the handshake to complete.
	cert := selfSigned(t, "mesh.test")
	go func() {
		done <- ServeMesh(ctx, ln, func(h *tls.ClientHelloInfo) (*tls.Certificate, error) {
			_ = want
			return cert, nil
		}, func(at time.Time) { reads <- at })
	}()
	for _, sni := range []string{"mesh.test", "anything.else", ""} {
		cfg := &tls.Config{InsecureSkipVerify: true, ServerName: sni, MinVersion: tls.VersionTLS12} //nolint:gosec // the test reads the certificate only
		c, err := tls.Dial("tcp", ln.Addr().String(), cfg)
		if err != nil {
			t.Fatalf("server name %q: %v", sni, err)
		}
		if got := c.ConnectionState().PeerCertificates[0].DNSNames; len(got) != 1 || got[0] != "mesh.test" {
			t.Fatalf("server name %q got %v", sni, got)
		}
		_ = c.Close()
		select {
		case <-reads:
		case <-time.After(3 * time.Second):
			t.Fatalf("a handshake for %q was not recorded as a read", sni)
		}
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestChallengePathAnswersManagedNamesOnly(t *testing.T) {
	s := New(Deps{}, Settings{Names: []string{"rmm.test"}})
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("next")) })
	h := s.HTTPHandler(next)
	for host, want := range map[string]int{"other.test": 404, "rmm.test": 404, "rmm.test:80": 404} {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", "/.well-known/acme-challenge/token", nil)
		r.Host = host
		h.ServeHTTP(w, r)
		if w.Code != want || strings.Contains(w.Body.String(), "next") {
			t.Errorf("%s: %d %q", host, w.Code, w.Body.String())
		}
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/x", nil))
	if w.Body.String() != "next" {
		t.Error("other requests do not go on")
	}
	// A check token is served only for a name being checked (storage is not reached for unmanaged names).
	w = httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/.well-known/easyrmm-check/abc", nil)
	r.Host = "other.test"
	h.ServeHTTP(w, r)
	if w.Code != 404 {
		t.Errorf("a token for an unmanaged name: %d", w.Code)
	}
}

func TestAddressPolicyOfTheChecks(t *testing.T) {
	s := New(Deps{}, Settings{Own: func() []netip.Addr {
		return []netip.Addr{netip.MustParseAddr("203.0.113.5"), netip.MustParseAddr("127.0.0.1")}
	}})
	for a, want := range map[string]bool{
		"203.0.113.5": true, "127.0.0.1": true, // this server's own
		"8.8.8.8": true, "2606:4700::1111": true, // public unicast
		"10.0.0.1": false, "127.0.0.2": false, "169.254.169.254": false, "100.100.100.200": false, "fd00:ec2::254": false,
		"224.0.0.1": false, "0.0.0.0": false, "192.168.1.1": false, "::1": false, "203.0.113.9": false,
	} {
		if got := s.dialAllowed(netip.MustParseAddr(a)); got != want {
			t.Errorf("%s: %v, want %v", a, got, want)
		}
	}
}

func TestRecordsCheck(t *testing.T) {
	s := New(Deps{}, Settings{Own: func() []netip.Addr { return []netip.Addr{netip.MustParseAddr("203.0.113.5")} }})
	for _, c := range []struct {
		addrs []string
		want  string
	}{
		{[]string{"203.0.113.5"}, CheckOK},
		{[]string{"198.51.100.1"}, CheckWarn},
		{[]string{"203.0.113.5", "2001:db8::1"}, CheckFail},
	} {
		var a []netip.Addr
		for _, x := range c.addrs {
			a = append(a, netip.MustParseAddr(x))
		}
		if got := s.recordsCheck(a); got.Status != c.want {
			t.Errorf("%v: %s, want %s", c.addrs, got.Status, c.want)
		}
	}
}

func TestPortNumber(t *testing.T) {
	for in, want := range map[string]int{"80": 80, ":8080": 8080, "127.0.0.1:443": 443, "": 0} {
		if got := portNumber(in); got != want {
			t.Errorf("%q: %d", in, got)
		}
	}
}

func TestRefusedErrorSaysWhen(t *testing.T) {
	e := &RefusedError{Reason: "too many", RetryAt: t0}
	if !strings.Contains(e.Error(), "2026-11-26T12:00:00Z") || (&RefusedError{Reason: "x"}).Error() != "tls: x" {
		t.Error(e.Error())
	}
	if !strings.Contains((&ErrTooSoon{RetryAfter: 3 * time.Second}).Error(), "wait 4 seconds") {
		t.Error("too soon")
	}
}
