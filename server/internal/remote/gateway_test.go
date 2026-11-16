package remote

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/paulmataruso/easyrmm/server/internal/meshcentral"
)

// upstream records what the gateway forwards.
type upstream struct {
	*httptest.Server
	got chan *http.Request
}

func newUpstream(t *testing.T) *upstream {
	t.Helper()
	u := &upstream{got: make(chan *http.Request, 16)}
	u.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u.got <- r.Clone(r.Context())
		_, _ = io.WriteString(w, "from meshcentral")
	}))
	t.Cleanup(u.Close)
	return u
}

func newTestGateway(t *testing.T, up string, secure bool) *Gateway {
	t.Helper()
	target, _ := url.Parse(up)
	g, err := NewGateway(nil, GatewayConfig{Upstream: target, Secure: secure}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return g
}

func serve(g *Gateway, r *http.Request) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	g.ServeHTTP(w, r)
	return w
}

func TestNewGatewayValidates(t *testing.T) {
	if _, err := NewGateway(nil, GatewayConfig{}, nil); err == nil {
		t.Fatal("NewGateway without an upstream succeeded")
	}
	g := newTestGateway(t, "http://127.0.0.1:1", true)
	if g.CookieName() != "__Host-easyrmm_remote" {
		t.Errorf("secure cookie name = %q", g.CookieName())
	}
	if g := newTestGateway(t, "http://127.0.0.1:1", false); g.CookieName() != "easyrmm_remote" {
		t.Errorf("development cookie name = %q", g.CookieName())
	}
}

func TestGatewayForwardsAgents(t *testing.T) {
	up := newUpstream(t)
	g := newTestGateway(t, up.URL, true)
	r := httptest.NewRequest(http.MethodGet, "https://mesh.example.com/agent.ashx?x=1", nil)
	r.RemoteAddr = "203.0.113.7:5555"
	r.Header.Set("X-Forwarded-For", "10.9.9.9")
	r.Header.Set("Forwarded", "for=10.9.9.9")
	w := serve(g, r)
	if w.Code != http.StatusOK || w.Body.String() != "from meshcentral" {
		t.Fatalf("agent request: %d %q", w.Code, w.Body.String())
	}
	in := <-up.got
	if in.Host != "mesh.example.com" {
		t.Errorf("upstream Host = %q, want the public hostname", in.Host)
	}
	if got := in.Header.Get("X-Forwarded-For"); got != "203.0.113.7" {
		t.Errorf("X-Forwarded-For = %q, want only the real client address", got)
	}
	if in.Header.Get("Forwarded") != "" || in.Header.Get("X-Forwarded-Proto") != "https" {
		t.Errorf("forwarding headers = %v", in.Header)
	}
	if w.Header().Get("Strict-Transport-Security") == "" {
		t.Error("no HSTS on a secure gateway response")
	}
}

func TestGatewayRefusesBrowsersWithoutGrant(t *testing.T) {
	up := newUpstream(t)
	g := newTestGateway(t, up.URL, true)
	cases := []struct {
		name string
		path string
		hdr  map[string]string
	}{
		{"root", "/", nil},
		{"browser on an agent route", "/meshrelay.ashx", map[string]string{"Origin": "https://rmm.example.com"}},
		{"fetch metadata on an agent route", "/agent.ashx", map[string]string{"Sec-Fetch-Mode": "navigate"}},
		{"control channel", "/control.ashx", nil},
		{"unknown cookie value", "/", map[string]string{"Cookie": "other=1"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "https://mesh.example.com"+c.path, nil)
			for k, v := range c.hdr {
				r.Header.Set(k, v)
			}
			w := serve(g, r)
			if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "Remote session required") {
				t.Fatalf("got %d %q", w.Code, w.Body.String())
			}
			if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
				t.Errorf("Content-Type = %q", ct)
			}
		})
	}
	select {
	case r := <-up.got:
		t.Fatalf("forwarded %s without a grant", r.URL)
	default:
	}
}

func TestGatewayBlocksFeatures(t *testing.T) {
	up := newUpstream(t)
	g := newTestGateway(t, up.URL, true)
	for _, c := range []struct{ method, path string }{
		{http.MethodGet, "/meshsettings?id=x"},
		{http.MethodGet, "/MeshSettings?id=x"},
		{http.MethodGet, "/invite"},
		{http.MethodGet, "/createaccount"},
		{http.MethodPost, "/login"},
		{http.MethodPost, "/LOGIN/"},
		{http.MethodGet, "/auth-oidc"},
		{http.MethodGet, "/backup.zip"},
		{http.MethodGet, "/pluginadmin.ashx"},
		{http.MethodGet, "/webrelay.ashx"},
		{http.MethodGet, "/mstsc.html"},
		{http.MethodGet, "/mstscrelay.ashx"},
		{http.MethodGet, "/sshterminalrelay.ashx"},
		{http.MethodGet, "/amtevents.ashx"},
		{http.MethodGet, "/sharing"},
	} {
		r := httptest.NewRequest(c.method, "https://mesh.example.com"+c.path, nil)
		r.Header.Set("Sec-Fetch-Mode", "navigate")
		if w := serve(g, r); w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "Not available") {
			t.Errorf("%s %s: %d %q", c.method, c.path, w.Code, w.Body.String())
		}
	}
	// Agents fetching an update use an agent route; it is not blocked.
	r := httptest.NewRequest(http.MethodGet, "https://mesh.example.com/meshagents?id=6&auth=x", nil)
	if w := serve(g, r); w.Code != http.StatusOK {
		t.Errorf("agent update download: %d", w.Code)
	}
	// The device page cannot open a device without the MeshCommander frame,
	// and it loads the RDP client scripts; both are static and are not
	// blocked (they still need a grant, like every page).
	for _, p := range []string{"/commander.ashx", "/mstsc/mstsc.js", "/mstsc/client.js"} {
		if blocked(http.MethodGet, p) {
			t.Errorf("%s is blocked", p)
		}
	}
}

func TestGatewayRefusesUnusualPaths(t *testing.T) {
	g := newTestGateway(t, "http://127.0.0.1:1", true)
	for _, raw := range []string{"//meshsettings", "/x/../meshsettings", "/./agent.ashx", "/a%2fb", "/%2e%2e/x", `/a\b`} {
		r := httptest.NewRequest(http.MethodGet, "https://mesh.example.com/", nil)
		r.URL = &url.URL{Path: raw, RawPath: ""}
		if strings.Contains(raw, "%") {
			u, err := url.Parse("https://mesh.example.com" + raw)
			if err != nil {
				t.Fatal(err)
			}
			r.URL = u
		}
		if w := serve(g, r); w.Code != http.StatusBadRequest {
			t.Errorf("%q: %d", raw, w.Code)
		}
	}
	for _, ok := range []string{"/", "/agent.ashx", "/scripts/x.js", "/styles/"} {
		r := httptest.NewRequest(http.MethodGet, "https://mesh.example.com"+ok, nil)
		if unusualPath(r) {
			t.Errorf("%q reported unusual", ok)
		}
	}
}

func TestGatewayLaunchRejectsPost(t *testing.T) {
	g := newTestGateway(t, "http://127.0.0.1:1", true)
	w := serve(g, httptest.NewRequest(http.MethodPost, "https://mesh.example.com"+LaunchPath+"?t=x", nil))
	if w.Code != http.StatusMethodNotAllowed || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("POST launch: %d %v", w.Code, w.Header())
	}
}

func TestGatewayUpstreamDown(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	g := newTestGateway(t, "http://"+addr, true)
	w := serve(g, httptest.NewRequest(http.MethodGet, "https://mesh.example.com/agent.ashx", nil))
	if w.Code != http.StatusBadGateway || !strings.Contains(w.Body.String(), "unavailable") {
		t.Fatalf("upstream down: %d %q", w.Code, w.Body.String())
	}
}

func TestStripOwnCookie(t *testing.T) {
	g := newTestGateway(t, "http://127.0.0.1:1", true)
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Cookie", "xid=abc; __Host-easyrmm_remote=secret; xid.sig=def")
	g.stripOwnCookie(r)
	if got := r.Header.Get("Cookie"); got != "xid=abc; xid.sig=def" {
		t.Errorf("Cookie = %q", got)
	}
	r.Header.Set("Cookie", "__Host-easyrmm_remote=secret")
	g.stripOwnCookie(r)
	if _, ok := r.Header["Cookie"]; ok {
		t.Errorf("Cookie header kept: %q", r.Header.Get("Cookie"))
	}
}

func TestPageEscapes(t *testing.T) {
	w := httptest.NewRecorder()
	page(w, http.StatusTeapot, `<b>"x"</b>`, "a & b")
	body := w.Body.String()
	if strings.Contains(body, "<b>") || !strings.Contains(body, "&lt;b&gt;&#34;x&#34;") || !strings.Contains(body, "a &amp; b") {
		t.Errorf("body = %s", body)
	}
	if !strings.Contains(w.Header().Get("Content-Security-Policy"), "default-src 'none'") {
		t.Error("no CSP on the message page")
	}
}

func TestTrackingAndSweepBookkeeping(t *testing.T) {
	g := newTestGateway(t, "http://127.0.0.1:1", true)
	s1, s2 := uuid.New(), uuid.New()
	a, b := net.Pipe()
	defer func() { _ = b.Close() }()
	c1 := g.track(s1, a)
	x, y := net.Pipe()
	defer func() { _ = y.Close() }()
	g.track(s2, x)
	if g.OpenConnections() != 2 {
		t.Fatalf("open = %d", g.OpenConnections())
	}
	_ = c1.Close()
	_ = c1.Close() // idempotent
	if g.OpenConnections() != 1 {
		t.Fatalf("open after close = %d", g.OpenConnections())
	}
	g.remember("cookie", s2)
	if s, ok := g.cache[cookieKey("cookie")]; !ok || s.session != s2 || !s.until.After(time.Now()) {
		t.Fatalf("cache entry = %+v", s)
	}
	g.closeAll()
	if g.OpenConnections() != 0 {
		t.Fatalf("open after closeAll = %d", g.OpenConnections())
	}
	if _, err := x.Write([]byte("x")); err == nil {
		t.Error("connection still open after closeAll")
	}
}

func TestGatewayRunClosesConnectionsOnShutdown(t *testing.T) {
	target, _ := url.Parse("http://127.0.0.1:1")
	g, err := NewGateway(nil, GatewayConfig{Upstream: target, CacheTTL: time.Hour}, nil)
	if err != nil {
		t.Fatal(err)
	}
	a, b := net.Pipe()
	defer func() { _ = b.Close() }()
	g.track(uuid.New(), a)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { g.Run(ctx); close(done) }()
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return")
	}
	if g.OpenConnections() != 0 {
		t.Fatal("connections left open at shutdown")
	}
	g.sweep(context.Background()) // nothing tracked: no lookups
}

func TestMalformedSecretsNeverReachTheDatabase(t *testing.T) {
	s := New(nil, nil, nil, Config{}, nil)
	for _, v := range []string{"", strings.Repeat("a", 129)} {
		if _, err := s.Redeem(context.Background(), v); !errors.Is(err, ErrGrantInvalid) {
			t.Errorf("Redeem(%d chars) = %v", len(v), err)
		}
		if _, err := s.CheckCookie(context.Background(), v); !errors.Is(err, ErrGrantInvalid) {
			t.Errorf("CheckCookie(%d chars) = %v", len(v), err)
		}
	}
}

func TestTrackingWriterUnwrapsAndNeedsHijacker(t *testing.T) {
	rec := httptest.NewRecorder()
	tw := &trackingWriter{ResponseWriter: rec, g: newTestGateway(t, "http://127.0.0.1:1", true), session: uuid.New()}
	if tw.Unwrap() != rec {
		t.Fatal("Unwrap")
	}
	if _, _, err := tw.Hijack(); err == nil {
		t.Fatal("Hijack on a writer that cannot hijack succeeded")
	}
}

func TestCachePrunesExpiredEntries(t *testing.T) {
	g := newTestGateway(t, "http://127.0.0.1:1", true)
	past := time.Now().Add(-time.Minute)
	for i := 0; i <= 10000; i++ {
		g.cache[cookieKey(strconv.Itoa(i))] = cached{until: past}
	}
	g.remember("fresh", uuid.New())
	if len(g.cache) != 1 {
		t.Fatalf("cache size after pruning = %d", len(g.cache))
	}
}

func TestHandleEventSchedulesDeviceRefresh(t *testing.T) {
	s := New(nil, nil, nil, Config{}, nil)
	s.HandleEvent(meshcentral.Event{Type: "user", Action: "accountchange"})
	select {
	case <-s.devices:
		t.Fatal("account event scheduled a device refresh")
	default:
	}
	s.HandleEvent(meshcentral.Event{Type: "node", Action: "changenode"})
	s.HandleEvent(meshcentral.Event{Type: "node", Action: "addnode"}) // coalesced
	select {
	case <-s.devices:
	default:
		t.Fatal("device event did not schedule a refresh")
	}
	// Connection changes carry no etype (as MeshCentral 1.3.1 sends them).
	s.HandleEvent(meshcentral.Event{Action: "nodeconnect"})
	select {
	case <-s.devices:
	default:
		t.Fatal("a disconnection did not schedule a refresh")
	}
	s.HandleEvent(meshcentral.Event{Action: "ifchange"})
	if len(s.devices) != 0 {
		t.Fatal("an unrelated event scheduled a refresh")
	}
	s.Changed()
	s.Changed()
	if len(s.full) != 1 {
		t.Fatal("full reconciliation requests not coalesced")
	}
}
