package httpapi

import (
	"bytes"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
)

func TestChainOrder(t *testing.T) {
	var order []string
	mw := func(name string) Middleware {
		return func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				order = append(order, name)
				next.ServeHTTP(w, r)
			})
		}
	}
	h := Chain(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { order = append(order, "handler") }),
		mw("outer"), mw("middle"), mw("inner"))
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
	if got := strings.Join(order, ","); got != "outer,middle,inner,handler" {
		t.Fatalf("order = %s", got)
	}
}

func clientIPThrough(t *testing.T, trusted []netip.Prefix, remote string, xff ...string) netip.Addr {
	t.Helper()
	var got netip.Addr
	h := RealIP(trusted)(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		got = ClientIP(r)
	}))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = remote
	for _, v := range xff {
		req.Header.Add("X-Forwarded-For", v)
	}
	h.ServeHTTP(httptest.NewRecorder(), req)
	return got
}

func TestRealIP(t *testing.T) {
	proxies := []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32"), netip.MustParsePrefix("10.0.0.0/8")}
	cases := []struct {
		name    string
		trusted []netip.Prefix
		remote  string
		xff     []string
		want    string
	}{
		{"no proxies configured ignores header", nil, "203.0.113.9:5555", []string{"1.2.3.4"}, "203.0.113.9"},
		{"untrusted peer cannot spoof", proxies, "203.0.113.9:5555", []string{"1.2.3.4"}, "203.0.113.9"},
		{"trusted peer, single hop", proxies, "127.0.0.1:40000", []string{"198.51.100.7"}, "198.51.100.7"},
		{"right-most untrusted hop wins", proxies, "127.0.0.1:40000", []string{"6.6.6.6, 198.51.100.7, 10.1.2.3"}, "198.51.100.7"},
		{"multiple headers are joined", proxies, "127.0.0.1:40000", []string{"6.6.6.6", "198.51.100.7, 10.1.2.3"}, "198.51.100.7"},
		{"garbage stops the walk", proxies, "127.0.0.1:40000", []string{"198.51.100.7, not-an-ip, 10.1.2.3"}, "10.1.2.3"},
		{"all hops trusted", proxies, "127.0.0.1:40000", []string{"10.9.9.9, 10.1.2.3"}, "10.9.9.9"},
		{"trusted peer without header", proxies, "127.0.0.1:40000", nil, "127.0.0.1"},
		{"ipv4-mapped ipv6 hop is unmapped", proxies, "127.0.0.1:40000", []string{"::ffff:198.51.100.7"}, "198.51.100.7"},
		{"ipv4-mapped peer is unmapped", proxies, "[::ffff:127.0.0.1]:40000", []string{"198.51.100.8"}, "198.51.100.8"},
		{"ipv6 peer", nil, "[2001:db8::1]:443", nil, "2001:db8::1"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := clientIPThrough(t, c.trusted, c.remote, c.xff...)
			if got.String() != c.want {
				t.Fatalf("client ip = %s, want %s", got, c.want)
			}
		})
	}
}

func TestClientIPWithoutMiddleware(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "192.0.2.4:1234"
	if got := ClientIP(req); got.String() != "192.0.2.4" {
		t.Fatalf("ClientIP = %s", got)
	}
	req.RemoteAddr = "192.0.2.5" // no port
	if got := ClientIP(req); got.String() != "192.0.2.5" {
		t.Fatalf("ClientIP without port = %s", got)
	}
	req.RemoteAddr = "@unix"
	if got := ClientIP(req); got.IsValid() {
		t.Fatalf("ClientIP for a non-IP peer = %s, want invalid", got)
	}
}

func TestRequestContext(t *testing.T) {
	var logs bytes.Buffer
	base := slog.New(slog.NewJSONHandler(&logs, nil))
	var seenID string
	var seenLogger *slog.Logger
	h := RequestContext(base)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenID = RequestID(r)
		seenLogger = LoggerFrom(r.Context())
		w.WriteHeader(http.StatusTeapot)
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/x?token=secret", nil))
	if seenID == "" || len(seenID) != 16 || rec.Header().Get("X-Request-Id") != seenID {
		t.Fatalf("request id %q, header %q", seenID, rec.Header().Get("X-Request-Id"))
	}
	if seenLogger == nil || seenLogger == slog.Default() {
		t.Fatal("handler did not get the request logger")
	}
	out := logs.String()
	if !strings.Contains(out, `"status":418`) || !strings.Contains(out, `"path":"/x"`) || !strings.Contains(out, seenID) {
		t.Fatalf("log line: %s", out)
	}
	if strings.Contains(out, "secret") {
		t.Fatalf("query string was logged: %s", out)
	}

	// Server errors are logged at error level; implicit 200 via Write.
	logs.Reset()
	h = RequestContext(base)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		w.WriteHeader(http.StatusOK) // ignored: the first status wins
	}))
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
	if !strings.Contains(logs.String(), `"level":"ERROR"`) || !strings.Contains(logs.String(), `"status":502`) {
		t.Fatalf("5xx log line: %s", logs.String())
	}
	logs.Reset()
	h = RequestContext(base)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("hi"))
	}))
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
	if !strings.Contains(logs.String(), `"status":200`) {
		t.Fatalf("implicit 200 log line: %s", logs.String())
	}
}

func TestRequestIDAbsent(t *testing.T) {
	if id := RequestID(httptest.NewRequest(http.MethodGet, "/", nil)); id != "" {
		t.Fatalf("RequestID = %q", id)
	}
}

func TestStatusRecorderUnwrap(t *testing.T) {
	rec := httptest.NewRecorder()
	s := &statusRecorder{ResponseWriter: rec}
	if s.Unwrap() != rec {
		t.Fatal("Unwrap should return the wrapped writer")
	}
}

func TestRecover(t *testing.T) {
	var logs bytes.Buffer
	base := slog.New(slog.NewTextHandler(&logs, nil))
	h := RequestContext(base)(Recover(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic("boom with secret")
	})))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d", rec.Code)
	}
	if d := decodeError(t, rec); d.Code != "internal_error" || strings.Contains(rec.Body.String(), "secret") {
		t.Fatalf("body = %s", rec.Body.String())
	}
	if !strings.Contains(logs.String(), "panic serving request") || !strings.Contains(logs.String(), "boom with secret") {
		t.Fatalf("panic not logged: %s", logs.String())
	}
	if errPanic.Error() != "handler panic" {
		t.Fatal("errPanic message")
	}
}

func TestRecoverRepanicsAbortHandler(t *testing.T) {
	h := Recover(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic(http.ErrAbortHandler)
	}))
	defer func() {
		v := recover()
		err, ok := v.(error)
		if !ok || !errors.Is(err, http.ErrAbortHandler) {
			t.Fatalf("recovered %v, want http.ErrAbortHandler", v)
		}
	}()
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
	t.Fatal("ErrAbortHandler should propagate")
}

func TestRecoverPassThrough(t *testing.T) {
	h := Recover(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusAccepted) }))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d", rec.Code)
	}
}

func TestSecurityHeaders(t *testing.T) {
	serve := func(hsts bool, frame string) http.Header {
		rec := httptest.NewRecorder()
		SecurityHeaders(hsts, frame)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).
			ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
		return rec.Header()
	}
	h := serve(true, "https://mesh.example.com")
	csp := h.Get("Content-Security-Policy")
	for _, want := range []string{"default-src 'self'", "frame-src https://mesh.example.com", "frame-ancestors 'none'", "object-src 'none'", "base-uri 'none'", "img-src 'self' data:"} {
		if !strings.Contains(csp, want) {
			t.Errorf("CSP %q lacks %q", csp, want)
		}
	}
	if strings.Contains(csp, "unsafe-inline") || strings.Contains(csp, "unsafe-eval") {
		t.Errorf("CSP allows unsafe sources: %q", csp)
	}
	want := map[string]string{
		"X-Content-Type-Options":       "nosniff",
		"X-Frame-Options":              "DENY",
		"Referrer-Policy":              "no-referrer",
		"Cross-Origin-Opener-Policy":   "same-origin",
		"Cross-Origin-Resource-Policy": "same-origin",
		"Strict-Transport-Security":    "max-age=63072000; includeSubDomains",
	}
	for k, v := range want {
		if h.Get(k) != v {
			t.Errorf("%s = %q, want %q", k, h.Get(k), v)
		}
	}
	if !strings.Contains(h.Get("Permissions-Policy"), "camera=()") {
		t.Errorf("Permissions-Policy = %q", h.Get("Permissions-Policy"))
	}

	h = serve(false, "")
	if h.Get("Strict-Transport-Security") != "" {
		t.Error("HSTS sent when disabled")
	}
	if !strings.Contains(h.Get("Content-Security-Policy"), "frame-src 'none'") {
		t.Errorf("CSP without frame origin: %q", h.Get("Content-Security-Policy"))
	}
}
