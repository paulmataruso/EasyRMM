package app

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/paulmataruso/easyrmm/server/internal/config"
	"github.com/paulmataruso/easyrmm/server/internal/pki"
)

func TestEdgeAddress(t *testing.T) {
	for listen, want := range map[string]string{
		":443":               "127.0.0.1:443",
		"0.0.0.0:8443":       "127.0.0.1:8443",
		"[::]:443":           "[::1]:443",
		"192.0.2.5:443":      "192.0.2.5:443",
		"127.0.0.1:9443":     "127.0.0.1:9443",
		"[2001:db8::5]:443":  "[2001:db8::5]:443",
		"rmm.example.com:44": "127.0.0.1:44",
		"":                   "127.0.0.1:443",
	} {
		if got := edgeAddress(listen); got != want {
			t.Errorf("edgeAddress(%q) = %s, want %s", listen, got, want)
		}
	}
}

// standInEdge is a stand-in for EasyRMM's own HTTPS listener: it serves the
// internal authority's certificate and reports the name each request asked
// for.
func standInEdge(t *testing.T, ca *pki.Authority) net.Listener {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: ca.GetCertificate})
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/moved" {
			http.Redirect(w, r, "https://elsewhere.example/", http.StatusFound)
			return
		}
		_, _ = io.WriteString(w, r.Host+" "+r.TLS.ServerName)
	})}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return ln
}

func TestAuthentikClient(t *testing.T) {
	ca, err := pki.New()
	if err != nil {
		t.Fatal(err)
	}
	if err := ca.SetAddresses(context.Background(), []string{"auth.rmm.test"}, nil); err != nil {
		t.Fatal(err)
	}
	ln := standInEdge(t, ca)
	cfg := &config.Config{TLSMode: config.TLSInternal, ListenHTTPS: ln.Addr().String(), Authentik: config.Authentik{Hostname: "auth.rmm.test"}}
	client, err := authentikClient(cfg, ca)
	if err != nil {
		t.Fatal(err)
	}
	// get returns the status and body.
	get := func(c *http.Client, url string) (int, string, error) {
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
		resp, err := c.Do(req)
		if err != nil {
			return 0, "", err
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b), nil
	}

	// The public name, over loopback, with TLS verified for it.
	status, body, err := get(client, "https://auth.rmm.test/application/o/easyrmm/.well-known/openid-configuration")
	if err != nil || status != http.StatusOK || body != "auth.rmm.test auth.rmm.test" {
		t.Fatalf("status %d, body %q, err %v", status, body, err)
	}
	// Redirects are not followed.
	status, _, err = get(client, "https://auth.rmm.test/moved")
	if err != nil || status != http.StatusFound {
		t.Fatalf("redirect: %d %v", status, err)
	}
	// Nothing but Authentik's name.
	if _, _, err := get(client, "https://elsewhere.example/"); err == nil || !strings.Contains(err.Error(), "is not auth.rmm.test") {
		t.Fatalf("another name: %v", err)
	}
	// Without EasyRMM's authority (another TLS mode), its certificate is not trusted.
	cfg.TLSMode = config.TLSManual
	untrusting, err := authentikClient(cfg, ca)
	if err != nil {
		t.Fatal(err)
	}
	var unknown x509.UnknownAuthorityError
	if _, _, err := get(untrusting, "https://auth.rmm.test/"); err == nil || !errors.As(err, &unknown) {
		t.Fatalf("an untrusted certificate: %v", err)
	}
}

func TestAuthentikProxy(t *testing.T) {
	var hsts string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Upgrade") == "websocket" {
			hj, _ := w.(http.Hijacker)
			conn, rw, err := hj.Hijack()
			if err != nil {
				return
			}
			defer conn.Close()
			_, _ = rw.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
			_ = rw.Flush()
			line, _ := rw.ReadString('\n')
			_, _ = rw.WriteString("echo " + line)
			_ = rw.Flush()
			return
		}
		if hsts != "" {
			w.Header().Set("Strict-Transport-Security", hsts)
		}
		_ = json.NewEncoder(w).Encode(map[string]string{
			"host": r.Host, "for": r.Header.Get("X-Forwarded-For"), "proto": r.Header.Get("X-Forwarded-Proto"),
			"fhost": r.Header.Get("X-Forwarded-Host"), "forwarded": r.Header.Get("Forwarded"), "uri": r.RequestURI,
		})
	}))
	defer upstream.Close()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	proxy := httptest.NewServer(authentikProxy(upstream.Listener.Addr().String(), true, log))
	defer proxy.Close()

	// do returns the status, the headers and the request the upstream saw.
	do := func(path string, header map[string]string) (int, http.Header, map[string]string) {
		t.Helper()
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, proxy.URL+path, nil)
		req.Host = "auth.rmm.test"
		for k, v := range header {
			req.Header.Set(k, v)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var got map[string]string
		_ = json.NewDecoder(resp.Body).Decode(&got)
		return resp.StatusCode, resp.Header, got
	}

	// The name is kept; a client's own forwarding headers are replaced.
	_, header, got := do("/if/flow/easyrmm-enrollment/?itoken=x", map[string]string{
		"X-Forwarded-For": "203.0.113.66", "X-Forwarded-Proto": "http", "X-Forwarded-Host": "evil.example", "Forwarded": "for=203.0.113.66",
	})
	want := map[string]string{"host": "auth.rmm.test", "for": "127.0.0.1", "proto": "https", "fhost": "auth.rmm.test", "forwarded": "",
		"uri": "/if/flow/easyrmm-enrollment/?itoken=x"}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %q, want %q", k, got[k], v)
		}
	}
	if header.Get("Strict-Transport-Security") != "max-age=63072000" {
		t.Errorf("HSTS %q", header.Get("Strict-Transport-Security"))
	}
	// Authentik's own HSTS is left as it is.
	hsts = "max-age=1"
	if _, header, _ := do("/", nil); header.Get("Strict-Transport-Security") != "max-age=1" {
		t.Errorf("Authentik's HSTS replaced: %q", header.Get("Strict-Transport-Security"))
	}

	// Websockets go through.
	conn, err := net.Dial("tcp", proxy.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_, _ = io.WriteString(conn, "GET /ws/client/ HTTP/1.1\r\nHost: auth.rmm.test\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"+
		"Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: "+base64.StdEncoding.EncodeToString([]byte("the sample nonce"))+"\r\n\r\n")
	r := bufio.NewReader(conn)
	status, _ := r.ReadString('\n')
	if !strings.Contains(status, "101") {
		t.Fatalf("upgrade: %q", status)
	}
	for {
		line, err := r.ReadString('\n')
		if err != nil || line == "\r\n" {
			break
		}
	}
	_, _ = io.WriteString(conn, "ping\n")
	if line, _ := r.ReadString('\n'); line != "echo ping\n" {
		t.Fatalf("over the websocket: %q", line)
	}

	// Authentik down: a plain answer, not a hang.
	upstream.Close()
	code, header, _ := do("/", nil)
	if code != http.StatusBadGateway || header.Get("Retry-After") == "" {
		t.Fatalf("Authentik down: %d", code)
	}
}
