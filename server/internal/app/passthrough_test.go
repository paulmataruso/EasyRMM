package app

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/paulmataruso/easyrmm/server/internal/config"
)

// proxyListener reads the PROXY protocol v2 header each connection starts
// with, as EasyPatch's Caddy does, and reports the client it names as the
// connection's remote address. The parser follows the specification
// rather than sharing code with the sender.
type proxyListener struct {
	net.Listener
	require bool
	mu      sync.Mutex
	seen    []string // first bytes of connections without a header
}

type proxiedConn struct {
	net.Conn
	r      *bufio.Reader
	remote net.Addr
}

func (c *proxiedConn) Read(p []byte) (int, error) { return c.r.Read(p) }
func (c *proxiedConn) RemoteAddr() net.Addr       { return c.remote }

func (l *proxyListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		pc, err := l.parse(c)
		if err != nil {
			_ = c.Close()
			continue
		}
		return pc, nil
	}
}

func (l *proxyListener) parse(c net.Conn) (net.Conn, error) {
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	defer func() { _ = c.SetReadDeadline(time.Time{}) }()
	r := bufio.NewReader(c)
	head, err := r.Peek(16)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(head[:12], []byte("\r\n\r\n\x00\r\nQUIT\n")) {
		if l.require {
			return nil, errors.New("no PROXY header")
		}
		l.mu.Lock()
		l.seen = append(l.seen, string(head[:2]))
		l.mu.Unlock()
		return &proxiedConn{Conn: c, r: r, remote: c.RemoteAddr()}, nil
	}
	if _, err := r.Discard(16); err != nil {
		return nil, err
	}
	body := make([]byte, binary.BigEndian.Uint16(head[14:16]))
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, err
	}
	remote := c.RemoteAddr()
	switch {
	case head[12] == 0x21 && head[13] == 0x11 && len(body) >= 12:
		remote = &net.TCPAddr{IP: net.IP(body[0:4]), Port: int(binary.BigEndian.Uint16(body[8:10]))}
	case head[12] == 0x21 && head[13] == 0x21 && len(body) >= 36:
		remote = &net.TCPAddr{IP: net.IP(body[0:16]), Port: int(binary.BigEndian.Uint16(body[32:34]))}
	case head[12] == 0x20: // LOCAL
	default:
		return nil, fmt.Errorf("unexpected PROXY header %x", head[12:14])
	}
	return &proxiedConn{Conn: c, r: r, remote: remote}, nil
}

// fakeEasyPatch is an HTTPS server for patch.test behind a PROXY protocol
// listener, answering with the client address it was given.
type fakeEasyPatch struct {
	addr string
	ln   *proxyListener
	cert *x509.Certificate
	srv  *http.Server
}

func startFakeEasyPatch(t *testing.T, requireProxy bool) *fakeEasyPatch {
	t.Helper()
	certFile, keyFile, der := writeCert(t, t.TempDir(), "patch.test")
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeEasyPatch{addr: raw.Addr().String(), ln: &proxyListener{Listener: raw, require: requireProxy}, cert: cert}
	f.srv = &http.Server{
		ReadHeaderTimeout: 5 * time.Second,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = fmt.Fprintf(w, "easypatch remote=%s path=%s", r.RemoteAddr, r.URL.RequestURI())
		}),
	}
	go func() { _ = f.srv.ServeTLS(f.ln, certFile, keyFile) }()
	t.Cleanup(func() { _ = f.srv.Close() })
	return f
}

// clientFor is an HTTPS client that trusts cert and connects to addr
// whatever the URL's host, recording its own address for each connection.
func clientFor(cert *x509.Certificate, addr string, locals chan<- string) *http.Client {
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12},
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				c, err := (&net.Dialer{}).DialContext(ctx, network, addr)
				if err == nil && locals != nil {
					locals <- c.LocalAddr().String()
				}
				return c, err
			},
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

func readBody(t *testing.T, c *http.Client, rawURL string) (httpResult, string) {
	t.Helper()
	var resp *http.Response
	var err error
	for i := 0; i < 50; i++ { // the edge may not be listening yet
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, rawURL, nil)
		resp, err = c.Do(req)
		if err == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("GET %s: %v", rawURL, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return httpResult{StatusCode: resp.StatusCode, Header: resp.Header, TLS: resp.TLS}, string(b)
}

// cohostEdge is an edge in manual TLS mode for rmm.test with EasyPatch's
// patch.test passed through to upstream.
func cohostEdge(t *testing.T, upstream, httpUpstream string, proxy bool) (*config.Config, *x509.Certificate) {
	t.Helper()
	cfg := testConfig(t)
	cfg.TLSMode = config.TLSManual
	var der []byte
	cfg.CertFile, cfg.KeyFile, der = writeCert(t, t.TempDir(), "rmm.test")
	cfg.ListenHTTPS = freeAddr(t)
	cfg.ListenHTTP = freeAddr(t)
	cfg.EasyPatch = config.EasyPatchHost{Hostname: "patch.test", TLSUpstream: upstream, HTTPUpstream: httpUpstream, ProxyProtocol: proxy}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cfg, cert
}

func TestEdgePassesEasyPatchThrough(t *testing.T) {
	ep := startFakeEasyPatch(t, true)
	challenges := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintf(w, "challenge host=%s path=%s xff=%s", r.Host, r.URL.Path, r.Header.Get("X-Forwarded-For"))
	}))
	defer challenges.Close()
	cfg, rmmCert := cohostEdge(t, ep.addr, strings.TrimPrefix(challenges.URL, "http://"), true)
	e := &edge{cfg: cfg, handler: okHandler(), log: discard()}
	stop := runEdge(t, e)

	// EasyPatch's name reaches EasyPatch, with its own certificate, and the
	// PROXY header names the real client.
	locals := make(chan string, 10)
	resp, body := readBody(t, clientFor(ep.cert, cfg.ListenHTTPS, locals), "https://patch.test/api/v1/health?x=1")
	var local string
	for len(locals) > 0 {
		local = <-locals // the last dial is the one that succeeded
	}
	if want := "easypatch remote=" + local + " path=/api/v1/health?x=1"; body != want {
		t.Fatalf("EasyPatch answered %q, want %q", body, want)
	}
	if !resp.TLS.PeerCertificates[0].Equal(ep.cert) {
		t.Fatal("the certificate was not EasyPatch's own")
	}
	// The name matches without regard to case.
	conn, err := tls.Dial("tcp", cfg.ListenHTTPS, &tls.Config{ServerName: "PATCH.test", RootCAs: poolOf(ep.cert), MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatalf("mixed-case name: %v", err)
	}
	if !conn.ConnectionState().PeerCertificates[0].Equal(ep.cert) {
		t.Fatal("mixed-case name did not reach EasyPatch")
	}
	_ = conn.Close()

	// EasyRMM's own name is EasyRMM's, as before.
	_, body = readBody(t, clientFor(rmmCert, cfg.ListenHTTPS, nil), "https://rmm.test/")
	if body != "edge-ok" {
		t.Fatalf("EasyRMM's name answered %q", body)
	}
	// So is a connection without a server name (an IP address).
	conn, err = tls.Dial("tcp", cfg.ListenHTTPS, &tls.Config{InsecureSkipVerify: true}) //nolint:gosec // only checks who answers
	if err != nil {
		t.Fatal(err)
	}
	if !conn.ConnectionState().PeerCertificates[0].Equal(rmmCert) {
		t.Fatal("a connection without a server name left EasyRMM")
	}
	_ = conn.Close()
	// Plain HTTP on the HTTPS port still gets the HTTPS server's answer.
	raw, err := net.Dial("tcp", cfg.ListenHTTPS)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = raw.Write([]byte("GET / HTTP/1.0\r\nHost: patch.test\r\n\r\n"))
	line, _ := bufio.NewReader(raw).ReadString('\n')
	_ = raw.Close()
	if !strings.HasPrefix(line, "HTTP/1.0 400") {
		t.Fatalf("plain HTTP on the HTTPS port: %q", line)
	}

	// Port 80: EasyPatch's certificate challenges go to EasyPatch, the rest
	// of its name is redirected to HTTPS, and EasyRMM's names are as before.
	_, body = get(t, noRedirect(), "http://"+cfg.ListenHTTP+"/.well-known/acme-challenge/tok123", "patch.test")
	if !strings.HasPrefix(body, "challenge host=patch.test path=/.well-known/acme-challenge/tok123 xff=127.0.0.1") {
		t.Fatalf("challenge: %q", body)
	}
	r80, _ := get(t, noRedirect(), "http://"+cfg.ListenHTTP+"/login?next=%2F", "Patch.Test")
	if r80.StatusCode != http.StatusPermanentRedirect || r80.Header.Get("Location") != "https://patch.test/login?next=%2F" {
		t.Fatalf("EasyPatch redirect: %d %q", r80.StatusCode, r80.Header.Get("Location"))
	}
	r80, _ = get(t, noRedirect(), "http://"+cfg.ListenHTTP+"/x", "rmm.test")
	if r80.StatusCode != http.StatusPermanentRedirect || !strings.HasPrefix(r80.Header.Get("Location"), "https://rmm.test:") {
		t.Fatalf("EasyRMM redirect: %d %q", r80.StatusCode, r80.Header.Get("Location"))
	}
	r80, _ = get(t, noRedirect(), "http://"+cfg.ListenHTTP+"/x", "other.test")
	if r80.StatusCode != http.StatusMisdirectedRequest {
		t.Fatalf("unknown name on port 80: %d", r80.StatusCode)
	}

	// A connection passing through when the edge stops is closed, and the
	// edge does not wait for it.
	held, err := tls.Dial("tcp", cfg.ListenHTTPS, &tls.Config{ServerName: "patch.test", RootCAs: poolOf(ep.cert), MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	if _, err := held.Write([]byte("GET / HTTP/1.1\r\nHost: patch.test\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	first, err := http.ReadResponse(bufio.NewReader(held), nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = first.Body.Close()
	stop()
	_ = held.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := held.Read(make([]byte, 1)); err == nil || errors.Is(err, context.DeadlineExceeded) || isTimeout(err) {
		t.Fatalf("the passed-through connection stayed open after shutdown: %v", err)
	}
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

func poolOf(c *x509.Certificate) *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(c)
	return p
}

func TestEdgePassthroughWithoutProxyProtocol(t *testing.T) {
	ep := startFakeEasyPatch(t, false)
	cfg, _ := cohostEdge(t, ep.addr, "", false)
	stop := runEdge(t, &edge{cfg: cfg, handler: okHandler(), log: discard()})
	defer stop()

	_, body := readBody(t, clientFor(ep.cert, cfg.ListenHTTPS, nil), "https://patch.test/")
	// EasyPatch sees the edge's own address, and its first bytes are the
	// client's TLS handshake, untouched.
	if !strings.HasPrefix(body, "easypatch remote=127.0.0.1:") {
		t.Fatalf("EasyPatch answered %q", body)
	}
	ep.ln.mu.Lock()
	seen := append([]string(nil), ep.ln.seen...)
	ep.ln.mu.Unlock()
	if len(seen) == 0 || seen[0] != "\x16\x03" {
		t.Fatalf("EasyPatch's first bytes %q, want a TLS handshake record", seen)
	}

	// Without an HTTP upstream, certificate challenges for EasyPatch's name
	// are redirected like everything else (TLS-ALPN-01 still works on 443).
	r80, _ := get(t, noRedirect(), "http://"+cfg.ListenHTTP+"/.well-known/acme-challenge/tok", "patch.test")
	if r80.StatusCode != http.StatusPermanentRedirect {
		t.Fatalf("challenge without an HTTP upstream: %d", r80.StatusCode)
	}
}

func TestEdgePassthroughWhenEasyPatchIsDown(t *testing.T) {
	cfg, rmmCert := cohostEdge(t, freeAddr(t), freeAddr(t), true)
	stop := runEdge(t, &edge{cfg: cfg, handler: okHandler(), log: discard()})
	defer stop()
	// EasyRMM keeps working.
	if _, body := readBody(t, clientFor(rmmCert, cfg.ListenHTTPS, nil), "https://rmm.test/"); body != "edge-ok" {
		t.Fatalf("EasyRMM answered %q", body)
	}
	// EasyPatch's connections are closed rather than left hanging.
	_, err := tls.Dial("tcp", cfg.ListenHTTPS, &tls.Config{ServerName: "patch.test", MinVersion: tls.VersionTLS12})
	if err == nil {
		t.Fatal("a handshake completed with nothing behind it")
	}
	// Its certificate challenges get a gateway error.
	resp, _ := get(t, noRedirect(), "http://"+cfg.ListenHTTP+"/.well-known/acme-challenge/tok", "patch.test")
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("challenge with EasyPatch down: %d", resp.StatusCode)
	}
}

func TestSNIRouterDropsSilentClients(t *testing.T) {
	raw, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	r := startSNIRouter(raw, config.EasyPatchHost{Hostname: "patch.test", TLSUpstream: freeAddr(t)}, discard(), 200*time.Millisecond)
	defer r.Close()

	c, err := net.Dial("tcp", raw.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	start := time.Now()
	if _, err := c.Read(make([]byte, 1)); err == nil || isTimeout(err) {
		t.Fatalf("a client that sent nothing was kept: %v", err)
	}
	if time.Since(start) > 3*time.Second {
		t.Fatalf("dropped after %v", time.Since(start))
	}

	// Closing stops Accept, and is safe to repeat.
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Accept(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Accept after Close: %v", err)
	}
	r.closePassing()
}

func TestPeekServerName(t *testing.T) {
	pipe := func(t *testing.T, client func(net.Conn)) (string, []byte, error) {
		t.Helper()
		a, b := net.Pipe()
		go func() {
			client(a)
			_ = a.Close()
		}()
		_ = b.SetReadDeadline(time.Now().Add(5 * time.Second))
		defer b.Close()
		return peekServerName(context.Background(), b)
	}
	hello := func(name string) func(net.Conn) {
		return func(c net.Conn) {
			_ = tls.Client(c, &tls.Config{ServerName: name, InsecureSkipVerify: true}).Handshake() //nolint:gosec // only the hello matters
		}
	}

	name, prefix, err := pipe(t, hello("patch.test"))
	if err != nil || name != "patch.test" || len(prefix) < 5 || prefix[0] != 0x16 {
		t.Fatalf("hello with a name: %q %d bytes %v", name, len(prefix), err)
	}
	name, _, err = pipe(t, hello(""))
	if err != nil || name != "" {
		t.Fatalf("hello without a name: %q %v", name, err)
	}
	name, prefix, err = pipe(t, func(c net.Conn) { _, _ = c.Write([]byte("GET / HTTP/1.1\r\n\r\n")) })
	if err != nil || name != "" || !bytes.HasPrefix([]byte("GET / HTTP/1.1\r\n\r\n"), prefix) || len(prefix) == 0 {
		t.Fatalf("not TLS: %q %q %v", name, prefix, err)
	}
	if _, _, err = pipe(t, func(net.Conn) {}); err == nil {
		t.Fatal("a closed connection was not an error")
	}
	// Half a record, then nothing.
	if _, _, err = pipe(t, func(c net.Conn) { _, _ = c.Write([]byte{0x16, 0x03, 0x01, 0x02, 0x00, 0x01}) }); err == nil {
		t.Fatal("a cut-off hello was not an error")
	}
}
