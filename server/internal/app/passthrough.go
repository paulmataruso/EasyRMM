package app

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"strings"
	"sync"
	"time"

	"github.com/paulmataruso/easyrmm/server/internal/config"
	"github.com/paulmataruso/easyrmm/server/internal/proxyproto"
)

// Co-hosting EasyPatch (ADR-0035): EasyRMM's edge keeps ports 80 and 443.
// On 443 it reads the server name a client asks for, before any TLS of its
// own, and passes connections for EasyPatch's name through untouched to
// EasyPatch's TLS listener on loopback, with a PROXY protocol v2 header
// naming the client. EasyPatch keeps its own certificates, headers and
// cookies, and EasyRMM never sees its traffic in the clear. On 80, EasyPatch's
// ACME HTTP-01 challenges go to its plain-HTTP listener and everything else
// is redirected to HTTPS.

const (
	// helloTimeout bounds how long a client may take to send its
	// ClientHello before the connection is dropped.
	helloTimeout = 10 * time.Second
	// upstreamDialTimeout bounds connecting to EasyPatch.
	upstreamDialTimeout = 5 * time.Second
)

// errPeeked stops the handshake used to read a ClientHello.
var errPeeked = errors.New("client hello read")

// recordingConn records what is read from a connection and refuses to
// write, so a TLS handshake can parse a ClientHello without answering it.
type recordingConn struct {
	net.Conn
	buf bytes.Buffer
}

func (c *recordingConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.buf.Write(p[:n])
	return n, err
}

func (c *recordingConn) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }

// peekServerName reads a TLS ClientHello from c and returns the server
// name it asks for ("" for none, or when the client did not speak TLS) and
// every byte read, to be replayed to whoever handles the connection.
func peekServerName(ctx context.Context, c net.Conn) (string, []byte, error) {
	rc := &recordingConn{Conn: c}
	name := ""
	err := tls.Server(rc, &tls.Config{
		GetConfigForClient: func(h *tls.ClientHelloInfo) (*tls.Config, error) {
			name = h.ServerName
			return nil, errPeeked
		},
	}).HandshakeContext(ctx)
	if errors.Is(err, errPeeked) {
		err = nil
	}
	var netErr net.Error
	if err != nil && (errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || errors.As(err, &netErr) ||
		errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)) {
		return "", rc.buf.Bytes(), err
	}
	// Anything else is not TLS: let the HTTPS server answer it as it would.
	return name, rc.buf.Bytes(), nil
}

// prefixConn replays bytes already read from a connection.
type prefixConn struct {
	net.Conn
	r io.Reader
}

func (c *prefixConn) Read(p []byte) (int, error) { return c.r.Read(p) }

// sniRouter is the HTTPS listener with EasyPatch's connections taken out.
type sniRouter struct {
	net.Listener
	cfg   config.EasyPatchHost
	log   *slog.Logger
	dial  func(ctx context.Context, network, addr string) (net.Conn, error)
	hello time.Duration // helloTimeout, shorter in tests

	conns     chan net.Conn
	closeOnce sync.Once
	done      chan struct{}
	// ctx ends with Close, cutting short handshakes still being read.
	ctx    context.Context
	cancel context.CancelFunc

	mu      sync.Mutex
	passing map[net.Conn]struct{}
	wg      sync.WaitGroup
}

func newSNIRouter(ln net.Listener, cfg config.EasyPatchHost, log *slog.Logger) *sniRouter {
	return startSNIRouter(ln, cfg, log, helloTimeout)
}

func startSNIRouter(ln net.Listener, cfg config.EasyPatchHost, log *slog.Logger, hello time.Duration) *sniRouter {
	r := &sniRouter{
		Listener: ln, cfg: cfg, log: log.With("component", "easypatch-passthrough"), hello: hello,
		dial:  (&net.Dialer{Timeout: upstreamDialTimeout, KeepAlive: 30 * time.Second}).DialContext,
		conns: make(chan net.Conn), done: make(chan struct{}), passing: map[net.Conn]struct{}{},
	}
	r.ctx, r.cancel = context.WithCancel(context.Background())
	go r.acceptLoop()
	return r
}

func (r *sniRouter) acceptLoop() {
	for {
		c, err := r.Listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				time.Sleep(50 * time.Millisecond)
				continue
			}
			r.log.Error("accepting connections", "error", err)
			_ = r.Close()
			return
		}
		go r.route(c)
	}
}

func (r *sniRouter) route(c net.Conn) {
	_ = c.SetReadDeadline(time.Now().Add(r.hello))
	name, prefix, err := peekServerName(r.ctx, c)
	_ = c.SetReadDeadline(time.Time{})
	if err != nil {
		_ = c.Close()
		return
	}
	if name != "" && strings.EqualFold(strings.TrimSuffix(name, "."), r.cfg.Hostname) {
		r.pass(c, prefix)
		return
	}
	select {
	case r.conns <- &prefixConn{Conn: c, r: io.MultiReader(bytes.NewReader(prefix), c)}:
	case <-r.done:
		_ = c.Close()
	}
}

// Accept hands EasyRMM's own connections to its HTTPS server.
func (r *sniRouter) Accept() (net.Conn, error) {
	select {
	case c := <-r.conns:
		return c, nil
	case <-r.done:
		return nil, net.ErrClosed
	}
}

// Close stops accepting. Connections already passing through stay open
// until closePassing.
func (r *sniRouter) Close() error {
	var err error
	r.closeOnce.Do(func() {
		close(r.done)
		r.cancel()
		err = r.Listener.Close()
	})
	return err
}

// closePassing ends the connections passing through and waits for them.
func (r *sniRouter) closePassing() {
	r.mu.Lock()
	for c := range r.passing {
		_ = c.Close()
	}
	r.mu.Unlock()
	r.wg.Wait()
}

func (r *sniRouter) track(cs ...net.Conn) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	select {
	case <-r.done:
		return false
	default:
	}
	for _, c := range cs {
		r.passing[c] = struct{}{}
	}
	r.wg.Add(1)
	return true
}

func (r *sniRouter) untrack(cs ...net.Conn) {
	r.mu.Lock()
	for _, c := range cs {
		delete(r.passing, c)
	}
	r.mu.Unlock()
	r.wg.Done()
}

// pass relays a connection to EasyPatch, prefixed with the PROXY header
// and the bytes already read.
func (r *sniRouter) pass(client net.Conn, prefix []byte) {
	ctx, cancel := context.WithTimeout(context.Background(), upstreamDialTimeout)
	up, err := r.dial(ctx, "tcp", r.cfg.TLSUpstream)
	cancel()
	if err != nil {
		r.log.Warn("EasyPatch is not answering on its loopback port; is it running with docker-compose.easyrmm.yml?", "upstream", r.cfg.TLSUpstream, "error", err)
		_ = client.Close()
		return
	}
	if !r.track(client, up) {
		_ = client.Close()
		_ = up.Close()
		return
	}
	defer r.untrack(client, up)
	defer client.Close()
	defer up.Close()

	head := prefix
	if r.cfg.ProxyProtocol {
		head = append(proxyproto.Header(client.RemoteAddr(), client.LocalAddr()), prefix...)
	}
	if _, err := up.Write(head); err != nil {
		return
	}
	done := make(chan struct{}, 2)
	relay := func(dst, src net.Conn) {
		_, _ = io.Copy(dst, src)
		// Pass a half-close on, so each side sees the other finish.
		if tc, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = tc.CloseWrite()
		} else {
			_ = dst.Close()
		}
		done <- struct{}{}
	}
	go relay(up, client)
	go relay(client, up)
	<-done
	<-done
}

// easyPatchHTTP answers port 80 for EasyPatch's name: its ACME HTTP-01
// challenges go to its own plain-HTTP listener (it obtains its certificates
// itself), everything else is redirected to HTTPS. Other names go to next.
func easyPatchHTTP(cfg config.EasyPatchHost, next http.Handler) http.Handler {
	if !cfg.Enabled() {
		return next
	}
	var challenges http.Handler
	if cfg.HTTPUpstream != "" {
		challenges = &httputil.ReverseProxy{
			Rewrite: func(pr *httputil.ProxyRequest) {
				pr.Out.URL.Scheme, pr.Out.URL.Host = "http", cfg.HTTPUpstream
				pr.Out.Host = cfg.Hostname
				pr.SetXForwarded()
			},
			Transport: &http.Transport{
				DialContext:           (&net.Dialer{Timeout: upstreamDialTimeout}).DialContext,
				ResponseHeaderTimeout: 30 * time.Second,
				DisableKeepAlives:     true,
			},
		}
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.EqualFold(strings.TrimSuffix(hostOnly(r.Host), "."), cfg.Hostname) {
			next.ServeHTTP(w, r)
			return
		}
		if challenges != nil && strings.HasPrefix(r.URL.Path, "/.well-known/acme-challenge/") {
			challenges.ServeHTTP(w, r)
			return
		}
		w.Header().Set("Connection", "close")
		http.Redirect(w, r, "https://"+cfg.Hostname+r.URL.RequestURI(), http.StatusPermanentRedirect) //nolint:gosec // G710: the configured EasyPatch name
	})
}
