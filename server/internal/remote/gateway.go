package remote

import (
	"bufio"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/paulmataruso/easyrmm/server/internal/httpapi"
)

// agentRoutes are the MeshCentral routes MeshAgent uses (the same set
// MeshCentral serves on its agent-only port). Requests from agents are
// forwarded without an EasyRMM grant: MeshCentral authenticates agents
// itself. Browser requests to these routes still need a grant.
var agentRoutes = map[string]bool{
	"/agent.ashx":         true,
	"/meshrelay.ashx":     true,
	"/devicefile.ashx":    true,
	"/agenttransfer.ashx": true,
	"/meshagents":         true,
	"/agentdownload.ashx": true,
}

// blockedPrefixes are MeshCentral features that are never reachable through
// the edge, even with a grant: account self-service, invitations and
// sharing, server administration, the external sign-in providers, and the
// RDP, SSH and Intel AMT connections.
//
// Two static resources stay reachable because MeshCentral's device page
// cannot work without them: the MeshCommander page (/commander.ashx), which
// the device page embeds in a frame and calls into whenever it opens a
// device, and the RDP client scripts (/mstsc/*.js) it loads. Neither connects
// anywhere by itself; the relays they would use are blocked here, and
// EasyRMM's MeshCentral rights deny Intel AMT.
var blockedPrefixes = []string{
	"/meshsettings", "/invite", "/agentinvite", "/sharing", "/createaccount", "/resetaccount",
	"/resetpassword", "/checkmail", "/tokenlogin", "/changepassword", "/deleteaccount",
	"/backup.zip", "/restoreserver.ashx", "/uploadmeshcorefile.ashx", "/pluginadmin.ashx",
	"/oneclickrecovery.ashx", "/auth-", "/firebaserelay.aspx", "/mqtt.ashx", "/webrelay.ashx",
	"/mstsc.html", "/mstscrelay.ashx", "/ssh", "/apf.ashx", "/amtevents.ashx", "/ipkvm.ashx",
	"/webider.ashx", "/messenger", "/recordings.ashx", "/2fahold.ashx",
}

// blocked reports whether a request is for a MeshCentral feature EasyRMM
// does not expose. Password sign-in is refused too: EasyRMM signs browsers
// in with one-time login tokens only.
// MeshCentral (Express) matches routes case-insensitively and ignores a
// trailing slash, so the comparison does too.
func blocked(method, p string) bool {
	p = strings.ToLower(p)
	if method == http.MethodPost && strings.TrimSuffix(p, "/") == "/login" {
		return true
	}
	for _, b := range blockedPrefixes {
		if strings.HasPrefix(p, b) {
			return true
		}
	}
	return false
}

// unusualPath reports paths no MeshCentral page or agent uses: dot
// segments, doubled or encoded separators. They are refused so that the
// gateway and MeshCentral can never disagree about which route a request
// is for.
func unusualPath(r *http.Request) bool {
	p := r.URL.Path
	if !strings.HasPrefix(p, "/") || strings.Contains(p, "//") || strings.Contains(p, "\\") {
		return true
	}
	if c := path.Clean(p); c != p && c+"/" != p {
		return true
	}
	raw := strings.ToLower(r.URL.EscapedPath())
	return strings.Contains(raw, "%2f") || strings.Contains(raw, "%5c") || strings.Contains(raw, "%2e")
}

// GatewayConfig configures the gateway.
type GatewayConfig struct {
	// Upstream is MeshCentral's loopback address (http://127.0.0.1:14430).
	Upstream *url.URL
	// Secure marks cookies Secure with the __Host- prefix and adds HSTS. It
	// is false only in plain-HTTP development mode.
	Secure bool
	// CacheTTL is how long a cookie check is trusted (default 15s); it also
	// sets how often open connections are re-checked.
	CacheTTL time.Duration
}

// Gateway serves the MeshCentral hostname: it forwards agent traffic, and
// browser traffic only for browsers holding a grant cookie bound to a valid
// EasyRMM session. Open WebSocket connections are closed when their session
// ends.
type Gateway struct {
	svc        *Service
	proxy      *httputil.ReverseProxy
	cookieName string
	secure     bool
	ttl        time.Duration
	log        *slog.Logger

	mu      sync.Mutex
	cache   map[[32]byte]cached
	tunnels map[uuid.UUID]map[*trackedConn]struct{}
}

type cached struct {
	session uuid.UUID
	until   time.Time
}

// NewGateway builds the gateway.
func NewGateway(svc *Service, cfg GatewayConfig, log *slog.Logger) (*Gateway, error) {
	if cfg.Upstream == nil || cfg.Upstream.Host == "" {
		return nil, errors.New("remote gateway: upstream is required")
	}
	if cfg.CacheTTL <= 0 {
		cfg.CacheTTL = 15 * time.Second
	}
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	name := "__Host-easyrmm_remote"
	if !cfg.Secure {
		name = "easyrmm_remote"
	}
	g := &Gateway{
		svc: svc, cookieName: name, secure: cfg.Secure, ttl: cfg.CacheTTL, log: log,
		cache: map[[32]byte]cached{}, tunnels: map[uuid.UUID]map[*trackedConn]struct{}{},
	}
	target := cfg.Upstream
	g.proxy = &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(target)
			pr.Out.Host = pr.In.Host
			pr.Out.Header.Del("Forwarded")
			pr.Out.Header.Set("X-Forwarded-For", httpapi.ClientIP(pr.In).String())
			pr.Out.Header.Set("X-Forwarded-Proto", "https")
			pr.Out.Header.Set("X-Forwarded-Host", pr.In.Host)
			g.stripOwnCookie(pr.Out)
		},
		Transport: &http.Transport{
			DialContext:           (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
			MaxIdleConns:          128,
			MaxIdleConnsPerHost:   64,
			IdleConnTimeout:       90 * time.Second,
			ResponseHeaderTimeout: 2 * time.Minute,
		},
		ModifyResponse: func(resp *http.Response) error {
			dropOwnSetCookies(resp.Header)
			if g.secure && resp.Header.Get("Strict-Transport-Security") == "" {
				resp.Header.Set("Strict-Transport-Security", "max-age=63072000")
			}
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			httpapi.LoggerFrom(r.Context()).Warn("remote gateway: MeshCentral unreachable", "error", err, "path", r.URL.Path)
			page(w, http.StatusBadGateway, "Remote access is unavailable", "EasyRMM could not reach its remote-access service. Try again in a minute.")
		},
	}
	return g, nil
}

// CookieName returns the gateway cookie's name.
func (g *Gateway) CookieName() string { return g.cookieName }

func (g *Gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if unusualPath(r) {
		page(w, http.StatusBadRequest, "Bad request", "The address is not valid.")
		return
	}
	reqPath := r.URL.Path
	if reqPath == LaunchPath {
		g.launch(w, r)
		return
	}
	// Agents use these exact paths.
	if agentRoutes[reqPath] && !g.fromBrowser(r) {
		g.proxy.ServeHTTP(w, r)
		return
	}
	if blocked(r.Method, reqPath) {
		page(w, http.StatusForbidden, "Not available", "This part of the remote-access service is not available through EasyRMM.")
		return
	}
	session, ok := g.authorize(r)
	if !ok {
		page(w, http.StatusForbidden, "Remote session required", "Open remote sessions from a device in the EasyRMM console.")
		return
	}
	if strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		w = &trackingWriter{ResponseWriter: w, g: g, session: session}
	}
	g.proxy.ServeHTTP(w, r)
}

// fromBrowser reports whether a request comes from a web browser rather
// than an agent. Browsers send Origin on WebSocket handshakes and Fetch
// metadata on every request; agents send neither, and never our cookie.
func (g *Gateway) fromBrowser(r *http.Request) bool {
	if r.Header.Get("Origin") != "" || r.Header.Get("Sec-Fetch-Mode") != "" || r.Header.Get("Sec-Fetch-Site") != "" {
		return true
	}
	_, err := r.Cookie(g.cookieName)
	return err == nil
}

func (g *Gateway) launch(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	if r.Method != http.MethodGet {
		page(w, http.StatusMethodNotAllowed, "Not allowed", "Open remote sessions from the EasyRMM console.")
		return
	}
	red, err := g.svc.Redeem(r.Context(), r.URL.Query().Get("t"))
	if err != nil {
		if !errors.Is(err, ErrGrantInvalid) {
			httpapi.LoggerFrom(r.Context()).Error("remote gateway: redeeming launch link failed", "error", err)
			page(w, http.StatusInternalServerError, "Something went wrong", "The remote session could not be started. The error has been logged.")
			return
		}
		page(w, http.StatusForbidden, "This link has expired", "Remote session links work once, for a minute. Start the session again from the EasyRMM console.")
		return
	}
	http.SetCookie(w, &http.Cookie{ //nolint:gosec // Secure is false only in the explicit plain-HTTP development mode
		Name: g.cookieName, Value: red.Cookie, Path: "/",
		Secure: g.secure, HttpOnly: true, SameSite: http.SameSiteStrictMode,
	})
	g.remember(red.Cookie, red.SessionID)
	http.Redirect(w, r, red.Target, http.StatusSeeOther)
}

func cookieKey(v string) [32]byte { return sha256.Sum256([]byte(v)) }

func (g *Gateway) remember(cookie string, session uuid.UUID) {
	g.mu.Lock()
	defer g.mu.Unlock()
	now := time.Now()
	if len(g.cache) > 10000 {
		for k, v := range g.cache {
			if now.After(v.until) {
				delete(g.cache, k)
			}
		}
	}
	g.cache[cookieKey(cookie)] = cached{session: session, until: now.Add(g.ttl)}
}

// authorize returns the EasyRMM session behind the request's grant cookie.
func (g *Gateway) authorize(r *http.Request) (uuid.UUID, bool) {
	c, err := r.Cookie(g.cookieName)
	if err != nil || c.Value == "" {
		return uuid.Nil, false
	}
	k := cookieKey(c.Value)
	g.mu.Lock()
	e, ok := g.cache[k]
	g.mu.Unlock()
	if ok && time.Now().Before(e.until) {
		return e.session, true
	}
	session, err := g.svc.CheckCookie(r.Context(), c.Value)
	if err != nil {
		if !errors.Is(err, ErrGrantInvalid) {
			httpapi.LoggerFrom(r.Context()).Error("remote gateway: checking grant failed", "error", err)
		}
		g.mu.Lock()
		delete(g.cache, k)
		g.mu.Unlock()
		return uuid.Nil, false
	}
	g.remember(c.Value, session)
	return session, true
}

// ownCookie reports whether a cookie is EasyRMM's: the gateway grant, or
// the console's session. Browsers do not keep cookies apart by port, so on
// an IP address (console on 443, MeshCentral on 4443) the console's cookies
// reach the gateway too (ADR-0016).
func ownCookie(name string) bool {
	name = strings.ToLower(name)
	return strings.HasPrefix(name, "__host-easyrmm") || strings.HasPrefix(name, "__secure-easyrmm") || strings.HasPrefix(name, "easyrmm")
}

// stripOwnCookie keeps EasyRMM's cookies away from MeshCentral.
func (g *Gateway) stripOwnCookie(r *http.Request) {
	cookies := r.Cookies()
	r.Header.Del("Cookie")
	var kept []string
	for _, c := range cookies {
		if !ownCookie(c.Name) {
			kept = append(kept, c.Name+"="+c.Value)
		}
	}
	if len(kept) > 0 {
		r.Header.Set("Cookie", strings.Join(kept, "; "))
	}
}

// dropOwnSetCookies stops MeshCentral from setting a cookie with one of
// EasyRMM's names, which on a shared IP address would reach the console.
func dropOwnSetCookies(h http.Header) {
	all := h.Values("Set-Cookie")
	if len(all) == 0 {
		return
	}
	h.Del("Set-Cookie")
	for _, v := range all {
		name, _, _ := strings.Cut(v, "=")
		if !ownCookie(strings.TrimSpace(name)) {
			h.Add("Set-Cookie", v)
		}
	}
}

// Run re-checks the sessions behind open connections and closes those whose
// session has ended (signed out, revoked, expired or the user disabled).
func (g *Gateway) Run(ctx context.Context) {
	t := time.NewTicker(g.ttl)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			g.closeAll()
			return
		case <-t.C:
			g.sweep(ctx)
		}
	}
}

func (g *Gateway) sweep(ctx context.Context) {
	g.mu.Lock()
	ids := make([]uuid.UUID, 0, len(g.tunnels))
	for id := range g.tunnels {
		ids = append(ids, id)
	}
	now := time.Now()
	for k, v := range g.cache {
		if now.After(v.until) {
			delete(g.cache, k)
		}
	}
	g.mu.Unlock()
	if len(ids) == 0 {
		return
	}
	valid, err := g.svc.SessionsValid(ctx, ids)
	if err != nil {
		g.log.Error("remote gateway: checking sessions failed", "error", err)
		return
	}
	var closing []*trackedConn
	g.mu.Lock()
	for _, id := range ids {
		if valid[id] {
			continue
		}
		for c := range g.tunnels[id] {
			closing = append(closing, c)
		}
		delete(g.tunnels, id)
		for k, v := range g.cache {
			if v.session == id {
				delete(g.cache, k)
			}
		}
	}
	g.mu.Unlock()
	for _, c := range closing {
		_ = c.Conn.Close()
	}
	if len(closing) > 0 {
		g.log.Info("remote gateway: closed connections of ended sessions", "connections", len(closing))
	}
}

func (g *Gateway) closeAll() {
	g.mu.Lock()
	var all []*trackedConn
	for _, set := range g.tunnels {
		for c := range set {
			all = append(all, c)
		}
	}
	g.tunnels = map[uuid.UUID]map[*trackedConn]struct{}{}
	g.mu.Unlock()
	for _, c := range all {
		_ = c.Conn.Close()
	}
}

// OpenConnections returns how many proxied WebSocket connections are open.
func (g *Gateway) OpenConnections() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	n := 0
	for _, set := range g.tunnels {
		n += len(set)
	}
	return n
}

func (g *Gateway) track(session uuid.UUID, c net.Conn) *trackedConn {
	tc := &trackedConn{Conn: c, g: g, session: session}
	g.mu.Lock()
	if g.tunnels[session] == nil {
		g.tunnels[session] = map[*trackedConn]struct{}{}
	}
	g.tunnels[session][tc] = struct{}{}
	g.mu.Unlock()
	return tc
}

func (g *Gateway) untrack(tc *trackedConn) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if set := g.tunnels[tc.session]; set != nil {
		delete(set, tc)
		if len(set) == 0 {
			delete(g.tunnels, tc.session)
		}
	}
}

type trackedConn struct {
	net.Conn
	g       *Gateway
	session uuid.UUID
	once    sync.Once
}

func (c *trackedConn) Close() error {
	c.once.Do(func() { c.g.untrack(c) })
	return c.Conn.Close()
}

// trackingWriter registers the connection the reverse proxy hijacks for a
// WebSocket, so it can be closed when the session ends.
type trackingWriter struct {
	http.ResponseWriter
	g       *Gateway
	session uuid.UUID
}

func (t *trackingWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	conn, rw, err := http.NewResponseController(t.ResponseWriter).Hijack()
	if err != nil {
		return nil, nil, err
	}
	return t.g.track(t.session, conn), rw, nil
}

func (t *trackingWriter) Unwrap() http.ResponseWriter { return t.ResponseWriter }

// page writes a minimal self-contained HTML message.
func page(w http.ResponseWriter, status int, title, msg string) {
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors *")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = fmt.Fprintf(w, `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>%s</title>
<style>body{font:15px/1.5 system-ui,sans-serif;margin:0;display:grid;place-items:center;min-height:100vh;background:#0f172a;color:#e2e8f0}main{max-width:28rem;padding:2rem}h1{font-size:1.1rem;margin:0 0 .5rem}p{margin:0;color:#94a3b8}</style>
</head><body><main><h1>%s</h1><p>%s</p></main></body></html>`, htmlEscape(title), htmlEscape(title), htmlEscape(msg))
}

var htmlEscaper = strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&#34;", "'", "&#39;")

func htmlEscape(s string) string { return htmlEscaper.Replace(s) }
