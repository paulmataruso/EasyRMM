package remote

import (
	"bufio"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"path"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"

	"github.com/paulmataruso/easyrmm/server/internal/httpapi"
)

// agentRoutes are the MeshCentral routes MeshAgent uses: the same set, and
// the same kinds of request, as MeshCentral serves on its agent-only port
// (WebSocket or plain GET). Requests from agents are forwarded without an
// EasyRMM grant: MeshCentral authenticates agents itself. Browser requests
// to these routes still need a grant.
//
// The main port MeshCentral listens on, which the gateway forwards to,
// serves more on some of these paths: a plain GET of /devicefile.ashx with
// a user's sign-in cookie downloads a file from a device. Holding agent
// requests to what the agent port serves keeps that behind the browser
// checks.
var agentRoutes = map[string]agentRoute{
	"/agent.ashx":         {websocket: true},
	"/meshrelay.ashx":     {websocket: true},
	"/devicefile.ashx":    {websocket: true},
	"/agenttransfer.ashx": {websocket: true},
	"/meshagents":         {},
	"/agentdownload.ashx": {},
}

// agentRoute is how agents use a route.
type agentRoute struct {
	websocket bool // a WebSocket; otherwise a plain GET
}

// blockedPrefixes are MeshCentral features that are never reachable through
// the edge, even with a grant: account self-service, invitations and
// sharing, server administration, the external sign-in providers, the
// stand-alone RDP page (which connects by cookie, to any address the cookie
// names), and the SSH and Intel AMT connections. The web RDP relay itself
// is admitted only for RDP grants (ADR-0026).
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
	"/mstsc.html", "/ssh", "/apf.ashx", "/amtevents.ashx", "/ipkvm.ashx",
	"/webider.ashx", "/messenger", "/recordings.ashx", "/2fahold.ashx", "/localrelay.ashx",
	// Uploads: server files, and files pushed to every device the user
	// can reach at once, with no EasyRMM session on any of them.
	"/uploadfile",
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
	svc   *Service
	proxy *httputil.ReverseProxy
	// relayProxy forwards relay connections, agents' and browsers', over
	// small connections to MeshCentral (ADR-0025).
	relayProxy *httputil.ReverseProxy
	// granted reports whether an EasyRMM session opened a remote session of
	// a kind on a device (by MeshCentral node ID); relay connections need
	// one.
	granted    func(ctx context.Context, session uuid.UUID, nodeID string, kind Kind) (bool, error)
	cookieName string
	secure     bool
	ttl        time.Duration
	log        *slog.Logger

	mu      sync.Mutex
	cache   map[[32]byte]cached
	tunnels map[uuid.UUID]map[*trackedConn]struct{}
	// admitted are the relay tunnels sessions may open, by tunnel id, and
	// admittedBy how many each session has waiting (tunnels.go).
	admitted   map[string]admittedTunnel
	admittedBy map[uuid.UUID]int
	// pressure is how long each device's desktop pictures were held
	// (ADR-0025), and grants the desktop grants the session view's
	// questions about it were checked against.
	pressure map[string]*nodePressure
	grants   map[grantKey]time.Time
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
		pressure: map[string]*nodePressure{}, grants: map[grantKey]time.Time{},
		admitted: map[string]admittedTunnel{}, admittedBy: map[uuid.UUID]int{},
	}
	if svc != nil {
		g.granted = svc.SessionGranted
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
			httpapi.LoggerFrom(r.Context()).Warn("remote gateway: MeshCentral unreachable", "error", err, "path", httpapi.LogSafe(r.URL.Path))
			page(w, http.StatusBadGateway, "Remote access is unavailable", "EasyRMM could not reach its remote-access service. Try again in a minute.")
		},
	}
	relay := *g.proxy
	dialer := &net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second, Control: smallUpstream}
	relay.Transport = &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			c, err := dialer.DialContext(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			if node, ok := ctx.Value(agentDesktopKey{}).(string); ok {
				var held *atomic.Int64
				var release func()
				if node != "" {
					p := g.holdPressure(node)
					held, release = &p.held, func() { g.releasePressure(node, p) }
				}
				paced, ok := pace(c, meshUnreadLimit, held, release)
				if !ok && release != nil {
					release()
				}
				c = paced
			}
			return c, nil
		},
		DisableKeepAlives:     true,
		ResponseHeaderTimeout: 2 * time.Minute,
	}
	g.relayProxy = &relay
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
	switch reqPath {
	case LaunchPath:
		g.launch(w, r)
		return
	case PressurePath:
		g.servePressure(w, r)
		return
	}
	// No request through the gateway signs in to MeshCentral with a
	// password: browsers use one-time login tokens, agents their keys.
	r.Header.Del("X-Meshauth")
	// Agents use these exact paths.
	if route, ok := agentRoutes[reqPath]; ok && !g.fromBrowser(r) {
		if err := g.checkAgentRequest(r, route); err != nil {
			g.refuse(w, r, err)
			return
		}
		// Agents send no cookies; a MeshCentral session cookie here would
		// sign a user in without passing the browser checks below.
		r.Header.Del("Cookie")
		if reqPath == "/meshrelay.ashx" {
			if q := r.URL.Query(); q.Get("p") == "2" {
				w = agentDesktopWriter{ResponseWriter: w, log: httpapi.LoggerFrom(r.Context())}
				// MeshCentral names the device in the agent's desktop relay;
				// without a usable name the relay is paced but not counted.
				node, _ := normalizeNodeID(q.Get("nodeid"))
				r = r.WithContext(context.WithValue(r.Context(), agentDesktopKey{}, node))
			}
			g.relayProxy.ServeHTTP(w, r)
			return
		}
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
	// MeshCentral matches routes case-insensitively and ignores a trailing
	// slash.
	route := strings.ToLower(strings.TrimSuffix(reqPath, "/"))
	upgrade := strings.EqualFold(r.Header.Get("Upgrade"), "websocket")
	var relayProto string
	switch route {
	case "/meshrelay.ashx":
		proto, err := g.checkRelay(r, session)
		if err != nil {
			g.refuse(w, r, err)
			return
		}
		relayProto = proto
	case "/devicefile.ashx":
		if err := g.checkDeviceFile(r, session, upgrade); err != nil {
			g.refuse(w, r, err)
			return
		}
	}
	if route == "/mstscrelay.ashx" && !upgrade {
		g.refuse(w, r, refused("RDP relay without a WebSocket"))
		return
	}
	if upgrade {
		// Uncompressed, so the control channel can be read (and MeshCentral
		// compresses nothing anyway: desktop frames are JPEG).
		r.Header.Del("Sec-Websocket-Extensions")
		tw := &trackingWriter{
			ResponseWriter: w, g: g, session: session, log: httpapi.LoggerFrom(r.Context()),
			desktop: route == "/meshrelay.ashx" && r.URL.Query().Get("p") == "2",
		}
		switch route {
		case "/control.ashx":
			tw.check, tw.what = g.controlCheck(r.Context(), session), "control channel"
		case "/mstscrelay.ashx":
			tw.check, tw.what = g.rdpCheck(r.Context(), session), "RDP relay"
		case "/meshrelay.ashx":
			tw.check, tw.what = relayProtocolCheck(relayProto), "relay"
		}
		w = tw
	}
	if route == "/meshrelay.ashx" {
		g.relayProxy.ServeHTTP(w, r)
		return
	}
	g.proxy.ServeHTTP(w, r)
}

// checkRelay allows a browser's relay connection only for one of EasyRMM's
// session types, without routing instructions, on a device the browser's
// EasyRMM session opened a remote session of that type on, and records its
// tunnel for the agent (tunnels.go). It returns the relay protocol.
func (g *Gateway) checkRelay(r *http.Request, session uuid.UUID) (string, error) {
	q := r.URL.Query()
	nodeID, kind, err := browserRelay(q)
	if err != nil {
		return "", err
	}
	ids := q["id"]
	if len(ids) != 1 {
		return "", refused("relay without one tunnel id")
	}
	if g.granted == nil {
		return "", refused("no grant check")
	}
	ok, err := g.granted(r.Context(), session, nodeID, kind)
	if err != nil {
		return "", fmt.Errorf("checking relay grant: %w", err)
	}
	if !ok {
		return "", refused("%s relay for a device the session opened no %s session on", kind, kind)
	}
	proto := q["p"][0]
	return proto, g.admitTunnel(session, ids[0], nodeID, proto)
}

// checkAgentRequest holds an agent's request to what MeshCentral's agent
// port serves on its route, and checks relay connections (tunnels.go).
func (g *Gateway) checkAgentRequest(r *http.Request, route agentRoute) error {
	if r.Method != http.MethodGet {
		return refused("agent request with method %s", r.Method)
	}
	if upgrade := strings.EqualFold(r.Header.Get("Upgrade"), "websocket"); upgrade != route.websocket {
		if route.websocket {
			return refused("agent request that is not a WebSocket")
		}
		return refused("agent WebSocket on a download route")
	}
	switch r.URL.Path {
	case "/meshrelay.ashx":
		return g.checkAgentRelay(r.URL.Query())
	case "/devicefile.ashx":
		// The agent's end of a file download: a tunnel id and relay cookie.
		return agentRelayRefused(r.URL.Query())
	}
	return nil
}

// checkDeviceFile allows a browser's file download from a device
// (devicefile.ashx?c=…&m=…&n=<node>&f=<path>, as MeshCentral's files view
// links them) only from a device the session opened a files session on.
// The WebSocket on the same path is the agent's end, never a browser's.
func (g *Gateway) checkDeviceFile(r *http.Request, session uuid.UUID, upgrade bool) error {
	if r.Method != http.MethodGet || upgrade {
		return refused("device file request that is not a download")
	}
	q := r.URL.Query()
	if hasBracketKey(q) {
		return refused("device file request with an array or object in its address")
	}
	nodes := q["n"]
	if len(nodes) != 1 {
		return refused("device file request without one device")
	}
	node, err := normalizeNodeID(nodes[0])
	if err != nil {
		return err
	}
	if g.granted == nil {
		return refused("no grant check")
	}
	ok, err := g.granted(r.Context(), session, node, KindFiles)
	if err != nil {
		return fmt.Errorf("checking device file grant: %w", err)
	}
	if !ok {
		return refused("file download from a device the session opened no files session on")
	}
	return nil
}

// refuse answers a request the gateway does not forward, and logs why.
func (g *Gateway) refuse(w http.ResponseWriter, r *http.Request, err error) {
	log := httpapi.LoggerFrom(r.Context())
	if !errors.Is(err, errRefused) {
		log.Error("remote gateway: checking a request failed", "error", httpapi.LogSafe(err.Error()), "path", httpapi.LogSafe(r.URL.Path))
		page(w, http.StatusInternalServerError, "Something went wrong", "The request could not be checked. The error has been logged.")
		return
	}
	log.Warn("remote gateway: refused a request", "reason", httpapi.LogSafe(err.Error()), "path", httpapi.LogSafe(r.URL.Path))
	page(w, http.StatusForbidden, "Not available", "This part of the remote-access service is not available through EasyRMM.")
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
	for k, until := range g.grants {
		if now.After(until) {
			delete(g.grants, k)
		}
	}
	g.pruneTunnels(now)
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
		for k := range g.grants {
			if k.session == id {
				delete(g.grants, k)
			}
		}
		g.forgetSessionTunnels(id)
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
	// reader, when set, is what reads the browser's side: the control
	// channel's message check.
	reader io.Reader
}

func (c *trackedConn) Read(p []byte) (int, error) {
	if c.reader != nil {
		return c.reader.Read(p)
	}
	return c.Conn.Read(p)
}

func (c *trackedConn) Close() error {
	c.once.Do(func() { c.g.untrack(c) })
	return c.Conn.Close()
}

// trackingWriter registers the connection the reverse proxy hijacks for a
// WebSocket, so it can be closed when the session ends; with check set it
// also checks every message the browser sends on it.
type trackingWriter struct {
	http.ResponseWriter
	g       *Gateway
	session uuid.UUID
	// check, when set, accepts or refuses each message from the browser;
	// what names the channel in the log.
	check func([]byte) error
	what  string
	// desktop marks a remote desktop relay, whose unsent bytes are bounded.
	desktop bool
	log     *slog.Logger
}

func (t *trackingWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	conn, rw, err := http.NewResponseController(t.ResponseWriter).Hijack()
	if err != nil {
		return nil, nil, err
	}
	if t.desktop {
		if err := boundSendQueue(conn, desktopSendQueue); err != nil {
			t.log.Warn("remote gateway: could not bound a desktop connection's send queue", "error", err)
		}
	}
	tc := t.g.track(t.session, conn)
	if t.check != nil {
		log, check, what := t.log, t.check, t.what
		tc.reader = newWSGuard(conn, func(msg []byte) error {
			err := check(msg)
			switch {
			case err == nil, errors.Is(err, errPassRest):
			case errors.Is(err, errDropped):
				log.Warn("remote gateway: dropped a message on a "+what, "reason", err.Error())
			default:
				log.Warn("remote gateway: closed a "+what, "reason", err.Error())
			}
			return err
		})
	}
	return tc, rw, nil
}

func (t *trackingWriter) Unwrap() http.ResponseWriter { return t.ResponseWriter }

// agentDesktopKey marks the request context of an agent's side of a desktop
// relay, whose connection to MeshCentral is paced; its value is the device's
// MeshCentral node ID, or "".
type agentDesktopKey struct{}

// agentDesktopWriter bounds the receive buffer of the connection the
// reverse proxy hijacks for an agent's side of a desktop relay.
type agentDesktopWriter struct {
	http.ResponseWriter
	log *slog.Logger
}

func (a agentDesktopWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	conn, rw, err := http.NewResponseController(a.ResponseWriter).Hijack()
	if err != nil {
		return nil, nil, err
	}
	if err := boundReceive(conn, agentDesktopBuffer); err != nil {
		a.log.Warn("remote gateway: could not bound an agent desktop connection's buffer", "error", err)
	}
	return conn, rw, nil
}

func (a agentDesktopWriter) Unwrap() http.ResponseWriter { return a.ResponseWriter }

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
