package easypatch

import (
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/paulmataruso/easyrmm/server/internal/httpapi"
)

// Agents on EasyRMM's name (one-product plan, B4). EasyPatch agents talk to
// EasyRMM's own address:
// the edge forwards exactly the paths they use to the patching engine on
// loopback, before the session, CSRF and console layers, none of which apply
// to an agent. Everything else of the engine stays on loopback.
//
// What is forwarded is served on EasyRMM's origin, where its session cookie
// lives, so nothing the engine answers may act on that origin: cookies are
// dropped both ways, and every answer is sandboxed and never sniffed.

// agentPrefixes are the engine's paths for agents: their API, and
// the agent packages and winget manifests they install from. Deployment-code
// install scripts (/downloads/install/) are not among them.
var agentPrefixes = []string{"/api/v1/agents/", "/downloads/agent/", "/downloads/winget/"}

// AgentBodyLimit caps what an agent may send through the edge; the
// engine's own limit is 16 MiB.
const AgentBodyLimit = 20 << 20

// AgentPath reports whether p is one of the engine's agent paths, which
// the edge forwards to it.
func AgentPath(p string) bool {
	for _, prefix := range agentPrefixes {
		if strings.HasPrefix(p, prefix) {
			return true
		}
	}
	return false
}

// AgentHost serves a name only EasyPatch agents use, that of an imported
// standalone EasyPatch (config.Patching.AgentHostnames): the agents' paths
// go to agents, and everything else (a person following a link to the old
// console) is sent to EasyRMM's patching pages at console.
func AgentHost(agents http.Handler, console string) http.Handler {
	target := strings.TrimRight(console, "/") + "/patching"
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if AgentPath(r.URL.Path) {
			agents.ServeHTTP(w, r)
			return
		}
		http.Redirect(w, r, target, http.StatusFound)
	})
}

// cleanAgentPath reports whether a request's path means the same to the
// engine as to EasyRMM: no dot segments, empty segments, backslashes or
// encoded separators that a server could resolve to a path outside the
// forwarded prefixes.
func cleanAgentPath(u *url.URL) bool {
	p := u.Path
	if strings.Contains(p, "//") || strings.Contains(p, `\`) || strings.ContainsRune(p, 0) {
		return false
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == "." || seg == ".." {
			return false
		}
	}
	raw := strings.ToLower(u.EscapedPath())
	for _, enc := range []string{"%2f", "%5c", "%2e", "%00"} {
		if strings.Contains(raw, enc) {
			return false
		}
	}
	return true
}

// NewAgentProxy forwards agent requests to the engine at target. secure
// adds HSTS to its answers.
func NewAgentProxy(target *url.URL, secure bool, log *slog.Logger) http.Handler {
	proxy := &httputil.ReverseProxy{
		// Rewrite starts from a request without X-Forwarded-* headers and
		// without hop-by-hop ones.
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(target)
			pr.Out.Host = pr.In.Host
			pr.Out.Header.Del("Forwarded")
			pr.Out.Header.Del("Cookie")
			// Only EasyRMM makes statements, on loopback.
			pr.Out.Header.Del(StatementHeader)
			// The address EasyRMM resolved: the peer, or in offload mode
			// what its trusted proxy reported.
			pr.Out.Header.Set("X-Forwarded-For", httpapi.ClientIP(pr.In).String())
			proto := "http"
			if o, ok := httpapi.OriginOf(pr.In); ok && strings.HasPrefix(o.Console, "https://") {
				proto = "https"
			}
			pr.Out.Header.Set("X-Forwarded-Proto", proto)
			pr.Out.Header.Set("X-Forwarded-Host", pr.In.Host)
		},
		// Agents sign the method, the exact request target and the body
		// (EasyPatch's request signing): all three pass through as sent, and
		// answers as the engine sent them, never decompressed.
		Transport: &http.Transport{
			Proxy:                 nil,
			DisableCompression:    true,
			DialContext:           (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
			MaxIdleConns:          128,
			MaxIdleConnsPerHost:   64,
			IdleConnTimeout:       90 * time.Second,
			ResponseHeaderTimeout: 2 * time.Minute,
		},
		ModifyResponse: func(resp *http.Response) error {
			h := resp.Header
			h.Del("Set-Cookie")
			h.Del("Clear-Site-Data")
			h.Set("X-Content-Type-Options", "nosniff")
			h.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'; sandbox")
			if secure && h.Get("Strict-Transport-Security") == "" {
				h.Set("Strict-Transport-Security", "max-age=63072000")
			}
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			if _, ok := errors.AsType[*http.MaxBytesError](err); ok {
				httpapi.WriteError(w, r, agentBodyTooLarge)
				return
			}
			httpapi.LoggerFrom(r.Context()).Warn("patching engine unreachable for an agent", "error", err, "path", httpapi.LogSafe(r.URL.Path))
			w.Header().Set("Retry-After", "30")
			httpapi.WriteError(w, r, &httpapi.Error{Status: http.StatusBadGateway, Code: "patching_unavailable",
				Message: "The patching engine is not answering. Try again shortly."})
		},
		ErrorLog: slog.NewLogLogger(log.Handler(), slog.LevelWarn),
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !cleanAgentPath(r.URL) {
			httpapi.WriteError(w, r, &httpapi.Error{Status: http.StatusBadRequest, Code: "bad_path", Message: "That path is not allowed."})
			return
		}
		if r.ContentLength > AgentBodyLimit {
			httpapi.WriteError(w, r, agentBodyTooLarge)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, AgentBodyLimit)
		proxy.ServeHTTP(w, r)
	})
}

var agentBodyTooLarge = &httpapi.Error{Status: http.StatusRequestEntityTooLarge, Code: "too_large", Message: "The request is larger than 20 MB."}
