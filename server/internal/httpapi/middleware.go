package httpapi

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"runtime/debug"
	"strings"
	"time"
)

// Middleware wraps a handler.
type Middleware func(http.Handler) http.Handler

// Chain applies middleware so that the first listed runs outermost.
func Chain(h http.Handler, mws ...Middleware) http.Handler {
	for i := len(mws) - 1; i >= 0; i-- {
		h = mws[i](h)
	}
	return h
}

type clientIPKey struct{}
type requestIDKey struct{}

// ClientIP returns the resolved client address for the request.
func ClientIP(r *http.Request) netip.Addr {
	if a, ok := r.Context().Value(clientIPKey{}).(netip.Addr); ok {
		return a
	}
	return remoteAddr(r)
}

// RequestID returns the request identifier.
func RequestID(r *http.Request) string {
	id, _ := r.Context().Value(requestIDKey{}).(string)
	return id
}

func remoteAddr(r *http.Request) netip.Addr {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	a, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}
	}
	return a.Unmap()
}

// RealIP resolves the client address. X-Forwarded-For is honored only when
// the direct peer is a trusted proxy, and then the right-most address that is
// not itself a trusted proxy is used, so clients cannot spoof their address
// by sending the header themselves.
func RealIP(trusted []netip.Prefix) Middleware {
	isTrusted := func(a netip.Addr) bool {
		for _, p := range trusted {
			if p.Contains(a) {
				return true
			}
		}
		return false
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := remoteAddr(r)
			if ip.IsValid() && isTrusted(ip) {
				var hops []string
				for _, v := range r.Header.Values("X-Forwarded-For") {
					hops = append(hops, strings.Split(v, ",")...)
				}
				for i := len(hops) - 1; i >= 0; i-- {
					a, err := netip.ParseAddr(strings.TrimSpace(hops[i]))
					if err != nil {
						break
					}
					ip = a.Unmap()
					if !isTrusted(ip) {
						break
					}
				}
			}
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), clientIPKey{}, ip)))
		})
	}
}

// RequestContext assigns a request id and a request-scoped logger, and logs
// each request on completion.
func RequestContext(base *slog.Logger) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			b := make([]byte, 8)
			_, _ = rand.Read(b)
			id := hex.EncodeToString(b)
			log := base.With("request_id", id)
			ctx := context.WithValue(r.Context(), requestIDKey{}, id)
			ctx = context.WithValue(ctx, loggerKey{}, log)
			w.Header().Set("X-Request-Id", id)
			rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
			start := time.Now()
			next.ServeHTTP(rec, r.WithContext(ctx))
			level := slog.LevelInfo
			if rec.status >= 500 {
				level = slog.LevelError
			}
			// Never log query strings: they may carry tokens.
			log.Log(ctx, level, "http request", "method", r.Method, "path", LogSafe(r.URL.Path), "status", rec.status,
				"duration_ms", time.Since(start).Milliseconds(), "client_ip", ClientIP(r).String())
		})
	}
}

type statusRecorder struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
}

func (s *statusRecorder) WriteHeader(code int) {
	if !s.wroteHeader {
		s.status, s.wroteHeader = code, true
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Write(b []byte) (int, error) {
	s.wroteHeader = true
	return s.ResponseWriter.Write(b)
}

// Unwrap lets http.ResponseController reach the underlying writer
// (flushing, hijacking for WebSockets).
func (s *statusRecorder) Unwrap() http.ResponseWriter { return s.ResponseWriter }

// Recover turns panics into 500 responses and logs the stack.
func Recover(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if v := recover(); v != nil {
				if err, ok := v.(error); ok && errors.Is(err, http.ErrAbortHandler) {
					panic(v)
				}
				LoggerFrom(r.Context()).Error("panic serving request", "panic", v, "stack", string(debug.Stack()))
				WriteError(w, r, errPanic)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

var errPanic = &panicError{}

type panicError struct{}

func (*panicError) Error() string { return "handler panic" }

// SecurityHeaders sets headers appropriate for the application origin.
// frameOrigin, when non-empty, is the only origin the UI may embed in an
// iframe (the MeshCentral host, for remote sessions).
func SecurityHeaders(hsts bool, frameOrigin string) Middleware {
	frameSrc := "'none'"
	if frameOrigin != "" {
		frameSrc = frameOrigin
	}
	csp := strings.Join([]string{
		"default-src 'self'",
		"script-src 'self'",
		"style-src 'self'",
		"img-src 'self' data:",
		"font-src 'self'",
		"connect-src 'self'",
		"frame-src " + frameSrc,
		"frame-ancestors 'none'",
		"form-action 'self'",
		"base-uri 'none'",
		"object-src 'none'",
	}, "; ")
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h := w.Header()
			h.Set("Content-Security-Policy", csp)
			h.Set("X-Content-Type-Options", "nosniff")
			h.Set("X-Frame-Options", "DENY")
			h.Set("Referrer-Policy", "no-referrer")
			h.Set("Cross-Origin-Opener-Policy", "same-origin")
			h.Set("Cross-Origin-Resource-Policy", "same-origin")
			h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=()")
			if hsts {
				h.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
			}
			next.ServeHTTP(w, r)
		})
	}
}
