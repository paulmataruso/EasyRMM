package middleware

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/paulmataruso/easyrm/internal/auth"
	"github.com/paulmataruso/easyrm/pkg/models"
)

func UserFromContext(ctx context.Context) *models.User {
	return auth.UserFromContext(ctx)
}

func SetUserContext(ctx context.Context, user *models.User) context.Context {
	return auth.SetUserContext(ctx, user)
}

func HashToken(token string) string {
	return auth.HashToken(token)
}

func JSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if data != nil {
		_ = json.NewEncoder(w).Encode(data)
	}
}

func Error(w http.ResponseWriter, status int, message string) {
	JSON(w, status, map[string]string{"error": message})
}

func SecureHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "SAMEORIGIN")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		next.ServeHTTP(w, r)
	})
}

func Logger(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			ww := &responseWriter{ResponseWriter: w, status: http.StatusOK}
			next.ServeHTTP(ww, r)
			logger.Info("http request",
				"method", r.Method,
				"path", r.URL.Path,
				"status", ww.status,
				"duration_ms", time.Since(start).Milliseconds(),
				"ip", r.RemoteAddr,
			)
		})
	}
}

type responseWriter struct {
	http.ResponseWriter
	status int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.status = code
	rw.ResponseWriter.WriteHeader(code)
}

func RateLimit(requestsPerMin int) func(http.Handler) http.Handler {
	type client struct {
		tokens    float64
		lastCheck time.Time
	}
	var (
		mu      sync.Mutex
		clients = make(map[string]*client)
	)

	go func() {
		for range time.Tick(5 * time.Minute) {
			mu.Lock()
			cutoff := time.Now().Add(-10 * time.Minute)
			for ip, c := range clients {
				if c.lastCheck.Before(cutoff) {
					delete(clients, ip)
				}
			}
			mu.Unlock()
		}
	}()

	rate := float64(requestsPerMin) / 60.0
	burst := float64(requestsPerMin)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := r.RemoteAddr
			mu.Lock()
			c, exists := clients[ip]
			if !exists {
				c = &client{tokens: burst, lastCheck: time.Now()}
				clients[ip] = c
			}

			elapsed := time.Since(c.lastCheck).Seconds()
			c.tokens += elapsed * rate
			if c.tokens > burst {
				c.tokens = burst
			}
			c.lastCheck = time.Now()

			if c.tokens < 1 {
				mu.Unlock()
				w.Header().Set("Retry-After", "60")
				Error(w, http.StatusTooManyRequests, "rate limit exceeded")
				return
			}
			c.tokens--
			mu.Unlock()

			next.ServeHTTP(w, r)
		})
	}
}
