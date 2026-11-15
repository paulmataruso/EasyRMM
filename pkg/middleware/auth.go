package middleware

import (
	"errors"
	"log/slog"
	"net/http"

	"github.com/jackc/pgx/v5"
	"github.com/paulmataruso/easyrm/internal/auth"
	"github.com/paulmataruso/easyrm/pkg/models"
)

const sessionCookieName = "__Host-session"

func RequireAuth(store *auth.Store) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			cookie, err := r.Cookie(sessionCookieName)
			if err != nil || cookie.Value == "" {
				writeError(w, http.StatusUnauthorized, "authentication required")
				return
			}

			tokenHash := auth.HashToken(cookie.Value)
			sess, err := store.GetSessionByToken(r.Context(), tokenHash)
			if err != nil {
				if errors.Is(err, pgx.ErrNoRows) {
					writeError(w, http.StatusUnauthorized, "session expired or invalid")
					return
				}
				slog.Error("auth middleware: get session", "error", err)
				writeError(w, http.StatusInternalServerError, "internal error")
				return
			}

			user, err := store.GetUserByID(r.Context(), sess.UserID)
			if err != nil {
				slog.Error("auth middleware: get user", "error", err)
				writeError(w, http.StatusInternalServerError, "internal error")
				return
			}

			if !user.IsActive {
				writeError(w, http.StatusForbidden, "account is disabled")
				return
			}

			ctx := auth.SetUserContext(r.Context(), user)
			ctx = auth.SetSessionContext(ctx, sess)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func RequireRole(roles ...string) func(http.Handler) http.Handler {
	allowed := make(map[string]bool, len(roles))
	for _, r := range roles {
		allowed[r] = true
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user := auth.UserFromContext(r.Context())
			if user == nil {
				writeError(w, http.StatusUnauthorized, "authentication required")
				return
			}
			if user.Role == models.RoleSuperAdmin {
				next.ServeHTTP(w, r)
				return
			}
			if !allowed[user.Role] {
				writeError(w, http.StatusForbidden, "insufficient permissions")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func RequireOrgAccess(store *auth.Store) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user := auth.UserFromContext(r.Context())
			if user == nil {
				writeError(w, http.StatusUnauthorized, "authentication required")
				return
			}
			if user.Role == models.RoleSuperAdmin {
				next.ServeHTTP(w, r)
				return
			}
			orgs, err := store.GetUserOrganizations(r.Context(), user.ID)
			if err != nil {
				slog.Error("org access middleware", "error", err)
				writeError(w, http.StatusInternalServerError, "internal error")
				return
			}
			if len(orgs) == 0 {
				writeError(w, http.StatusForbidden, "no organization access")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func writeError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(`{"error":"` + msg + `"}`))
}
