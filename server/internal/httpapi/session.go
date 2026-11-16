package httpapi

import (
	"context"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/paulmataruso/easyrmm/server/internal/access"
	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/auth"
	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
)

// SessionResolver is the subset of the authentication service the
// middleware needs.
type SessionResolver interface {
	Authenticate(ctx context.Context, token string) (*auth.Session, *auth.User, error)
	LoadPrincipal(ctx context.Context, userID uuid.UUID) (*rbac.Principal, error)
}

// Identity is the authenticated caller.
type Identity struct {
	Token     string
	Session   *auth.Session
	User      *auth.User
	Principal *rbac.Principal
	Scope     database.Scope
	CSRFToken string
}

type identityKey struct{}

// IdentityFrom returns the caller's identity, or nil.
func IdentityFrom(ctx context.Context) *Identity {
	id, _ := ctx.Value(identityKey{}).(*Identity)
	return id
}

// Sessions manages the session cookie, identity resolution and CSRF.
type Sessions struct {
	resolver   SessionResolver
	csrfKey    []byte
	cookieName string
	secure     bool
	origins    map[string]bool
}

// NewSessions builds the session middleware. masterKey is the primary secret
// key; the CSRF key is derived from it with HKDF so the two never coincide.
// When secure is false (local development over plain HTTP only) the cookie
// drops the __Host- prefix and the Secure attribute. origins are the console
// origins state-changing requests may come from.
func NewSessions(resolver SessionResolver, masterKey []byte, origins []string, secure bool) (*Sessions, error) {
	key, err := hkdf.Key(sha256.New, masterKey, nil, "easyrmm csrf v1", 32)
	if err != nil {
		return nil, err
	}
	name := "__Host-easyrmm_session"
	if !secure {
		name = "easyrmm_session"
	}
	allowed := make(map[string]bool, len(origins))
	for _, o := range origins {
		if o = strings.TrimSuffix(o, "/"); o != "" {
			allowed[o] = true
		}
	}
	return &Sessions{resolver: resolver, csrfKey: key, cookieName: name, secure: secure, origins: allowed}, nil
}

// CookieName returns the session cookie name.
func (s *Sessions) CookieName() string { return s.cookieName }

// CSRFToken derives the synchronizer token for a session token. It changes
// whenever the session token is rotated (sign-in steps, MFA).
func (s *Sessions) CSRFToken(sessionToken string) string {
	m := hmac.New(sha256.New, s.csrfKey)
	m.Write(auth.HashToken(sessionToken))
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

// SetCookie stores a session token in the browser.
func (s *Sessions) SetCookie(w http.ResponseWriter, token string, expires time.Time) {
	http.SetCookie(w, &http.Cookie{ //nolint:gosec // Secure is false only in the explicit plain-HTTP development mode
		Name: s.cookieName, Value: token, Path: "/", Expires: expires,
		Secure: s.secure, HttpOnly: true, SameSite: http.SameSiteStrictMode,
	})
}

// ClearCookie removes the session cookie.
func (s *Sessions) ClearCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{ //nolint:gosec // Secure is false only in the explicit plain-HTTP development mode
		Name: s.cookieName, Value: "", Path: "/", MaxAge: -1,
		Secure: s.secure, HttpOnly: true, SameSite: http.SameSiteStrictMode,
	})
}

// Load resolves the session cookie, if any, into an Identity on the request
// context. Invalid cookies are cleared. It never rejects a request; use
// RequireState or RequireActive for that.
func (s *Sessions) Load(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(s.cookieName)
		if err != nil || c.Value == "" {
			next.ServeHTTP(w, r)
			return
		}
		sess, user, err := s.resolver.Authenticate(r.Context(), c.Value)
		if err != nil {
			if !errors.Is(err, auth.ErrInvalidSession) {
				WriteError(w, r, err)
				return
			}
			s.ClearCookie(w)
			next.ServeHTTP(w, r)
			return
		}
		id := &Identity{Token: c.Value, Session: sess, User: user, CSRFToken: s.CSRFToken(c.Value)}
		if sess.State == auth.StateActive {
			p, err := s.resolver.LoadPrincipal(r.Context(), user.ID)
			if err != nil {
				WriteError(w, r, err)
				return
			}
			id.Principal = p
			id.Scope = auth.DataScope(p)
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), identityKey{}, id)))
	})
}

// CSRF protects state-changing requests. Every unsafe request must come
// from the application's own origin (Sec-Fetch-Site / Origin), and requests
// made with a session must also carry the session's synchronizer token.
func (s *Sessions) CSRF(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
			next.ServeHTTP(w, r)
			return
		}
		if !s.sameOrigin(r) {
			WriteError(w, r, ErrCSRF)
			return
		}
		if id := IdentityFrom(r.Context()); id != nil {
			got := r.Header.Get("X-CSRF-Token")
			if got == "" || !hmac.Equal([]byte(got), []byte(id.CSRFToken)) {
				WriteError(w, r, ErrCSRF)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Sessions) sameOrigin(r *http.Request) bool {
	if site := r.Header.Get("Sec-Fetch-Site"); site != "" {
		return site == "same-origin"
	}
	return s.origins[r.Header.Get("Origin")]
}

// RequireState rejects requests whose session is not in one of the states.
func RequireState(states ...auth.SessionState) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			id := IdentityFrom(r.Context())
			if id == nil {
				WriteError(w, r, ErrUnauthenticated)
				return
			}
			if !slices.Contains(states, id.Session.State) {
				WriteError(w, r, &Error{Status: http.StatusForbidden, Code: "mfa_required", Message: "Finish signing in to continue."})
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// RequireActive rejects requests without a fully signed-in session.
func RequireActive(next http.Handler) http.Handler {
	return RequireState(auth.StateActive)(next)
}

// Can reports whether the caller holds perm for the resource.
func Can(r *http.Request, perm rbac.Permission, res rbac.Resource) bool {
	id := IdentityFrom(r.Context())
	return id != nil && id.Principal.Can(perm, res)
}

// Actor returns the audit actor for the caller.
func Actor(r *http.Request) audit.Actor {
	a := audit.Actor{Type: audit.ActorUser, SourceIP: ClientIP(r), UserAgent: r.UserAgent()}
	if id := IdentityFrom(r.Context()); id != nil {
		a.ID, a.Label = id.User.ID, id.User.Email
	}
	return a
}

// Caller returns the signed-in caller for domain services. Use it only on
// routes wrapped in RequireActive.
func Caller(r *http.Request) access.Caller {
	id := IdentityFrom(r.Context())
	if id == nil || id.Principal == nil {
		// RequireActive guarantees an identity; an empty caller is denied
		// everything.
		return access.User(nil, database.Scope{}, Actor(r))
	}
	return access.User(id.Principal, id.Scope, Actor(r))
}

// Meta returns the client metadata used by the authentication service.
func Meta(r *http.Request) auth.RequestMeta {
	return auth.RequestMeta{IP: ClientIP(r), UserAgent: r.UserAgent()}
}
