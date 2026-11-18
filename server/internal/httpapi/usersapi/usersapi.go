// Package usersapi exposes user administration, the role catalog, the
// signed-in user's profile, and first-run setup.
package usersapi

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/auth"
	"github.com/paulmataruso/easyrmm/server/internal/httpapi"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
	"github.com/paulmataruso/easyrmm/server/internal/users"
)

// API serves the user routes.
type API struct {
	svc   *users.Service
	setup *Setup
}

// New builds the API.
func New(svc *users.Service, setup *Setup) *API { return &API{svc: svc, setup: setup} }

// Register mounts the routes.
func (a *API) Register(mux *http.ServeMux) {
	r := func(pattern string, h httpapi.HandlerFunc) {
		mux.Handle(pattern, httpapi.RequireActive(httpapi.Handle(h)))
	}
	r("GET /api/v1/roles", a.roles)
	r("GET /api/v1/users", a.list)
	r("POST /api/v1/users", a.invite)
	r("GET /api/v1/users/{id}", a.get)
	r("PATCH /api/v1/users/{id}", a.update)
	r("PUT /api/v1/users/{id}/roles", a.setRoles)
	r("POST /api/v1/users/{id}/disable", a.status("disabled"))
	r("POST /api/v1/users/{id}/enable", a.status("active"))
	r("POST /api/v1/users/{id}/unlock", a.unlock)
	r("POST /api/v1/users/{id}/reset-mfa", a.resetMFA)
	r("POST /api/v1/users/{id}/password-link", a.passwordLink)
	r("DELETE /api/v1/users/{id}", a.remove)
	r("PATCH /api/v1/me", a.updateMe)

	mux.Handle("GET /api/v1/setup", httpapi.Handle(a.setupStatus))
	mux.Handle("POST /api/v1/setup", httpapi.Handle(a.completeSetup))
}

// RoleView describes a built-in role.
type RoleView struct {
	Role        rbac.Role         `json:"role"`
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Rank        int               `json:"rank"`
	Scopes      []rbac.ScopeKind  `json:"scopes"`
	Permissions []rbac.Permission `json:"permissions"`
}

func (a *API) roles(w http.ResponseWriter, _ *http.Request) error {
	out := make([]RoleView, 0, len(rbac.Roles))
	for _, d := range rbac.Roles {
		perms := append([]rbac.Permission(nil), d.Permissions...)
		sort.Slice(perms, func(i, j int) bool { return perms[i] < perms[j] })
		out = append(out, RoleView{Role: d.Role, Name: d.Name, Description: d.Description, Rank: d.Rank, Scopes: d.Scopes, Permissions: perms})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Rank > out[j].Rank })
	httpapi.WriteJSON(w, http.StatusOK, httpapi.List[RoleView]{Items: out})
	return nil
}

func (a *API) list(w http.ResponseWriter, r *http.Request) error {
	org, err := httpapi.QueryID(r, "organizationId")
	if err != nil {
		return err
	}
	limit, err := httpapi.QueryInt(r, "limit", 100, 1, 200)
	if err != nil {
		return err
	}
	q := r.URL.Query()
	items, next, err := a.svc.List(r.Context(), httpapi.Caller(r), users.ListQuery{
		Search: q.Get("q"), OrganizationID: org, After: q.Get("after"), Limit: int(limit),
	})
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusOK, httpapi.List[users.User]{Items: items, Next: next})
	return nil
}

func (a *API) get(w http.ResponseWriter, r *http.Request) error {
	id, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	u, err := a.svc.Get(r.Context(), httpapi.Caller(r), id)
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusOK, u)
	return nil
}

func (a *API) invite(w http.ResponseWriter, r *http.Request) error {
	var in users.InviteInput
	if err := httpapi.DecodeJSON(w, r, &in); err != nil {
		return err
	}
	res, err := a.svc.Invite(r.Context(), httpapi.Caller(r), in, httpapi.Meta(r))
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusCreated, res)
	return nil
}

type profileInput struct {
	DisplayName string `json:"displayName"`
}

func (a *API) update(w http.ResponseWriter, r *http.Request) error {
	id, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	var in profileInput
	if err := httpapi.DecodeJSON(w, r, &in); err != nil {
		return err
	}
	u, err := a.svc.UpdateProfile(r.Context(), httpapi.Caller(r), id, in.DisplayName)
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusOK, u)
	return nil
}

type rolesInput struct {
	Assignments []users.Assignment `json:"assignments"`
}

func (a *API) setRoles(w http.ResponseWriter, r *http.Request) error {
	id, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	var in rolesInput
	if err := httpapi.DecodeJSON(w, r, &in); err != nil {
		return err
	}
	u, err := a.svc.SetAssignments(r.Context(), httpapi.Caller(r), id, in.Assignments)
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusOK, u)
	return nil
}

func (a *API) status(status string) httpapi.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) error {
		id, err := httpapi.PathID(r)
		if err != nil {
			return err
		}
		u, err := a.svc.SetStatus(r.Context(), httpapi.Caller(r), id, status)
		if err != nil {
			return err
		}
		httpapi.WriteJSON(w, http.StatusOK, u)
		return nil
	}
}

func (a *API) unlock(w http.ResponseWriter, r *http.Request) error {
	id, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	u, err := a.svc.Unlock(r.Context(), httpapi.Caller(r), id)
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusOK, u)
	return nil
}

func (a *API) resetMFA(w http.ResponseWriter, r *http.Request) error {
	id, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	u, err := a.svc.ResetMFA(r.Context(), httpapi.Caller(r), id)
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusOK, u)
	return nil
}

func (a *API) passwordLink(w http.ResponseWriter, r *http.Request) error {
	id, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	res, err := a.svc.IssuePasswordLink(r.Context(), httpapi.Caller(r), id, httpapi.Meta(r))
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusOK, res)
	return nil
}

func (a *API) remove(w http.ResponseWriter, r *http.Request) error {
	id, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	if err := a.svc.Delete(r.Context(), httpapi.Caller(r), id); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func (a *API) updateMe(w http.ResponseWriter, r *http.Request) error {
	var in profileInput
	if err := httpapi.DecodeJSON(w, r, &in); err != nil {
		return err
	}
	id := httpapi.IdentityFrom(r.Context())
	if err := a.svc.UpdateOwnProfile(r.Context(), httpapi.Actor(r), id.User.ID, in.DisplayName); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

// ---------------------------------------------------------------------------
// First-run setup
// ---------------------------------------------------------------------------

// Setup guards first-run setup with a one-time token written to the data
// directory, so only someone with access to the server can claim it. Without
// this, whoever reached a freshly started server first would become its
// administrator.
type Setup struct {
	svc  *users.Service
	path string
	log  *slog.Logger
	// Ten setup attempts at once per address, then one every 10 seconds.
	limit *auth.KeyedLimiter

	mu   sync.Mutex
	hash [32]byte
	done bool
}

// NewSetup prepares first-run setup. When no account exists it writes a new
// token to <dataDir>/setup-token (mode 0600) and logs where to find it.
func NewSetup(ctx context.Context, svc *users.Service, dataDir string, log *slog.Logger) (*Setup, error) {
	s := &Setup{svc: svc, path: filepath.Join(dataDir, "setup-token"), log: log,
		limit: auth.NewKeyedLimiter(10*time.Second, 10, 10_000)}
	needed, err := svc.NeedsSetup(ctx)
	if err != nil {
		return nil, err
	}
	if !needed {
		s.done = true
		_ = os.Remove(s.path)
		return s, nil
	}
	raw := make([]byte, 24)
	if _, err := rand.Read(raw); err != nil {
		return nil, err
	}
	token := base64.RawURLEncoding.EncodeToString(raw)
	s.hash = sha256.Sum256([]byte(token))
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return nil, fmt.Errorf("setup: creating data directory: %w", err)
	}
	if err := os.WriteFile(s.path, []byte(token+"\n"), 0o600); err != nil {
		return nil, fmt.Errorf("setup: writing token: %w", err)
	}
	log.Warn("first-run setup is pending: open the web interface and enter the setup token",
		"token_file", s.path)
	return s, nil
}

func (s *Setup) pending(ctx context.Context) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.done {
		return false, nil
	}
	needed, err := s.svc.NeedsSetup(ctx)
	if err != nil {
		return false, err
	}
	if !needed {
		s.finish()
	}
	return needed, nil
}

func (s *Setup) finish() {
	s.done = true
	if err := os.Remove(s.path); err != nil && !os.IsNotExist(err) {
		s.log.Error("could not remove the setup token file; delete it manually", "path", s.path, "error", err)
	}
}

func (a *API) setupStatus(w http.ResponseWriter, r *http.Request) error {
	pending, err := a.setup.pending(r.Context())
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusOK, map[string]any{"required": pending, "passwordMinLength": auth.MinPasswordLength})
	return nil
}

type setupRequest struct {
	Token string `json:"token"`
	users.SetupInput
}

func (a *API) completeSetup(w http.ResponseWriter, r *http.Request) error {
	var in setupRequest
	if err := httpapi.DecodeJSON(w, r, &in); err != nil {
		return err
	}
	if !a.setup.limit.Allow(auth.LimitKey(httpapi.ClientIP(r))) {
		return httpapi.ErrTooMany
	}
	s := a.setup
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.done {
		return users.ErrSetupDone
	}
	got := sha256.Sum256([]byte(in.Token))
	if subtle.ConstantTimeCompare(got[:], s.hash[:]) != 1 {
		return apperr.Invalid("token", "The setup token is not correct. Copy it from the setup-token file in the server's data directory.")
	}
	if _, err := a.svc.Bootstrap(r.Context(), in.SetupInput, httpapi.Meta(r)); err != nil {
		if err == users.ErrSetupDone { //nolint:errorlint // sentinel returned directly
			s.finish()
		}
		return err
	}
	s.finish()
	s.log.Info("first-run setup completed")
	w.WriteHeader(http.StatusNoContent)
	return nil
}
