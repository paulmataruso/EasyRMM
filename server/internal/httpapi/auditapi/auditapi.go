// Package auditapi exposes the audit log.
package auditapi

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/httpapi"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
)

// API serves the audit routes.
type API struct{ log *audit.Logger }

// New builds the API.
func New(log *audit.Logger) *API { return &API{log: log} }

// Register mounts the routes.
func (a *API) Register(mux *http.ServeMux) {
	mux.Handle("GET /api/v1/audit", httpapi.RequireActive(httpapi.Handle(a.list)))
	mux.Handle("GET /api/v1/audit/verify", httpapi.RequireActive(httpapi.Handle(a.verify)))
}

// Scope returns the database scope in which the caller may read the audit
// log: only where they hold audit.view, which is narrower than where they
// can see devices.
func Scope(p *rbac.Principal) database.Scope {
	sc := p.Scope(rbac.PermAuditView)
	return database.Scope{All: sc.All, Orgs: sc.Orgs, Sites: sc.Sites}
}

func (a *API) list(w http.ResponseWriter, r *http.Request) error {
	id := httpapi.IdentityFrom(r.Context())
	scope := Scope(id.Principal)
	if !scope.All && len(scope.Orgs) == 0 && len(scope.Sites) == 0 {
		return apperr.Forbidden()
	}
	org, err := httpapi.QueryID(r, "organizationId")
	if err != nil {
		return err
	}
	actor, err := httpapi.QueryID(r, "actorId")
	if err != nil {
		return err
	}
	device, err := httpapi.QueryID(r, "deviceId")
	if err != nil {
		return err
	}
	before, err := httpapi.QueryInt(r, "before", 0, 0, 1<<62)
	if err != nil {
		return err
	}
	limit, err := httpapi.QueryInt(r, "limit", 100, 1, 500)
	if err != nil {
		return err
	}
	action := strings.TrimSpace(r.URL.Query().Get("action"))
	if action != "" && (len(action) > 100 || !validAction(action)) {
		return apperr.Invalid("action", "must be an action name or prefix, such as user or user.invite")
	}
	entries, err := a.log.List(r.Context(), scope, audit.Query{
		OrganizationID: org, ActorID: actor, DeviceID: device, ActionPrefix: action, Before: before, Limit: int(limit) + 1,
	})
	if err != nil {
		return err
	}
	next := ""
	if len(entries) > int(limit) {
		entries = entries[:limit]
		next = strconv.FormatInt(entries[len(entries)-1].ID, 10)
	}
	if entries == nil {
		entries = []audit.Entry{}
	}
	httpapi.WriteJSON(w, http.StatusOK, httpapi.List[audit.Entry]{Items: entries, Next: next})
	return nil
}

// validAction accepts action names and prefixes: lower-case words separated
// by dots, with digits and underscores inside words.
func validAction(s string) bool {
	for i, c := range s {
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9' && i > 0, c == '.' && i > 0, c == '_' && i > 0:
		default:
			return false
		}
	}
	return true
}

// verify recomputes the hash chain. It is limited to platform-wide auditors
// because the chain spans every tenant.
func (a *API) verify(w http.ResponseWriter, r *http.Request) error {
	id := httpapi.IdentityFrom(r.Context())
	if !id.Principal.CanGlobal(rbac.PermAuditView) {
		return apperr.Forbidden()
	}
	after, err := httpapi.QueryInt(r, "after", 0, 0, 1<<62)
	if err != nil {
		return err
	}
	limit, err := httpapi.QueryInt(r, "limit", 100_000, 1, 1_000_000)
	if err != nil {
		return err
	}
	res, err := a.log.Verify(r.Context(), after, int(limit))
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusOK, res)
	return nil
}
