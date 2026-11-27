// Package tlsaddnameapi exposes adding a DNS name pair to an installation set
// up on an IP address (ADR-0055, slice 5b3). Every route but the reachability
// token and the browser confirmation needs settings.manage; adding and
// removing also need step-up authentication. No response carries a key.
package tlsaddnameapi

import (
	"errors"
	"net/http"
	"strings"

	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/httpapi"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
	"github.com/paulmataruso/easyrmm/server/internal/tlsaddname"
	"github.com/paulmataruso/easyrmm/server/internal/tlsmove"
)

// API serves the routes.
type API struct {
	svc      *tlsaddname.Service
	sessions *httpapi.Sessions
}

// New builds the API; sessions asks for the step-up.
func New(svc *tlsaddname.Service, sessions *httpapi.Sessions) *API {
	return &API{svc: svc, sessions: sessions}
}

const base = "/api/v1/settings/certificates/added-name"

// Register mounts the routes.
func (a *API) Register(mux *http.ServeMux) {
	r := func(pattern string, stepUp bool, h httpapi.HandlerFunc) {
		var handler http.Handler = httpapi.Handle(h) //nolint:staticcheck // the step-up wrapper returns the interface
		if stepUp {
			handler = a.sessions.RequireStepUp(handler)
		}
		mux.Handle(pattern, httpapi.RequireActive(httpapi.Handle(func(w http.ResponseWriter, r *http.Request) error {
			if !httpapi.Can(r, rbac.PermSettingsManage, rbac.Resource{}) {
				return apperr.Forbidden()
			}
			handler.ServeHTTP(w, r)
			return nil
		})))
	}
	r("GET "+base, false, a.status)
	r("POST "+base+"/check", false, a.check)
	r("POST "+base, true, a.add)
	r("DELETE "+base, true, a.remove)
	r("POST "+base+"/resend", false, a.resend)
	// Any signed-in person loading the console through a name is proof that
	// it reaches this server, so no permission beyond a session is asked.
	mux.Handle("POST "+base+"/browser-confirm", httpapi.RequireActive(httpapi.Handle(a.browserConfirm)))
	// The server's own reachability fetch, unauthenticated.
	mux.HandleFunc("GET "+tlsaddname.ReachPath, a.svc.ServeReach)
}

type pairBody struct {
	Console string `json:"console"`
	Mesh    string `json:"mesh"`
}

func (a *API) status(w http.ResponseWriter, r *http.Request) error {
	out := map[string]any{"eligible": a.svc.Eligible(r.Context())}
	p, err := a.svc.Status(r.Context())
	switch {
	case err == nil:
		out["pair"] = p
	case !errors.Is(err, tlsaddname.ErrNone):
		return err
	}
	httpapi.WriteJSON(w, http.StatusOK, out)
	return nil
}

func (a *API) check(w http.ResponseWriter, r *http.Request) error {
	var in pairBody
	if err := httpapi.DecodeJSON(w, r, &in); err != nil {
		return err
	}
	checks, err := a.svc.Preflight(r.Context(), in.Console, in.Mesh)
	if err != nil {
		return mapErr(err)
	}
	httpapi.WriteJSON(w, http.StatusOK, map[string]any{"checks": checks})
	return nil
}

func (a *API) add(w http.ResponseWriter, r *http.Request) error {
	var in pairBody
	if err := httpapi.DecodeJSON(w, r, &in); err != nil {
		return err
	}
	if err := a.svc.Add(r.Context(), httpapi.Actor(r), in.Console, in.Mesh); err != nil {
		return mapErr(err)
	}
	httpapi.WriteJSON(w, http.StatusAccepted, map[string]string{"status": "pending"})
	return nil
}

func (a *API) remove(w http.ResponseWriter, r *http.Request) error {
	if err := a.svc.Remove(r.Context(), httpapi.Actor(r)); err != nil {
		return mapErr(err)
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func (a *API) resend(w http.ResponseWriter, r *http.Request) error {
	if err := a.svc.Resend(r.Context()); err != nil {
		return mapErr(err)
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func (a *API) browserConfirm(w http.ResponseWriter, r *http.Request) error {
	if err := a.svc.BrowserConfirm(r.Context(), r.Host); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func conflict(code, msg string) error {
	return &httpapi.Error{Status: http.StatusConflict, Code: code, Message: msg}
}

func mapErr(err error) error {
	switch {
	case errors.Is(err, tlsaddname.ErrBadName), errors.Is(err, tlsaddname.ErrNotSameSite):
		return httpapi.BadRequest(strings.TrimPrefix(err.Error(), "tlsaddname: "))
	case errors.Is(err, tlsaddname.ErrNone):
		return apperr.NotFound()
	case errors.Is(err, tlsaddname.ErrExists):
		return conflict("exists", "A name pair is added already. Remove it first.")
	case errors.Is(err, tlsaddname.ErrNotIPInstall):
		return conflict("not_ip_install", "This installation already has a DNS name; changing it is not supported here.")
	case errors.Is(err, tlsaddname.ErrNotReachable):
		return conflict("not_reachable", strings.TrimPrefix(err.Error(), "tlsaddname: ")+". Create the DNS records the page shows and check again.")
	case errors.Is(err, tlsaddname.ErrUnavailable):
		return conflict("unavailable", "This server cannot obtain Let's Encrypt certificates in its current TLS mode.")
	case errors.Is(err, tlsmove.ErrMoveActive):
		return conflict("move_active", "A move of one of these names is already waiting.")
	}
	return err
}
