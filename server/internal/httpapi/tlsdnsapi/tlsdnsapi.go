// Package tlsdnsapi exposes DNS-01 challenge credentials (ADR-0055, slice
// 5b4). Every route needs settings.manage; writes need step-up. No response
// carries a secret.
package tlsdnsapi

import (
	"errors"
	"net/http"

	"github.com/google/uuid"

	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/httpapi"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
	"github.com/paulmataruso/easyrmm/server/internal/tlsdns"
)

// API serves the DNS credential routes.
type API struct {
	svc      *tlsdns.Service
	sessions *httpapi.Sessions
}

// New builds the API.
func New(svc *tlsdns.Service, sessions *httpapi.Sessions) *API {
	return &API{svc: svc, sessions: sessions}
}

const base = "/api/v1/settings/certificates/dns"

// Register mounts the routes.
func (a *API) Register(mux *http.ServeMux) {
	r := func(pattern string, stepUp bool, h httpapi.HandlerFunc) {
		var handler http.Handler = httpapi.Handle(h) //nolint:staticcheck
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
	r("GET "+base, false, a.list)
	r("POST "+base, true, a.save)
	r("PUT "+base+"/{id}", true, a.replace)
	r("DELETE "+base+"/{id}", true, a.remove)
	r("POST "+base+"/{id}/test", false, a.retest)
}

func (a *API) list(w http.ResponseWriter, r *http.Request) error {
	creds, err := a.svc.List(r.Context())
	if err != nil {
		return err
	}
	if creds == nil {
		creds = []tlsdns.Credential{}
	}
	httpapi.WriteJSON(w, http.StatusOK, map[string]any{"credentials": creds})
	return nil
}

func (a *API) save(w http.ResponseWriter, r *http.Request) error {
	var in tlsdns.SaveInput
	if err := httpapi.DecodeJSON(w, r, &in); err != nil {
		return err
	}
	cred, reason, err := a.svc.Save(r.Context(), httpapi.Actor(r), in)
	if err != nil {
		return mapErr(err)
	}
	httpapi.WriteJSON(w, http.StatusCreated, map[string]any{"credential": cred, "testResult": reason})
	return nil
}

func (a *API) replace(w http.ResponseWriter, r *http.Request) error {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		return apperr.Invalid("id", "not a valid UUID")
	}
	var in tlsdns.SaveInput
	if err := httpapi.DecodeJSON(w, r, &in); err != nil {
		return err
	}
	cred, reason, err := a.svc.Replace(r.Context(), httpapi.Actor(r), id, in)
	if err != nil {
		return mapErr(err)
	}
	httpapi.WriteJSON(w, http.StatusOK, map[string]any{"credential": cred, "testResult": reason})
	return nil
}

func (a *API) remove(w http.ResponseWriter, r *http.Request) error {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		return apperr.Invalid("id", "not a valid UUID")
	}
	if err := a.svc.Remove(r.Context(), httpapi.Actor(r), id); err != nil {
		return mapErr(err)
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func (a *API) retest(w http.ResponseWriter, r *http.Request) error {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		return apperr.Invalid("id", "not a valid UUID")
	}
	reason, err := a.svc.Retest(r.Context(), httpapi.Actor(r), id)
	if err != nil {
		return mapErr(err)
	}
	httpapi.WriteJSON(w, http.StatusOK, map[string]any{"testResult": reason})
	return nil
}

func mapErr(err error) error {
	switch {
	case errors.Is(err, tlsdns.ErrNotFound):
		return apperr.NotFound()
	case errors.Is(err, tlsdns.ErrDuplicateZone):
		return apperr.Conflict("duplicate_zone", "A credential for this zone already exists.")
	case errors.Is(err, tlsdns.ErrBadProvider):
		return apperr.Invalid("provider", "Unknown provider; use rfc2136 or cloudflare.")
	case errors.Is(err, tlsdns.ErrBadZone):
		return apperr.Invalid("zone", "Not a valid DNS zone.")
	case errors.Is(err, tlsdns.ErrBadAlgorithm):
		return apperr.Invalid("algorithm", "TSIG algorithm not allowed; use hmac-sha256, hmac-sha384 or hmac-sha512.")
	case errors.Is(err, tlsdns.ErrBadServer):
		return apperr.Invalid("server", "The server address could not be resolved or is not allowed.")
	case errors.Is(err, tlsdns.ErrCloudMetadata):
		return apperr.Invalid("server", "Cloud metadata addresses are not allowed.")
	case errors.Is(err, tlsdns.ErrMissingField):
		return apperr.Invalid("", "A required field is empty.")
	}
	return err
}
