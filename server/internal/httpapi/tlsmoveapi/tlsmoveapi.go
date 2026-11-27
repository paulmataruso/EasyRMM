// Package tlsmoveapi exposes moving a DNS name's certificate between sources
// (ADR-0055, slice 5b2): manual files or what .env gives it, the internal
// authority, and Let's Encrypt. Every route needs settings.manage everywhere;
// starting a move also needs step-up authentication. No response carries a
// key or a credential.
package tlsmoveapi

import (
	"errors"
	"net/http"

	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/httpapi"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
	"github.com/paulmataruso/easyrmm/server/internal/tlscert"
	"github.com/paulmataruso/easyrmm/server/internal/tlsmove"
)

// API serves the routes.
type API struct {
	svc      *tlsmove.Service
	sessions *httpapi.Sessions
}

// New builds the API; sessions asks for the step-up.
func New(svc *tlsmove.Service, sessions *httpapi.Sessions) *API {
	return &API{svc: svc, sessions: sessions}
}

// Register mounts the routes.
func (a *API) Register(mux *http.ServeMux) {
	r := func(pattern string, stepUp bool, h httpapi.HandlerFunc) {
		handler := httpapi.Handle(h)
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
	r("GET /api/v1/settings/certificates/sources", false, a.sources)
	r("GET /api/v1/settings/certificates/{name}/move", false, a.progress)
	r("POST /api/v1/settings/certificates/{name}/move", true, a.start)
	r("DELETE /api/v1/settings/certificates/{name}/move", false, a.cancel)
}

func (a *API) sources(w http.ResponseWriter, r *http.Request) error {
	names, err := a.svc.Names(r.Context())
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusOK, map[string]any{"names": names})
	return nil
}

func (a *API) progress(w http.ResponseWriter, r *http.Request) error {
	p, err := a.svc.Progress(r.Context(), r.PathValue("name"))
	if err != nil {
		return mapErr(err)
	}
	httpapi.WriteJSON(w, http.StatusOK, p)
	return nil
}

func (a *API) start(w http.ResponseWriter, r *http.Request) error {
	var in struct {
		Target string `json:"target"`
	}
	if err := httpapi.DecodeJSON(w, r, &in); err != nil {
		return err
	}
	if err := a.svc.Start(r.Context(), httpapi.Actor(r), r.PathValue("name"), in.Target); err != nil {
		return mapErr(err)
	}
	httpapi.WriteJSON(w, http.StatusAccepted, map[string]string{"status": "waiting"})
	return nil
}

func (a *API) cancel(w http.ResponseWriter, r *http.Request) error {
	if err := a.svc.Cancel(r.Context(), httpapi.Actor(r), r.PathValue("name")); err != nil {
		return mapErr(err)
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func conflict(code, msg string) error {
	return &httpapi.Error{Status: http.StatusConflict, Code: code, Message: msg}
}

func mapErr(err error) error {
	var caRefused *tlscert.RefusedError
	switch {
	case errors.Is(err, tlsmove.ErrBadName), errors.Is(err, tlsmove.ErrBadSource):
		return httpapi.BadRequest(err.Error())
	case errors.Is(err, tlsmove.ErrNoMove), errors.Is(err, tlscert.ErrNoName):
		return apperr.NotFound()
	case errors.Is(err, tlsmove.ErrMoveActive):
		return conflict("move_active", "A move of this name is already waiting for its devices. Cancel it first.")
	case errors.Is(err, tlsmove.ErrSameSource):
		return conflict("same_source", "This name is served from that source already.")
	case errors.Is(err, tlsmove.ErrUnavailable):
		return conflict("unavailable", "This server cannot serve that source for the name in its current TLS mode.")
	case errors.As(err, &caRefused):
		return conflict("attempt_refused", caRefused.Error())
	case errors.Is(err, tlscert.ErrNoAccount):
		return conflict("no_account", "The ACME account is not established yet: the certificate authority could not be reached. Check the server's log.")
	case errors.Is(err, tlscert.ErrBusy):
		return conflict("busy", err.Error())
	case errors.Is(err, tlscert.ErrHeld):
		return conflict("held", err.Error())
	}
	return err
}
