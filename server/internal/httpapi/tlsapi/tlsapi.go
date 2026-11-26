// Package tlsapi exposes the Certificates page (ADR-0055): Settings →
// Certificates. Every route needs settings.manage everywhere. No response
// carries a key or a credential.
package tlsapi

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/httpapi"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
	"github.com/paulmataruso/easyrmm/server/internal/tlscert"
)

// API serves the certificate routes. Service is nil unless the server obtains
// its certificates itself (acme mode); Mode says where they come from.
type API struct {
	svc  *tlscert.Service
	mode string
}

// New builds the API.
func New(svc *tlscert.Service, mode string) *API { return &API{svc: svc, mode: mode} }

// Register mounts the routes.
func (a *API) Register(mux *http.ServeMux) {
	r := func(pattern string, h httpapi.HandlerFunc) {
		mux.Handle(pattern, httpapi.RequireActive(httpapi.Handle(func(w http.ResponseWriter, r *http.Request) error {
			if !httpapi.Can(r, rbac.PermSettingsManage, rbac.Resource{}) {
				return apperr.Forbidden()
			}
			return h(w, r)
		})))
	}
	r("GET /api/v1/settings/certificates", a.get)
	r("POST /api/v1/settings/certificates/{name}/retry", a.act(a.retry))
	r("POST /api/v1/settings/certificates/{name}/order-anyway", a.act(a.orderAnyway))
	r("POST /api/v1/settings/certificates/{name}/check", a.check)
}

// response is the page's data: where the certificates come from, and, in acme
// mode, each name's state.
type response struct {
	Mode    string          `json:"mode"`
	Managed bool            `json:"managed"`
	Status  *tlscert.Status `json:"status,omitempty"`
}

func (a *API) get(w http.ResponseWriter, r *http.Request) error {
	out := response{Mode: a.mode, Managed: a.svc != nil}
	if a.svc != nil {
		st, err := a.svc.Status(r.Context())
		if err != nil {
			return err
		}
		out.Status = &st
	}
	httpapi.WriteJSON(w, http.StatusOK, out)
	return nil
}

func (a *API) act(f func(ctx context.Context, r *http.Request, name string) error) httpapi.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) error {
		if a.svc == nil {
			return apperr.NotFound()
		}
		if err := f(r.Context(), r, r.PathValue("name")); err != nil {
			return mapErr(err)
		}
		httpapi.WriteJSON(w, http.StatusAccepted, map[string]string{"status": "started"})
		return nil
	}
}

func (a *API) retry(ctx context.Context, r *http.Request, name string) error {
	return a.svc.RetryNow(ctx, httpapi.Actor(r), name)
}

func (a *API) orderAnyway(ctx context.Context, r *http.Request, name string) error {
	return a.svc.OrderAnyway(ctx, httpapi.Actor(r), name)
}

func (a *API) check(w http.ResponseWriter, r *http.Request) error {
	if a.svc == nil {
		return apperr.NotFound()
	}
	res, err := a.svc.Check(r.Context(), r.PathValue("name"))
	if err != nil {
		return mapErr(err)
	}
	httpapi.WriteJSON(w, http.StatusOK, map[string]any{"checks": res})
	return nil
}

func mapErr(err error) error {
	var refused *tlscert.RefusedError
	var soon *tlscert.ErrTooSoon
	switch {
	case errors.Is(err, tlscert.ErrNoName):
		return apperr.NotFound()
	case errors.As(err, &refused):
		e := &httpapi.Error{Status: http.StatusConflict, Code: "attempt_refused", Message: err.Error()}
		if !refused.RetryAt.IsZero() {
			e.Fields = map[string]string{"retryAt": refused.RetryAt.UTC().Format(time.RFC3339)}
		}
		return e
	case errors.Is(err, tlscert.ErrHeld):
		return &httpapi.Error{Status: http.StatusConflict, Code: "held", Message: err.Error()}
	case errors.Is(err, tlscert.ErrBusy):
		return &httpapi.Error{Status: http.StatusConflict, Code: "busy", Message: err.Error()}
	case errors.Is(err, tlscert.ErrNoAccount):
		return &httpapi.Error{Status: http.StatusConflict, Code: "no_account", Message: "The ACME account is not established yet: the certificate authority could not be reached. Check the server's log."}
	case errors.As(err, &soon):
		return &httpapi.Error{Status: http.StatusTooManyRequests, Code: "check_rate_limited", Message: err.Error(), RetryAfter: soon.RetryAfter}
	}
	return err
}
