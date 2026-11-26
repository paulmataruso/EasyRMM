// Package keystoreapi exposes the keystore's state, the per-volume escrow state
// of a device and, from slice 2, the one route that returns a key (ADR-0081).
package keystoreapi

import (
	"errors"
	"net/http"

	"github.com/google/uuid"

	"github.com/paulmataruso/easyrmm/server/internal/httpapi"
	"github.com/paulmataruso/easyrmm/server/internal/keystore"
)

// API serves the routes.
type API struct{ svc *keystore.Service }

// New builds the API.
func New(svc *keystore.Service) *API { return &API{svc: svc} }

// Register mounts the routes. Every route requires a fully signed-in session.
func (a *API) Register(mux *http.ServeMux) {
	r := func(pattern string, h httpapi.HandlerFunc) {
		mux.Handle(pattern, httpapi.RequireActive(httpapi.Handle(h)))
	}
	r("GET /api/v1/devices/{id}/escrow", a.device)
	r("GET /api/v1/keystore", a.status)
	r("POST /api/v1/devices/{id}/escrow/read", a.read)
	r("GET /api/v1/keystore/requests", a.requests)
	r("POST /api/v1/keystore/requests/{id}/approve", a.decide(true))
	r("POST /api/v1/keystore/requests/{id}/deny", a.decide(false))
	r("GET /api/v1/keystore/notices", a.notices)
	r("GET /api/v1/keystore/alerts", a.alerts)
	r("POST /api/v1/keystore/alerts/{id}/resolve", a.resolveAlert)
	r("GET /api/v1/organizations/{id}/keystore-settings", a.settings)
	r("PUT /api/v1/organizations/{id}/keystore-settings", a.setSettings)
}

type readBody struct {
	Volume    string    `json:"volume"`
	Protector string    `json:"protector"`
	Reason    string    `json:"reason"`
	Ticket    string    `json:"ticket"`
	RequestID uuid.UUID `json:"requestId"`
}

// read releases a key. The key is written by hand into a buffer that is
// zeroed afterward and never goes through a JSON encoder, a logger or an
// error; the answer is never cached.
func (a *API) read(w http.ResponseWriter, r *http.Request) error {
	id, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	var b readBody
	if err := httpapi.DecodeJSON(w, r, &b); err != nil {
		return err
	}
	res, err := a.svc.Read(r.Context(), httpapi.Caller(r), id, keystore.ReadInput{
		Volume: b.Volume, Protector: b.Protector, Reason: b.Reason, Ticket: b.Ticket, RequestID: b.RequestID,
	})
	if err != nil {
		return err
	}
	defer res.Wipe()
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	if res.Pending != nil {
		httpapi.WriteJSON(w, http.StatusAccepted, map[string]any{"pending": res.Pending})
		return nil
	}
	for _, c := range res.Key {
		if (c < '0' || c > '9') && c != '-' {
			return errors.New("keystoreapi: the key is not in the form the console shows") // never says what it was
		}
	}
	out := make([]byte, 0, len(res.Key)+16)
	defer func() { clear(out[:cap(out)]) }()
	out = append(out, `{"key":"`...)
	out = append(out, res.Key...)
	out = append(out, `"}`...)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(out) //nolint:gosec // digits and dashes only, checked above, in a JSON response
	return nil
}

func (a *API) requests(w http.ResponseWriter, r *http.Request) error {
	out, err := a.svc.Requests(r.Context(), httpapi.Caller(r))
	if err != nil {
		return err
	}
	w.Header().Set("Cache-Control", "no-store")
	httpapi.WriteJSON(w, http.StatusOK, map[string]any{"requests": out})
	return nil
}

func (a *API) decide(approve bool) httpapi.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) error {
		id, err := httpapi.PathID(r)
		if err != nil {
			return err
		}
		out, err := a.svc.Decide(r.Context(), httpapi.Caller(r), id, approve)
		if err != nil {
			return err
		}
		w.Header().Set("Cache-Control", "no-store")
		httpapi.WriteJSON(w, http.StatusOK, out)
		return nil
	}
}

func (a *API) notices(w http.ResponseWriter, r *http.Request) error {
	out, err := a.svc.Notices(r.Context(), httpapi.Caller(r))
	if err != nil {
		return err
	}
	w.Header().Set("Cache-Control", "no-store")
	httpapi.WriteJSON(w, http.StatusOK, map[string]any{"notices": out})
	return nil
}

func (a *API) alerts(w http.ResponseWriter, r *http.Request) error {
	out, err := a.svc.Alerts(r.Context(), httpapi.Caller(r))
	if err != nil {
		return err
	}
	w.Header().Set("Cache-Control", "no-store")
	httpapi.WriteJSON(w, http.StatusOK, map[string]any{"alerts": out})
	return nil
}

func (a *API) resolveAlert(w http.ResponseWriter, r *http.Request) error {
	id, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	if err := a.svc.ResolveAlert(r.Context(), httpapi.Caller(r), id); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func (a *API) settings(w http.ResponseWriter, r *http.Request) error {
	id, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	out, err := a.svc.SettingsOf(r.Context(), httpapi.Caller(r), id)
	if err != nil {
		return err
	}
	w.Header().Set("Cache-Control", "no-store")
	httpapi.WriteJSON(w, http.StatusOK, out)
	return nil
}

func (a *API) setSettings(w http.ResponseWriter, r *http.Request) error {
	id, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	var b struct {
		TwoPerson bool `json:"twoPerson"`
	}
	if err := httpapi.DecodeJSON(w, r, &b); err != nil {
		return err
	}
	out, err := a.svc.SetTwoPerson(r.Context(), httpapi.Caller(r), id, b.TwoPerson)
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusOK, out)
	return nil
}

func (a *API) device(w http.ResponseWriter, r *http.Request) error {
	id, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	out, err := a.svc.DeviceState(r.Context(), httpapi.Caller(r), id)
	if err != nil {
		return err
	}
	w.Header().Set("Cache-Control", "no-store")
	httpapi.WriteJSON(w, http.StatusOK, out)
	return nil
}

func (a *API) status(w http.ResponseWriter, r *http.Request) error {
	st, err := a.svc.Platform(r.Context(), httpapi.Caller(r))
	if err != nil {
		return err
	}
	w.Header().Set("Cache-Control", "no-store")
	httpapi.WriteJSON(w, http.StatusOK, st)
	return nil
}
