// Package collectedlogsapi exposes the logs agents' collectors gathered
// (ADR-0060, slice 2) to the console: a device's events, searched by time,
// source and text, and what it logged by the hour.
package collectedlogsapi

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/httpapi"
	"github.com/paulmataruso/easyrmm/server/internal/logstore"
)

// API serves the collected-log routes.
type API struct{ svc *logstore.Service }

// New builds the API.
func New(svc *logstore.Service) *API { return &API{svc: svc} }

var errUnavailable = &httpapi.Error{Status: http.StatusServiceUnavailable, Code: "logs_unavailable",
	Message: "The log store is not available. The rest of EasyRMM works; ask an administrator to check the log database."}

// Register mounts the routes. Every route requires a fully signed-in
// session; reading needs log.view on the device, and command lines and script
// text log.view_sensitive, which the service checks.
func (a *API) Register(mux *http.ServeMux) {
	r := func(pattern string, h httpapi.HandlerFunc) {
		mux.Handle(pattern, httpapi.RequireActive(httpapi.Handle(h)))
	}
	r("GET /api/v1/devices/{id}/collected-logs", a.read)
	r("GET /api/v1/devices/{id}/collected-logs/timeline", a.timeline)
}

func query(r *http.Request) (logstore.Query, error) {
	v := r.URL.Query()
	q := logstore.Query{Text: strings.TrimSpace(v.Get("q"))}
	var err error
	if q.Limit, err = httpapi.QueryCount(r, "limit", logstore.DefaultLimit, 1, logstore.MaxLimit); err != nil {
		return q, err
	}
	if s := v.Get("source"); s != "" {
		q.Sources = strings.Split(s, ",")
	}
	for name, dst := range map[string]*time.Time{"since": &q.Since, "until": &q.Until} {
		if s := v.Get(name); s != "" {
			t, err := time.Parse(time.RFC3339, s)
			if err != nil {
				return q, apperr.Invalid(name, "must be a time such as 2026-11-27T10:00:00Z")
			}
			*dst = t
		}
	}
	return q, nil
}

func mapErr(err error) error {
	if errors.Is(err, logstore.ErrUnavailable) {
		return errUnavailable
	}
	return err
}

func (a *API) read(w http.ResponseWriter, r *http.Request) error {
	id, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	q, err := query(r)
	if err != nil {
		return err
	}
	res, err := a.svc.Read(r.Context(), httpapi.Caller(r), id, q)
	if err != nil {
		return mapErr(err)
	}
	w.Header().Set("Cache-Control", "no-store")
	httpapi.WriteJSON(w, http.StatusOK, res)
	return nil
}

func (a *API) timeline(w http.ResponseWriter, r *http.Request) error {
	id, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	q, err := query(r)
	if err != nil {
		return err
	}
	t, err := a.svc.Timeline(r.Context(), httpapi.Caller(r), id, q)
	if err != nil {
		return mapErr(err)
	}
	w.Header().Set("Cache-Control", "no-store")
	httpapi.WriteJSON(w, http.StatusOK, t)
	return nil
}
