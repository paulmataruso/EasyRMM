// Package agentlogsapi exposes devices' agent logs to the console
// (ADR-0069, Part L).
package agentlogsapi

import (
	"net/http"
	"strings"
	"time"

	"github.com/paulmataruso/easyrmm/server/internal/agentlogs"
	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/httpapi"
)

// API serves the agent log routes.
type API struct {
	svc *agentlogs.Service
}

// New builds the API.
func New(svc *agentlogs.Service) *API { return &API{svc: svc} }

// Register mounts the routes. Every route requires a fully signed-in
// session; reading needs log.view, verbose mode device.edit.
func (a *API) Register(mux *http.ServeMux) {
	r := func(pattern string, h httpapi.HandlerFunc) {
		mux.Handle(pattern, httpapi.RequireActive(httpapi.Handle(h)))
	}
	r("GET /api/v1/devices/{id}/agent-logs", a.read)
	r("GET /api/v1/devices/{id}/agent-logs/download", a.download)
	r("PUT /api/v1/devices/{id}/agent-logs/verbose", a.setDevice)
	r("DELETE /api/v1/devices/{id}/agent-logs/verbose", a.clearDevice)
	r("PUT /api/v1/device-groups/{id}/agent-logs/verbose", a.setGroup)
	r("DELETE /api/v1/device-groups/{id}/agent-logs/verbose", a.clearGroup)
}

// query reads the filters from the request.
func query(r *http.Request) (agentlogs.Query, error) {
	q := agentlogs.Query{Level: r.URL.Query().Get("level"), Text: strings.TrimSpace(r.URL.Query().Get("q"))}
	var err error
	if q.After, err = httpapi.QueryInt(r, "after", 0, 0, 1<<62); err != nil {
		return q, err
	}
	if q.Before, err = httpapi.QueryInt(r, "before", 0, 0, 1<<62); err != nil {
		return q, err
	}
	if q.Limit, err = httpapi.QueryCount(r, "limit", 200, 1, agentlogs.MaxPage); err != nil {
		return q, err
	}
	if v := r.URL.Query().Get("source"); v != "" {
		q.Sources = strings.Split(v, ",")
	}
	for name, dst := range map[string]*time.Time{"since": &q.Since, "until": &q.Until} {
		if v := r.URL.Query().Get(name); v != "" {
			t, err := time.Parse(time.RFC3339, v)
			if err != nil {
				return q, apperr.Invalid(name, "must be a time such as 2026-11-23T10:00:00Z")
			}
			*dst = t
		}
	}
	return q, nil
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
	page, err := a.svc.Read(r.Context(), httpapi.Caller(r), id, q, r.URL.Query().Get("follow") == "true")
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusOK, page)
	return nil
}

func (a *API) download(w http.ResponseWriter, r *http.Request) error {
	id, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	q, err := query(r)
	if err != nil {
		return err
	}
	format, ext, ctype := agentlogs.Text, "log", "text/plain; charset=utf-8"
	if r.URL.Query().Get("format") == "jsonl" {
		format, ext, ctype = agentlogs.JSONL, "jsonl", "application/x-ndjson"
	} else if f := r.URL.Query().Get("format"); f != "" && f != "text" {
		return apperr.Invalid("format", "must be text or jsonl")
	}
	// The headers go out with the first line, and the status is 200 from
	// then on: a failure in the middle ends the file.
	w.Header().Set("Content-Type", ctype)
	w.Header().Set("Content-Disposition", `attachment; filename="agent-logs-`+id.String()[:8]+`.`+ext+`"`)
	w.Header().Set("Cache-Control", "no-store")
	_, err = a.svc.Download(r.Context(), httpapi.Caller(r), id, q, format, w)
	if err != nil {
		w.Header().Del("Content-Disposition")
		w.Header().Set("Content-Type", "application/json")
	}
	return err
}

// verboseBody is what turning verbose mode on takes.
type verboseBody struct {
	Hours int `json:"hours"`
}

func (a *API) setDevice(w http.ResponseWriter, r *http.Request) error {
	id, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	var in verboseBody
	if err := httpapi.DecodeJSON(w, r, &in); err != nil {
		return err
	}
	until, err := a.svc.SetDeviceVerbose(r.Context(), httpapi.Caller(r), id, in.Hours)
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusOK, map[string]time.Time{"until": until})
	return nil
}

func (a *API) clearDevice(w http.ResponseWriter, r *http.Request) error {
	id, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	if err := a.svc.ClearDeviceVerbose(r.Context(), httpapi.Caller(r), id); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func (a *API) setGroup(w http.ResponseWriter, r *http.Request) error {
	id, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	var in verboseBody
	if err := httpapi.DecodeJSON(w, r, &in); err != nil {
		return err
	}
	until, err := a.svc.SetGroupVerbose(r.Context(), httpapi.Caller(r), id, in.Hours)
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusOK, map[string]time.Time{"until": until})
	return nil
}

func (a *API) clearGroup(w http.ResponseWriter, r *http.Request) error {
	id, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	if err := a.svc.ClearGroupVerbose(r.Context(), httpapi.Caller(r), id); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}
