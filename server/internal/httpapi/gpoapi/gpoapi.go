// Package gpoapi serves what the Group Policy module keeps of its own (ADR-0083): the automatic backups, the requests for
// a second person's approval, the organization's approval setting and its card. The reads and the changes themselves go
// through the winmod routes; the service checks each permission and answers 404 for anything the caller may not see.
package gpoapi

import (
	"net/http"
	"strconv"

	"github.com/google/uuid"

	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/httpapi"
	"github.com/paulmataruso/easyrmm/server/internal/winmod/grouppolicy"
)

// API serves the routes.
type API struct{ svc *grouppolicy.Service }

// New builds the API.
func New(s *grouppolicy.Service) *API { return &API{svc: s} }

// Register mounts the routes.
func (a *API) Register(mux *http.ServeMux) {
	r := func(pattern string, h httpapi.HandlerFunc) {
		mux.Handle(pattern, httpapi.RequireActive(httpapi.Handle(h)))
	}
	r("GET /api/v1/organizations/{id}/gpo/summary", a.summary)
	r("GET /api/v1/organizations/{id}/gpo/settings", a.getSettings)
	r("PUT /api/v1/organizations/{id}/gpo/settings", a.putSettings)
	r("GET /api/v1/organizations/{id}/gpo/requests", a.requests)
	r("POST /api/v1/devices/{id}/gpo/requests", a.submit)
	r("POST /api/v1/gpo/requests/{id}/approve", a.approve)
	r("POST /api/v1/gpo/requests/{id}/reject", a.reject)
	r("GET /api/v1/devices/{id}/gpo/backups", a.backups)
	r("GET /api/v1/devices/{id}/gpo/backups/{backupId}/chunks/{index}", a.chunk)
	r("GET /api/v1/devices/{id}/gpo/backups/{backupId}/download", a.download)
}

func (a *API) summary(w http.ResponseWriter, r *http.Request) error {
	id, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	out, err := a.svc.Summary(r.Context(), httpapi.Caller(r), id)
	if err != nil {
		return err
	}
	w.Header().Set("Cache-Control", "no-store")
	httpapi.WriteJSON(w, http.StatusOK, out)
	return nil
}

func (a *API) getSettings(w http.ResponseWriter, r *http.Request) error {
	id, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	out, err := a.svc.GetSettings(r.Context(), httpapi.Caller(r), id)
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusOK, out)
	return nil
}

func (a *API) putSettings(w http.ResponseWriter, r *http.Request) error {
	id, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	var in grouppolicy.Settings
	if err := httpapi.DecodeJSON(w, r, &in); err != nil {
		return err
	}
	if err := a.svc.SetSettings(r.Context(), httpapi.Caller(r), id, in); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func (a *API) requests(w http.ResponseWriter, r *http.Request) error {
	id, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	out, err := a.svc.ListRequests(r.Context(), httpapi.Caller(r), id)
	if err != nil {
		return err
	}
	w.Header().Set("Cache-Control", "no-store")
	httpapi.WriteJSON(w, http.StatusOK, out)
	return nil
}

func (a *API) submit(w http.ResponseWriter, r *http.Request) error {
	id, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	var in grouppolicy.NewRequest
	if err := httpapi.DecodeJSON(w, r, &in); err != nil {
		return err
	}
	out, err := a.svc.Submit(r.Context(), httpapi.Caller(r), id, in)
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusCreated, out)
	return nil
}

type decision struct {
	Reason string `json:"reason"`
}

func (a *API) approve(w http.ResponseWriter, r *http.Request) error {
	id, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	var in decision
	if err := httpapi.DecodeJSON(w, r, &in); err != nil {
		return err
	}
	run, err := a.svc.Approve(r.Context(), httpapi.Caller(r), id, in.Reason)
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusAccepted, run)
	return nil
}

func (a *API) reject(w http.ResponseWriter, r *http.Request) error {
	id, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	var in decision
	if err := httpapi.DecodeJSON(w, r, &in); err != nil {
		return err
	}
	if err := a.svc.Reject(r.Context(), httpapi.Caller(r), id, in.Reason); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func (a *API) backups(w http.ResponseWriter, r *http.Request) error {
	id, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	var gpo *uuid.UUID
	if q := r.URL.Query().Get("gpoId"); q != "" {
		g, err := uuid.Parse(q)
		if err != nil {
			return apperr.Invalid("gpoId", "This is not a GPO identifier.")
		}
		gpo = &g
	}
	out, err := a.svc.ListBackups(r.Context(), httpapi.Caller(r), id, gpo)
	if err != nil {
		return err
	}
	w.Header().Set("Cache-Control", "no-store")
	httpapi.WriteJSON(w, http.StatusOK, out)
	return nil
}

func (a *API) chunk(w http.ResponseWriter, r *http.Request) error {
	id, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	bid, err := uuid.Parse(r.PathValue("backupId"))
	if err != nil {
		return apperr.NotFound()
	}
	n, err := strconv.Atoi(r.PathValue("index"))
	if err != nil {
		return apperr.NotFound()
	}
	out, err := a.svc.BackupChunk(r.Context(), httpapi.Caller(r), id, bid, n)
	if err != nil {
		return err
	}
	w.Header().Set("Cache-Control", "no-store")
	httpapi.WriteJSON(w, http.StatusOK, out)
	return nil
}

func (a *API) download(w http.ResponseWriter, r *http.Request) error {
	id, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	bid, err := uuid.Parse(r.PathValue("backupId"))
	if err != nil {
		return apperr.NotFound()
	}
	raw, _, err := a.svc.DownloadBackup(r.Context(), httpapi.Caller(r), id, bid)
	if err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", `attachment; filename="gpo-backup-`+bid.String()+`.zip"`)
	w.Header().Set("Cache-Control", "no-store")
	_, err = w.Write(raw) //nolint:gosec // G705: a zip sent as an attachment with a fixed type, never rendered as HTML
	return err
}
