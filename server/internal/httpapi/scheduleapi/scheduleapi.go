// Package scheduleapi exposes scheduled tasks to the console (feature 11).
// Saving a task (create, edit, resume) needs a stepped-up session.
package scheduleapi

import (
	"context"
	"net/http"

	"github.com/google/uuid"

	"github.com/paulmataruso/easyrmm/server/internal/access"
	"github.com/paulmataruso/easyrmm/server/internal/httpapi"
	"github.com/paulmataruso/easyrmm/server/internal/schedule"
)

// StepUp is what the API asks of the session: nil when it was stepped up
// within the window (httpapi.Sessions).
type StepUp interface {
	StepUp(r *http.Request) error
}

// API serves the scheduled-task routes.
type API struct {
	svc    *schedule.Service
	stepUp StepUp
}

// New builds the API.
func New(svc *schedule.Service, stepUp StepUp) *API { return &API{svc: svc, stepUp: stepUp} }

// Register mounts the routes. Every route requires a fully signed-in session.
func (a *API) Register(mux *http.ServeMux) {
	r := func(pattern string, h httpapi.HandlerFunc) {
		mux.Handle(pattern, httpapi.RequireActive(httpapi.Handle(h)))
	}
	saved := func(h httpapi.HandlerFunc) httpapi.HandlerFunc {
		return func(w http.ResponseWriter, req *http.Request) error {
			if err := a.stepUp.StepUp(req); err != nil {
				return err
			}
			return h(w, req)
		}
	}
	r("GET /api/v1/scheduled-tasks", a.list)
	r("POST /api/v1/scheduled-tasks", saved(a.create))
	r("GET /api/v1/scheduled-tasks/upcoming", a.upcoming)
	r("GET /api/v1/scheduled-tasks/{id}", a.get)
	r("PATCH /api/v1/scheduled-tasks/{id}", saved(a.update))
	r("GET /api/v1/scheduled-tasks/{id}/runs", a.history)
	r("POST /api/v1/scheduled-tasks/{id}/pause", a.change(a.svc.Pause))
	r("POST /api/v1/scheduled-tasks/{id}/resume", saved(a.change(a.svc.Resume)))
	r("POST /api/v1/scheduled-tasks/{id}/cancel", a.change(a.svc.Cancel))
}

func (a *API) list(w http.ResponseWriter, r *http.Request) error {
	org, err := httpapi.QueryID(r, "organizationId")
	if err != nil {
		return err
	}
	site, err := httpapi.QueryID(r, "siteId")
	if err != nil {
		return err
	}
	items, err := a.svc.List(r.Context(), httpapi.Caller(r), schedule.Query{OrganizationID: org, SiteID: site, State: r.URL.Query().Get("state")})
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusOK, httpapi.List[*schedule.Task]{Items: items})
	return nil
}

func (a *API) upcoming(w http.ResponseWriter, r *http.Request) error {
	n, err := httpapi.QueryCount(r, "limit", 50, 1, 200)
	if err != nil {
		return err
	}
	items, err := a.svc.Upcoming(r.Context(), httpapi.Caller(r), n)
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusOK, httpapi.List[*schedule.Task]{Items: items})
	return nil
}

func (a *API) create(w http.ResponseWriter, r *http.Request) error {
	var in schedule.Input
	if err := httpapi.DecodeJSON(w, r, &in); err != nil {
		return err
	}
	t, err := a.svc.Create(r.Context(), httpapi.Caller(r), in)
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusCreated, t)
	return nil
}

func (a *API) get(w http.ResponseWriter, r *http.Request) error {
	id, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	t, err := a.svc.Get(r.Context(), httpapi.Caller(r), id)
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusOK, t)
	return nil
}

func (a *API) update(w http.ResponseWriter, r *http.Request) error {
	id, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	var p schedule.Patch
	if err := httpapi.DecodeJSON(w, r, &p); err != nil {
		return err
	}
	t, err := a.svc.Update(r.Context(), httpapi.Caller(r), id, p)
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusOK, t)
	return nil
}

func (a *API) history(w http.ResponseWriter, r *http.Request) error {
	id, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	n, err := httpapi.QueryCount(r, "limit", 100, 1, 500)
	if err != nil {
		return err
	}
	items, err := a.svc.History(r.Context(), httpapi.Caller(r), id, n)
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusOK, httpapi.List[*schedule.Run]{Items: items})
	return nil
}

// change serves pause, resume and cancel.
func (a *API) change(fn func(ctx context.Context, c access.Caller, id uuid.UUID) (*schedule.Task, error)) httpapi.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) error {
		id, err := httpapi.PathID(r)
		if err != nil {
			return err
		}
		t, err := fn(r.Context(), httpapi.Caller(r), id)
		if err != nil {
			return err
		}
		httpapi.WriteJSON(w, http.StatusOK, t)
		return nil
	}
}
