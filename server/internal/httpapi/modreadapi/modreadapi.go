// Package modreadapi serves a Windows management module's last result to the
// console (ADR-0073 section 5, as amended): what a tab shows when it opens,
// with its age, and a fresh read started by itself when that result is old.
package modreadapi

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/paulmataruso/easyrmm/server/internal/httpapi"
	"github.com/paulmataruso/easyrmm/server/internal/modsnap"
)

// minAge is the youngest result a tab may ask for.
const minAge = 5 * time.Second

// API serves the route.
type API struct {
	svc *modsnap.Service
}

// New builds the API.
func New(svc *modsnap.Service) *API { return &API{svc: svc} }

// Register mounts the route. It requires a fully signed-in session; the
// service checks the module's permission, the toggle and the development
// scope, and answers 404 for anything the caller may not see.
func (a *API) Register(mux *http.ServeMux) {
	mux.Handle("POST /api/v1/devices/{id}/winmod-read/{action}", httpapi.RequireActive(httpapi.Handle(a.read)))
}

// read answers with the stored result and its age at once. When the result
// is older than modsnap.AutoReadAge or missing and the computer is online, it
// starts one read (never two for the same action and parameters) and names
// its run, which the console follows with GET /winmod/runs/{id}.
func (a *API) read(w http.ResponseWriter, r *http.Request) error {
	id, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	var in struct {
		Params json.RawMessage `json:"params"`
		// MaxAgeSeconds asks for a younger result than the default two
		// minutes, from 5 seconds up (a running operation's progress).
		MaxAgeSeconds int `json:"maxAgeSeconds"`
	}
	if err := httpapi.DecodeJSON(w, r, &in); err != nil {
		return err
	}
	maxAge := modsnap.AutoReadAge
	if in.MaxAgeSeconds > 0 {
		maxAge = min(max(time.Duration(in.MaxAgeSeconds)*time.Second, minAge), modsnap.AutoReadAge)
	}
	snap, err := a.svc.GetWithin(r.Context(), httpapi.Caller(r), id, r.PathValue("action"), in.Params, maxAge)
	if err != nil {
		return err
	}
	w.Header().Set("Cache-Control", "no-store")
	httpapi.WriteJSON(w, http.StatusOK, snap)
	return nil
}
