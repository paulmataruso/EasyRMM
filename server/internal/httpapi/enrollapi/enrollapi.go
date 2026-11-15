// Package enrollapi exposes deployment tokens and the agent downloads to the
// console.
package enrollapi

import (
	"net/http"
	"strings"

	"github.com/paulmataruso/easyrmm/server/internal/agents"
	"github.com/paulmataruso/easyrmm/server/internal/httpapi"
)

// API serves the enrollment routes.
type API struct {
	svc    *agents.Service
	builds *agents.Builds
	server string
}

// New builds the API. server is the public URL agents enroll with.
func New(svc *agents.Service, builds *agents.Builds, server string) *API {
	return &API{svc: svc, builds: builds, server: strings.TrimSuffix(server, "/")}
}

// Register mounts the routes. Every route requires a fully signed-in session.
func (a *API) Register(mux *http.ServeMux) {
	r := func(pattern string, h httpapi.HandlerFunc) {
		mux.Handle(pattern, httpapi.RequireActive(httpapi.Handle(h)))
	}
	r("GET /api/v1/enrollment-tokens", a.list)
	r("POST /api/v1/sites/{id}/enrollment-tokens", a.create)
	r("GET /api/v1/enrollment-tokens/{id}", a.get)
	r("POST /api/v1/enrollment-tokens/{id}/revoke", a.revoke)
	r("GET /api/v1/agent-downloads", a.downloads)
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
	items, err := a.svc.ListTokens(r.Context(), httpapi.Caller(r), agents.TokenQuery{
		OrganizationID: org, SiteID: site, Active: r.URL.Query().Get("status") == "active",
	})
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusOK, httpapi.List[*agents.Token]{Items: items})
	return nil
}

// created is a new token with what the console needs to show install
// commands. The secret is in no other response.
type created struct {
	*agents.NewToken
	ServerURL string `json:"serverUrl"`
}

func (a *API) create(w http.ResponseWriter, r *http.Request) error {
	site, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	var in agents.TokenInput
	if err := httpapi.DecodeJSON(w, r, &in); err != nil {
		return err
	}
	t, err := a.svc.CreateToken(r.Context(), httpapi.Caller(r), site, in)
	if err != nil {
		return err
	}
	w.Header().Set("Cache-Control", "no-store")
	httpapi.WriteJSON(w, http.StatusCreated, created{NewToken: t, ServerURL: a.server})
	return nil
}

func (a *API) get(w http.ResponseWriter, r *http.Request) error {
	id, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	t, err := a.svc.GetToken(r.Context(), httpapi.Caller(r), id)
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusOK, t)
	return nil
}

func (a *API) revoke(w http.ResponseWriter, r *http.Request) error {
	id, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	t, err := a.svc.RevokeToken(r.Context(), httpapi.Caller(r), id)
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusOK, t)
	return nil
}

type downloads struct {
	ServerURL string         `json:"serverUrl"`
	Items     []agents.Build `json:"items"`
}

func (a *API) downloads(w http.ResponseWriter, _ *http.Request) error {
	httpapi.WriteJSON(w, http.StatusOK, downloads{ServerURL: a.server, Items: a.builds.List()})
	return nil
}
