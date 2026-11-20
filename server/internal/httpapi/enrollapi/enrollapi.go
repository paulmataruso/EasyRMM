// Package enrollapi exposes deployment tokens and the agent downloads to the
// console.
package enrollapi

import (
	"net/http"
	"strings"

	"github.com/google/uuid"

	"github.com/paulmataruso/easyrmm/server/internal/agents"
	"github.com/paulmataruso/easyrmm/server/internal/httpapi"
)

// API serves the enrollment routes.
type API struct {
	svc       *agents.Service
	builds    *agents.Builds
	server    string
	addresses []Address
	ca        *Authority
}

// Address is a server address agents can be installed through (ADR-0016).
type Address struct {
	// URL is the console origin: the public URL, or an IP address.
	URL string `json:"url"`
	// Pin is the public-key pin of the address's certificate when it comes
	// from the server's own certificate authority, for curl --pinnedpubkey.
	Pin string `json:"pin,omitempty"`
	// KeyPin is the same key's pin for the Windows PowerShell command: the
	// hex SHA-256 of the public key.
	KeyPin string `json:"keyPin,omitempty"`
}

// Authority describes the server's own certificate authority.
type Authority struct {
	// Fingerprint is the SHA-256 fingerprint browsers show (AB:CD:...).
	Fingerprint string `json:"fingerprint"`
	// URL is the path its certificate downloads from, in PEM.
	URL string `json:"url"`
	// CertURL is the same certificate in DER, a .crt file Windows and macOS
	// install with a double click.
	CertURL string `json:"certUrl"`
}

// New builds the API. server is the public URL agents enroll with;
// addresses are every address the server answers on, the public URL first;
// ca is nil when no address uses the internal certificate authority.
func New(svc *agents.Service, builds *agents.Builds, server string, addresses []Address, ca *Authority) *API {
	if addresses == nil {
		addresses = []Address{{URL: strings.TrimSuffix(server, "/")}}
	}
	return &API{svc: svc, builds: builds, server: strings.TrimSuffix(server, "/"), addresses: addresses, ca: ca}
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
	r("POST /api/v1/enrollment-tokens/{id}/reveal", a.reveal)
	r("GET /api/v1/agent-downloads", a.downloads)
	// Enrollment with approval (ADR-0024).
	r("GET /api/v1/approval-tokens", a.listApproval)
	r("POST /api/v1/approval-tokens", a.createApproval)
	r("POST /api/v1/approval-tokens/{id}/revoke", a.revokeApproval)
	r("POST /api/v1/approval-tokens/{id}/reveal", a.revealApproval)
	r("GET /api/v1/enrollment-requests", a.listRequests)
	r("GET /api/v1/enrollment-requests/waiting", a.waiting)
	r("POST /api/v1/enrollment-requests/approve", a.approve)
	r("POST /api/v1/enrollment-requests/reject", a.reject)
}

func (a *API) listApproval(w http.ResponseWriter, r *http.Request) error {
	items, err := a.svc.ListApprovalTokens(r.Context(), httpapi.Caller(r), r.URL.Query().Get("status") == "active")
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusOK, httpapi.List[*agents.ApprovalToken]{Items: items})
	return nil
}

// createdApproval is an approval token with its secret and what the console
// needs to show install commands: when it is created, and when it is shown
// again.
type createdApproval struct {
	*agents.NewApprovalToken
	ServerURL string `json:"serverUrl"`
}

func (a *API) createApproval(w http.ResponseWriter, r *http.Request) error {
	var in agents.ApprovalTokenInput
	if err := httpapi.DecodeJSON(w, r, &in); err != nil {
		return err
	}
	t, err := a.svc.CreateApprovalToken(r.Context(), httpapi.Caller(r), in)
	if err != nil {
		return err
	}
	w.Header().Set("Cache-Control", "no-store")
	httpapi.WriteJSON(w, http.StatusCreated, createdApproval{NewApprovalToken: t, ServerURL: a.server})
	return nil
}

func (a *API) revealApproval(w http.ResponseWriter, r *http.Request) error {
	id, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	t, err := a.svc.RevealApprovalToken(r.Context(), httpapi.Caller(r), id)
	if err != nil {
		return err
	}
	w.Header().Set("Cache-Control", "no-store")
	httpapi.WriteJSON(w, http.StatusOK, createdApproval{NewApprovalToken: t, ServerURL: a.server})
	return nil
}

func (a *API) revokeApproval(w http.ResponseWriter, r *http.Request) error {
	id, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	t, err := a.svc.RevokeApprovalToken(r.Context(), httpapi.Caller(r), id)
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusOK, t)
	return nil
}

func (a *API) listRequests(w http.ResponseWriter, r *http.Request) error {
	state := r.URL.Query().Get("state")
	if state == "" {
		state = "pending"
	}
	list, err := a.svc.ListRequests(r.Context(), httpapi.Caller(r), state)
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusOK, list)
	return nil
}

// waiting is how many devices wait for approval, for the menu; 0 for
// callers who cannot approve them.
func (a *API) waiting(w http.ResponseWriter, r *http.Request) error {
	n, err := a.svc.Waiting(r.Context(), httpapi.Caller(r))
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusOK, map[string]int{"waiting": n})
	return nil
}

func (a *API) approve(w http.ResponseWriter, r *http.Request) error {
	var in agents.ApproveInput
	if err := httpapi.DecodeJSON(w, r, &in); err != nil {
		return err
	}
	d, err := a.svc.Approve(r.Context(), httpapi.Caller(r), in)
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusOK, d)
	return nil
}

func (a *API) reject(w http.ResponseWriter, r *http.Request) error {
	var in struct {
		IDs []uuid.UUID `json:"ids"`
	}
	if err := httpapi.DecodeJSON(w, r, &in); err != nil {
		return err
	}
	d, err := a.svc.Reject(r.Context(), httpapi.Caller(r), in.IDs)
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusOK, d)
	return nil
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

// created is a token with its secret and what the console needs to show
// install commands: when it is created, and when it is shown again.
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

func (a *API) reveal(w http.ResponseWriter, r *http.Request) error {
	id, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	t, err := a.svc.RevealToken(r.Context(), httpapi.Caller(r), id)
	if err != nil {
		return err
	}
	w.Header().Set("Cache-Control", "no-store")
	httpapi.WriteJSON(w, http.StatusOK, created{NewToken: t, ServerURL: a.server})
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
	Addresses []Address      `json:"addresses"`
	// Current is the address this request came to.
	Current              string     `json:"current"`
	CertificateAuthority *Authority `json:"certificateAuthority"`
}

func (a *API) downloads(w http.ResponseWriter, r *http.Request) error {
	current := a.server
	if o, ok := httpapi.OriginOf(r); ok {
		current = o.Console
	}
	httpapi.WriteJSON(w, http.StatusOK, downloads{
		ServerURL: a.server, Items: a.builds.List(), Addresses: a.addresses,
		Current: current, CertificateAuthority: a.ca,
	})
	return nil
}
