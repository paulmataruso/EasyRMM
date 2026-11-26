// Package quickassistapi serves Quick Assist (ADR-0080): the console's
// routes for links and sessions, and the public page a user opens from a
// link. The page and its download are public by design; they answer one
// message for every link that cannot be used.
package quickassistapi

import (
	"errors"
	"html/template"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/paulmataruso/easyrmm/server/internal/agents"
	"github.com/paulmataruso/easyrmm/server/internal/httpapi"
	"github.com/paulmataruso/easyrmm/server/internal/quickassist"
)

// StepUp is what the API asks of the session (httpapi.Sessions).
type StepUp interface {
	StepUp(r *http.Request) error
}

// Builds is the agent builds the server serves (agents.Builds).
type Builds interface {
	For(goos, goarch string) (agents.Build, bool)
	Open(file string) (io.ReadSeekCloser, agents.Build, error)
}

// API serves the routes.
type API struct {
	svc    *quickassist.Service
	stepUp StepUp
	builds Builds
}

// New builds the API. builds may be nil: the page then offers no download.
func New(svc *quickassist.Service, stepUp StepUp, builds Builds) *API {
	return &API{svc: svc, stepUp: stepUp, builds: builds}
}

// Register mounts the routes.
func (a *API) Register(mux *http.ServeMux) {
	r := func(pattern string, h httpapi.HandlerFunc) {
		mux.Handle(pattern, httpapi.RequireActive(httpapi.Handle(h)))
	}
	r("GET /api/v1/quickassist/settings", a.getSettings)
	r("PUT /api/v1/quickassist/settings", a.putSettings)
	r("GET /api/v1/quickassist/waiting", a.waiting)
	r("GET /api/v1/organizations/{id}/quickassist/links", a.listLinks)
	r("POST /api/v1/organizations/{id}/quickassist/links", a.createLink)
	r("POST /api/v1/quickassist/links/{id}/revoke", a.revokeLink)
	r("POST /api/v1/quickassist/links/{id}/pause", a.pauseLink)
	r("GET /api/v1/organizations/{id}/quickassist/sessions", a.listSessions)
	r("POST /api/v1/quickassist/sessions/{id}/accept", a.accept)
	r("POST /api/v1/quickassist/sessions/{id}/decline", a.decline)
	r("POST /api/v1/quickassist/sessions/{id}/end", a.end)
	r("POST /api/v1/quickassist/sessions/{id}/takeover", a.takeover)
	r("POST /api/v1/quickassist/sessions/{id}/install", a.install)

	mux.Handle("GET /qa/{token}", httpapi.Handle(a.page))
	mux.Handle("GET /qa/{token}/download", httpapi.Handle(a.download))
}

type modeBody struct {
	Mode string `json:"mode"`
}

func (a *API) getSettings(w http.ResponseWriter, r *http.Request) error {
	m, err := a.svc.Mode(r.Context())
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusOK, modeBody{Mode: m})
	return nil
}

func (a *API) putSettings(w http.ResponseWriter, r *http.Request) error {
	var in modeBody
	if err := httpapi.DecodeJSON(w, r, &in); err != nil {
		return err
	}
	// Lifting the restriction changes who may be sent an unsigned program.
	if err := a.stepUp.StepUp(r); err != nil {
		return err
	}
	if err := a.svc.SetMode(r.Context(), httpapi.Caller(r), in.Mode); err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusOK, in)
	return nil
}

func (a *API) waiting(w http.ResponseWriter, r *http.Request) error {
	n, err := a.svc.Waiting(r.Context(), httpapi.Caller(r))
	if err != nil {
		return err
	}
	w.Header().Set("Cache-Control", "no-store")
	httpapi.WriteJSON(w, http.StatusOK, map[string]int{"waiting": n})
	return nil
}

func (a *API) listLinks(w http.ResponseWriter, r *http.Request) error {
	org, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	l, err := a.svc.ListLinks(r.Context(), httpapi.Caller(r), org)
	if err != nil {
		return err
	}
	w.Header().Set("Cache-Control", "no-store")
	httpapi.WriteJSON(w, http.StatusOK, map[string]any{"links": l})
	return nil
}

type createBody struct {
	Kind          string     `json:"kind"`
	Name          string     `json:"name"`
	Note          string     `json:"note"`
	SiteID        *uuid.UUID `json:"siteId"`
	LifeMinutes   int        `json:"lifeMinutes"`
	ConsoleOrigin string     `json:"-"`
}

func (a *API) createLink(w http.ResponseWriter, r *http.Request) error {
	org, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	var in createBody
	if err := httpapi.DecodeJSON(w, r, &in); err != nil {
		return err
	}
	// A permanent link is a standing door to the request queue: step-up.
	if in.Kind == quickassist.KindPermanent {
		if err := a.stepUp.StepUp(r); err != nil {
			return err
		}
	}
	l, err := a.svc.CreateLink(r.Context(), httpapi.Caller(r), quickassist.CreateInput{
		OrganizationID: org, SiteID: in.SiteID, Kind: in.Kind, Name: in.Name, Note: in.Note,
		Life: time.Duration(in.LifeMinutes) * time.Minute,
	})
	if err != nil {
		return err
	}
	w.Header().Set("Cache-Control", "no-store")
	httpapi.WriteJSON(w, http.StatusCreated, l)
	return nil
}

func (a *API) revokeLink(w http.ResponseWriter, r *http.Request) error {
	id, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	l, err := a.svc.RevokeLink(r.Context(), httpapi.Caller(r), id, func() error { return a.stepUp.StepUp(r) })
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusOK, l)
	return nil
}

func (a *API) pauseLink(w http.ResponseWriter, r *http.Request) error {
	id, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	var in struct {
		Paused bool `json:"paused"`
	}
	if err := httpapi.DecodeJSON(w, r, &in); err != nil {
		return err
	}
	l, err := a.svc.PauseLink(r.Context(), httpapi.Caller(r), id, in.Paused)
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusOK, l)
	return nil
}

func (a *API) listSessions(w http.ResponseWriter, r *http.Request) error {
	org, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	states := []string{quickassist.SessionRequested, quickassist.SessionActive}
	if q := r.URL.Query().Get("state"); q != "" {
		states = nil
		for _, s := range strings.Split(q, ",") {
			switch s {
			case "requested", "active", "declined", "ended", "lost":
				states = append(states, s)
			default:
				return httpapi.BadRequest("Unknown state " + strconv.Quote(s) + ".")
			}
		}
	}
	l, err := a.svc.ListSessions(r.Context(), httpapi.Caller(r), org, states)
	if err != nil {
		return err
	}
	w.Header().Set("Cache-Control", "no-store")
	httpapi.WriteJSON(w, http.StatusOK, map[string]any{"sessions": l})
	return nil
}

func (a *API) accept(w http.ResponseWriter, r *http.Request) error {
	id, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	var in struct {
		Code string `json:"code"`
	}
	if err := httpapi.DecodeJSON(w, r, &in); err != nil {
		return err
	}
	x, err := a.svc.Accept(r.Context(), httpapi.Caller(r), id, in.Code)
	var wrong *quickassist.ErrWrongCode
	if errors.As(err, &wrong) {
		return &httpapi.Error{Status: http.StatusUnprocessableEntity, Code: "wrong_code",
			Message: "That is not the code on the user's screen. Tries left: " + strconv.Itoa(wrong.Left) + "."}
	}
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusOK, x)
	return nil
}

func (a *API) simple(f func(r *http.Request, id uuid.UUID) error) httpapi.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) error {
		id, err := httpapi.PathID(r)
		if err != nil {
			return err
		}
		if err := f(r, id); err != nil {
			return err
		}
		w.WriteHeader(http.StatusNoContent)
		return nil
	}
}

func (a *API) decline(w http.ResponseWriter, r *http.Request) error {
	return a.simple(func(r *http.Request, id uuid.UUID) error { return a.svc.Decline(r.Context(), httpapi.Caller(r), id) })(w, r)
}

func (a *API) end(w http.ResponseWriter, r *http.Request) error {
	return a.simple(func(r *http.Request, id uuid.UUID) error { return a.svc.End(r.Context(), httpapi.Caller(r), id) })(w, r)
}

// install asks to keep the agent on the computer. It needs a second factor
// within five minutes; nothing happens until the user agrees on their screen.
func (a *API) install(w http.ResponseWriter, r *http.Request) error {
	if err := a.stepUp.StepUp(r); err != nil {
		return err
	}
	return a.simple(func(r *http.Request, id uuid.UUID) error {
		return a.svc.RequestInstall(r.Context(), httpapi.Caller(r), id)
	})(w, r)
}

func (a *API) takeover(w http.ResponseWriter, r *http.Request) error {
	return a.simple(func(r *http.Request, id uuid.UUID) error { return a.svc.Takeover(r.Context(), httpapi.Caller(r), id) })(w, r)
}

// The public page. One message for every link that cannot be used.
var pageTmpl = template.Must(template.New("qa").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="referrer" content="no-referrer"><title>Remote support</title>
<style>body{font:16px/1.5 system-ui,sans-serif;max-width:40rem;margin:2rem auto;padding:0 1rem;color:#1b1f24}
h1{font-size:1.4rem}.btn{display:inline-block;padding:.6rem 1rem;border:1px solid #1b1f24;border-radius:6px;margin:.25rem .5rem .25rem 0;color:inherit}
.note{background:#f4f1e8;padding:.75rem 1rem;border-radius:6px}code{word-break:break-all}</style></head><body>
{{if .OK}}<h1>Remote support from {{.Organization}}</h1>
{{if .Name}}<p>{{.Name}}</p>{{end}}
{{if .Test}}<p class="note">This is a test link, made before this program is signed.</p>{{end}}
<p>This downloads a program that lets the technician see and control your screen, run programs, see your computer's details and installed updates, and transfer files, until you close its window. It asks you first and shows a six-digit code that you read to the technician. It installs nothing and removes itself when the session ends.</p>
<p class="note">Your browser or Windows may warn that this program is unrecognized, because it is not signed yet. Check that the address in the program's window is <strong>{{.Server}}</strong> and that the technician you are speaking to gives you the same name. Only run it if you started this call. If in doubt, close this page and call your technician.</p>
<p><a class="btn" href="{{.Path}}/download?os=windows">Download for Windows</a><a class="btn" href="{{.Path}}/download?os=linux">Download for Linux</a></p>
{{else}}<h1>This link cannot be used</h1><p>Call your technician for a new one.</p>{{end}}
</body></html>`))

type pageData struct {
	OK                               bool
	Organization, Name, Server, Path string
	Test                             bool
}

func secureHeaders(w http.ResponseWriter) {
	h := w.Header()
	h.Set("Cache-Control", "no-store")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
	h.Set("Content-Type", "text/html; charset=utf-8")
}

func (a *API) page(w http.ResponseWriter, r *http.Request) error {
	secureHeaders(w)
	tok := r.PathValue("token")
	p, err := a.svc.Resolve(r.Context(), httpapi.ClientIP(r), tok)
	switch {
	case errors.Is(err, quickassist.ErrRateLimited):
		return &httpapi.Error{Status: http.StatusTooManyRequests, Code: "rate_limited", Message: "Too many requests. Try again later."}
	case errors.Is(err, quickassist.ErrLinkUnavailable):
		w.WriteHeader(http.StatusNotFound)
		return pageTmpl.Execute(w, pageData{})
	case err != nil:
		return err
	}
	return pageTmpl.Execute(w, pageData{OK: true, Organization: p.Organization, Name: p.Name, Server: p.Server, Test: p.Test, Path: "/qa/" + tok})
}

func (a *API) download(w http.ResponseWriter, r *http.Request) error {
	if a.builds == nil {
		return httpapi.ErrNotFound
	}
	goos := r.URL.Query().Get("os")
	if goos != "windows" && goos != "linux" {
		return httpapi.BadRequest("Choose windows or linux.")
	}
	b, ok := a.builds.For(goos, "amd64")
	if !ok {
		return httpapi.ErrNotFound
	}
	trailer, _, err := a.svc.Download(r.Context(), httpapi.ClientIP(r), r.PathValue("token"))
	switch {
	case errors.Is(err, quickassist.ErrRateLimited), errors.Is(err, quickassist.ErrThrottled):
		secureHeaders(w)
		w.Header().Set("Retry-After", "180")
		w.WriteHeader(http.StatusTooManyRequests)
		return pageTmpl.Execute(w, pageData{})
	case errors.Is(err, quickassist.ErrLinkUnavailable):
		secureHeaders(w)
		w.WriteHeader(http.StatusNotFound)
		return pageTmpl.Execute(w, pageData{})
	case err != nil:
		return err
	}
	f, _, err := a.builds.Open(b.File)
	if err != nil {
		return httpapi.ErrNotFound
	}
	defer func() { _ = f.Close() }()
	name := "easyrmm-quick-assist"
	if goos == "windows" {
		name += ".exe"
	}
	h := w.Header()
	h.Set("Content-Type", "application/octet-stream")
	h.Set("Content-Disposition", `attachment; filename="`+name+`"`)
	h.Set("Content-Length", strconv.FormatInt(b.Size+int64(len(trailer)), 10))
	h.Set("Cache-Control", "no-store")
	h.Set("X-Program-Sha256", b.SHA256)
	if _, err := io.Copy(w, f); err != nil {
		return nil
	}
	_, _ = w.Write(trailer)
	return nil
}
