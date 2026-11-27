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
	r("PUT /api/v1/quickassist/settings/default-life", a.putDefaultLife)
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
	Mode               string `json:"mode"`
	DefaultLifeMinutes int    `json:"defaultLifeMinutes,omitempty"`
}

func (a *API) getSettings(w http.ResponseWriter, r *http.Request) error {
	m, err := a.svc.Mode(r.Context())
	if err != nil {
		return err
	}
	life, err := a.svc.DefaultLife(r.Context())
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusOK, modeBody{Mode: m, DefaultLifeMinutes: int(life / time.Minute)})
	return nil
}

// putDefaultLife sets the default lifetime of a new one-time link, for the whole app.
func (a *API) putDefaultLife(w http.ResponseWriter, r *http.Request) error {
	var in struct {
		Minutes int `json:"minutes"`
	}
	if err := httpapi.DecodeJSON(w, r, &in); err != nil {
		return err
	}
	if err := a.svc.SetDefaultLife(r.Context(), httpapi.Caller(r), in.Minutes); err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusOK, in)
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
<style>
*,*::before,*::after{box-sizing:border-box}
body{font:16px/1.6 system-ui,-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
  margin:0;padding:0;color:#0f172a;background:#f4f6f9;min-height:100vh;display:flex;flex-direction:column;align-items:center;justify-content:center}
.wrap{width:100%;max-width:32rem;margin:2rem auto;padding:0 1rem}
.card{background:#fff;border-radius:12px;box-shadow:0 1px 3px rgba(15,23,42,.08),0 4px 12px rgba(15,23,42,.04);padding:2rem;border:1px solid #dde3ea}
.brand{display:flex;align-items:center;gap:.5rem;margin-bottom:1.5rem;padding-bottom:1rem;border-bottom:1px solid #dde3ea}
.brand svg{width:28px;height:28px;flex-shrink:0}
.brand span{font-size:.875rem;font-weight:600;color:#5b6678;letter-spacing:.02em;text-transform:uppercase}
h1{font-size:1.25rem;font-weight:600;color:#0f172a;margin:0 0 .25rem}
.org{color:#2563eb;font-weight:500}
.sub{color:#5b6678;font-size:.875rem;margin:0 0 1.25rem}
.info{font-size:.9rem;color:#3a4452;line-height:1.65;margin:0 0 1.25rem}
.note{background:#e7efff;color:#1e3a5f;padding:.75rem 1rem;border-radius:8px;font-size:.85rem;line-height:1.55;margin:0 0 1.5rem;border-left:3px solid #2563eb}
.note.warn{background:#fdf1df;color:#7c4a03;border-left-color:#b45309}
.note.test{background:#fde8e8;color:#8b1a1a;border-left-color:#c62828}
.btns{display:flex;gap:.75rem;flex-wrap:wrap}
.btn{display:inline-flex;align-items:center;gap:.5rem;padding:.65rem 1.25rem;border-radius:8px;font-size:.9rem;font-weight:500;text-decoration:none;transition:background .15s,box-shadow .15s}
.btn-primary{background:#2563eb;color:#fff;border:none}
.btn-primary:hover{background:#1d4ed8;box-shadow:0 2px 8px rgba(37,99,235,.25)}
.btn-secondary{background:#fff;color:#0f172a;border:1px solid #c5ced9}
.btn-secondary:hover{background:#eef2f7;border-color:#9aa6b8}
.btn svg{width:18px;height:18px;fill:currentColor}
.server{font-weight:600;color:#0f172a}
.expired{text-align:center;padding:3rem 1rem}
.expired h1{font-size:1.5rem;color:#5b6678;margin-bottom:.5rem}
.expired p{color:#8a94a6;font-size:.95rem}
@media(prefers-color-scheme:dark){
  body{background:#0b0f17;color:#e6ebf2}
  .card{background:#121824;border-color:#243044;box-shadow:0 1px 3px rgba(0,0,0,.2),0 4px 12px rgba(0,0,0,.15)}
  .brand{border-bottom-color:#243044}
  .brand span{color:#9aa6b8}
  h1{color:#e6ebf2}
  .org{color:#4f8cff}
  .sub{color:#9aa6b8}
  .info{color:#c0c9d6}
  .note{background:#15233d;color:#b8d4ff;border-left-color:#4f8cff}
  .note.warn{background:#2d2410;color:#fbbf24;border-left-color:#fbbf24}
  .note.test{background:#2f1517;color:#f87171;border-left-color:#f87171}
  .btn-primary{background:#4f8cff;color:#06101f}
  .btn-primary:hover{background:#6a9dff}
  .btn-secondary{background:#171e2c;color:#e6ebf2;border-color:#33415a}
  .btn-secondary:hover{background:#1c2433;border-color:#4a5568}
  .server{color:#e6ebf2}
  .expired h1{color:#9aa6b8}
  .expired p{color:#6b778b}
}
</style></head><body>
<div class="wrap">
{{if .OK}}<div class="card">
  <div class="brand"><svg viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg"><rect x="2" y="3" width="20" height="14" rx="2" stroke="currentColor" stroke-width="1.5"/><path d="M8 21h8M12 17v4" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/><path d="M7 8h4M7 11h6" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" opacity=".5"/></svg><span>Remote Support</span></div>
  <h1>Support from <span class="org">{{.Organization}}</span></h1>
  {{if .Name}}<p class="sub">{{.Name}}</p>{{else}}<div style="margin-bottom:1rem"></div>{{end}}
  {{if .Test}}<p class="note test">This is a test link. The program is not yet signed.</p>{{end}}
  <p class="info">This downloads a small program that lets a technician see and control your screen, run programs, view your computer details and installed updates, and transfer files &mdash; until you close its window. It asks your permission first and shows a six-digit code to read to the technician. It installs nothing and removes itself when the session ends.</p>
  <p class="note warn">Your browser or Windows may warn that this program is unrecognized. Verify that the address shown in the program is <span class="server">{{.Server}}</span> and matches what your technician tells you. Only run it if you initiated this call.</p>
  <div class="btns">
    <a class="btn btn-primary" href="{{.Path}}/download?os=windows"><svg viewBox="0 0 24 24"><path d="M3 5.548l7.066-.966v6.825H3V5.548zm0 12.904l7.066.966v-6.825H3v5.859zm7.945 1.086L21 21V12.593H10.945v6.945zM10.945 4.462V11.407H21V3l-10.055 1.462z"/></svg>Windows</a>
    <a class="btn btn-secondary" href="{{.Path}}/download?os=linux"><svg viewBox="0 0 24 24"><path d="M12.504 2c-.404.008-.793.168-1.128.45-.568.48-.9 1.258-1.025 2.088a5.252 5.252 0 00-.047 1.26c-.395.326-.724.726-.977 1.166a5.14 5.14 0 00-.563 1.467c-.125.585-.16 1.173-.085 1.68-.49.422-.855.978-1.09 1.593-.234.613-.34 1.274-.32 1.943a4.44 4.44 0 00.335 1.624c-.386.46-.645 1.03-.778 1.63a4.724 4.724 0 00-.043 1.864c.09.616.3 1.198.615 1.683.316.488.743.878 1.244 1.117a3.1 3.1 0 001.555.287c.516-.024.998-.16 1.43-.38a3.9 3.9 0 001.11-.89c.42.233.886.388 1.367.455.48.067.976.044 1.448-.07.472-.113.912-.316 1.29-.594.267.3.57.564.907.776.337.21.705.37 1.09.47a3.1 3.1 0 001.556.025c.508-.125.964-.386 1.335-.748a3.4 3.4 0 00.838-1.372c.185-.54.253-1.117.198-1.695a4.5 4.5 0 00-.428-1.597 3.8 3.8 0 00.447-.965c.138-.49.17-1.007.096-1.52a3.74 3.74 0 00-.524-1.428 4.22 4.22 0 00-1.055-1.11 5.14 5.14 0 00.03-1.08 4.3 4.3 0 00-.316-1.26 4.1 4.1 0 00-.7-1.1 3.6 3.6 0 00-1.028-.82 5.4 5.4 0 00-.23-1.388 4.14 4.14 0 00-.627-1.195A2.63 2.63 0 0014.14 2.2a2.1 2.1 0 00-.637-.178A2.2 2.2 0 0012.504 2z"/></svg>Linux</a>
  </div>
</div>
{{else}}<div class="card expired">
  <svg viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg" style="width:48px;height:48px;margin:0 auto 1rem;display:block;color:#8a94a6"><circle cx="12" cy="12" r="9" stroke="currentColor" stroke-width="1.5"/><path d="M12 7v5l3 3" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/></svg>
  <h1>This link has expired</h1>
  <p>Please contact your technician for a new link.</p>
</div>{{end}}
</div>
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
