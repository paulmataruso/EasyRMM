// Package ssoapi serves single sign-on with OpenID Connect (ADR-0034): the
// sign-in page's providers, the browser's trip to a provider and back, the
// providers' settings for super administrators, and a person's own linked
// identities.
package ssoapi

import (
	"errors"
	"net/http"
	"net/url"
	"time"

	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/auth"
	"github.com/paulmataruso/easyrmm/server/internal/httpapi"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
	"github.com/paulmataruso/easyrmm/server/internal/sso"
)

// API serves single sign-on.
type API struct {
	svc      *sso.Service
	sessions *httpapi.Sessions
	public   *url.URL
}

// New builds the API. public is EASYRMM_PUBLIC_URL, where sign-ins start
// and end.
func New(svc *sso.Service, sessions *httpapi.Sessions, public *url.URL) *API {
	return &API{svc: svc, sessions: sessions, public: public}
}

// Register adds the routes.
func (a *API) Register(mux *http.ServeMux) {
	h := httpapi.Handle
	mux.Handle("GET /api/v1/auth/sso", h(a.buttons))
	mux.Handle("GET /api/v1/auth/sso/{id}/start", http.HandlerFunc(a.start))
	mux.Handle("GET "+sso.CallbackPath, http.HandlerFunc(a.callback))
	// Step-up through the provider (ADR-0055): a fresh sign-in there.
	mux.Handle("POST /api/v1/auth/step-up/oidc/begin", httpapi.RequireActive(h(a.beginStepUp)))
	mux.Handle("GET /api/v1/auth/identities", httpapi.RequireActive(h(a.identities)))
	mux.Handle("DELETE /api/v1/auth/identities/{id}", httpapi.RequireActive(h(a.unlink)))

	settings := func(pattern string, hf httpapi.HandlerFunc) {
		mux.Handle(pattern, httpapi.RequireActive(h(func(w http.ResponseWriter, r *http.Request) error {
			if !httpapi.Can(r, rbac.PermSettingsManage, rbac.Resource{}) {
				return apperr.Forbidden()
			}
			return hf(w, r)
		})))
	}
	settings("GET /api/v1/settings/sso", a.providers)
	settings("POST /api/v1/settings/sso/providers", a.create)
	settings("PUT /api/v1/settings/sso/providers/{id}", a.update)
	settings("DELETE /api/v1/settings/sso/providers/{id}", a.remove)
}

func (a *API) flowCookieName() string {
	if a.sessions.Secure() {
		return "__Host-easyrmm_sso"
	}
	return "easyrmm_sso"
}

// setFlow keeps the sealed flow until the provider sends the browser back.
// SameSite=Lax: the callback is a top-level navigation from the provider's
// site, which a Strict cookie would not reach.
func (a *API) setFlow(w http.ResponseWriter, value string, maxAge int) {
	http.SetCookie(w, &http.Cookie{ //nolint:gosec // Secure is false only in the explicit plain-HTTP development mode
		Name: a.flowCookieName(), Value: value, Path: "/", MaxAge: maxAge,
		Secure: a.sessions.Secure(), HttpOnly: true, SameSite: http.SameSiteLaxMode,
	})
}

// toLogin sends the browser to the sign-in page, which explains a failure
// or continues the sign-in (a second factor, a passkey offer, returnTo).
func toLogin(w http.ResponseWriter, r *http.Request, q url.Values) {
	target := "/login"
	if len(q) > 0 {
		target += "?" + q.Encode()
	}
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, target, http.StatusSeeOther)
}

func failed(w http.ResponseWriter, r *http.Request, err error) {
	code := "error"
	var f *sso.Failure
	if errors.As(err, &f) {
		code = f.Code
		httpapi.LoggerFrom(r.Context()).Info("single sign-on refused", "code", f.Code, "err", err)
	} else {
		httpapi.LoggerFrom(r.Context()).Error("single sign-on failed", "err", err)
	}
	toLogin(w, r, url.Values{"sso_error": {code}})
}

func (a *API) buttons(w http.ResponseWriter, r *http.Request) error {
	b, err := a.svc.Buttons(r.Context())
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusOK, map[string]any{"providers": b})
	return nil
}

func (a *API) start(w http.ResponseWriter, r *http.Request) {
	id, err := httpapi.PathID(r)
	if err != nil {
		failed(w, r, &sso.Failure{Code: sso.FailUnavailable})
		return
	}
	returnTo := sso.SafeReturn(r.URL.Query().Get("returnTo"))
	// The flow cookie must be set where the provider will send the browser
	// back: the public URL. The redirect is rebuilt from the parsed id and
	// return path, never copied from the request.
	if r.Host != a.public.Host {
		u := *a.public
		u.Path = "/api/v1/auth/sso/" + id.String() + "/start"
		u.RawQuery = ""
		if returnTo != "/" {
			u.RawQuery = url.Values{"returnTo": {returnTo}}.Encode()
		}
		http.Redirect(w, r, u.String(), http.StatusSeeOther) //nolint:gosec // G710: the configured public URL, a parsed UUID and SafeReturn's path
		return
	}
	authURL, sealed, err := a.svc.Start(r.Context(), id, returnTo)
	if err != nil {
		failed(w, r, err)
		return
	}
	a.setFlow(w, sealed, int(sso.FlowTTL/time.Second))
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, authURL, http.StatusSeeOther) //nolint:gosec // G710: the authorization endpoint of a provider a super administrator set up
}

type stepUpRequest struct {
	ReturnTo string `json:"returnTo"`
}

// beginStepUp answers with the provider's address for a fresh sign-in; the
// console goes there, and the provider sends the browser back to the callback.
func (a *API) beginStepUp(w http.ResponseWriter, r *http.Request) error {
	var req stepUpRequest
	if err := httpapi.DecodeJSON(w, r, &req); err != nil {
		return err
	}
	id := httpapi.IdentityFrom(r.Context())
	authURL, err := a.svc.StartStepUp(r.Context(), id.Session, req.ReturnTo, httpapi.Meta(r))
	switch {
	case errors.Is(err, auth.ErrNoSecondFactor):
		return &httpapi.Error{Status: http.StatusConflict, Code: "no_second_factor", Message: "This sign-in cannot be repeated at your provider. Set up an authenticator app or a security key in your account settings."}
	case errors.Is(err, auth.ErrRateLimited):
		return httpapi.ErrTooMany
	case err != nil:
		var f *sso.Failure
		if errors.As(err, &f) {
			return &httpapi.Error{Status: http.StatusBadGateway, Code: "provider_unavailable", Message: "The identity provider could not be reached."}
		}
		return err
	}
	httpapi.WriteJSON(w, http.StatusOK, map[string]string{"authUrl": authURL})
	return nil
}

func (a *API) callback(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	// A step-up's state is on its session's row; the session cookie is
	// SameSite=Strict and does not come back from the provider.
	if a.svc.IsStepUp(r.Context(), q.Get("state")) {
		a.stepUpCallback(w, r)
		return
	}
	in := sso.CallbackInput{State: q.Get("state"), Code: q.Get("code"), Error: q.Get("error"), ErrorDescription: q.Get("error_description")}
	if c, err := r.Cookie(a.flowCookieName()); err == nil {
		in.Sealed = c.Value
	}
	// The flow is used once, whatever happens next.
	a.setFlow(w, "", -1)
	res, err := a.svc.Callback(r.Context(), in, httpapi.Meta(r))
	if err != nil {
		failed(w, r, err)
		return
	}
	a.sessions.SetCookie(w, res.Token, res.Session.ExpiresAt)
	// The sign-in page takes it from here: a second factor if one is due,
	// the passkey offer, then returnTo.
	v := url.Values{}
	if res.ReturnTo != "/" {
		v.Set("returnTo", res.ReturnTo)
	}
	toLogin(w, r, v)
}

func (a *API) identities(w http.ResponseWriter, r *http.Request) error {
	id := httpapi.IdentityFrom(r.Context())
	list, err := a.svc.Identities(r.Context(), id.User.ID)
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusOK, map[string]any{"items": list})
	return nil
}

func (a *API) unlink(w http.ResponseWriter, r *http.Request) error {
	providerID, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	id := httpapi.IdentityFrom(r.Context())
	if err := a.svc.Unlink(r.Context(), httpapi.Actor(r), id.User.ID, providerID); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func (a *API) providers(w http.ResponseWriter, r *http.Request) error {
	list, err := a.svc.Providers(r.Context())
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusOK, map[string]any{"redirectUri": a.svc.RedirectURI(), "providers": list})
	return nil
}

func (a *API) create(w http.ResponseWriter, r *http.Request) error {
	var in sso.ProviderInput
	if err := httpapi.DecodeJSON(w, r, &in); err != nil {
		return err
	}
	p, err := a.svc.CreateProvider(r.Context(), httpapi.Actor(r), in)
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusCreated, p)
	return nil
}

func (a *API) update(w http.ResponseWriter, r *http.Request) error {
	id, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	var in sso.ProviderInput
	if err := httpapi.DecodeJSON(w, r, &in); err != nil {
		return err
	}
	p, err := a.svc.UpdateProvider(r.Context(), httpapi.Actor(r), id, in)
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusOK, p)
	return nil
}

func (a *API) remove(w http.ResponseWriter, r *http.Request) error {
	id, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	if err := a.svc.DeleteProvider(r.Context(), httpapi.Actor(r), id); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

// stepUpCallback completes a step-up and sends the browser back to the
// console page it came from, saying how it went (?stepup=done or failed).
func (a *API) stepUpCallback(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	in := sso.CallbackInput{State: q.Get("state"), Code: q.Get("code"), Error: q.Get("error"), ErrorDescription: q.Get("error_description")}
	returnTo, err := a.svc.CompleteStepUp(r.Context(), in, httpapi.Meta(r))
	u := *a.public
	u.Path, u.RawQuery = "/", ""
	if p, perr := url.Parse(sso.SafeReturn(returnTo)); perr == nil {
		u.Path, u.RawQuery = p.Path, p.RawQuery
	}
	v := u.Query()
	v.Set("stepup", "done")
	if err != nil {
		v.Set("stepup", "failed")
		var f *sso.Failure
		if errors.As(err, &f) {
			v.Set("reason", f.Code)
		}
	}
	u.RawQuery = v.Encode()
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, u.String(), http.StatusSeeOther) //nolint:gosec // G710: the configured public URL and SafeReturn's path
}
