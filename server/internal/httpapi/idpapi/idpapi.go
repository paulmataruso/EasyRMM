// Package idpapi serves EasyRMM's OpenID provider for EasyPatch (ADR-0036):
// the provider's own routes (discovery, keys, authorize, token), which sit
// outside the console's CSRF layer and check what they need themselves, and
// the console's settings for EasyPatch's client.
package idpapi

import (
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/auth"
	"github.com/paulmataruso/easyrmm/server/internal/httpapi"
	"github.com/paulmataruso/easyrmm/server/internal/idp"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
)

// API serves the provider.
type API struct {
	svc *idp.Service
	// authorizeLimit bounds authorization requests per address: refusals
	// are audited, and the audit log is not a free-for-all.
	authorizeLimit *auth.KeyedLimiter
}

// New builds the API.
func New(svc *idp.Service) *API {
	return &API{svc: svc, authorizeLimit: auth.NewKeyedLimiter(2*time.Second, 30, 10_000)}
}

// IsProviderPath reports whether a path is one of the provider's routes.
func IsProviderPath(p string) bool {
	return p == idp.PathDiscovery || strings.HasPrefix(p, "/oauth2/")
}

// Provider is the provider's routes. Mount it with the session loaded
// (authorize reads it) and without the CSRF layer: the token endpoint is
// called by EasyPatch's server, not a browser.
func (a *API) Provider() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("GET "+idp.PathDiscovery, a.enabled(a.discovery))
	mux.Handle("GET "+idp.PathJWKS, a.enabled(a.jwks))
	mux.Handle("GET "+idp.PathAuthorize, a.enabled(a.authorize))
	mux.Handle("POST "+idp.PathAuthorize, a.enabled(a.authorize))
	mux.Handle("POST "+idp.PathToken, a.enabled(a.token))
	mux.Handle("/", httpapi.Handle(func(http.ResponseWriter, *http.Request) error { return httpapi.ErrNotFound }))
	return mux
}

// Register adds the settings routes to the console's API.
func (a *API) Register(mux *http.ServeMux) {
	settings := func(pattern string, h httpapi.HandlerFunc) {
		mux.Handle(pattern, httpapi.RequireActive(httpapi.Handle(func(w http.ResponseWriter, r *http.Request) error {
			if !httpapi.Can(r, rbac.PermSettingsManage, rbac.Resource{}) {
				return apperr.Forbidden()
			}
			return h(w, r)
		})))
	}
	settings("GET /api/v1/settings/easypatch/sign-in", a.settings)
	settings("POST /api/v1/settings/easypatch/sign-in", a.create)
	settings("POST /api/v1/settings/easypatch/sign-in/rotate", a.rotate)
	settings("DELETE /api/v1/settings/easypatch/sign-in", a.delete)
}

// enabled answers 404 until a super administrator sets EasyPatch up as the
// client: until then EasyRMM is no provider at all.
func (a *API) enabled(h httpapi.HandlerFunc) http.Handler {
	return httpapi.Handle(func(w http.ResponseWriter, r *http.Request) error {
		ok, err := a.svc.Enabled(r.Context())
		if err != nil {
			return err
		}
		if !ok {
			return httpapi.ErrNotFound
		}
		return h(w, r)
	})
}

// Discovery is the OpenID Provider metadata.
type Discovery struct {
	Issuer                            string   `json:"issuer"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	JWKSURI                           string   `json:"jwks_uri"`
	ResponseTypesSupported            []string `json:"response_types_supported"`
	ResponseModesSupported            []string `json:"response_modes_supported"`
	GrantTypesSupported               []string `json:"grant_types_supported"`
	SubjectTypesSupported             []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported  []string `json:"id_token_signing_alg_values_supported"`
	ScopesSupported                   []string `json:"scopes_supported"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
	CodeChallengeMethodsSupported     []string `json:"code_challenge_methods_supported"`
	ClaimsSupported                   []string `json:"claims_supported"`
	ClaimsParameterSupported          bool     `json:"claims_parameter_supported"`
	RequestParameterSupported         bool     `json:"request_parameter_supported"`
	RequestURIParameterSupported      bool     `json:"request_uri_parameter_supported"`
	AuthorizationResponseIssSupported bool     `json:"authorization_response_iss_parameter_supported"`
}

func (a *API) discovery(w http.ResponseWriter, _ *http.Request) error {
	iss := a.svc.Issuer()
	w.Header().Set("Cache-Control", "public, max-age=300")
	httpapi.WriteJSON(w, http.StatusOK, Discovery{
		Issuer: iss, AuthorizationEndpoint: iss + idp.PathAuthorize, TokenEndpoint: iss + idp.PathToken, JWKSURI: iss + idp.PathJWKS,
		ResponseTypesSupported: []string{"code"}, ResponseModesSupported: []string{"query"}, GrantTypesSupported: []string{"authorization_code"},
		SubjectTypesSupported: []string{"public"}, IDTokenSigningAlgValuesSupported: []string{"ES256"},
		ScopesSupported:                   []string{"openid", "profile", "email"},
		TokenEndpointAuthMethodsSupported: []string{"client_secret_basic", "client_secret_post"},
		CodeChallengeMethodsSupported:     []string{"S256"},
		ClaimsSupported: []string{"iss", "aud", "sub", "exp", "iat", "auth_time", "nonce", "name", "email", "email_verified",
			"amr", "easypatch"},
		AuthorizationResponseIssSupported: true,
	})
	return nil
}

func (a *API) jwks(w http.ResponseWriter, r *http.Request) error {
	set, err := a.svc.JWKS(r.Context())
	if err != nil {
		return err
	}
	w.Header().Set("Cache-Control", "public, max-age=300")
	httpapi.WriteJSON(w, http.StatusOK, set)
	return nil
}

func (a *API) authorize(w http.ResponseWriter, r *http.Request) error {
	if !a.authorizeLimit.Allow(httpapi.ClientIP(r).String()) {
		return &httpapi.Error{Status: http.StatusTooManyRequests, Code: "rate_limited", Message: "Too many sign-in requests. Wait a moment and try again."}
	}
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	if err := r.ParseForm(); err != nil {
		return &httpapi.Error{Status: http.StatusBadRequest, Code: "invalid_request", Message: "The sign-in request could not be read."}
	}
	var in idp.Signin
	if id := httpapi.IdentityFrom(r.Context()); id != nil {
		in = idp.Signin{Session: id.Session, User: id.User}
	}
	d, err := a.svc.Authorize(r.Context(), idp.ParseAuthRequest(r.Form), in, httpapi.Actor(r))
	if errors.Is(err, idp.ErrUntrustedRedirect) {
		// Never redirect to an address that is not EasyPatch's.
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte("This sign-in request is not from the EasyPatch this EasyRMM is set up for, so EasyRMM cannot answer it.\n" +
			"If you followed a link, go back to EasyPatch and choose \"Sign in with EasyRMM\" again.\n"))
		return nil
	}
	if err != nil {
		return err
	}
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, d.Location, http.StatusFound)
	return nil
}

func (a *API) token(w http.ResponseWriter, r *http.Request) error {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	fail := func(e *idp.TokenError) error {
		if e.Code == "invalid_client" && r.Header.Get("Authorization") != "" {
			w.Header().Set("WWW-Authenticate", `Basic realm="EasyRMM", charset="UTF-8"`)
		}
		httpapi.WriteJSON(w, e.Status, e)
		return nil
	}
	if ct := r.Header.Get("Content-Type"); !strings.HasPrefix(strings.ToLower(ct), "application/x-www-form-urlencoded") {
		return fail(&idp.TokenError{Status: http.StatusBadRequest, Code: "invalid_request", Description: "Send the request as a form."})
	}
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	if err := r.ParseForm(); err != nil {
		return fail(&idp.TokenError{Status: http.StatusBadRequest, Code: "invalid_request", Description: "The request could not be read."})
	}
	f := r.PostForm
	req := idp.TokenRequest{
		GrantType: f.Get("grant_type"), Code: f.Get("code"), RedirectURI: f.Get("redirect_uri"), CodeVerifier: f.Get("code_verifier"),
		Limit: httpapi.ClientIP(r).String(),
	}
	if user, pass, ok := r.BasicAuth(); ok {
		if f.Has("client_secret") {
			return fail(&idp.TokenError{Status: http.StatusBadRequest, Code: "invalid_request", Description: "Use one way of authenticating the client."})
		}
		// RFC 6749, 2.3.1: both parts are form-encoded.
		id, err1 := url.QueryUnescape(user)
		secret, err2 := url.QueryUnescape(pass)
		if err1 != nil || err2 != nil {
			return fail(&idp.TokenError{Status: http.StatusUnauthorized, Code: "invalid_client", Description: "Client authentication failed."})
		}
		if f.Has("client_id") && f.Get("client_id") != id {
			return fail(&idp.TokenError{Status: http.StatusBadRequest, Code: "invalid_request", Description: "The client ids differ."})
		}
		req.ClientID, req.ClientSecret, req.Basic = id, secret, true
	} else {
		req.ClientID, req.ClientSecret = f.Get("client_id"), f.Get("client_secret")
	}
	resp, err := a.svc.Token(r.Context(), req)
	var te *idp.TokenError
	if errors.As(err, &te) {
		return fail(te)
	}
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusOK, resp)
	return nil
}

func (a *API) settings(w http.ResponseWriter, r *http.Request) error {
	s, err := a.svc.Settings(r.Context(), httpapi.Caller(r))
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusOK, s)
	return nil
}

func (a *API) create(w http.ResponseWriter, r *http.Request) error {
	s, err := a.svc.Create(r.Context(), httpapi.Caller(r))
	if err != nil {
		return err
	}
	w.Header().Set("Cache-Control", "no-store")
	httpapi.WriteJSON(w, http.StatusCreated, s)
	return nil
}

func (a *API) rotate(w http.ResponseWriter, r *http.Request) error {
	s, err := a.svc.Rotate(r.Context(), httpapi.Caller(r))
	if err != nil {
		return err
	}
	w.Header().Set("Cache-Control", "no-store")
	httpapi.WriteJSON(w, http.StatusOK, s)
	return nil
}

func (a *API) delete(w http.ResponseWriter, r *http.Request) error {
	if err := a.svc.Delete(r.Context(), httpapi.Caller(r)); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}
