package m365test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

// Refusal is a token request the stand-in endpoint refuses, as the
// identity platform answers one.
type Refusal struct {
	Status      int
	Error       string
	Description string
	Code        int
}

// The identity platform's refusals the stand-in gives, with its words.
var (
	BadSecret = Refusal{http.StatusUnauthorized, "invalid_client",
		"AADSTS7000215: Invalid client secret provided. Ensure the secret being sent in the request is the client secret value, not the client secret ID, for a secret added to app '" + ClientID + "'.", 7000215}
	BadAssertion = Refusal{http.StatusUnauthorized, "invalid_client",
		"AADSTS700027: The certificate with identifier used to sign the client assertion is not registered on application.", 700027}
	NoTenant = Refusal{http.StatusBadRequest, "invalid_request",
		"AADSTS90002: Tenant '%s' not found. Check to make sure you have the correct tenant ID and are signing into the correct cloud.", 90002}
	NoApplication = Refusal{http.StatusBadRequest, "unauthorized_client",
		"AADSTS700016: Application with identifier '%s' was not found in the directory.", 700016}
)

// TokenEndpoint is a stand-in for the Microsoft identity platform's token
// endpoint, for one tenant and one application: it grants the client
// credentials grant for Exchange Online's scope to the application's
// secret, or to a client assertion signed with its certificate.
type TokenEndpoint struct {
	// URL is the authority, as m365.Credentials.Authority takes it.
	URL string
	srv *httptest.Server

	mu sync.Mutex
	// Lifetime is each token's expires_in.
	Lifetime time.Duration
	// Refuse, when set, is the answer to every request.
	Refuse *Refusal
	// ExpiresAsString answers expires_in as a string of digits.
	ExpiresAsString bool
	// Delay is how long each answer takes: a slow identity platform.
	Delay    time.Duration
	cert     *x509.Certificate
	issued   []string
	requests []url.Values
	jtis     map[string]bool
	n        int
}

// NewTokenEndpoint starts a stand-in token endpoint over HTTPS, on
// loopback, until the test ends. cert, when given, is the application's
// certificate, which client assertions must be signed with; without it,
// only Secret is taken.
func NewTokenEndpoint(t testing.TB, cert *x509.Certificate) *TokenEndpoint {
	t.Helper()
	e := &TokenEndpoint{Lifetime: time.Hour, cert: cert, jtis: map[string]bool{}}
	e.srv = httptest.NewUnstartedServer(http.HandlerFunc(e.serve))
	e.srv.TLS = ServerTLS()
	e.srv.StartTLS()
	t.Cleanup(e.srv.Close)
	e.URL = e.srv.URL
	return e
}

// Set changes the endpoint while it serves.
func (e *TokenEndpoint) Set(f func()) {
	e.mu.Lock()
	defer e.mu.Unlock()
	f()
}

// Issued are the tokens granted, oldest first.
func (e *TokenEndpoint) Issued() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]string{}, e.issued...)
}

// Requests are the forms of the requests made, oldest first.
func (e *TokenEndpoint) Requests() []url.Values {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]url.Values{}, e.requests...)
}

// Valid reports whether token is one the endpoint granted.
func (e *TokenEndpoint) Valid(token string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, t := range e.issued {
		if t == token {
			return true
		}
	}
	return false
}

func (e *TokenEndpoint) serve(w http.ResponseWriter, r *http.Request) {
	refuse := func(rf Refusal, args ...any) {
		desc := rf.Description
		if len(args) > 0 {
			desc = fmt.Sprintf(desc, args...)
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(rf.Status)
		_ = json.NewEncoder(w).Encode(map[string]any{"error": rf.Error,
			"error_description": desc + "\r\nTrace ID: 00000000-0000-0000-0000-000000000000\r\nTimestamp: 2026-11-22 00:00:00Z",
			"error_codes":       []int{rf.Code}, "trace_id": "00000000-0000-0000-0000-000000000000"})
	}
	e.mu.Lock()
	delay := e.Delay
	e.mu.Unlock()
	select {
	case <-time.After(delay):
	case <-r.Context().Done():
		return
	}
	tenant, ok := strings.CutSuffix(r.URL.Path, "/oauth2/v2.0/token")
	tenant = strings.TrimPrefix(tenant, "/")
	if r.Method != http.MethodPost || !ok {
		http.NotFound(w, r)
		return
	}
	if err := r.ParseForm(); err != nil || r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
		refuse(Refusal{http.StatusBadRequest, "invalid_request", "AADSTS900144: The request body must contain the following parameter: 'grant_type'.", 900144})
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.requests = append(e.requests, r.PostForm)
	f := r.PostForm
	switch {
	case e.Refuse != nil:
		refuse(*e.Refuse)
		return
	case tenant != TenantID && tenant != "m365.example.com":
		refuse(NoTenant, tenant)
		return
	case f.Get("grant_type") != "client_credentials":
		refuse(Refusal{http.StatusBadRequest, "unsupported_grant_type", "AADSTS70003: The app requested an unsupported grant type.", 70003})
		return
	case f.Get("scope") != "https://outlook.office365.com/.default":
		refuse(Refusal{http.StatusBadRequest, "invalid_scope", "AADSTS1002012: The provided value for scope is not valid.", 1002012})
		return
	case f.Get("client_id") != ClientID:
		refuse(NoApplication, f.Get("client_id"))
		return
	}
	switch {
	case f.Has("client_secret") && f.Has("client_assertion"):
		refuse(Refusal{http.StatusBadRequest, "invalid_request", "AADSTS50027: Only one client credential may be given.", 50027})
		return
	case f.Has("client_secret"):
		if f.Get("client_secret") != Secret {
			refuse(BadSecret)
			return
		}
	case f.Get("client_assertion_type") == "urn:ietf:params:oauth:client-assertion-type:jwt-bearer":
		if err := e.checkAssertion(f.Get("client_assertion"), e.URL+"/"+tenant+"/oauth2/v2.0/token"); err != nil {
			refuse(BadAssertion)
			return
		}
	default:
		refuse(Refusal{http.StatusUnauthorized, "invalid_client", "AADSTS7000218: The request body must contain the following parameter: 'client_assertion' or 'client_secret'.", 7000218})
		return
	}
	e.n++
	b := make([]byte, 24)
	_, _ = rand.Read(b)
	token := fmt.Sprintf("eyJ0eXAiOiJKV1QifQ.stand-in-%d.%s", e.n, hex.EncodeToString(b))
	e.issued = append(e.issued, token)
	var expires any = int(e.Lifetime / time.Second)
	if e.ExpiresAsString {
		expires = fmt.Sprint(expires)
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(map[string]any{"token_type": "Bearer", "expires_in": expires, "ext_expires_in": expires, "access_token": token})
}

// checkAssertion checks a client assertion as Entra does: PS256, the
// certificate's SHA-256 thumbprint, signed by its key, for this endpoint,
// from and about the application, current, and never seen before.
func (e *TokenEndpoint) checkAssertion(jwt, aud string) error {
	if e.cert == nil {
		return fmt.Errorf("no certificate registered")
	}
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		return fmt.Errorf("not a JWT")
	}
	var head struct {
		Alg     string `json:"alg"`
		Typ     string `json:"typ"`
		X5tS256 string `json:"x5t#S256"`
	}
	var claims struct {
		Aud, Iss, Sub, Jti string
		Nbf, Exp, Iat      int64
	}
	for i, v := range []any{&head, &claims} {
		raw, err := base64.RawURLEncoding.DecodeString(parts[i])
		if err != nil {
			return err
		}
		if err := json.Unmarshal(raw, v); err != nil {
			return err
		}
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return err
	}
	now := time.Now().Unix()
	switch {
	case head.Alg != "PS256" || head.Typ != "JWT" || head.X5tS256 != x5tS256(e.cert):
		return fmt.Errorf("header %+v", head)
	case claims.Aud != aud || claims.Iss != ClientID || claims.Sub != ClientID || claims.Jti == "" || e.jtis[claims.Jti]:
		return fmt.Errorf("claims %+v", claims)
	case claims.Nbf > now+60 || claims.Exp <= now || claims.Exp-claims.Nbf > 600 || claims.Iat != claims.Nbf:
		return fmt.Errorf("times %+v", claims)
	}
	if err := verifyPS256(e.cert.PublicKey.(*rsa.PublicKey), parts[0]+"."+parts[1], sig); err != nil {
		return err
	}
	e.jtis[claims.Jti] = true
	return nil
}
