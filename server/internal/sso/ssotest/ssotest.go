// Package ssotest locates the disposable Dex that integration tests sign in
// through (scripts/test-oidc.sh, `make test-oidc`), and drives its sign-in
// form the way a browser would.
package ssotest

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// DirVar names the directory scripts/test-oidc.sh wrote env.json into.
const DirVar = "EASYRMM_TEST_OIDC_DIR"

// PublicURL is the EasyRMM public URL the test client is registered for:
// its redirect URI is this plus /api/v1/auth/sso/callback. Nothing listens
// there; tests take the code from Dex's redirect.
const PublicURL = "http://127.0.0.1:25599"

// AppPublicURL is the public URL of the application tests' server
// (internal/app), registered at Dex as well.
const AppPublicURL = "https://rmm.test"

// callbackPath is where Dex sends the browser back (sso.CallbackPath).
const callbackPath = "/api/v1/auth/sso/callback"

// Dex's users. They share Settings.Password, and Dex reports every one's
// email as verified.
const (
	Alex      = "alex@sso.test"      // an EasyRMM user in tests
	Sam       = "sam@sso.test"       // an EasyRMM user with a second factor
	Dana      = "dana@sso.test"      // a disabled EasyRMM user
	Nobody    = "nobody@sso.test"    // no EasyRMM account
	Elsewhere = "eve@elsewhere.test" // a domain the provider is not allowed
)

// Users lists them for the Dex configuration.
var Users = []string{Alex, Sam, Dana, Nobody, Elsewhere}

// Settings is what scripts/test-oidc.sh generated for this run.
type Settings struct {
	Issuer       string `json:"issuer"`
	ClientID     string `json:"clientId"`
	ClientSecret string `json:"clientSecret"`
	PublicURL    string `json:"publicUrl"`
	Password     string `json:"password"`
}

// Get returns the running Dex's settings. A missing environment fails the
// test rather than skipping it, so CI cannot pass without these tests.
func Get(t testing.TB) Settings {
	t.Helper()
	dir := os.Getenv(DirVar)
	if dir == "" {
		t.Fatalf("%s is not set; run `make test-oidc`", DirVar)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "env.json")) //nolint:gosec // test environment directory from the test runner
	if err != nil {
		t.Fatalf("ssotest: %v", err)
	}
	var s Settings
	if err := json.Unmarshal(raw, &s); err != nil {
		t.Fatalf("ssotest: %v", err)
	}
	return s
}

var formAction = regexp.MustCompile(`<form[^>]*action="([^"]*)"`)

// SignIn opens authURL in a fresh browser, signs in to Dex as email, and
// returns where Dex sends the browser back: the EasyRMM callback with the
// code and state. Dex shows its error page instead for a bad password,
// which fails the test.
func (s Settings) SignIn(t testing.TB, authURL, email string) *url.URL {
	t.Helper()
	u, err := s.signIn(authURL, email, s.Password)
	if err != nil {
		t.Fatalf("ssotest: signing in to Dex as %s: %v", email, err)
	}
	return u
}

func (s Settings) signIn(authURL, email, password string) (*url.URL, error) {
	jar, _ := cookiejar.New(nil)
	var back *url.URL
	c := &http.Client{Jar: jar, Timeout: 20 * time.Second, CheckRedirect: func(r *http.Request, _ []*http.Request) error {
		if r.URL.Path == callbackPath {
			back = r.URL
			return http.ErrUseLastResponse
		}
		return nil
	}}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, authURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	page, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	_ = resp.Body.Close()
	if back != nil {
		return back, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, errors.New("Dex answered " + resp.Status + ": " + string(page))
	}
	m := formAction.FindSubmatch(page)
	if m == nil {
		return nil, errors.New("no sign-in form on Dex's page")
	}
	action, err := resp.Request.URL.Parse(strings.ReplaceAll(string(m[1]), "&amp;", "&"))
	if err != nil {
		return nil, err
	}
	req, err = http.NewRequestWithContext(context.Background(), http.MethodPost, action.String(),
		strings.NewReader(url.Values{"login": {email}, "password": {password}}.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err = c.Do(req)
	if err != nil {
		return nil, err
	}
	page, _ = io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	_ = resp.Body.Close()
	if back == nil {
		return nil, errors.New("Dex did not send the browser back (" + resp.Status + "): " + string(page))
	}
	return back, nil
}
