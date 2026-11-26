//go:build integration

package app_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/paulmataruso/easyrmm/server/internal/quickassist"
)

// Quick Assist over HTTP (ADR-0080): the restricted mode, step-up for what
// needs it, the public page, and the console's requests and acceptance.
func TestHTTPQuickAssist(t *testing.T) {
	h := newHarness(t, false)
	admin, secret := setUp(t, h)
	acme := orgID(t, admin, "Acme")
	base := "/api/v1/organizations/" + acme + "/quickassist"

	var made struct {
		Token string `json:"token"`
		Path  string `json:"path"`
		Link  struct {
			ID   string `json:"id"`
			Test bool   `json:"test"`
		} `json:"link"`
	}
	admin.expect(http.StatusCreated, "POST", base+"/links", map[string]any{"kind": "one_time", "name": "Support for Acme"}, &made)
	if !made.Link.Test || !strings.HasPrefix(made.Token, "qal_") || made.Path != "/qa/"+made.Token {
		t.Fatalf("link: %+v", made)
	}
	var links struct {
		Links []map[string]any `json:"links"`
	}
	r := admin.expect(http.StatusOK, "GET", base+"/links", nil, &links)
	if len(links.Links) != 1 || strings.Contains(string(r.body), made.Token) {
		t.Fatalf("the list must not show the token: %s", r.body)
	}

	// A permanent link needs a second factor, and in the restricted mode is
	// refused even with one.
	wantStatus(t, admin.do("POST", base+"/links", map[string]any{"kind": "permanent"}), http.StatusUnauthorized, "step_up_required")
	wantStatus(t, admin.do("PUT", "/api/v1/quickassist/settings", map[string]string{"mode": "open"}), http.StatusUnauthorized, "step_up_required")
	admin.expect(http.StatusOK, "POST", "/api/v1/auth/step-up/totp", map[string]string{"code": code(t, secret, time.Now().Add(30*time.Second))}, nil)
	wantStatus(t, admin.do("POST", base+"/links", map[string]any{"kind": "permanent"}), http.StatusConflict, "test_links_only")
	wantStatus(t, admin.do("POST", base+"/links", map[string]any{"kind": "bogus"}), http.StatusUnprocessableEntity, "")
	var mode struct {
		Mode string `json:"mode"`
	}
	admin.expect(http.StatusOK, "GET", "/api/v1/quickassist/settings", nil, &mode)
	if mode.Mode != "own_test" {
		t.Fatalf("default mode %q", mode.Mode)
	}
	wantStatus(t, admin.do("PUT", "/api/v1/quickassist/settings", map[string]string{"mode": "x"}), http.StatusUnprocessableEntity, "")
	admin.expect(http.StatusOK, "PUT", "/api/v1/quickassist/settings", map[string]string{"mode": "open"}, nil)

	// The app-wide default lifetime of a new one-time link: set, read back,
	// and refused outside its bounds or when it is not JSON.
	admin.expect(http.StatusOK, "PUT", "/api/v1/quickassist/settings/default-life", map[string]int{"minutes": 90}, nil)
	var life struct {
		DefaultLifeMinutes int `json:"defaultLifeMinutes"`
	}
	admin.expect(http.StatusOK, "GET", "/api/v1/quickassist/settings", nil, &life)
	if life.DefaultLifeMinutes != 90 {
		t.Fatalf("default life %d, want 90", life.DefaultLifeMinutes)
	}
	wantStatus(t, admin.do("PUT", "/api/v1/quickassist/settings/default-life", map[string]int{"minutes": 0}), http.StatusUnprocessableEntity, "")
	wantStatus(t, admin.do("PUT", "/api/v1/quickassist/settings/default-life", map[string]int{"minutes": 7*24*60 + 1}), http.StatusUnprocessableEntity, "")
	wantStatus(t, admin.do("PUT", "/api/v1/quickassist/settings/default-life", "ninety"), http.StatusBadRequest, "")
	var perm struct {
		Link struct {
			ID string `json:"id"`
		} `json:"link"`
		Token string `json:"token"`
	}
	admin.expect(http.StatusCreated, "POST", base+"/links", map[string]any{"kind": "permanent", "name": "Help desk"}, &perm)
	admin.expect(http.StatusOK, "POST", "/api/v1/quickassist/links/"+perm.Link.ID+"/pause", map[string]bool{"paused": true}, nil)
	admin.expect(http.StatusOK, "POST", "/api/v1/quickassist/links/"+perm.Link.ID+"/pause", map[string]bool{"paused": false}, nil)
	admin.expect(http.StatusOK, "POST", "/api/v1/quickassist/links/"+perm.Link.ID+"/revoke", nil, nil)
	wantStatus(t, admin.do("POST", "/api/v1/quickassist/links/nope/revoke", nil), http.StatusNotFound, "")
	wantStatus(t, admin.do("POST", "/api/v1/quickassist/links/nope/pause", map[string]bool{"paused": true}), http.StatusNotFound, "")
	wantStatus(t, admin.do("POST", "/api/v1/quickassist/links/"+perm.Link.ID+"/pause", "yes"), http.StatusBadRequest, "")
	wantStatus(t, admin.do("POST", "/api/v1/quickassist/sessions/"+uuid.NewString()+"/install", nil), http.StatusNotFound, "")
	wantStatus(t, admin.do("POST", "/api/v1/quickassist/sessions/nope/install", nil), http.StatusNotFound, "")

	// The public page: no session needed, locked-down headers, and one answer
	// for every link that cannot be used.
	anon := h.client()
	page := anon.do("GET", made.Path, nil)
	if page.status != http.StatusOK || !strings.Contains(string(page.body), "Remote support from Acme") || !strings.Contains(string(page.body), "Support for Acme") {
		t.Fatalf("page: %d %s", page.status, page.body)
	}
	if csp := page.header.Get("Content-Security-Policy"); !strings.Contains(csp, "frame-ancestors 'none'") || page.header.Get("Referrer-Policy") != "no-referrer" {
		t.Errorf("headers: %q %q", csp, page.header.Get("Referrer-Policy"))
	}
	missing := anon.do("GET", "/qa/qal_"+strings.Repeat("A", 43), nil)
	revoked := anon.do("GET", "/qa/"+perm.Token, nil)
	if missing.status != http.StatusNotFound || revoked.status != http.StatusNotFound || string(missing.body) != string(revoked.body) {
		t.Fatalf("an oracle between a missing and a revoked link: %d %d", missing.status, revoked.status)
	}
	// No builds are served here, so there is nothing to download.
	wantStatus(t, anon.do("GET", made.Path+"/download?os=linux", nil), http.StatusNotFound, "")
	wantStatus(t, anon.do("GET", made.Path+"/download?os=plan9", nil), http.StatusBadRequest, "")

	// A session, as the runner's request makes it, then the console's view.
	tr, _, err := h.deps.QuickAssist.Download(context.Background(), netip.MustParseAddr("192.0.2.10"), made.Token)
	if err != nil {
		t.Fatal(err)
	}
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	res, err := h.deps.QuickAssist.Enroll(context.Background(), netip.MustParseAddr("192.0.2.10"), quickassist.EnrollRequest{
		Ticket: base64.StdEncoding.EncodeToString(tr), PublicKey: base64.StdEncoding.EncodeToString(pub), Code: "424242", Consent: true,
		Facts: quickassist.Facts{Hostname: "front-desk", Platform: "linux", Elevated: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	var waiting struct {
		Waiting int `json:"waiting"`
	}
	admin.expect(http.StatusOK, "GET", "/api/v1/quickassist/waiting", nil, &waiting)
	if waiting.Waiting != 1 {
		t.Fatalf("waiting %d", waiting.Waiting)
	}
	var sessions struct {
		Sessions []map[string]any `json:"sessions"`
	}
	r = admin.expect(http.StatusOK, "GET", base+"/sessions", nil, &sessions)
	if len(sessions.Sessions) != 1 || strings.Contains(string(r.body), "424242") {
		t.Fatalf("sessions: %s", r.body)
	}
	wantStatus(t, admin.do("GET", base+"/sessions?state=bogus", nil), http.StatusBadRequest, "")
	sid := res.SessionID
	wantStatus(t, admin.do("POST", "/api/v1/quickassist/sessions/"+sid+"/accept", map[string]string{"code": "000000"}), http.StatusUnprocessableEntity, "wrong_code")
	admin.expect(http.StatusOK, "POST", "/api/v1/quickassist/sessions/"+sid+"/accept", map[string]string{"code": "424242"}, nil)
	admin.expect(http.StatusOK, "GET", "/api/v1/quickassist/waiting", nil, &waiting)
	if waiting.Waiting != 0 {
		t.Fatalf("waiting after accept: %d", waiting.Waiting)
	}
	admin.expect(http.StatusNoContent, "POST", "/api/v1/quickassist/sessions/"+sid+"/takeover", nil, nil)
	admin.expect(http.StatusNoContent, "POST", "/api/v1/quickassist/sessions/"+sid+"/end", nil, nil)
	wantStatus(t, admin.do("POST", "/api/v1/quickassist/sessions/"+sid+"/end", nil), http.StatusConflict, "")
	wantStatus(t, admin.do("POST", "/api/v1/quickassist/sessions/"+sid+"/decline", nil), http.StatusConflict, "")
}
