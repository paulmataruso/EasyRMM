//go:build integration

package app_test

import (
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const adminPassword = "correct horse battery staple"

// setUp completes first-run setup and returns a signed-in super admin and
// their TOTP secret.
func setUp(t *testing.T, h *harness) (*client, string) {
	t.Helper()
	c := h.client()
	token, err := os.ReadFile(filepath.Join(h.dataDir, "setup-token"))
	if err != nil {
		t.Fatal(err)
	}
	c.expect(http.StatusNoContent, "POST", "/api/v1/setup", map[string]string{
		"token": strings.TrimSpace(string(token)), "email": "admin@msp.example", "displayName": "Ada Admin",
		"password": adminPassword, "organizationName": "Acme",
	}, nil)
	return c, c.signIn("admin@msp.example", adminPassword, "")
}

// enroll signs in a user who must enroll TOTP and returns the secret and
// recovery codes.
func (c *client) enroll(email, password string) (string, []string) {
	t := c.h.t
	t.Helper()
	var s sessionView
	c.expect(http.StatusOK, "POST", "/api/v1/auth/login", map[string]string{"email": email, "password": password}, &s)
	c.csrf = s.CSRFToken
	var enr struct {
		Secret string `json:"secret"`
	}
	c.expect(http.StatusOK, "POST", "/api/v1/auth/mfa/totp/begin", map[string]string{}, &enr)
	var done struct {
		RecoveryCodes []string    `json:"recoveryCodes"`
		Session       sessionView `json:"session"`
	}
	c.expect(http.StatusOK, "POST", "/api/v1/auth/mfa/totp/confirm", map[string]string{"code": code(t, enr.Secret, time.Now())}, &done)
	c.csrf = done.Session.CSRFToken
	return enr.Secret, done.RecoveryCodes
}

// invite creates a user with the given assignments and sets their password.
func invite(t *testing.T, h *harness, admin *client, email string, assignments []map[string]any) string {
	t.Helper()
	var inv struct {
		User struct {
			ID string `json:"id"`
		} `json:"user"`
		Link string `json:"link"`
	}
	admin.expect(http.StatusCreated, "POST", "/api/v1/users", map[string]any{
		"email": email, "displayName": "User " + email, "assignments": assignments,
	}, &inv)
	_, tok, ok := strings.Cut(inv.Link, "#token=")
	if !ok {
		t.Fatalf("no token in invite link %q", inv.Link)
	}
	h.client().expect(http.StatusNoContent, "POST", "/api/v1/auth/password-reset/complete", map[string]string{"token": tok, "password": "a long and unusual passphrase"}, nil)
	return inv.User.ID
}

func orgID(t *testing.T, c *client, name string) string {
	t.Helper()
	var orgs struct {
		Items []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"items"`
	}
	c.expect(http.StatusOK, "GET", "/api/v1/organizations?q="+url.QueryEscape(name), nil, &orgs)
	for _, o := range orgs.Items {
		if o.Name == name {
			return o.ID
		}
	}
	t.Fatalf("organization %q not found", name)
	return ""
}

func wantStatus(t *testing.T, r response, status int, code string) {
	t.Helper()
	if r.status != status {
		t.Fatalf("status %d, want %d: %s", r.status, status, r.body)
	}
	if code != "" {
		if got := r.errorCode(t); got != code {
			t.Fatalf("error code %q, want %q: %s", got, code, r.body)
		}
	}
}

func TestAuthAPI(t *testing.T) {
	h := newHarness(t, false)
	anon := h.client()

	var opts struct {
		PasswordResetAvailable bool `json:"passwordResetAvailable"`
		MFARequired            bool `json:"mfaRequired"`
		PasswordMinLength      int  `json:"passwordMinLength"`
	}
	anon.expect(http.StatusOK, "GET", "/api/v1/auth/options", nil, &opts)
	if opts.PasswordResetAvailable || !opts.MFARequired || opts.PasswordMinLength != 12 {
		t.Fatalf("options: %+v", opts)
	}
	wantStatus(t, anon.do("GET", "/api/v1/auth/session", nil), http.StatusUnauthorized, "unauthenticated")
	wantStatus(t, anon.do("POST", "/api/v1/auth/login", map[string]string{"email": " ", "password": ""}), http.StatusUnprocessableEntity, "validation_failed")
	wantStatus(t, anon.do("POST", "/api/v1/auth/login", nil), http.StatusUnsupportedMediaType, "unsupported_media_type")
	wantStatus(t, anon.do("POST", "/api/v1/auth/login", nil, func(r *http.Request) {
		r.Header.Set("Content-Type", "application/json")
		r.Body = http.NoBody
	}), http.StatusBadRequest, "bad_request")
	wantStatus(t, anon.do("POST", "/api/v1/auth/password-reset/request", map[string]string{"email": "a@b.example"}), http.StatusNotFound, "reset_unavailable")
	wantStatus(t, anon.do("POST", "/api/v1/auth/password-reset/complete", map[string]string{"token": "nope", "password": "whatever whatever"}), http.StatusBadRequest, "invalid_reset_token")
	wantStatus(t, anon.do("POST", "/api/v1/auth/password-reset/request", map[string]any{"email": 1}), http.StatusUnprocessableEntity, "")
	wantStatus(t, anon.do("POST", "/api/v1/auth/password-reset/complete", "x"), http.StatusBadRequest, "")
	anon.expect(http.StatusNoContent, "POST", "/api/v1/auth/logout", nil, nil) // no session: still fine

	admin, _ := setUp(t, h)
	acme := orgID(t, admin, "Acme")
	userID := invite(t, h, admin, "rita@acme.example", []map[string]any{{"role": "technician", "organizationId": acme}})

	rita := h.client()
	secret, codes := rita.enroll("rita@acme.example", "a long and unusual passphrase")
	if len(codes) != 10 {
		t.Fatalf("recovery codes: %d", len(codes))
	}
	// Enrollment is over: neither enrollment step nor MFA verification applies.
	wantStatus(t, rita.do("POST", "/api/v1/auth/mfa/totp/begin", map[string]string{}), http.StatusConflict, "wrong_state")
	wantStatus(t, rita.do("POST", "/api/v1/auth/mfa/totp/confirm", map[string]string{"code": "123456"}), http.StatusConflict, "wrong_state")
	wantStatus(t, rita.do("POST", "/api/v1/auth/mfa/verify", map[string]string{"code": "123456"}), http.StatusForbidden, "mfa_required")
	wantStatus(t, rita.do("POST", "/api/v1/auth/mfa/verify", "x"), http.StatusForbidden, "mfa_required")

	var sl struct {
		Items []struct {
			ID      string `json:"id"`
			Current bool   `json:"current"`
		} `json:"items"`
	}
	rita.expect(http.StatusOK, "GET", "/api/v1/auth/sessions", nil, &sl)
	if len(sl.Items) != 1 {
		t.Fatalf("sessions: %+v", sl.Items)
	}
	first := sl.Items[0].ID

	// Signing in again in the same browser replaces the session; the
	// second factor can be a recovery code.
	var s sessionView
	rita.expect(http.StatusOK, "POST", "/api/v1/auth/login", map[string]string{"email": "rita@acme.example", "password": "a long and unusual passphrase"}, &s)
	if s.State != "mfa_required" {
		t.Fatalf("state %q", s.State)
	}
	rita.csrf = s.CSRFToken
	wantStatus(t, rita.do("POST", "/api/v1/auth/mfa/verify", map[string]string{"code": "000000"}), http.StatusUnauthorized, "invalid_code")
	wantStatus(t, rita.do("POST", "/api/v1/auth/mfa/verify", "x"), http.StatusBadRequest, "")
	rita.expect(http.StatusOK, "POST", "/api/v1/auth/mfa/verify", map[string]string{"code": codes[0]}, &s)
	if s.State != "active" {
		t.Fatalf("after recovery code: %q", s.State)
	}
	rita.csrf = s.CSRFToken
	rita.expect(http.StatusOK, "GET", "/api/v1/auth/sessions", nil, &sl)
	if len(sl.Items) != 1 || sl.Items[0].ID == first || !sl.Items[0].Current {
		t.Fatalf("old session not replaced: %+v", sl.Items)
	}

	// A used recovery code does not work twice.
	other := h.client()
	other.expect(http.StatusOK, "POST", "/api/v1/auth/login", map[string]string{"email": "rita@acme.example", "password": "a long and unusual passphrase"}, &s)
	other.csrf = s.CSRFToken
	wantStatus(t, other.do("POST", "/api/v1/auth/mfa/verify", map[string]string{"code": codes[0]}), http.StatusUnauthorized, "invalid_code")
	other.expect(http.StatusOK, "POST", "/api/v1/auth/mfa/verify", map[string]string{"code": code(t, secret, time.Now().Add(30*time.Second))}, &s)
	other.csrf = s.CSRFToken

	// Recovery codes can be regenerated with the password; the old set dies.
	wantStatus(t, rita.do("POST", "/api/v1/auth/mfa/recovery-codes", map[string]string{"password": "wrong password here"}), http.StatusUnprocessableEntity, "validation_failed")
	wantStatus(t, rita.do("POST", "/api/v1/auth/mfa/recovery-codes", "x"), http.StatusBadRequest, "")
	var regen struct {
		RecoveryCodes []string `json:"recoveryCodes"`
	}
	rita.expect(http.StatusOK, "POST", "/api/v1/auth/mfa/recovery-codes", map[string]string{"password": "a long and unusual passphrase"}, &regen)
	if len(regen.RecoveryCodes) != 10 || regen.RecoveryCodes[0] == codes[1] {
		t.Fatalf("regenerated codes: %v", regen.RecoveryCodes)
	}
	third := h.client()
	third.expect(http.StatusOK, "POST", "/api/v1/auth/login", map[string]string{"email": "rita@acme.example", "password": "a long and unusual passphrase"}, &s)
	third.csrf = s.CSRFToken
	wantStatus(t, third.do("POST", "/api/v1/auth/mfa/verify", map[string]string{"code": codes[1]}), http.StatusUnauthorized, "invalid_code")
	third.expect(http.StatusOK, "POST", "/api/v1/auth/mfa/verify", map[string]string{"code": regen.RecoveryCodes[0]}, &s)
	third.csrf = s.CSRFToken

	// Sessions belonging to someone else, or not existing, are not found.
	var adminSessions struct {
		Items []struct {
			ID string `json:"id"`
		} `json:"items"`
	}
	admin.expect(http.StatusOK, "GET", "/api/v1/auth/sessions", nil, &adminSessions)
	wantStatus(t, rita.do("DELETE", "/api/v1/auth/sessions/"+adminSessions.Items[0].ID, nil), http.StatusNotFound, "not_found")
	wantStatus(t, rita.do("DELETE", "/api/v1/auth/sessions/00000000-0000-0000-0000-000000000001", nil), http.StatusNotFound, "not_found")
	wantStatus(t, rita.do("DELETE", "/api/v1/auth/sessions/not-a-uuid", nil), http.StatusNotFound, "not_found")

	// Password change: field-level errors, then success signs out the rest.
	wantStatus(t, rita.do("POST", "/api/v1/auth/password", map[string]string{"currentPassword": "not my password", "newPassword": "another long passphrase"}), http.StatusUnprocessableEntity, "validation_failed")
	if r := rita.do("POST", "/api/v1/auth/password", map[string]string{"currentPassword": "not my password", "newPassword": "x"}); !strings.Contains(string(r.body), `"newPassword"`) {
		t.Fatalf("weak new password: %s", r.body)
	}
	if r := rita.do("POST", "/api/v1/auth/password", map[string]string{"currentPassword": "not my password", "newPassword": "another long passphrase"}); !strings.Contains(string(r.body), `"currentPassword"`) {
		t.Fatalf("wrong current password: %s", r.body)
	}
	wantStatus(t, rita.do("POST", "/api/v1/auth/password", "x"), http.StatusBadRequest, "")
	before := rita.csrf
	var changed struct {
		CSRFToken string `json:"csrfToken"`
		State     string `json:"state"`
	}
	rita.expect(http.StatusOK, "POST", "/api/v1/auth/password", map[string]string{"currentPassword": "a long and unusual passphrase", "newPassword": "another long passphrase"}, &changed)
	// This session continues under a new token and CSRF token; the old CSRF
	// token is refused.
	if changed.State != "active" || changed.CSRFToken == "" || changed.CSRFToken == before {
		t.Fatalf("session after a password change: %+v", changed)
	}
	wantStatus(t, rita.do("POST", "/api/v1/auth/mfa/recovery-codes", map[string]string{"password": "another long passphrase"}), http.StatusForbidden, "csrf_failed")
	rita.csrf = changed.CSRFToken
	wantStatus(t, other.do("GET", "/api/v1/auth/session", nil), http.StatusUnauthorized, "")
	wantStatus(t, third.do("GET", "/api/v1/auth/session", nil), http.StatusUnauthorized, "")
	rita.expect(http.StatusOK, "GET", "/api/v1/auth/session", nil, nil)

	// Revoking the current session clears the cookie.
	rita.expect(http.StatusOK, "GET", "/api/v1/auth/sessions", nil, &sl)
	r := rita.expect(http.StatusNoContent, "DELETE", "/api/v1/auth/sessions/"+sl.Items[0].ID, nil, nil)
	if sc := r.header.Get("Set-Cookie"); !strings.Contains(sc, "Max-Age=0") {
		t.Fatalf("cookie not cleared: %q", sc)
	}
	wantStatus(t, rita.do("GET", "/api/v1/auth/session", nil), http.StatusUnauthorized, "")

	// A disabled account's credentials no longer open a session.
	admin.expect(http.StatusOK, "POST", "/api/v1/users/"+userID+"/disable", nil, nil)
	wantStatus(t, h.client().do("POST", "/api/v1/auth/login", map[string]string{"email": "rita@acme.example", "password": "another long passphrase"}), http.StatusUnauthorized, "invalid_credentials")
}

func TestAuthAPIEnrollmentErrors(t *testing.T) {
	h := newHarness(t, false)
	admin, _ := setUp(t, h)
	acme := orgID(t, admin, "Acme")
	invite(t, h, admin, "sam@acme.example", []map[string]any{{"role": "read_only", "organizationId": acme}})
	sam := h.client()
	var s sessionView
	sam.expect(http.StatusOK, "POST", "/api/v1/auth/login", map[string]string{"email": "sam@acme.example", "password": "a long and unusual passphrase"}, &s)
	sam.csrf = s.CSRFToken
	// Confirming before beginning, and malformed bodies.
	wantStatus(t, sam.do("POST", "/api/v1/auth/mfa/totp/confirm", map[string]string{"code": "123456"}), http.StatusConflict, "wrong_state")
	wantStatus(t, sam.do("POST", "/api/v1/auth/mfa/totp/confirm", "x"), http.StatusBadRequest, "")
	// Half-signed-in sessions cannot use active-only endpoints.
	wantStatus(t, sam.do("GET", "/api/v1/auth/sessions", nil), http.StatusForbidden, "mfa_required")
	sam.expect(http.StatusOK, "GET", "/api/v1/auth/session", nil, &s)
	if s.State != "mfa_enrollment" || len(s.Permissions) != 0 {
		t.Fatalf("enrollment session view: %+v", s)
	}
	sam.expect(http.StatusNoContent, "POST", "/api/v1/auth/logout", nil, nil)
	wantStatus(t, sam.do("GET", "/api/v1/auth/session", nil), http.StatusUnauthorized, "")
}

func TestTenancyAPI(t *testing.T) {
	h := newHarness(t, false)
	admin, _ := setUp(t, h)

	var org struct {
		ID        string `json:"id"`
		Name      string `json:"name"`
		Notes     string `json:"notes"`
		SiteCount int    `json:"siteCount"`
	}
	admin.expect(http.StatusCreated, "POST", "/api/v1/organizations", map[string]string{"name": "Initech", "notes": "staplers"}, &org)
	wantStatus(t, admin.do("POST", "/api/v1/organizations", "x"), http.StatusBadRequest, "")
	var list struct {
		Items []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"items"`
	}
	admin.expect(http.StatusOK, "GET", "/api/v1/organizations?q=init", nil, &list)
	if len(list.Items) != 1 || list.Items[0].ID != org.ID {
		t.Fatalf("search: %+v", list.Items)
	}
	admin.expect(http.StatusOK, "GET", "/api/v1/organizations/"+org.ID, nil, &org)
	if org.Notes != "staplers" {
		t.Fatalf("get: %+v", org)
	}
	admin.expect(http.StatusOK, "PUT", "/api/v1/organizations/"+org.ID, map[string]string{"name": "Initech LLC"}, &org)
	if org.Name != "Initech LLC" || org.Notes != "" {
		t.Fatalf("update: %+v", org)
	}
	wantStatus(t, admin.do("PUT", "/api/v1/organizations/"+org.ID, map[string]string{"name": ""}), http.StatusUnprocessableEntity, "validation_failed")
	wantStatus(t, admin.do("PUT", "/api/v1/organizations/"+org.ID, "x"), http.StatusBadRequest, "")
	for _, p := range []string{"/api/v1/organizations/nope", "/api/v1/organizations/nope/sites", "/api/v1/sites/nope", "/api/v1/sites/nope/device-groups"} {
		wantStatus(t, admin.do("GET", p, nil), http.StatusNotFound, "not_found")
	}
	for _, c := range []struct{ m, p string }{
		{"PUT", "/api/v1/organizations/nope"}, {"DELETE", "/api/v1/organizations/nope"},
		{"POST", "/api/v1/organizations/nope/sites"}, {"PUT", "/api/v1/sites/nope"}, {"DELETE", "/api/v1/sites/nope"},
		{"POST", "/api/v1/sites/nope/device-groups"}, {"PUT", "/api/v1/device-groups/nope"}, {"DELETE", "/api/v1/device-groups/nope"},
	} {
		wantStatus(t, admin.do(c.m, c.p, map[string]string{"name": "x"}), http.StatusNotFound, "not_found")
	}
	wantStatus(t, admin.do("GET", "/api/v1/sites?organizationId=nope", nil), http.StatusUnprocessableEntity, "validation_failed")

	var site struct {
		ID               string `json:"id"`
		OrganizationID   string `json:"organizationId"`
		OrganizationName string `json:"organizationName"`
		Name             string `json:"name"`
		Timezone         string `json:"timezone"`
		DeviceGroupCount int    `json:"deviceGroupCount"`
	}
	admin.expect(http.StatusCreated, "POST", "/api/v1/organizations/"+org.ID+"/sites", map[string]string{"name": "Austin", "timezone": "America/Chicago"}, &site)
	wantStatus(t, admin.do("POST", "/api/v1/organizations/"+org.ID+"/sites", "x"), http.StatusBadRequest, "")
	if site.OrganizationName != "Initech LLC" || site.Timezone != "America/Chicago" {
		t.Fatalf("site: %+v", site)
	}
	admin.expect(http.StatusOK, "GET", "/api/v1/sites?organizationId="+org.ID+"&q=aus", nil, &list)
	if len(list.Items) != 1 {
		t.Fatalf("site filter: %+v", list.Items)
	}
	admin.expect(http.StatusOK, "GET", "/api/v1/sites", nil, &list)
	if len(list.Items) != 1 {
		t.Fatalf("all sites: %+v", list.Items)
	}
	admin.expect(http.StatusOK, "GET", "/api/v1/organizations/"+org.ID+"/sites?q=zzz", nil, &list)
	if len(list.Items) != 0 {
		t.Fatalf("org sites search: %+v", list.Items)
	}
	admin.expect(http.StatusOK, "PUT", "/api/v1/sites/"+site.ID, map[string]string{"name": "Austin HQ"}, &site)
	if site.Name != "Austin HQ" || site.Timezone != "UTC" {
		t.Fatalf("site update: %+v", site)
	}
	wantStatus(t, admin.do("PUT", "/api/v1/sites/"+site.ID, "x"), http.StatusBadRequest, "")

	var group struct {
		ID          string `json:"id"`
		Name        string `json:"name"`
		Description string `json:"description"`
	}
	admin.expect(http.StatusCreated, "POST", "/api/v1/sites/"+site.ID+"/device-groups", map[string]string{"name": "Laptops", "description": "Field staff"}, &group)
	wantStatus(t, admin.do("POST", "/api/v1/sites/"+site.ID+"/device-groups", "x"), http.StatusBadRequest, "")
	admin.expect(http.StatusOK, "GET", "/api/v1/sites/"+site.ID+"/device-groups", nil, &list)
	if len(list.Items) != 1 {
		t.Fatalf("groups: %+v", list.Items)
	}
	admin.expect(http.StatusOK, "PUT", "/api/v1/device-groups/"+group.ID, map[string]string{"name": "Notebooks"}, &group)
	if group.Name != "Notebooks" || group.Description != "" {
		t.Fatalf("group update: %+v", group)
	}
	wantStatus(t, admin.do("PUT", "/api/v1/device-groups/"+group.ID, "x"), http.StatusBadRequest, "")
	admin.expect(http.StatusOK, "GET", "/api/v1/sites/"+site.ID, nil, &site)
	if site.DeviceGroupCount != 1 {
		t.Fatalf("group count: %+v", site)
	}
	admin.expect(http.StatusNoContent, "DELETE", "/api/v1/device-groups/"+group.ID, nil, nil)
	admin.expect(http.StatusNoContent, "DELETE", "/api/v1/sites/"+site.ID, nil, nil)
	admin.expect(http.StatusNoContent, "DELETE", "/api/v1/organizations/"+org.ID, nil, nil)
	wantStatus(t, admin.do("GET", "/api/v1/organizations/"+org.ID, nil), http.StatusNotFound, "not_found")
}

type userView struct {
	ID          string `json:"id"`
	Email       string `json:"email"`
	DisplayName string `json:"displayName"`
	Status      string `json:"status"`
	PasswordSet bool   `json:"passwordSet"`
	MFAEnabled  bool   `json:"mfaEnabled"`
	Assignments []struct {
		Role           string `json:"role"`
		OrganizationID string `json:"organizationId"`
	} `json:"assignments"`
}

func TestUsersAPI(t *testing.T) {
	h := newHarness(t, false)
	admin, _ := setUp(t, h)
	acme := orgID(t, admin, "Acme")

	var roles struct {
		Items []struct {
			Role        string   `json:"role"`
			Rank        int      `json:"rank"`
			Scopes      []string `json:"scopes"`
			Permissions []string `json:"permissions"`
		} `json:"items"`
	}
	admin.expect(http.StatusOK, "GET", "/api/v1/roles", nil, &roles)
	// The five built-in roles, then the recovery-key add-ons (ADR-0081).
	if len(roles.Items) != 7 || roles.Items[0].Role != "super_admin" || roles.Items[0].Scopes[0] != "global" || roles.Items[4].Role != "read_only" ||
		roles.Items[5].Role != "key_approver" || roles.Items[6].Role != "key_reader" {
		t.Fatalf("roles: %+v", roles.Items)
	}
	for _, r := range roles.Items[5:] {
		if len(r.Permissions) != 1 {
			t.Fatalf("an add-on role grants one permission: %+v", r)
		}
	}
	for i := 1; i < len(roles.Items); i++ {
		if roles.Items[i].Rank > roles.Items[i-1].Rank {
			t.Fatal("roles not ordered by rank")
		}
	}
	if s := roles.Items[2].Scopes; len(s) != 2 || s[0] != "organization" || s[1] != "site" {
		t.Fatalf("site admin scopes: %v", s)
	}

	var inv struct {
		User    userView `json:"user"`
		Link    string   `json:"link"`
		Emailed bool     `json:"emailed"`
	}
	wantStatus(t, admin.do("POST", "/api/v1/users", "x"), http.StatusBadRequest, "")
	for _, e := range []string{"b@acme.example", "c@acme.example", "d@other.example"} {
		admin.expect(http.StatusCreated, "POST", "/api/v1/users", map[string]any{
			"email": e, "displayName": "Person " + e[:1],
			"assignments": []map[string]any{{"role": "technician", "organizationId": acme}},
		}, &inv)
	}
	if inv.Emailed || inv.Link == "" || inv.User.PasswordSet {
		t.Fatalf("invite: %+v", inv)
	}
	d := inv.User.ID

	var page struct {
		Items []userView `json:"items"`
		Next  string     `json:"next"`
	}
	admin.expect(http.StatusOK, "GET", "/api/v1/users?limit=2", nil, &page)
	if len(page.Items) != 2 || page.Next == "" || page.Items[0].Email != "admin@msp.example" {
		t.Fatalf("page 1: %+v", page)
	}
	next := page.Next
	page = struct {
		Items []userView `json:"items"`
		Next  string     `json:"next"`
	}{}
	admin.expect(http.StatusOK, "GET", "/api/v1/users?limit=2&after="+url.QueryEscape(next), nil, &page)
	if len(page.Items) != 2 || page.Items[0].Email != "c@acme.example" || page.Next != "" {
		t.Fatalf("page 2: %+v", page)
	}
	admin.expect(http.StatusOK, "GET", "/api/v1/users?q=OTHER", nil, &page)
	if len(page.Items) != 1 || page.Items[0].ID != d {
		t.Fatalf("search: %+v", page)
	}
	admin.expect(http.StatusOK, "GET", "/api/v1/users?organizationId="+acme, nil, &page)
	if len(page.Items) != 3 {
		t.Fatalf("org filter: %+v", page.Items)
	}
	wantStatus(t, admin.do("GET", "/api/v1/users?limit=0", nil), http.StatusUnprocessableEntity, "validation_failed")
	wantStatus(t, admin.do("GET", "/api/v1/users?limit=abc", nil), http.StatusUnprocessableEntity, "validation_failed")
	wantStatus(t, admin.do("GET", "/api/v1/users?organizationId=nope", nil), http.StatusUnprocessableEntity, "validation_failed")
	wantStatus(t, admin.do("GET", "/api/v1/users?after=%21%21%21", nil), http.StatusUnprocessableEntity, "")

	var u userView
	admin.expect(http.StatusOK, "GET", "/api/v1/users/"+d, nil, &u)
	if u.Email != "d@other.example" || len(u.Assignments) != 1 || u.Assignments[0].Role != "technician" {
		t.Fatalf("get: %+v", u)
	}
	admin.expect(http.StatusOK, "PATCH", "/api/v1/users/"+d, map[string]string{"displayName": "Dana"}, &u)
	if u.DisplayName != "Dana" {
		t.Fatalf("patch: %+v", u)
	}
	admin.expect(http.StatusOK, "PUT", "/api/v1/users/"+d+"/roles", map[string]any{
		"assignments": []map[string]any{{"role": "org_admin", "organizationId": acme}},
	}, &u)
	if len(u.Assignments) != 1 || u.Assignments[0].Role != "org_admin" {
		t.Fatalf("roles: %+v", u)
	}
	admin.expect(http.StatusOK, "POST", "/api/v1/users/"+d+"/disable", nil, &u)
	if u.Status != "disabled" {
		t.Fatalf("disable: %+v", u)
	}
	wantStatus(t, admin.do("POST", "/api/v1/users/"+d+"/password-link", nil), http.StatusConflict, "user_disabled")
	admin.expect(http.StatusOK, "POST", "/api/v1/users/"+d+"/enable", nil, &u)
	if u.Status != "active" {
		t.Fatalf("enable: %+v", u)
	}
	admin.expect(http.StatusOK, "POST", "/api/v1/users/"+d+"/unlock", nil, &u)
	admin.expect(http.StatusOK, "POST", "/api/v1/users/"+d+"/reset-mfa", nil, &u)
	if u.MFAEnabled {
		t.Fatalf("reset-mfa: %+v", u)
	}
	var link struct {
		Link    string   `json:"link"`
		Emailed bool     `json:"emailed"`
		User    userView `json:"user"`
	}
	admin.expect(http.StatusOK, "POST", "/api/v1/users/"+d+"/password-link", nil, &link)
	if link.Emailed || !strings.Contains(link.Link, "/welcome#token=") || link.User.ID != d {
		t.Fatalf("password link: %+v", link)
	}
	for _, c := range []struct{ m, p string }{
		{"GET", "/api/v1/users/nope"}, {"PATCH", "/api/v1/users/nope"}, {"PUT", "/api/v1/users/nope/roles"},
		{"POST", "/api/v1/users/nope/disable"}, {"POST", "/api/v1/users/nope/unlock"}, {"POST", "/api/v1/users/nope/reset-mfa"},
		{"POST", "/api/v1/users/nope/password-link"}, {"DELETE", "/api/v1/users/nope"},
	} {
		var body any
		switch c.m {
		case "PATCH":
			body = map[string]string{"displayName": "x"}
		case "PUT":
			body = map[string]any{"assignments": []any{}}
		}
		wantStatus(t, admin.do(c.m, c.p, body), http.StatusNotFound, "not_found")
	}
	wantStatus(t, admin.do("PATCH", "/api/v1/users/"+d, "x"), http.StatusBadRequest, "")
	wantStatus(t, admin.do("PUT", "/api/v1/users/"+d+"/roles", "x"), http.StatusBadRequest, "")
	wantStatus(t, admin.do("PATCH", "/api/v1/users/"+d, map[string]string{"displayName": ""}), http.StatusUnprocessableEntity, "validation_failed")
	wantStatus(t, admin.do("PUT", "/api/v1/users/"+d+"/roles", map[string]any{"assignments": []map[string]any{{"role": "nope"}}}), http.StatusUnprocessableEntity, "validation_failed")

	admin.expect(http.StatusNoContent, "DELETE", "/api/v1/users/"+d, nil, nil)
	wantStatus(t, admin.do("GET", "/api/v1/users/"+d, nil), http.StatusNotFound, "not_found")

	// The signed-in user edits their own profile.
	admin.expect(http.StatusNoContent, "PATCH", "/api/v1/me", map[string]string{"displayName": "Ada Lovelace"}, nil)
	wantStatus(t, admin.do("PATCH", "/api/v1/me", map[string]string{"displayName": " "}), http.StatusUnprocessableEntity, "validation_failed")
	wantStatus(t, admin.do("PATCH", "/api/v1/me", "x"), http.StatusBadRequest, "")
	var s struct {
		User struct {
			DisplayName string `json:"displayName"`
		} `json:"user"`
	}
	admin.expect(http.StatusOK, "GET", "/api/v1/auth/session", nil, &s)
	if s.User.DisplayName != "Ada Lovelace" {
		t.Fatalf("own profile: %+v", s)
	}

	var st struct {
		Required          bool `json:"required"`
		PasswordMinLength int  `json:"passwordMinLength"`
	}
	admin.expect(http.StatusOK, "GET", "/api/v1/setup", nil, &st)
	if st.Required || st.PasswordMinLength != 12 {
		t.Fatalf("setup status: %+v", st)
	}
	wantStatus(t, admin.do("POST", "/api/v1/setup", "x"), http.StatusBadRequest, "")
	wantStatus(t, admin.do("POST", "/api/v1/setup", map[string]string{"token": "x"}), http.StatusConflict, "setup_complete")
	wantStatus(t, admin.do("POST", "/api/v1/users", map[string]any{"email": "bad", "displayName": "", "assignments": []any{}}), http.StatusUnprocessableEntity, "validation_failed")
	wantStatus(t, admin.do("POST", "/api/v1/users/"+u.ID+"/disable", nil), http.StatusNotFound, "not_found")
}

type auditEntry struct {
	ID             int64   `json:"id"`
	Action         string  `json:"action"`
	ActorID        *string `json:"actorId"`
	OrganizationID *string `json:"organizationId"`
}

type auditPage struct {
	Items []auditEntry `json:"items"`
	Next  string       `json:"next"`
}

func TestAuditAPI(t *testing.T) {
	h := newHarness(t, false)
	admin, _ := setUp(t, h)
	acme := orgID(t, admin, "Acme")
	var other struct {
		ID string `json:"id"`
	}
	admin.expect(http.StatusCreated, "POST", "/api/v1/organizations", map[string]string{"name": "Globex"}, &other)
	admin.expect(http.StatusOK, "PUT", "/api/v1/organizations/"+other.ID, map[string]string{"name": "Globex Corp"}, nil)
	var me sessionView
	admin.expect(http.StatusOK, "GET", "/api/v1/auth/session", nil, &me)

	var p auditPage
	admin.expect(http.StatusOK, "GET", "/api/v1/audit?organizationId="+other.ID, nil, &p)
	if len(p.Items) != 2 {
		t.Fatalf("org filter: %+v", p.Items)
	}
	for _, e := range p.Items {
		if e.OrganizationID == nil || *e.OrganizationID != other.ID {
			t.Fatalf("org filter leaked %+v", e)
		}
	}
	admin.expect(http.StatusOK, "GET", "/api/v1/audit?actorId="+me.User.ID, nil, &p)
	for _, e := range p.Items {
		if e.ActorID == nil || *e.ActorID != me.User.ID {
			t.Fatalf("actor filter leaked %+v", e)
		}
	}
	admin.expect(http.StatusOK, "GET", "/api/v1/audit?action=organization", nil, &p)
	if len(p.Items) != 3 { // Acme at setup, Globex create and update
		t.Fatalf("action prefix: %+v", p.Items)
	}
	admin.expect(http.StatusOK, "GET", "/api/v1/audit?action=organization.create", nil, &p)
	if len(p.Items) != 2 {
		t.Fatalf("exact action: %+v", p.Items)
	}
	admin.expect(http.StatusOK, "GET", "/api/v1/audit?action=organization.cr", nil, &p)
	if len(p.Items) != 0 {
		t.Fatalf("partial word matched: %+v", p.Items)
	}
	admin.expect(http.StatusOK, "GET", "/api/v1/audit?deviceId=00000000-0000-0000-0000-000000000001", nil, &p)
	if len(p.Items) != 0 {
		t.Fatalf("device filter: %+v", p.Items)
	}

	// Keyset pagination.
	var first, second auditPage
	admin.expect(http.StatusOK, "GET", "/api/v1/audit?limit=1", nil, &first)
	if len(first.Items) != 1 || first.Next == "" {
		t.Fatalf("page 1: %+v", first)
	}
	admin.expect(http.StatusOK, "GET", "/api/v1/audit?limit=1&before="+first.Next, nil, &second)
	if len(second.Items) != 1 || second.Items[0].ID >= first.Items[0].ID {
		t.Fatalf("page 2: %+v after %+v", second, first)
	}
	p = auditPage{}
	admin.expect(http.StatusOK, "GET", "/api/v1/audit?limit=500", nil, &p)
	if p.Next != "" {
		t.Fatalf("last page has a cursor: %q", p.Next)
	}

	for _, q := range []string{"action=Org%25", "action=organization.%25", "action=" + strings.Repeat("a", 101), "action=.x", "limit=0", "limit=501",
		"before=-1", "before=x", "organizationId=x", "actorId=x", "deviceId=x"} {
		wantStatus(t, admin.do("GET", "/api/v1/audit?"+q, nil), http.StatusUnprocessableEntity, "validation_failed")
	}

	var v struct {
		Checked    int64  `json:"checked"`
		FirstBadID *int64 `json:"firstBadId"`
	}
	admin.expect(http.StatusOK, "GET", "/api/v1/audit/verify?after=0&limit=1", nil, &v)
	if v.Checked != 1 || v.FirstBadID != nil {
		t.Fatalf("verify: %+v", v)
	}
	for _, q := range []string{"after=-1", "limit=0", "limit=x"} {
		wantStatus(t, admin.do("GET", "/api/v1/audit/verify?"+q, nil), http.StatusUnprocessableEntity, "validation_failed")
	}

	// Technicians hold no audit.view.
	invite(t, h, admin, "tech@acme.example", []map[string]any{{"role": "technician", "organizationId": acme}})
	tech := h.client()
	tech.signIn("tech@acme.example", "a long and unusual passphrase", "")
	wantStatus(t, tech.do("GET", "/api/v1/audit", nil), http.StatusForbidden, "forbidden")
	wantStatus(t, tech.do("GET", "/api/v1/audit/verify", nil), http.StatusForbidden, "forbidden")
}
