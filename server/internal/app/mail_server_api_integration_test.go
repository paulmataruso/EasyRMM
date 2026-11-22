//go:build integration

package app_test

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/config"
	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/testmail"
)

type mailServerView struct {
	InForce string `json:"inForce"`
	Env     *struct {
		Host        string `json:"host"`
		SignIn      string `json:"signIn"`
		PasswordSet bool   `json:"passwordSet"`
		FromAddress string `json:"fromAddress"`
		FromName    string `json:"fromName"`
	} `json:"env"`
	Console *struct {
		Host        string `json:"host"`
		Port        int    `json:"port"`
		Security    string `json:"security"`
		SignIn      string `json:"signIn"`
		Username    string `json:"username"`
		PasswordSet bool   `json:"passwordSet"`
		FromAddress string `json:"fromAddress"`
		UpdatedBy   string `json:"updatedBy"`
	} `json:"console"`
	Limits struct {
		PerMinute int `json:"perMinute"`
		PerDay    int `json:"perDay"`
	} `json:"limits"`
	Usage struct {
		LastMinute     int `json:"lastMinute"`
		LastDay        int `json:"lastDay"`
		AccountLastDay int `json:"accountLastDay"`
		AdminDayLimit  int `json:"adminDayLimit"`
		OtherDayLimit  int `json:"otherDayLimit"`
	} `json:"usage"`
}

type testResult struct {
	OK      bool   `json:"ok"`
	Message string `json:"message"`
}

func resetAvailable(t *testing.T, h *harness) bool {
	t.Helper()
	var opts struct {
		PasswordResetAvailable bool `json:"passwordResetAvailable"`
	}
	h.client().expect(http.StatusOK, "GET", "/api/v1/auth/options", nil, &opts)
	return opts.PasswordResetAvailable
}

// TestMailServerAPI sets the mail server in the console, tries it with the
// test message, and sends an invitation through it, to a real SMTP server
// (Mailpit); only super administrators reach it (ADR-0053).
func TestMailServerAPI(t *testing.T) {
	h := newHarness(t, false)
	admin, _ := setUp(t, h)
	mp := testmail.New(t)
	const base = "/api/v1/settings/mail-server"

	// An organization's administrator, invited while there is no mail
	// server: the link comes back to the inviter.
	acme := orgID(t, admin, "Acme")
	invite(t, h, admin, "olive@acme.example", []map[string]any{{"role": "org_admin", "organizationId": acme}})
	org := h.client()
	org.signIn("olive@acme.example", "a long and unusual passphrase", "")

	var v mailServerView
	admin.expect(http.StatusOK, "GET", base, nil, &v)
	if v.InForce != "none" || v.Console != nil || v.Env != nil || v.Limits.PerMinute != 30 || v.Limits.PerDay != 9000 || v.Usage.AdminDayLimit != 8100 ||
		v.Usage.OtherDayLimit != 7200 {
		t.Fatalf("at first: %+v", v)
	}
	if resetAvailable(t, h) {
		t.Fatal("password reset offered without a mail server")
	}
	wantStatus(t, admin.do("POST", base+"/test", map[string]any{"to": mp.Address("ops")}), http.StatusConflict, "no_mail_server")

	form := map[string]any{"host": mp.Host, "port": mp.Port, "security": "none", "signIn": "password", "username": mp.Username,
		"password": mp.Password, "fromAddress": mp.From, "fromName": "EasyRMM"}

	// The test message, before saving.
	to := mp.Address("ops")
	var res testResult
	admin.expect(http.StatusOK, "POST", base+"/test", map[string]any{"to": to, "server": form}, &res)
	if !res.OK || !strings.Contains(res.Message, "answered: 250 ") {
		t.Fatalf("test: %+v", res)
	}
	if got := mp.Wait(to, 1)[0]; got.Subject != "EasyRMM test message" {
		t.Fatalf("test message %+v", got)
	}
	r := admin.do("POST", base+"/test", map[string]any{"to": to, "server": form})
	wantStatus(t, r, http.StatusTooManyRequests, "test_rate_limited")
	if s, err := strconv.Atoi(r.header.Get("Retry-After")); err != nil || s < 1 || s > 30 {
		t.Fatalf("Retry-After %q", r.header.Get("Retry-After"))
	}
	var afterTest mailServerView
	admin.expect(http.StatusOK, "GET", base, nil, &afterTest)
	if afterTest.Console != nil || afterTest.Usage.LastDay != 1 {
		t.Fatalf("after the test: %+v", afterTest)
	}

	// Saving.
	wantStatus(t, admin.do("PUT", base, map[string]any{"host": "smtp.example.com", "port": 25, "security": "none", "signIn": "none",
		"fromAddress": mp.From}), http.StatusUnprocessableEntity, "validation_failed")
	wantStatus(t, admin.do("PUT", base, map[string]any{"bogus": 1}), http.StatusUnprocessableEntity, "validation_failed")
	r = admin.expect(http.StatusOK, "PUT", base, form, &v)
	if v.InForce != "console" || v.Console == nil || !v.Console.PasswordSet || v.Console.UpdatedBy != "admin@msp.example" ||
		strings.Contains(string(r.body), mp.Password) {
		t.Fatalf("saved: %s", r.body)
	}
	if r := admin.expect(http.StatusOK, "GET", base, nil, nil); strings.Contains(string(r.body), mp.Password) {
		t.Fatal("the settings carry the password")
	}
	if !resetAvailable(t, h) {
		t.Fatal("password reset not offered with a mail server")
	}

	// An invitation goes by mail now, in HTML and text.
	newcomer := mp.Address("newcomer")
	var inv struct {
		Emailed     bool   `json:"emailed"`
		Link        string `json:"link"`
		MailProblem string `json:"mailProblem"`
	}
	admin.expect(http.StatusCreated, "POST", "/api/v1/users", map[string]any{"email": newcomer, "displayName": "Newcomer",
		"assignments": []map[string]any{{"role": "technician", "organizationId": acme}}}, &inv)
	if !inv.Emailed || inv.Link != "" || inv.MailProblem != "" {
		t.Fatalf("invitation: %+v", inv)
	}
	got := mp.Wait(newcomer, 1)[0]
	if got.Subject != "You have been invited to EasyRMM" || !strings.Contains(got.Text, publicOrigin+"/welcome#token=") ||
		!strings.Contains(got.HTML, ">Set up your account</a>") {
		t.Fatalf("invitation mail %+v", got)
	}

	// The limits.
	wantStatus(t, admin.do("PUT", base+"/limits", map[string]any{"perMinute": 0, "perDay": 10}), http.StatusUnprocessableEntity, "validation_failed")
	admin.expect(http.StatusOK, "PUT", base+"/limits", map[string]any{"perMinute": 10, "perDay": 100}, &v)
	if v.Limits.PerMinute != 10 || v.Limits.PerDay != 100 || v.Usage.LastDay != 2 || v.Usage.AccountLastDay != 1 || v.Usage.AdminDayLimit != 90 ||
		v.Usage.OtherDayLimit != 80 {
		t.Fatalf("limits: %+v", v)
	}

	// Only super administrators.
	for _, c := range []struct {
		method, path string
		body         any
	}{
		{"GET", base, nil}, {"PUT", base, form}, {"DELETE", base, nil},
		{"PUT", base + "/limits", map[string]any{"perMinute": 1, "perDay": 1}}, {"POST", base + "/test", map[string]any{"to": to}},
	} {
		wantStatus(t, org.do(c.method, c.path, c.body), http.StatusForbidden, "forbidden")
		if r := h.client().do(c.method, c.path, c.body); r.status != http.StatusUnauthorized && r.status != http.StatusForbidden {
			t.Fatalf("%s %s signed out: %d", c.method, c.path, r.status)
		}
	}

	// Removing.
	var removed mailServerView
	admin.expect(http.StatusOK, "DELETE", base, nil, &removed)
	if removed.InForce != "none" || removed.Console != nil || removed.Limits.PerMinute != 10 {
		t.Fatalf("removed: %+v", removed)
	}
	wantStatus(t, admin.do("DELETE", base, nil), http.StatusNotFound, "not_found")
	if resetAvailable(t, h) {
		t.Fatal("password reset offered after the mail server was removed")
	}

	entries, err := h.deps.Audit.List(context.Background(), database.System, audit.Query{ActionPrefix: "mail_server"})
	if err != nil {
		t.Fatal(err)
	}
	actions := map[string]int{}
	for _, e := range entries {
		actions[e.Action]++
		if e.ActorLabel != "admin@msp.example" {
			t.Errorf("%s by %q", e.Action, e.ActorLabel)
		}
	}
	if actions["mail_server.test"] != 1 || actions["mail_server.update"] != 1 || actions["mail_server.limits_update"] != 1 || actions["mail_server.delete"] != 1 {
		t.Fatalf("audited: %v", actions)
	}
}

// TestMailServerFromEnv: .env's mail server wins over the console's.
func TestMailServerFromEnv(t *testing.T) {
	mp := testmail.New(t)
	h := newHarnessWith(t, false, func(c *config.Config) {
		c.SMTP = config.SMTPConfig{Host: mp.Host, Port: mp.Port, Username: mp.Username, Password: mp.Password, From: "EasyRMM Env <" + mp.From + ">", TLS: "none"}
	})
	admin, _ := setUp(t, h)
	const base = "/api/v1/settings/mail-server"
	var v mailServerView
	r := admin.expect(http.StatusOK, "GET", base, nil, &v)
	if v.InForce != "env" || v.Env == nil || v.Env.Host != mp.Host || v.Env.FromAddress != mp.From || v.Env.FromName != "EasyRMM Env" ||
		!v.Env.PasswordSet || v.Env.SignIn != "password" || strings.Contains(string(r.body), mp.Password) {
		t.Fatalf("from .env: %s", r.body)
	}
	form := map[string]any{"host": mp.Host, "port": mp.Port, "security": "none", "signIn": "none", "fromAddress": mp.From}
	wantStatus(t, admin.do("PUT", base, form), http.StatusConflict, "mail_server_from_env")
	// Nothing saved in the console to remove; removing it would not change
	// the mail server in force.
	wantStatus(t, admin.do("DELETE", base, nil), http.StatusNotFound, "not_found")
	wantStatus(t, admin.do("POST", base+"/test", map[string]any{"to": mp.Address("a"), "server": form}), http.StatusConflict, "mail_server_from_env")
	admin.expect(http.StatusOK, "PUT", base+"/limits", map[string]any{"perMinute": 20, "perDay": 500}, &v)
	if v.Limits.PerMinute != 20 {
		t.Fatalf("limits: %+v", v.Limits)
	}
	if !resetAvailable(t, h) {
		t.Fatal("password reset not offered with .env's mail server")
	}
	to := mp.Address("ops")
	var res testResult
	admin.expect(http.StatusOK, "POST", base+"/test", map[string]any{"to": to}, &res)
	if !res.OK {
		t.Fatalf("test: %+v", res)
	}
	if got := mp.Wait(to, 1)[0]; got.From.Name != "EasyRMM Env" || got.From.Address != mp.From {
		t.Fatalf("from %+v", got.From)
	}
}
