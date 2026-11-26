//go:build integration

package app_test

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// signedInAdmin sets the server up and returns its first administrator, signed
// in with a second factor.
func signedInAdmin(t *testing.T, h *harness) *client {
	t.Helper()
	c := h.client()
	token, err := os.ReadFile(filepath.Join(h.dataDir, "setup-token"))
	if err != nil {
		t.Fatal(err)
	}
	c.expect(http.StatusNoContent, "POST", "/api/v1/setup", map[string]string{"token": strings.TrimSpace(string(token)),
		"email": "admin@msp.example", "displayName": "Ada", "password": "correct horse battery staple", "organizationName": "Acme Corp"}, nil)
	var s sessionView
	c.expect(http.StatusOK, "POST", "/api/v1/auth/login", map[string]string{"email": "admin@msp.example", "password": "correct horse battery staple"}, &s)
	c.csrf = s.CSRFToken
	var enr struct {
		Secret string `json:"secret"`
	}
	c.expect(http.StatusOK, "POST", "/api/v1/auth/mfa/totp/begin", map[string]string{}, &enr)
	var done struct {
		Session sessionView `json:"session"`
	}
	c.expect(http.StatusOK, "POST", "/api/v1/auth/mfa/totp/confirm", map[string]string{"code": code(t, enr.Secret, time.Now())}, &done)
	c.csrf = done.Session.CSRFToken
	return c
}

// The notification routes, through the real server: channels, a test, the
// secret shown again, sharing, approvals, quotas, notices and the delivery log.
func TestHTTPNotificationChannels(t *testing.T) {
	h := newHarness(t, true)
	// The sender runs, as in the server, and holds its lock for the test.
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Go(func() { h.deps.Notify.Run(ctx) })
	t.Cleanup(func() { cancel(); wg.Wait() })
	c := signedInAdmin(t, h)
	var orgs struct {
		Items []struct {
			ID string `json:"id"`
		} `json:"items"`
	}
	c.expect(http.StatusOK, "GET", "/api/v1/organizations", nil, &orgs)
	org := orgs.Items[0].ID

	type channel struct {
		ID      string `json:"id"`
		Name    string `json:"name"`
		Kind    string `json:"kind"`
		State   string `json:"state"`
		Host    string `json:"host"`
		Enabled bool   `json:"enabled"`
		Pending int    `json:"pending"`
	}
	var mail channel
	to := h.mp.Address("desk")
	c.expect(http.StatusCreated, "POST", "/api/v1/notifications/channels",
		map[string]any{"organizationId": org, "kind": "email", "name": "Service desk", "recipients": []string{to}}, &mail)
	if mail.State != "sending" || mail.Kind != "email" {
		t.Fatalf("%+v", mail)
	}
	if r := c.do("POST", "/api/v1/notifications/channels", map[string]any{"organizationId": org, "kind": "email", "name": "service DESK", "recipients": []string{to}}); r.status != http.StatusUnprocessableEntity {
		t.Fatalf("duplicate name: %d %s", r.status, r.body)
	}
	if r := c.do("POST", "/api/v1/notifications/channels", map[string]any{"organizationId": org, "kind": "webhook", "name": "bad", "url": "http://insecure.example/x"}); r.status != http.StatusUnprocessableEntity || !strings.Contains(string(r.body), "https://") {
		t.Fatalf("http address: %d %s", r.status, r.body)
	}
	var hook channel
	c.expect(http.StatusCreated, "POST", "/api/v1/notifications/channels",
		map[string]any{"organizationId": org, "kind": "webhook", "name": "PSA", "url": "https://psa.example.test/hook?token=sekrit"}, &hook)
	if hook.Host != "psa.example.test" {
		t.Fatalf("%+v", hook)
	}
	var list struct {
		Channels []channel `json:"channels"`
	}
	c.expect(http.StatusOK, "GET", "/api/v1/notifications/channels?organizationId="+org, nil, &list)
	if len(list.Channels) != 2 {
		t.Fatalf("%+v", list)
	}
	if strings.Contains(string(c.do("GET", "/api/v1/notifications/channels?organizationId="+org, nil).body), "sekrit") {
		t.Fatal("the list holds the address's query")
	}
	// Everything of every owner is the platform's list.
	c.expect(http.StatusOK, "GET", "/api/v1/notifications/channels", nil, &list)
	c.expect(http.StatusOK, "GET", "/api/v1/notifications/channels/"+hook.ID, nil, &hook)
	if r := c.do("GET", "/api/v1/notifications/channels/not-an-id", nil); r.status != http.StatusNotFound {
		t.Fatalf("bad id: %d", r.status)
	}
	c.expect(http.StatusOK, "PUT", "/api/v1/notifications/channels/"+mail.ID, map[string]any{"name": "Service desk (on call)", "recipients": []string{to, h.mp.Address("lead")}}, &mail)
	if mail.Name != "Service desk (on call)" {
		t.Fatalf("%+v", mail)
	}

	// Revealed with no-store, audited; an email channel has nothing to show.
	r := c.expect(http.StatusOK, "POST", "/api/v1/notifications/channels/"+hook.ID+"/reveal", nil, nil)
	if r.header.Get("Cache-Control") != "no-store" || !strings.Contains(string(r.body), "sekrit") {
		t.Fatalf("reveal: %v %s", r.header, r.body)
	}
	if r := c.do("POST", "/api/v1/notifications/channels/"+mail.ID+"/reveal", nil); r.status != http.StatusConflict {
		t.Fatalf("reveal of an email channel: %d", r.status)
	}
	c.expect(http.StatusNoContent, "POST", "/api/v1/notifications/channels/"+hook.ID+"/rotate-secret", nil, nil)

	// A test goes ahead of the queue, through the worker, to the mail server.
	var test struct {
		Status string `json:"status"`
	}
	c.expect(http.StatusOK, "POST", "/api/v1/notifications/channels/"+mail.ID+"/test", nil, &test)
	if test.Status != "sent" {
		t.Fatalf("%+v", test)
	}
	if got := h.mp.Wait(to, 1); len(got) != 1 || got[0].Subject != "EasyRMM test notification" {
		t.Fatalf("mail: %+v", got)
	}
	if r := c.do("POST", "/api/v1/notifications/channels/"+mail.ID+"/test", nil); r.status != http.StatusTooManyRequests || r.errorCode(t) != "test_rate_limited" || r.header.Get("Retry-After") == "" {
		t.Fatalf("second test: %d %s", r.status, r.body)
	}
	var log struct {
		Deliveries []struct {
			Kind   string `json:"kind"`
			Status string `json:"status"`
		} `json:"deliveries"`
		RetentionDays int `json:"retentionDays"`
	}
	c.expect(http.StatusOK, "GET", "/api/v1/notifications/deliveries?channelId="+mail.ID, nil, &log)
	if len(log.Deliveries) != 1 || log.Deliveries[0].Kind != "test" || log.RetentionDays != 30 {
		t.Fatalf("%+v", log)
	}
	if r := c.do("GET", "/api/v1/notifications/deliveries?status=bogus", nil); r.status != http.StatusUnprocessableEntity {
		t.Fatalf("bad status: %d", r.status)
	}

	// Approvals: an organization's webhook may ask; a platform channel needs none.
	if r := c.do("POST", "/api/v1/notifications/channels/"+hook.ID+"/approval", nil); r.status != http.StatusOK {
		t.Fatalf("ask: %d %s", r.status, r.body)
	}
	var reqs struct {
		Requests []struct {
			ChannelID string `json:"channelId"`
		} `json:"requests"`
	}
	c.expect(http.StatusOK, "GET", "/api/v1/notifications/approvals", nil, &reqs)
	if len(reqs.Requests) != 1 || reqs.Requests[0].ChannelID != hook.ID {
		t.Fatalf("%+v", reqs)
	}
	if r := c.do("POST", "/api/v1/notifications/channels/"+hook.ID+"/approval/approve", map[string]any{"prefixes": []string{}}); r.status != http.StatusUnprocessableEntity {
		t.Fatalf("empty approval: %d %s", r.status, r.body)
	}
	c.expect(http.StatusNoContent, "DELETE", "/api/v1/notifications/channels/"+hook.ID+"/approval", nil, nil)
	if r := c.do("DELETE", "/api/v1/notifications/channels/"+hook.ID+"/approval", nil); r.status != http.StatusNotFound {
		t.Fatalf("withdraw twice: %d", r.status)
	}

	// A platform channel is shared with the organization, then not.
	var plat channel
	c.expect(http.StatusCreated, "POST", "/api/v1/notifications/channels", map[string]any{"kind": "email", "name": "MSP", "recipients": []string{to}}, &plat)
	c.expect(http.StatusNoContent, "PUT", "/api/v1/notifications/channels/"+plat.ID+"/shares/"+org, nil, nil)
	c.expect(http.StatusNoContent, "DELETE", "/api/v1/notifications/channels/"+plat.ID+"/shares/"+org, nil, nil)
	if r := c.do("PUT", "/api/v1/notifications/channels/"+mail.ID+"/shares/"+org, nil); r.status != http.StatusConflict {
		t.Fatalf("sharing an organization's channel: %d", r.status)
	}

	// Quotas, and notices.
	var q struct {
		MessagesPerHour int `json:"messagesPerHour"`
	}
	c.expect(http.StatusOK, "GET", "/api/v1/notifications/quotas/"+org, nil, &q)
	if q.MessagesPerHour != 600 {
		t.Fatalf("%+v", q)
	}
	c.expect(http.StatusOK, "PUT", "/api/v1/notifications/quotas/"+org, map[string]int{"channels": 5, "rules": 10, "testsPerHour": 5, "messagesPerHour": 100}, &q)
	if q.MessagesPerHour != 100 {
		t.Fatalf("%+v", q)
	}
	if r := c.do("PUT", "/api/v1/notifications/quotas/"+org, map[string]int{"channels": -1}); r.status != http.StatusUnprocessableEntity {
		t.Fatalf("negative quota: %d", r.status)
	}
	var notices struct {
		Notices []struct {
			ID string `json:"id"`
		} `json:"notices"`
	}
	c.expect(http.StatusOK, "GET", "/api/v1/notices", nil, &notices)
	if len(notices.Notices) != 0 {
		t.Fatalf("%+v", notices)
	}
	if r := c.do("POST", "/api/v1/notices/00000000-0000-4000-8000-000000000000/acknowledge", nil); r.status != http.StatusNotFound {
		t.Fatalf("acknowledge of nothing: %d", r.status)
	}

	// Turned off, then deleted.
	c.expect(http.StatusOK, "PUT", "/api/v1/notifications/channels/"+mail.ID, map[string]any{"enabled": false}, &mail)
	if mail.State != "off" || mail.Pending != 0 {
		t.Fatalf("%+v", mail)
	}
	c.expect(http.StatusNoContent, "DELETE", "/api/v1/notifications/channels/"+mail.ID, nil, nil)
	if r := c.do("DELETE", "/api/v1/notifications/channels/"+mail.ID, nil); r.status != http.StatusNotFound {
		t.Fatalf("delete twice: %d", r.status)
	}
	// The log keeps no secret: the server's log neither.
	if strings.Contains(h.logs.String(), "sekrit") {
		t.Fatal("the server's log holds a webhook address's query")
	}
	// Signed out, nothing is served.
	anon := h.client()
	if r := anon.do("GET", "/api/v1/notifications/channels", nil); r.status != http.StatusUnauthorized {
		t.Fatalf("signed out: %d", r.status)
	}
}
