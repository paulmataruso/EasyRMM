//go:build integration

package app_test

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"testing"
	"time"

	agentclient "github.com/paulmataruso/easyrmm/agent/client"
	"github.com/paulmataruso/easyrmm/internal/agentproto"
)

// TestEnrollmentApprovalAPI installs agents with an approval token, as the
// real agent's client does, and approves and rejects them through the
// console API (ADR-0024).
func TestEnrollmentApprovalAPI(t *testing.T) {
	h := newHarness(t, false)
	admin, _ := setUp(t, h)
	acme := orgID(t, admin, "Acme")
	var hq struct {
		ID string `json:"id"`
	}
	admin.expect(http.StatusCreated, "POST", "/api/v1/organizations/"+acme+"/sites", map[string]string{"name": "HQ", "timezone": "UTC"}, &hq)

	type approvalToken struct {
		ID      string `json:"id"`
		Name    string `json:"name"`
		Status  string `json:"status"`
		Uses    int    `json:"uses"`
		Waiting int    `json:"waiting"`
	}
	var created struct {
		Token     approvalToken `json:"token"`
		Secret    string        `json:"secret"`
		ServerURL string        `json:"serverUrl"`
	}
	r := admin.expect(http.StatusCreated, "POST", "/api/v1/approval-tokens", map[string]any{"name": "Office rollout", "expiresInDays": 30}, &created)
	if created.Secret == "" || created.ServerURL != publicOrigin || created.Token.Status != "active" || r.header.Get("Cache-Control") != "no-store" {
		t.Fatalf("created %+v", created)
	}
	wantStatus(t, admin.do("POST", "/api/v1/approval-tokens", map[string]any{"name": "", "expiresInDays": 400}), http.StatusUnprocessableEntity, "validation_failed")

	// Two machines run the install command.
	ctx := context.Background()
	c := h.agentClient()
	frontKey, kioskKey := newKey(t), newKey(t)
	front, err := c.Enroll(ctx, created.Secret, frontKey.Public().(ed25519.PublicKey), facts("front-desk"))
	if err != nil || front.Pending == nil || front.DeviceID != "" || front.Pending.Code != agentproto.DeviceCode(frontKey.Public().(ed25519.PublicKey)) {
		t.Fatalf("waiting: %+v %v", front, err)
	}
	if _, err := c.Enroll(ctx, created.Secret, kioskKey.Public().(ed25519.PublicKey), facts("kiosk")); err != nil {
		t.Fatal(err)
	}
	// The server answers 202 Accepted to a device that waits.
	body, _ := json.Marshal(agentproto.EnrollRequest{Token: created.Secret,
		PublicKey: base64.StdEncoding.EncodeToString(newKey(t).Public().(ed25519.PublicKey)), Facts: facts("lab")})
	if r := h.raw("POST", agentproto.PathEnroll, body, ""); r.status != http.StatusAccepted {
		t.Fatalf("waiting device answered %d %s", r.status, r.body)
	}

	type request struct {
		ID       string `json:"id"`
		Code     string `json:"code"`
		Hostname string `json:"hostname"`
		Online   bool   `json:"online"`
		State    string `json:"state"`
	}
	var list struct {
		Items   []request `json:"items"`
		Waiting int       `json:"waiting"`
	}
	admin.expect(http.StatusOK, "GET", "/api/v1/enrollment-requests", nil, &list)
	if len(list.Items) != 3 || list.Waiting != 3 || !list.Items[0].Online {
		t.Fatalf("requests %+v", list)
	}
	ids := map[string]string{}
	for _, it := range list.Items {
		ids[it.Hostname] = it.ID
	}
	var waiting struct {
		Waiting int `json:"waiting"`
	}
	admin.expect(http.StatusOK, "GET", "/api/v1/enrollment-requests/waiting", nil, &waiting)
	if waiting.Waiting != 3 {
		t.Errorf("waiting %d", waiting.Waiting)
	}
	var toks struct {
		Items []approvalToken `json:"items"`
	}
	admin.expect(http.StatusOK, "GET", "/api/v1/approval-tokens?status=active", nil, &toks)
	if len(toks.Items) != 1 || toks.Items[0].Uses != 3 || toks.Items[0].Waiting != 3 {
		t.Fatalf("tokens %+v", toks.Items)
	}

	// Approve the front desk while its agent waits for the answer.
	got := make(chan error, 1)
	var approved *agentproto.EnrollResponse
	go func() {
		var err error
		approved, err = h.agentClient().Enroll(ctx, created.Secret, frontKey.Public().(ed25519.PublicKey), facts("front-desk"))
		got <- err
	}()
	time.Sleep(300 * time.Millisecond)
	var d struct {
		Decided []string `json:"decided"`
		Devices []string `json:"devices"`
		Skipped []string `json:"skipped"`
	}
	admin.expect(http.StatusOK, "POST", "/api/v1/enrollment-requests/approve", map[string]any{"ids": []string{ids["front-desk"]}, "siteId": hq.ID}, &d)
	if len(d.Decided) != 1 || len(d.Devices) != 1 {
		t.Fatalf("approve %+v", d)
	}
	select {
	case err := <-got:
		if err != nil || approved.DeviceID != d.Devices[0] || approved.Pending != nil {
			t.Fatalf("the waiting agent: %+v %v", approved, err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the waiting agent did not hear of its approval")
	}
	var dev agentDevice
	admin.expect(http.StatusOK, "GET", "/api/v1/devices/"+d.Devices[0], nil, &dev)
	if dev.Name != "front-desk" || dev.SiteName != "HQ" || dev.Agent == nil || dev.Platform != "linux" {
		t.Errorf("approved device %+v", dev)
	}
	wantStatus(t, admin.do("POST", "/api/v1/enrollment-requests/approve", map[string]any{"ids": []string{ids["kiosk"]}}), http.StatusUnprocessableEntity, "validation_failed")

	// Reject the kiosk: its agent is told so and stops asking.
	admin.expect(http.StatusOK, "POST", "/api/v1/enrollment-requests/reject", map[string]any{"ids": []string{ids["kiosk"]}}, &d)
	if len(d.Decided) != 1 {
		t.Fatalf("reject %+v", d)
	}
	time.Sleep(2100 * time.Millisecond)
	_, err = c.Enroll(ctx, created.Secret, kioskKey.Public().(ed25519.PublicKey), facts("kiosk"))
	var ae *agentclient.Error
	if !errors.As(err, &ae) || ae.Status != http.StatusForbidden || ae.Code != agentproto.CodeEnrollmentRejected {
		t.Fatalf("rejected agent: %v", err)
	}
	admin.expect(http.StatusOK, "GET", "/api/v1/enrollment-requests?state=rejected", nil, &list)
	if len(list.Items) != 1 || list.Items[0].Hostname != "kiosk" || list.Waiting != 1 {
		t.Errorf("rejected %+v", list)
	}
	wantStatus(t, admin.do("GET", "/api/v1/enrollment-requests?state=approved", nil), http.StatusUnprocessableEntity, "validation_failed")

	// Revoking the token stops new devices.
	var tok approvalToken
	admin.expect(http.StatusOK, "POST", "/api/v1/approval-tokens/"+created.Token.ID+"/revoke", nil, &tok)
	if tok.Status != "revoked" {
		t.Errorf("revoked %+v", tok)
	}
	if _, err := c.Enroll(ctx, created.Secret, newKey(t).Public().(ed25519.PublicKey), facts("late")); !errors.As(err, &ae) || ae.Code != "token_invalid" {
		t.Errorf("revoked token: %v", err)
	}

	// The console's audit log has every step.
	var entries struct {
		Items []struct {
			Action string `json:"action"`
		} `json:"items"`
	}
	admin.expect(http.StatusOK, "GET", "/api/v1/audit?action=enrollment_request", nil, &entries)
	if len(entries.Items) != 5 {
		t.Errorf("request audit %+v", entries.Items)
	}

	// Waiting devices belong to no organization yet: only those who manage
	// enrollment everywhere see and decide them.
	invite(t, h, admin, "olive@acme.example", []map[string]any{{"role": "org_admin", "organizationId": acme}})
	org := h.client()
	org.signIn("olive@acme.example", "a long and unusual passphrase", "")
	for _, call := range []struct {
		method, path string
		body         any
	}{
		{"GET", "/api/v1/approval-tokens", nil},
		{"POST", "/api/v1/approval-tokens", map[string]any{"name": "x", "expiresInDays": 1}},
		{"POST", "/api/v1/approval-tokens/" + created.Token.ID + "/revoke", nil},
		{"GET", "/api/v1/enrollment-requests", nil},
		{"POST", "/api/v1/enrollment-requests/approve", map[string]any{"ids": []string{ids["lab"]}, "siteId": hq.ID}},
		{"POST", "/api/v1/enrollment-requests/reject", map[string]any{"ids": []string{ids["lab"]}}},
	} {
		wantStatus(t, org.do(call.method, call.path, call.body), http.StatusForbidden, "forbidden")
	}
	org.expect(http.StatusOK, "GET", "/api/v1/enrollment-requests/waiting", nil, &waiting)
	if waiting.Waiting != 0 {
		t.Errorf("an organization administrator is told %d devices wait", waiting.Waiting)
	}
	wantStatus(t, h.client().do("GET", "/api/v1/enrollment-requests", nil), http.StatusUnauthorized, "")
}
