//go:build integration

package app_test

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/rdpcreds"
)

const rdpPassword = "Pa\"ss\\wörd世 \U0001F600 1234"

// Saved RDP credentials over HTTP (ADR-0079): saving and deleting need a
// fresh second factor, nothing returns a password, the password is stored
// sealed, and a session that will use one steps up before it starts.
func TestHTTPSavedRDPCredentials(t *testing.T) {
	h := newHarnessWith(t, false, withRemote(t))
	admin, secret := setUp(t, h)
	acme := orgID(t, admin, "Acme")
	var site struct {
		ID string `json:"id"`
	}
	admin.expect(http.StatusCreated, "POST", "/api/v1/organizations/"+acme+"/sites", map[string]string{"name": "HQ"}, &site)
	var win, lin string
	if err := h.db.DB.InTx(context.Background(), database.System, func(tx pgx.Tx) error {
		q := `INSERT INTO devices (organization_id, site_id, name, hostname, platform, mesh_node_id, remote_online)
			VALUES ($1, $2, $3, $3, $4, $5, true) RETURNING id`
		if err := tx.QueryRow(context.Background(), q, acme, site.ID, "WIN-SRV", "windows", "node//rdptest1").Scan(&win); err != nil {
			return err
		}
		return tx.QueryRow(context.Background(), q, acme, site.ID, "lin-box", "linux", "node//rdptest2").Scan(&lin)
	}); err != nil {
		t.Fatal(err)
	}
	base := "/api/v1/devices/" + win + "/rdp-credentials"
	body := map[string]string{"label": "Server admin", "domain": "CORP", "username": "svc-admin", "password": rdpPassword}

	// Without a step-up nothing is saved, and the console can tell why.
	wantStatus(t, admin.do("PUT", base, body), http.StatusUnauthorized, "step_up_required")
	var list struct {
		Credentials []map[string]any `json:"credentials"`
	}
	admin.expect(http.StatusOK, "GET", base, nil, &list)
	if len(list.Credentials) != 0 {
		t.Fatalf("saved without a step-up: %+v", list)
	}
	admin.expect(http.StatusOK, "POST", "/api/v1/auth/step-up/totp", map[string]string{"code": code(t, secret, time.Now().Add(30*time.Second))}, nil)

	r := admin.expect(http.StatusOK, "PUT", base, body, nil)
	if strings.Contains(string(r.body), "Pa\\\"ss") || strings.Contains(strings.ToLower(string(r.body)), "password") {
		t.Errorf("the save answered with the password: %s", r.body)
	}
	if r.header.Get("Cache-Control") != "no-store" {
		t.Error("the answer may be cached")
	}
	g := admin.expect(http.StatusOK, "GET", base, nil, &list)
	if len(list.Credentials) != 1 || list.Credentials[0]["username"] != "svc-admin" || list.Credentials[0]["domain"] != "CORP" {
		t.Fatalf("list: %s", g.body)
	}
	if strings.Contains(strings.ToLower(string(g.body)), "password") || strings.Contains(string(g.body), "sealed") {
		t.Errorf("the list shows more than it should: %s", g.body)
	}
	id, _ := list.Credentials[0]["id"].(string)

	// The stored password opens to exactly what was typed, escapes and all.
	cid, _ := uuid.Parse(id)
	var user, org uuid.UUID
	var siteID uuid.UUID
	var dev uuid.UUID
	if err := h.db.DB.ReadTx(context.Background(), database.System, func(tx pgx.Tx) error {
		return tx.QueryRow(context.Background(), `SELECT c.user_id, c.organization_id, d.site_id, d.id FROM device_rdp_credentials c JOIN devices d ON d.id = c.device_id WHERE c.id = $1`, cid).
			Scan(&user, &org, &siteID, &dev)
	}); err != nil {
		t.Fatal(err)
	}
	var sess uuid.UUID
	if err := h.db.DB.ReadTx(context.Background(), database.System, func(tx pgx.Tx) error {
		return tx.QueryRow(context.Background(), `SELECT id FROM sessions WHERE user_id = $1 AND stepped_up_at IS NOT NULL`, user).Scan(&sess)
	}); err != nil {
		t.Fatal(err)
	}
	o, err := h.deps.RDPCreds.OpenForSession(context.Background(), rdpcreds.Use{CredentialID: cid, Session: sess, Grant: uuid.New(), User: user, Organization: org, Site: siteID, Device: dev})
	if err != nil || string(o.Password) != rdpPassword {
		t.Fatalf("opened %q: %v", o.Password, err)
	}

	// Bad bodies, a Linux device, a device that is not there.
	for name, b := range map[string]any{
		"no password":       map[string]string{"username": "u"},
		"number password":   map[string]any{"username": "u", "password": 5},
		"unknown field":     map[string]any{"username": "u", "password": "x", "reveal": true},
		"password is a map": map[string]any{"username": "u", "password": map[string]string{}},
	} {
		if r := admin.do("PUT", base, b); r.status != http.StatusUnprocessableEntity {
			t.Errorf("%s: %d %s", name, r.status, r.body)
		}
	}
	if r := admin.do("PUT", "/api/v1/devices/"+lin+"/rdp-credentials", body); r.status != http.StatusUnprocessableEntity {
		t.Errorf("Linux device: %d %s", r.status, r.body)
	}
	wantStatus(t, admin.do("PUT", "/api/v1/devices/"+uuid.NewString()+"/rdp-credentials", body), http.StatusNotFound, "not_found")

	// A remote session that will use a saved credential steps up first, and
	// only RDP sessions can.
	wantStatus(t, admin.do("POST", "/api/v1/devices/"+win+"/remote-sessions", map[string]any{"kind": "terminal", "savedCredential": true}),
		http.StatusUnprocessableEntity, "validation_failed")
	steppedUp := func(at string) {
		t.Helper()
		if err := h.db.DB.InTx(context.Background(), database.System, func(tx pgx.Tx) error {
			_, err := tx.Exec(context.Background(), `UPDATE sessions SET stepped_up_at = `+at+` WHERE user_id = $1`, user)
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	steppedUp("NULL")
	wantStatus(t, admin.do("POST", "/api/v1/devices/"+win+"/remote-sessions", map[string]any{"kind": "rdp", "savedCredential": true}),
		http.StatusUnauthorized, "step_up_required")
	wantStatus(t, admin.do("DELETE", base+"/"+id, nil), http.StatusUnauthorized, "step_up_required")
	steppedUp("now()")

	// Routes name real things.
	wantStatus(t, admin.do("GET", "/api/v1/devices/"+uuid.NewString()+"/rdp-credentials", nil), http.StatusNotFound, "not_found")
	wantStatus(t, admin.do("GET", "/api/v1/devices/nope/rdp-credentials", nil), http.StatusNotFound, "")
	wantStatus(t, admin.do("DELETE", base+"/nope", nil), http.StatusNotFound, "")
	wantStatus(t, admin.do("DELETE", "/api/v1/devices/nope/rdp-credentials/"+id, nil), http.StatusNotFound, "")

	// Delete, then the credential is gone; and no password is in the logs.
	wantStatus(t, admin.do("DELETE", base+"/"+id, nil), http.StatusNoContent, "")
	wantStatus(t, admin.do("DELETE", base+"/"+id, nil), http.StatusNotFound, "not_found")
	admin.expect(http.StatusOK, "GET", base, nil, &list)
	if len(list.Credentials) != 0 {
		t.Errorf("after delete: %+v", list)
	}
	if strings.Contains(h.logs.String(), "Pa\\\"ss") || strings.Contains(h.logs.String(), "wörd") {
		t.Error("the password reached the server's logs")
	}
}
