//go:build integration

package app_test

import (
	"context"
	"crypto/ed25519"
	"net/http"
	"testing"
)

// The Windows hardening console's endpoints (ADR-0054, W3): the catalog,
// the fleet, a device's guards and Keep, with who may do each.
func TestWindowsHardeningConsoleAPI(t *testing.T) {
	h := newHarness(t, false)
	admin, _ := setUp(t, h)
	acme := orgID(t, admin, "Acme")
	var hq idObj
	admin.expect(http.StatusCreated, "POST", "/api/v1/organizations/"+acme+"/sites", map[string]string{"name": "HQ", "timezone": "UTC"}, &hq)
	var token struct {
		Secret string `json:"secret"`
	}
	admin.expect(http.StatusCreated, "POST", "/api/v1/sites/"+hq.ID+"/enrollment-tokens", map[string]any{"name": "Console", "expiresInDays": 1}, &token)
	f := facts("ws-01")
	f.Platform, f.OS = "windows", "Windows 11 Pro"
	enr, err := h.agentClient().Enroll(context.Background(), token.Secret, newKey(t).Public().(ed25519.PublicKey), f)
	if err != nil {
		t.Fatal(err)
	}
	device := enr.DeviceID
	invite(t, h, admin, "tess@acme.example", []map[string]any{{"role": "technician", "organizationId": acme}})
	tech := h.client()
	tech.signIn("tess@acme.example", "a long and unusual passphrase", "")

	var cat struct {
		Items []struct {
			ID       string `json:"id"`
			Tier     int    `json:"tier"`
			Settings []struct {
				ID string `json:"id"`
			} `json:"settings"`
		} `json:"items"`
	}
	tech.expect(http.StatusOK, "GET", "/api/v1/hardening/windows/catalog", nil, &cat)
	if len(cat.Items) < 20 || cat.Items[0].Settings == nil {
		t.Errorf("catalog of %d modules", len(cat.Items))
	}

	var fleet struct {
		Devices []struct {
			ID    string `json:"id"`
			Guard string `json:"guard"`
		} `json:"devices"`
	}
	tech.expect(http.StatusOK, "GET", "/api/v1/hardening/windows/fleet?organizationId="+acme, nil, &fleet)
	if len(fleet.Devices) != 1 || fleet.Devices[0].ID != device {
		t.Errorf("fleet %+v", fleet)
	}
	wantStatus(t, tech.do("GET", "/api/v1/hardening/windows/fleet?organizationId=not-an-id", nil), http.StatusUnprocessableEntity, "")

	var guards struct {
		Items []any `json:"items"`
	}
	tech.expect(http.StatusOK, "GET", "/api/v1/devices/"+device+"/hardening/guards", nil, &guards)
	if guards.Items == nil || len(guards.Items) != 0 {
		t.Errorf("guards %+v", guards)
	}
	wantStatus(t, tech.do("POST", "/api/v1/devices/"+device+"/hardening/guard/keep", nil), http.StatusForbidden, "")
	wantStatus(t, admin.do("POST", "/api/v1/devices/"+device+"/hardening/guard/keep", nil), http.StatusConflict, "no_armed_guard")
}
