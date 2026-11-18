//go:build integration

package app_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/csv"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
)

// TestReportsAPI reads reports through the console API and downloads one as
// CSV (ADR-0029).
func TestReportsAPI(t *testing.T) {
	h := newHarness(t, false)
	admin, _ := setUp(t, h)
	acme := orgID(t, admin, "Acme")
	var hq idObj
	admin.expect(http.StatusCreated, "POST", "/api/v1/organizations/"+acme+"/sites", map[string]string{"name": "HQ", "timezone": "UTC"}, &hq)
	var token struct {
		Secret string `json:"secret"`
	}
	admin.expect(http.StatusCreated, "POST", "/api/v1/sites/"+hq.ID+"/enrollment-tokens", map[string]any{"name": "Reports", "expiresInDays": 1}, &token)
	ctx := context.Background()
	ac := h.agentClient()
	key := newKey(t)
	enr, err := ac.Enroll(ctx, token.Secret, key.Public().(ed25519.PublicKey), facts("=cmd|calc"))
	if err != nil {
		t.Fatal(err)
	}
	ac.SetIdentity(enr.DeviceID, key)
	if _, err := ac.Heartbeat(ctx, agentproto.HeartbeatRequest{Facts: facts("=cmd|calc")}); err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(agentproto.Inventory{
		System:         agentproto.SystemInfo{Manufacturer: "QEMU", Model: "Standard PC", Serial: "S-1"},
		CPU:            agentproto.CPUInfo{Model: "EPYC", Cores: 4, Threads: 8},
		Memory:         8 << 30,
		PackageManager: "dpkg",
		Packages:       []agentproto.Package{{Name: "openssl", Version: "3.5.1-1", Arch: "amd64"}, {Name: "jq", Version: "1.7.1-6", Arch: "amd64"}},
	})
	if _, err := ac.Inventory(ctx, body); err != nil {
		t.Fatal(err)
	}

	var rep struct {
		Name    string `json:"name"`
		Title   string `json:"title"`
		Columns []struct {
			Key, Label, Type string
		} `json:"columns"`
		Rows      [][]any `json:"rows"`
		Total     int     `json:"total"`
		Truncated bool    `json:"truncated"`
	}
	admin.expect(http.StatusOK, "GET", "/api/v1/reports/devices?organizationId="+acme, nil, &rep)
	if rep.Title != "Device inventory" || rep.Total != 1 || len(rep.Rows) != 1 || rep.Rows[0][2] != "=cmd|calc" || rep.Rows[0][9] != "QEMU" || rep.Columns[6].Type != "bool" {
		t.Errorf("devices report %+v", rep)
	}
	admin.expect(http.StatusOK, "GET", "/api/v1/reports/software?q=SSL&siteId="+hq.ID, nil, &rep)
	if rep.Total != 1 || rep.Rows[0][4] != "openssl" {
		t.Errorf("software report %+v", rep)
	}
	for _, q := range []string{"devices?platform=beos", "alerts?days=0", "health?diskPercent=101", "devices?organizationId=nope", "devices?siteId=nope", "health?offlineDays=x"} {
		wantStatus(t, admin.do("GET", "/api/v1/reports/"+q, nil), http.StatusUnprocessableEntity, "validation_failed")
	}
	wantStatus(t, admin.do("GET", "/api/v1/reports/payroll", nil), http.StatusNotFound, "not_found")
	wantStatus(t, h.client().do("GET", "/api/v1/reports/devices", nil), http.StatusUnauthorized, "")

	// A read-only user reads reports and downloads them.
	invite(t, h, admin, "rory@acme.example", []map[string]any{{"role": "read_only", "organizationId": acme}})
	viewer := h.client()
	viewer.signIn("rory@acme.example", "a long and unusual passphrase", "")
	r := viewer.do("GET", "/api/v1/reports/devices/csv?organizationId="+acme, nil)
	wantStatus(t, r, http.StatusOK, "")
	if ct := r.header.Get("Content-Type"); ct != "text/csv; charset=utf-8" {
		t.Errorf("content type %s", ct)
	}
	if cd := r.header.Get("Content-Disposition"); !strings.HasPrefix(cd, `attachment; filename="easyrmm-devices-`) || !strings.HasSuffix(cd, `.csv"`) {
		t.Errorf("disposition %s", cd)
	}
	if r.header.Get("X-Report-Rows") != "1" || r.header.Get("Cache-Control") != "no-store" {
		t.Errorf("headers %v", r.header)
	}
	if !bytes.HasPrefix(r.body, []byte("\xef\xbb\xbf")) {
		t.Error("no byte order mark")
	}
	records, err := csv.NewReader(bytes.NewReader(r.body[3:])).ReadAll()
	if err != nil || len(records) != 2 {
		t.Fatalf("csv %q %v", records, err)
	}
	if records[0][7] != "Last seen (UTC)" || records[1][2] != "'=cmd|calc" || records[1][6] != "Yes" || records[1][13] != "4" {
		t.Errorf("csv rows %q", records)
	}

	var audit struct {
		Items []struct {
			Action  string         `json:"action"`
			Details map[string]any `json:"details"`
		} `json:"items"`
	}
	admin.expect(http.StatusOK, "GET", "/api/v1/audit?action=report", nil, &audit)
	if len(audit.Items) != 1 || audit.Items[0].Action != "report.export" || audit.Items[0].Details["report"] != "devices" || audit.Items[0].Details["rows"] != 1.0 {
		t.Errorf("audit %+v", audit.Items)
	}
}
