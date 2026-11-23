//go:build integration

package app_test

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/server/internal/database"
)

// TestAlertsAPI raises an alert from a device's measurements and works it
// through the console API (ADR-0019).
func TestAlertsAPI(t *testing.T) {
	h := newHarness(t, false)
	admin, _ := setUp(t, h)
	acme := orgID(t, admin, "Acme")
	var hq idObj
	admin.expect(http.StatusCreated, "POST", "/api/v1/organizations/"+acme+"/sites", map[string]string{"name": "HQ", "timezone": "UTC"}, &hq)
	var device idObj
	if err := h.db.DB.InTx(context.Background(), database.System, func(tx pgx.Tx) error {
		return tx.QueryRow(context.Background(), `INSERT INTO devices (organization_id, site_id, name, agent_last_seen_at)
			VALUES ($1, $2, 'pc-01', now()) RETURNING id`, acme, hq.ID).Scan(&device.ID)
	}); err != nil {
		t.Fatal(err)
	}
	exec(t, h, `INSERT INTO device_metric_samples (device_id, at, cpu_percent, memory_percent, swap_percent, disk_percent, load1)
		SELECT $1, now() - make_interval(secs => g * 60 + 10), 5, 30, 0, 96, 0 FROM generate_series(0, 9) g`, device.ID)

	type policyView struct {
		ID           string `json:"id"`
		Level        string `json:"level"`
		Name         string `json:"name"`
		Kind         string `json:"kind"`
		Threshold    *int   `json:"threshold"`
		Minutes      int    `json:"minutes"`
		Enabled      bool   `json:"enabled"`
		ActiveAlerts int    `json:"activeAlerts"`
		CanEdit      bool   `json:"canEdit"`
	}
	type alertView struct {
		ID             string  `json:"id"`
		DeviceID       string  `json:"deviceId"`
		DeviceName     string  `json:"deviceName"`
		Name           string  `json:"name"`
		Status         string  `json:"status"`
		Severity       string  `json:"severity"`
		LastValue      float64 `json:"lastValue"`
		AcknowledgedBy string  `json:"acknowledgedBy"`
		Resolution     string  `json:"resolution"`
		CanManage      bool    `json:"canManage"`
	}
	var policies struct{ Items []policyView }
	admin.expect(http.StatusOK, "GET", "/api/v1/alert-policies", nil, &policies)
	// Four for devices, five for disk health (ADR-0065), and remote access
	// down and EasyRMM agent silent (ADR-0069).
	seeded := map[string]policyView{}
	for _, p := range policies.Items {
		seeded[p.Name] = p
	}
	if len(policies.Items) != 11 || !seeded["Disk almost full"].CanEdit || !seeded["Remote access down"].Enabled || !seeded["EasyRMM agent silent"].Enabled {
		t.Fatalf("seeded policies %+v", policies.Items)
	}

	// Policies.
	var p policyView
	admin.expect(http.StatusCreated, "POST", "/api/v1/alert-policies", map[string]any{
		"organizationId": acme, "siteId": hq.ID, "name": "HQ memory", "kind": "memory", "threshold": 25, "minutes": 5, "severity": "warning",
	}, &p)
	if p.Level != "site" || *p.Threshold != 25 || !p.Enabled {
		t.Fatalf("created %+v", p)
	}
	wantStatus(t, admin.do("POST", "/api/v1/alert-policies", map[string]any{"name": "x", "kind": "cpu", "minutes": 5, "severity": "warning"}),
		http.StatusUnprocessableEntity, "validation_failed")
	wantStatus(t, admin.do("POST", "/api/v1/alert-policies", "x"), http.StatusBadRequest, "")
	admin.expect(http.StatusOK, "PATCH", "/api/v1/alert-policies/"+p.ID, map[string]any{"minutes": 3}, &p)
	if p.Minutes != 3 {
		t.Fatalf("updated %+v", p)
	}
	admin.expect(http.StatusOK, "GET", "/api/v1/alert-policies/"+p.ID, nil, &p)
	admin.expect(http.StatusOK, "GET", "/api/v1/alert-policies?organizationId="+acme, nil, &policies)
	if len(policies.Items) != 12 {
		t.Fatalf("Acme's policies %+v", policies.Items)
	}
	wantStatus(t, admin.do("GET", "/api/v1/alert-policies?organizationId=nope", nil), http.StatusUnprocessableEntity, "validation_failed")
	wantStatus(t, admin.do("GET", "/api/v1/alert-policies/nope", nil), http.StatusNotFound, "not_found")
	wantStatus(t, admin.do("PATCH", "/api/v1/alert-policies/00000000-0000-0000-0000-000000000001", map[string]any{"minutes": 3}), http.StatusNotFound, "not_found")

	// The server evaluates; alerts appear.
	if _, err := h.deps.Monitoring.Evaluate(context.Background()); err != nil {
		t.Fatal(err)
	}
	var alerts struct {
		Items []alertView
		Next  string
	}
	admin.expect(http.StatusOK, "GET", "/api/v1/alerts", nil, &alerts)
	if len(alerts.Items) != 2 || alerts.Items[0].DeviceName != "pc-01" || !alerts.Items[0].CanManage {
		t.Fatalf("alerts %+v", alerts.Items)
	}
	admin.expect(http.StatusOK, "GET", "/api/v1/alerts?severity=critical&deviceId="+device.ID+"&siteId="+hq.ID+"&organizationId="+acme, nil, &alerts)
	if len(alerts.Items) != 1 || alerts.Items[0].Name != "Disk almost full" || alerts.Items[0].LastValue != 96 {
		t.Fatalf("critical alerts %+v", alerts.Items)
	}
	disk := alerts.Items[0]
	admin.expect(http.StatusOK, "GET", "/api/v1/alerts?limit=1", nil, &alerts)
	if len(alerts.Items) != 1 || alerts.Next == "" {
		t.Fatalf("first page %+v %q", alerts.Items, alerts.Next)
	}
	var page2 struct {
		Items []alertView
		Next  string
	}
	admin.expect(http.StatusOK, "GET", "/api/v1/alerts?limit=1&before="+alerts.Next, nil, &page2)
	if len(page2.Items) != 1 || page2.Next != "" || page2.Items[0].ID == alerts.Items[0].ID {
		t.Fatalf("second page %+v %q", page2.Items, page2.Next)
	}
	for _, q := range []string{"status=open", "severity=info", "limit=0", "before=x", "deviceId=x", "organizationId=x", "siteId=x"} {
		wantStatus(t, admin.do("GET", "/api/v1/alerts?"+q, nil), http.StatusUnprocessableEntity, "validation_failed")
	}
	var policy policyView
	admin.expect(http.StatusOK, "GET", "/api/v1/alert-policies/"+p.ID, nil, &policy)
	if policy.ActiveAlerts != 1 {
		t.Fatalf("policy's active alerts %d", policy.ActiveAlerts)
	}

	var sum struct {
		Active, Critical, Warning, Acknowledged, Devices int
	}
	admin.expect(http.StatusOK, "GET", "/api/v1/alerts/summary", nil, &sum)
	if sum.Active != 2 || sum.Critical != 1 || sum.Warning != 1 || sum.Devices != 1 {
		t.Fatalf("summary %+v", sum)
	}
	type deviceCount struct {
		DeviceID       string `json:"deviceId"`
		OrganizationID string `json:"organizationId"`
		SiteID         string `json:"siteId"`
		Active         int    `json:"active"`
		Critical       int    `json:"critical"`
	}
	var counts struct{ Items []deviceCount }
	admin.expect(http.StatusOK, "GET", "/api/v1/alerts/devices", nil, &counts)
	if len(counts.Items) != 1 || counts.Items[0] != (deviceCount{device.ID, acme, hq.ID, 2, 1}) {
		t.Fatalf("alerts by device %+v", counts.Items)
	}

	// A read-only user sees alerts but cannot act on them.
	invite(t, h, admin, "rita@acme.example", []map[string]any{{"role": "read_only", "organizationId": acme}})
	viewer := h.client()
	viewer.signIn("rita@acme.example", "a long and unusual passphrase", "")
	var one alertView
	viewer.expect(http.StatusOK, "GET", "/api/v1/alerts/"+disk.ID, nil, &one)
	if one.CanManage {
		t.Fatal("read-only user can manage alerts")
	}
	viewer.expect(http.StatusOK, "GET", "/api/v1/alerts/devices", nil, &counts)
	if len(counts.Items) != 1 || counts.Items[0].Active != 2 {
		t.Fatalf("alerts by device for a read-only user %+v", counts.Items)
	}
	// Someone with no organization in common sees no counts.
	var other0 idObj
	admin.expect(http.StatusCreated, "POST", "/api/v1/organizations", map[string]string{"name": "Other"}, &other0)
	invite(t, h, admin, "olga@other.example", []map[string]any{{"role": "read_only", "organizationId": other0.ID}})
	other := h.client()
	other.signIn("olga@other.example", "a long and unusual passphrase", "")
	other.expect(http.StatusOK, "GET", "/api/v1/alerts/devices", nil, &counts)
	if len(counts.Items) != 0 {
		t.Fatalf("alerts by device in another organization %+v", counts.Items)
	}

	// An alert's card: its measurement over its window, and the policy's
	// openings on the device, for those who see the device's alerts only.
	var metrics struct {
		Metric        string
		Threshold     *int
		From, To      string
		BucketSeconds int
		Trimmed       *bool
		Samples       []struct {
			At    string
			Value float64
		}
	}
	for _, c := range []*client{admin, viewer} {
		c.expect(http.StatusOK, "GET", "/api/v1/alerts/"+disk.ID+"/metrics", nil, &metrics)
		if metrics.Metric != "disk" || *metrics.Threshold != 90 || metrics.BucketSeconds != 60 || metrics.Trimmed == nil || *metrics.Trimmed ||
			len(metrics.Samples) == 0 || metrics.Samples[0].Value != 96 {
			t.Fatalf("disk alert's measurements %+v", metrics)
		}
	}
	wantStatus(t, other.do("GET", "/api/v1/alerts/"+disk.ID+"/metrics", nil), http.StatusNotFound, "not_found")
	wantStatus(t, admin.do("GET", "/api/v1/alerts/nope/metrics", nil), http.StatusNotFound, "not_found")
	wantStatus(t, admin.do("GET", "/api/v1/alerts/00000000-0000-0000-0000-000000000001/metrics", nil), http.StatusNotFound, "not_found")
	other.expect(http.StatusOK, "GET", "/api/v1/alerts?status=all&policyId="+p.ID, nil, &alerts)
	if len(alerts.Items) != 0 {
		t.Fatalf("another organization's alerts by policy %+v", alerts.Items)
	}
	viewer.expect(http.StatusOK, "GET", "/api/v1/alerts?status=all&deviceId="+device.ID+"&policyId="+p.ID, nil, &alerts)
	if len(alerts.Items) != 1 || alerts.Items[0].Name != "HQ memory" {
		t.Fatalf("the policy's alerts on the device %+v", alerts.Items)
	}
	admin.expect(http.StatusOK, "GET", "/api/v1/alerts?status=all&policyId="+p.ID+"&subject=sda", nil, &alerts)
	if len(alerts.Items) != 0 {
		t.Fatalf("another subject's alerts %+v", alerts.Items)
	}
	for _, q := range []string{"policyId=x", "subject=" + strings.Repeat("x", 65)} {
		wantStatus(t, admin.do("GET", "/api/v1/alerts?"+q, nil), http.StatusUnprocessableEntity, "validation_failed")
	}
	wantStatus(t, viewer.do("POST", "/api/v1/alerts/"+disk.ID+"/acknowledge", nil), http.StatusForbidden, "forbidden")
	wantStatus(t, viewer.do("PATCH", "/api/v1/alert-policies/"+p.ID, map[string]any{"minutes": 4}), http.StatusForbidden, "forbidden")

	admin.expect(http.StatusOK, "POST", "/api/v1/alerts/"+disk.ID+"/acknowledge", nil, &one)
	if one.Status != "acknowledged" || one.AcknowledgedBy != "admin@msp.example" {
		t.Fatalf("acknowledged %+v", one)
	}
	admin.expect(http.StatusOK, "POST", "/api/v1/alerts/"+disk.ID+"/resolve", nil, &one)
	if one.Status != "resolved" || one.Resolution != "manual" {
		t.Fatalf("resolved %+v", one)
	}
	wantStatus(t, admin.do("POST", "/api/v1/alerts/"+disk.ID+"/resolve", nil), http.StatusConflict, "alert_resolved")
	wantStatus(t, admin.do("POST", "/api/v1/alerts/nope/acknowledge", nil), http.StatusNotFound, "not_found")
	wantStatus(t, admin.do("POST", "/api/v1/alerts/nope/resolve", nil), http.StatusNotFound, "not_found")
	wantStatus(t, admin.do("GET", "/api/v1/alerts/00000000-0000-0000-0000-000000000001", nil), http.StatusNotFound, "not_found")
	admin.expect(http.StatusOK, "GET", "/api/v1/alerts?status=resolved", nil, &alerts)
	if len(alerts.Items) != 1 || alerts.Items[0].ID != disk.ID {
		t.Fatalf("resolved %+v", alerts.Items)
	}

	// Deleting the policy resolves its alert.
	admin.expect(http.StatusNoContent, "DELETE", "/api/v1/alert-policies/"+p.ID, nil, nil)
	wantStatus(t, admin.do("DELETE", "/api/v1/alert-policies/"+p.ID, nil), http.StatusNotFound, "not_found")
	admin.expect(http.StatusOK, "GET", "/api/v1/alerts?status=all", nil, &alerts)
	if len(alerts.Items) != 2 || alerts.Items[0].Resolution != "policy_deleted" {
		t.Fatalf("after deleting the policy %+v", alerts.Items)
	}

	// Signed out, nothing.
	wantStatus(t, h.client().do("GET", "/api/v1/alerts", nil), http.StatusUnauthorized, "")
}
