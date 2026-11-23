//go:build integration

package app_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/server/internal/database"
)

// TestGroupIDFilters narrows every list a console view shows to one device
// group (ADR-0069): devices, alerts, jobs, runs, scripts and software.
func TestGroupIDFilters(t *testing.T) {
	h := newHarness(t, false)
	admin, _ := setUp(t, h)
	acme := orgID(t, admin, "Acme")
	var hq, branch idObj
	admin.expect(http.StatusCreated, "POST", "/api/v1/organizations/"+acme+"/sites", map[string]string{"name": "HQ", "timezone": "UTC"}, &hq)
	admin.expect(http.StatusCreated, "POST", "/api/v1/organizations/"+acme+"/sites", map[string]string{"name": "Branch", "timezone": "UTC"}, &branch)
	var servers, desks, branchGroup idObj
	admin.expect(http.StatusCreated, "POST", "/api/v1/sites/"+hq.ID+"/device-groups", map[string]string{"name": "Servers"}, &servers)
	admin.expect(http.StatusCreated, "POST", "/api/v1/sites/"+hq.ID+"/device-groups", map[string]string{"name": "Desks"}, &desks)
	admin.expect(http.StatusCreated, "POST", "/api/v1/sites/"+branch.ID+"/device-groups", map[string]string{"name": "Tills"}, &branchGroup)

	// srv-01 and srv-02 are in Servers, desk-01 in Desks, loose-01 in none, till-01 at the other site.
	device := func(name, site string, group *string) string {
		var id string
		if err := h.db.DB.InTx(context.Background(), database.System, func(tx pgx.Tx) error {
			return tx.QueryRow(context.Background(), `INSERT INTO devices (organization_id, site_id, device_group_id, name, platform, agent_last_seen_at, agent_public_key, enrolled_at)
				VALUES ($1, $2, $3, $4, 'linux', now(), sha256($4::text::bytea), now()) RETURNING id`, acme, site, group, name).Scan(&id)
		}); err != nil {
			t.Fatal(err)
		}
		exec(t, h, `INSERT INTO device_metric_samples (device_id, at, cpu_percent, memory_percent, swap_percent, disk_percent, load1)
			SELECT $1, now() - make_interval(secs => g * 60 + 10), 5, 30, 0, 96, 0 FROM generate_series(0, 9) g`, id)
		exec(t, h, `INSERT INTO device_software (device_id, name, version) VALUES ($1, 'openssl', '3.0')`, id)
		return id
	}
	srv1, srv2 := device("srv-01", hq.ID, &servers.ID), device("srv-02", hq.ID, &servers.ID)
	desk := device("desk-01", hq.ID, &desks.ID)
	loose := device("loose-01", hq.ID, nil)
	till := device("till-01", branch.ID, &branchGroup.ID)

	names := func(items []struct {
		Name string `json:"name"`
	}) []string {
		out := []string{}
		for _, i := range items {
			out = append(out, i.Name)
		}
		return out
	}
	same := func(got, want []string) bool {
		if len(got) != len(want) {
			return false
		}
		for i := range got {
			if got[i] != want[i] {
				return false
			}
		}
		return true
	}

	// Devices.
	var devs struct {
		Items []struct {
			Name string `json:"name"`
		}
	}
	admin.expect(http.StatusOK, "GET", "/api/v1/devices?groupId="+servers.ID, nil, &devs)
	if got := names(devs.Items); !same(got, []string{"srv-01", "srv-02"}) {
		t.Errorf("devices in Servers: %v", got)
	}
	admin.expect(http.StatusOK, "GET", "/api/v1/devices?groupId="+desks.ID+"&siteId="+hq.ID, nil, &devs)
	if got := names(devs.Items); !same(got, []string{"desk-01"}) {
		t.Errorf("devices in Desks: %v", got)
	}
	admin.expect(http.StatusOK, "GET", "/api/v1/devices?groupId="+servers.ID+"&siteId="+branch.ID, nil, &devs)
	if len(devs.Items) != 0 {
		t.Errorf("a group of another site: %v", devs.Items)
	}
	admin.expect(http.StatusOK, "GET", "/api/v1/devices", nil, &devs)
	if len(devs.Items) != 5 {
		t.Errorf("all devices: %d", len(devs.Items))
	}

	// Alerts: every device raised a disk alert.
	if _, err := h.deps.Monitoring.Evaluate(context.Background()); err != nil {
		t.Fatal(err)
	}
	var alerts struct {
		Items []struct {
			DeviceName string `json:"deviceName"`
		}
	}
	admin.expect(http.StatusOK, "GET", "/api/v1/alerts?groupId="+servers.ID, nil, &alerts)
	seen := map[string]bool{}
	for _, a := range alerts.Items {
		seen[a.DeviceName] = true
	}
	if len(seen) != 2 || !seen["srv-01"] || !seen["srv-02"] {
		t.Errorf("alerts in Servers are of %v", seen)
	}
	admin.expect(http.StatusOK, "GET", "/api/v1/alerts?groupId="+desks.ID, nil, &alerts)
	for _, a := range alerts.Items {
		if a.DeviceName != "desk-01" {
			t.Errorf("alert of %s in Desks", a.DeviceName)
		}
	}
	if len(alerts.Items) == 0 {
		t.Error("no alerts in Desks")
	}

	// Scripts: one of the organization, one of HQ, one of Branch.
	var orgScript, hqScript, branchScript idObj
	admin.expect(http.StatusCreated, "POST", "/api/v1/scripts", map[string]any{"organizationId": acme, "name": "Org", "shell": "bash", "body": "true"}, &orgScript)
	admin.expect(http.StatusCreated, "POST", "/api/v1/scripts", map[string]any{"organizationId": acme, "siteId": hq.ID, "name": "Hq", "shell": "bash", "body": "true"}, &hqScript)
	admin.expect(http.StatusCreated, "POST", "/api/v1/scripts", map[string]any{"organizationId": acme, "siteId": branch.ID, "name": "Branch", "shell": "bash", "body": "true"}, &branchScript)
	var scripts struct {
		Items []struct {
			Name string `json:"name"`
		}
	}
	admin.expect(http.StatusOK, "GET", "/api/v1/scripts?groupId="+servers.ID, nil, &scripts)
	if got := names(scripts.Items); !same(got, []string{"Hq", "Org"}) {
		t.Errorf("scripts for Servers: %v", got)
	}
	admin.expect(http.StatusOK, "GET", "/api/v1/scripts?groupId="+branchGroup.ID, nil, &scripts)
	if got := names(scripts.Items); !same(got, []string{"Branch", "Org"}) {
		t.Errorf("scripts for Tills: %v", got)
	}
	wantStatus(t, admin.do("GET", "/api/v1/scripts?groupId=00000000-0000-0000-0000-000000000001", nil), http.StatusNotFound, "not_found")

	// Jobs and runs: one job on srv-01 and desk-01, one on till-01.
	var j1, j2 idObj
	admin.expect(http.StatusCreated, "POST", "/api/v1/jobs", map[string]any{"scriptId": orgScript.ID, "deviceIds": []string{srv1, desk}}, &j1)
	admin.expect(http.StatusCreated, "POST", "/api/v1/jobs", map[string]any{"scriptId": orgScript.ID, "deviceIds": []string{till}}, &j2)
	var jobs struct {
		Items []idObj
	}
	for group, want := range map[string]int{servers.ID: 1, desks.ID: 1, branchGroup.ID: 1} {
		admin.expect(http.StatusOK, "GET", "/api/v1/jobs?groupId="+group, nil, &jobs)
		if len(jobs.Items) != want {
			t.Errorf("jobs of group %s: %d", group, len(jobs.Items))
		}
	}
	admin.expect(http.StatusOK, "GET", "/api/v1/jobs?groupId="+servers.ID, nil, &jobs)
	if len(jobs.Items) != 1 || jobs.Items[0].ID != j1.ID {
		t.Errorf("jobs of Servers: %+v", jobs.Items)
	}
	var runs struct {
		Items []struct {
			DeviceID string `json:"deviceId"`
		}
	}
	admin.expect(http.StatusOK, "GET", "/api/v1/job-runs?groupId="+servers.ID, nil, &runs)
	if len(runs.Items) != 1 || runs.Items[0].DeviceID != srv1 {
		t.Errorf("runs of Servers: %+v", runs.Items)
	}
	wantStatus(t, admin.do("GET", "/api/v1/job-runs", nil), http.StatusUnprocessableEntity, "validation_failed")
	_ = srv2
	_ = loose

	// Software.
	var found struct {
		Items []struct {
			Name    string `json:"name"`
			Devices int    `json:"devices"`
		}
	}
	admin.expect(http.StatusOK, "GET", "/api/v1/software?q=openssl&groupId="+servers.ID, nil, &found)
	if len(found.Items) != 1 || found.Items[0].Devices != 2 {
		t.Errorf("software in Servers: %+v", found.Items)
	}
	var holders struct {
		Items []struct {
			DeviceName string `json:"deviceName"`
		}
	}
	admin.expect(http.StatusOK, "GET", "/api/v1/software/devices?name=openssl&groupId="+desks.ID, nil, &holders)
	if len(holders.Items) != 1 || holders.Items[0].DeviceName != "desk-01" {
		t.Errorf("holders in Desks: %+v", holders.Items)
	}

	// The tree's groups and counts, and the devices of a site in no group.
	var tree struct {
		Groups []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"groups"`
		Counts []struct {
			SiteID  string  `json:"siteId"`
			GroupID *string `json:"groupId"`
			Total   int     `json:"total"`
			Online  int     `json:"online"`
		} `json:"counts"`
	}
	admin.expect(http.StatusOK, "GET", "/api/v1/device-tree", nil, &tree)
	if len(tree.Groups) != 3 || len(tree.Counts) != 4 {
		t.Fatalf("tree: %+v", tree)
	}
	for _, n := range tree.Counts {
		switch {
		case n.GroupID != nil && *n.GroupID == servers.ID:
			if n.Total != 2 || n.Online != 2 || n.SiteID != hq.ID {
				t.Errorf("Servers: %+v", n)
			}
		case n.GroupID == nil && n.SiteID == hq.ID:
			if n.Total != 1 {
				t.Errorf("HQ ungrouped: %+v", n)
			}
		}
	}
	admin.expect(http.StatusOK, "GET", "/api/v1/devices?siteId="+hq.ID+"&ungrouped=true", nil, &devs)
	if got := names(devs.Items); !same(got, []string{"loose-01"}) {
		t.Errorf("devices of HQ in no group: %v", got)
	}

	// A malformed id is refused on each endpoint.
	for _, p := range []string{"/api/v1/devices", "/api/v1/alerts", "/api/v1/scripts", "/api/v1/jobs", "/api/v1/job-runs", "/api/v1/software", "/api/v1/software/devices?name=x&"} {
		sep := "?"
		if p[len(p)-1] == '&' {
			sep = ""
		}
		wantStatus(t, admin.do("GET", p+sep+"groupId=nope", nil), http.StatusUnprocessableEntity, "validation_failed")
	}
}
