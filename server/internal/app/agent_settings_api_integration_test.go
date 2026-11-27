//go:build integration

package app_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/server/internal/database"
)

type settingEntry struct {
	Key string `json:"key"`
	Set *struct {
		Value    int  `json:"value"`
		Enforced bool `json:"enforced"`
		InEffect bool `json:"inEffect"`
	} `json:"set"`
	Inherited struct {
		Value int `json:"value"`
		From  *struct {
			Scope string `json:"scope"`
			Name  string `json:"name"`
		} `json:"from"`
	} `json:"inherited"`
	EnforcedBy *struct {
		Scope string `json:"scope"`
	} `json:"enforcedBy"`
	Effective struct {
		Value  int  `json:"value"`
		Raised bool `json:"raised"`
	} `json:"effective"`
	CanWrite   bool   `json:"canWrite"`
	CanEnforce bool   `json:"canEnforce"`
	Permission string `json:"permission"`
	Min        int    `json:"min"`
}

type settingList struct {
	Scope  string         `json:"scope"`
	Name   string         `json:"name"`
	Items  []settingEntry `json:"items"`
	Limits struct {
		Min int `json:"minHeartbeatSeconds"`
	} `json:"limits"`
	Device *struct {
		HeartbeatSeconds int `json:"heartbeatSeconds"`
	} `json:"device"`
}

func insertID(t *testing.T, f *moveFixture, sql string, args ...any) string {
	t.Helper()
	var id string
	if err := f.h.db.DB.InTx(context.Background(), database.System, func(tx pgx.Tx) error {
		return tx.QueryRow(context.Background(), sql, args...).Scan(&id)
	}); err != nil {
		t.Fatal(err)
	}
	return id
}

const settingKey = "/agent.heartbeat_seconds"

// Every route and every error of the agent settings API (ADR-0058).
func TestAgentSettingsAPI(t *testing.T) {
	f := newMoveFixture(t)
	dev := f.device(t, "srv-01", f.acme, f.hq, &f.servers)
	bare := insertID(t, f, `INSERT INTO devices (organization_id, site_id, name, platform) VALUES ($1, $2, 'no-agent', 'linux') RETURNING id`, f.acme, f.hq)
	admin := f.admin
	val := func(v int, enforced bool) map[string]any { return map[string]any{"value": v, "enforced": enforced} }
	list := func(c *client, path string) settingList {
		t.Helper()
		var l settingList
		c.expect(http.StatusOK, "GET", path, nil, &l)
		return l
	}

	// The catalog.
	var keys struct {
		Items []struct {
			Key         string            `json:"key"`
			Permissions map[string]string `json:"permissions"`
			EnforceAt   []string          `json:"enforceAt"`
		} `json:"items"`
	}
	admin.expect(http.StatusOK, "GET", "/api/v1/agent-settings/keys", nil, &keys)
	if len(keys.Items) != 1 || keys.Items[0].Key != "agent.heartbeat_seconds" || keys.Items[0].Permissions["device"] != "device.configure" || keys.Items[0].Permissions["platform"] != "settings.manage" {
		t.Fatalf("keys: %+v", keys)
	}

	// Each scope: set, read, change, clear.
	bases := map[string]string{
		"platform":     "/api/v1/settings/agent-settings",
		"organization": "/api/v1/organizations/" + f.acme + "/agent-settings",
		"site":         "/api/v1/sites/" + f.hq + "/agent-settings",
		"device":       "/api/v1/devices/" + dev + "/agent-settings",
	}
	for i, scope := range []string{"platform", "organization", "site", "device"} {
		base := bases[scope]
		v := 100 - 10*i
		var e settingEntry
		admin.expect(http.StatusOK, "PUT", base+settingKey, val(v, false), &e)
		if e.Set == nil || e.Set.Value != v || e.Effective.Value != v {
			t.Fatalf("%s after set: %+v", scope, e)
		}
		l := list(admin, base)
		if l.Scope != scope || len(l.Items) != 1 || l.Items[0].Set == nil || l.Items[0].Set.Value != v || !l.Items[0].CanWrite {
			t.Fatalf("%s listing: %+v", scope, l)
		}
	}
	d := list(admin, bases["device"])
	if d.Device == nil || d.Device.HeartbeatSeconds != 60 || d.Name != "srv-01" || d.Items[0].Inherited.Value != 80 || d.Items[0].Inherited.From.Scope != "site" || d.Items[0].Inherited.From.Name != "HQ" {
		t.Fatalf("device listing: %+v", d)
	}
	admin.expect(http.StatusNoContent, "DELETE", bases["device"]+settingKey, nil, nil)
	if e := list(admin, bases["device"]).Items[0]; e.Set != nil || e.Effective.Value != 80 {
		t.Fatalf("after clearing the device: %+v", e)
	}
	wantStatus(t, admin.do("DELETE", bases["device"]+settingKey, nil), http.StatusNotFound, "not_found")

	// Errors: a bad value, a bad scope, an unknown key, a device without the
	// agent, an unknown target.
	wantStatus(t, admin.do("PUT", bases["site"]+settingKey, val(5, false)), http.StatusBadRequest, "setting_invalid")
	wantStatus(t, admin.do("PUT", bases["site"]+settingKey, map[string]any{"value": "60"}), http.StatusBadRequest, "setting_invalid")
	wantStatus(t, admin.do("PUT", bases["site"]+settingKey, val(60, true)), http.StatusBadRequest, "setting_scope")
	wantStatus(t, admin.do("PUT", bases["site"]+settingKey, map[string]any{"value": 60, "extra": 1}), http.StatusUnprocessableEntity, "")
	wantStatus(t, admin.do("PUT", bases["site"]+"/agent.nothing", val(60, false)), http.StatusNotFound, "not_found")
	wantStatus(t, admin.do("GET", "/api/v1/devices/"+bare+"/agent-settings", nil), http.StatusBadRequest, "setting_scope")
	wantStatus(t, admin.do("PUT", "/api/v1/devices/"+bare+"/agent-settings"+settingKey, val(60, false)), http.StatusBadRequest, "setting_scope")
	wantStatus(t, admin.do("GET", "/api/v1/sites/00000000-0000-0000-0000-000000000001/agent-settings", nil), http.StatusNotFound, "not_found")
	wantStatus(t, admin.do("GET", "/api/v1/sites/not-a-uuid/agent-settings", nil), http.StatusNotFound, "")

	// Enforcement: the organization enforces; below it, 409; the platform
	// limits.
	admin.expect(http.StatusOK, "PUT", bases["organization"]+settingKey, val(200, true), nil)
	wantStatus(t, admin.do("PUT", bases["site"]+settingKey, val(60, false)), http.StatusConflict, "setting_enforced")
	wantStatus(t, admin.do("PUT", bases["device"]+settingKey, val(60, false)), http.StatusConflict, "setting_enforced")
	if e := list(admin, bases["device"]).Items[0]; e.EnforcedBy == nil || e.EnforcedBy.Scope != "organization" || e.Effective.Value != 200 || e.CanWrite {
		t.Fatalf("under enforcement: %+v", e)
	}
	if e := list(admin, bases["site"]).Items[0]; e.Set == nil || e.Set.InEffect || e.Set.Value != 80 {
		t.Fatalf("the site's kept value: %+v", e)
	}
	var lim struct {
		Min int `json:"minHeartbeatSeconds"`
	}
	admin.expect(http.StatusOK, "GET", bases["platform"]+"/limits", nil, &lim)
	if lim.Min != 30 {
		t.Fatalf("default limits: %+v", lim)
	}
	admin.expect(http.StatusOK, "PUT", bases["platform"]+"/limits", map[string]int{"minHeartbeatSeconds": 100}, &lim)
	if lim.Min != 100 || list(admin, bases["site"]).Limits.Min != 100 {
		t.Fatalf("limits after: %+v", lim)
	}
	wantStatus(t, admin.do("PUT", bases["platform"]+"/limits", map[string]int{"minHeartbeatSeconds": 10}), http.StatusBadRequest, "setting_invalid")
	wantStatus(t, admin.do("PUT", bases["platform"]+"/limits", map[string]int{"min": 10}), http.StatusUnprocessableEntity, "")

	// People: a technician reads but writes nothing; a site administrator
	// writes at their site and device but not the organization's or the
	// platform's; a read-only user sees.
	tech := f.user(t, "tess@acme.example", "technician", map[string]any{"organizationId": f.acme})
	siteAdmin := f.user(t, "sam@acme.example", "site_admin", map[string]any{"organizationId": f.acme, "siteId": f.hq})
	other := f.user(t, "gina@globex.example", "org_admin", map[string]any{"organizationId": f.globex})
	for _, base := range bases {
		wantStatus(t, tech.do("PUT", base+settingKey, val(150, false)), http.StatusForbidden, "forbidden")
		wantStatus(t, tech.do("DELETE", base+settingKey, nil), http.StatusForbidden, "forbidden")
		list(tech, base)
	}
	if e := list(tech, bases["device"]).Items[0]; e.CanWrite || e.Permission != "device.configure" {
		t.Fatalf("a technician is offered a write: %+v", e)
	}
	admin.expect(http.StatusOK, "PUT", bases["organization"]+settingKey, val(200, false), nil)
	siteAdmin.expect(http.StatusOK, "PUT", bases["site"]+settingKey, val(150, false), nil)
	siteAdmin.expect(http.StatusOK, "PUT", bases["device"]+settingKey, val(120, false), nil)
	wantStatus(t, siteAdmin.do("PUT", bases["organization"]+settingKey, val(150, false)), http.StatusForbidden, "forbidden")
	wantStatus(t, siteAdmin.do("PUT", bases["platform"]+settingKey, val(150, false)), http.StatusForbidden, "forbidden")
	wantStatus(t, siteAdmin.do("PUT", bases["platform"]+"/limits", map[string]int{"minHeartbeatSeconds": 30}), http.StatusForbidden, "forbidden")
	if e := list(siteAdmin, bases["platform"]).Items[0]; e.CanWrite || e.Set == nil {
		t.Fatalf("a site admin reading the platform's value: %+v", e)
	}
	// Another organization's people see nothing of these.
	for _, p := range []string{bases["organization"], bases["site"], bases["device"]} {
		wantStatus(t, other.do("GET", p, nil), http.StatusNotFound, "not_found")
		wantStatus(t, other.do("PUT", p+settingKey, val(150, false)), http.StatusNotFound, "not_found")
	}
	// Not signed in.
	wantStatus(t, f.h.client().do("GET", bases["platform"], nil), http.StatusUnauthorized, "")
	wantStatus(t, f.h.client().do("GET", "/api/v1/agent-settings/keys", nil), http.StatusUnauthorized, "")

	// The audit log names each change.
	var events struct {
		Items []struct {
			Action string `json:"action"`
		} `json:"items"`
	}
	admin.expect(http.StatusOK, "GET", "/api/v1/audit?limit=200", nil, &events)
	seen := map[string]int{}
	for _, e := range events.Items {
		seen[e.Action]++
	}
	if seen["agent_setting.set"] < 8 || seen["agent_setting.cleared"] != 1 || seen["agent_setting.limits_set"] != 1 {
		t.Fatalf("audit: %+v", seen)
	}
}

// The writes are rate limited per caller and per target (429).
func TestAgentSettingsAPIRateLimit(t *testing.T) {
	f := newMoveFixture(t)
	base := "/api/v1/sites/" + f.hq + "/agent-settings" + settingKey
	var last response
	n := 0
	for ; n < 40; n++ {
		last = f.admin.do("PUT", base, map[string]any{"value": 60 + n%2})
		if last.status != http.StatusOK {
			break
		}
	}
	if n != 30 {
		t.Fatalf("%d writes before the limit", n)
	}
	wantStatus(t, last, http.StatusTooManyRequests, "rate_limited")
}

// A move to another site ends the settings set for the device alone; one
// within the site keeps them (ADR-0069, ADR-0058).
func TestMoveEndsDeviceSettings(t *testing.T) {
	f := newMoveFixture(t)
	dev := f.device(t, "srv-01", f.acme, f.hq, &f.servers)
	base := "/api/v1/devices/" + dev + "/agent-settings" + settingKey
	f.admin.expect(http.StatusOK, "PUT", base, map[string]any{"value": 90}, nil)
	f.admin.expect(http.StatusOK, "POST", "/api/v1/devices/move", move([]string{dev}, f.hq, &f.desks), nil)
	if n := f.count(t, `SELECT count(*) FROM agent_settings WHERE device_id = $1`, dev); n != 1 {
		t.Fatalf("a move within the site left %d rows", n)
	}
	f.admin.expect(http.StatusOK, "POST", "/api/v1/devices/move", move([]string{dev}, f.branch, nil), nil)
	if n := f.count(t, `SELECT count(*) FROM agent_settings WHERE device_id = $1`, dev); n != 0 {
		t.Fatalf("a move to another site left %d rows", n)
	}
}

// An alert policy's page lists the devices whose interval makes it wait
// longer (ADR-0058).
func TestPolicySlowDevicesAPI(t *testing.T) {
	f := newMoveFixture(t)
	slow := f.device(t, "slow-01", f.acme, f.hq, &f.servers)
	f.device(t, "quick-01", f.acme, f.hq, &f.servers)
	f.admin.expect(http.StatusOK, "PUT", "/api/v1/devices/"+slow+"/agent-settings"+settingKey, map[string]any{"value": 300}, nil)
	if err := f.h.db.DB.InTx(context.Background(), database.System, func(tx pgx.Tx) error {
		_, err := tx.Exec(context.Background(), `UPDATE devices SET agent_heartbeat_seconds = 300 WHERE id = $1`, slow)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	var p idObj
	f.admin.expect(http.StatusCreated, "POST", "/api/v1/alert-policies", map[string]any{
		"name": "Gone quiet", "kind": "offline", "minutes": 10, "severity": "warning", "enabled": true}, &p)
	var out struct {
		Items []struct {
			DeviceID         string `json:"deviceId"`
			Name             string `json:"name"`
			HeartbeatSeconds int    `json:"heartbeatSeconds"`
			WaitMinutes      int    `json:"waitMinutes"`
		} `json:"items"`
		Total int `json:"total"`
	}
	f.admin.expect(http.StatusOK, "GET", "/api/v1/alert-policies/"+p.ID+"/slow-devices", nil, &out)
	if out.Total != 1 || len(out.Items) != 1 || out.Items[0].DeviceID != slow || out.Items[0].WaitMinutes != 15 || out.Items[0].HeartbeatSeconds != 300 {
		t.Fatalf("slow devices: %+v", out)
	}
	wantStatus(t, f.admin.do("GET", "/api/v1/alert-policies/00000000-0000-0000-0000-000000000001/slow-devices", nil), http.StatusNotFound, "not_found")
	other := f.user(t, "gina@globex.example", "org_admin", map[string]any{"organizationId": f.globex})
	other.expect(http.StatusOK, "GET", "/api/v1/alert-policies/"+p.ID+"/slow-devices", nil, &out)
	if out.Total != 0 {
		t.Fatalf("another organization sees %d of Acme's devices", out.Total)
	}
}
