//go:build integration

package app_test

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/server/internal/database"
)

type ruleView struct {
	ID             string   `json:"id"`
	OrganizationID *string  `json:"organizationId"`
	Platform       bool     `json:"platform"`
	Source         string   `json:"source"`
	Name           string   `json:"name"`
	Enabled        bool     `json:"enabled"`
	WaitMinutes    int      `json:"waitMinutes"`
	ReminderHours  int      `json:"reminderHours"`
	OnResolve      bool     `json:"onResolve"`
	ChannelIDs     []string `json:"channelIds"`
	Severities     struct {
		Mode   string   `json:"mode"`
		Values []string `json:"values"`
	} `json:"severities"`
	Sites struct {
		Mode string   `json:"mode"`
		IDs  []string `json:"ids"`
	} `json:"sites"`
}

// notifyFixture is an organization with a site, a device and an email channel.
type notifyFixture struct {
	admin   *client
	org     string
	site    string
	device  string
	channel string
}

func newNotifyFixture(t *testing.T, h *harness) notifyFixture {
	t.Helper()
	admin, _ := setUp(t, h)
	f := notifyFixture{admin: admin, org: orgID(t, admin, "Acme")}
	var s idObj
	admin.expect(http.StatusCreated, "POST", "/api/v1/organizations/"+f.org+"/sites", map[string]string{"name": "HQ", "timezone": "UTC"}, &s)
	f.site = s.ID
	if err := h.db.DB.InTx(context.Background(), database.System, func(tx pgx.Tx) error {
		return tx.QueryRow(context.Background(), `INSERT INTO devices (organization_id, site_id, name) VALUES ($1, $2, 'pc-01') RETURNING id`, f.org, f.site).Scan(&f.device)
	}); err != nil {
		t.Fatal(err)
	}
	var ch idObj
	admin.expect(http.StatusCreated, "POST", "/api/v1/notifications/channels",
		map[string]any{"organizationId": f.org, "kind": "email", "name": "Desk", "recipients": []string{"desk@acme.example"}}, &ch)
	f.channel = ch.ID
	return f
}

// otherOrgAdmin makes a second organization and signs in its administrator.
func otherOrgAdmin(t *testing.T, h *harness, admin *client) *client {
	t.Helper()
	var beta idObj
	admin.expect(http.StatusCreated, "POST", "/api/v1/organizations", map[string]string{"name": "Beta"}, &beta)
	invite(t, h, admin, "bea@beta.example", []map[string]any{{"role": "org_admin", "organizationId": beta.ID}})
	bea := h.client()
	bea.signIn("bea@beta.example", "a long and unusual passphrase", "")
	return bea
}

// Rules through the real server: create, read, update, list, validate, own
// organization only, quota and delete (ADR-0053).
func TestHTTPNotifyRules(t *testing.T) {
	h := newHarness(t, false)
	f := newNotifyFixture(t, h)
	admin := f.admin

	var created ruleView
	admin.expect(http.StatusCreated, "POST", "/api/v1/notifications/rules", map[string]any{
		"organizationId": f.org, "name": "Critical to desk", "enabled": true, "channelIds": []string{f.channel}, "onResolve": true,
		"severities": map[string]any{"mode": "list", "values": []string{"critical"}},
		"sites":      map[string]any{"mode": "list", "ids": []string{f.site}},
	}, &created)
	if created.ID == "" || created.Platform || created.Source != "alerts" || created.Severities.Mode != "list" ||
		len(created.Severities.Values) != 1 || len(created.Sites.IDs) != 1 || len(created.ChannelIDs) != 1 || !created.OnResolve {
		t.Fatalf("created %+v", created)
	}

	var got ruleView
	admin.expect(http.StatusOK, "GET", "/api/v1/notifications/rules/"+created.ID, nil, &got)
	if got.Name != "Critical to desk" || got.ChannelIDs[0] != f.channel {
		t.Fatalf("read back %+v", got)
	}

	var upd ruleView
	admin.expect(http.StatusOK, "PUT", "/api/v1/notifications/rules/"+created.ID, map[string]any{
		"name": "Everything to desk", "enabled": false, "channelIds": []string{f.channel}, "waitMinutes": 15, "reminderHours": 4,
		"source": "notices",
	}, &upd)
	if upd.Name != "Everything to desk" || upd.Enabled || upd.WaitMinutes != 15 || upd.ReminderHours != 4 || upd.Severities.Mode != "any" || upd.Source != "notices" {
		t.Fatalf("updated %+v", upd)
	}

	var list struct {
		Rules []ruleView `json:"rules"`
	}
	admin.expect(http.StatusOK, "GET", "/api/v1/notifications/rules?organizationId="+f.org, nil, &list)
	if len(list.Rules) != 1 || list.Rules[0].ID != created.ID {
		t.Fatalf("list %+v", list.Rules)
	}

	// A platform rule has no organization and may ignore maintenance windows.
	var platChannel, plat ruleView
	admin.expect(http.StatusCreated, "POST", "/api/v1/notifications/channels", map[string]any{"kind": "email", "name": "MSP desk", "recipients": []string{"msp@msp.example"}}, &platChannel)
	admin.expect(http.StatusCreated, "POST", "/api/v1/notifications/rules", map[string]any{
		"name": "Platform rule", "enabled": true, "channelIds": []string{platChannel.ID}, "ignoreWindows": true,
	}, &plat)
	if plat.OrganizationID != nil {
		t.Fatalf("platform rule %+v", plat)
	}

	// Validation.
	bad := func(field string, m map[string]any) {
		t.Helper()
		base := map[string]any{"organizationId": f.org, "name": "r-" + field, "enabled": true, "channelIds": []string{f.channel}}
		for k, v := range m {
			base[k] = v
		}
		r := admin.do("POST", "/api/v1/notifications/rules", base)
		wantStatus(t, r, http.StatusUnprocessableEntity, "validation_failed")
		if !strings.Contains(string(r.body), field) {
			t.Fatalf("%s: error does not name the field: %s", field, r.body)
		}
	}
	bad("name", map[string]any{"name": ""})
	bad("source", map[string]any{"source": "bogus"})
	bad("severities", map[string]any{"severities": map[string]any{"mode": "list", "values": []string{"mild"}}})
	bad("severities", map[string]any{"severities": map[string]any{"mode": "sometimes"}})
	bad("deviceKinds", map[string]any{"deviceKinds": map[string]any{"mode": "list", "values": []string{"toaster"}}})
	bad("waitMinutes", map[string]any{"waitMinutes": 2000})
	bad("reminderHours", map[string]any{"reminderHours": -1})
	bad("ignoreWindows", map[string]any{"ignoreWindows": true})
	bad("channelIds", map[string]any{"channelIds": []string{}})
	bad("channelIds", map[string]any{"channelIds": []string{"00000000-0000-4000-8000-000000000001"}})
	bad("sites", map[string]any{"sites": map[string]any{"mode": "list", "ids": []string{"00000000-0000-4000-8000-000000000001"}}})
	bad("organizations", map[string]any{"organizations": map[string]any{"mode": "list", "ids": []string{f.org}}})
	bad("name", map[string]any{"name": "Everything to desk"}) // duplicate within the owner
	wantStatus(t, admin.do("POST", "/api/v1/notifications/rules", "x"), http.StatusBadRequest, "")
	wantStatus(t, admin.do("GET", "/api/v1/notifications/rules?organizationId=nope", nil), http.StatusUnprocessableEntity, "validation_failed")
	wantStatus(t, admin.do("GET", "/api/v1/notifications/rules/nope", nil), http.StatusNotFound, "not_found")
	wantStatus(t, admin.do("GET", "/api/v1/notifications/rules/00000000-0000-4000-8000-000000000001", nil), http.StatusNotFound, "not_found")
	wantStatus(t, admin.do("PUT", "/api/v1/notifications/rules/00000000-0000-4000-8000-000000000001", map[string]any{"name": "x", "channelIds": []string{f.channel}}), http.StatusNotFound, "not_found")
	wantStatus(t, admin.do("PUT", "/api/v1/notifications/rules/"+created.ID, map[string]any{"name": "x", "channelIds": []string{}}), http.StatusUnprocessableEntity, "validation_failed")

	// Quota.
	admin.expect(http.StatusOK, "PUT", "/api/v1/notifications/quotas/"+f.org, map[string]int{"channels": 5, "rules": 1, "testsPerHour": 5, "messagesPerHour": 100}, nil)
	wantStatus(t, admin.do("POST", "/api/v1/notifications/rules", map[string]any{"organizationId": f.org, "name": "one too many", "channelIds": []string{f.channel}}),
		http.StatusConflict, "rule_quota")

	// Someone with no right to the organization cannot see or touch its rules.
	bea := otherOrgAdmin(t, h, admin)
	wantStatus(t, bea.do("GET", "/api/v1/notifications/rules/"+created.ID, nil), http.StatusNotFound, "not_found")
	wantStatus(t, bea.do("PUT", "/api/v1/notifications/rules/"+created.ID, map[string]any{"name": "mine", "channelIds": []string{f.channel}}), http.StatusNotFound, "not_found")
	wantStatus(t, bea.do("DELETE", "/api/v1/notifications/rules/"+created.ID, nil), http.StatusNotFound, "not_found")
	if r := bea.do("POST", "/api/v1/notifications/rules", map[string]any{"organizationId": f.org, "name": "x", "channelIds": []string{f.channel}}); r.status < 400 {
		t.Fatalf("another organization's admin created a rule: %d", r.status)
	}
	if r := bea.do("POST", "/api/v1/notifications/rules", map[string]any{"name": "platform", "channelIds": []string{f.channel}}); r.status < 400 {
		t.Fatalf("an organization admin created a platform rule: %d", r.status)
	}
	wantStatus(t, bea.do("GET", "/api/v1/notifications/rules?organizationId="+f.org, nil), http.StatusNotFound, "not_found")
	wantStatus(t, bea.do("GET", "/api/v1/notifications/rules", nil), http.StatusNotFound, "not_found") // the platform's rules are not theirs
	wantStatus(t, h.client().do("GET", "/api/v1/notifications/rules", nil), http.StatusUnauthorized, "")

	// Delete.
	admin.expect(http.StatusNoContent, "DELETE", "/api/v1/notifications/rules/"+created.ID, nil, nil)
	wantStatus(t, admin.do("DELETE", "/api/v1/notifications/rules/"+created.ID, nil), http.StatusNotFound, "not_found")
	wantStatus(t, admin.do("GET", "/api/v1/notifications/rules/"+created.ID, nil), http.StatusNotFound, "not_found")
}

// Maintenance windows, the fleet-wide hold, the journal's quarantine and a
// device's kind, through the real server.
func TestHTTPNotifyWindowsAndAdmin(t *testing.T) {
	h := newHarness(t, false)
	f := newNotifyFixture(t, h)
	admin := f.admin

	type windowView struct {
		ID            string `json:"id"`
		SiteID        string `json:"siteId"`
		Name          string `json:"name"`
		Kind          string `json:"kind"`
		Days          []int  `json:"days"`
		Start         string `json:"start"`
		StartsAt      string `json:"startsAt"`
		LengthMinutes int    `json:"lengthMinutes"`
		Enabled       bool   `json:"enabled"`
		CanEdit       bool   `json:"canEdit"`
	}
	var weekly windowView
	admin.expect(http.StatusCreated, "POST", "/api/v1/sites/"+f.site+"/maintenance-windows", map[string]any{
		"name": "Nightly", "kind": "weekly", "days": []int{1, 3}, "start": "22:00", "lengthMinutes": 120, "enabled": true,
	}, &weekly)
	if weekly.ID == "" || weekly.SiteID != f.site || len(weekly.Days) != 2 || weekly.Start != "22:00" || !weekly.CanEdit {
		t.Fatalf("weekly %+v", weekly)
	}
	var once windowView
	startsAt := time.Now().UTC().Add(48 * time.Hour).Format("2006-01-02T15:04")
	admin.expect(http.StatusCreated, "POST", "/api/v1/sites/"+f.site+"/maintenance-windows", map[string]any{
		"name": "Patch day", "kind": "once", "startsAt": startsAt, "lengthMinutes": 60, "enabled": true,
	}, &once)
	if once.Kind != "once" || once.StartsAt != startsAt {
		t.Fatalf("once %+v", once)
	}

	var list struct {
		Windows []windowView `json:"windows"`
	}
	admin.expect(http.StatusOK, "GET", "/api/v1/maintenance-windows?organizationId="+f.org+"&siteId="+f.site, nil, &list)
	if len(list.Windows) != 2 {
		t.Fatalf("windows %+v", list.Windows)
	}
	admin.expect(http.StatusOK, "GET", "/api/v1/maintenance-windows", nil, &list)
	if len(list.Windows) != 2 {
		t.Fatalf("all windows %+v", list.Windows)
	}

	admin.expect(http.StatusOK, "PUT", "/api/v1/maintenance-windows/"+weekly.ID, map[string]any{
		"name": "Nightly (late)", "kind": "weekly", "days": []int{5}, "start": "23:30", "lengthMinutes": 30, "enabled": false,
	}, &weekly)
	if weekly.Name != "Nightly (late)" || weekly.Enabled || weekly.Start != "23:30" || len(weekly.Days) != 1 {
		t.Fatalf("updated %+v", weekly)
	}

	post := func(m map[string]any) response {
		return admin.do("POST", "/api/v1/sites/"+f.site+"/maintenance-windows", m)
	}
	invalid := http.StatusUnprocessableEntity
	wantStatus(t, post(map[string]any{"name": "", "kind": "weekly", "days": []int{1}, "start": "22:00", "lengthMinutes": 60}), invalid, "validation_failed")
	wantStatus(t, post(map[string]any{"name": "a", "kind": "weekly", "days": []int{1}, "start": "late", "lengthMinutes": 60}), invalid, "validation_failed")
	wantStatus(t, post(map[string]any{"name": "a", "kind": "weekly", "days": []int{9}, "start": "22:00", "lengthMinutes": 60}), invalid, "validation_failed")
	wantStatus(t, post(map[string]any{"name": "a", "kind": "weekly", "days": []int{}, "start": "22:00", "lengthMinutes": 60}), invalid, "validation_failed")
	wantStatus(t, post(map[string]any{"name": "a", "kind": "weekly", "days": []int{1}, "start": "22:00", "lengthMinutes": 0}), invalid, "validation_failed")
	wantStatus(t, post(map[string]any{"name": "a", "kind": "once", "startsAt": "tomorrow", "lengthMinutes": 60}), invalid, "validation_failed")
	wantStatus(t, post(map[string]any{"name": "a", "kind": "once", "startsAt": "2001-01-01T00:00", "lengthMinutes": 60}), invalid, "validation_failed")
	wantStatus(t, post(map[string]any{"name": "a", "kind": "once", "startsAt": time.Now().UTC().Add(200 * 24 * time.Hour).Format("2006-01-02T15:04"), "lengthMinutes": 60}), invalid, "validation_failed")
	wantStatus(t, post(map[string]any{"name": "a", "kind": "yearly", "lengthMinutes": 60}), invalid, "validation_failed")
	wantStatus(t, admin.do("POST", "/api/v1/sites/00000000-0000-4000-8000-000000000001/maintenance-windows", map[string]any{"name": "a", "kind": "weekly", "days": []int{1}, "start": "22:00", "lengthMinutes": 60}), http.StatusNotFound, "not_found")
	wantStatus(t, admin.do("PUT", "/api/v1/maintenance-windows/00000000-0000-4000-8000-000000000001", map[string]any{"name": "a", "kind": "weekly", "days": []int{1}, "start": "22:00", "lengthMinutes": 60}), http.StatusNotFound, "not_found")
	wantStatus(t, admin.do("GET", "/api/v1/maintenance-windows?siteId=nope", nil), invalid, "validation_failed")

	// Another organization's administrator cannot touch them.
	bea := otherOrgAdmin(t, h, admin)
	wantStatus(t, bea.do("DELETE", "/api/v1/maintenance-windows/"+once.ID, nil), http.StatusNotFound, "not_found")
	wantStatus(t, bea.do("POST", "/api/v1/sites/"+f.site+"/maintenance-windows", map[string]any{"name": "a", "kind": "weekly", "days": []int{1}, "start": "22:00", "lengthMinutes": 60}), http.StatusNotFound, "not_found")
	bea.expect(http.StatusOK, "GET", "/api/v1/maintenance-windows", nil, &list)
	if len(list.Windows) != 0 {
		t.Fatalf("Beta sees Acme's windows %+v", list.Windows)
	}

	admin.expect(http.StatusNoContent, "DELETE", "/api/v1/maintenance-windows/"+once.ID, nil, nil)
	wantStatus(t, admin.do("DELETE", "/api/v1/maintenance-windows/"+once.ID, nil), http.StatusNotFound, "not_found")

	// Device kind.
	var k struct {
		Kind string `json:"kind"`
	}
	admin.expect(http.StatusOK, "PUT", "/api/v1/devices/"+f.device+"/kind", map[string]any{"kind": "server"}, &k)
	if k.Kind != "server" {
		t.Fatalf("kind %+v", k)
	}
	admin.expect(http.StatusOK, "PUT", "/api/v1/devices/"+f.device+"/kind", map[string]any{"kind": nil}, &k)
	wantStatus(t, admin.do("PUT", "/api/v1/devices/"+f.device+"/kind", map[string]any{"kind": "toaster"}), invalid, "validation_failed")
	wantStatus(t, admin.do("PUT", "/api/v1/devices/00000000-0000-4000-8000-000000000001/kind", map[string]any{"kind": "server"}), http.StatusNotFound, "not_found")
	wantStatus(t, bea.do("PUT", "/api/v1/devices/"+f.device+"/kind", map[string]any{"kind": "server"}), http.StatusNotFound, "not_found")

	// The fleet-wide hold: none now; one is made; it ends once.
	var s struct {
		Silence *struct {
			ID      string `json:"id"`
			Counted int    `json:"counted"`
		} `json:"silence"`
	}
	admin.expect(http.StatusOK, "GET", "/api/v1/notifications/silence", nil, &s)
	if s.Silence != nil {
		t.Fatalf("silence %+v", s.Silence)
	}
	wantStatus(t, admin.do("POST", "/api/v1/notifications/silence/end", nil), http.StatusConflict, "no_silence")
	exec(t, h, `INSERT INTO fleet_silences (counted_n) VALUES (3)`)
	admin.expect(http.StatusOK, "GET", "/api/v1/notifications/silence", nil, &s)
	if s.Silence == nil || s.Silence.Counted != 3 {
		t.Fatalf("silence %+v", s.Silence)
	}
	admin.expect(http.StatusNoContent, "POST", "/api/v1/notifications/silence/end", nil, nil)
	admin.expect(http.StatusOK, "GET", "/api/v1/notifications/silence", nil, &s)
	if s.Silence != nil {
		t.Fatalf("silence not ended %+v", s.Silence)
	}
	if r := bea.do("GET", "/api/v1/notifications/silence", nil); r.status < 400 {
		t.Fatalf("an organization admin read the fleet-wide hold: %d", r.status)
	}
	if r := bea.do("POST", "/api/v1/notifications/silence/end", nil); r.status < 400 {
		t.Fatalf("an organization admin ended the fleet-wide hold: %d", r.status)
	}

	// The journal's quarantine.
	var q struct {
		Rows []struct {
			ID         int64  `json:"id"`
			Event      string `json:"event"`
			Error      string `json:"error"`
			FailedRuns int    `json:"failedRuns"`
		} `json:"rows"`
	}
	admin.expect(http.StatusOK, "GET", "/api/v1/notifications/quarantined", nil, &q)
	if len(q.Rows) != 0 {
		t.Fatalf("quarantine %+v", q.Rows)
	}
	// The journal is written by the database; two notices make two rows, set aside as the sender does after three failures.
	exec(t, h, `INSERT INTO notices (organization_id, kind, subject, title) VALUES ($1, 'test_notice', 'a', 'A'), ($1, 'test_notice', 'b', 'B')`, f.org)
	exec(t, h, `UPDATE notification_events SET status = 'quarantined', failed_runs = 3, error = 'boom' WHERE subject_type = 'notice'`)
	admin.expect(http.StatusOK, "GET", "/api/v1/notifications/quarantined", nil, &q)
	if len(q.Rows) != 2 || q.Rows[0].Error != "boom" || q.Rows[0].Event != "opened" || q.Rows[0].FailedRuns != 3 {
		t.Fatalf("quarantine %+v", q.Rows)
	}
	first, second := q.Rows[0].ID, q.Rows[1].ID
	row := func(id int64) string { return "/api/v1/notifications/quarantined/" + strconv.FormatInt(id, 10) }
	admin.expect(http.StatusNoContent, "POST", row(first)+"/retry", nil, nil)
	wantStatus(t, admin.do("POST", row(first)+"/retry", nil), http.StatusNotFound, "not_found") // no longer quarantined
	admin.expect(http.StatusNoContent, "POST", row(second)+"/discard", nil, nil)
	wantStatus(t, admin.do("POST", row(second)+"/discard", nil), http.StatusNotFound, "not_found")
	wantStatus(t, admin.do("POST", "/api/v1/notifications/quarantined/0/retry", nil), http.StatusNotFound, "not_found")
	wantStatus(t, admin.do("POST", "/api/v1/notifications/quarantined/abc/discard", nil), http.StatusNotFound, "not_found")
	if r := bea.do("POST", row(first)+"/retry", nil); r.status < 400 {
		t.Fatalf("an organization admin retried a journal row: %d", r.status)
	}
	if r := bea.do("GET", "/api/v1/notifications/quarantined", nil); r.status < 400 {
		t.Fatalf("an organization admin read the quarantine: %d", r.status)
	}
}
