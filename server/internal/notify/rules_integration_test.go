//go:build integration

package notify

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/server/internal/access"
	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/devscope"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
)

// Device alert rules (ADR-0053, slice 4), against real PostgreSQL.

func (f *fx) site(org uuid.UUID, name, tz string) uuid.UUID {
	f.t.Helper()
	return f.id(`INSERT INTO sites (organization_id, name, timezone) VALUES ($1, $2, $3) RETURNING id`, org, name, tz)
}

func (f *fx) group(org, site uuid.UUID, name string) uuid.UUID {
	f.t.Helper()
	return f.id(`INSERT INTO device_groups (organization_id, site_id, name) VALUES ($1, $2, $3) RETURNING id`, org, site, name)
}

func (f *fx) device(org, site uuid.UUID, name string) uuid.UUID {
	f.t.Helper()
	return f.id(`INSERT INTO devices (organization_id, site_id, name, hostname, platform, os_description, agent_public_key, enrolled_at, agent_last_seen_at)
		VALUES ($1, $2, $3, $3, 'linux', 'Ubuntu 24.04', decode(md5(random()::text) || md5(random()::text), 'hex'), now(), now()) RETURNING id`, org, site, name)
}

func (f *fx) offlinePolicy() uuid.UUID {
	f.t.Helper()
	return f.id(`INSERT INTO alert_policies (name, kind, minutes, severity) VALUES ('Offline test', 'offline', 15, 'critical') RETURNING id`)
}

func (f *fx) alert(dev uuid.UUID, policy *uuid.UUID, kind string) uuid.UUID {
	f.t.Helper()
	return f.id(`INSERT INTO alerts (policy_id, device_id, name, kind, minutes, severity, value, last_value, opened_at)
		VALUES ($1, $2, $3, $4, 15, 'critical', 20, 20, $5) RETURNING id`, policy, dev, "Device "+kind, kind, f.now())
}

func (f *fx) now() time.Time { return f.svc.now() }

func (f *fx) resolveAlert(id uuid.UUID, resolution string) {
	f.t.Helper()
	f.exec(`UPDATE alerts SET status = 'resolved', resolved_at = $2, resolution = $3 WHERE id = $1`, id, f.now(), resolution)
}

func (f *fx) ackAlert(id uuid.UUID) {
	f.t.Helper()
	f.exec(`UPDATE alerts SET status = 'acknowledged', acknowledged_at = $2, acknowledged_by_label = 'tech@example.com' WHERE id = $1`, id, f.now())
}

func (f *fx) plan() {
	f.t.Helper()
	if err := f.svc.Plan(f.ctx); err != nil {
		f.t.Fatal(err)
	}
}

// planAndSend plans, then sends what is due.
func (f *fx) planAndSend() {
	f.t.Helper()
	f.plan()
	f.sendAll()
}

// sendAll sends what is due until nothing is: one delivery goes at a time on a channel.
func (f *fx) sendAll() {
	f.t.Helper()
	for range 30 {
		f.svc.SendDue(f.ctx)
	}
}

func (f *fx) emailChannel(org *uuid.UUID, name string) (Channel, string) {
	f.t.Helper()
	to := f.mp.Address("alerts")
	ch, err := f.svc.Create(f.ctx, f.super(), ChannelInput{OrganizationID: org, Kind: KindEmail, Name: ptr(name), Recipients: []string{to}})
	if err != nil {
		f.t.Fatal(err)
	}
	return ch, to
}

// rule makes a rule over channels, with the changes the test wants.
func (f *fx) rule(owner *uuid.UUID, name string, chans []Channel, change func(r *Rule)) Rule {
	f.t.Helper()
	in := Rule{OrganizationID: owner, Name: name, Source: SourceAlerts, Enabled: true, OnResolve: true, GroupOutages: true}
	for _, c := range chans {
		in.ChannelIDs = append(in.ChannelIDs, c.ID)
	}
	if change != nil {
		change(&in)
	}
	caller := f.super()
	if owner != nil {
		caller = f.orgAdmin(*owner)
	}
	r, err := f.svc.CreateRule(f.ctx, caller, in)
	if err != nil {
		f.t.Fatal(err)
	}
	return r
}

func (f *fx) events(r *receiver) []string {
	var out []string
	for _, q := range r.got() {
		out = append(out, q.header.Get("X-EasyRMM-Event"))
	}
	return out
}

func (f *fx) deliveries(where string, args ...any) int {
	return f.n(`SELECT count(*) FROM notification_deliveries WHERE `+where, args...)
}

type alertsBody struct {
	Event  string      `json:"event"`
	Alerts []AlertItem `json:"alerts"`
	Site   *OutageItem `json:"site"`
}

func decode(t *testing.T, b []byte) alertsBody {
	t.Helper()
	var out alertsBody
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

// A device goes offline: the signed webhook and the email arrive; it comes
// back: the resolutions arrive (ADR-0053, slice 4 "Verified").
func TestADeviceGoesOfflineAndComesBack(t *testing.T) {
	f := newFx(t)
	r := newReceiver(t)
	hook := f.platformHook(r, "psa")
	mail, to := f.emailChannel(nil, "desk")
	f.rule(nil, "everything", []Channel{hook, mail}, nil)
	site := f.site(f.orgA, "Main office", "UTC")
	dev := f.device(f.orgA, site, "SRV01")
	policy := f.offlinePolicy()

	alert := f.alert(dev, &policy, "offline")
	f.planAndSend()
	reqs := r.got()
	if len(reqs) != 1 || reqs[0].header.Get("X-EasyRMM-Event") != EventAlertOpened {
		t.Fatalf("webhook: %v", f.events(r))
	}
	sec, err := f.svc.Reveal(f.ctx, f.super(), hook.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got := Sign(sec.Secret, time.Unix(mustUnix(t, reqs[0].header.Get("X-EasyRMM-Signature")), 0), reqs[0].body); got != reqs[0].header.Get("X-EasyRMM-Signature") {
		t.Fatal("the signature does not verify")
	}
	body := decode(t, reqs[0].body)
	if len(body.Alerts) != 1 || body.Alerts[0].ID != alert || body.Alerts[0].Device != "SRV01" || body.Alerts[0].Site != "Main office" || body.Alerts[0].Status != "open" {
		t.Fatalf("body: %s", reqs[0].body)
	}
	msgs := f.mp.Wait(to, 1)
	if !strings.Contains(msgs[0].Subject, "1 new") || !strings.Contains(msgs[0].Text, "Device offline on SRV01") {
		t.Fatalf("email: %q\n%s", msgs[0].Subject, msgs[0].Text)
	}

	f.resolveAlert(alert, "cleared")
	f.planAndSend()
	if got := f.events(r); len(got) != 2 || got[1] != EventAlertResolved {
		t.Fatalf("webhook: %v", got)
	}
	if res := decode(t, r.got()[1].body); res.Alerts[0].ID != alert || res.Alerts[0].Status != "resolved" || res.Alerts[0].Resolution != "cleared" {
		t.Fatalf("resolution: %s", r.got()[1].body)
	}
	msgs = f.mp.Wait(to, 2)
	if !strings.Contains(msgs[0].Subject, "1 resolved") {
		t.Fatalf("email: %q", msgs[0].Subject)
	}
}

func mustUnix(t *testing.T, sig string) int64 {
	t.Helper()
	var n int64
	for _, p := range strings.Split(sig, ",") {
		if v, ok := strings.CutPrefix(p, "t="); ok {
			for _, c := range v {
				n = n*10 + int64(c-'0')
			}
		}
	}
	return n
}

func TestTheJournalHasARowForEachPath(t *testing.T) {
	f := newFx(t)
	site := f.site(f.orgA, "Main", "UTC")
	dev := f.device(f.orgA, site, "SRV01")
	policy := f.offlinePolicy()
	rows := func() []string {
		var out []string
		_ = f.db.ReadTx(f.ctx, database.System, func(tx pgx.Tx) error {
			rs, err := tx.Query(f.ctx, `SELECT event FROM notification_events WHERE subject_type = 'alert' ORDER BY id`)
			if err != nil {
				return err
			}
			defer rs.Close()
			for rs.Next() {
				var e string
				_ = rs.Scan(&e)
				out = append(out, e)
			}
			return nil
		})
		return out
	}
	a := f.alert(dev, &policy, "offline")
	f.exec(`UPDATE alerts SET last_value = 99 WHERE id = $1`, a) // neither status nor acknowledgement
	// A person's acknowledge in one organization's scope writes its row.
	if err := f.db.InTx(f.ctx, database.Scope{Orgs: []uuid.UUID{f.orgA}}, func(tx pgx.Tx) error {
		_, err := tx.Exec(f.ctx, `UPDATE alerts SET status = 'acknowledged', acknowledged_at = now() WHERE id = $1`, a)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	f.resolveAlert(a, "manual")
	f.exec(`DELETE FROM alerts WHERE id = $1`, a) // a purge of a resolved alert writes nothing
	b := f.alert(dev, &policy, "offline")
	// A heartbeat's merge deletes a discovered device with the setting; the setting is gone after.
	other := f.device(f.orgA, site, "discovered")
	c := f.alert(other, &policy, "offline")
	if err := f.db.InTx(f.ctx, database.System, func(tx pgx.Tx) error {
		if _, err := tx.Exec(f.ctx, `SELECT set_config('easyrmm.alert_delete_reason', 'merged', true)`); err != nil {
			return err
		}
		if _, err := tx.Exec(f.ctx, `DELETE FROM devices WHERE id = $1`, other); err != nil {
			return err
		}
		if _, err := tx.Exec(f.ctx, `SELECT set_config('easyrmm.alert_delete_reason', '', true)`); err != nil {
			return err
		}
		_, err := tx.Exec(f.ctx, `DELETE FROM alerts WHERE id = $1`, b)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	want := []string{"opened", "acknowledged", "resolved", "opened", "opened", "deleted", "deleted"}
	if got := rows(); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("journal %v, want %v", got, want)
	}
	if why := f.str(`SELECT new_row->>'reason' FROM notification_events WHERE subject_id = $1 AND event = 'deleted'`, c); why != "merged" {
		t.Fatalf("a merge reads %q", why)
	}
	if why := f.str(`SELECT new_row->>'reason' FROM notification_events WHERE subject_id = $1 AND event = 'deleted'`, b); why != "device_removed" {
		t.Fatalf("a later deletion in the same transaction reads %q", why)
	}
	// The runtime role can neither forge a row nor rewrite what one recorded.
	if err := f.db.InTx(f.ctx, database.System, func(tx pgx.Tx) error {
		_, err := tx.Exec(f.ctx, `INSERT INTO notification_events (subject_type, subject_id, event) VALUES ('alert', gen_random_uuid(), 'opened')`)
		return err
	}); err == nil {
		t.Fatal("the app role inserted into the journal")
	}
	if err := f.db.InTx(f.ctx, database.System, func(tx pgx.Tx) error {
		_, err := tx.Exec(f.ctx, `UPDATE notification_events SET new_row = '{}'`)
		return err
	}); err == nil {
		t.Fatal("the app role rewrote a recorded column")
	}
}

func TestAWaitTheAlertOutlivesAndOneItDoesNot(t *testing.T) {
	f := newFx(t)
	r := newReceiver(t)
	hook := f.platformHook(r, "psa")
	f.rule(nil, "slow", []Channel{hook}, func(r *Rule) { r.WaitMinutes = 10 })
	site := f.site(f.orgA, "Main", "UTC")
	d1, d2, d3 := f.device(f.orgA, site, "A"), f.device(f.orgA, site, "B"), f.device(f.orgA, site, "C")
	resolved := f.alert(d1, nil, "cpu")
	acked := f.alert(d2, nil, "cpu")
	stays := f.alert(d3, nil, "cpu")
	f.planAndSend()
	if len(r.got()) != 0 {
		t.Fatalf("sent before the wait: %v", f.events(r))
	}
	f.advance(5 * time.Minute)
	f.resolveAlert(resolved, "cleared")
	f.ackAlert(acked)
	f.planAndSend()
	f.advance(6 * time.Minute)
	f.planAndSend()
	reqs := r.got()
	if len(reqs) != 1 {
		t.Fatalf("%v", f.events(r))
	}
	if b := decode(t, reqs[0].body); b.Alerts[0].ID != stays {
		t.Fatalf("an alert resolved or acknowledged before the wait sends nothing: %s", reqs[0].body)
	}
	// What was never told is never told as resolved.
	f.resolveAlert(stays, "cleared")
	f.planAndSend()
	if got := f.events(r); len(got) != 2 || got[1] != EventAlertResolved {
		t.Fatalf("%v", got)
	}
	if f.deliveries(`status = 'pending'`) != 0 {
		t.Fatal("something is left pending")
	}
}

func TestAcknowledgementAndRemindersAndWhatWasToldIsToldToTheEnd(t *testing.T) {
	f := newFx(t)
	r := newReceiver(t)
	hook := f.platformHook(r, "psa")
	rule := f.rule(nil, "all", []Channel{hook}, func(r *Rule) { r.OnAcknowledge = true; r.ReminderHours = 2 })
	site := f.site(f.orgA, "Main", "UTC")
	dev := f.device(f.orgA, site, "SRV01")
	a := f.alert(dev, nil, "memory")
	f.planAndSend()
	f.advance(3 * time.Hour)
	f.planAndSend()
	if got := f.events(r); len(got) != 2 || got[1] != EventAlertReminder {
		t.Fatalf("%v", got)
	}
	// An unsent reminder is dropped when a newer event about the alert is queued.
	f.advance(3 * time.Hour)
	f.plan() // queues a second reminder, not sent
	if f.deliveries(`event = 'alerts.reminder' AND status = 'pending'`) != 1 {
		t.Fatal("a reminder was not queued")
	}
	f.ackAlert(a)
	f.plan()
	if f.deliveries(`event = 'alerts.reminder' AND status = 'dropped'`) != 1 {
		t.Fatal("the unsent reminder was not dropped")
	}
	f.svc.SendDue(f.ctx)
	if got := f.events(r); got[len(got)-1] != EventAlertAcknowledged {
		t.Fatalf("%v", got)
	}
	// Acknowledging stops reminders.
	f.advance(10 * time.Hour)
	f.planAndSend()
	if len(r.got()) != 3 {
		t.Fatalf("%v", f.events(r))
	}
	// The rule is deleted; the channel is still told of the resolution.
	if err := f.svc.DeleteRule(f.ctx, f.super(), rule.ID); err != nil {
		t.Fatal(err)
	}
	f.resolveAlert(a, "cleared")
	f.planAndSend()
	if got := f.events(r); got[len(got)-1] != EventAlertResolved {
		t.Fatalf("%v", got)
	}
}

func TestAnOpenedNeverSentIsDroppedWithItsResolution(t *testing.T) {
	f := newFx(t)
	r := newReceiver(t)
	hook := f.platformHook(r, "psa")
	f.rule(nil, "all", []Channel{hook}, nil)
	site := f.site(f.orgA, "Main", "UTC")
	a := f.alert(f.device(f.orgA, site, "SRV01"), nil, "cpu")
	f.plan() // queued, not sent
	f.resolveAlert(a, "cleared")
	f.planAndSend()
	if len(r.got()) != 0 || f.deliveries(`status = 'dropped'`) != 1 || f.deliveries(`status = 'pending'`) != 0 {
		t.Fatalf("%v", f.events(r))
	}
}

func TestOneIncidentAcrossAPolicyChange(t *testing.T) {
	f := newFx(t)
	r := newReceiver(t)
	hook := f.platformHook(r, "psa")
	f.rule(nil, "all", []Channel{hook}, func(r *Rule) { r.OnAcknowledge = true })
	site := f.site(f.orgA, "Main", "UTC")
	dev := f.device(f.orgA, site, "SRV01")
	policy := f.offlinePolicy()

	first := f.alert(dev, &policy, "offline")
	f.ackAlert(first)
	f.planAndSend()
	f.resolveAlert(first, "policy_changed")
	f.plan()
	second := f.alert(dev, &policy, "offline")
	f.planAndSend()
	// Neither is sent; the incident goes on, with its acknowledgement and its ID.
	if got := f.events(r); len(got) != 1 {
		t.Fatalf("a successor sent something: %v", got)
	}
	if st := f.str(`SELECT status || ':' || alert_id FROM alert_incidents WHERE id = $1`, first); st != "acknowledged:"+second.String() {
		t.Fatalf("incident %s", st)
	}
	f.resolveAlert(second, "cleared")
	f.planAndSend()
	res := decode(t, r.got()[len(r.got())-1].body)
	if got := f.events(r); got[len(got)-1] != EventAlertResolved || res.Alerts[0].ID != first || res.Alerts[0].AlertID != second {
		t.Fatalf("the payload's id is the incident's: %v %s", got, r.got()[len(r.got())-1].body)
	}

	// A change that changes the kind starts a new incident.
	third := f.alert(dev, &policy, "offline")
	f.planAndSend()
	f.resolveAlert(third, "policy_changed")
	f.plan()
	fourth := f.alert(dev, nil, "cpu")
	f.planAndSend()
	if f.n(`SELECT count(*) FROM alert_incidents WHERE id = $1`, fourth) != 1 {
		t.Fatal("a different alert did not start a new incident")
	}
	// One whose successor never opens is resolved after the hold, with the resolution.
	f.advance(PolicyHold + time.Minute)
	f.planAndSend()
	var resolved int
	for _, q := range r.got() {
		if b := decode(t, q.body); q.header.Get("X-EasyRMM-Event") == EventAlertResolved && b.Alerts[0].ID == third {
			resolved++
		}
	}
	if resolved != 1 {
		t.Fatalf("the held resolution was sent %d times", resolved)
	}
}

func TestMaintenanceWindowsHoldOrganizationsRulesNotPlatformsThatIgnoreThem(t *testing.T) {
	f := newFx(t)
	r1, r2 := newReceiver(t), newReceiver(t)
	orgHook, err := f.svc.Create(f.ctx, f.super(), ChannelInput{Kind: KindWebhook, Name: ptr("shared"), URL: ptr(r1.url()), TrustedAuthority: ptr(r1.authority())})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.svc.Share(f.ctx, f.super(), orgHook.ID, f.orgA); err != nil {
		t.Fatal(err)
	}
	platHook := f.platformHook(r2, "msp")
	f.rule(&f.orgA, "org's", []Channel{orgHook}, nil)
	f.rule(nil, "msp ignores", []Channel{platHook}, func(r *Rule) { r.IgnoreWindows = true })
	site := f.site(f.orgA, "Main", "UTC")
	now := f.now()
	admin := f.orgAdmin(f.orgA)
	w, err := f.svc.CreateWindow(f.ctx, admin, site, Window{Name: "nightly", Kind: "weekly", Days: []int{int(now.Weekday()), int((now.Weekday() + 6) % 7)},
		Start: now.Add(-time.Hour).Format("15:04"), LengthMinutes: 180, Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	dev, dev2 := f.device(f.orgA, site, "SRV01"), f.device(f.orgA, site, "SRV02")
	told := f.alert(dev, nil, "cpu")
	_ = told
	f.planAndSend()
	if len(r1.got()) != 0 || len(r2.got()) != 1 {
		t.Fatalf("org: %v, platform: %v", f.events(r1), f.events(r2))
	}
	if f.n(`SELECT count(*) FROM notices WHERE kind = $1 AND resolved_at IS NULL`, NoticeMaintenance) != 1 {
		t.Fatal("the window's start is a notice")
	}
	f.alert(dev2, nil, "memory")
	f.planAndSend()
	if len(r1.got()) != 0 {
		t.Fatal("something went to the organization during the window")
	}
	// It ends: what is open is sent, and the end is a notice.
	f.advance(4 * time.Hour)
	f.planAndSend()
	if len(r1.got()) != 2 {
		t.Fatalf("after the window: %v", f.events(r1))
	}
	if f.n(`SELECT count(*) FROM notices WHERE kind = $1 AND resolved_at IS NULL`, NoticeMaintenance) != 0 {
		t.Fatal("the window's end resolves its notice")
	}
	if f.n(`SELECT count(*) FROM audit_log WHERE action = $1`, ActionWindowCreate) != 1 {
		t.Fatal("a window's creation is audited")
	}
	if err := f.svc.DeleteWindow(f.ctx, admin, w.ID); err != nil {
		t.Fatal(err)
	}
}

func TestWindowRules(t *testing.T) {
	f := newFx(t)
	site := f.site(f.orgA, "Main", "UTC")
	admin := f.orgAdmin(f.orgA)
	for name, w := range map[string]Window{
		"weekly over a day":  {Name: "x", Kind: "weekly", Days: []int{1}, Start: "22:00", LengthMinutes: 25 * 60},
		"weekly no days":     {Name: "x", Kind: "weekly", Start: "22:00", LengthMinutes: 60},
		"weekly bad start":   {Name: "x", Kind: "weekly", Days: []int{1}, Start: "late", LengthMinutes: 60},
		"once over a week":   {Name: "x", Kind: "once", StartsAt: f.now().Add(time.Hour).Format(local), LengthMinutes: 7*24*60 + 1},
		"once too far ahead": {Name: "x", Kind: "once", StartsAt: f.now().Add(91 * 24 * time.Hour).Format(local), LengthMinutes: 60},
		"once already ended": {Name: "x", Kind: "once", StartsAt: f.now().Add(-3 * time.Hour).Format(local), LengthMinutes: 60},
		"a day out of range": {Name: "x", Kind: "weekly", Days: []int{7}, Start: "01:00", LengthMinutes: 60},
		"no name":            {Kind: "weekly", Days: []int{1}, Start: "01:00", LengthMinutes: 60},
		"an unknown kind":    {Name: "x", Kind: "daily", LengthMinutes: 60},
	} {
		if _, err := f.svc.CreateWindow(f.ctx, admin, site, w); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	ok, err := f.svc.CreateWindow(f.ctx, admin, site, Window{Name: "maint", Kind: "once", StartsAt: f.now().Add(48 * time.Hour).Format(local), LengthMinutes: 7 * 24 * 60, Enabled: true})
	if err != nil || ok.Kind != "once" {
		t.Fatalf("%+v %v", ok, err)
	}
	// A site administrator of another organization sees nothing; a viewer cannot change it.
	stranger := f.orgAdmin(f.orgB)
	if _, err := f.svc.CreateWindow(f.ctx, stranger, site, Window{Name: "x", Kind: "weekly", Days: []int{1}, Start: "01:00", LengthMinutes: 60}); err == nil {
		t.Fatal("another organization created a window")
	}
	viewer := f.caller(rbac.RoleReadOnly, f.orgA)
	if _, err := f.svc.UpdateWindow(f.ctx, viewer, ok.ID, Window{Name: "x", Kind: "weekly", Days: []int{1}, Start: "01:00", LengthMinutes: 60}); err == nil {
		t.Fatal("a viewer changed a window")
	}
	list, err := f.svc.Windows(f.ctx, viewer, WindowQuery{OrganizationID: &f.orgA})
	if err != nil || len(list) != 1 || list[0].CanEdit {
		t.Fatalf("%+v %v", list, err)
	}
	if list, _ := f.svc.Windows(f.ctx, stranger, WindowQuery{OrganizationID: &f.orgA}); len(list) != 0 {
		t.Fatal("another organization read a window")
	}
	up, err := f.svc.UpdateWindow(f.ctx, admin, ok.ID, Window{Name: "weekly now", Kind: "weekly", Days: []int{1, 3, 1}, Start: "02:30", LengthMinutes: 90, Enabled: true})
	if err != nil || up.Kind != "weekly" || len(up.Days) != 2 || up.Start != "02:30" {
		t.Fatalf("%+v %v", up, err)
	}
}

func TestASiteGoesOfflineAndComesBack(t *testing.T) {
	f := newFx(t)
	r := newReceiver(t)
	hook := f.platformHook(r, "psa")
	mail, to := f.emailChannel(nil, "desk")
	f.rule(nil, "all", []Channel{hook, mail}, nil)
	site := f.site(f.orgA, "Branch", "UTC")
	policy := f.offlinePolicy()
	devs := []uuid.UUID{f.device(f.orgA, site, "A"), f.device(f.orgA, site, "B"), f.device(f.orgA, site, "C")}
	// One never enrolled and one with no agent do not count.
	f.exec(`INSERT INTO devices (organization_id, site_id, name, platform) VALUES ($1, $2, 'mesh only', 'linux')`, f.orgA, site)
	var alerts []uuid.UUID
	for _, d := range devs {
		alerts = append(alerts, f.alert(d, &policy, "offline"))
	}
	f.planAndSend()
	if got := f.events(r); len(got) != 1 || got[0] != EventSiteOffline {
		t.Fatalf("the outage folds the alerts: %v", got)
	}
	b := decode(t, r.got()[0].body)
	if b.Site == nil || b.Site.Devices != 3 || len(b.Site.AlertIDs) != 3 {
		t.Fatalf("%s", r.got()[0].body)
	}
	msgs := f.mp.Wait(to, 1)
	if !strings.Contains(msgs[0].Text, "all 3 devices offline") || strings.Contains(msgs[0].Text, "New alerts") {
		t.Fatalf("%s", msgs[0].Text)
	}
	// A folded alert resolving is not told on its own; one device back ends the outage.
	f.resolveAlert(alerts[0], "cleared")
	f.planAndSend()
	got := f.events(r)
	if len(got) != 4 || got[1] != EventSiteOnline {
		t.Fatalf("%v", got)
	}
	// The folded alerts still open are then sent as their own opened alerts.
	opened := 0
	for _, e := range got[2:] {
		if e == EventAlertOpened {
			opened++
		}
	}
	if opened != 2 {
		t.Fatalf("%v", got)
	}
	back := decode(t, r.got()[1].body)
	if back.Site.Back != 1 || back.Site.Devices != 3 {
		t.Fatalf("%+v", back.Site)
	}
}

func TestAnOutageNeedsTwoDevicesAndEveryOneOffline(t *testing.T) {
	f := newFx(t)
	r := newReceiver(t)
	f.rule(nil, "all", []Channel{f.platformHook(r, "psa")}, nil)
	site := f.site(f.orgA, "Branch", "UTC")
	policy := f.offlinePolicy()
	a, b := f.device(f.orgA, site, "A"), f.device(f.orgA, site, "B")
	f.alert(a, &policy, "offline")
	f.planAndSend()
	if got := f.events(r); len(got) != 1 || got[0] != EventAlertOpened {
		t.Fatalf("one of two offline is not an outage: %v", got)
	}
	// Uninstalled devices are left out.
	f.exec(`UPDATE devices SET agent_uninstalled_at = now() WHERE id = $1`, b)
	f.planAndSend()
	if f.n(`SELECT count(*) FROM site_outages`) != 0 {
		t.Fatal("a site with one device watched is down")
	}
}

func TestTheFleetWideHold(t *testing.T) {
	f := newFx(t)
	orgHook := f.platformHook(newReceiver(t), "shared")
	if err := f.svc.Share(f.ctx, f.super(), orgHook.ID, f.orgA); err != nil {
		t.Fatal(err)
	}
	r2 := newReceiver(t)
	platHook := f.platformHook(r2, "msp")
	f.rule(&f.orgA, "org", []Channel{orgHook}, func(r *Rule) { r.GroupOutages = false })
	f.rule(nil, "msp", []Channel{platHook}, func(r *Rule) { r.GroupOutages = false })
	site := f.site(f.orgA, "Main", "UTC")
	policy := f.offlinePolicy()
	var devs []uuid.UUID
	for i := range 24 {
		devs = append(devs, f.device(f.orgA, site, "D"+string(rune('a'+i))))
	}
	// Four had been silent already and are not counted; 20 were checking in and went silent at once.
	f.exec(`UPDATE devices SET agent_last_seen_at = now() - interval '2 hours' WHERE id = ANY ($1)`, devs[:4])
	f.exec(`UPDATE devices SET agent_last_seen_at = $2 WHERE id = ANY ($1)`, devs[4:], f.now().Add(-4*time.Minute))
	// The server just began serving: before its floor nothing starts.
	f.svc.SetSeenFloor(func(now time.Time) time.Time { return now.Add(time.Minute) })
	f.plan()
	if f.n(`SELECT count(*) FROM fleet_silences`) != 0 {
		t.Fatal("a restart started the hold")
	}
	f.svc.SetSeenFloor(func(time.Time) time.Time { return f.now().Add(-time.Hour) })
	f.plan()
	if f.n(`SELECT count(*) FROM fleet_silences WHERE ended_at IS NULL AND counted_n = 20`) != 1 {
		t.Fatal("twenty devices going silent at once did not start the hold")
	}
	if f.n(`SELECT count(*) FROM notices WHERE kind = $1 AND resolved_at IS NULL`, NoticeFleetSilent) != 1 {
		t.Fatal("no notice")
	}
	for _, d := range devs[4:] {
		f.alert(d, &policy, "offline")
	}
	f.planAndSend()
	if len(r2.got()) != 20 {
		t.Fatalf("platform rules send the offline openings: %d", len(r2.got()))
	}
	if f.deliveries(`charged_org = $1`, f.orgA) != 0 {
		t.Fatal("an organization's rule sent an offline opening during the hold")
	}
	// A restart during the silence neither ends it nor starts one: before the floor, nothing changes.
	f.exec(`UPDATE devices SET agent_last_seen_at = $2 WHERE id = ANY ($1)`, devs[4:], f.now().Add(time.Second))
	f.svc.SetSeenFloor(func(now time.Time) time.Time { return now.Add(time.Minute) })
	f.plan()
	if f.n(`SELECT count(*) FROM fleet_silences WHERE ended_at IS NULL`) != 1 {
		t.Fatal("a restart ended the hold")
	}
	// A super administrator ends it; the openings that waited and whose alerts are still open go out.
	f.svc.SetSeenFloor(func(time.Time) time.Time { return f.now().Add(-time.Hour) })
	f.resolveAlert(f.id(`SELECT id FROM alerts WHERE device_id = $1`, devs[4]), "cleared")
	f.exec(`UPDATE devices SET agent_last_seen_at = $2 WHERE id = ANY ($1)`, devs[4:8], f.now().Add(-10*time.Minute))
	if err := f.svc.EndSilence(f.ctx, f.orgAdmin(f.orgA)); err == nil {
		t.Fatal("an organization administrator ended the hold")
	}
	if s, err := f.svc.CurrentSilence(f.ctx, f.super()); err != nil || s == nil || s.Counted != 20 {
		t.Fatalf("%+v %v", s, err)
	}
	if err := f.svc.EndSilence(f.ctx, f.super()); err != nil {
		t.Fatal(err)
	}
	f.planAndSend()
	if n := f.deliveries(`charged_org = $1 AND event = 'alerts.opened'`, f.orgA); n != 19 {
		t.Fatalf("after the hold, %d openings, want the 19 alerts still open", n)
	}
	if err := f.svc.EndSilence(f.ctx, f.super()); err == nil {
		t.Fatal("ended twice")
	}
}

// Devices that check in every 5 minutes are silent after 15, not after 3: a fleet of them four minutes
// after their last heartbeat is not a fleet gone silent (ADR-0058).
func TestTheFleetWideHoldFollowsEachDevicesInterval(t *testing.T) {
	f := newFx(t)
	site := f.site(f.orgA, "Main", "UTC")
	var devs []uuid.UUID
	for i := range 24 {
		devs = append(devs, f.device(f.orgA, site, "D"+string(rune('a'+i))))
	}
	f.svc.SetSeenFloor(func(time.Time) time.Time { return f.now().Add(-time.Hour) })
	f.exec(`UPDATE devices SET agent_heartbeat_seconds = 300, agent_last_seen_at = $2::timestamptz, agent_online_until = $2::timestamptz + interval '15 minutes' WHERE id = ANY ($1)`, devs, f.now().Add(-4*time.Minute))
	f.plan()
	if f.n(`SELECT count(*) FROM fleet_silences`) != 0 {
		t.Fatal("devices four minutes into a five-minute interval started the hold")
	}
	f.exec(`UPDATE devices SET agent_last_seen_at = $2::timestamptz, agent_online_until = $2::timestamptz + interval '15 minutes' WHERE id = ANY ($1)`, devs, f.now().Add(-21*time.Minute))
	f.plan()
	if f.n(`SELECT count(*) FROM fleet_silences`) != 0 {
		t.Fatal("devices silent for longer than the window were counted as having been checking in")
	}
	f.exec(`UPDATE devices SET agent_last_seen_at = $2::timestamptz, agent_online_until = $2::timestamptz + interval '15 minutes' WHERE id = ANY ($1)`, devs, f.now().Add(-16*time.Minute))
	f.plan()
	if f.n(`SELECT count(*) FROM fleet_silences WHERE ended_at IS NULL AND counted_n = 24`) != 1 {
		t.Fatal("devices past three of their intervals did not start the hold")
	}
}

func TestTheHoldEndsWhenMoreThanHalfAreBack(t *testing.T) {
	f := newFx(t)
	site := f.site(f.orgA, "Main", "UTC")
	var devs []uuid.UUID
	for i := range 22 {
		devs = append(devs, f.device(f.orgA, site, "D"+string(rune('a'+i))))
	}
	f.exec(`UPDATE devices SET agent_last_seen_at = $1`, f.now().Add(-4*time.Minute))
	f.plan()
	if f.n(`SELECT count(*) FROM fleet_silences WHERE ended_at IS NULL`) != 1 {
		t.Fatal("not started")
	}
	f.advance(time.Minute)
	f.exec(`UPDATE devices SET agent_last_seen_at = $2 WHERE id = ANY ($1)`, devs[:11], f.now())
	f.plan()
	if f.n(`SELECT count(*) FROM fleet_silences WHERE ended_at IS NULL`) != 1 {
		t.Fatal("half is not more than half")
	}
	f.exec(`UPDATE devices SET agent_last_seen_at = $2 WHERE id = $1`, devs[11], f.now())
	f.plan()
	if f.n(`SELECT count(*) FROM fleet_silences WHERE ended_at IS NOT NULL AND back_n = 12`) != 1 {
		t.Fatal("more than half back did not end the hold")
	}
}

func TestRestartsNeverSendTwice(t *testing.T) {
	f := newFx(t)
	r := newReceiver(t)
	f.rule(nil, "all", []Channel{f.platformHook(r, "psa")}, nil)
	site := f.site(f.orgA, "Main", "UTC")
	a := f.alert(f.device(f.orgA, site, "SRV01"), nil, "cpu")
	f.planAndSend()
	// A server that starts afresh, and a second one planning at the same time.
	again := New(f.db, audit.New(f.db, nil), f.svc.sealer, f.svc.env, f.mail, f.svc.log)
	again.now = f.svc.now
	var wg sync.WaitGroup
	for _, s := range []*Service{again, f.svc, again} {
		wg.Add(1)
		go func() { defer wg.Done(); _ = s.Plan(f.ctx) }()
	}
	wg.Wait()
	again.SendDue(f.ctx)
	if len(r.got()) != 1 || f.deliveries(`event = 'alerts.opened'`) != 1 {
		t.Fatalf("%v", f.events(r))
	}
	// Two servers planning at once queue each delivery once.
	var alerts []uuid.UUID
	for i := range 8 {
		alerts = append(alerts, f.alert(f.device(f.orgA, site, "N"+string(rune('a'+i))), nil, "memory"))
	}
	for range 3 {
		var wg sync.WaitGroup
		for _, s := range []*Service{again, f.svc} {
			wg.Add(1)
			go func() { defer wg.Done(); _ = s.Plan(f.ctx) }()
		}
		wg.Wait()
	}
	if n := f.deliveries(`event = 'alerts.opened'`); n != 9 {
		t.Fatalf("%d opened deliveries", n)
	}
	f.resolveAlert(a, "cleared")
	_ = alerts
	f.plan()
	f.plan()
	if f.deliveries(`event = 'alerts.resolved'`) != 1 {
		t.Fatal("a resolution was queued twice")
	}
}

func TestTheDevScopeKeepsOtherOrganizationsQuiet(t *testing.T) {
	f := newFx(t)
	r := newReceiver(t)
	f.rule(nil, "all", []Channel{f.platformHook(r, "psa")}, nil)
	siteA, siteB := f.site(f.orgA, "A", "UTC"), f.site(f.orgB, "B", "UTC")
	restore := devscope.Set(f.orgB)
	defer restore()
	f.alert(f.device(f.orgA, siteA, "SRV01"), nil, "cpu")
	inScope := f.alert(f.device(f.orgB, siteB, "SRV02"), nil, "cpu")
	f.planAndSend()
	reqs := r.got()
	if len(reqs) != 1 || decode(t, reqs[0].body).Alerts[0].ID != inScope {
		t.Fatalf("%v", f.events(r))
	}
	if f.n(`SELECT count(*) FROM alert_incidents`) != 1 {
		t.Fatal("an organization outside the scope has an incident")
	}
}

func TestRulesAndTheirConstraints(t *testing.T) {
	f := newFx(t)
	siteA, siteB := f.site(f.orgA, "A", "UTC"), f.site(f.orgB, "B", "UTC")
	groupA := f.group(f.orgA, siteA, "Servers")
	own, err := f.svc.Create(f.ctx, f.orgAdmin(f.orgA), ChannelInput{OrganizationID: &f.orgA, Kind: KindEmail, Name: ptr("own"), Recipients: []string{"a@example.com"}})
	if err != nil {
		t.Fatal(err)
	}
	hook := f.platformHook(newReceiver(t), "shared later")
	admin := f.orgAdmin(f.orgA)
	// An organization's rule refused a platform channel not shared with it.
	if _, err := f.svc.CreateRule(f.ctx, admin, Rule{OrganizationID: &f.orgA, Name: "r", ChannelIDs: []uuid.UUID{hook.ID}}); err == nil {
		t.Fatal("a platform channel not shared was accepted")
	}
	// The same, with the service's checks bypassed.
	if err := f.db.InTx(f.ctx, database.System, func(tx pgx.Tx) error {
		id := uuid.New()
		if _, err := tx.Exec(f.ctx, `INSERT INTO notification_rules (id, organization_id, owner, name) VALUES ($1, $2, $2, 'raw')`, id, f.orgA); err != nil {
			return err
		}
		_, err := tx.Exec(f.ctx, `INSERT INTO notification_rule_channels (rule_id, owner, channel_id, channel_owner) VALUES ($1, $2, $3, $4)`, id, f.orgA, hook.ID, uuid.Nil)
		return err
	}); err == nil {
		t.Fatal("the database accepted an unshared platform channel")
	}
	// Another organization's site in an organization's rule: refused, in the service and in the database.
	if _, err := f.svc.CreateRule(f.ctx, admin, Rule{OrganizationID: &f.orgA, Name: "r", ChannelIDs: []uuid.UUID{own.ID}, Sites: ListFilter{Mode: ModeList, IDs: []uuid.UUID{siteB}}}); err == nil {
		t.Fatal("another organization's site was accepted")
	}
	if err := f.db.InTx(f.ctx, database.System, func(tx pgx.Tx) error {
		id := uuid.New()
		if _, err := tx.Exec(f.ctx, `INSERT INTO notification_rules (id, organization_id, owner, name) VALUES ($1, $2, $2, 'raw2')`, id, f.orgA); err != nil {
			return err
		}
		_, err := tx.Exec(f.ctx, `INSERT INTO notification_rule_sites (rule_id, owner, organization_id, site_id) VALUES ($1, $2, $3, $4)`, id, f.orgA, f.orgB, siteB)
		return err
	}); err == nil {
		t.Fatal("the database accepted another organization's site")
	}
	for name, in := range map[string]Rule{
		"no channel":        {OrganizationID: &f.orgA, Name: "x"},
		"organizations":     {OrganizationID: &f.orgA, Name: "x", ChannelIDs: []uuid.UUID{own.ID}, Organizations: ListFilter{Mode: ModeList, IDs: []uuid.UUID{f.orgA}}},
		"ignore windows":    {OrganizationID: &f.orgA, Name: "x", ChannelIDs: []uuid.UUID{own.ID}, IgnoreWindows: true},
		"wait too long":     {OrganizationID: &f.orgA, Name: "x", ChannelIDs: []uuid.UUID{own.ID}, WaitMinutes: 1441},
		"reminder":          {OrganizationID: &f.orgA, Name: "x", ChannelIDs: []uuid.UUID{own.ID}, ReminderHours: 721},
		"unknown severity":  {OrganizationID: &f.orgA, Name: "x", ChannelIDs: []uuid.UUID{own.ID}, Severities: ValueFilter{Mode: ModeList, Values: []string{"fatal"}}},
		"a bad condition":   {OrganizationID: &f.orgA, Name: "x", ChannelIDs: []uuid.UUID{own.ID}, Conditions: ValueFilter{Mode: ModeList, Values: []string{"Drop Table"}}},
		"a missing group":   {OrganizationID: &f.orgA, Name: "x", ChannelIDs: []uuid.UUID{own.ID}, Groups: ListFilter{Mode: ModeList, IDs: []uuid.UUID{uuid.New()}}},
		"a missing channel": {OrganizationID: &f.orgA, Name: "x", ChannelIDs: []uuid.UUID{uuid.New()}},
		"a source":          {OrganizationID: &f.orgA, Name: "x", Source: "pigeons", ChannelIDs: []uuid.UUID{own.ID}},
		"no name":           {OrganizationID: &f.orgA, ChannelIDs: []uuid.UUID{own.ID}},
	} {
		if _, err := f.svc.CreateRule(f.ctx, admin, in); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	// Another organization's administrator cannot make or read it.
	if _, err := f.svc.CreateRule(f.ctx, f.orgAdmin(f.orgB), Rule{OrganizationID: &f.orgA, Name: "x", ChannelIDs: []uuid.UUID{own.ID}}); err == nil {
		t.Fatal("another organization's administrator made a rule")
	}

	rule, err := f.svc.CreateRule(f.ctx, admin, Rule{OrganizationID: &f.orgA, Name: "Servers", Enabled: true, OnResolve: true, ChannelIDs: []uuid.UUID{own.ID},
		Sites: ListFilter{Mode: ModeList, IDs: []uuid.UUID{siteA}}, Groups: ListFilter{Mode: ModeList, IDs: []uuid.UUID{groupA}},
		DeviceKinds: ValueFilter{Mode: ModeList, Values: []string{"server"}}, Conditions: ValueFilter{Mode: ModeList, Values: []string{"offline", "disk_health"}},
		Checks: ValueFilter{Mode: ModeList, Values: []string{"wear"}}})
	if err != nil || rule.MatchesNothing || len(rule.Sites.IDs) != 1 || rule.DeviceKinds.Mode != ModeList {
		t.Fatalf("%+v %v", rule, err)
	}
	if _, err := f.svc.CreateRule(f.ctx, admin, Rule{OrganizationID: &f.orgA, Name: "servers", ChannelIDs: []uuid.UUID{own.ID}}); err == nil {
		t.Fatal("a name is used twice")
	}
	if list, err := f.svc.Rules(f.ctx, admin, &f.orgA); err != nil || len(list) != 1 {
		t.Fatalf("%v %v", list, err)
	}
	if _, err := f.svc.Rule(f.ctx, f.orgAdmin(f.orgB), rule.ID); err == nil {
		t.Fatal("read another organization's rule")
	}
	// Deleting the last listed group makes the rule match nothing, and the planner raises a notice.
	f.exec(`DELETE FROM device_groups WHERE id = $1`, groupA)
	got, err := f.svc.Rule(f.ctx, admin, rule.ID)
	if err != nil || !got.MatchesNothing || got.Groups.Mode != ModeList || len(got.Groups.IDs) != 0 {
		t.Fatalf("%+v %v", got, err)
	}
	f.plan()
	if f.n(`SELECT count(*) FROM notices WHERE kind = $1 AND resolved_at IS NULL AND organization_id = $2`, NoticeRuleEmpty, f.orgA) != 1 {
		t.Fatal("no notice for a rule that matches nothing")
	}
	// Sharing, linking and unsharing: the link goes.
	if err := f.svc.Share(f.ctx, f.super(), hook.ID, f.orgA); err != nil {
		t.Fatal(err)
	}
	up := got
	up.ChannelIDs = []uuid.UUID{own.ID, hook.ID}
	up.Groups = ListFilter{Mode: ModeAny}
	if got, err = f.svc.UpdateRule(f.ctx, admin, rule.ID, up); err != nil || len(got.ChannelIDs) != 2 || got.MatchesNothing {
		t.Fatalf("%+v %v", got, err)
	}
	if err := f.svc.Unshare(f.ctx, f.super(), hook.ID, f.orgA); err != nil {
		t.Fatal(err)
	}
	if got, _ = f.svc.Rule(f.ctx, admin, rule.ID); len(got.ChannelIDs) != 1 {
		t.Fatalf("the link to an unshared channel stayed: %v", got.ChannelIDs)
	}
	f.plan()
	if f.n(`SELECT count(*) FROM notices WHERE kind = $1 AND resolved_at IS NULL`, NoticeRuleEmpty) != 0 {
		t.Fatal("the notice stays after the rule matches again")
	}
	// At most 20 channels in the database, whatever the service says.
	if err := f.svc.DeleteRule(f.ctx, admin, rule.ID); err != nil {
		t.Fatal(err)
	}
	if f.n(`SELECT count(*) FROM audit_log WHERE action IN ($1, $2, $3)`, ActionRuleCreate, ActionRuleUpdate, ActionRuleDelete) != 3 {
		t.Fatal("rule changes are audited")
	}
}

func TestRuleQuota(t *testing.T) {
	f := newFx(t)
	ch, err := f.svc.Create(f.ctx, f.orgAdmin(f.orgA), ChannelInput{OrganizationID: &f.orgA, Kind: KindEmail, Name: ptr("own"), Recipients: []string{"a@example.com"}})
	if err != nil {
		t.Fatal(err)
	}
	f.exec(`INSERT INTO notification_quotas (organization_id, rules) VALUES ($1, 1)`, f.orgA)
	admin := f.orgAdmin(f.orgA)
	if _, err := f.svc.CreateRule(f.ctx, admin, Rule{OrganizationID: &f.orgA, Name: "one", ChannelIDs: []uuid.UUID{ch.ID}}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.CreateRule(f.ctx, admin, Rule{OrganizationID: &f.orgA, Name: "two", ChannelIDs: []uuid.UUID{ch.ID}}); !errors.Is(err, ErrRuleQuota) {
		t.Fatalf("%v", err)
	}
}

func TestANoticeRuleSendsNotices(t *testing.T) {
	f := newFx(t)
	r := newReceiver(t)
	hook := f.platformHook(r, "ops")
	f.rule(nil, "notices", []Channel{hook}, func(r *Rule) {
		r.Source = SourceNotices
		r.Conditions = ValueFilter{Mode: ModeList, Values: []string{"channel_failing"}}
	})
	f.exec(`INSERT INTO notices (organization_id, kind, subject, title, detail) VALUES (NULL, 'channel_failing', 'x', 'Channel "psa" is failing', 'details')`)
	f.exec(`INSERT INTO notices (organization_id, kind, subject, title, detail) VALUES (NULL, 'quota_reached', 'x', 'Other', 'details')`)
	f.advance(time.Minute) // notices are stamped by the database's clock
	f.planAndSend()
	if got := f.events(r); len(got) != 1 || got[0] != EventNoticeOpened {
		t.Fatalf("%v", got)
	}
	f.exec(`UPDATE notices SET resolved_at = now() WHERE kind = 'channel_failing'`)
	f.planAndSend()
	if got := f.events(r); len(got) != 2 || got[1] != EventNoticeResolved {
		t.Fatalf("%v", got)
	}
}

// A row that cannot be planned is retried, then set aside, holding the later
// rows about its subject while the others go out; Retry and Discard do what
// they say.
func TestABadRowIsQuarantinedAndHoldsItsSubject(t *testing.T) {
	f := newFx(t)
	r := newReceiver(t)
	f.rule(nil, "all", []Channel{f.platformHook(r, "psa")}, nil)
	site := f.site(f.orgA, "Main", "UTC")
	bad := f.alert(f.device(f.orgA, site, "SRV01"), nil, "cpu")
	f.corruptJournal(bad)
	good := f.alert(f.device(f.orgA, site, "SRV02"), nil, "cpu")
	f.ackAlert(bad) // a later row about the same subject

	for range 4 {
		_ = f.svc.Plan(f.ctx)
	}
	if f.n(`SELECT count(*) FROM notification_events WHERE status = 'quarantined' AND subject_id = $1`, bad) != 1 {
		t.Fatal("the bad row was not quarantined")
	}
	if f.n(`SELECT count(*) FROM notices WHERE kind = $1 AND resolved_at IS NULL`, NoticeQuarantined) != 1 {
		t.Fatal("super administrators were not told")
	}
	f.svc.SendDue(f.ctx)
	reqs := r.got()
	if len(reqs) != 1 || decode(t, reqs[0].body).Alerts[0].ID != good {
		t.Fatalf("the others go out: %v", f.events(r))
	}
	if f.n(`SELECT count(*) FROM notification_events WHERE status = 'new' AND subject_id = $1`, bad) != 1 {
		t.Fatal("the later row about the bad row's subject was planned out of order")
	}
	q, err := f.svc.QuarantinedRows(f.ctx, f.super())
	if err != nil || len(q) != 1 || q[0].Held != 1 || q[0].FailedRuns < PlanQuarantine {
		t.Fatalf("%+v %v", q, err)
	}
	if _, err := f.svc.QuarantinedRows(f.ctx, f.orgAdmin(f.orgA)); err == nil {
		t.Fatal("an organization administrator read the quarantine")
	}
	// Discard plans the subject's current state as one row: the alert is open and acknowledged, so nothing is sent.
	if err := f.svc.DiscardJournal(f.ctx, f.super(), q[0].ID); err != nil {
		t.Fatal(err)
	}
	f.planAndSend()
	if f.n(`SELECT count(*) FROM notification_events WHERE status <> 'planned'`) != 0 {
		t.Fatal("rows are left")
	}
	if f.n(`SELECT count(*) FROM alert_incidents WHERE id = $1 AND status = 'acknowledged'`, bad) != 1 {
		t.Fatal("the current state was not planned")
	}
	if got := f.events(r); len(got) != 2 {
		t.Fatalf("discard tells channels the current state: %v", got)
	}
	f.resolveAlert(bad, "cleared")
	f.planAndSend()
	if got := f.events(r); len(got) != 3 || got[2] != EventAlertResolved {
		t.Fatalf("%v", got)
	}
}

func (f *fx) corruptJournal(alert uuid.UUID) {
	f.t.Helper()
	c, err := pgx.Connect(f.ctx, f.dsn)
	if err != nil {
		f.t.Fatal(err)
	}
	defer c.Close(context.Background())
	if _, err := c.Exec(f.ctx, `UPDATE notification_events SET new_row = '"junk"' WHERE subject_id = $1 AND event = 'opened'`, alert); err != nil {
		f.t.Fatal(err)
	}
}

func TestRetryReplaysAQuarantinedRow(t *testing.T) {
	f := newFx(t)
	r := newReceiver(t)
	f.rule(nil, "all", []Channel{f.platformHook(r, "psa")}, nil)
	site := f.site(f.orgA, "Main", "UTC")
	bad := f.alert(f.device(f.orgA, site, "SRV01"), nil, "cpu")
	f.corruptJournal(bad)
	for range 4 {
		_ = f.svc.Plan(f.ctx)
	}
	q, _ := f.svc.QuarantinedRows(f.ctx, f.super())
	if len(q) != 1 {
		t.Fatalf("%+v", q)
	}
	// Repaired, then retried.
	c, err := pgx.Connect(f.ctx, f.dsn)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Exec(f.ctx, `UPDATE notification_events SET new_row = (SELECT to_jsonb(a) FROM alerts a WHERE id = $1) WHERE id = $2`, bad, q[0].ID); err != nil {
		t.Fatal(err)
	}
	c.Close(f.ctx)
	if err := f.svc.RetryJournal(f.ctx, f.super(), q[0].ID); err != nil {
		t.Fatal(err)
	}
	if err := f.svc.RetryJournal(f.ctx, f.super(), q[0].ID); err == nil {
		t.Fatal("retried a row that is not quarantined")
	}
	f.planAndSend()
	if got := f.events(r); len(got) != 1 {
		t.Fatalf("%v", got)
	}
}

func TestPlanningStoppedNotice(t *testing.T) {
	f := newFx(t)
	site := f.site(f.orgA, "Main", "UTC")
	bad := f.alert(f.device(f.orgA, site, "SRV01"), nil, "cpu")
	f.corruptJournal(bad)
	_ = f.svc.Plan(f.ctx)
	f.advance(PlanStoppedAfter + time.Minute)
	_ = f.svc.Plan(f.ctx)
	if f.n(`SELECT count(*) FROM notices WHERE kind = $1 AND resolved_at IS NULL`, NoticePlanningStopped) != 1 {
		t.Fatal("no *planning has stopped* notice after 10 minutes")
	}
	f.exec(`DELETE FROM alerts WHERE id = $1`, bad)
	c, _ := pgx.Connect(f.ctx, f.dsn)
	_, _ = c.Exec(f.ctx, `UPDATE notification_events SET status = 'planned' WHERE status <> 'planned'`)
	c.Close(f.ctx)
	f.plan()
	if f.n(`SELECT count(*) FROM notices WHERE kind = $1 AND resolved_at IS NULL`, NoticePlanningStopped) != 0 {
		t.Fatal("the notice stays after a row is planned")
	}
}

func TestADeletedDeviceSendsOneResolution(t *testing.T) {
	f := newFx(t)
	r := newReceiver(t)
	f.rule(nil, "all", []Channel{f.platformHook(r, "psa")}, nil)
	site := f.site(f.orgA, "Main", "UTC")
	dev := f.device(f.orgA, site, "SRV01")
	a := f.alert(dev, nil, "cpu")
	f.planAndSend()
	f.resolveAlert(a, "cleared")
	f.exec(`DELETE FROM devices WHERE id = $1`, dev)
	f.planAndSend()
	if got := f.events(r); len(got) != 2 || got[1] != EventAlertResolved {
		t.Fatalf("%v", got)
	}
	// A device that goes with an open alert is told as removed.
	dev2 := f.device(f.orgA, site, "SRV02")
	f.alert(dev2, nil, "cpu")
	f.planAndSend()
	f.exec(`DELETE FROM devices WHERE id = $1`, dev2)
	f.planAndSend()
	if got := f.events(r); len(got) != 4 || got[3] != EventAlertResolved {
		t.Fatalf("%v", got)
	}
	if res := decode(t, r.got()[3].body); res.Alerts[0].Resolution != "device_removed" {
		t.Fatalf("%s", r.got()[3].body)
	}
	// An alert that opened and whose device is gone before it is planned is never told.
	dev3 := f.device(f.orgA, site, "SRV03")
	f.alert(dev3, nil, "cpu")
	f.exec(`DELETE FROM devices WHERE id = $1`, dev3)
	f.planAndSend()
	if len(r.got()) != 4 {
		t.Fatalf("%v", f.events(r))
	}
}

func TestSetDeviceKind(t *testing.T) {
	f := newFx(t)
	site := f.site(f.orgA, "Main", "UTC")
	dev := f.device(f.orgA, site, "SRV01")
	siteAdmin := f.caller(rbac.RoleSiteAdmin, f.orgA)
	kind, err := f.svc.SetDeviceKind(f.ctx, f.orgAdmin(f.orgA), dev, ptr("workstation"))
	if err != nil || kind != "workstation" {
		t.Fatalf("%q %v", kind, err)
	}
	_ = siteAdmin
	if kind, err = f.svc.SetDeviceKind(f.ctx, f.orgAdmin(f.orgA), dev, nil); err != nil || kind != "server" {
		t.Fatalf("a cleared kind reads Linux as a server: %q %v", kind, err)
	}
	if _, err = f.svc.SetDeviceKind(f.ctx, f.orgAdmin(f.orgA), dev, ptr("toaster")); err == nil {
		t.Fatal("a kind that is neither")
	}
	if _, err = f.svc.SetDeviceKind(f.ctx, f.orgAdmin(f.orgB), dev, ptr("server")); err == nil {
		t.Fatal("another organization set a kind")
	}
	if _, err = f.svc.SetDeviceKind(f.ctx, f.caller(rbac.RoleReadOnly, f.orgA), dev, ptr("server")); err == nil {
		t.Fatal("a viewer set a kind")
	}
	if f.n(`SELECT count(*) FROM audit_log WHERE action = $1`, ActionDeviceKind) != 2 {
		t.Fatal("not audited")
	}
}

var _ = access.System
