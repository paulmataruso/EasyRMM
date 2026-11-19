//go:build integration

package easypatch

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/easypatch/eptest"
)

// alertFixture is the fleet with alerts: web-01's (HQ) and db-01's
// (Branch), an Acme alert of no device, the stray endpoint's (no EasyRMM
// device), Globex's, and a resolved one of web-01.
type alertFixture struct {
	*fleetFixture
	aWeb, aDB, aHeld, aStray, aGlobex, aResolved uuid.UUID
}

func newAlertFixture(t *testing.T) *alertFixture {
	t.Helper()
	f := &alertFixture{fleetFixture: newFleetFixture(t)}
	at := time.Date(2026, 11, 19, 8, 0, 0, 0, time.UTC)
	add := func(a eptest.AlertInfo, minutes int) uuid.UUID {
		a.OpenedAt = at.Add(time.Duration(minutes) * time.Minute)
		return f.engine.AddAlert(a)
	}
	f.aWeb = add(eptest.AlertInfo{RuleType: "OsUnsupported", Severity: "Warning", Title: "WEB-01: Windows Server 2016 support ends on 2027-01-12",
		Org: f.epAcme, Endpoint: &f.eWeb.ID}, 1)
	f.aDB = add(eptest.AlertInfo{RuleType: "InstallFailed", Severity: "Critical", Title: "DB-01: 1 update failed to install", Org: f.epAcme,
		Endpoint: &f.eDB.ID}, 2)
	f.aHeld = add(eptest.AlertInfo{RuleType: "UpdateHeld", Severity: "Warning", Title: "Acme: 1 update on hold", Org: f.epAcme}, 3)
	f.aStray = add(eptest.AlertInfo{RuleType: "EndpointOffline", Severity: "Info", Title: "stray-01 has been offline for 26 hours", Org: f.epAcme,
		Endpoint: &f.eStray.ID}, 4)
	f.aGlobex = add(eptest.AlertInfo{RuleType: "UpdateHeld", Severity: "Warning", Title: "Globex: 2 updates on hold", Org: f.epGlobex}, 5)
	resolvedAt := at
	f.aResolved = add(eptest.AlertInfo{RuleType: "RestartPending", Severity: "Info", Status: "Resolved", Title: "WEB-01 needs a restart",
		Org: f.epAcme, Endpoint: &f.eWeb.ID, ResolvedAt: &resolvedAt}, 0)
	return f
}

func alertIDs(list AlertList) []uuid.UUID {
	out := make([]uuid.UUID, 0, len(list.Items))
	for _, a := range list.Items {
		out = append(out, a.ID)
	}
	return out
}

func sameIDs(got []uuid.UUID, want ...uuid.UUID) bool {
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

// Each caller sees the alerts of the devices whose patching they see, and
// an organization's own alerts (and those of endpoints EasyRMM does not
// link) when they see the whole organization; the most severe first.
func TestAlerts(t *testing.T) {
	f := newAlertFixture(t)
	ctx := f.ctx

	all, err := f.svc.Alerts(ctx, f.admin, AlertsQuery{})
	if err != nil || all.Capped || !sameIDs(alertIDs(all), f.aDB, f.aGlobex, f.aHeld, f.aWeb, f.aStray) {
		t.Fatalf("super administrator: %+v, %v", all, err)
	}
	web := all.Items[3]
	if web.OrganizationID != f.acme || web.OrganizationName != "Acme" || web.DeviceID == nil || *web.DeviceID != f.web || web.DeviceName != "WEB-01" ||
		!web.CanAcknowledge || web.Alert.OrganizationID != f.epAcme {
		t.Fatalf("web-01's alert: %+v", web)
	}
	if stray := all.Items[4]; stray.DeviceID != nil || stray.Hostname != "stray-01" {
		t.Fatalf("the stray endpoint's alert: %+v", stray)
	}
	if st := f.lastStatement("GET", "/api/v1/alerts"); st.Role != RoleReadOnly || len(st.Organizations) != 1 {
		t.Fatalf("statement: %+v", st)
	}

	tech, err := f.svc.Alerts(ctx, f.tech, AlertsQuery{})
	if err != nil || !sameIDs(alertIDs(tech), f.aDB, f.aHeld, f.aWeb, f.aStray) || !tech.Items[0].CanAcknowledge {
		t.Fatalf("Acme's technician: %+v, %v", tech, err)
	}
	site, err := f.svc.Alerts(ctx, f.siteTech, AlertsQuery{})
	if err != nil || !sameIDs(alertIDs(site), f.aWeb) || !site.Items[0].CanAcknowledge {
		t.Fatalf("HQ's technician: %+v, %v", site, err)
	}
	reader, err := f.svc.Alerts(ctx, f.reader, AlertsQuery{})
	if err != nil || len(reader.Items) != 4 || reader.Items[0].CanAcknowledge {
		t.Fatalf("reader: %+v, %v", reader, err)
	}
	if l, err := f.svc.Alerts(ctx, f.tech, AlertsQuery{OrganizationID: f.globex}); err != nil || len(l.Items) != 0 {
		t.Fatalf("another organization: %+v, %v", l, err)
	}

	for name, c := range map[string]struct {
		q    AlertsQuery
		want []uuid.UUID
	}{
		"severity":     {AlertsQuery{Severity: "Critical"}, []uuid.UUID{f.aDB}},
		"rule type":    {AlertsQuery{RuleType: "UpdateHeld"}, []uuid.UUID{f.aGlobex, f.aHeld}},
		"search":       {AlertsQuery{Search: "  web-01 "}, []uuid.UUID{f.aWeb}},
		"organization": {AlertsQuery{OrganizationID: f.globex}, []uuid.UUID{f.aGlobex}},
		"device":       {AlertsQuery{Status: "all"}, nil},
		"resolved":     {AlertsQuery{Status: "resolved"}, []uuid.UUID{f.aResolved}},
		"all":          {AlertsQuery{Status: "all", OrganizationID: f.acme}, []uuid.UUID{f.aDB, f.aHeld, f.aWeb, f.aStray, f.aResolved}},
	} {
		if name == "device" {
			c.q.DeviceID, c.want = f.web, []uuid.UUID{f.aWeb, f.aResolved}
		}
		l, err := f.svc.Alerts(ctx, f.admin, c.q)
		if err != nil || !sameIDs(alertIDs(l), c.want...) {
			t.Errorf("%s: %v, %v", name, alertIDs(l), err)
		}
	}
	for field, q := range map[string]AlertsQuery{
		"status":   {Status: "Open"},
		"severity": {Severity: "warning"},
		"ruleType": {RuleType: "Offline"},
		"search":   {Search: "web\x00"},
	} {
		if _, err := f.svc.Alerts(ctx, f.admin, q); fieldOf(err) != field {
			t.Errorf("%s: %v", field, err)
		}
	}
	if _, err := f.svc.Alerts(ctx, f.admin, AlertsQuery{DeviceID: uuid.New()}); !isKind(err, apperr.KindNotFound) {
		t.Fatalf("unknown device: %v", err)
	}

	// EasyPatch counts for those who see whole organizations; EasyRMM for
	// the rest, over the devices they see.
	sum, err := f.svc.AlertCounts(ctx, f.admin, uuid.Nil)
	if err != nil || sum.Open != 5 || sum.Acknowledged != 0 || sum.Critical != 1 || sum.Warning != 3 || sum.Info != 1 || sum.Capped {
		t.Fatalf("super administrator's counts: %+v, %v", sum, err)
	}
	if st := f.lastStatement("GET", "/api/v1/alerts/summary"); st.Role != RoleReadOnly || len(st.Organizations) != 2 {
		t.Fatalf("summary statement: %+v", st)
	}
	if sum, err := f.svc.AlertCounts(ctx, f.tech, uuid.Nil); err != nil || sum.Open != 4 || sum.Critical != 1 {
		t.Fatalf("technician's counts: %+v, %v", sum, err)
	}
	summaries := len(f.engine.RequestsTo("GET", "/api/v1/alerts/summary"))
	if sum, err := f.svc.AlertCounts(ctx, f.siteTech, uuid.Nil); err != nil || sum.Open != 1 || sum.Warning != 1 || sum.Critical != 0 {
		t.Fatalf("HQ technician's counts: %+v, %v", sum, err)
	}
	if len(f.engine.RequestsTo("GET", "/api/v1/alerts/summary")) != summaries {
		t.Fatal("EasyPatch counted for a caller who sees part of the organization")
	}
	if sum, err := f.svc.AlertCounts(ctx, f.admin, f.globex); err != nil || sum.Open != 1 {
		t.Fatalf("Globex's counts: %+v, %v", sum, err)
	}
}

// Acknowledging takes the alerts the caller may manage the patching of,
// with an Admin statement, and records one event for each device and for
// the organization's own.
func TestAcknowledgeAlerts(t *testing.T) {
	f := newAlertFixture(t)
	ctx := f.ctx

	n, err := f.svc.AcknowledgeAlerts(ctx, f.siteTech, []uuid.UUID{f.aWeb, f.aDB, f.aHeld, f.aWeb})
	if err != nil || n != 1 {
		t.Fatalf("HQ's technician: %d, %v", n, err)
	}
	if a, _ := f.engine.AlertState(f.aWeb); a.Status != "Acknowledged" || a.AcknowledgedBy != "easyrmm:sid@example.com" {
		t.Fatalf("web-01's alert: %+v", a)
	}
	if a, _ := f.engine.AlertState(f.aDB); a.Status != "Open" {
		t.Fatalf("db-01's alert: %+v", a)
	}
	if st := f.lastStatement("POST", "/api/v1/alerts/acknowledge"); st.Role != RoleAdmin || len(st.Organizations) != 1 || st.Organizations[0] != f.epAcme {
		t.Fatalf("statement: %+v", st)
	}
	a := f.audits("patch.alert_acknowledge")
	if len(a) != 1 || a[0].Device == nil || *a[0].Device != f.web || a[0].Details["alerts"] != 1.0 || a[0].Details["device"] != "WEB-01" {
		t.Fatalf("audit: %+v", a)
	}

	// Acknowledged and resolved alerts are left as they are.
	n, err = f.svc.AcknowledgeAlerts(ctx, f.tech, []uuid.UUID{f.aWeb, f.aDB, f.aHeld, f.aResolved, f.aGlobex})
	if err != nil || n != 2 {
		t.Fatalf("Acme's technician: %d, %v", n, err)
	}
	if a, _ := f.engine.AlertState(f.aGlobex); a.Status != "Open" {
		t.Fatalf("Globex's alert: %+v", a)
	}
	a = f.audits("patch.alert_acknowledge")
	if len(a) != 3 || a[1].Device == nil || *a[1].Device != f.dbHost || a[2].Device != nil {
		t.Fatalf("audit: %+v", a)
	}
	l, _ := f.svc.Alerts(ctx, f.admin, AlertsQuery{Status: "acknowledged"})
	if len(l.Items) != 3 || l.Items[0].CanAcknowledge {
		t.Fatalf("acknowledged: %+v", l)
	}
	if sum, err := f.svc.AlertCounts(ctx, f.admin, uuid.Nil); err != nil || sum.Open != 2 || sum.Acknowledged != 3 {
		t.Fatalf("counts: %+v, %v", sum, err)
	}

	if n, err := f.svc.AcknowledgeAlerts(ctx, f.tech, []uuid.UUID{uuid.New()}); err != nil || n != 0 {
		t.Fatalf("unknown alert: %d, %v", n, err)
	}
	if _, err := f.svc.AcknowledgeAlerts(ctx, f.reader, []uuid.UUID{f.aStray}); !isKind(err, apperr.KindForbidden) {
		t.Fatalf("reader: %v", err)
	}
	if _, err := f.svc.AcknowledgeAlerts(ctx, f.admin, nil); fieldOf(err) != "alertIds" {
		t.Fatalf("none: %v", err)
	}
	many := make([]uuid.UUID, 201)
	for i := range many {
		many[i] = uuid.New()
	}
	if _, err := f.svc.AcknowledgeAlerts(ctx, f.admin, many); fieldOf(err) != "alertIds" {
		t.Fatalf("too many: %v", err)
	}
}

// Super administrators read and change EasyPatch's alert rules with
// SuperAdmin statements; EasyRMM checks them as EasyPatch does, field by
// field.
func TestAlertRules(t *testing.T) {
	f := newFleetFixture(t)
	ctx := f.ctx

	l, err := f.svc.AlertRules(ctx, f.admin)
	if err != nil || len(l.Items) != 9 || len(l.Types) != 9 || len(l.Channels) != 0 || l.Items[0].Name != "Endpoint offline" ||
		l.Items[0].ChannelIDs == nil || l.Items[0].ThresholdUnit != "hours" {
		t.Fatalf("rules: %+v, %v", l, err)
	}
	if st := f.lastStatement("GET", "/api/v1/alert-rules"); st.Role != RoleSuperAdmin || !st.AllOrganizations {
		t.Fatalf("statement: %+v", st)
	}
	for _, c := range []struct {
		name string
		call func() error
	}{
		{"organization administrator", func() error { _, err := f.svc.AlertRules(ctx, f.orgAdmin); return err }},
		{"technician", func() error { _, err := f.svc.AlertRules(ctx, f.tech); return err }},
	} {
		if err := c.call(); !isKind(err, apperr.KindForbidden) {
			t.Errorf("%s: %v", c.name, err)
		}
	}

	ch, err := f.svc.CreateChannel(ctx, f.admin, ChannelRequest{Name: "Operations", Type: "Email", Enabled: true,
		EmailRecipients: []string{" ops@example.com ", "OPS@example.com", "noc@example.com"}})
	if err != nil || len(ch.Channel.EmailRecipients) != 2 || ch.SigningSecret != "" {
		t.Fatalf("channel: %+v, %v", ch, err)
	}
	tag, err := f.svc.CreateTag(ctx, f.admin, TagInput{Name: "Servers", Color: "blue"})
	if err != nil {
		t.Fatal(err)
	}
	two := 2
	in := AlertRuleRequest{Name: " Acme servers offline ", Type: "EndpointOffline", Enabled: true, Severity: "Critical", Threshold: &two,
		OrganizationID: &f.acme, TagID: &tag.ID, ChannelIDs: []uuid.UUID{ch.Channel.ID, ch.Channel.ID}, RenotifyHours: 24, NotifyOnResolve: true}
	r, err := f.svc.CreateAlertRule(ctx, f.admin, in)
	if err != nil || r.Name != "Acme servers offline" || r.OrganizationID == nil || *r.OrganizationID != f.acme || r.OrganizationName != "Acme" ||
		r.AlertRule.OrganizationID == nil || *r.AlertRule.OrganizationID != f.epAcme || r.TagName != "Servers" || len(r.ChannelIDs) != 1 {
		t.Fatalf("created: %+v, %v", r, err)
	}
	if st := f.lastStatement("POST", "/api/v1/alert-rules"); st.Role != RoleSuperAdmin || !st.AllOrganizations || st.Name != "ada@example.com" {
		t.Fatalf("create statement: %+v", st)
	}
	// A type without a threshold drops the one given.
	failed := AlertRuleRequest{Name: "Failed installs", Type: "InstallFailed", Enabled: true, Severity: "Warning", Threshold: &two}
	if r, err := f.svc.CreateAlertRule(ctx, f.admin, failed); err != nil || r.Threshold != nil || r.OrganizationID != nil || r.UnlinkedOrganization {
		t.Fatalf("without threshold: %+v, %v", r, err)
	}

	zero, big := 0, 400
	unknown := uuid.New()
	for field, change := range map[string]func(*AlertRuleRequest){
		"name":           func(r *AlertRuleRequest) { r.Name = "  " },
		"type":           func(r *AlertRuleRequest) { r.Type = "Offline" },
		"severity":       func(r *AlertRuleRequest) { r.Severity = "critical" },
		"threshold":      func(r *AlertRuleRequest) { r.Threshold = &zero },
		"renotifyHours":  func(r *AlertRuleRequest) { r.RenotifyHours = 721 },
		"organizationId": func(r *AlertRuleRequest) { r.OrganizationID = &unknown },
		"tagId":          func(r *AlertRuleRequest) { r.TagID = &unknown },
		"channelIds":     func(r *AlertRuleRequest) { r.ChannelIDs = []uuid.UUID{unknown} },
	} {
		bad := in
		change(&bad)
		if _, err := f.svc.CreateAlertRule(ctx, f.admin, bad); fieldOf(err) != field {
			t.Errorf("%s: %v", field, err)
		}
	}
	if _, err := f.svc.CreateAlertRule(ctx, f.admin, AlertRuleRequest{Name: "Missing", Type: "OsUnsupported", Severity: "Info"}); fieldOf(err) != "threshold" {
		t.Fatalf("no threshold: %v", err)
	}
	if _, err := f.svc.CreateAlertRule(ctx, f.admin, AlertRuleRequest{Name: "Missing", Type: "SecurityUpdateMissing", Severity: "Info",
		Threshold: &big}); fieldOf(err) != "threshold" {
		t.Fatalf("threshold over: %v", err)
	}
	if _, err := f.svc.CreateAlertRule(ctx, f.admin, AlertRuleRequest{Name: "Held", Type: "UpdateHeld", Severity: "Info", TagID: &tag.ID}); fieldOf(err) != "tagId" {
		t.Fatalf("tag on an organization's rule: %v", err)
	}
	if _, err := f.svc.CreateAlertRule(ctx, f.orgAdmin, in); !isKind(err, apperr.KindForbidden) {
		t.Fatalf("organization administrator's rule: %v", err)
	}

	in.Severity, in.OrganizationID = "Warning", nil
	u, err := f.svc.UpdateAlertRule(ctx, f.admin, r.ID, in)
	if err != nil || u.Severity != "Warning" || u.OrganizationID != nil || u.AlertRule.OrganizationID != nil {
		t.Fatalf("updated: %+v, %v", u, err)
	}
	if _, err := f.svc.UpdateAlertRule(ctx, f.admin, uuid.New(), in); !isKind(err, apperr.KindNotFound) {
		t.Fatalf("unknown rule: %v", err)
	}

	// A rule of an organization EasyRMM does not link is said to be so, and
	// is not widened to every organization by a change.
	initech := f.engine.Org("Initech")
	var raw AlertRule
	if err := f.svc.engine.client.do(WithStatement(ctx, Statement{Subject: ServiceSubject, Name: "console", Role: RoleSuperAdmin, AllOrganizations: true}),
		"POST", alertRulesPath, nil, map[string]any{"name": "Initech failures", "type": "InstallFailed", "severity": "Warning", "enabled": true,
			"organizationId": initech, "renotifyHours": 0}, "", &raw); err != nil {
		t.Fatal(err)
	}
	l, _ = f.svc.AlertRules(ctx, f.admin)
	if i := indexRule(l, raw.ID); i < 0 || !l.Items[i].UnlinkedOrganization || l.Items[i].OrganizationID != nil {
		t.Fatalf("unlinked: %+v", l.Items)
	}
	if _, err := f.svc.UpdateAlertRule(ctx, f.admin, raw.ID, failed); fieldOf(err) != "organizationId" {
		t.Fatalf("widening: %v", err)
	}

	// Deleting resolves its alerts.
	alert := f.engine.AddAlert(eptest.AlertInfo{Rule: &r.ID, RuleType: "EndpointOffline", Severity: "Warning", Title: "WEB-01 offline", Org: f.epAcme,
		Endpoint: &f.eWeb.ID})
	if err := f.svc.DeleteAlertRule(ctx, f.admin, r.ID); err != nil {
		t.Fatal(err)
	}
	if a, _ := f.engine.AlertState(alert); a.Status != "Resolved" {
		t.Fatalf("its alert: %+v", a)
	}
	if err := f.svc.DeleteAlertRule(ctx, f.admin, r.ID); !isKind(err, apperr.KindNotFound) {
		t.Fatalf("deleted twice: %v", err)
	}
	if err := f.svc.DeleteAlertRule(ctx, f.admin, raw.ID); err != nil {
		t.Fatalf("unlinked rule: %v", err)
	}
	a := f.audits("patch.alert_rule_")
	if len(a) != 5 || a[0].Action != "patch.alert_rule_create" || a[0].Details["organization"] != "Acme" || a[0].Details["tag"] != "Servers" ||
		a[2].Action != "patch.alert_rule_update" || a[3].Action != "patch.alert_rule_delete" {
		t.Fatalf("audit: %+v", a)
	}
}

func indexRule(l AlertRuleList, id uuid.UUID) int {
	for i, r := range l.Items {
		if r.ID == id {
			return i
		}
	}
	return -1
}

// Channels are added, changed, tested and deleted with SuperAdmin
// statements; a webhook's address never reaches EasyRMM's audit log, and
// the mail server stays as EasyRMM gave it.
func TestNotifications(t *testing.T) {
	f := newFleetFixture(t)
	ctx := f.ctx

	v, err := f.svc.Notifications(ctx, f.admin)
	if err != nil || v.Channels == nil || len(v.Channels) != 0 || v.AllowPrivateNetworkWebhooks {
		t.Fatalf("view: %+v, %v", v, err)
	}
	if _, err := f.svc.Notifications(ctx, f.orgAdmin); !isKind(err, apperr.KindForbidden) {
		t.Fatalf("organization administrator: %v", err)
	}

	// Whether webhooks may go to private networks; the mail server stays.
	before := f.engine.Mail()
	v, err = f.svc.SetNotificationSettings(ctx, f.admin, NotificationSettings{AllowPrivateNetworkWebhooks: true})
	if err != nil || !v.AllowPrivateNetworkWebhooks {
		t.Fatalf("private networks: %+v, %v", v, err)
	}
	after := f.engine.Mail()
	if after["allowPrivateNetworkWebhooks"] != true || after["smtpHost"] != before["smtpHost"] || after["smtpPort"] != before["smtpPort"] {
		t.Fatalf("mail settings: %+v, then %+v", before, after)
	}
	puts := len(f.engine.RequestsTo("PUT", "/api/v1/notifications/settings"))
	if _, err := f.svc.SetNotificationSettings(ctx, f.admin, NotificationSettings{AllowPrivateNetworkWebhooks: true}); err != nil ||
		len(f.engine.RequestsTo("PUT", "/api/v1/notifications/settings")) != puts {
		t.Fatalf("unchanged: %v", err)
	}
	if a := f.audits("patch.notifications_update"); len(a) != 1 {
		t.Fatalf("settings audit: %+v", a)
	}

	generic := "Generic"
	address := "https://hooks.example.com/services/T0/B0?token=s3cret"
	hook, err := f.svc.CreateChannel(ctx, f.admin, ChannelRequest{Name: "PSA", Type: "Webhook", Enabled: true, WebhookFormat: &generic,
		WebhookURL: &address})
	if err != nil || hook.SigningSecret == "" || !hook.Channel.HasSigningSecret || hook.Channel.WebhookHost != "hooks.example.com" ||
		hook.Channel.EmailRecipients == nil {
		t.Fatalf("webhook: %+v, %v", hook, err)
	}
	if st := f.lastStatement("POST", "/api/v1/notifications/channels"); st.Role != RoleSuperAdmin || !st.AllOrganizations {
		t.Fatalf("statement: %+v", st)
	}
	plain, short, user := "http://hooks.example.com/x", "", "https://me:pw@hooks.example.com/x"
	slack := "Slack"
	for field, in := range map[string]ChannelRequest{
		"name":            {Name: strings.Repeat("n", 101), Type: "Email", EmailRecipients: []string{"ops@example.com"}},
		"type":            {Name: "Text", Type: "Sms"},
		"emailRecipients": {Name: "Mail", Type: "Email", EmailRecipients: []string{"ops@example.com", "not an address"}},
		"webhookFormat":   {Name: "Hook", Type: "Webhook", WebhookURL: &address},
		"webhookUrl":      {Name: "Hook", Type: "Webhook", WebhookFormat: &slack, WebhookURL: &plain},
	} {
		if _, err := f.svc.CreateChannel(ctx, f.admin, in); fieldOf(err) != field {
			t.Errorf("%s: %v", field, err)
		}
	}
	for name, u := range map[string]*string{"none": nil, "empty": &short, "credentials": &user} {
		if _, err := f.svc.CreateChannel(ctx, f.admin, ChannelRequest{Name: "Hook", Type: "Webhook", WebhookFormat: &slack, WebhookURL: u}); fieldOf(err) != "webhookUrl" {
			t.Errorf("address %s: %v", name, err)
		}
	}
	if _, err := f.svc.CreateChannel(ctx, f.admin, ChannelRequest{Name: "Mail", Type: "Email"}); fieldOf(err) != "emailRecipients" {
		t.Fatalf("no recipients: %v", err)
	}

	// A change without an address keeps it; Slack has no signing secret.
	saved, err := f.svc.UpdateChannel(ctx, f.admin, hook.Channel.ID, ChannelRequest{Name: "PSA (Slack)", Type: "Webhook", Enabled: false,
		WebhookFormat: &slack})
	if err != nil || saved.Channel.WebhookHost != "hooks.example.com" || saved.Channel.HasSigningSecret || saved.Channel.Enabled {
		t.Fatalf("changed: %+v, %v", saved, err)
	}
	if _, err := f.svc.UpdateChannel(ctx, f.admin, hook.Channel.ID, ChannelRequest{Name: "PSA", Type: "Email",
		EmailRecipients: []string{"ops@example.com"}}); fieldOf(err) != "type" {
		t.Fatalf("type change: %v", err)
	}
	if _, err := f.svc.RotateChannelSecret(ctx, f.admin, hook.Channel.ID); !isCode(err, "easypatch_no_secret") {
		t.Fatalf("secret of a Slack webhook: %v", err)
	}
	saved, err = f.svc.UpdateChannel(ctx, f.admin, hook.Channel.ID, ChannelRequest{Name: "PSA", Type: "Webhook", Enabled: true,
		WebhookFormat: &generic})
	if err != nil || saved.SigningSecret == "" || saved.SigningSecret == hook.SigningSecret {
		t.Fatalf("generic again: %+v, %v", saved, err)
	}
	rotated, err := f.svc.RotateChannelSecret(ctx, f.admin, hook.Channel.ID)
	if err != nil || rotated.SigningSecret == "" || rotated.SigningSecret == saved.SigningSecret {
		t.Fatalf("rotated: %+v, %v", rotated, err)
	}

	d, err := f.svc.TestChannel(ctx, f.admin, hook.Channel.ID)
	if err != nil || d.Kind != "Test" || d.Status != "Pending" || d.ChannelID != hook.Channel.ID {
		t.Fatalf("test: %+v, %v", d, err)
	}
	if _, err := f.svc.TestChannel(ctx, f.admin, hook.Channel.ID); !isCode(err, "easypatch_test_too_soon") {
		t.Fatalf("test again: %v", err)
	}
	p, err := f.svc.Deliveries(ctx, f.admin, DeliveriesQuery{Page: 1})
	if err != nil || p.TotalCount != 1 || p.Items[0].ChannelName != "PSA" || p.PageSize != 50 {
		t.Fatalf("deliveries: %+v, %v", p, err)
	}
	if p, err := f.svc.Deliveries(ctx, f.admin, DeliveriesQuery{Status: "Sent", ChannelID: hook.Channel.ID, Page: 1}); err != nil || len(p.Items) != 0 {
		t.Fatalf("sent: %+v, %v", p, err)
	}
	if _, err := f.svc.Deliveries(ctx, f.admin, DeliveriesQuery{Status: "sent", Page: 1}); fieldOf(err) != "status" {
		t.Fatalf("status: %v", err)
	}
	if _, err := f.svc.Deliveries(ctx, f.admin, DeliveriesQuery{Page: 0}); fieldOf(err) != "page" {
		t.Fatalf("page: %v", err)
	}

	// Deleting takes the channel out of the rules that send to it.
	r, err := f.svc.CreateAlertRule(ctx, f.admin, AlertRuleRequest{Name: "Failures to the PSA", Type: "InstallFailed", Enabled: true,
		Severity: "Warning", ChannelIDs: []uuid.UUID{hook.Channel.ID}})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.svc.DeleteChannel(ctx, f.admin, hook.Channel.ID); err != nil {
		t.Fatal(err)
	}
	l, _ := f.svc.AlertRules(ctx, f.admin)
	if i := indexRule(l, r.ID); i < 0 || len(l.Items[i].ChannelIDs) != 0 {
		t.Fatalf("rule after the channel went: %+v", l.Items)
	}
	if err := f.svc.DeleteChannel(ctx, f.admin, hook.Channel.ID); !isKind(err, apperr.KindNotFound) {
		t.Fatalf("deleted twice: %v", err)
	}

	a := f.audits("patch.channel_")
	actions := make([]string, 0, len(a))
	for _, e := range a {
		actions = append(actions, e.Action)
		b, _ := json.Marshal(e.Details)
		if strings.Contains(string(b), "s3cret") || strings.Contains(string(b), "/services/") {
			t.Fatalf("the webhook's address in the audit log: %s", b)
		}
	}
	if strings.Join(actions, " ") != "patch.channel_create patch.channel_update patch.channel_update patch.channel_rotate_secret patch.channel_test patch.channel_delete" ||
		a[0].Details["host"] != "hooks.example.com" {
		t.Fatalf("audit: %+v", a)
	}
}

// With a connected server, alerts are read and acknowledged with
// EasyRMM's token, and rules and channels are EasyPatch's console's.
func TestAlertsConnected(t *testing.T) {
	f := newFixture(t)
	ctx := f.ctx
	f.connect()
	org := f.ep.Org("Acme Patch")
	if err := f.svc.LinkOrganization(ctx, f.admin.Actor, f.acme, org); err != nil {
		t.Fatal(err)
	}
	id := f.ep.AddAlert(eptest.AlertInfo{RuleType: "UpdateHeld", Severity: "Warning", Title: "Acme Patch: 1 update on hold", Org: org})
	f.ep.AddAlert(eptest.AlertInfo{RuleType: "UpdateHeld", Severity: "Warning", Title: "Unlinked: 1 update on hold", Org: f.ep.Org("Unlinked")})
	l, err := f.svc.Alerts(ctx, f.admin, AlertsQuery{})
	if err != nil || !sameIDs(alertIDs(l), id) || !l.Items[0].CanAcknowledge {
		t.Fatalf("alerts: %+v, %v", l, err)
	}
	if n, err := f.svc.AcknowledgeAlerts(ctx, f.admin, []uuid.UUID{id}); err != nil || n != 1 {
		t.Fatalf("acknowledge: %d, %v", n, err)
	}
	for name, call := range map[string]func() error{
		"rules":         func() error { _, err := f.svc.AlertRules(ctx, f.admin); return err },
		"notifications": func() error { _, err := f.svc.Notifications(ctx, f.admin); return err },
		"channel":       func() error { _, err := f.svc.CreateChannel(ctx, f.admin, ChannelRequest{}); return err },
		"deliveries":    func() error { _, err := f.svc.Deliveries(ctx, f.admin, DeliveriesQuery{Page: 1}); return err },
	} {
		if err := call(); !isCode(err, "easypatch_server_wide") {
			t.Errorf("%s: %v", name, err)
		}
	}
	f.ep.Set(func() { f.ep.ReadOnly = true })
	if _, err := f.svc.CheckConnection(ctx); err != nil {
		t.Fatal(err)
	}
	if l, err := f.svc.Alerts(ctx, f.admin, AlertsQuery{Status: "all"}); err != nil || len(l.Items) != 1 || l.Items[0].CanAcknowledge {
		t.Fatalf("read-only token's alerts: %+v, %v", l, err)
	}
	if _, err := f.svc.AcknowledgeAlerts(ctx, f.admin, []uuid.UUID{id}); !isCode(err, "easypatch_read_only") {
		t.Fatalf("read-only token: %v", err)
	}
}

// Before EasyPatch is set up, and while the engine does not answer, each
// call says so.
func TestAlertsUnavailable(t *testing.T) {
	plain := newFixture(t)
	f := newFleetFixture(t)
	f.engine.Set(func() { f.engine.Down = true })
	for name, call := range map[string]func(*fixture) error{
		"alerts": func(x *fixture) error { _, err := x.svc.Alerts(x.ctx, x.admin, AlertsQuery{}); return err },
		"counts": func(x *fixture) error { _, err := x.svc.AlertCounts(x.ctx, x.admin, uuid.Nil); return err },
		"acknowledge": func(x *fixture) error {
			_, err := x.svc.AcknowledgeAlerts(x.ctx, x.admin, []uuid.UUID{uuid.New()})
			return err
		},
		"rules":         func(x *fixture) error { _, err := x.svc.AlertRules(x.ctx, x.admin); return err },
		"notifications": func(x *fixture) error { _, err := x.svc.Notifications(x.ctx, x.admin); return err },
		"deliveries": func(x *fixture) error {
			_, err := x.svc.Deliveries(x.ctx, x.admin, DeliveriesQuery{Page: 1})
			return err
		},
		"test":        func(x *fixture) error { _, err := x.svc.TestChannel(x.ctx, x.admin, uuid.New()); return err },
		"delete rule": func(x *fixture) error { return x.svc.DeleteAlertRule(x.ctx, x.admin, uuid.New()) },
		"private": func(x *fixture) error {
			_, err := x.svc.SetNotificationSettings(x.ctx, x.admin, NotificationSettings{})
			return err
		},
	} {
		if err := call(plain); !isCode(err, "easypatch_not_configured") {
			t.Errorf("%s, not set up: %v", name, err)
		}
		if err := call(f.fixture); !isCode(err, "patching_unavailable") {
			t.Errorf("%s, engine down: %v", name, err)
		}
	}
}

// TestAlertsLostReplies has EasyPatch fail each call the alerts, rules and
// channels make, one at a time: the error reaches the caller, and nothing is
// recorded as done.
func TestAlertsLostReplies(t *testing.T) {
	f := newAlertFixture(t)
	ctx := f.ctx
	rules, err := f.svc.AlertRules(ctx, f.admin)
	if err != nil {
		t.Fatal(err)
	}
	rule := rules.Items[0]
	generic := "Generic"
	address := "https://hooks.example.com/easyrmm"
	hook, err := f.svc.CreateChannel(ctx, f.admin, ChannelRequest{Name: "PSA", Type: "Webhook", Enabled: true, WebhookFormat: &generic,
		WebhookURL: &address})
	if err != nil {
		t.Fatal(err)
	}
	rulePath := alertRulesPath + "/" + rule.ID.String()
	hookPath := channelsPath + "/" + hook.Channel.ID.String()
	ruleIn := AlertRuleRequest{Name: rule.Name, Type: rule.Type, Enabled: true, Severity: rule.Severity, Threshold: rule.Threshold}
	hookIn := ChannelRequest{Name: "PSA", Type: "Webhook", Enabled: true, WebhookFormat: &generic}
	for _, c := range []struct {
		name, method, path string
		call               func() error
	}{
		{"alerts", "GET", "/api/v1/alerts", func() error { return second(f.svc.Alerts(ctx, f.admin, AlertsQuery{})) }},
		{"a device's alerts", "GET", "/api/v1/alerts", func() error {
			return second(f.svc.Alerts(ctx, f.admin, AlertsQuery{DeviceID: f.web}))
		}},
		{"counts", "GET", "/api/v1/alerts/summary", func() error { return second(f.svc.AlertCounts(ctx, f.admin, uuid.Nil)) }},
		{"a site's counts", "GET", "/api/v1/alerts", func() error { return second(f.svc.AlertCounts(ctx, f.siteTech, uuid.Nil)) }},
		{"acknowledge, finding them", "GET", "/api/v1/alerts", func() error {
			return second(f.svc.AcknowledgeAlerts(ctx, f.admin, []uuid.UUID{f.aWeb}))
		}},
		{"acknowledge", "POST", "/api/v1/alerts/acknowledge", func() error {
			return second(f.svc.AcknowledgeAlerts(ctx, f.admin, []uuid.UUID{f.aWeb}))
		}},
		{"rules", "GET", alertRulesPath, func() error { return second(f.svc.AlertRules(ctx, f.admin)) }},
		{"rules' tags", "GET", "/api/v1/tags", func() error { return second(f.svc.AlertRules(ctx, f.admin)) }},
		{"rules' channels", "GET", channelsPath, func() error { return second(f.svc.AlertRules(ctx, f.admin)) }},
		{"create a rule", "POST", alertRulesPath, func() error {
			in := ruleIn
			in.Name = "Another"
			return second(f.svc.CreateAlertRule(ctx, f.admin, in))
		}},
		{"create a rule, reading tags", "GET", "/api/v1/tags", func() error { return second(f.svc.CreateAlertRule(ctx, f.admin, ruleIn)) }},
		{"change a rule", "PUT", rulePath, func() error { return second(f.svc.UpdateAlertRule(ctx, f.admin, rule.ID, ruleIn)) }},
		{"change a rule, reading it", "GET", alertRulesPath, func() error {
			return second(f.svc.UpdateAlertRule(ctx, f.admin, rule.ID, ruleIn))
		}},
		{"delete a rule, reading it", "GET", alertRulesPath, func() error { return f.svc.DeleteAlertRule(ctx, f.admin, rule.ID) }},
		{"delete a rule", "DELETE", rulePath, func() error { return f.svc.DeleteAlertRule(ctx, f.admin, rule.ID) }},
		{"notifications", "GET", channelsPath, func() error { return second(f.svc.Notifications(ctx, f.admin)) }},
		{"notifications' mail", "GET", mailSettingsPath, func() error { return second(f.svc.Notifications(ctx, f.admin)) }},
		{"private networks", "PUT", mailSettingsPath, func() error {
			return second(f.svc.SetNotificationSettings(ctx, f.admin, NotificationSettings{AllowPrivateNetworkWebhooks: true}))
		}},
		{"private networks, reading", "GET", mailSettingsPath, func() error {
			return second(f.svc.SetNotificationSettings(ctx, f.admin, NotificationSettings{AllowPrivateNetworkWebhooks: true}))
		}},
		{"create a channel", "POST", channelsPath, func() error {
			return second(f.svc.CreateChannel(ctx, f.admin, ChannelRequest{Name: "Desk", Type: "Email", Enabled: true,
				EmailRecipients: []string{"desk@example.com"}}))
		}},
		{"change a channel", "PUT", hookPath, func() error { return second(f.svc.UpdateChannel(ctx, f.admin, hook.Channel.ID, hookIn)) }},
		{"change a channel, reading it", "GET", channelsPath, func() error {
			return second(f.svc.UpdateChannel(ctx, f.admin, hook.Channel.ID, hookIn))
		}},
		{"new signing key", "POST", hookPath + "/rotate-secret", func() error {
			return second(f.svc.RotateChannelSecret(ctx, f.admin, hook.Channel.ID))
		}},
		{"new signing key, reading", "GET", channelsPath, func() error {
			return second(f.svc.RotateChannelSecret(ctx, f.admin, hook.Channel.ID))
		}},
		{"test", "POST", hookPath + "/test", func() error { return second(f.svc.TestChannel(ctx, f.admin, hook.Channel.ID)) }},
		{"test, reading", "GET", channelsPath, func() error { return second(f.svc.TestChannel(ctx, f.admin, hook.Channel.ID)) }},
		{"messages", "GET", "/api/v1/notifications/deliveries", func() error {
			return second(f.svc.Deliveries(ctx, f.admin, DeliveriesQuery{Page: 1}))
		}},
		// Last: a lost delete is a delete.
		{"delete a channel, reading it", "GET", channelsPath, func() error { return f.svc.DeleteChannel(ctx, f.admin, hook.Channel.ID) }},
		{"delete a channel", "DELETE", hookPath, func() error { return f.svc.DeleteChannel(ctx, f.admin, hook.Channel.ID) }},
	} {
		before := len(f.audits("patch."))
		f.engine.Set(func() { f.engine.LoseReply = func(m, p string) bool { return m == c.method && p == c.path } })
		err := c.call()
		f.engine.Set(func() { f.engine.LoseReply = nil })
		if err == nil {
			t.Errorf("%s with %s %s lost: no error", c.name, c.method, c.path)
		}
		if after := len(f.audits("patch.")); after != before {
			t.Errorf("%s with %s %s lost: %d audit events recorded", c.name, c.method, c.path, after-before)
		}
	}
}
