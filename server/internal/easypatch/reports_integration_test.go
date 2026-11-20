//go:build integration

package easypatch

import (
	"bytes"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/easypatch/eptest"
	"github.com/paulmataruso/easyrmm/server/internal/reports"
)

// The compliance trend adds up the organizations the caller sees whole.
func TestComplianceTrend(t *testing.T) {
	f := newFleetFixture(t)
	ctx := f.ctx
	today := time.Now().UTC()
	day := func(back int) string { return today.AddDate(0, 0, -back).Format(time.DateOnly) }
	f.engine.SetTrend(f.epAcme,
		eptest.TrendDay{Date: day(40), Total: 9, Compliant: 9},
		eptest.TrendDay{Date: day(1), Total: 3, Compliant: 1, Missing: 2},
		eptest.TrendDay{Date: day(0), Total: 3, Compliant: 2, Missing: 1, Offline: 1})
	f.engine.SetTrend(f.epGlobex, eptest.TrendDay{Date: day(0), Total: 1, Compliant: 1})

	tr, err := f.svc.ComplianceTrend(ctx, f.admin, uuid.Nil, 0)
	if err != nil || tr.Organizations != 2 || len(tr.Points) != 2 {
		t.Fatalf("both organizations: %+v, %v", tr, err)
	}
	if p := tr.Points[1]; p.Date != day(0) || p.TotalEndpoints != 4 || p.Compliant != 3 || p.MissingUpdates != 1 || p.Offline != 1 ||
		p.CompliancePercent != 75 {
		t.Fatalf("today: %+v", p)
	}
	if p := tr.Points[0]; p.Date != day(1) || p.CompliancePercent != 33.3 {
		t.Fatalf("yesterday: %+v", p)
	}
	if st := f.lastStatement("GET", "/api/v1/reports/compliance/trend"); st.Role != RoleReadOnly || !slices.Equal(st.Organizations, []uuid.UUID{f.epGlobex}) {
		t.Fatalf("statement: %+v", st)
	}
	if tr, err := f.svc.ComplianceTrend(ctx, f.admin, uuid.Nil, 60); err != nil || len(tr.Points) != 3 {
		t.Fatalf("60 days: %+v, %v", tr, err)
	}
	if tr, err := f.svc.ComplianceTrend(ctx, f.reader, uuid.Nil, 0); err != nil || tr.Organizations != 1 || tr.Points[1].TotalEndpoints != 3 {
		t.Fatalf("Acme's reader: %+v, %v", tr, err)
	}
	if tr, err := f.svc.ComplianceTrend(ctx, f.admin, f.globex, 0); err != nil || tr.Organizations != 1 || len(tr.Points) != 1 {
		t.Fatalf("Globex: %+v, %v", tr, err)
	}
	// A site's technician does not see an organization whole.
	if tr, err := f.svc.ComplianceTrend(ctx, f.siteTech, uuid.Nil, 0); err != nil || tr.Organizations != 0 || len(tr.Points) != 0 {
		t.Fatalf("a site's technician: %+v, %v", tr, err)
	}
	if _, err := f.svc.ComplianceTrend(ctx, f.admin, uuid.Nil, 400); !isKind(err, apperr.KindInvalid) {
		t.Fatalf("400 days: %v", err)
	}
	nobody := f.user("nina@example.com")
	if _, err := f.svc.ComplianceTrend(ctx, nobody, uuid.Nil, 0); !isKind(err, apperr.KindForbidden) {
		t.Fatalf("no role: %v", err)
	}
	f.engine.Set(func() { f.engine.Down = true })
	if _, err := f.svc.ComplianceTrend(ctx, f.admin, uuid.Nil, 0); !isCode(err, "patching_unavailable") {
		t.Fatalf("engine down: %v", err)
	}
}

// The installations report lists what jobs finished with on the devices the
// caller sees, newest first; endpoints with no device are left out.
func TestInstallations(t *testing.T) {
	f := newFleetFixture(t)
	ctx := f.ctx
	now := time.Now().UTC()
	webJob := f.engine.AddInstallation(f.eWeb, eptest.InstallationInfo{Title: "2026-11 Cumulative Update", KB: "KB5070001", Category: "Cumulative",
		RebootRequired: true, CompletedAt: now.Add(-2 * time.Hour)})
	f.engine.AddInstallation(f.eDB, eptest.InstallationInfo{Title: "openssl", Status: "Failed", ErrorCode: "0x80240022",
		ErrorMessage: "The download failed.", CompletedAt: now.Add(-time.Hour)})
	f.engine.AddInstallation(f.eDB, eptest.InstallationInfo{Title: "tzdata", Status: "Skipped", SkipReason: "Held", CompletedAt: now.Add(-3 * time.Hour)})
	f.engine.AddInstallation(f.eDB, eptest.InstallationInfo{Title: "old", CompletedAt: now.AddDate(0, 0, -40)})
	f.engine.AddInstallation(f.eStray, eptest.InstallationInfo{Title: "stray", CompletedAt: now.Add(-time.Hour)})

	list, err := f.svc.Installations(ctx, f.admin, InstallationQuery{})
	if err != nil || len(list.Items) != 3 || list.Truncated {
		t.Fatalf("all: %+v, %v", list, err)
	}
	if i := list.Items[0]; i.DeviceID != f.dbHost || i.Title != "openssl" || i.Result != "Failed" ||
		i.Detail != "The download failed. (0x80240022)" || i.SiteName != "Branch" {
		t.Fatalf("newest: %+v", i)
	}
	if i := list.Items[1]; i.DeviceName != "WEB-01" || i.KB != "KB5070001" || !i.RebootRequired || i.JobID != webJob || i.OrganizationName != "Acme" {
		t.Fatalf("WEB-01: %+v", i)
	}
	if i := list.Items[2]; i.Detail != "Held" {
		t.Fatalf("skipped: %+v", i)
	}
	if list, err := f.svc.Installations(ctx, f.admin, InstallationQuery{Days: 60}); err != nil || len(list.Items) != 4 {
		t.Fatalf("60 days: %+v, %v", list, err)
	}
	if list, err := f.svc.Installations(ctx, f.admin, InstallationQuery{SiteID: f.branch, Result: "Failed"}); err != nil || len(list.Items) != 1 {
		t.Fatalf("Branch's failures: %+v, %v", list, err)
	}
	if list, err := f.svc.Installations(ctx, f.admin, InstallationQuery{Category: "Cumulative"}); err != nil || len(list.Items) != 1 {
		t.Fatalf("cumulative: %+v, %v", list, err)
	}
	if list, err := f.svc.Installations(ctx, f.siteTech, InstallationQuery{}); err != nil || len(list.Items) != 1 || list.Items[0].DeviceID != f.web {
		t.Fatalf("HQ's technician: %+v, %v", list, err)
	}
	for name, q := range map[string]InstallationQuery{"days": {Days: 400}, "category": {Category: "Firmware"}, "result": {Result: "Done"}} {
		if _, err := f.svc.Installations(ctx, f.admin, q); !isKind(err, apperr.KindInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := f.svc.Installations(ctx, f.user("nina@example.com"), InstallationQuery{}); !isKind(err, apperr.KindForbidden) {
		t.Fatalf("no role: %v", err)
	}
}

// EasyRMM's reports read patching through the service, and keep to each row's
// site.
func TestPatchReports(t *testing.T) {
	f := newFleetFixture(t)
	ctx := f.ctx
	f.exec(`UPDATE devices SET platform = 'windows' WHERE id = $1`, f.web)
	f.device(f.acme, f.hq, "NEW-01")
	f.engine.Set(func() { f.eWeb.Compliance, f.eDB.Compliance, f.eDB.Missing = "Compliant", "MissingUpdates", 2 })
	f.engine.AddInstallation(f.eWeb, eptest.InstallationInfo{Title: "Defender update", Category: "Definition", CompletedAt: time.Now().Add(-time.Hour)})
	f.engine.AddInstallation(f.eDB, eptest.InstallationInfo{Title: "openssl", Status: "Failed", CompletedAt: time.Now().Add(-time.Hour)})
	svc := reports.New(f.db, audit.New(f.db, nil))
	if _, err := svc.Run(ctx, f.admin, "patch-compliance", reports.Query{}, reports.PreviewRows); !isKind(err, apperr.KindNotFound) {
		t.Fatalf("without patching: %v", err)
	}
	svc.UsePatching(f.svc)

	rep, err := svc.Run(ctx, f.admin, "patch-compliance", reports.Query{}, reports.PreviewRows)
	if err != nil || rep.Total != 4 {
		t.Fatalf("compliance: %+v, %v", rep, err)
	}
	rows := map[string][]any{}
	for _, r := range rep.Rows {
		rows[r[2].(string)] = r
	}
	if r := rows["WEB-01"]; r[3] != "Windows" || r[4] != "Up to date" || r[11] != "Windows Server 2025 Standard" || r[12] != "26100.2314" ||
		r[13] != "Supported" {
		t.Fatalf("WEB-01: %v", r)
	}
	if r := rows["DB-01"]; r[4] != "Updates missing" || r[6] != 1 || r[7] != 2 || r[13] != "" {
		t.Fatalf("DB-01: %v", r)
	}
	if r := rows["NEW-01"]; r[4] != "Not patched" || r[5] != "EasyPatch's agent is not on the device." || r[6] != nil {
		t.Fatalf("NEW-01: %v", r)
	}
	if rep, err := svc.Run(ctx, f.siteTech, "patch-compliance", reports.Query{}, reports.PreviewRows); err != nil || rep.Total != 2 {
		t.Fatalf("HQ's technician: %+v, %v", rep, err)
	}
	if rep, err := svc.Run(ctx, f.admin, "patch-compliance", reports.Query{Platform: "windows"}, reports.PreviewRows); err != nil || rep.Total != 1 {
		t.Fatalf("Windows: %+v, %v", rep, err)
	}
	if rep, err := svc.Run(ctx, f.admin, "patch-compliance", reports.Query{Compliance: LinkUnlinked}, reports.PreviewRows); err != nil ||
		rep.Total != 1 || rep.Rows[0][2] != "NEW-01" {
		t.Fatalf("not patched: %+v, %v", rep, err)
	}
	if _, err := svc.Run(ctx, f.admin, "patch-compliance", reports.Query{Compliance: "Sideways"}, reports.PreviewRows); !isKind(err, apperr.KindInvalid) {
		t.Fatalf("unknown status: %v", err)
	}

	rep, err = svc.Export(ctx, f.tech, "patch-installations", reports.Query{Result: "Failed"})
	if err != nil || rep.Total != 1 || rep.Rows[0][3] != "DB-01" || rep.Rows[0][7] != "Failed" {
		t.Fatalf("Acme's failures: %+v, %v", rep, err)
	}
	if a := f.audits("report.export"); len(a) != 1 || a[0].Details["report"] != "patch-installations" || a[0].Details["result"] != "Failed" ||
		a[0].Details["days"] != float64(30) {
		t.Fatalf("export audit: %+v", a)
	}
	if rep, err := svc.Run(ctx, f.admin, "patch-installations", reports.Query{Search: "defender"}, reports.PreviewRows); err != nil ||
		rep.Total != 1 || rep.Rows[0][6] != "Definition" || rep.Rows[0][7] != "Installed" {
		t.Fatalf("search: %+v, %v", rep, err)
	}

	// An organization EasyPatch cannot be read for fails the report.
	f.engine.Set(func() { f.engine.Down = true })
	f.svc.fleet.clear()
	if _, err := svc.Run(ctx, f.admin, "patch-compliance", reports.Query{}, reports.PreviewRows); !isCode(err, "easypatch_unavailable") {
		t.Fatalf("engine down: %v", err)
	}
}

// Monthly reports: made by those who manage patching of the whole
// organization, read by those who see it, emailed through EasyRMM's mail
// server.
func TestMonthlyReports(t *testing.T) {
	f := newFleetFixture(t)
	ctx := f.ctx
	last := time.Now().UTC().AddDate(0, -1, 0)

	if _, err := f.svc.GenerateMonthlyReport(ctx, f.reader, f.acme, last.Year(), int(last.Month()), true); !isKind(err, apperr.KindForbidden) {
		t.Fatalf("a reader generates: %v", err)
	}
	if _, err := f.svc.GenerateMonthlyReport(ctx, f.siteTech, f.acme, last.Year(), int(last.Month()), true); !isKind(err, apperr.KindForbidden) {
		t.Fatalf("a site's technician generates: %v", err)
	}
	for name, ym := range map[string][2]int{"month 13": {last.Year(), 13}, "next year": {last.Year() + 2, 1}, "too old": {last.Year() - 11, 1}} {
		if _, err := f.svc.GenerateMonthlyReport(ctx, f.tech, f.acme, ym[0], ym[1], true); !isKind(err, apperr.KindInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	rep, err := f.svc.GenerateMonthlyReport(ctx, f.tech, f.acme, last.Year(), int(last.Month()), false)
	if err != nil || rep.OrganizationID != f.acme || rep.OrganizationName != "Acme" || rep.MonthToDate || rep.PeriodStart != last.Format("2006-01")+"-01" {
		t.Fatalf("generate: %+v, %v", rep, err)
	}
	if st := f.lastStatement("POST", "/api/v1/monthly-reports"); st.Role != RoleAdmin || !slices.Equal(st.Organizations, []uuid.UUID{f.epAcme}) {
		t.Fatalf("generate statement: %+v", st)
	}
	if r := f.engine.MonthlyReports(); len(r) != 1 || r[0].IncludeEndpointList {
		t.Fatalf("engine: %+v", r)
	}
	if a := f.audits("patch.report_generate"); len(a) != 1 || a[0].Details["period"] != last.Format("2006-01") || a[0].Details["includeEndpointList"] != false {
		t.Fatalf("generate audit: %+v", a)
	}
	now := time.Now().UTC()
	glob, err := f.svc.GenerateMonthlyReport(ctx, f.admin, f.globex, now.Year(), int(now.Month()), true)
	if err != nil || !glob.MonthToDate {
		t.Fatalf("Globex so far: %+v, %v", glob, err)
	}

	list, err := f.svc.MonthlyReports(ctx, f.admin, uuid.Nil)
	if err != nil || len(list.Items) != 2 || list.Items[0].ID != glob.ID || !list.Items[0].CanManage || len(list.CanGenerate) != 2 || list.Capped {
		t.Fatalf("admin's list: %+v, %v", list, err)
	}
	list, err = f.svc.MonthlyReports(ctx, f.reader, uuid.Nil)
	if err != nil || len(list.Items) != 1 || list.Items[0].ID != rep.ID || list.Items[0].CanManage || len(list.CanGenerate) != 0 {
		t.Fatalf("reader's list: %+v, %v", list, err)
	}
	if list, err := f.svc.MonthlyReports(ctx, f.siteTech, uuid.Nil); err != nil || len(list.Items) != 0 {
		t.Fatalf("a site's technician's list: %+v, %v", list, err)
	}

	// The PDF, for anyone who sees the organization's patching whole.
	m, pdf, err := f.svc.MonthlyReportPDF(ctx, f.reader, rep.ID)
	if err != nil || !bytes.HasPrefix(pdf, []byte("%PDF-")) || m.ID != rep.ID {
		t.Fatalf("PDF: %q, %v", pdf, err)
	}
	if a := f.audits("patch.report_download"); len(a) != 1 || a[0].Details["file"] != m.FileName {
		t.Fatalf("download audit: %+v", a)
	}
	if _, _, err := f.svc.MonthlyReportPDF(ctx, f.reader, glob.ID); !isKind(err, apperr.KindNotFound) {
		t.Fatalf("Globex's report for Acme's reader: %v", err)
	}
	if _, _, err := f.svc.MonthlyReportPDF(ctx, f.siteTech, rep.ID); !isKind(err, apperr.KindNotFound) {
		t.Fatalf("for a site's technician: %v", err)
	}
	if _, _, err := f.svc.MonthlyReportPDF(ctx, f.admin, uuid.New()); !isKind(err, apperr.KindNotFound) {
		t.Fatalf("no such report: %v", err)
	}

	// Emailing it: EasyRMM has no mail server yet.
	if _, err := f.svc.SendMonthlyReport(ctx, f.tech, rep.ID, []string{"cfo@example.com"}); !isCode(err, "mail_not_configured") ||
		!strings.Contains(err.Error(), "EASYRMM_SMTP_HOST") {
		t.Fatalf("no mail server: %v", err)
	}
	if _, err := f.svc.SendMonthlyReport(ctx, f.reader, rep.ID, []string{"cfo@example.com"}); !isKind(err, apperr.KindForbidden) {
		t.Fatalf("a reader sends: %v", err)
	}
	for name, to := range map[string][]string{"not an address": {"cfo"}, "a name": {"CFO <cfo@example.com>"}, "too many": manyAddresses(21)} {
		if _, err := f.svc.SendMonthlyReport(ctx, f.tech, rep.ID, to); !isKind(err, apperr.KindInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}

	// EasyRMM's mail server reaches the engine on the next pass, once.
	f.svc = f.engineService(f.engine, Mail(MailConfig{Host: "smtp.example.com", Port: 465, Username: "mailer", Password: "pw",
		From: "Acme IT <it@example.com>", TLS: "implicit"}))
	f.reconcile()
	f.reconcile()
	if n := len(f.engine.RequestsTo("PUT", "/api/v1/notifications/settings")); n != 1 {
		t.Fatalf("%d mail settings pushes", n)
	}
	mail := f.engine.Mail()
	if mail["smtpHost"] != "smtp.example.com" || mail["smtpPort"] != float64(465) || mail["smtpSecurity"] != "SslOnConnect" ||
		mail["smtpUsername"] != "mailer" || mail["smtpPassword"] != "pw" || mail["fromAddress"] != "it@example.com" || mail["fromName"] != "Acme IT" {
		t.Fatalf("engine's mail settings: %v", mail)
	}
	if st := f.lastStatement("PUT", "/api/v1/notifications/settings"); st.Role != RoleSuperAdmin || st.Subject != ServiceSubject {
		t.Fatalf("mail statement: %+v", st)
	}
	if _, err := f.svc.SendMonthlyReport(ctx, f.tech, rep.ID, nil); !isKind(err, apperr.KindInvalid) {
		t.Fatalf("no recipients, no schedule: %v", err)
	}
	sent, err := f.svc.SendMonthlyReport(ctx, f.tech, rep.ID, []string{" cfo@example.com ", "CFO@example.com", "ops@example.com"})
	if err != nil || sent.DeliveryStatus != "Pending" || !slices.Equal(sent.Recipients, []string{"cfo@example.com", "ops@example.com"}) {
		t.Fatalf("send: %+v, %v", sent, err)
	}
	if a := f.audits("patch.report_send"); len(a) != 1 || a[0].Details["recipients"] != float64(2) {
		t.Fatalf("send audit: %+v", a)
	}

	// A mail server without encryption is refused for reports.
	f.svc = f.engineService(f.engine, Mail(MailConfig{Host: "relay.example.com", From: "it@example.com", TLS: "none"}))
	f.reconcile()
	if _, err := f.svc.SendMonthlyReport(ctx, f.tech, rep.ID, []string{"cfo@example.com"}); !isCode(err, "mail_not_encrypted") {
		t.Fatalf("plain mail server: %v", err)
	}
	if m := f.engine.Mail(); m["smtpPort"] != float64(587) || m["smtpSecurity"] != "None" || m["fromName"] != "EasyRMM" {
		t.Fatalf("plain mail settings: %v", m)
	}
	// No mail server at all removes the engine's.
	f.svc = f.engineService(f.engine, Mail(MailConfig{}))
	f.reconcile()
	if m := f.engine.Mail(); m["smtpHost"] != nil || m["smtpPassword"] != "" {
		t.Fatalf("mail server removed: %v", m)
	}

	// Deleting.
	if err := f.svc.DeleteMonthlyReport(ctx, f.reader, rep.ID); !isKind(err, apperr.KindForbidden) {
		t.Fatalf("a reader deletes: %v", err)
	}
	if err := f.svc.DeleteMonthlyReport(ctx, f.tech, rep.ID); err != nil {
		t.Fatal(err)
	}
	if a := f.audits("patch.report_delete"); len(a) != 1 {
		t.Fatalf("delete audit: %+v", a)
	}
	if err := f.svc.DeleteMonthlyReport(ctx, f.tech, rep.ID); !isKind(err, apperr.KindNotFound) {
		t.Fatalf("deleted twice: %v", err)
	}
}

func manyAddresses(n int) []string {
	var out []string
	for i := range n {
		out = append(out, "user"+string(rune('a'+i))+"@example.com")
	}
	return out
}

// Schedules are read by those who see an organization's patching whole and
// changed by those who configure it.
func TestReportSchedules(t *testing.T) {
	f := newFleetFixture(t)
	ctx := f.ctx

	list, err := f.svc.ReportSchedules(ctx, f.admin)
	if err != nil || len(list) != 2 || list[0].OrganizationName != "Acme" || !list[0].CanEdit || list[0].Enabled || list[0].DayOfMonth != 1 ||
		list[0].Recipients == nil {
		t.Fatalf("admin: %+v, %v", list, err)
	}
	if list, err := f.svc.ReportSchedules(ctx, f.tech); err != nil || len(list) != 1 || list[0].CanEdit {
		t.Fatalf("Acme's technician: %+v, %v", list, err)
	}
	in := ReportScheduleInput{Enabled: true, Recipients: []string{" cfo@example.com", "CFO@example.com "}, DayOfMonth: 5, IncludeEndpointList: true}
	if _, err := f.svc.SetReportSchedule(ctx, f.tech, f.acme, in); !isKind(err, apperr.KindForbidden) {
		t.Fatalf("a technician schedules: %v", err)
	}
	for name, bad := range map[string]ReportScheduleInput{
		"day 29":        {DayOfMonth: 29},
		"no recipients": {Enabled: true, DayOfMonth: 5},
		"bad address":   {DayOfMonth: 5, Recipients: []string{"cfo@"}},
	} {
		if _, err := f.svc.SetReportSchedule(ctx, f.orgAdmin, f.acme, bad); !isKind(err, apperr.KindInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	s, err := f.svc.SetReportSchedule(ctx, f.orgAdmin, f.acme, in)
	if err != nil || !s.Enabled || s.DayOfMonth != 5 || !slices.Equal(s.Recipients, []string{"cfo@example.com"}) || s.NextReportDate == nil || !s.CanEdit {
		t.Fatalf("schedule: %+v, %v", s, err)
	}
	if sc := f.engine.Schedule(f.epAcme); sc == nil || sc.DayOfMonth != 5 || !sc.IncludeEndpointList {
		t.Fatalf("engine: %+v", sc)
	}
	if st := f.lastStatement("PUT", "/api/v1/organizations/"+f.epAcme.String()+"/report-schedule"); st.Role != RoleAdmin {
		t.Fatalf("statement: %+v", st)
	}
	if a := f.audits("patch.report_schedule"); len(a) != 1 || a[0].Details["dayOfMonth"] != float64(5) || a[0].Details["recipients"] != float64(1) {
		t.Fatalf("audit: %+v", a)
	}
	if _, err := f.svc.SetReportSchedule(ctx, f.admin, uuid.New(), in); !isCode(err, "easypatch_not_linked") {
		t.Fatalf("an organization that is not linked: %v", err)
	}
}
