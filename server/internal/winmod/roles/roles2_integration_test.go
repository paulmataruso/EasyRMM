//go:build integration

package roles_test

import (
	"testing"
	"time"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/server/internal/winmod/certauth"
	"github.com/paulmataruso/easyrmm/server/internal/winmod/printsrv"
)

// The certificate authority, file-sharing and print alerts from snapshots,
// through the real evaluator and module gate, on real PostgreSQL.

func TestCAFilesPrintDefaultPolicies(t *testing.T) {
	f := newFx(t)
	f.server("ca1", agentproto.RoleADCS, agentproto.RoleFileServer, agentproto.RolePrintServer)
	f.evaluate()
	f.evaluate()
	for module, want := range map[string]int{"certificate_authority": 5, "file_shares": 1, "print": 3} {
		if n := f.num(`SELECT count(*)::text FROM alert_policies WHERE organization_id = $1 AND module = $2`, f.acme, module); n != want {
			t.Errorf("%s: %d default policies, want %d", module, n, want)
		}
	}
	// On: the four CA kinds ADR-0076 lists as on, and two print kinds. Off: findings, file service, print service.
	if n := f.num(`SELECT count(*)::text FROM alert_policies WHERE organization_id = $1 AND module IN ('certificate_authority','file_shares','print') AND enabled`, f.acme); n != 6 {
		t.Errorf("%d defaults start on, want 6", n)
	}
	if got := f.str(`SELECT severity || ' ' || threshold::text FROM alert_policies WHERE default_key = 'expiring_14'`); got != "critical 14" {
		t.Errorf("expiring_14: %s", got)
	}
}

func TestCAAlertsFromSnapshots(t *testing.T) {
	f := newFx(t)
	dev := f.server("ca1", agentproto.RoleADCS)
	f.evaluate()
	status := func(days, crlHours int, state string) certauth.Status {
		return certauth.Status{
			CAName: "Corp CA", CAType: "enterprise_root", Enterprise: true, ServiceState: state,
			Certificate: &certauth.CertSummary{Subject: "CN=Corp CA", Thumbprint: "AB", NotAfter: time.Now().AddDate(0, 0, days), DaysLeft: days},
			CRL:         &certauth.CRLSummary{HoursToBaseExpiry: ptr(crlHours)},
		}
	}
	f.snapshot(dev, "certificate_authority", "certificate_authority.status", 1, status(60, 100, "running"))
	f.evaluate()
	if got := f.open(dev); got != "Certificate authority: CA certificate expires within 90 days" {
		t.Fatalf("open alerts %q", got)
	}
	// Within 14 days the critical alert opens as well; the warning stays until it clears.
	f.snapshot(dev, "certificate_authority", "certificate_authority.status", 0, status(10, 100, "running"))
	f.evaluate()
	if got := f.open(dev); got != "Certificate authority: CA certificate expires within 14 days | Certificate authority: CA certificate expires within 90 days" {
		t.Errorf("open alerts %q", got)
	}
	// A revocation list within four hours of lapsing.
	f.snapshot(dev, "certificate_authority", "certificate_authority.status", 0, status(1000, 3, "running"))
	f.evaluate()
	if got := f.open(dev); got != "Certificate authority: CRL about to lapse" {
		t.Errorf("open alerts %q", got)
	}
	// No alert names the CA's subject.
	if n := f.num(`SELECT count(*)::text FROM alerts WHERE detail LIKE '%CN=%'`); n != 0 {
		t.Errorf("%d alerts name a subject", n)
	}
	f.snapshot(dev, "certificate_authority", "certificate_authority.status", 0, status(1000, 100, "running"))
	f.evaluate()
	if got := f.open(dev); got != "" {
		t.Errorf("still open: %q", got)
	}
}

func TestPrintAlertsFromSnapshots(t *testing.T) {
	f := newFx(t)
	dev := f.server("print1", agentproto.RolePrintServer)
	f.evaluate()
	weak := printsrv.Hardening{RestrictDriverInstall: ptr(int64(0)), Weakened: true, SpoolerRunning: true}
	f.snapshot(dev, "print", "print.hardening_status", 1, weak)
	f.evaluate()
	if got := f.open(dev); got != "Print: Point and Print weakened" {
		t.Fatalf("open alerts %q", got)
	}
	// A queue stuck waits its hour; a paused printer is never stuck.
	old := int64(120)
	printers := func(paused bool) printsrv.Printers {
		return printsrv.Printers{Printers: []printsrv.Printer{{Name: "Front desk", JobCount: 2, Paused: paused, OldestJobAgeMinutes: &old}}}
	}
	f.snapshot(dev, "print", "print.printer_list", 1, printers(true))
	f.evaluate()
	f.exec(`UPDATE windows_module_conditions SET since = now() - interval '61 minutes'`)
	f.snapshot(dev, "print", "print.printer_list", 0, printers(true))
	f.evaluate()
	if got := f.open(dev); got != "Print: Point and Print weakened" {
		t.Errorf("a paused printer alerted: %q", got)
	}
	f.snapshot(dev, "print", "print.printer_list", 0, printers(false))
	f.evaluate()
	f.exec(`UPDATE windows_module_conditions SET since = now() - interval '61 minutes'`)
	f.snapshot(dev, "print", "print.printer_list", 0, printers(false))
	f.evaluate()
	if got := f.open(dev); got != "Print: Point and Print weakened | Print: queue stuck" {
		t.Errorf("open alerts %q", got)
	}
	// Strengthened and drained resolves both.
	f.snapshot(dev, "print", "print.hardening_status", 0, printsrv.Hardening{RestrictDriverInstall: ptr(int64(1)), SpoolerRunning: true})
	f.snapshot(dev, "print", "print.printer_list", 0, printsrv.Printers{})
	f.evaluate()
	if got := f.open(dev); got != "" {
		t.Errorf("still open: %q", got)
	}
}
