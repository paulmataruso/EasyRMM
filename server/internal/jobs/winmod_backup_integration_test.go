//go:build integration

package jobs

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/paulmataruso/easyrmm/server/internal/access"
	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/modules"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
	"github.com/paulmataruso/easyrmm/server/internal/secrets"
	"github.com/paulmataruso/easyrmm/server/internal/winmod"
	"github.com/paulmataruso/easyrmm/server/internal/winmod/backup"
)

// ADR-0077 through the real winmod path: the permission matrix of the
// tiers, the confirmation and step-up of tier 3, and the share password as a
// sealed secret that no stored row holds.

func backupFixture(t *testing.T) *fixture {
	t.Helper()
	f := newFixture(t)
	cat, err := winmod.NewCatalog(backup.Actions()...)
	if err != nil {
		t.Fatal(err)
	}
	raw := make([]byte, 32)
	_, _ = rand.Read(raw)
	sealer, err := secrets.NewSealer(secrets.Key{ID: "k1", Raw: raw})
	if err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	f.svc.SetWinmod(cat, modules.New(f.db, audit.New(f.db, time.Now), log), sealer)
	return f
}

func TestBackupTiersPermissionsConfirmationAndStepUp(t *testing.T) {
	f := backupFixture(t)
	tech := f.user("tech@example.com", rbac.Assignment{Role: rbac.RoleTechnician, OrganizationID: f.acme, SiteID: f.hq})
	ro := f.user("ro@example.com", rbac.Assignment{Role: rbac.RoleReadOnly, OrganizationID: f.acme, SiteID: f.hq})
	siteAdmin := f.user("sa@example.com", rbac.Assignment{Role: rbac.RoleSiteAdmin, OrganizationID: f.acme, SiteID: f.hq})
	dev := f.winmodDevice("HQ-SRV", "windows")
	run := func(caller access.Caller, action, params, confirm string) error {
		_, err := f.svc.RunWinmod(f.ctx, caller, WinmodInput{DeviceID: dev, Action: "windows_backup." + action, Params: json.RawMessage(params), Confirm: confirm})
		return err
	}
	f.svc.SetStepUp(stepUpStub{})

	// Tier 0 and 1: a technician reads and runs a backup; read-only does neither.
	if err := run(tech, "status", `{}`, ""); err != nil {
		t.Errorf("technician reads: %v", err)
	}
	if err := run(tech, "run_now", `{}`, ""); err != nil {
		t.Errorf("technician runs a backup: %v", err)
	}
	if err := run(ro, "status", `{}`, ""); err == nil {
		t.Error("read-only read the backup state")
	}
	// The target paths need backup.view_sensitive, which a technician lacks:
	// the result is refused at read time (framework rule); the run itself is
	// a read and starts.

	// Tier 2 is confirmed: "<action>:<device name>".
	params := `{"device":"HQ-SRV","volume":"E:"}`
	for _, confirm := range []string{"", "windows_backup.target_volume_set", "windows_backup.target_volume_set:OTHER"} {
		fieldErr(t, run(tech, "target_volume_set", params, confirm), "confirm", "windows_backup.target_volume_set:HQ-SRV")
	}
	if err := run(tech, "target_volume_set", params, "windows_backup.target_volume_set:HQ-SRV"); err != nil {
		t.Errorf("a confirmed tier 2 action: %v", err)
	}
	fieldErr(t, run(tech, "target_volume_set", `{"device":"HQ-SRV","volume":"E:\\x"}`, ""), "params.volume", "")

	// Tier 3 needs backup.destroy: a technician is refused, a site
	// administrator needs the confirmation and a fresh step-up.
	destroy := `{"device":"HQ-SRV"}`
	if err := run(tech, "policy_remove", destroy, "windows_backup.policy_remove:HQ-SRV"); err == nil {
		t.Error("a technician removed the backup policy")
	}
	fieldErr(t, run(siteAdmin, "policy_remove", destroy, ""), "confirm", "windows_backup.policy_remove:HQ-SRV")
	tooOld := errors.New("step up required")
	f.svc.SetStepUp(stepUpStub{err: tooOld})
	before := f.count(`SELECT count(*) FROM audit_log WHERE action = 'winmod.windows_backup.policy_remove'`)
	if err := run(siteAdmin, "policy_remove", destroy, "windows_backup.policy_remove:HQ-SRV"); !errors.Is(err, tooOld) {
		t.Errorf("tier 3 without a step-up: %v", err)
	}
	if f.count(`SELECT count(*) FROM audit_log WHERE action = 'winmod.windows_backup.policy_remove'`) != before {
		t.Error("a refused tier 3 action left a job")
	}
	f.svc.SetStepUp(stepUpStub{})
	if err := run(siteAdmin, "policy_remove", destroy, "windows_backup.policy_remove:HQ-SRV"); err != nil {
		t.Errorf("a tier 3 action with step-up: %v", err)
	}
	got := f.str(`SELECT details::text FROM audit_log WHERE action = 'winmod.windows_backup.policy_remove'`)
	if !strings.Contains(got, `"destructive": true`) || !strings.Contains(got, `"stepUp": true`) {
		t.Errorf("audit %s", got)
	}
	// A bad parameter is refused before anything else.
	if e, ok := apperr.As(run(siteAdmin, "versions_prune", `{"device":"HQ-SRV","keep":0,"expect":1}`, "")); !ok || e.Code == "" {
		t.Error("keep 0 was not refused")
	}
}

const sharePassword = "Sh@reP4ss-marker-9"

func TestBackupSharePasswordIsASealedSecret(t *testing.T) {
	f := backupFixture(t)
	f.svc.SetStepUp(stepUpStub{})
	tech := f.user("tech@example.com", rbac.Assignment{Role: rbac.RoleTechnician, OrganizationID: f.acme, SiteID: f.hq})
	dev := f.winmodDevice("HQ-SRV", "windows")
	in := WinmodInput{DeviceID: dev, Action: "windows_backup.target_network_set",
		Params:  json.RawMessage(`{"device":"HQ-SRV","unc":"\\\\nas.example.net\\backups\\hq-srv","user":"EXAMPLE\\svc-backup","password":"` + sharePassword + `"}`),
		Confirm: "windows_backup.target_network_set:HQ-SRV"}
	run, err := f.svc.RunWinmod(f.ctx, tech, in)
	if err != nil {
		t.Fatal(err)
	}
	if n := f.count(`SELECT count(*) FROM winmod_job_secrets WHERE job_id = $1 AND sealed NOT LIKE '%' || $2 || '%'`, run.JobID, sharePassword); n != 1 {
		t.Errorf("%d sealed secret rows", n)
	}
	for _, q := range []string{
		`SELECT params::text FROM jobs WHERE id = $1`, `SELECT winmod::text FROM jobs WHERE id = $1`,
		`SELECT body FROM jobs WHERE id = $1`, `SELECT string_agg(details::text, ' ') FROM audit_log WHERE details->>'jobId' = $1::text`,
	} {
		if got := f.str(q, run.JobID); strings.Contains(got, sharePassword) || got == "" {
			t.Errorf("%s holds the password or nothing: %q", q, got)
		}
	}
	audit := f.str(`SELECT details::text FROM audit_log WHERE action = 'winmod.windows_backup.target_network_set'`)
	if !strings.Contains(audit, "(secret)") || strings.Contains(audit, "nas.example.net") || strings.Contains(audit, "svc-backup") {
		t.Errorf("audit holds the share, the account or no secret marker: %s", audit)
	}
}
