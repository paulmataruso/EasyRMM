//go:build integration

package jobs

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/paulmataruso/easyrmm/server/internal/access"
	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/modules"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
	"github.com/paulmataruso/easyrmm/server/internal/secrets"
	"github.com/paulmataruso/easyrmm/server/internal/winmod"
	"github.com/paulmataruso/easyrmm/server/internal/winmod/roles"
)

// The certificate authority, file-sharing and print actions through the real
// winmod path: the permission matrix, the protected-share refusals before any
// job exists, confirmation by the computer's name, and the step-up.
func TestWinmodCAFilesPrint(t *testing.T) {
	f := newFixture(t)
	cat, err := winmod.NewCatalog(roles.Actions()...)
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
	f.svc.SetStepUp(stepUpStub{})

	as := func(email string, role rbac.Role) access.Caller {
		return f.user(email, rbac.Assignment{Role: role, OrganizationID: f.acme, SiteID: f.hq})
	}
	tech, siteAdmin, ro := as("t@example.com", rbac.RoleTechnician), as("s@example.com", rbac.RoleSiteAdmin), as("r@example.com", rbac.RoleReadOnly)
	orgAdmin := f.user("o@example.com", rbac.Assignment{Role: rbac.RoleOrgAdmin, OrganizationID: f.acme})
	dev := f.winmodDevice("HQ-FS", "windows")
	jobs := func() int { return f.count(`SELECT count(*) FROM jobs`) }
	run := func(c access.Caller, action, params, confirm string) error {
		_, err := f.svc.RunWinmod(f.ctx, c, WinmodInput{DeviceID: dev, Action: action, Params: json.RawMessage(params), Confirm: confirm})
		return err
	}
	code := func(err error) string {
		if e, ok := apperr.As(err); ok {
			return e.Code
		}
		return ""
	}

	// Protected shares and unsafe requests are refused before a job exists, in every spelling.
	for _, n := range []string{"SYSVOL", "sysvol", "NETLOGON", "print$", "IPC$", "ADMIN$", "C$", "x$"} {
		if got := code(run(siteAdmin, "file_shares.share_remove", `{"device":"HQ-FS","name":"`+n+`"}`, "file_shares.share_remove:HQ-FS")); got != "protected_share" {
			t.Errorf("remove %s: %q", n, got)
		}
		if got := code(run(siteAdmin, "file_shares.share_grant", `{"device":"HQ-FS","name":"`+n+`","account":"Alice","right":"Read"}`, "file_shares.share_grant:HQ-FS")); got != "protected_share" {
			t.Errorf("grant on %s: %q", n, got)
		}
	}
	if got := code(run(siteAdmin, "file_shares.share_grant", `{"device":"HQ-FS","name":"Data","account":"Everyone","right":"Full"}`, "file_shares.share_grant:HQ-FS")); got != "weakens_access" {
		t.Errorf("Everyone full: %q", got)
	}
	if got := code(run(siteAdmin, "file_shares.share_create", `{"device":"HQ-FS","name":"Root","path":"C:\\"}`, "file_shares.share_create:HQ-FS")); got != "protected_path" {
		t.Errorf("a drive root: %q", got)
	}
	if jobs() != 0 {
		t.Fatalf("%d jobs were created by refused requests", jobs())
	}

	// Permissions: a Technician reads print and manages jobs, nothing of CA or shares; tier 3 print is for Site Administrators.
	fieldErr(t, run(tech, "file_shares.share_list", ``, ""), "deviceIds", "cannot")
	fieldErr(t, run(tech, "certificate_authority.status", ``, ""), "deviceIds", "cannot")
	fieldErr(t, run(ro, "print.printer_list", ``, ""), "deviceIds", "cannot")
	if err := run(tech, "print.printer_list", ``, ""); err != nil {
		t.Errorf("a Technician reads printers: %v", err)
	}
	if err := run(tech, "print.job_cancel", `{"printer":"Front desk","ids":"4,5"}`, ""); err != nil {
		t.Errorf("a Technician cancels jobs: %v", err)
	}
	fieldErr(t, run(tech, "print.job_list_sensitive", `{"printer":"Front desk"}`, ""), "deviceIds", "cannot")
	fieldErr(t, run(tech, "print.queue_clear", `{"device":"HQ-FS","printer":"Front desk"}`, "print.queue_clear:HQ-FS"), "deviceIds", "cannot")
	if err := run(siteAdmin, "file_shares.share_list", ``, ""); err != nil {
		t.Errorf("a Site Administrator reads shares: %v", err)
	}
	fieldErr(t, run(siteAdmin, "certificate_authority.request_approve", `{"device":"HQ-FS","id":3}`, "certificate_authority.request_approve:HQ-FS"), "deviceIds", "cannot")

	// Tier 3 needs the confirmation naming the computer, and a step-up inside five minutes.
	before := jobs()
	fieldErr(t, run(orgAdmin, "certificate_authority.request_approve", `{"device":"HQ-FS","id":3}`, ""), "confirm", "certificate_authority.request_approve:HQ-FS")
	fieldErr(t, run(orgAdmin, "certificate_authority.request_approve", `{"device":"HQ-FS","id":3}`, "certificate_authority.request_approve:OTHER"), "confirm", "certificate_authority.request_approve:HQ-FS")
	f.svc.SetStepUp(stepUpStub{err: errors.New("step up required")})
	for _, c := range []struct {
		who            access.Caller
		action, params string
	}{
		{orgAdmin, "certificate_authority.certificate_revoke", `{"device":"HQ-FS","serial":"6100aa","reason":"key_compromise"}`},
		{siteAdmin, "file_shares.share_remove", `{"device":"HQ-FS","name":"Data"}`},
		{siteAdmin, "print.spooler_restart", `{"device":"HQ-FS"}`},
	} {
		if err := run(c.who, c.action, c.params, c.action+":HQ-FS"); err == nil {
			t.Errorf("%s ran without a step-up", c.action)
		}
	}
	if jobs() != before {
		t.Error("a refused tier 3 action left a job")
	}
	f.svc.SetStepUp(stepUpStub{})
	if err := run(orgAdmin, "certificate_authority.request_approve", `{"device":"hq-fs","id":3}`, "certificate_authority.request_approve:hq-fs"); err != nil {
		t.Errorf("approve with the step-up (the name matched ignoring case): %v", err)
	}
	if err := run(siteAdmin, "file_shares.share_remove", `{"device":"HQ-FS","name":"Data"}`, "file_shares.share_remove:HQ-FS"); err != nil {
		t.Errorf("remove a share: %v", err)
	}
	// Tier 2 needs the confirmation, no step-up.
	f.svc.SetStepUp(nil)
	if err := run(siteAdmin, "file_shares.share_set", `{"device":"HQ-FS","name":"Data","description":"x"}`, "file_shares.share_set:HQ-FS"); err != nil {
		t.Errorf("a tier 2 change: %v", err)
	}
	fieldErr(t, run(siteAdmin, "file_shares.share_set", `{"device":"HQ-FS","name":"Data","description":"x"}`, ""), "confirm", "file_shares.share_set:HQ-FS")
}
