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

	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/server/internal/access"
	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/modules"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
	"github.com/paulmataruso/easyrmm/server/internal/secrets"
	"github.com/paulmataruso/easyrmm/server/internal/winmod"
	"github.com/paulmataruso/easyrmm/server/internal/winmod/activedirectory"
)

const (
	adUser     = "S-1-5-21-1004336348-1177238915-682003330-1104"
	adTyped    = "Correct-Horse-Battery-9!"
	adAdminPwd = "Domain-Admin-Marker-77"
)

func adFixture(t *testing.T) *fixture {
	t.Helper()
	f := newFixture(t)
	cat, err := winmod.NewCatalog(activedirectory.Actions()...)
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
	return f
}

// The Active Directory permission split of ADR-0075 section 6, through the
// real RunWinmod: a Technician does the help-desk work and nothing else, an
// Organization Administrator the rest, and a read-only role nothing.
func TestADPermissionSplit(t *testing.T) {
	f := adFixture(t)
	tech := f.user("tech@example.com", rbac.Assignment{Role: rbac.RoleTechnician, OrganizationID: f.acme, SiteID: f.hq})
	site := f.user("site@example.com", rbac.Assignment{Role: rbac.RoleSiteAdmin, OrganizationID: f.acme, SiteID: f.hq})
	admin := f.user("admin@example.com", rbac.Assignment{Role: rbac.RoleOrgAdmin, OrganizationID: f.acme})
	ro := f.user("ro@example.com", rbac.Assignment{Role: rbac.RoleReadOnly, OrganizationID: f.acme, SiteID: f.hq})
	dev := f.winmodDevice("DC1", "windows")
	run := func(c access.Caller, action, params, confirm string) error {
		_, err := f.svc.RunWinmod(f.ctx, c, WinmodInput{DeviceID: dev, Action: "active_directory." + action, Params: json.RawMessage(params), Confirm: confirm})
		return err
	}
	id := `{"id":"` + adUser + `"}`
	confirm := func(action string) string { return "active_directory." + action + ":" + adUser }

	// Reads: a Technician reads; Read-Only does not.
	for _, a := range []string{"status", "ou_tree", "user_list", "group_list", "health_read"} {
		if err := run(tech, a, `{}`, ""); err != nil {
			t.Errorf("a Technician reading %s: %v", a, err)
		}
		fieldErr(t, run(ro, a, `{}`, ""), "deviceIds", "cannot")
	}
	// The personal fields start at Site Administrator.
	fieldErr(t, run(tech, "user_get", id, ""), "deviceIds", "cannot")
	if err := run(site, "user_get", id, ""); err != nil {
		t.Errorf("a Site Administrator reading a user: %v", err)
	}

	// The help desk, with its confirmation and step-up.
	if err := run(tech, "user_unlock", id, ""); err != nil {
		t.Errorf("unlock: %v", err)
	}
	for _, a := range []string{"user_enable", "user_disable"} {
		fieldErr(t, run(tech, a, id, ""), "confirm", confirm(a))
		if err := run(tech, a, id, confirm(a)); err != nil {
			t.Errorf("%s: %v", a, err)
		}
	}
	if err := run(tech, "user_reset_password", id, confirm("user_reset_password")); err != nil {
		t.Errorf("reset: %v", err)
	}

	// Everything else needs Organization Administrator, even for a Site Administrator.
	manage := map[string]string{
		"user_delete": id, "user_move": `{"id":"` + adUser + `","targetOu":"OU=Staff,DC=corp,DC=test"}`,
		"user_set":    `{"id":"` + adUser + `","title":"Boss"}`,
		"group_add":   `{"id":"` + adUser + `","member":"` + adUser + `"}`,
		"user_create": `{"ou":"OU=Staff,DC=corp,DC=test","sam":"bob","name":"Bob"}`,
	}
	delete(manage, "group_add")
	for a, params := range manage {
		for _, c := range []access.Caller{tech, site} {
			err := run(c, a, params, confirm(a))
			if a == "user_create" {
				err = run(c, a, params, "active_directory.user_create:bob")
			}
			if e, ok := apperr.As(err); ok && e.Kind == apperr.KindInvalid && e.Fields["deviceIds"] == "" {
				t.Fatalf("%s: %v %+v", a, err, e.Fields)
			}
			fieldErr(t, err, "deviceIds", "cannot")
		}
	}
	if err := run(admin, "user_set", manage["user_set"], confirm("user_set")); err != nil {
		t.Errorf("an Organization Administrator editing a user: %v", err)
	}
	if err := run(admin, "user_delete", id, confirm("user_delete")); err != nil {
		t.Errorf("an Organization Administrator deleting a user: %v", err)
	}

	// A service account's second confirmation needs ad.manage; a
	// Technician cannot send it, and the account's password reset needs
	// ad.reset_password.
	svc := `{"id":"` + adUser + `","serviceConfirm":"service-account:svc_backup"}`
	if err := run(tech, "user_disable", svc, confirm("user_disable")); !errors.Is(err, apperr.Forbidden()) {
		t.Errorf("a Technician sent the service-account confirmation: %v", err)
	}
	if err := run(admin, "user_disable", svc, confirm("user_disable")); err != nil {
		t.Errorf("an Organization Administrator confirming a service account: %v", err)
	}
	fieldErr(t, run(admin, "user_disable", `{"id":"`+adUser+`","serviceConfirm":"service-account:"}`, confirm("user_disable")), "params.serviceConfirm", "form")

	// The domain's powerful accounts never reach a script (the server's table).
	for _, rid := range []string{"500", "502", "512", "518", "519"} {
		bad := `{"id":"S-1-5-21-1004336348-1177238915-682003330-` + rid + `"}`
		fieldErr(t, run(admin, "user_disable", bad, "active_directory.user_disable:S-1-5-21-1004336348-1177238915-682003330-"+rid), "params.id", "well-known")
	}
	fieldErr(t, run(admin, "user_unlock", `{"id":"S-1-5-32-544"}`, ""), "params.id", "well-known")
}

// A password: generated by the server when the request leaves it out, shown
// once in the answer, sealed at rest, in no row, delivered once to the agent.
func TestADPasswordIsGeneratedSealedAndShownOnce(t *testing.T) {
	f := adFixture(t)
	admin := f.user("admin@example.com", rbac.Assignment{Role: rbac.RoleOrgAdmin, OrganizationID: f.acme})
	dev := f.winmodDevice("DC1", "windows")
	reset := WinmodInput{DeviceID: dev, Action: "active_directory.user_reset_password", Params: json.RawMessage(`{"id":"` + adUser + `","mustChange":true}`),
		Confirm: "active_directory.user_reset_password:" + adUser}
	run, err := f.svc.RunWinmod(f.ctx, admin, reset)
	if err != nil {
		t.Fatal(err)
	}
	pw := run.Generated["password"]
	if len(pw) != 20 {
		t.Fatalf("generated %q", pw)
	}
	var echoed struct{ Generated map[string]string }
	if body, _ := json.Marshal(run); json.Unmarshal(body, &echoed) != nil || echoed.Generated["password"] != pw {
		t.Error("the answer does not carry the generated password")
	}
	assertNowhere := func(secret string, jobID any) {
		t.Helper()
		for _, q := range []string{
			`SELECT params::text FROM jobs WHERE id = $1`, `SELECT winmod::text FROM jobs WHERE id = $1`, `SELECT body FROM jobs WHERE id = $1`,
			`SELECT coalesce(string_agg(details::text, ' '), 'none') FROM audit_log`, `SELECT coalesce(string_agg(sealed, ' '), 'none') FROM winmod_job_secrets`,
			`SELECT coalesce(string_agg(data::text, ' '), 'none') FROM windows_module_snapshots`,
		} {
			args := []any{}
			if strings.Contains(q, "$1") {
				args = append(args, jobID)
			}
			if got := f.str(q, args...); strings.Contains(got, secret) {
				t.Errorf("%q is in the result of %s", secret, q)
			}
		}
	}
	assertNowhere(pw, run.JobID)
	if got := f.str(`SELECT details::text FROM audit_log WHERE action = 'winmod.active_directory.user_reset_password'`); !strings.Contains(got, "(secret)") {
		t.Errorf("audit %s", got)
	}

	// Delivered once, in the signed params; the row is gone afterwards.
	resp, err := f.svc.Poll(f.ctx, dev, []string{agentproto.CapJobParams})
	if err != nil || len(resp.Jobs) != 1 {
		t.Fatalf("poll %+v, %v", resp, err)
	}
	p, err := agentproto.VerifyJob(f.key, resp.Jobs[0], dev.String(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(p.Params, &got); err != nil || got["password"] != pw || got["id"] != adUser {
		t.Errorf("delivered params %s, %v", p.Params, err)
	}
	if f.count(`SELECT count(*) FROM winmod_job_secrets`) != 0 {
		t.Error("the secret row survived delivery")
	}
	assertNowhere(pw, run.JobID)

	// A typed password, and the credential fallback, travel the same way.
	typed := WinmodInput{DeviceID: dev, Action: "active_directory.user_reset_password", Confirm: reset.Confirm,
		Params: json.RawMessage(`{"id":"` + adUser + `","password":"` + adTyped + `","credUser":"CORP\\admin","credPassword":"` + adAdminPwd + `"}`)}
	run2, err := f.svc.RunWinmod(f.ctx, admin, typed)
	if err != nil {
		t.Fatal(err)
	}
	if len(run2.Generated) != 0 {
		t.Errorf("a typed password was echoed: %v", run2.Generated)
	}
	if n := f.count(`SELECT count(*) FROM winmod_job_secrets WHERE job_id = $1`, run2.JobID); n != 2 {
		t.Errorf("%d sealed secrets, want the password and the credential's", n)
	}
	assertNowhere(adTyped, run2.JobID)
	assertNowhere(adAdminPwd, run2.JobID)
	// The credential's user name is audited as a length and a hash only.
	if got := f.str(`SELECT string_agg(details::text, ' ') FROM audit_log WHERE action = 'winmod.active_directory.user_reset_password'`); strings.Contains(got, "CORP") {
		t.Errorf("the credential's user name is in the audit: %s", got)
	}

	// No step-up, no job and no secret.
	before := f.count(`SELECT count(*) FROM winmod_job_secrets`)
	f.svc.SetStepUp(stepUpStub{err: errors.New("step up required")})
	if _, err := f.svc.RunWinmod(f.ctx, admin, reset); err == nil {
		t.Error("a password reset without a fresh step-up")
	}
	if f.count(`SELECT count(*) FROM winmod_job_secrets`) != before {
		t.Error("a refused reset left a secret")
	}
}

// A reset's result has the flags only: the stored result and the audit of
// the finished run hold no password.
func TestADResultsAreTypedAndKeepNoPassword(t *testing.T) {
	f := adFixture(t)
	admin := f.user("admin@example.com", rbac.Assignment{Role: rbac.RoleOrgAdmin, OrganizationID: f.acme})
	dev := f.winmodDevice("DC1", "windows")
	run, err := f.svc.RunWinmod(f.ctx, admin, WinmodInput{DeviceID: dev, Action: "active_directory.user_reset_password",
		Params: json.RawMessage(`{"id":"` + adUser + `","password":"` + adTyped + `"}`), Confirm: "active_directory.user_reset_password:" + adUser})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.Poll(f.ctx, dev, []string{agentproto.CapJobParams}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.Start(f.ctx, dev, run.RunID); err != nil {
		t.Fatal(err)
	}
	out := winmod.ResultPrefix + `{"ok":true,"version":1,"data":{"mustChange":true,"unlocked":false},"error":null}` + "\n"
	if err := f.svc.Result(f.ctx, dev, run.RunID, agentproto.ResultRequest{Status: StatusSucceeded, ExitCode: ptr(0), Stdout: out}); err != nil {
		t.Fatal(err)
	}
	res, err := f.svc.ReadWinmodResult(f.ctx, admin, run.RunID)
	if err != nil || res.OK == nil || !*res.OK || !strings.Contains(strings.ReplaceAll(string(res.Data), " ", ""), `"mustChange":true`) {
		t.Fatalf("%+v, %v", res, err)
	}
	for _, q := range []string{`SELECT string_agg(data::text, ' ') FROM winmod_run_results`, `SELECT string_agg(details::text, ' ') FROM audit_log`} {
		if got := f.str(q); strings.Contains(got, adTyped) {
			t.Errorf("the password is in %s", q)
		}
	}
	// A partial result is a failure with its own code, and says what happened.
	run2, err := f.svc.RunWinmod(f.ctx, admin, WinmodInput{DeviceID: dev, Action: "active_directory.user_reset_password",
		Params: json.RawMessage(`{"id":"` + adUser + `"}`), Confirm: "active_directory.user_reset_password:" + adUser})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.Poll(f.ctx, dev, []string{agentproto.CapJobParams}); err != nil {
		t.Fatal(err)
	}
	_, _ = f.svc.Start(f.ctx, dev, run2.RunID)
	partial := winmod.ResultPrefix + `{"ok":false,"version":1,"data":null,"error":{"code":"partial","message":"The password was changed, but the must-change flag was not."}}` + "\n"
	if err := f.svc.Result(f.ctx, dev, run2.RunID, agentproto.ResultRequest{Status: StatusSucceeded, ExitCode: ptr(0), Stdout: partial}); err != nil {
		t.Fatal(err)
	}
	if res, err := f.svc.ReadWinmodResult(f.ctx, admin, run2.RunID); err != nil || res.OK == nil || *res.OK || !strings.Contains(string(res.Failure), "partial") {
		t.Errorf("%+v, %v", res, err)
	}
}
