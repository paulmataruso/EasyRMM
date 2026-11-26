//go:build integration

package grouppolicy_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/server/internal/access"
	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/auth"
	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/jobs"
	"github.com/paulmataruso/easyrmm/server/internal/modules"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
	"github.com/paulmataruso/easyrmm/server/internal/secrets"
	"github.com/paulmataruso/easyrmm/server/internal/testdb"
	"github.com/paulmataruso/easyrmm/server/internal/winmod"
	. "github.com/paulmataruso/easyrmm/server/internal/winmod/grouppolicy" //nolint:revive // the tests read as the package's own
	"github.com/paulmataruso/easyrmm/server/internal/winmod/grouppolicy/gpowire"
)

const (
	gpoID  = "8f2c1b3a-5d4e-4a7b-9c1d-2e3f4a5b6c7d"
	ouDN   = "OU=Test,OU=EasyRMM,DC=corp,DC=example"
	rootDN = "DC=corp,DC=example"
	dcDN   = "OU=Domain Controllers,DC=corp,DC=example"
	sid    = "S-1-5-21-1-2-3-1104"
)

type stepUpStub struct{}

func (stepUpStub) VerifyStepUp(context.Context) error { return nil }

type fx struct {
	t                  *testing.T
	ctx                context.Context
	db                 *database.DB
	jobs               *jobs.Service
	svc                *Service
	org, site, dev     uuid.UUID
	otherOrg, otherDev uuid.UUID
	admin, admin2      access.Caller
	site2, tech, ro    access.Caller
}

func (f *fx) id(sql string, args ...any) uuid.UUID {
	f.t.Helper()
	var id uuid.UUID
	if err := f.db.InTx(f.ctx, database.System, func(tx pgx.Tx) error { return tx.QueryRow(f.ctx, sql, args...).Scan(&id) }); err != nil {
		f.t.Fatal(err)
	}
	return id
}

func (f *fx) exec(sql string, args ...any) {
	f.t.Helper()
	if err := f.db.InTx(f.ctx, database.System, func(tx pgx.Tx) error { _, err := tx.Exec(f.ctx, sql, args...); return err }); err != nil {
		f.t.Fatal(err)
	}
}

func (f *fx) count(sql string, args ...any) int {
	f.t.Helper()
	var n int
	if err := f.db.ReadTx(f.ctx, database.System, func(tx pgx.Tx) error { return tx.QueryRow(f.ctx, sql, args...).Scan(&n) }); err != nil {
		f.t.Fatal(err)
	}
	return n
}

func (f *fx) user(email string, role rbac.Role, org, site uuid.UUID) access.Caller {
	f.t.Helper()
	id := f.id(`INSERT INTO users (email, display_name) VALUES ($1, $1) RETURNING id`, email)
	as := rbac.Assignment{Role: role, OrganizationID: org, SiteID: site}
	var o, s *uuid.UUID
	if org != uuid.Nil {
		o = &org
	}
	if site != uuid.Nil {
		s = &site
	}
	f.exec(`INSERT INTO role_assignments (user_id, role, organization_id, site_id) VALUES ($1, $2, $3, $4)`, id, string(role), o, s)
	p, err := rbac.NewPrincipal(id, []rbac.Assignment{as})
	if err != nil {
		f.t.Fatal(err)
	}
	return access.User(p, auth.DataScope(p), audit.Actor{Type: audit.ActorUser, ID: id, Label: email})
}

func (f *fx) device(org, site uuid.UUID, name string) uuid.UUID {
	f.t.Helper()
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	d := f.id(`INSERT INTO devices (organization_id, site_id, name, hostname, platform, agent_public_key, enrolled_at, agent_last_seen_at, roles, roles_at)
		VALUES ($1, $2, $3, $3, 'windows', $4, now(), now(), '[{"name":"gpmc","state":"present"}]'::jsonb, now()) RETURNING id`, org, site, name, key)
	f.poll(d)
	return d
}

// poll is the agent asking for work: it says what its build accepts, and does not wait for a job.
func (f *fx) poll(d uuid.UUID) {
	f.t.Helper()
	ctx, cancel := context.WithTimeout(f.ctx, 500*time.Millisecond)
	defer cancel()
	_, _ = f.jobs.Poll(ctx, d, []string{agentproto.CapJobPwsh, agentproto.CapJobParams})
}

func newFx(t *testing.T) *fx {
	t.Helper()
	inst := testdb.New(t)
	f := &fx{t: t, ctx: context.Background(), db: inst.DB}
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	a := audit.New(inst.DB, time.Now)
	f.jobs = jobs.New(inst.DB, a, priv, 90*24*time.Hour, 30*24*time.Hour, log)
	cat, err := winmod.NewCatalog(Actions()...)
	if err != nil {
		t.Fatal(err)
	}
	raw := make([]byte, 32)
	_, _ = rand.Read(raw)
	sealer, err := secrets.NewSealer(secrets.Key{ID: "k1", Raw: raw})
	if err != nil {
		t.Fatal(err)
	}
	mods := modules.New(inst.DB, a, log)
	f.jobs.SetWinmod(cat, mods, sealer)
	f.jobs.SetStepUp(stepUpStub{})
	f.svc = gpowire.New(inst.DB, a, mods, cat, f.jobs)
	f.org = f.id(`INSERT INTO organizations (name) VALUES ('Acme') RETURNING id`)
	f.site = f.id(`INSERT INTO sites (organization_id, name) VALUES ($1, 'HQ') RETURNING id`, f.org)
	f.otherOrg = f.id(`INSERT INTO organizations (name) VALUES ('Globex') RETURNING id`)
	otherSite := f.id(`INSERT INTO sites (organization_id, name) VALUES ($1, 'Plant') RETURNING id`, f.otherOrg)
	f.dev = f.device(f.org, f.site, "DC1")
	f.otherDev = f.device(f.otherOrg, otherSite, "DC9")
	f.admin = f.user("admin@example.com", rbac.RoleOrgAdmin, f.org, uuid.Nil)
	f.admin2 = f.user("admin2@example.com", rbac.RoleOrgAdmin, f.org, uuid.Nil)
	f.site2 = f.user("siteadmin@example.com", rbac.RoleSiteAdmin, f.org, f.site)
	f.tech = f.user("tech@example.com", rbac.RoleTechnician, f.org, f.site)
	f.ro = f.user("ro@example.com", rbac.RoleReadOnly, f.org, f.site)
	return f
}

func (f *fx) run(c access.Caller, dev uuid.UUID, action, params, confirm string) (*jobs.WinmodRun, error) {
	return f.jobs.RunWinmod(f.ctx, c, jobs.WinmodInput{DeviceID: dev, Action: "group_policy." + action, Params: json.RawMessage(params), Confirm: confirm})
}

// finish plays the agent: it delivers the run and reports the output.
func (f *fx) finish(dev uuid.UUID, run *jobs.WinmodRun, stdout string) {
	f.t.Helper()
	f.poll(dev)
	if st, err := f.jobs.Start(f.ctx, dev, run.RunID); err != nil || !st.Proceed {
		f.t.Fatalf("start: %v %+v", err, st)
	}
	zero := 0
	if err := f.jobs.Result(f.ctx, dev, run.RunID, agentproto.ResultRequest{Status: jobs.StatusSucceeded, ExitCode: &zero, Stdout: stdout}); err != nil {
		f.t.Fatal(err)
	}
}

func zipBytes(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b
}

// changed is a rename's output with a backup of the given zip.
func changed(zip []byte, gpo, backupID string) string {
	sum := sha256.Sum256(zip)
	return `EASYRMM-WINMOD-RESULT-V1 {"ok":true,"version":1,"data":{"summary":"Renamed the GPO a to b.","before":{"name":"a"},"after":{"name":"b"},"gpoId":"` + gpo + `","gpoName":"b",` +
		`"backup":{"backupId":"` + backupID + `","domain":"corp.example","gpoId":"` + gpo + `","gpoName":"a","size":` + itoa(len(zip)) + `,"sha256":"` + hex.EncodeToString(sum[:]) + `",` +
		`"computer":{"directory":2,"sysvol":2},"user":{"directory":0,"sysvol":0},"zip":"` + base64.StdEncoding.EncodeToString(zip) + `"},` +
		`"versionBefore":{"computer":{"directory":2,"sysvol":2},"user":{"directory":0,"sysvol":0}},"versionAfter":{"computer":{"directory":2,"sysvol":2},"user":{"directory":0,"sysvol":0}}},"error":null}` + "\n"
}

func itoa(n int) string { b, _ := json.Marshal(n); return string(b) }

const why = `"reason":"Tidy up the name"`

func code(err error) string {
	var ae *apperr.Error
	if errors.As(err, &ae) {
		return ae.Code
	}
	return ""
}

// The permission split of ADR-0083 section 8, through the real RunWinmod: a Technician and a Site Administrator read and
// nothing more, Read-Only nothing, an Organization Administrator everything.
func TestPermissionSplit(t *testing.T) {
	f := newFx(t)
	rename := `{"id":"` + gpoID + `","newName":"Renamed",` + why + `}`
	link := `{"id":"` + gpoID + `","target":"` + ouDN + `",` + why + `}`
	for _, c := range []struct {
		who  string
		call access.Caller
	}{{"tech", f.tech}, {"site admin", f.site2}} {
		for _, a := range []string{"status", "gpo_list", "link_tree", "wmi_filters"} {
			if _, err := f.run(c.call, f.dev, a, `{}`, ""); err != nil {
				t.Errorf("%s reading %s: %v", c.who, a, err)
			}
		}
		if _, err := f.run(c.call, f.dev, "gpo_rename", rename, ""); err == nil {
			t.Errorf("%s renamed a GPO", c.who)
		}
		if _, err := f.run(c.call, f.dev, "link_add", link, ""); err == nil {
			t.Errorf("%s linked a GPO", c.who)
		}
	}
	if _, err := f.run(f.ro, f.dev, "status", `{}`, ""); err == nil {
		t.Error("Read-Only read Group Policy")
	}
	if _, err := f.run(f.admin, f.dev, "gpo_rename", rename, ""); err != nil {
		t.Errorf("an Organization Administrator renaming: %v", err)
	}
	if _, err := f.run(f.admin, f.dev, "link_add", link, ""); err != nil {
		t.Errorf("an Organization Administrator linking: %v", err)
	}
	// Another organization's controller is not found, even for an administrator.
	if _, err := f.run(f.admin, f.otherDev, "status", `{}`, ""); !errors.Is(err, apperr.NotFound()) && err == nil {
		t.Errorf("another organization's controller: %v", err)
	}
	// A typed confirmation is the GPO's name.
	del := `{"id":"` + gpoID + `","name":"Baseline",` + why + `}`
	if _, err := f.run(f.admin, f.dev, "gpo_delete", del, ""); err == nil {
		t.Error("a delete without its confirmation ran")
	}
	if _, err := f.run(f.admin, f.dev, "gpo_delete", del, "group_policy.gpo_delete:Baseline"); err != nil {
		t.Errorf("a confirmed delete: %v", err)
	}
	// The module off for the site is not found.
	f.exec(`INSERT INTO windows_module_settings (organization_id, module, enabled) VALUES ($1, 'group_policy', false)`, f.org)
	if _, err := f.run(f.admin, f.dev, "status", `{}`, ""); err == nil {
		t.Error("a module that is off ran")
	}
}

// The guards of section 7: a change at the domain root needs a second person; a request, an approval by the same person, by
// another, and the approval runs once, for exactly the change that was asked.
func TestTwoPersonApproval(t *testing.T) {
	f := newFx(t)
	root := `{"id":"` + gpoID + `","target":"` + rootDN + `",` + why + `}`
	if _, err := f.run(f.admin, f.dev, "link_add", root, ""); code(err) != "approval_required" {
		t.Fatalf("a link at the domain root ran, or was refused for another reason: %v", err)
	}
	if n := f.count(`SELECT count(*) FROM jobs WHERE kind = 'winmod'`); n != 0 {
		t.Fatalf("%d jobs were made for a refused change", n)
	}
	// A tech cannot even ask: the change is an Organization Administrator's.
	if _, err := f.svc.Submit(f.ctx, f.tech, f.dev, NewRequest{Action: "group_policy.link_add", Params: json.RawMessage(root)}); err == nil {
		t.Error("a Technician submitted a request")
	}
	req, err := f.svc.Submit(f.ctx, f.admin, f.dev, NewRequest{Action: "group_policy.link_add", Params: json.RawMessage(root), Subject: "Baseline at the root"})
	if err != nil {
		t.Fatal(err)
	}
	if req.Sensitivity != "sensitive_link" || req.Status != "pending" {
		t.Errorf("request: %+v", req)
	}
	// A change that needs no approval is not accepted as a request.
	ou := `{"id":"` + gpoID + `","target":"` + ouDN + `",` + why + `}`
	if _, err := f.svc.Submit(f.ctx, f.admin, f.dev, NewRequest{Action: "group_policy.link_add", Params: json.RawMessage(ou)}); code(err) != "approval_not_needed" {
		t.Errorf("an ordinary link was accepted as a request: %v", err)
	}
	// The one who asked cannot approve; a Site Administrator (no gpo.edit) cannot; another administrator can.
	if _, err := f.svc.Approve(f.ctx, f.admin, req.ID, "I am approving my own change"); code(err) != "same_person" {
		t.Errorf("self-approval: %v", err)
	}
	if _, err := f.svc.Approve(f.ctx, f.site2, req.ID, "A site administrator approving"); err == nil {
		t.Error("a Site Administrator approved")
	}
	if _, err := f.svc.Approve(f.ctx, f.admin2, req.ID, "short"); err == nil {
		t.Error("an approval without a reason")
	}
	// A forged approval id on a fresh request is refused.
	forged := `{"id":"` + gpoID + `","target":"` + rootDN + `",` + why + `,"approvalId":"` + uuid.NewString() + `"}`
	if _, err := f.run(f.admin, f.dev, "link_add", forged, ""); code(err) != "approval_invalid" {
		t.Errorf("a forged approval: %v", err)
	}
	if _, err := f.run(f.admin, f.dev, "link_add", `{"id":"`+gpoID+`","target":"`+rootDN+`",`+why+`,"approvalId":"`+req.ID.String()+`"}`, ""); code(err) != "approval_invalid" {
		t.Errorf("an approval that is not granted yet: %v", err)
	}
	run, err := f.svc.Approve(f.ctx, f.admin2, req.ID, "Reviewed the diff and the target")
	if err != nil || run == nil {
		t.Fatalf("approve: %v", err)
	}
	if n := f.count(`SELECT count(*) FROM jobs WHERE kind = 'winmod' AND created_by_label = 'admin2@example.com'`); n != 1 {
		t.Errorf("the change did not run under the approver's name: %d", n)
	}
	// It runs once, and only for what was asked.
	again := `{"id":"` + gpoID + `","target":"` + rootDN + `",` + why + `,"approvalId":"` + req.ID.String() + `"}`
	if _, err := f.run(f.admin2, f.dev, "link_add", again, ""); code(err) != "approval_invalid" {
		t.Errorf("an approval used twice: %v", err)
	}
	if _, err := f.svc.Approve(f.ctx, f.admin2, req.ID, "Approving it a second time"); code(err) != "request_closed" {
		t.Errorf("a closed request approved again: %v", err)
	}
	// The audit has the request, the approval and the job, by their own people.
	for action, who := range map[string]string{"group_policy.request": "admin@example.com", "group_policy.approve": "admin2@example.com"} {
		if n := f.count(`SELECT count(*) FROM audit_log WHERE action = $1 AND actor_label = $2`, action, who); n != 1 {
			t.Errorf("audit %s by %s: %d rows", action, who, n)
		}
	}
}

func TestApprovalIsForExactlyTheRequestedChange(t *testing.T) {
	f := newFx(t)
	root := `{"id":"` + gpoID + `","target":"` + rootDN + `",` + why + `}`
	req, err := f.svc.Submit(f.ctx, f.admin, f.dev, NewRequest{Action: "group_policy.link_add", Params: json.RawMessage(root)})
	if err != nil {
		t.Fatal(err)
	}
	// Approve by hand (no job), then try the approval on another target, another GPO and another action.
	f.exec(`UPDATE gpo_change_requests SET status = 'approved', decided_by = $2, decided_label = 'x', decided_at = now() WHERE id = $1`, req.ID, f.admin2.Actor.ID)
	for name, p := range map[string]string{
		"another target": `{"id":"` + gpoID + `","target":"` + dcDN + `",` + why + `,"approvalId":"` + req.ID.String() + `"}`,
		"another gpo":    `{"id":"` + uuid.NewString() + `","target":"` + rootDN + `",` + why + `,"approvalId":"` + req.ID.String() + `"}`,
	} {
		if _, err := f.run(f.admin2, f.dev, "link_add", p, ""); code(err) != "approval_invalid" {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := f.run(f.admin2, f.dev, "link_enforced", `{"id":"`+gpoID+`","target":"`+rootDN+`","enforced":true,`+why+`,"approvalId":"`+req.ID.String()+`"}`, ""); code(err) != "approval_invalid" {
		t.Errorf("another action: %v", err)
	}
	// A lapsed approval is refused.
	f.exec(`UPDATE gpo_change_requests SET decided_at = now() - interval '2 hours' WHERE id = $1`, req.ID)
	if _, err := f.run(f.admin2, f.dev, "link_add", root[:len(root)-1]+`,"approvalId":"`+req.ID.String()+`"}`, ""); code(err) != "approval_invalid" {
		t.Errorf("a lapsed approval: %v", err)
	}
}

func TestDefaultPolicyAlwaysNeedsTwoPeople(t *testing.T) {
	f := newFx(t)
	name := DefaultPolicies[DefaultDomainPolicyID]
	p := `{"id":"` + DefaultDomainPolicyID + `","trustee":"` + sid + `",` + why + `,"confirmName":"` + name + `"}`
	if _, err := f.run(f.admin, f.dev, "sec_filter_add", p, ""); code(err) != "approval_required" {
		t.Fatalf("a change to the Default Domain Policy ran: %v", err)
	}
	// Turning the sensitive rule off is an Organization Administrator's, audited, and lets it through.
	if err := f.svc.SetSettings(f.ctx, f.tech, f.org, Settings{}); err == nil {
		t.Error("a Technician changed the approval setting")
	}
	if err := f.svc.SetSettings(f.ctx, f.admin, f.org, Settings{ApprovalSensitive: false}); err != nil {
		t.Fatal(err)
	}
	if n := f.count(`SELECT count(*) FROM audit_log WHERE action = 'group_policy.settings' AND details->>'weakened' = 'true'`); n != 1 {
		t.Errorf("the weakening is not in the audit: %d", n)
	}
	if _, err := f.run(f.admin, f.dev, "sec_filter_add", p, ""); err != nil {
		t.Errorf("with the rule off: %v", err)
	}
	// Even then, a Default policy is never deleted, renamed, unlinked or disabled.
	del := `{"id":"` + DefaultDomainPolicyID + `","name":"` + name + `",` + why + `,"confirmName":"` + name + `"}`
	if _, err := f.run(f.admin, f.dev, "gpo_delete", del, "group_policy.gpo_delete:"+name); code(err) != "protected_policy" {
		t.Errorf("deleting a Default policy: %v", err)
	}
	// The organization can require approval for everything.
	if err := f.svc.SetSettings(f.ctx, f.admin, f.org, Settings{ApprovalSensitive: true, ApprovalAll: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.run(f.admin, f.dev, "gpo_rename", `{"id":"`+gpoID+`","newName":"Renamed",`+why+`}`, ""); code(err) != "approval_required" {
		t.Errorf("with approval for everything: %v", err)
	}
	// A backup and a read are never held for approval.
	if _, err := f.run(f.admin, f.dev, "gpo_backup", `{"id":"`+gpoID+`",`+why+`}`, ""); err != nil {
		t.Errorf("a backup: %v", err)
	}
	if _, err := f.run(f.admin, f.dev, "gpo_list", `{}`, ""); err != nil {
		t.Errorf("a read: %v", err)
	}
}

// A GPO the console read as linked at the domain root needs two people for its content changes, too.
func TestGPOLinkedAtTheRootNeedsTwoPeople(t *testing.T) {
	f := newFx(t)
	key, _ := winmod.ParamsKey([]byte(`{"id":"` + gpoID + `"}`))
	detail := `{"id":"` + gpoID + `","name":"A","status":"AllSettingsEnabled","description":"","owner":"o","created":null,"modified":null,"computer":{"directory":1,"sysvol":1},"user":{"directory":0,"sysvol":0},` +
		`"wmiFilter":"","default":false,"linkCount":1,"links":[],"reportLinks":[{"name":"corp.example","path":"corp.example","enabled":true,"enforced":false,"sensitive":true}],"trustees":[]}`
	f.exec(`INSERT INTO windows_module_snapshots (device_id, module, action, params_hash, taken_at, sensitive, data) VALUES ($1, 'group_policy', 'group_policy.gpo_get', $2, now(), false, $3)`, f.dev, key, []byte(detail))
	if _, err := f.run(f.admin, f.dev, "gpo_rename", `{"id":"`+gpoID+`","newName":"Renamed",`+why+`}`, ""); code(err) != "approval_required" {
		t.Errorf("renaming a GPO linked at the root: %v", err)
	}
	if _, err := f.run(f.admin, f.dev, "gpo_rename", `{"id":"`+uuid.NewString()+`","newName":"Renamed",`+why+`}`, ""); err != nil {
		t.Errorf("renaming a GPO that is not linked at the root: %v", err)
	}
}

// The backup a change takes first is moved out of the run's output into the server's table, with its hash checked; the
// stored result and the job's output hold no zip; the audit row carries the diff and the backup's id.
func TestBackupIsKeptAndTheResultIsLean(t *testing.T) {
	f := newFx(t)
	zip := zipBytes(5000)
	bid := uuid.NewString()
	run, err := f.run(f.admin, f.dev, "gpo_rename", `{"id":"`+gpoID+`","newName":"b",`+why+`}`, "")
	if err != nil {
		t.Fatal(err)
	}
	f.finish(f.dev, run, changed(zip, gpoID, bid))
	if n := f.count(`SELECT count(*) FROM gpo_backups WHERE gpo_id = $1 AND backup_id = $2 AND size_bytes = 5000 AND kind = 'automatic' AND action = 'group_policy.gpo_rename' AND actor_label = 'admin@example.com'`, gpoID, bid); n != 1 {
		t.Fatalf("the backup is not kept: %d", n)
	}
	if n := f.count(`SELECT count(*) FROM winmod_run_results WHERE run_id = $1 AND data::text NOT LIKE '%zip%' AND data->>'summary' <> ''`, run.RunID); n != 1 {
		t.Error("the stored result is missing, or still holds the zip")
	}
	if n := f.count(`SELECT count(*) FROM audit_log WHERE action = 'winmod.group_policy.gpo_rename.change' AND details->>'reason' = 'Tidy up the name' AND details->>'backupId' <> '' AND details->>'diff' LIKE '%"after"%'`); n != 1 {
		t.Errorf("the change's audit row: %d", n)
	}
	// The list shows it, to a reader; the chunks and the download need gpo.manage and rebuild the same bytes.
	f.exec(`INSERT INTO windows_module_snapshots (device_id, module, action, params_hash, taken_at, sensitive, data) VALUES ($1, 'group_policy', 'group_policy.status', '', now(), false, $2)`,
		f.dev, []byte(`{"domain":"corp.example","domainDn":"DC=corp,DC=example","controller":"dc1","gpoCount":1,"empty":0,"unlinked":0,"targets":1}`))
	list, err := f.svc.ListBackups(f.ctx, f.tech, f.dev, nil)
	if err != nil || len(list) != 1 || list[0].Parts != 1 {
		t.Fatalf("list: %v %+v", err, list)
	}
	if _, _, err := f.svc.DownloadBackup(f.ctx, f.tech, f.dev, list[0].ID); err == nil {
		t.Error("a Technician downloaded a backup")
	}
	if _, err := f.svc.BackupChunk(f.ctx, f.tech, f.dev, list[0].ID, 0); err == nil {
		t.Error("a Technician read a backup's chunks")
	}
	raw, _, err := f.svc.DownloadBackup(f.ctx, f.admin, f.dev, list[0].ID)
	if err != nil || string(raw) != string(zip) {
		t.Errorf("download: %v", err)
	}
	if got, err := f.svc.ListBackups(f.ctx, f.admin, f.otherDev, nil); err == nil && len(got) != 0 {
		t.Errorf("another organization's backups: %+v", got)
	}
	// A tampered or oversize backup in a result fails the recording.
	bad := strings.Replace(changed(zip, gpoID, uuid.NewString()), `"sha256":"`, `"sha256":"0`, 1)
	run2, _ := f.run(f.admin, f.dev, "gpo_rename", `{"id":"`+gpoID+`","newName":"c",`+why+`}`, "")
	f.finish(f.dev, run2, bad)
	if n := f.count(`SELECT count(*) FROM gpo_backups`); n != 1 {
		t.Errorf("a backup that does not match its hash was kept: %d", n)
	}
}

func TestBackupRetention(t *testing.T) {
	f := newFx(t)
	for i := 0; i < KeepNewest+5; i++ {
		f.exec(`INSERT INTO gpo_backups (organization_id, site_id, device_id, domain, gpo_id, gpo_name, backup_id, kind, action, size_bytes, sha256, zip, created_at)
			VALUES ($1, $2, $3, 'corp.example', $4, 'A', gen_random_uuid(), 'automatic', 'group_policy.gpo_rename', 3, $5, '\x010203', now() - make_interval(days => $6))`,
			f.org, f.site, f.dev, gpoID, strings.Repeat("a", 64), 100+i)
	}
	run, _ := f.run(f.admin, f.dev, "gpo_rename", `{"id":"`+gpoID+`","newName":"b",`+why+`}`, "")
	f.finish(f.dev, run, changed(zipBytes(100), gpoID, uuid.NewString()))
	// 25 old ones (all over 90 days) and the new one: the newest 20 are kept, the rest go.
	if n := f.count(`SELECT count(*) FROM gpo_backups WHERE gpo_id = $1`, gpoID); n != KeepNewest {
		t.Errorf("%d backups kept, want %d", n, KeepNewest)
	}
	// Anything under 90 days old stays, however many.
	for i := 0; i < 5; i++ {
		f.exec(`INSERT INTO gpo_backups (organization_id, site_id, device_id, domain, gpo_id, gpo_name, backup_id, kind, action, size_bytes, sha256, zip, created_at)
			VALUES ($1, $2, $3, 'corp.example', $4, 'A', gen_random_uuid(), 'automatic', 'group_policy.gpo_rename', 3, $5, '\x010203', now() - make_interval(days => $6))`,
			f.org, f.site, f.dev, gpoID, strings.Repeat("a", 64), 10+i)
	}
	run, _ = f.run(f.admin, f.dev, "gpo_rename", `{"id":"`+gpoID+`","newName":"c",`+why+`}`, "")
	f.finish(f.dev, run, changed(zipBytes(100), gpoID, uuid.NewString()))
	if n := f.count(`SELECT count(*) FROM gpo_backups WHERE gpo_id = $1 AND created_at > now() - interval '90 days'`, gpoID); n < 7 {
		t.Errorf("a backup under 90 days old was pruned: %d left", n)
	}
}

// A restore is only of a backup the server holds, by its hash, for that GPO, in this organization.
func TestRestoreOnlyOfWhatTheServerHolds(t *testing.T) {
	f := newFx(t)
	zip := zipBytes(300)
	bid := uuid.NewString()
	run, _ := f.run(f.admin, f.dev, "gpo_rename", `{"id":"`+gpoID+`","newName":"b",`+why+`}`, "")
	f.finish(f.dev, run, changed(zip, gpoID, bid))
	sum := sha256.Sum256(zip)
	hash := hex.EncodeToString(sum[:])
	restore := func(c access.Caller, dev uuid.UUID, gpo, backup, h string) error {
		_, err := f.run(c, dev, "gpo_restore", `{"id":"`+gpo+`","name":"b","backupId":"`+backup+`","zipSha256":"`+h+`","parts":1,`+why+`}`, "group_policy.gpo_restore:b")
		return err
	}
	if err := restore(f.admin, f.dev, gpoID, bid, hash); err != nil {
		t.Errorf("a restore of a held backup: %v", err)
	}
	if err := restore(f.admin, f.dev, gpoID, bid, strings.Repeat("0", 64)); err == nil {
		t.Error("a restore with a hash the server does not hold")
	}
	if err := restore(f.admin, f.dev, gpoID, uuid.NewString(), hash); err == nil {
		t.Error("a restore of a backup the server does not hold")
	}
	if err := restore(f.admin, f.dev, uuid.NewString(), bid, hash); err == nil {
		t.Error("a restore of a backup into another GPO")
	}
	if err := restore(f.site2, f.dev, gpoID, bid, hash); err == nil {
		t.Error("a Site Administrator restored")
	}
	// Chunks are staged only for a held backup, too.
	stage := func(backup string) error {
		_, err := f.run(f.admin, f.dev, "gpo_restore_stage", `{"backupId":"`+backup+`","index":0,"count":1,"chunk":"UEs="}`, "")
		return err
	}
	if err := stage(bid); err != nil {
		t.Errorf("staging a held backup: %v", err)
	}
	if err := stage(uuid.NewString()); err == nil {
		t.Error("staging a backup the server does not hold")
	}
	// Chunks rebuild the zip.
	f.exec(`INSERT INTO windows_module_snapshots (device_id, module, action, params_hash, taken_at, sensitive, data) VALUES ($1, 'group_policy', 'group_policy.status', '', now(), false, $2)`,
		f.dev, []byte(`{"domain":"corp.example","domainDn":"DC=corp,DC=example","controller":"dc1","gpoCount":1,"empty":0,"unlinked":0,"targets":1}`))
	list, _ := f.svc.ListBackups(f.ctx, f.admin, f.dev, nil)
	c, err := f.svc.BackupChunk(f.ctx, f.admin, f.dev, list[0].ID, 0)
	if err != nil || c.Count != 1 {
		t.Fatalf("chunk: %v %+v", err, c)
	}
	if b, _ := base64.StdEncoding.DecodeString(c.Chunk); string(b) != string(zip) {
		t.Error("the chunk is not the backup")
	}
	if _, err := f.svc.BackupChunk(f.ctx, f.admin, f.dev, list[0].ID, 1); err == nil {
		t.Error("a chunk past the end")
	}
}

func TestSummaryCard(t *testing.T) {
	f := newFx(t)
	f.exec(`INSERT INTO windows_module_snapshots (device_id, module, action, params_hash, taken_at, sensitive, data) VALUES ($1, 'group_policy', 'group_policy.status', '', now(), false, $2)`,
		f.dev, []byte(`{"domain":"corp.example","domainDn":"DC=corp,DC=example","controller":"dc1","gpoCount":7,"empty":2,"unlinked":3,"targets":9}`))
	root := `{"id":"` + gpoID + `","target":"` + rootDN + `",` + why + `}`
	if _, err := f.svc.Submit(f.ctx, f.admin, f.dev, NewRequest{Action: "group_policy.link_add", Params: json.RawMessage(root)}); err != nil {
		t.Fatal(err)
	}
	s, err := f.svc.Summary(f.ctx, f.tech, f.org)
	if err != nil || !s.Enabled || len(s.Domains) != 1 || s.Domains[0].GPOCount != 7 || *s.Domains[0].Unlinked != 3 || s.PendingApprovals != 1 {
		t.Fatalf("%v %+v", err, s)
	}
	if _, err := f.svc.Summary(f.ctx, f.ro, f.org); err == nil {
		t.Error("Read-Only read the card")
	}
	if _, err := f.svc.Summary(f.ctx, f.admin, f.otherOrg); err == nil {
		t.Error("another organization's card")
	}
	// A request can be rejected with a reason, by anyone who may decide or by the one who asked.
	reqs, _ := f.svc.ListRequests(f.ctx, f.admin2, f.org)
	if len(reqs) != 1 || !reqs[0].CanDecide {
		t.Fatalf("%+v", reqs)
	}
	if err := f.svc.Reject(f.ctx, f.admin, reqs[0].ID, "Withdrawing my own request"); err != nil {
		t.Errorf("withdrawing: %v", err)
	}
	if err := f.svc.Reject(f.ctx, f.admin2, reqs[0].ID, "Rejecting it again now"); code(err) != "request_closed" {
		t.Errorf("rejecting a closed request: %v", err)
	}
	if s, _ := f.svc.Summary(f.ctx, f.tech, f.org); s.PendingApprovals != 0 {
		t.Errorf("pending after a rejection: %d", s.PendingApprovals)
	}
}
