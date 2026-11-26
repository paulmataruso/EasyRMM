package grouppolicy

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/server/internal/access"
	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/modules"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
	"github.com/paulmataruso/easyrmm/server/internal/winmod"
)

// Retention of the automatic backups (ADR-0083 section 7): the newest KeepNewest per GPO, and anything younger than KeepDays,
// whichever is more.
const (
	KeepNewest = 20
	KeepDays   = 90
	// RequestLife is how long a request for approval stands.
	RequestLife = 24 * time.Hour
	// ApprovalLife is how long an approved request may be used to start its job.
	ApprovalLife = time.Hour
	// maxAuditDiff is the most of a change's diff the audit row keeps. The audit's own limit on details is 16 KiB, so the
	// ADR's 64 KiB is amended (ADR-0083, decided in review); a hash of the whole diff and a marker say when it was cut.
	maxAuditDiff = 12 << 10
)

// Run is what a started change answers: the run to follow (the shape of jobs.WinmodRun).
type Run struct {
	JobID     uuid.UUID `json:"jobId"`
	RunID     uuid.UUID `json:"runId"`
	Action    string    `json:"action"`
	Status    string    `json:"status"`
	ExpiresAt time.Time `json:"expiresAt"`
}

// Runner starts a winmod job: jobs.Service, through the adapter in gpowire (this package does not import jobs, which
// would make a cycle with the jobs package's own tests).
type Runner interface {
	RunWinmod(ctx context.Context, c access.Caller, device uuid.UUID, action string, params json.RawMessage, confirm string) (*Run, error)
}

// ResultEvent is what a finished run of the module reported (jobs.WinmodResultEvent, through the adapter).
type ResultEvent struct {
	Action                        winmod.Action
	RunID, JobID, DeviceID, OrgID uuid.UUID
	SiteID                        uuid.UUID
	Stdout                        string
	Result                        *winmod.Result
	Params                        []byte
}

// Service keeps what the module keeps of its own: the automatic backups, the requests for approval and each
// organization's setting, and decides in the job's transaction whether a change may run.
type Service struct {
	db      *database.DB
	audit   *audit.Logger
	mods    *modules.Service
	catalog *winmod.Catalog
	runner  Runner
	now     func() time.Time
}

// New builds the service.
func New(db *database.DB, a *audit.Logger, mods *modules.Service, catalog *winmod.Catalog, runner Runner) *Service {
	return &Service{db: db, audit: a, mods: mods, catalog: catalog, runner: runner, now: time.Now}
}

// Settings is an organization's approval setting.
type Settings struct {
	// ApprovalSensitive: two people for a GPO linked at the domain root, to the Domain Controllers OU or to a site, a link
	// there, and the Default policies. On by default.
	ApprovalSensitive bool `json:"approvalSensitive"`
	// ApprovalAll: two people for every Group Policy change. Off by default.
	ApprovalAll bool `json:"approvalAll"`
}

func settingsIn(ctx context.Context, tx pgx.Tx, org uuid.UUID) (Settings, error) {
	s := Settings{ApprovalSensitive: true}
	err := tx.QueryRow(ctx, `SELECT approval_sensitive, approval_all FROM gpo_org_settings WHERE organization_id = $1`, org).Scan(&s.ApprovalSensitive, &s.ApprovalAll)
	if errors.Is(err, pgx.ErrNoRows) {
		return Settings{ApprovalSensitive: true}, nil
	}
	return s, err
}

func decodeParams(raw json.RawMessage) (map[string]any, error) {
	m := map[string]any{}
	if len(bytes.TrimSpace(raw)) == 0 {
		return m, nil
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&m); err != nil {
		return nil, err
	}
	return m, nil
}

// contentChange are the actions that change what a GPO is, not where it is linked.
var contentChange = map[string]bool{"gpo_rename": true, "gpo_delete": true, "gpo_status": true, "sec_filter_add": true, "sec_filter_remove": true, "wmi_set": true, "gpo_restore": true}

// linkedSensitive says, from what the console last read of the GPO on this controller, whether it is linked at the domain
// root, to the Domain Controllers OU or to a site. A GPO the console never read is not known here (the script reports
// it, and the audit says so).
func linkedSensitive(ctx context.Context, tx pgx.Tx, device uuid.UUID, id string) bool {
	key, err := winmod.ParamsKey([]byte(`{"id":"` + id + `"}`))
	if err != nil {
		return false
	}
	var data []byte
	if err := tx.QueryRow(ctx, `SELECT data FROM windows_module_snapshots WHERE device_id = $1 AND action = 'group_policy.gpo_get' AND params_hash = $2`, device, key).Scan(&data); err != nil {
		return false
	}
	var d GPODetail
	if json.Unmarshal(data, &d) != nil {
		return false
	}
	for _, l := range d.ReportLinks {
		if l.Sensitive {
			return true
		}
	}
	return false
}

// Requirement says whether a change needs a second person and why: "default_policy", "sensitive_link", or "organization".
func (s *Service) requirement(ctx context.Context, tx pgx.Tx, org, device uuid.UUID, action string, p map[string]any) (string, error) {
	if !NeedsApprovalCheck(action) {
		return "", nil
	}
	set, err := settingsIn(ctx, tx, org)
	if err != nil {
		return "", err
	}
	why := Sensitivity(action, p)
	short := strings.TrimPrefix(action, "group_policy.")
	if why == "" && contentChange[short] {
		if id, _ := p["id"].(string); id != "" && linkedSensitive(ctx, tx, device, id) {
			why = "sensitive_link"
		}
	}
	switch {
	case why != "" && set.ApprovalSensitive:
		return why, nil
	case set.ApprovalAll:
		if why == "" {
			why = "organization"
		}
		return why, nil
	}
	return "", nil
}

// CheckWinmod is the jobs package's gate (jobs.ApprovalGate): for a Group Policy change that needs two people it
// refuses a request that carries no approval, and uses up the approval one carries. It also refuses a restore of a backup
// the server does not hold, so a restore can only put back what EasyRMM itself took.
func (s *Service) CheckWinmod(ctx context.Context, tx pgx.Tx, c access.Caller, org, device uuid.UUID, a winmod.Action, raw json.RawMessage) error {
	if a.Module != modules.GroupPolicy {
		return nil
	}
	p, err := decodeParams(raw)
	if err != nil {
		return apperr.Invalid("params", "The parameters must be a JSON object.")
	}
	short := strings.TrimPrefix(a.Name, "group_policy.")
	if short == "gpo_restore" || short == "gpo_restore_stage" {
		bid, _ := p["backupId"].(string)
		var ok bool
		q := `SELECT EXISTS (SELECT 1 FROM gpo_backups WHERE organization_id = $1 AND backup_id = $2`
		args := []any{org, bid}
		if h, _ := p["zipSha256"].(string); short == "gpo_restore" {
			q += ` AND sha256 = $3 AND gpo_id = $4`
			args = append(args, h, p["id"])
		}
		if err := tx.QueryRow(ctx, q+`)`, args...).Scan(&ok); err != nil || !ok {
			return apperr.Invalid("params.backupId", "EasyRMM holds no such backup of this GPO.")
		}
	}
	why, err := s.requirement(ctx, tx, org, device, a.Name, p)
	if err != nil {
		return err
	}
	if why == "" {
		return nil
	}
	idText, _ := p["approvalId"].(string)
	if idText == "" {
		return apperr.Conflict("approval_required", approvalText(why))
	}
	id, err := uuid.Parse(idText)
	if err != nil {
		return apperr.Conflict("approval_required", approvalText(why))
	}
	var (
		status   string
		stored   []byte
		dev      uuid.UUID
		act      string
		decided  *time.Time
		consumed *time.Time
	)
	err = tx.QueryRow(ctx, `SELECT status, params, device_id, action, decided_at, consumed_at FROM gpo_change_requests WHERE id = $1 AND organization_id = $2 FOR UPDATE`, id, org).
		Scan(&status, &stored, &dev, &act, &decided, &consumed)
	if errors.Is(err, pgx.ErrNoRows) {
		return apperr.Conflict("approval_invalid", "That approval does not exist.")
	}
	if err != nil {
		return err
	}
	switch {
	case status != "approved" || decided == nil || consumed != nil:
		return apperr.Conflict("approval_invalid", "That approval is not open: it was not granted, or it was already used.")
	case s.now().Sub(*decided) > ApprovalLife:
		return apperr.Conflict("approval_invalid", "That approval has lapsed. Ask again.")
	case dev != device || act != a.Name:
		return apperr.Conflict("approval_invalid", "That approval is for another change.")
	}
	want, err := decodeParams(stored)
	if err != nil {
		return err
	}
	delete(p, "approvalId")
	delete(want, "approvalId")
	a1, _ := json.Marshal(p)
	a2, _ := json.Marshal(want)
	if !bytes.Equal(a1, a2) {
		return apperr.Conflict("approval_invalid", "That approval is for another change.")
	}
	_, err = tx.Exec(ctx, `UPDATE gpo_change_requests SET consumed_at = now() WHERE id = $1`, id)
	return err
}

func approvalText(why string) string {
	switch why {
	case "default_policy":
		return "A change to a Default policy needs a second person to approve it."
	case "sensitive_link":
		return "A change at the domain root, the Domain Controllers OU or a site, or to a GPO linked there, needs a second person to approve it."
	}
	return "This organization requires a second person to approve every Group Policy change."
}

// BackupFromOutput reads the backup a change's output carries, with its zip.
func BackupFromOutput(stdout string) (*Backup, error) {
	lines := strings.Split(strings.TrimRight(stdout, "\r\n \t"), "\n")
	body, ok := strings.CutPrefix(strings.TrimSpace(lines[len(lines)-1]), winmod.ResultPrefix)
	if !ok {
		return nil, errors.New("no result line")
	}
	var env struct {
		Data struct {
			Backup *Backup `json:"backup"`
		} `json:"data"`
	}
	if err := json.Unmarshal([]byte(body), &env); err != nil {
		return nil, err
	}
	return env.Data.Backup, nil
}

// Hook is the jobs package's result hook (jobs.WinmodResultHook, through the adapter): it moves the backup a change took out of the run's
// output into gpo_backups, applies the retention, and writes the audit row that carries the change's diff.
func (s *Service) Hook(ctx context.Context, tx pgx.Tx, ev ResultEvent) error {
	a := ev.Action
	if a.Module != modules.GroupPolicy || ev.Result == nil || !ev.Result.OK {
		return nil
	}
	short := strings.TrimPrefix(a.Name, "group_policy.")
	var (
		actorID  *uuid.UUID
		actorLbl string
	)
	if err := tx.QueryRow(ctx, `SELECT created_by, created_by_label FROM jobs WHERE id = $1`, ev.JobID).Scan(&actorID, &actorLbl); err != nil {
		return err
	}
	params, _ := decodeParams(ev.Params)
	reason, _ := params["reason"].(string)
	var ch Changed
	if json.Unmarshal(ev.Result.Data, &ch) == nil && short != "gpo_restore_stage" && ch.Summary != "" {
		backupID, backupNote := "", ""
		if b, err := BackupFromOutput(ev.Stdout); err == nil && b != nil && b.Zip != "" {
			raw, derr := base64.StdEncoding.DecodeString(b.Zip)
			sum := sha256.Sum256(raw)
			switch {
			case derr != nil || len(raw) == 0 || len(raw) > MaxBackupZip:
				backupNote = "the backup in the result was not usable and was not kept"
			case hex.EncodeToString(sum[:]) != b.SHA256:
				backupNote = "the backup in the result did not match its hash and was not kept"
			default:
				kind := "automatic"
				if short == "gpo_backup" {
					kind = "manual"
				}
				var id uuid.UUID
				if err := tx.QueryRow(ctx, `INSERT INTO gpo_backups (organization_id, site_id, device_id, domain, gpo_id, gpo_name, backup_id, computer_version, user_version,
						kind, action, job_id, actor_id, actor_label, reason, size_bytes, sha256, zip)
					VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18) RETURNING id`,
					ev.OrgID, ev.SiteID, ev.DeviceID, nonEmpty(b.Domain, "unknown"), b.GPOID, truncate(b.GPOName, 256), b.BackupID, b.Computer.Directory, b.User.Directory,
					kind, a.Name, ev.JobID, actorID, actorLbl, truncate(reason, 500), len(raw), b.SHA256, raw).Scan(&id); err != nil {
					return err
				}
				backupID = id.String()
				if _, err := tx.Exec(ctx, `DELETE FROM gpo_backups WHERE id IN (
						SELECT id FROM gpo_backups WHERE organization_id = $1 AND gpo_id = $2 ORDER BY created_at DESC, id OFFSET $3)
					AND created_at < now() - make_interval(days => $4)`, ev.OrgID, b.GPOID, KeepNewest, KeepDays); err != nil {
					return err
				}
			}
		}
		if !a.Changes && short != "gpo_backup" {
			return nil
		}
		actor := audit.SystemActor("winmod")
		if actorID != nil {
			actor = audit.Actor{Type: audit.ActorUser, ID: *actorID, Label: actorLbl}
		}
		diff, _ := json.Marshal(map[string]any{"before": ch.Before, "after": ch.After})
		full := sha256.Sum256(diff)
		shown := string(diff)
		cut := false
		if len(diff) > maxAuditDiff {
			shown, cut = string(diff[:maxAuditDiff]), true
		}
		d := map[string]any{
			"module": string(a.Module), "action": a.Name, "reason": reason, "summary": truncate(ch.Summary, 500), "gpoId": ch.GPOID, "gpoName": truncate(ch.GPOName, 256),
			"versionBefore": ch.VersionBefore, "versionAfter": ch.VersionAfter, "backupId": backupID,
			"diff": shown, "diffSha256": hex.EncodeToString(full[:]), "diffCut": cut,
		}
		if backupNote != "" {
			d["backupNote"] = backupNote
		}
		if id, _ := params["approvalId"].(string); id != "" {
			d["approvalId"] = id
		}
		return s.audit.Write(ctx, tx, audit.Event{
			Actor: actor, Action: "winmod." + a.Name + ".change", Outcome: audit.Success, OrganizationID: ev.OrgID, SiteID: ev.SiteID, DeviceID: ev.DeviceID,
			TargetType: "gpo", TargetID: nonEmpty(ch.GPOID, "none"), Details: d,
		})
	}
	return nil
}

func nonEmpty(s, def string) string {
	if strings.TrimSpace(s) == "" {
		return def
	}
	return s
}

func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) > n {
		return string(r[:n])
	}
	return s
}

// deviceFor loads a device the caller may use the module on: its organization and site, with the permission checked
// at its site and the module on (the 404 rule of ADR-0073).
func (s *Service) deviceFor(ctx context.Context, tx pgx.Tx, c access.Caller, device uuid.UUID, perm rbac.Permission) (org, site uuid.UUID, err error) {
	if err = tx.QueryRow(ctx, `SELECT organization_id, site_id FROM devices WHERE id = $1 AND platform = 'windows' AND roles @> '[{"name":"gpmc"}]'`, device).Scan(&org, &site); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return uuid.Nil, uuid.Nil, apperr.NotFound()
		}
		return uuid.Nil, uuid.Nil, err
	}
	if !c.Can(perm, rbac.Site(org, site)) || !s.mods.Allowed(ctx, org, site, modules.GroupPolicy) {
		return uuid.Nil, uuid.Nil, apperr.NotFound()
	}
	return org, site, nil
}
