// Package engine is the compliance engine's service (ADR-0078, slice C1):
// it loads the content, plans and advances scans, keeps per-control
// results and reads them back with their roll-up. It never runs a script of
// its own: it asks the hardening check to read, and stores what that stored.
package engine

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"slices"
	"sort"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/server/internal/access"
	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/compliance"
	"github.com/paulmataruso/easyrmm/server/internal/compliance/packs"
	"github.com/paulmataruso/easyrmm/server/internal/compliance/rollup"
	"github.com/paulmataruso/easyrmm/server/internal/compliance/scan"
	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/devscope"
	"github.com/paulmataruso/easyrmm/server/internal/jobs"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
)

// Service is the compliance engine.
type Service struct {
	db    *database.DB
	jobs  *jobs.Service
	audit *audit.Logger
	log   *slog.Logger
	now   func() time.Time

	mu     sync.Mutex
	report []packs.Status
}

// New builds the service. jobs makes the hardening check jobs of a scan.
func New(db *database.DB, j *jobs.Service, auditLog *audit.Logger, log *slog.Logger) *Service {
	return &Service{db: db, jobs: j, audit: auditLog, log: log, now: time.Now}
}

// SetClock replaces the clock, for tests.
func (s *Service) SetClock(now func() time.Time) { s.now = now }

// LoadContent loads the embedded content into the global tables for the
// build's edition and keeps what became of each file.
func (s *Service) LoadContent(ctx context.Context, fsys fs.FS, edition string) error {
	st, err := packs.Load(ctx, s.db, fsys, edition, s.log)
	s.mu.Lock()
	s.report = st
	s.mu.Unlock()
	return err
}

// LoadReport says what the loader did with each content file.
func (s *Service) LoadReport() []packs.Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.report)
}

// requireOrg checks a permission in the organization and that the caller
// can see it.
func requireOrg(c access.Caller, perm rbac.Permission, org uuid.UUID) error {
	if !c.Can(perm, rbac.Org(org)) {
		return apperr.NotFound()
	}
	return nil
}

// ---- reading the library ---------------------------------------------------------------------

// PackInfo is a pack as the console lists it.
type PackInfo struct {
	Key          string           `json:"key"`
	Version      string           `json:"version"`
	Kind         string           `json:"kind"`
	Title        string           `json:"title"`
	LicenceClass compliance.Class `json:"licenceClass"`
	ReviewState  string           `json:"reviewState"`
	Origin       string           `json:"origin"`
	Enabled      bool             `json:"enabled"`
	// Framework and Coverage are for a framework pack: how many of its
	// requirements a scan can reach, partly or not at all.
	Framework  string           `json:"framework,omitempty"`
	TextPolicy string           `json:"textPolicy,omitempty"`
	Coverage   *rollup.Coverage `json:"coverage,omitempty"`
	// Note is the wording rule that goes with the pack, where it has one.
	Note string `json:"note,omitempty"`
}

// Packs lists the packs, and for an organization whether each is enabled
// there. Reading is open to anyone who may view compliance in the
// organization.
func (s *Service) Packs(ctx context.Context, c access.Caller, org uuid.UUID) ([]PackInfo, error) {
	if err := requireOrg(c, rbac.PermComplianceView, org); err != nil {
		return nil, err
	}
	out := []PackInfo{}
	err := s.db.ReadTx(ctx, c.Scope, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT p.id, p.key, p.version, p.kind, p.title, p.licence_class, p.review_state, p.origin,
				EXISTS (SELECT 1 FROM compliance_org_packs o WHERE o.pack_id = p.id AND o.organization_id = $1),
				coalesce(f.key, ''), coalesce(f.version, ''), coalesce(f.text_policy, '')
			FROM compliance_packs p LEFT JOIN compliance_frameworks f ON f.pack_id = p.id
			WHERE p.origin = 'builtin' ORDER BY p.kind, p.key`, org)
		if err != nil {
			return err
		}
		type fw struct{ key, ver string }
		var fws []fw
		for rows.Next() {
			var id uuid.UUID
			var p PackInfo
			var fver string
			if err := rows.Scan(&id, &p.Key, &p.Version, &p.Kind, &p.Title, &p.LicenceClass, &p.ReviewState, &p.Origin, &p.Enabled,
				&p.Framework, &fver, &p.TextPolicy); err != nil {
				rows.Close()
				return err
			}
			if p.Key == "cis-xref" {
				p.Note = compliance.CISNote
			}
			if p.Kind == "framework" || p.Kind == "xref" {
				fws = append(fws, fw{p.Framework, fver})
			} else {
				fws = append(fws, fw{})
			}
			out = append(out, p)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		for i := range out {
			if fws[i].key == "" {
				continue
			}
			reqs, err := loadRequirements(ctx, tx, fws[i].key, fws[i].ver)
			if err != nil {
				return err
			}
			cov := rollup.CoverageOf(reqs)
			out[i].Coverage = &cov
		}
		return nil
	})
	return out, err
}

// ControlInfo is a library control as the console lists it.
type ControlInfo struct {
	ID             string           `json:"id"`
	Version        int              `json:"version"`
	Title          string           `json:"title"`
	Severity       string           `json:"severity"`
	Executor       string           `json:"executor"`
	RiskTier       string           `json:"riskTier"`
	ApplySupported bool             `json:"applySupported"`
	UndoKind       string           `json:"undoKind"`
	Platforms      json.RawMessage  `json:"platforms"`
	LicenceClass   compliance.Class `json:"licenceClass"`
	ReviewState    string           `json:"reviewState"`
	Provenance     json.RawMessage  `json:"provenance"`
}

// Controls lists the latest version of each library control, for a
// platform (windows or linux) or all.
func (s *Service) Controls(ctx context.Context, c access.Caller, platform string) ([]ControlInfo, error) {
	if !c.CanAnywhere(rbac.PermComplianceView) {
		return nil, apperr.Forbidden()
	}
	out := []ControlInfo{}
	err := s.db.ReadTx(ctx, c.Scope, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT DISTINCT ON (id) id, version, title, severity, executor, risk_tier, apply_supported, undo_kind,
				platforms, licence_class, review_state, provenance
			FROM compliance_controls WHERE $1 = '' OR platforms->>'os' = $1 ORDER BY id, version DESC`, platform)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var i ControlInfo
			if err := rows.Scan(&i.ID, &i.Version, &i.Title, &i.Severity, &i.Executor, &i.RiskTier, &i.ApplySupported, &i.UndoKind,
				&i.Platforms, &i.LicenceClass, &i.ReviewState, &i.Provenance); err != nil {
				return err
			}
			out = append(out, i)
		}
		return rows.Err()
	})
	return out, err
}

// ProfileInfo is a profile as the console lists it.
type ProfileInfo struct {
	Key          string          `json:"key"`
	Version      string          `json:"version"`
	Title        string          `json:"title"`
	Platform     json.RawMessage `json:"platform"`
	FrameworkKey *string         `json:"frameworkKey"`
	Controls     int             `json:"controls"`
}

// Profiles lists the assessment profiles.
func (s *Service) Profiles(ctx context.Context, c access.Caller) ([]ProfileInfo, error) {
	if !c.CanAnywhere(rbac.PermComplianceView) {
		return nil, apperr.Forbidden()
	}
	out := []ProfileInfo{}
	err := s.db.ReadTx(ctx, c.Scope, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT p.key, p.version, p.title, p.platform, p.framework_key,
				(SELECT count(*) FROM compliance_profile_controls pc WHERE pc.profile_key = p.key AND pc.profile_version = p.version)
			FROM compliance_profiles p ORDER BY p.key`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var i ProfileInfo
			if err := rows.Scan(&i.Key, &i.Version, &i.Title, &i.Platform, &i.FrameworkKey, &i.Controls); err != nil {
				return err
			}
			out = append(out, i)
		}
		return rows.Err()
	})
	return out, err
}

func loadRequirements(ctx context.Context, tx pgx.Tx, key, version string) ([]rollup.Requirement, error) {
	rows, err := tx.Query(ctx, `SELECT req_id, class, coalesce((flags->>'no_check_yet')::boolean, false) FROM compliance_requirements
		WHERE framework_key = $1 AND framework_version = $2 ORDER BY req_id`, key, version)
	if err != nil {
		return nil, err
	}
	var reqs []rollup.Requirement
	idx := map[string]int{}
	for rows.Next() {
		var r rollup.Requirement
		if err := rows.Scan(&r.ID, &r.Class, &r.NoCheckYet); err != nil {
			rows.Close()
			return nil, err
		}
		idx[r.ID] = len(reqs)
		reqs = append(reqs, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	mr, err := tx.Query(ctx, `SELECT req_id, control_id, relation FROM compliance_mappings WHERE framework_key = $1 AND framework_version = $2`, key, version)
	if err != nil {
		return nil, err
	}
	defer mr.Close()
	for mr.Next() {
		var req string
		var m rollup.Mapping
		if err := mr.Scan(&req, &m.ControlID, &m.Relation); err != nil {
			return nil, err
		}
		if i, ok := idx[req]; ok {
			reqs[i].Mappings = append(reqs[i].Mappings, m)
		}
	}
	return reqs, mr.Err()
}

// ---- scans ----------------------------------------------------------------------------------

// ScanInput starts a scan.
type ScanInput struct {
	// Profile is the key of the profile whose controls are read.
	Profile string `json:"profile"`
	// DeviceIDs are the computers in scope; empty means every computer of
	// the organization that has an agent.
	DeviceIDs []uuid.UUID `json:"deviceIds"`
	// Run asks the computers for a fresh check. Without it the scan reads
	// what the last hardening checks stored.
	Run bool `json:"run"`
	// WaitHours is how long to wait for an offline computer; zero is the
	// default.
	WaitHours int `json:"waitHours"`
}

// Scan is a scan and where it stands.
type Scan struct {
	ID         uuid.UUID       `json:"id"`
	OrgID      uuid.UUID       `json:"organizationId"`
	Trigger    string          `json:"trigger"`
	Selection  json.RawMessage `json:"selection"`
	State      string          `json:"state"`
	StartedAt  time.Time       `json:"startedAt"`
	FinishedAt *time.Time      `json:"finishedAt"`
	ResultHash *string         `json:"resultHash"`
	// Waiting is how many device checks have not answered yet.
	Waiting int `json:"waiting"`
}

type selection struct {
	Profile    string      `json:"profile"`
	Version    string      `json:"version"`
	Framework  *string     `json:"framework"`
	DeviceIDs  []uuid.UUID `json:"deviceIds"`
	Run        bool        `json:"run"`
	Controls   int         `json:"controls"`
	Unscanned  []string    `json:"notScanned,omitempty"`
	WaitHours  int         `json:"waitHours,omitempty"`
	Controlsum string      `json:"controlsSha256"`
}

// controlsOf loads a profile's hardening controls, at their latest versions.
func controlsOf(ctx context.Context, tx pgx.Tx, profile string) (ver string, fw *string, cs []scan.Control, other int, err error) {
	err = tx.QueryRow(ctx, `SELECT version, framework_key FROM compliance_profiles WHERE key = $1`, profile).Scan(&ver, &fw)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil, nil, 0, apperr.Invalid("profile", "There is no such profile.")
	}
	if err != nil {
		return "", nil, nil, 0, err
	}
	rows, err := tx.Query(ctx, `SELECT c.id, c.version, c.executor, c.executor_ref FROM compliance_profile_controls pc
		JOIN LATERAL (SELECT * FROM compliance_controls x WHERE x.id = pc.control_id ORDER BY x.version DESC LIMIT 1) c ON true
		WHERE pc.profile_key = $1 AND pc.profile_version = $2 ORDER BY c.id`, profile, ver)
	if err != nil {
		return "", nil, nil, 0, err
	}
	defer rows.Close()
	for rows.Next() {
		var c scan.Control
		var exec string
		var ref compliance.HardeningRef
		if err := rows.Scan(&c.ID, &c.Version, &exec, &ref); err != nil {
			return "", nil, nil, 0, err
		}
		if exec != compliance.ExecHardening {
			other++ // read by an executor a later slice adds
			continue
		}
		c.Platform, c.Module, c.Setting = ref.Platform, ref.Module, ref.Setting
		cs = append(cs, c)
	}
	return ver, fw, cs, other, rows.Err()
}

type device struct {
	id       uuid.UUID
	platform string
}

// StartScan plans and starts a scan, by a person. It needs compliance.scan
// in the organization, and an organization the dev scope lets automatic
// behavior reach.
func (s *Service) StartScan(ctx context.Context, c access.Caller, org uuid.UUID, in ScanInput) (*Scan, error) {
	if err := requireOrg(c, rbac.PermComplianceScan, org); err != nil {
		return nil, err
	}
	return s.start(ctx, c, org, in, "manual")
}

func (s *Service) start(ctx context.Context, c access.Caller, org uuid.UUID, in ScanInput, trigger string) (*Scan, error) {
	if !devscope.Allowed(org) {
		return nil, apperr.Conflict("not_available", "Compliance scans are not available for this organization in this build.")
	}
	f := apperr.Fields{}
	f.Check(in.Profile != "", "profile", "Choose a profile.")
	if err := f.Err(); err != nil {
		return nil, err
	}
	var (
		ver     string
		fw      *string
		ctrls   []scan.Control
		other   int
		devs    []device
		scanID  = uuid.New()
		started = s.now()
	)
	// The person's permission in the organization is checked; the writes are the server's, as device_hardening's are.
	err := s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		var err error
		if ver, fw, ctrls, other, err = controlsOf(ctx, tx, in.Profile); err != nil {
			return err
		}
		if len(ctrls) == 0 {
			return apperr.Invalid("profile", "This profile has no control that a computer can be asked to check.")
		}
		rows, err := tx.Query(ctx, `SELECT id, platform FROM devices WHERE organization_id = $1 AND agent_public_key IS NOT NULL
			AND platform IN ('windows', 'linux') AND (cardinality($2::uuid[]) = 0 OR id = ANY ($2)) ORDER BY id`, org, append([]uuid.UUID{}, in.DeviceIDs...))
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var d device
			if err := rows.Scan(&d.id, &d.platform); err != nil {
				return err
			}
			devs = append(devs, d)
		}
		if err := rows.Err(); err != nil {
			return err
		}
		rows.Close()
		if len(in.DeviceIDs) > 0 && len(devs) != len(dedupe(in.DeviceIDs)) {
			return apperr.Invalid("deviceIds", "Some of these computers are not in this organization or have no agent.")
		}
		// Only computers of a platform the profile has controls for are in scope.
		kept := devs[:0]
		for _, d := range devs {
			if scan.HasPlatform(ctrls, d.platform) {
				kept = append(kept, d)
			}
		}
		devs = kept
		if len(devs) == 0 {
			return apperr.Invalid("deviceIds", "There is no computer to scan: none runs a platform this profile checks.")
		}
		ids := make([]uuid.UUID, len(devs))
		for i, d := range devs {
			ids[i] = d.id
		}
		sel := selection{Profile: in.Profile, Version: ver, Framework: fw, DeviceIDs: ids, Run: in.Run, Controls: len(ctrls) + other,
			WaitHours: in.WaitHours, Controlsum: controlsSum(ctrls)}
		sj, _ := json.Marshal(sel)
		var by *uuid.UUID
		if c.Principal != nil && !c.IsSystem() {
			by = &c.Principal.UserID
		}
		if _, err := tx.Exec(ctx, `INSERT INTO compliance_scans (id, organization_id, started_by, trigger, selection, state, started_at)
			VALUES ($1, $2, $3, $4, $5, 'planned', $6)`, scanID, org, by, trigger, sj, started); err != nil {
			return err
		}
		return s.audit.Write(ctx, tx, audit.Event{Actor: c.Actor, Action: "compliance.scan_start", OrganizationID: org,
			TargetType: "compliance_scan", TargetID: scanID.String(), Outcome: audit.Success,
			Details: map[string]any{"profile": in.Profile, "devices": len(devs), "run": in.Run, "trigger": trigger}})
	})
	if err != nil {
		return nil, err
	}
	if err := s.dispatch(ctx, c, scanID, org, in, ctrls, devs); err != nil {
		_ = s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
			_, e := tx.Exec(ctx, `UPDATE compliance_scans SET state = 'failed', finished_at = now() WHERE id = $1`, scanID)
			return e
		})
		return nil, err
	}
	return s.Scan(ctx, c, org, scanID)
}

func dedupe(l []uuid.UUID) []uuid.UUID {
	seen := map[uuid.UUID]bool{}
	var out []uuid.UUID
	for _, x := range l {
		if !seen[x] {
			seen[x] = true
			out = append(out, x)
		}
	}
	return out
}

func controlsSum(cs []scan.Control) string {
	h := sha256.New()
	for _, c := range cs {
		fmt.Fprintf(h, "%s@%d\n", c.ID, c.Version)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// dispatch makes the hardening check jobs, one per platform, for the
// devices, and records them; without Run it ingests what is stored.
func (s *Service) dispatch(ctx context.Context, c access.Caller, scanID, org uuid.UUID, in ScanInput, ctrls []scan.Control, devs []device) error {
	if !in.Run {
		for _, d := range devs {
			if err := s.addScanJob(ctx, scanID, org, d.id, nil, nil, 1, false); err != nil {
				return err
			}
		}
		return s.advance(ctx, scanID)
	}
	for _, platform := range scan.Platforms {
		var ids []uuid.UUID
		for _, d := range devs {
			if d.platform == platform {
				ids = append(ids, d.id)
			}
		}
		mods := scan.Modules(ctrls, platform)
		if len(ids) == 0 || len(mods) == 0 {
			for _, id := range ids { // nothing to ask: stored results stand
				if err := s.addScanJob(ctx, scanID, org, id, nil, nil, 1, false); err != nil {
					return err
				}
			}
			continue
		}
		if err := s.queueCheck(ctx, c, scanID, org, platform, ids, mods, 1, in.WaitHours); err != nil {
			return err
		}
	}
	return s.advance(ctx, scanID)
}

// queueCheck creates the check job and its scan_jobs rows.
func (s *Service) queueCheck(ctx context.Context, c access.Caller, scanID, org uuid.UUID, platform string, ids []uuid.UUID, mods []string, attempt, wait int) error {
	h := jobs.Hardening{Mode: jobs.HardeningCheck, Modules: mods}
	if platform == compliance.PlatformWindows {
		h.Platform = jobs.HardeningWindows
	}
	job, err := s.jobs.CreateHardeningJob(ctx, c, jobs.HardeningInput{DeviceIDs: ids, Hardening: h, WaitHours: wait})
	if err != nil {
		return err
	}
	for _, id := range ids {
		jid := job.ID
		if err := s.addScanJob(ctx, scanID, org, id, &jid, mods, attempt, false); err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) addScanJob(ctx context.Context, scanID, org, device uuid.UUID, job *uuid.UUID, mods []string, attempt int, ingested bool) error {
	return s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO compliance_scan_jobs (organization_id, scan_id, device_id, job_id, modules, attempt, ingested)
			VALUES ($1, $2, $3, $4, $5, $6, $7) ON CONFLICT (scan_id, device_id, modules) DO NOTHING`,
			org, scanID, device, job, nilToEmpty(mods), attempt, ingested)
		return err
	})
}

func nilToEmpty(l []string) []string {
	if l == nil {
		return []string{}
	}
	return l
}

// Scan returns a scan, first moving it forward: results of checks that
// have finished are read in, and the scan is finished when all have.
func (s *Service) Scan(ctx context.Context, c access.Caller, org, id uuid.UUID) (*Scan, error) {
	if err := requireOrg(c, rbac.PermComplianceView, org); err != nil {
		return nil, err
	}
	var in bool
	err := s.db.ReadTx(ctx, c.Scope, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT state IN ('planned', 'running') FROM compliance_scans WHERE id = $1 AND organization_id = $2`, id, org).Scan(&in)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, apperr.NotFound()
	}
	if err != nil {
		return nil, err
	}
	if in {
		if err := s.advance(ctx, id); err != nil {
			return nil, err
		}
	}
	var out Scan
	err = s.db.ReadTx(ctx, c.Scope, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT s.id, s.organization_id, s.trigger, s.selection, s.state, s.started_at, s.finished_at, s.result_hash,
				(SELECT count(*) FROM compliance_scan_jobs j WHERE j.scan_id = s.id AND NOT j.ingested)
			FROM compliance_scans s WHERE s.id = $1 AND s.organization_id = $2`, id, org).
			Scan(&out.ID, &out.OrgID, &out.Trigger, &out.Selection, &out.State, &out.StartedAt, &out.FinishedAt, &out.ResultHash, &out.Waiting)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, apperr.NotFound()
	}
	return &out, err
}

// Scans lists an organization's scans, newest first.
func (s *Service) Scans(ctx context.Context, c access.Caller, org uuid.UUID, limit int) ([]Scan, error) {
	if err := requireOrg(c, rbac.PermComplianceView, org); err != nil {
		return nil, err
	}
	out := []Scan{}
	err := s.db.ReadTx(ctx, c.Scope, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT s.id, s.organization_id, s.trigger, s.selection, s.state, s.started_at, s.finished_at, s.result_hash,
				(SELECT count(*) FROM compliance_scan_jobs j WHERE j.scan_id = s.id AND NOT j.ingested)
			FROM compliance_scans s WHERE s.organization_id = $1 ORDER BY s.started_at DESC LIMIT $2`, org, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var x Scan
			if err := rows.Scan(&x.ID, &x.OrgID, &x.Trigger, &x.Selection, &x.State, &x.StartedAt, &x.FinishedAt, &x.ResultHash, &x.Waiting); err != nil {
				return err
			}
			out = append(out, x)
		}
		return rows.Err()
	})
	return out, err
}

// advance reads in the answer of every scan job whose check has finished,
// queues one smaller re-run for modules whose result was cut short, and
// finishes the scan when nothing is left.
func (s *Service) advance(ctx context.Context, scanID uuid.UUID) error {
	var (
		org     uuid.UUID
		selJSON []byte
		started time.Time
		state   string
	)
	type sj struct {
		id, device uuid.UUID
		job        *uuid.UUID
		modules    []string
		attempt    int
		status     *string
	}
	var todo []sj
	err := s.db.ReadTx(ctx, database.System, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `SELECT organization_id, selection, started_at, state FROM compliance_scans WHERE id = $1`, scanID).
			Scan(&org, &selJSON, &started, &state); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `SELECT j.id, j.device_id, j.job_id, j.modules, j.attempt,
				(SELECT r.status FROM job_runs r WHERE r.job_id = j.job_id AND r.device_id = j.device_id ORDER BY r.created_at DESC LIMIT 1)
			FROM compliance_scan_jobs j WHERE j.scan_id = $1 AND NOT j.ingested`, scanID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var x sj
			if err := rows.Scan(&x.id, &x.device, &x.job, &x.modules, &x.attempt, &x.status); err != nil {
				return err
			}
			todo = append(todo, x)
		}
		return rows.Err()
	})
	if err != nil {
		return err
	}
	if state != "planned" && state != "running" {
		return nil
	}
	var sel selection
	if err := json.Unmarshal(selJSON, &sel); err != nil {
		return err
	}
	var ctrls []scan.Control
	err = s.db.ReadTx(ctx, database.System, func(tx pgx.Tx) error {
		var e error
		_, _, ctrls, _, e = controlsOf(ctx, tx, sel.Profile)
		return e
	})
	if err != nil {
		return err
	}
	partial := false
	for _, t := range todo {
		terminal, failed := true, false
		if t.job != nil {
			switch *deref(t.status) {
			case "succeeded":
			case "queued", "sent", "running", "":
				terminal = false
			default:
				failed = true
			}
		}
		if !terminal {
			continue
		}
		cs := ctrls
		if len(t.modules) > 0 {
			cs = filterModules(ctrls, t.modules)
		}
		redo, err := s.ingestDevice(ctx, scanID, org, t.device, t.job, cs, failed, t.attempt, started, t.id, str(t.status))
		if err != nil {
			return err
		}
		if len(redo) > 0 {
			if t.attempt >= 2 {
				partial = true
			} else if err := s.rerun(ctx, scanID, org, t.device, ctrls, redo, sel.WaitHours); err != nil {
				s.log.Warn("compliance: queueing a smaller check failed", "scan", scanID, "error", err)
				partial = true
			}
		}
	}
	return s.finish(ctx, scanID, partial)
}

func deref(s *string) *string {
	if s == nil {
		e := ""
		return &e
	}
	return s
}

func str(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func filterModules(cs []scan.Control, mods []string) []scan.Control {
	var out []scan.Control
	for _, c := range cs {
		if slices.Contains(mods, c.Module) {
			out = append(out, c)
		}
	}
	return out
}

// rerun asks the device for the truncated modules, one job per module
// ("one module per job"), as attempt two.
func (s *Service) rerun(ctx context.Context, scanID, org, dev uuid.UUID, ctrls []scan.Control, mods []string, wait int) error {
	platform := ""
	for _, c := range ctrls {
		if slices.Contains(mods, c.Module) {
			platform = c.Platform
			break
		}
	}
	if platform == "" {
		return nil
	}
	for _, m := range mods {
		if err := s.queueCheck(ctx, access.System("compliance"), scanID, org, platform, []uuid.UUID{dev}, []string{m}, 2, wait); err != nil {
			return err
		}
	}
	return nil
}

// ingestDevice reads one device's stored modules and writes a result for
// each control of the scan job. It returns the modules to ask for again.
func (s *Service) ingestDevice(ctx context.Context, scanID, org, dev uuid.UUID, job *uuid.UUID, ctrls []scan.Control, failed bool,
	attempt int, started time.Time, sjID uuid.UUID, status string) (redo []string, err error) {
	mods := map[string]scan.ModuleRow{}
	var platform string
	err = s.db.ReadTx(ctx, database.System, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `SELECT platform FROM devices WHERE id = $1`, dev).Scan(&platform); err != nil {
			return err
		}
		if failed {
			return nil
		}
		rows, err := tx.Query(ctx, `SELECT module, state, detail, checked_at, job_id FROM device_hardening WHERE device_id = $1`, dev)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var m scan.ModuleRow
			if err := rows.Scan(&m.Module, &m.State, &m.Detail, &m.CheckedAt, &m.JobID); err != nil {
				return err
			}
			mods[m.Module] = m
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	mine := make([]scan.Control, 0, len(ctrls))
	for _, c := range ctrls {
		if c.Platform == platform {
			mine = append(mine, c)
		}
	}
	rows := scan.Ingest(mine, mods)
	if failed {
		for i := range rows {
			rows[i].CheckedAt = s.now()
			rows[i].JobID = job
			rows[i].Observed = json.RawMessage(fmt.Sprintf(`{"reason":%q}`, "the check job ended as "+status))
		}
	}
	redo = scan.TruncatedModules(mine, rows)
	if len(redo) > 0 && attempt < 2 {
		// Leave the cut-short controls for the smaller jobs; write the rest.
		keep := rows[:0]
		skip := map[string]bool{}
		for _, m := range redo {
			skip[m] = true
		}
		byID := map[string]scan.Control{}
		for _, c := range mine {
			byID[c.ID] = c
		}
		for _, r := range rows {
			if r.Truncated && skip[byID[r.ControlID].Module] {
				continue
			}
			keep = append(keep, r)
		}
		rows = keep
	}
	now := s.now()
	err = s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		batch := &pgx.Batch{}
		for _, r := range rows {
			at := r.CheckedAt
			if at.IsZero() {
				at = now
			}
			batch.Queue(`INSERT INTO compliance_results_history (organization_id, scan_id, device_id, control_id, control_version, state,
					observed, expected, owner, job_id, checked_at)
				VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) ON CONFLICT (scan_id, device_id, control_id) DO NOTHING`,
				org, scanID, dev, r.ControlID, r.ControlVersion, r.State, jsonOrNil(r.Observed), jsonOrNil(r.Expected), jsonOrNil(r.Owner), r.JobID, at)
		}
		if err := sendBatch(ctx, tx, batch); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `UPDATE compliance_scan_jobs SET ingested = true WHERE id = $1`, sjID)
		return err
	})
	return redo, err
}

func jsonOrNil(b json.RawMessage) any {
	if len(b) == 0 {
		return nil
	}
	return string(b)
}

func sendBatch(ctx context.Context, tx pgx.Tx, b *pgx.Batch) error {
	if b.Len() == 0 {
		return nil
	}
	br := tx.SendBatch(ctx, b)
	for i := 0; i < b.Len(); i++ {
		if _, err := br.Exec(); err != nil {
			_ = br.Close()
			return err
		}
	}
	return br.Close()
}

// finish closes the scan once every job is read in: done, or partial when a
// cut-short result could not be completed. The result hash covers the rows.
func (s *Service) finish(ctx context.Context, scanID uuid.UUID, partial bool) error {
	return s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		var open int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM compliance_scan_jobs WHERE scan_id = $1 AND NOT ingested`, scanID).Scan(&open); err != nil {
			return err
		}
		if open > 0 {
			_, err := tx.Exec(ctx, `UPDATE compliance_scans SET state = 'running' WHERE id = $1 AND state = 'planned'`, scanID)
			return err
		}
		var unk int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM compliance_results_history WHERE scan_id = $1 AND state = 'unknown'`, scanID).Scan(&unk); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `SELECT device_id, control_id, control_version, state, checked_at FROM compliance_results_history
			WHERE scan_id = $1 ORDER BY device_id, control_id`, scanID)
		if err != nil {
			return err
		}
		h := sha256.New()
		n := 0
		for rows.Next() {
			var d uuid.UUID
			var c, st string
			var v int
			var at time.Time
			if err := rows.Scan(&d, &c, &v, &st, &at); err != nil {
				rows.Close()
				return err
			}
			fmt.Fprintf(h, "%s|%s|%d|%s|%s\n", d, c, v, st, at.UTC().Format(time.RFC3339Nano))
			n++
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		state := "done"
		if partial || n == 0 {
			state = "partial"
		}
		if n == 0 {
			state = "failed"
		}
		_, err = tx.Exec(ctx, `UPDATE compliance_scans SET state = $2, finished_at = now(), result_hash = $3
			WHERE id = $1 AND state IN ('planned', 'running')`, scanID, state, hex.EncodeToString(h.Sum(nil)))
		return err
	})
}

// ---- reading results ------------------------------------------------------------------------

// DeviceResult is one control's latest result on a device.
type DeviceResult struct {
	ControlID string          `json:"controlId"`
	Version   int             `json:"controlVersion"`
	Title     string          `json:"title"`
	State     string          `json:"state"`
	Word      string          `json:"word"`
	Observed  json.RawMessage `json:"observed"`
	Expected  json.RawMessage `json:"expected"`
	Owner     json.RawMessage `json:"owner"`
	CheckedAt time.Time       `json:"checkedAt"`
	ScanID    uuid.UUID       `json:"scanId"`
}

// DeviceResults are the latest results on a device, with stale ones named
// as such, and the organization's freshness window applied.
func (s *Service) DeviceResults(ctx context.Context, c access.Caller, device uuid.UUID) ([]DeviceResult, error) {
	var org, site uuid.UUID
	err := s.db.ReadTx(ctx, c.Scope, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT organization_id, site_id FROM devices WHERE id = $1`, device).Scan(&org, &site)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, apperr.NotFound()
	}
	if err != nil {
		return nil, err
	}
	if !c.Can(rbac.PermComplianceView, rbac.Org(org)) {
		return nil, apperr.NotFound()
	}
	out := []DeviceResult{}
	now := s.now()
	err = s.db.ReadTx(ctx, c.Scope, func(tx pgx.Tx) error {
		fresh, err := freshness(ctx, tx, org)
		if err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `SELECT r.control_id, r.control_version, coalesce(c.title, ''), r.state, r.observed, r.expected, r.owner, r.checked_at, r.scan_id
			FROM compliance_results r LEFT JOIN compliance_controls c ON c.id = r.control_id AND c.version = r.control_version
			WHERE r.device_id = $1 AND r.organization_id = $2 ORDER BY r.control_id`, device, org)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var d DeviceResult
			if err := rows.Scan(&d.ControlID, &d.Version, &d.Title, &d.State, &d.Observed, &d.Expected, &d.Owner, &d.CheckedAt, &d.ScanID); err != nil {
				return err
			}
			d.State = rollup.EffectiveState(rollup.Result{State: d.State, CheckedAt: d.CheckedAt}, now, fresh)
			d.Word = compliance.ResultWord(d.State)
			out = append(out, d)
		}
		return rows.Err()
	})
	return out, err
}

func freshness(ctx context.Context, tx pgx.Tx, org uuid.UUID) (time.Duration, error) {
	days := 30
	err := tx.QueryRow(ctx, `SELECT freshness_days FROM compliance_org_settings WHERE organization_id = $1`, org).Scan(&days)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return 0, err
	}
	return time.Duration(days) * 24 * time.Hour, nil
}

// FrameworkStatus is a framework's roll-up for an organization.
type FrameworkStatus struct {
	Framework  string            `json:"framework"`
	Version    string            `json:"version"`
	Title      string            `json:"title"`
	ScanID     *uuid.UUID        `json:"scanId"`
	Coverage   rollup.Coverage   `json:"coverage"`
	Counts     map[string]int    `json:"counts"`
	Outcomes   []rollup.Outcome  `json:"requirements"`
	InScope    int               `json:"inScope"`
	OutOfScope []uuid.UUID       `json:"outOfScope"`
	Disclaimer string            `json:"disclaimer"`
	Notes      []string          `json:"notes,omitempty"`
	Titles     map[string]string `json:"titles"`
}

// Framework rolls a framework's requirements up from an organization's
// latest results. The computers in scope are those of its latest scan that
// finished (or all of the organization's computers that have results when
// there is none); computers with results outside that scan are listed out
// of scope.
func (s *Service) Framework(ctx context.Context, c access.Caller, org uuid.UUID, key string) (*FrameworkStatus, error) {
	if err := requireOrg(c, rbac.PermComplianceView, org); err != nil {
		return nil, err
	}
	out := &FrameworkStatus{Framework: key, Disclaimer: compliance.Disclaimer, Counts: map[string]int{}, Titles: map[string]string{}}
	now := s.now()
	err := s.db.ReadTx(ctx, c.Scope, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `SELECT version, title FROM compliance_frameworks WHERE key = $1`, key).Scan(&out.Version, &out.Title); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return apperr.NotFound()
			}
			return err
		}
		reqs, err := loadRequirements(ctx, tx, key, out.Version)
		if err != nil {
			return err
		}
		out.Coverage = rollup.CoverageOf(reqs)
		tr, err := tx.Query(ctx, `SELECT req_id, title_own FROM compliance_requirements WHERE framework_key = $1 AND framework_version = $2`, key, out.Version)
		if err != nil {
			return err
		}
		for tr.Next() {
			var id, t string
			if err := tr.Scan(&id, &t); err != nil {
				tr.Close()
				return err
			}
			out.Titles[id] = t
		}
		tr.Close()
		fresh, err := freshness(ctx, tx, org)
		if err != nil {
			return err
		}
		var sid uuid.UUID
		var selJSON []byte
		err = tx.QueryRow(ctx, `SELECT id, selection FROM compliance_scans WHERE organization_id = $1 AND state IN ('done', 'partial')
			ORDER BY started_at DESC LIMIT 1`, org).Scan(&sid, &selJSON)
		var in []uuid.UUID
		switch {
		case err == nil:
			out.ScanID = &sid
			var sel selection
			if err := json.Unmarshal(selJSON, &sel); err != nil {
				return err
			}
			in = sel.DeviceIDs
		case errors.Is(err, pgx.ErrNoRows):
			out.Notes = append(out.Notes, "No scan has finished yet.")
		default:
			return err
		}
		ctrl := map[string]bool{}
		for _, r := range reqs {
			for _, m := range r.Mappings {
				ctrl[m.ControlID] = true
			}
		}
		ids := make([]string, 0, len(ctrl))
		for id := range ctrl {
			ids = append(ids, id)
		}
		results := map[string]map[uuid.UUID]rollup.Result{}
		have := map[uuid.UUID]bool{}
		rr, err := tx.Query(ctx, `SELECT control_id, device_id, state, checked_at, owner FROM compliance_results
			WHERE organization_id = $1 AND control_id = ANY ($2)`, org, ids)
		if err != nil {
			return err
		}
		defer rr.Close()
		for rr.Next() {
			var cid string
			var d uuid.UUID
			var r rollup.Result
			var owner []byte
			if err := rr.Scan(&cid, &d, &r.State, &r.CheckedAt, &owner); err != nil {
				return err
			}
			if len(owner) > 0 {
				var o struct {
					Name  string `json:"name"`
					Meets bool   `json:"meets"`
				}
				if json.Unmarshal(owner, &o) == nil {
					r.Owner = &rollup.Owner{Name: o.Name, Meets: &o.Meets}
				}
			}
			if results[cid] == nil {
				results[cid] = map[uuid.UUID]rollup.Result{}
			}
			results[cid][d] = r
			have[d] = true
		}
		if err := rr.Err(); err != nil {
			return err
		}
		scoped := map[uuid.UUID]bool{}
		for _, d := range in {
			scoped[d] = true
		}
		var outScope []uuid.UUID
		for d := range have {
			if !scoped[d] {
				outScope = append(outScope, d)
			}
		}
		sort.Slice(outScope, func(i, j int) bool { return outScope[i].String() < outScope[j].String() })
		out.OutOfScope = outScope
		out.InScope = len(in)
		out.Outcomes = rollup.Compute(rollup.Input{Requirements: reqs, Results: results, InScope: in, OutOfScope: outScope, Now: now, Fresh: fresh})
		for _, o := range out.Outcomes {
			out.Counts[string(o.Status)]++
		}
		if key == "cis-xref" {
			out.Notes = append(out.Notes, compliance.CISNote)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// ---- settings and scheduling ------------------------------------------------------------------

// Settings are an organization's compliance settings.
type Settings struct {
	Enabled       bool    `json:"enabled"`
	FreshnessDays int     `json:"freshnessDays"`
	ScanSchedule  *string `json:"scanSchedule"`
	ScanProfile   *string `json:"scanProfile"`
}

// GetSettings reads an organization's settings; the defaults when none are
// stored (off, 30 days, no schedule).
func (s *Service) GetSettings(ctx context.Context, c access.Caller, org uuid.UUID) (*Settings, error) {
	if err := requireOrg(c, rbac.PermComplianceView, org); err != nil {
		return nil, err
	}
	out := &Settings{FreshnessDays: 30}
	err := s.db.ReadTx(ctx, c.Scope, func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx, `SELECT enabled, freshness_days, scan_schedule, scan_profile FROM compliance_org_settings WHERE organization_id = $1`, org).
			Scan(&out.Enabled, &out.FreshnessDays, &out.ScanSchedule, &out.ScanProfile)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		return err
	})
	return out, err
}

// PutSettings stores an organization's settings. It needs compliance.edit.
func (s *Service) PutSettings(ctx context.Context, c access.Caller, org uuid.UUID, in Settings) (*Settings, error) {
	if err := requireOrg(c, rbac.PermComplianceEdit, org); err != nil {
		return nil, err
	}
	f := apperr.Fields{}
	f.Check(in.FreshnessDays >= 1 && in.FreshnessDays <= 365, "freshnessDays", "Choose 1 to 365 days.")
	f.Check(in.ScanSchedule == nil || *in.ScanSchedule == "weekly", "scanSchedule", "Choose weekly, or no schedule.")
	f.Check(in.ScanSchedule == nil || in.ScanProfile != nil && *in.ScanProfile != "", "scanProfile", "A schedule needs a profile.")
	if err := f.Err(); err != nil {
		return nil, err
	}
	err := s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		if in.ScanProfile != nil {
			var n int
			if err := tx.QueryRow(ctx, `SELECT count(*) FROM compliance_profiles WHERE key = $1`, *in.ScanProfile).Scan(&n); err != nil {
				return err
			}
			if n == 0 {
				return apperr.Invalid("scanProfile", "There is no such profile.")
			}
		}
		if _, err := tx.Exec(ctx, `INSERT INTO compliance_org_settings (organization_id, enabled, freshness_days, scan_schedule, scan_profile, updated_at)
			VALUES ($1, $2, $3, $4, $5, now())
			ON CONFLICT (organization_id) DO UPDATE SET enabled = EXCLUDED.enabled, freshness_days = EXCLUDED.freshness_days,
				scan_schedule = EXCLUDED.scan_schedule, scan_profile = EXCLUDED.scan_profile, updated_at = now()`,
			org, in.Enabled, in.FreshnessDays, in.ScanSchedule, in.ScanProfile); err != nil {
			return err
		}
		return s.audit.Write(ctx, tx, audit.Event{Actor: c.Actor, Action: "compliance.settings_update", OrganizationID: org,
			TargetType: "organization", TargetID: org.String(), Outcome: audit.Success,
			Details: map[string]any{"enabled": in.Enabled, "freshnessDays": in.FreshnessDays, "schedule": in.ScanSchedule}})
	})
	if err != nil {
		return nil, err
	}
	return s.GetSettings(ctx, c, org)
}

// ScheduleInterval is how often a weekly scan is due.
const ScheduleInterval = 7 * 24 * time.Hour

// Tick starts the scheduled scans that are due: organizations that turned
// the module on and chose a weekly schedule, with no scan in the last
// week. Every organization is checked against the dev scope first
// (ADR-0078, section 4). It returns how many scans it started.
func (s *Service) Tick(ctx context.Context) (int, error) {
	type due struct {
		org     uuid.UUID
		profile string
	}
	var list []due
	err := s.db.ReadTx(ctx, database.System, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT o.organization_id, o.scan_profile FROM compliance_org_settings o
			WHERE o.enabled AND o.scan_schedule = 'weekly' AND o.scan_profile IS NOT NULL
			AND NOT EXISTS (SELECT 1 FROM compliance_scans s WHERE s.organization_id = o.organization_id AND s.started_at > $1)`, s.now().Add(-ScheduleInterval))
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var d due
			if err := rows.Scan(&d.org, &d.profile); err != nil {
				return err
			}
			list = append(list, d)
		}
		return rows.Err()
	})
	if err != nil {
		return 0, err
	}
	n := 0
	for _, d := range list {
		if !devscope.Allowed(d.org) {
			continue
		}
		if _, err := s.start(ctx, access.System("compliance"), d.org, ScanInput{Profile: d.profile, Run: true}, "schedule"); err != nil {
			s.log.Warn("compliance: a scheduled scan did not start", "organization_id", d.org, "error", err)
			continue
		}
		n++
	}
	return n, nil
}

// Run ticks the schedule hourly until ctx ends, and finishes scans that
// were waiting on checks.
func (s *Service) Run(ctx context.Context) {
	t := time.NewTicker(time.Hour)
	defer t.Stop()
	for {
		if _, err := s.Tick(ctx); err != nil && ctx.Err() == nil {
			s.log.Error("compliance: the scan schedule failed", "error", err)
		}
		if err := s.AdvanceOpen(ctx); err != nil && ctx.Err() == nil {
			s.log.Error("compliance: advancing scans failed", "error", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// AdvanceOpen moves every unfinished scan forward.
func (s *Service) AdvanceOpen(ctx context.Context) error {
	var ids []uuid.UUID
	err := s.db.ReadTx(ctx, database.System, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT id FROM compliance_scans WHERE state IN ('planned', 'running')`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var id uuid.UUID
			if err := rows.Scan(&id); err != nil {
				return err
			}
			ids = append(ids, id)
		}
		return rows.Err()
	})
	if err != nil {
		return err
	}
	for _, id := range ids {
		if err := s.advance(ctx, id); err != nil {
			return err
		}
	}
	return nil
}
