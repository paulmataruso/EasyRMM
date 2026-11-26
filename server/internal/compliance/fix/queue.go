package fix

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/server/internal/access"
	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/compliance/content"
	"github.com/paulmataruso/easyrmm/server/internal/compliance/engine"
	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/devscope"
	"github.com/paulmataruso/easyrmm/server/internal/jobs"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
)

// Item states (migration 90321).
const (
	StateOpen        = "open"
	StateAwaiting    = "awaiting_approval"
	StateApplying    = "applying"
	StateApplied     = "applied"
	StateVerified    = "verified"
	StateNotVerified = "not_verified"
	StateFailed      = "failed"
	StateUndoing     = "undoing"
	StateUndone      = "undone"
	StateDeclined    = "declined"
	StateResolved    = "resolved"
)

// activeStates are the states of an item that is still in the queue.
var activeStates = []string{StateOpen, StateAwaiting, StateApplying, StateApplied, StateNotVerified, StateUndoing, StateDeclined}

// Service is the fix queue.
type Service struct {
	db       *database.DB
	jobs     *jobs.Service
	eng      *engine.Service
	audit    *audit.Logger
	log      *slog.Logger
	now      func() time.Time
	stepUp   jobs.StepUpVerifier
	warnings map[string]content.Warning
}

// New builds the queue and registers it with the engine, which tells it
// when a scan finishes. It fails if the embedded warnings cannot be read.
func New(db *database.DB, j *jobs.Service, eng *engine.Service, auditLog *audit.Logger, log *slog.Logger) (*Service, error) {
	w, err := content.Warnings()
	if err != nil {
		return nil, err
	}
	s := &Service{db: db, jobs: j, eng: eng, audit: auditLog, log: log, now: time.Now, warnings: w}
	eng.SetOnScanDone(s.onScanDone)
	return s, nil
}

// SetStepUp gives the queue the step-up check. Without one, a change of
// tier 3 is refused (ADR-0078: T3 is disabled until step-up ships).
func (s *Service) SetStepUp(v jobs.StepUpVerifier) { s.stepUp = v }

// SetClock replaces the clock, for tests.
func (s *Service) SetClock(now func() time.Time) { s.now = now }

// Requirement is a framework requirement a fix would help (a link for the
// person's benefit, never a claim).
type Requirement struct {
	Framework string `json:"framework"`
	ID        string `json:"id"`
}

// Decline is why an item was set aside.
type Decline struct {
	Kind      string     `json:"kind"`
	Reason    string     `json:"reason"`
	ExpiresAt *time.Time `json:"expiresAt"`
	By        *uuid.UUID `json:"by"`
}

// Item is one failed control on one computer, as the console shows it.
type Item struct {
	ID         uuid.UUID       `json:"id"`
	OrgID      uuid.UUID       `json:"organizationId"`
	DeviceID   uuid.UUID       `json:"deviceId"`
	SiteID     uuid.UUID       `json:"siteId"`
	DeviceName string          `json:"deviceName"`
	Platform   string          `json:"platform"`
	ControlID  string          `json:"controlId"`
	Version    int             `json:"controlVersion"`
	Title      string          `json:"title"`
	Severity   string          `json:"severity"`
	Tier       string          `json:"tier"`
	State      string          `json:"state"`
	Observed   json.RawMessage `json:"observed"`
	Expected   json.RawMessage `json:"expected"`
	// Warning is the text the item is agreed under; Preconditions are
	// shown with it and recorded with the agreement.
	Warning       *content.Warning `json:"warning"`
	Preconditions []string         `json:"preconditions"`
	UndoKind      string           `json:"undoKind"`
	NeedsRestart  bool             `json:"needsRestart"`
	Requirements  []Requirement    `json:"requirements"`
	// ApplyBlocked says why no Apply is offered ("" when it is).
	ApplyBlocked string `json:"applyBlocked"`
	// RequiresTyped, RequiresStepUp and RequiresApproval are what a fix of
	// this item needs besides the agreement.
	RequiresTyped    bool `json:"requiresTyped"`
	RequiresStepUp   bool `json:"requiresStepUp"`
	RequiresApproval bool `json:"requiresApproval"`
	CanUndo          bool `json:"canUndo"`
	// Outcome is what the job reported for the setting: its value before
	// and after and when it changed.
	Outcome     json.RawMessage `json:"outcome"`
	FailReason  string          `json:"failReason"`
	Decline     *Decline        `json:"decline"`
	ApplyJobID  *uuid.UUID      `json:"applyJobId"`
	UndoJobID   *uuid.UUID      `json:"undoJobId"`
	RequestedBy *uuid.UUID      `json:"requestedBy"`
	CreatedAt   time.Time       `json:"createdAt"`
	UpdatedAt   time.Time       `json:"updatedAt"`
}

// itemRow is a row of the items query with the control's columns.
type itemRow struct {
	Item
	warningID string
	applyRef  json.RawMessage
	precond   json.RawMessage
	declKind  *string
	declWhy   *string
	declExp   *time.Time
	declBy    *uuid.UUID
}

const itemSelect = `SELECT i.id, i.organization_id, i.device_id, d.name, coalesce(c.platforms->>'os', d.platform), i.control_id, i.control_version,
		coalesce(c.title, i.control_id), coalesce(c.severity, ''), i.tier, i.state, i.observed, i.expected, i.apply_job_id, i.undo_job_id,
		i.outcome, i.fail_reason, i.decline_kind, i.decline_reason, i.decline_expires, i.declined_by, i.requested_by, i.created_at, i.updated_at,
		coalesce(c.warning_id, ''), coalesce(c.undo_kind, 'none'), coalesce(c.needs_restart, false), c.apply_ref, coalesce(c.preconditions, '[]'::jsonb), d.site_id
	FROM compliance_fix_items i JOIN devices d ON d.id = i.device_id
	LEFT JOIN compliance_controls c ON c.id = i.control_id AND c.version = i.control_version`

func scanItem(rows pgx.Rows) (*itemRow, error) {
	var r itemRow
	err := rows.Scan(&r.ID, &r.OrgID, &r.DeviceID, &r.DeviceName, &r.Platform, &r.ControlID, &r.Version, &r.Title, &r.Severity, &r.Tier,
		&r.State, &r.Observed, &r.Expected, &r.ApplyJobID, &r.UndoJobID, &r.Outcome, &r.FailReason, &r.declKind, &r.declWhy, &r.declExp,
		&r.declBy, &r.RequestedBy, &r.CreatedAt, &r.UpdatedAt, &r.warningID, &r.UndoKind, &r.NeedsRestart, &r.applyRef, &r.precond, &r.SiteID)
	return &r, err
}

// applyRef is the part of a control's apply reference the queue reads.
type applyRef struct {
	Platform string   `json:"platform"`
	Modules  []string `json:"modules"`
	Settings []string `json:"settings"`
}

// setting is the one setting id a control's fix changes, and why it is not
// offered when there is none. Windows controls name their setting; a Linux
// control's apply is a whole module's, which would change more than the
// one control the person agreed to (section 6: "a fix must change one
// control"), so no Apply is offered for it until the Linux script takes
// setting ids.
func (r *itemRow) setting() (string, string) {
	var a applyRef
	if len(r.applyRef) == 0 || json.Unmarshal(r.applyRef, &a) != nil || len(r.applyRef) == 4 {
		return "", "This control has no automatic fix."
	}
	if len(a.Settings) != 1 {
		return "", "The fix for this control changes a whole group of settings at once, which is more than the one control you would agree to. Make the change by hand, or from the Hardening tab."
	}
	return a.Settings[0], ""
}

// finish fills what depends on the warning table and the organization.
func (s *Service) finish(r *itemRow, approval []string) Item {
	it := r.Item
	if w, ok := s.warnings[r.warningID]; ok {
		it.Warning = &w
		it.RequiresTyped, it.RequiresStepUp = w.TypedRequired, w.StepUpRequired
	}
	it.RequiresTyped = it.RequiresTyped || it.Tier == T3
	it.RequiresStepUp = it.RequiresStepUp || it.Tier == T3
	it.RequiresApproval = slices.Contains(approval, it.Tier)
	it.Preconditions = preconditions(r)
	if _, why := r.setting(); why != "" {
		it.ApplyBlocked = why
	}
	if r.declKind != nil {
		it.Decline = &Decline{Kind: *r.declKind, Reason: strVal(r.declWhy), ExpiresAt: r.declExp, By: r.declBy}
	}
	it.CanUndo = (it.State == StateApplied || it.State == StateVerified || it.State == StateNotVerified) && it.UndoKind != "none" && it.ApplyBlocked == ""
	if it.Requirements == nil {
		it.Requirements = []Requirement{}
	}
	return it
}

func strVal(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

// preconditions are the lines shown with the warning and recorded with the
// agreement: the control's own, and what the queue knows about the change.
func preconditions(r *itemRow) []string {
	var own []string
	if json.Unmarshal(r.precond, &own) != nil {
		own = nil
	}
	out := append([]string{}, own...)
	if r.NeedsRestart {
		out = append(out, "The change takes effect after a restart of the computer. EasyRMM never restarts it.")
	}
	if r.UndoKind == "none" {
		out = append(out, "This change cannot be undone from here.")
	}
	if r.Tier == T3 && r.Platform == "windows" {
		out = append(out, fmt.Sprintf("The computer undoes the change by itself after %d minutes unless the agent reports back.", jobs.GuardMinutes))
	}
	return out
}

// Filter narrows a list of items.
type Filter struct {
	DeviceID uuid.UUID
	SiteID   uuid.UUID
	// State is "active" (the default: still in the queue), "history" (done or set aside), "all", or one state.
	State string
	Tier  string
	Limit int
}

// requireView checks that the caller may see the organization's results.
func requireView(c access.Caller, org uuid.UUID) error {
	if !c.Can(rbac.PermComplianceView, rbac.Org(org)) {
		return apperr.NotFound()
	}
	return nil
}

// Queue lists an organization's items, advancing those whose job has
// finished first.
func (s *Service) Queue(ctx context.Context, c access.Caller, org uuid.UUID, f Filter) ([]Item, error) {
	if err := requireView(c, org); err != nil {
		return nil, err
	}
	if err := s.advanceOrg(ctx, org); err != nil {
		s.log.Warn("compliance: advancing fix items failed", "organization_id", org, "error", err)
	}
	var out []Item
	err := s.db.ReadTx(ctx, c.Scope, func(tx pgx.Tx) error {
		var err error
		out, err = s.list(ctx, tx, org, f)
		return err
	})
	if out == nil {
		out = []Item{}
	}
	return out, err
}

func (s *Service) approvalTiers(ctx context.Context, tx pgx.Tx, org uuid.UUID) ([]string, error) {
	var t []string
	err := tx.QueryRow(ctx, `SELECT require_approval FROM compliance_fix_settings WHERE organization_id = $1`, org).Scan(&t)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return t, err
}

func (s *Service) list(ctx context.Context, tx pgx.Tx, org uuid.UUID, f Filter) ([]Item, error) {
	if f.Limit <= 0 || f.Limit > 500 {
		f.Limit = 200
	}
	where := []string{"i.organization_id = $1"}
	args := []any{org}
	add := func(cond string, v any) {
		args = append(args, v)
		where = append(where, fmt.Sprintf(cond, len(args)))
	}
	// A fix that was verified stays in the queue for a week, so it can be undone from there; after that it is history.
	const inQueue = "(i.state = ANY ($%d) OR (i.state = 'verified' AND i.updated_at > now() - interval '7 days'))"
	switch f.State {
	case "", "active":
		add(inQueue, activeStates)
	case "history":
		add("NOT "+inQueue, activeStates)
	case "all":
	default:
		add("i.state = $%d", f.State)
	}
	if f.DeviceID != uuid.Nil {
		add("i.device_id = $%d", f.DeviceID)
	}
	if f.SiteID != uuid.Nil {
		add("d.site_id = $%d", f.SiteID)
	}
	if f.Tier != "" {
		add("i.tier = $%d", f.Tier)
	}
	args = append(args, f.Limit)
	rows, err := tx.Query(ctx, itemSelect+" WHERE "+strings.Join(where, " AND ")+
		fmt.Sprintf(" ORDER BY i.updated_at DESC, i.tier DESC, i.control_id LIMIT $%d", len(args)), args...)
	if err != nil {
		return nil, err
	}
	var raw []*itemRow
	for rows.Next() {
		r, err := scanItem(rows)
		if err != nil {
			rows.Close()
			return nil, err
		}
		raw = append(raw, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	approval, err := s.approvalTiers(ctx, tx, org)
	if err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(raw))
	for _, r := range raw {
		ids = append(ids, r.ControlID)
	}
	reqs := map[string][]Requirement{}
	if len(ids) > 0 {
		mr, err := tx.Query(ctx, `SELECT DISTINCT control_id, framework_key, req_id FROM compliance_mappings WHERE control_id = ANY ($1)
			ORDER BY control_id, framework_key, req_id`, ids)
		if err != nil {
			return nil, err
		}
		for mr.Next() {
			var cid string
			var q Requirement
			if err := mr.Scan(&cid, &q.Framework, &q.ID); err != nil {
				mr.Close()
				return nil, err
			}
			reqs[cid] = append(reqs[cid], q)
		}
		mr.Close()
		if err := mr.Err(); err != nil {
			return nil, err
		}
	}
	out := make([]Item, 0, len(raw))
	for _, r := range raw {
		r.Requirements = reqs[r.ControlID]
		out = append(out, s.finish(r, approval))
	}
	return out, nil
}

// Agreement is one recorded agreement.
type AgreementRecord struct {
	ID            uuid.UUID       `json:"id"`
	Act           string          `json:"act"`
	UserID        *uuid.UUID      `json:"userId"`
	At            time.Time       `json:"at"`
	WarningID     string          `json:"warningId"`
	WarningSHA256 string          `json:"warningSha256"`
	Version       int             `json:"controlVersion"`
	Typed         *string         `json:"typedText"`
	StepUp        bool            `json:"stepUp"`
	Preconditions json.RawMessage `json:"preconditions"`
}

// ItemDetail is an item with its history of agreements.
type ItemDetail struct {
	Item
	Agreements []AgreementRecord `json:"agreements"`
}

// Get returns one item with its agreements.
func (s *Service) Get(ctx context.Context, c access.Caller, org, id uuid.UUID) (*ItemDetail, error) {
	if err := requireView(c, org); err != nil {
		return nil, err
	}
	var out *ItemDetail
	err := s.db.ReadTx(ctx, c.Scope, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, itemSelect+" WHERE i.organization_id = $1 AND i.id = $2", org, id)
		if err != nil {
			return err
		}
		var r *itemRow
		if rows.Next() {
			if r, err = scanItem(rows); err != nil {
				rows.Close()
				return err
			}
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		if r == nil {
			return apperr.NotFound()
		}
		approval, err := s.approvalTiers(ctx, tx, org)
		if err != nil {
			return err
		}
		out = &ItemDetail{Item: s.finish(r, approval), Agreements: []AgreementRecord{}}
		ar, err := tx.Query(ctx, `SELECT id, act, user_id, agreed_at, warning_id, warning_sha256, control_version, typed_text, step_up, preconditions
			FROM compliance_fix_agreements WHERE item_id = $1 ORDER BY agreed_at, id`, id)
		if err != nil {
			return err
		}
		defer ar.Close()
		for ar.Next() {
			var a AgreementRecord
			if err := ar.Scan(&a.ID, &a.Act, &a.UserID, &a.At, &a.WarningID, &a.WarningSHA256, &a.Version, &a.Typed, &a.StepUp, &a.Preconditions); err != nil {
				return err
			}
			out.Agreements = append(out.Agreements, a)
		}
		return ar.Err()
	})
	return out, err
}

// Settings are an organization's fix-queue settings.
type Settings struct {
	// RequireApproval are the tiers whose fixes wait for a second person.
	RequireApproval []string `json:"requireApproval"`
}

// GetSettings reads them (none required by default).
func (s *Service) GetSettings(ctx context.Context, c access.Caller, org uuid.UUID) (*Settings, error) {
	if err := requireView(c, org); err != nil {
		return nil, err
	}
	out := &Settings{RequireApproval: []string{}}
	err := s.db.ReadTx(ctx, c.Scope, func(tx pgx.Tx) error {
		t, err := s.approvalTiers(ctx, tx, org)
		if t != nil {
			out.RequireApproval = t
		}
		return err
	})
	return out, err
}

// PutSettings stores them. It needs compliance.edit.
func (s *Service) PutSettings(ctx context.Context, c access.Caller, org uuid.UUID, in Settings) (*Settings, error) {
	if !c.Can(rbac.PermComplianceEdit, rbac.Org(org)) {
		return nil, apperr.NotFound()
	}
	seen := map[string]bool{}
	tiers := []string{}
	for _, t := range in.RequireApproval {
		if t != T1 && t != T2 && t != T3 {
			return nil, apperr.Invalid("requireApproval", "Choose from T1, T2 and T3.")
		}
		if !seen[t] {
			seen[t] = true
			tiers = append(tiers, t)
		}
	}
	slices.Sort(tiers)
	err := s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO compliance_fix_settings (organization_id, require_approval, updated_at) VALUES ($1, $2, now())
			ON CONFLICT (organization_id) DO UPDATE SET require_approval = EXCLUDED.require_approval, updated_at = now()`, org, tiers); err != nil {
			return err
		}
		return s.audit.Write(ctx, tx, audit.Event{Actor: c.Actor, Action: "compliance.fix.settings_update", OrganizationID: org,
			TargetType: "organization", TargetID: org.String(), Outcome: audit.Success, Details: map[string]any{"requireApproval": tiers}})
	})
	if err != nil {
		return nil, err
	}
	return s.GetSettings(ctx, c, org)
}

// ---- keeping the queue in step with the results ---------------------------------------------

// Sync makes an item for each fixable control that does not meet, closes
// the open items whose control now meets, and reopens deferred items whose
// time is up. It is automatic behavior, refused for an organization
// outside the development scope, and for one that has not turned the module
// on. It never duplicates an item: one is open per computer and control.
func (s *Service) Sync(ctx context.Context, org uuid.UUID) error {
	if !devscope.Allowed(org) {
		return nil
	}
	return s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		var on bool
		if err := tx.QueryRow(ctx, `SELECT coalesce((SELECT enabled FROM compliance_org_settings WHERE organization_id = $1), false)`, org).Scan(&on); err != nil {
			return err
		}
		if !on {
			return nil
		}
		now := s.now()
		// A deferred item whose time is up is open again.
		if _, err := tx.Exec(ctx, `UPDATE compliance_fix_items SET state = 'open', decline_kind = NULL, decline_reason = NULL,
				decline_expires = NULL, declined_by = NULL, updated_at = $2
			WHERE organization_id = $1 AND state = 'declined' AND decline_kind = 'deferred' AND decline_expires <= $2`, org, now); err != nil {
			return err
		}
		// An item whose re-scan could not say, and whose control meets now, is verified.
		if _, err := tx.Exec(ctx, `UPDATE compliance_fix_items i SET state = 'verified', fail_reason = '', updated_at = $2
			WHERE i.organization_id = $1 AND i.state = 'not_verified'
			AND EXISTS (SELECT 1 FROM compliance_results r WHERE r.device_id = i.device_id AND r.control_id = i.control_id AND r.state = 'in_place')`, org, now); err != nil {
			return err
		}
		// Items whose control meets now, without a fix from here, are resolved.
		if _, err := tx.Exec(ctx, `UPDATE compliance_fix_items i SET state = 'resolved', updated_at = $2
			WHERE i.organization_id = $1 AND i.state IN ('open', 'awaiting_approval', 'declined')
			AND EXISTS (SELECT 1 FROM compliance_results r WHERE r.device_id = i.device_id AND r.control_id = i.control_id AND r.state = 'in_place')`, org, now); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `SELECT r.device_id, r.control_id, r.control_version, r.observed, r.expected, c.risk_tier,
				coalesce(c.platforms->>'os', ''), coalesce(c.apply_ref->'settings'->>0, '')
			FROM compliance_results r
			JOIN compliance_controls c ON c.id = r.control_id AND c.version = r.control_version
			JOIN devices d ON d.id = r.device_id AND d.organization_id = r.organization_id
			WHERE r.organization_id = $1 AND r.state IN ('not_in_place', 'partly', 'half_applied')
			AND c.apply_supported AND c.risk_tier IN ('T1', 'T2', 'T3')`, org)
		if err != nil {
			return err
		}
		type cand struct {
			dev            uuid.UUID
			control        string
			version        int
			observed, want json.RawMessage
			tier           string
		}
		var cs []cand
		for rows.Next() {
			var x cand
			var tier, platform, setting string
			if err := rows.Scan(&x.dev, &x.control, &x.version, &x.observed, &x.want, &tier, &platform, &setting); err != nil {
				rows.Close()
				return err
			}
			x.tier = Effective(tier, platform, setting)
			cs = append(cs, x)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		batch := &pgx.Batch{}
		for _, x := range cs {
			batch.Queue(`INSERT INTO compliance_fix_items (organization_id, device_id, control_id, control_version, tier, state, observed, expected)
				VALUES ($1, $2, $3, $4, $5, 'open', $6, $7)
				ON CONFLICT (device_id, control_id) WHERE state IN ('open', 'awaiting_approval', 'applying', 'applied', 'not_verified', 'undoing', 'declined') DO NOTHING`,
				org, x.dev, x.control, x.version, x.tier, nilJSON(x.observed), nilJSON(x.want))
		}
		br := tx.SendBatch(ctx, batch)
		for range cs {
			if _, err := br.Exec(); err != nil {
				_ = br.Close()
				return err
			}
		}
		return br.Close()
	})
}

func nilJSON(b json.RawMessage) any {
	if len(b) == 0 {
		return nil
	}
	return []byte(b)
}

// onScanDone is the engine's notice that a scan finished.
func (s *Service) onScanDone(ctx context.Context, scanID, org uuid.UUID, trigger string) {
	if trigger == "verify" {
		if err := s.finishVerify(ctx, scanID, org); err != nil {
			s.log.Warn("compliance: reading a verification scan failed", "scan", scanID, "error", err)
		}
	}
	if err := s.Sync(ctx, org); err != nil {
		s.log.Warn("compliance: syncing the fix queue failed", "organization_id", org, "error", err)
	}
}

// Run advances the items whose jobs run, and syncs every organization that
// has the module on, until ctx ends. Syncing is also automatic behavior
// and is checked against the development scope inside Sync.
func (s *Service) Run(ctx context.Context) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	n := 0
	for {
		if err := s.AdvanceOpen(ctx); err != nil && ctx.Err() == nil {
			s.log.Error("compliance: advancing fix items failed", "error", err)
		}
		if n%60 == 0 { // hourly: the deferred items whose time is up
			if err := s.SyncAll(ctx); err != nil && ctx.Err() == nil {
				s.log.Error("compliance: syncing the fix queue failed", "error", err)
			}
		}
		n++
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// SyncAll syncs every organization that has the module on.
func (s *Service) SyncAll(ctx context.Context) error {
	var orgs []uuid.UUID
	err := s.db.ReadTx(ctx, database.System, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT organization_id FROM compliance_org_settings WHERE enabled`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var o uuid.UUID
			if err := rows.Scan(&o); err != nil {
				return err
			}
			orgs = append(orgs, o)
		}
		return rows.Err()
	})
	if err != nil {
		return err
	}
	for _, o := range orgs {
		if err := s.Sync(ctx, o); err != nil {
			return err
		}
	}
	return nil
}
