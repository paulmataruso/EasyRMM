package fix

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/server/internal/access"
	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/devscope"
	"github.com/paulmataruso/easyrmm/server/internal/jobs"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
)

// MaxBatch is the most items one request may hold.
const MaxBatch = 100

// ApplyInput asks to apply the fixes of some items, under one agreement.
type ApplyInput struct {
	ItemIDs []uuid.UUID `json:"itemIds"`
	Agreement
}

// loaded is an item with what an act on it needs.
type loaded struct {
	*itemRow
	sid string
}

// load reads the items of an organization, as the caller sees them, and
// holds them to the rules every act shares.
func (s *Service) load(ctx context.Context, c access.Caller, org uuid.UUID, ids []uuid.UUID) ([]loaded, error) {
	var out []loaded
	err := s.db.ReadTx(ctx, c.Scope, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, itemSelect+" WHERE i.organization_id = $1 AND i.id = ANY ($2) ORDER BY i.device_id, i.control_id", org, ids)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			r, err := scanItem(rows)
			if err != nil {
				return err
			}
			st, _ := r.setting()
			out = append(out, loaded{r, st})
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	if len(out) != len(uniq(ids)) {
		return nil, apperr.NotFound()
	}
	return out, nil
}

func uniq(ids []uuid.UUID) []uuid.UUID {
	seen := map[uuid.UUID]bool{}
	var out []uuid.UUID
	for _, id := range ids {
		if !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	return out
}

// gate holds a request to the rules of section 6: one tier, the bulk rules,
// the permission for the tier, the module in scope, and the agreement and
// the step-up the tier needs. It runs before anything is written.
func (s *Service) gate(ctx context.Context, c access.Caller, org uuid.UUID, items []loaded, a Agreement, needStepUp bool) (tier string, err error) {
	tiers := map[string]bool{}
	controls := map[string]bool{}
	for _, it := range items {
		tiers[it.Tier] = true
		controls[it.ControlID] = true
	}
	if len(tiers) != 1 {
		return "", apperr.Invalid("itemIds", "Choose items of one tier: each tier is agreed to in its own way.")
	}
	for t := range tiers {
		tier = t
	}
	if ok, why := Bulk(tier, controls, len(items)); !ok {
		return "", apperr.Invalid("itemIds", why)
	}
	perm := rbac.PermComplianceFix
	if tier == T3 {
		perm = rbac.PermComplianceFixHigh
	}
	if !c.Can(perm, rbac.Org(org)) {
		return "", apperr.Forbidden()
	}
	if !devscope.Allowed(org) {
		return "", apperr.Conflict("not_available", "Fixes are not available for this organization in this build.")
	}
	for _, it := range items {
		// A fix is made through the hardening path, which needs device.harden on the computer.
		if !c.Can(rbac.PermDeviceHarden, rbac.Site(org, it.SiteID)) {
			return "", apperr.Forbidden()
		}
		w, ok := s.warnings[it.warningID]
		if !ok {
			return "", apperr.Conflict("no_warning", "This control has no warning text, so it cannot be agreed to.")
		}
		if err := a.Check(tier, w, it.DeviceName); err != nil {
			return "", err
		}
	}
	if tier == T3 || needStepUp {
		if s.stepUp == nil {
			return "", apperr.Conflict("step_up_required", "This needs step-up authentication, which is not available yet, so it cannot be done from here.")
		}
		if err := s.stepUp.VerifyStepUp(ctx); err != nil {
			return "", err
		}
	}
	return tier, nil
}

// event is an audit event of the fix queue.
func event(c access.Caller, action string, it *itemRow, outcome audit.Outcome, extra map[string]any) audit.Event {
	d := map[string]any{"control": it.ControlID, "controlVersion": it.Version, "tier": it.Tier}
	for k, v := range extra {
		d[k] = v
	}
	return audit.Event{Actor: c.Actor, Action: action, OrganizationID: it.OrgID, DeviceID: it.DeviceID, TargetType: "compliance_fix_item",
		TargetID: it.ID.String(), Outcome: outcome, Details: d}
}

// agree records an agreement for an item in the transaction and audits it.
func (s *Service) agree(ctx context.Context, tx pgx.Tx, c access.Caller, it *itemRow, act string, a Agreement, stepUp bool, action string) (uuid.UUID, error) {
	w := s.warnings[it.warningID]
	var uid *uuid.UUID
	if c.Principal != nil && !c.IsSystem() {
		uid = &c.Principal.UserID
	}
	var typed *string
	if t := strings.TrimSpace(a.Typed); t != "" {
		typed = &t
	}
	pre, _ := json.Marshal(preconditions(it))
	id := uuid.New()
	if _, err := tx.Exec(ctx, `INSERT INTO compliance_fix_agreements (id, organization_id, item_id, act, user_id, agreed_at, warning_id, warning_sha256,
			control_version, typed_text, step_up, preconditions) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`,
		id, it.OrgID, it.ID, act, uid, s.now(), w.ID, w.SHA256, it.Version, typed, stepUp, pre); err != nil {
		return uuid.Nil, err
	}
	return id, s.audit.Write(ctx, tx, event(c, action, it, audit.Success, map[string]any{"agreementId": id, "warning": w.ID, "warningSha256": w.SHA256, "typed": typed != nil, "stepUp": stepUp}))
}

// setState moves an item from a state to another, and says whether it was in
// the state.
func (s *Service) setState(ctx context.Context, tx pgx.Tx, id uuid.UUID, from []string, to string, by *uuid.UUID) (bool, error) {
	tag, err := tx.Exec(ctx, `UPDATE compliance_fix_items SET state = $3, updated_at = $4, requested_by = coalesce($5, requested_by),
			fail_reason = CASE WHEN $3 IN ('applying', 'undoing') THEN '' ELSE fail_reason END
		WHERE id = $1 AND state = ANY ($2)`, id, from, to, s.now(), by)
	return tag.RowsAffected() == 1, err
}

func requester(c access.Caller) *uuid.UUID {
	if c.Principal != nil && !c.IsSystem() {
		return &c.Principal.UserID
	}
	return nil
}

// Apply agrees to and applies fixes (or, for a tier an organization wants
// approved, agrees and waits for a second person). Each item gets its own
// agreement row and audit events; a change that cannot be undone or can cut
// access has more to it (section 6). It returns the items as they stand.
func (s *Service) Apply(ctx context.Context, c access.Caller, org uuid.UUID, in ApplyInput) ([]Item, error) {
	if err := requireView(c, org); err != nil {
		return nil, err
	}
	if len(in.ItemIDs) == 0 || len(in.ItemIDs) > MaxBatch {
		return nil, apperr.Invalid("itemIds", "Choose between 1 and 100 items.")
	}
	items, err := s.load(ctx, c, org, in.ItemIDs)
	if err != nil {
		return nil, err
	}
	for _, it := range items {
		if it.State != StateOpen && it.State != StateNotVerified {
			return nil, apperr.Conflict("not_open", "An item that was already agreed to, applied or set aside is not agreed to again.")
		}
		if it.sid == "" {
			_, why := it.setting()
			return nil, apperr.Conflict("not_offered", why)
		}
	}
	tier, err := s.gate(ctx, c, org, items, in.Agreement, false)
	if err != nil {
		return nil, err
	}
	var approval []string
	if err := s.db.ReadTx(ctx, c.Scope, func(tx pgx.Tx) error {
		var e error
		approval, e = s.approvalTiers(ctx, tx, org)
		return e
	}); err != nil {
		return nil, err
	}
	if contains(approval, tier) {
		err := s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
			for _, it := range items {
				ok, err := s.setState(ctx, tx, it.ID, []string{StateOpen}, StateAwaiting, requester(c))
				if err != nil {
					return err
				}
				if !ok {
					return apperr.Conflict("not_open", "An item was changed by someone else; look again.")
				}
				if _, err := s.agree(ctx, tx, c, it.itemRow, "apply", in.Agreement, tier == T3, "compliance.fix.agreed"); err != nil {
					return err
				}
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
		return s.byIDs(ctx, c, org, in.ItemIDs)
	}
	if err := s.dispatchApply(ctx, c, items, in.Agreement, tier, "apply", true); err != nil {
		return nil, err
	}
	return s.byIDs(ctx, c, org, in.ItemIDs)
}

func contains(l []string, v string) bool {
	for _, x := range l {
		if x == v {
			return true
		}
	}
	return false
}

func (s *Service) byIDs(ctx context.Context, c access.Caller, org uuid.UUID, ids []uuid.UUID) ([]Item, error) {
	var out []Item
	err := s.db.ReadTx(ctx, c.Scope, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, itemSelect+" WHERE i.organization_id = $1 AND i.id = ANY ($2) ORDER BY i.device_id, i.control_id", org, ids)
		if err != nil {
			return err
		}
		var raw []*itemRow
		for rows.Next() {
			r, err := scanItem(rows)
			if err != nil {
				rows.Close()
				return err
			}
			raw = append(raw, r)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		approval, err := s.approvalTiers(ctx, tx, org)
		if err != nil {
			return err
		}
		for _, r := range raw {
			out = append(out, s.finish(r, approval))
		}
		return nil
	})
	return out, err
}

// dispatchApply records the agreement of each item, then asks the hardening
// path for one job per computer that changes the items' settings. The
// agreement comes first: no job exists that was not agreed to. A job the
// path refuses puts the item back to open, and the refusal is audited.
func (s *Service) dispatchApply(ctx context.Context, c access.Caller, items []loaded, a Agreement, tier, mode string, record bool) error {
	byDev := map[uuid.UUID][]loaded{}
	var order []uuid.UUID
	for _, it := range items {
		if _, ok := byDev[it.DeviceID]; !ok {
			order = append(order, it.DeviceID)
		}
		byDev[it.DeviceID] = append(byDev[it.DeviceID], it)
	}
	act, from, busy, jobMode := "apply", StateOpen, StateApplying, jobs.HardeningApply
	if mode == "undo" {
		act, busy, jobMode = "undo", StateUndoing, jobs.HardeningUndo
	}
	for _, dev := range order {
		group := byDev[dev]
		var settings []string
		err := s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
			var n int
			if err := tx.QueryRow(ctx, `SELECT count(*) FROM compliance_fix_items WHERE device_id = $1 AND state IN ('applying', 'undoing')`, dev).Scan(&n); err != nil {
				return err
			}
			if n > 0 {
				return apperr.Conflict("device_busy", "A change is already being made on this computer. One change is made at a time.")
			}
			for _, it := range group {
				var by *uuid.UUID
				if mode == "apply" && record {
					by = requester(c)
				}
				ok, err := s.setState(ctx, tx, it.ID, s.fromStates(mode, from), busy, by)
				if err != nil {
					return err
				}
				if !ok {
					return apperr.Conflict("not_open", "An item was changed by someone else; look again.")
				}
				if record {
					if _, err := s.agree(ctx, tx, c, it.itemRow, act, a, tier == T3, "compliance.fix.agreed"); err != nil {
						return err
					}
				}
				settings = append(settings, it.sid)
			}
			return nil
		})
		if err != nil {
			return err
		}
		h := jobs.Hardening{Mode: jobMode, Settings: settings}
		if group[0].Platform == "windows" {
			h.Platform = jobs.HardeningWindows
		}
		job, jerr := s.jobs.CreateHardeningJob(ctx, c, jobs.HardeningInput{DeviceIDs: []uuid.UUID{dev}, Hardening: h,
			Confirm: jobs.HardeningConfirmation{Agreed: a.Agreed, Typed: strings.TrimSpace(a.Typed)}})
		err = s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
			for _, it := range group {
				if jerr != nil {
					if _, err := tx.Exec(ctx, `UPDATE compliance_fix_items SET state = $2, updated_at = $3 WHERE id = $1`, it.ID, it.State, s.now()); err != nil {
						return err
					}
					if err := s.audit.Write(ctx, tx, event(c, "compliance.fix.dispatch_failed", it.itemRow, audit.Failure, map[string]any{"act": act})); err != nil {
						return err
					}
					continue
				}
				col := "apply_job_id"
				if mode == "undo" {
					col = "undo_job_id"
				}
				if _, err := tx.Exec(ctx, `UPDATE compliance_fix_items SET `+col+` = $2, updated_at = $3 WHERE id = $1`, it.ID, job.ID, s.now()); err != nil {
					return err
				}
				if err := s.audit.Write(ctx, tx, event(c, "compliance.fix.dispatched", it.itemRow, audit.Success, map[string]any{"jobId": job.ID, "act": act})); err != nil {
					return err
				}
			}
			return nil
		})
		if jerr != nil {
			return jerr
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// fromStates are the states an item may be in for an act.
func (s *Service) fromStates(mode, open string) []string {
	if mode == "undo" {
		return []string{StateApplied, StateVerified, StateNotVerified}
	}
	return []string{open, StateAwaiting, StateNotVerified}
}

// Undo puts back what a fix changed, through the hardening undo, while the
// computer holds the record of the change. It is agreed to like the fix.
func (s *Service) Undo(ctx context.Context, c access.Caller, org, id uuid.UUID, a Agreement) (*Item, error) {
	if err := requireView(c, org); err != nil {
		return nil, err
	}
	items, err := s.load(ctx, c, org, []uuid.UUID{id})
	if err != nil {
		return nil, err
	}
	it := items[0]
	finished := it.State == StateApplied || it.State == StateVerified || it.State == StateNotVerified
	if !finished {
		return nil, apperr.Conflict("not_undoable", "Only a fix that was applied can be undone.")
	}
	if it.UndoKind == "none" || it.sid == "" {
		return nil, apperr.Conflict("not_undoable", "This change cannot be undone from here.")
	}
	tier, err := s.gate(ctx, c, org, items, a, false)
	if err != nil {
		return nil, err
	}
	if err := s.dispatchApply(ctx, c, items, a, tier, "undo", true); err != nil {
		return nil, err
	}
	out, err := s.byIDs(ctx, c, org, []uuid.UUID{id})
	if err != nil || len(out) == 0 {
		return nil, err
	}
	return &out[0], nil
}

// Approve is the second person's agreement to an item that waits for it:
// someone else than the requester, holding compliance.fix_approve, with a
// step-up. The approver's agreement is a second row, and the fix is made.
func (s *Service) Approve(ctx context.Context, c access.Caller, org, id uuid.UUID, a Agreement) (*Item, error) {
	if err := requireView(c, org); err != nil {
		return nil, err
	}
	if !c.Can(rbac.PermComplianceFixApprove, rbac.Org(org)) {
		return nil, apperr.Forbidden()
	}
	items, err := s.load(ctx, c, org, []uuid.UUID{id})
	if err != nil {
		return nil, err
	}
	it := items[0]
	if it.State != StateAwaiting {
		return nil, apperr.Conflict("not_waiting", "This item is not waiting for approval.")
	}
	me := requester(c)
	if me != nil && it.RequestedBy != nil && *me == *it.RequestedBy {
		return nil, apperr.Conflict("own_item", "A fix is approved by someone other than the person who asked for it.")
	}
	if it.sid == "" {
		_, why := it.setting()
		return nil, apperr.Conflict("not_offered", why)
	}
	tier, err := s.gate(ctx, c, org, items, a, true)
	if err != nil {
		return nil, err
	}
	if err := s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		_, err := s.agree(ctx, tx, c, it.itemRow, "approve", a, true, "compliance.fix.approved")
		return err
	}); err != nil {
		return nil, err
	}
	// Dispatch under the approver's own permissions; the requester's agreement stays on record.
	if err := s.dispatchApply(ctx, c, items, a, tier, "apply", false); err != nil {
		return nil, err
	}
	out, err := s.byIDs(ctx, c, org, []uuid.UUID{id})
	if err != nil || len(out) == 0 {
		return nil, err
	}
	return &out[0], nil
}

// DeclineInput sets an item aside with a reason.
type DeclineInput struct {
	// Kind is accepted_risk or deferred.
	Kind      string     `json:"kind"`
	Reason    string     `json:"reason"`
	ExpiresAt *time.Time `json:"expiresAt"`
}

// Decline records that an item is accepted as a risk or deferred, with a
// reason and, for a deferral, a date it comes back. It stays visible, and
// feeds a draft POA&M item in a later slice (C5).
func (s *Service) Decline(ctx context.Context, c access.Caller, org, id uuid.UUID, in DeclineInput) (*Item, error) {
	if err := requireView(c, org); err != nil {
		return nil, err
	}
	if !c.Can(rbac.PermComplianceFix, rbac.Org(org)) {
		return nil, apperr.Forbidden()
	}
	f := apperr.Fields{}
	reason := strings.TrimSpace(in.Reason)
	f.Check(in.Kind == "accepted_risk" || in.Kind == "deferred", "kind", "Choose accepted as a risk, or deferred.")
	f.Check(reason != "" && len(reason) <= 2000, "reason", "Give a reason, up to 2000 characters.")
	now := s.now()
	var exp *time.Time
	if in.Kind == "deferred" {
		f.Check(in.ExpiresAt != nil && in.ExpiresAt.After(now) && in.ExpiresAt.Before(now.AddDate(1, 0, 1)), "expiresAt", "Choose a date in the next year when it comes back.")
		exp = in.ExpiresAt
	}
	if err := f.Err(); err != nil {
		return nil, err
	}
	items, err := s.load(ctx, c, org, []uuid.UUID{id})
	if err != nil {
		return nil, err
	}
	it := items[0]
	err = s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE compliance_fix_items SET state = 'declined', decline_kind = $2, decline_reason = $3, decline_expires = $4,
				declined_by = $5, updated_at = $6 WHERE id = $1 AND state IN ('open', 'awaiting_approval')`, id, in.Kind, reason, exp, requester(c), now)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return apperr.Conflict("not_open", "Only an item that waits can be set aside.")
		}
		return s.audit.Write(ctx, tx, event(c, "compliance.fix.declined", it.itemRow, audit.Success, map[string]any{"kind": in.Kind, "expires": exp}))
	})
	if err != nil {
		return nil, err
	}
	out, err := s.byIDs(ctx, c, org, []uuid.UUID{id})
	if err != nil || len(out) == 0 {
		return nil, err
	}
	return &out[0], nil
}

// Reopen brings a declined item back to open.
func (s *Service) Reopen(ctx context.Context, c access.Caller, org, id uuid.UUID) (*Item, error) {
	if err := requireView(c, org); err != nil {
		return nil, err
	}
	if !c.Can(rbac.PermComplianceFix, rbac.Org(org)) {
		return nil, apperr.Forbidden()
	}
	items, err := s.load(ctx, c, org, []uuid.UUID{id})
	if err != nil {
		return nil, err
	}
	it := items[0]
	err = s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE compliance_fix_items SET state = 'open', decline_kind = NULL, decline_reason = NULL, decline_expires = NULL,
				declined_by = NULL, updated_at = $2 WHERE id = $1 AND state = 'declined'`, id, s.now())
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return apperr.Conflict("not_declined", "This item was not set aside.")
		}
		return s.audit.Write(ctx, tx, event(c, "compliance.fix.reopened", it.itemRow, audit.Success, nil))
	})
	if err != nil {
		return nil, err
	}
	out, err := s.byIDs(ctx, c, org, []uuid.UUID{id})
	if err != nil || len(out) == 0 {
		return nil, err
	}
	return &out[0], nil
}
