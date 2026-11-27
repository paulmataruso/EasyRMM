package grouppolicy

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
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
)

// Request is a change waiting for a second person (ADR-0083 section 7).
type Request struct {
	ID             uuid.UUID       `json:"id"`
	DeviceID       uuid.UUID       `json:"deviceId"`
	Action         string          `json:"action"`
	Label          string          `json:"label"`
	Params         json.RawMessage `json:"params"`
	Sensitivity    string          `json:"sensitivity"`
	Summary        string          `json:"summary"`
	Reason         string          `json:"reason"`
	Status         string          `json:"status"`
	RequestedBy    uuid.UUID       `json:"requestedBy"`
	RequestedLabel string          `json:"requestedLabel"`
	CreatedAt      time.Time       `json:"createdAt"`
	ExpiresAt      time.Time       `json:"expiresAt"`
	DecidedLabel   string          `json:"decidedLabel"`
	DecidedReason  string          `json:"decidedReason"`
	DecidedAt      *time.Time      `json:"decidedAt"`
	RunID          *uuid.UUID      `json:"runId"`
	// CanDecide is true for a person who holds gpo.edit at the device's site and is not the one who asked.
	CanDecide bool `json:"canDecide"`
}

// NewRequest asks for a second person's approval of a change.
type NewRequest struct {
	Action string          `json:"action"`
	Params json.RawMessage `json:"params"`
	// Subject is the name the console shows for it (a GPO's name); the approver also sees the exact parameters.
	Subject string `json:"subject"`
}

// Submit stores a request for a change that needs approval. The change is validated as it would be to run, by a
// person who may run it; a change that needs no approval is not accepted (run it).
func (s *Service) Submit(ctx context.Context, c access.Caller, device uuid.UUID, in NewRequest) (*Request, error) {
	a, ok := s.catalog.Lookup(in.Action)
	if !ok || a.Module != modules.GroupPolicy || !NeedsApprovalCheck(a.Name) {
		return nil, apperr.Invalid("action", "That change is not one that is approved by a second person.")
	}
	chk, err := a.Validate(in.Params)
	if err != nil {
		return nil, err
	}
	params, err := decodeParams(chk.Params)
	if err != nil {
		return nil, err
	}
	if _, has := params["approvalId"]; has {
		return nil, apperr.Invalid("params.approvalId", "A request carries no approval.")
	}
	reason, _ := params["reason"].(string)
	req := &Request{}
	err = s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		org, site, err := s.deviceFor(ctx, tx, c, device, a.Permission)
		if err != nil {
			return err
		}
		why, err := s.requirement(ctx, tx, org, device, a.Name, params)
		if err != nil {
			return err
		}
		if why == "" {
			return apperr.Conflict("approval_not_needed", "This change needs no second person; run it.")
		}
		summary := truncate(strings.TrimSpace(in.Subject), 200)
		if summary == "" {
			summary = a.Label
		} else {
			summary = a.Label + ": " + summary
		}
		req.Action, req.Label, req.DeviceID, req.Sensitivity, req.Summary, req.Reason = a.Name, a.Label, device, why, summary, reason
		req.Params, req.Status, req.RequestedBy, req.RequestedLabel = chk.Params, "pending", c.Actor.ID, c.Actor.Label
		req.CreatedAt = s.now()
		req.ExpiresAt = req.CreatedAt.Add(RequestLife)
		if err := tx.QueryRow(ctx, `INSERT INTO gpo_change_requests (organization_id, site_id, device_id, action, params, sensitivity, summary, reason, requested_by, requested_label, created_at, expires_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12) RETURNING id`,
			org, site, device, a.Name, []byte(chk.Params), why, summary, reason, c.Actor.ID, c.Actor.Label, req.CreatedAt, req.ExpiresAt).Scan(&req.ID); err != nil {
			return err
		}
		return s.audit.Write(ctx, tx, audit.Event{
			Actor: c.Actor, Action: "group_policy.request", Outcome: audit.Success, OrganizationID: org, SiteID: site, DeviceID: device,
			TargetType: "gpo_change_request", TargetID: req.ID.String(),
			Details: map[string]any{"change": a.Name, "sensitivity": why, "summary": summary, "reason": reason, "params": chk.Audit},
		})
	})
	if err != nil {
		return nil, wrap(err, "submitting a request")
	}
	return req, nil
}

func wrap(err error, what string) error {
	if err == nil {
		return nil
	}
	var ae *apperr.Error
	if errors.As(err, &ae) || errors.Is(err, apperr.ErrNotFound) || errors.Is(err, apperr.ErrForbidden) {
		return err
	}
	return fmt.Errorf("grouppolicy: %s: %w", what, err)
}

// ListRequests lists an organization's requests, the open ones first. It needs gpo.view at the organization.
func (s *Service) ListRequests(ctx context.Context, c access.Caller, org uuid.UUID) ([]Request, error) {
	if !c.CanInOrg(rbac.PermGPOView, org) {
		return nil, apperr.NotFound()
	}
	out := []Request{}
	err := s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `UPDATE gpo_change_requests SET status = 'expired' WHERE organization_id = $1 AND status = 'pending' AND expires_at <= now()`, org); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `SELECT id, site_id, device_id, action, params, sensitivity, summary, reason, status, requested_by, requested_label, created_at, expires_at,
				decided_label, decided_reason, decided_at, run_id
			FROM gpo_change_requests WHERE organization_id = $1 ORDER BY (status = 'pending') DESC, created_at DESC LIMIT 100`, org)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var r Request
			var site uuid.UUID
			var params []byte
			if err := rows.Scan(&r.ID, &site, &r.DeviceID, &r.Action, &params, &r.Sensitivity, &r.Summary, &r.Reason, &r.Status, &r.RequestedBy, &r.RequestedLabel,
				&r.CreatedAt, &r.ExpiresAt, &r.DecidedLabel, &r.DecidedReason, &r.DecidedAt, &r.RunID); err != nil {
				return err
			}
			if !c.Can(rbac.PermGPOView, rbac.Site(org, site)) {
				continue
			}
			r.Params = params
			if a, ok := s.catalog.Lookup(r.Action); ok {
				r.Label = a.Label
			}
			r.CanDecide = r.Status == "pending" && r.RequestedBy != c.Actor.ID && c.Can(rbac.PermGPOEdit, rbac.Site(org, site))
			out = append(out, r)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, wrap(err, "listing requests")
	}
	return out, nil
}

// Approve lets a second person grant a request: they must hold gpo.edit, must not be the one who asked, and the change
// runs at once under their name (their permission, their step-up, their confirmation by approving). The change's own
// checks, the version check among them, run as for any change; a failure puts the request back as pending.
func (s *Service) Approve(ctx context.Context, c access.Caller, id uuid.UUID, reason string) (*Run, error) {
	reason = strings.TrimSpace(reason)
	if n := len([]rune(reason)); n < 10 || n > 500 {
		return nil, apperr.Invalid("reason", "Say why in 10 to 500 characters.")
	}
	var (
		device uuid.UUID
		action string
		params []byte
		org    uuid.UUID
		site   uuid.UUID
	)
	err := s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		var status string
		var requester uuid.UUID
		var expires time.Time
		if err := tx.QueryRow(ctx, `SELECT organization_id, site_id, device_id, action, params, status, requested_by, expires_at FROM gpo_change_requests WHERE id = $1 FOR UPDATE`, id).
			Scan(&org, &site, &device, &action, &params, &status, &requester, &expires); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return apperr.NotFound()
			}
			return err
		}
		if !c.Can(rbac.PermGPOEdit, rbac.Site(org, site)) {
			return apperr.NotFound()
		}
		switch {
		case status != "pending" || !expires.After(s.now()):
			return apperr.Conflict("request_closed", "That request is no longer open.")
		case requester == c.Actor.ID:
			return apperr.Conflict("same_person", "The person who asked cannot approve their own change. Another administrator with gpo.edit must.")
		}
		if _, err := tx.Exec(ctx, `UPDATE gpo_change_requests SET status = 'approved', decided_by = $2, decided_label = $3, decided_reason = $4, decided_at = now() WHERE id = $1`,
			id, c.Actor.ID, c.Actor.Label, reason); err != nil {
			return err
		}
		return s.audit.Write(ctx, tx, audit.Event{
			Actor: c.Actor, Action: "group_policy.approve", Outcome: audit.Success, OrganizationID: org, SiteID: site, DeviceID: device,
			TargetType: "gpo_change_request", TargetID: id.String(), Details: map[string]any{"change": action, "reason": reason, "requestedBy": requester.String()},
		})
	})
	if err != nil {
		return nil, wrap(err, "approving")
	}
	a, ok := s.catalog.Lookup(action)
	if !ok {
		return nil, apperr.NotFound()
	}
	p, err := decodeParams(params)
	if err != nil {
		return nil, err
	}
	p["approvalId"] = id.String()
	body, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}
	confirm := ""
	if a.NeedsConfirm() {
		subject, _ := p[a.Subject].(string)
		confirm = a.ConfirmText(subject)
	}
	run, err := s.runner.RunWinmod(ctx, c, device, action, body, confirm)
	if err != nil {
		// Not started (a step-up lapsed, the module was turned off, a check failed): the request is open again.
		if rerr := s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
			_, e := tx.Exec(ctx, `UPDATE gpo_change_requests SET status = 'pending', decided_by = NULL, decided_label = '', decided_reason = '', decided_at = NULL WHERE id = $1 AND consumed_at IS NULL`, id)
			return e
		}); rerr != nil {
			return nil, fmt.Errorf("grouppolicy: reopening a request: %w (after %w)", rerr, err)
		}
		return nil, err
	}
	if err := s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `UPDATE gpo_change_requests SET run_id = $2 WHERE id = $1`, id, run.RunID)
		return e
	}); err != nil {
		return nil, wrap(err, "recording the run")
	}
	return run, nil
}

// Reject closes a request with a reason. Anyone who may decide may; so may the person who asked, to withdraw it.
func (s *Service) Reject(ctx context.Context, c access.Caller, id uuid.UUID, reason string) error {
	reason = strings.TrimSpace(reason)
	if n := len([]rune(reason)); n < 10 || n > 500 {
		return apperr.Invalid("reason", "Say why in 10 to 500 characters.")
	}
	return wrap(s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		var org, site, device, requester uuid.UUID
		var status, action string
		if err := tx.QueryRow(ctx, `SELECT organization_id, site_id, device_id, action, status, requested_by FROM gpo_change_requests WHERE id = $1 FOR UPDATE`, id).
			Scan(&org, &site, &device, &action, &status, &requester); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return apperr.NotFound()
			}
			return err
		}
		if (!c.Can(rbac.PermGPOEdit, rbac.Site(org, site)) && requester != c.Actor.ID) || !c.Can(rbac.PermGPOView, rbac.Site(org, site)) {
			return apperr.NotFound()
		}
		if status != "pending" {
			return apperr.Conflict("request_closed", "That request is no longer open.")
		}
		if _, err := tx.Exec(ctx, `UPDATE gpo_change_requests SET status = 'rejected', decided_by = $2, decided_label = $3, decided_reason = $4, decided_at = now() WHERE id = $1`,
			id, c.Actor.ID, c.Actor.Label, reason); err != nil {
			return err
		}
		return s.audit.Write(ctx, tx, audit.Event{
			Actor: c.Actor, Action: "group_policy.reject", Outcome: audit.Success, OrganizationID: org, SiteID: site, DeviceID: device,
			TargetType: "gpo_change_request", TargetID: id.String(), Details: map[string]any{"change": action, "reason": reason},
		})
	}), "rejecting")
}

// GetSettings returns an organization's approval setting. It needs gpo.view.
func (s *Service) GetSettings(ctx context.Context, c access.Caller, org uuid.UUID) (*Settings, error) {
	if !c.CanInOrg(rbac.PermGPOView, org) {
		return nil, apperr.NotFound()
	}
	var out Settings
	err := s.db.ReadTx(ctx, database.System, func(tx pgx.Tx) error {
		var err error
		out, err = settingsIn(ctx, tx, org)
		return err
	})
	if err != nil {
		return nil, wrap(err, "reading the setting")
	}
	return &out, nil
}

// SetSettings changes an organization's approval setting. It needs an Organization Administrator (org.manage and gpo.manage
// on the organization) and is audited either way; turning a requirement off is the change the ADR names.
func (s *Service) SetSettings(ctx context.Context, c access.Caller, org uuid.UUID, in Settings) error {
	if !c.Can(rbac.PermOrgManage, rbac.Org(org)) || !c.Can(rbac.PermGPOManage, rbac.Org(org)) {
		return apperr.NotFound()
	}
	return wrap(s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		before, err := settingsIn(ctx, tx, org)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO gpo_org_settings (organization_id, approval_sensitive, approval_all, updated_by) VALUES ($1, $2, $3, $4)
			ON CONFLICT (organization_id) DO UPDATE SET approval_sensitive = excluded.approval_sensitive, approval_all = excluded.approval_all, updated_by = excluded.updated_by, updated_at = now()`,
			org, in.ApprovalSensitive, in.ApprovalAll, c.Actor.Label); err != nil {
			return err
		}
		return s.audit.Write(ctx, tx, audit.Event{
			Actor: c.Actor, Action: "group_policy.settings", Outcome: audit.Success, OrganizationID: org, TargetType: "organization", TargetID: org.String(),
			Details: map[string]any{"before": before, "after": in, "weakened": (before.ApprovalSensitive && !in.ApprovalSensitive) || (before.ApprovalAll && !in.ApprovalAll)},
		})
	}), "saving the setting")
}

// BackupMeta is a stored backup, without its zip.
type BackupMeta struct {
	ID              uuid.UUID `json:"id"`
	BackupID        uuid.UUID `json:"backupId"`
	GPOID           uuid.UUID `json:"gpoId"`
	GPOName         string    `json:"gpoName"`
	Kind            string    `json:"kind"`
	Action          string    `json:"action"`
	ActorLabel      string    `json:"actorLabel"`
	Reason          string    `json:"reason"`
	Size            int       `json:"size"`
	SHA256          string    `json:"sha256"`
	ComputerVersion int       `json:"computerVersion"`
	UserVersion     int       `json:"userVersion"`
	CreatedAt       time.Time `json:"createdAt"`
	// Parts is how many chunks the backup travels in when it is restored.
	Parts int `json:"parts"`
}

func chunks(size int) int {
	b64 := (size + 2) / 3 * 4
	return (b64 + ChunkChars - 1) / ChunkChars
}

// domainOf is the domain the controller's last status read names.
func domainOf(ctx context.Context, tx pgx.Tx, device uuid.UUID) string {
	var d string
	_ = tx.QueryRow(ctx, `SELECT coalesce(data->>'domain', '') FROM windows_module_snapshots WHERE device_id = $1 AND action = 'group_policy.status' AND params_hash = ''`, device).Scan(&d)
	return d
}

// ListBackups lists the backups of the controller's domain, newest first, for one GPO when gpo is not nil. It needs gpo.view.
func (s *Service) ListBackups(ctx context.Context, c access.Caller, device uuid.UUID, gpo *uuid.UUID) ([]BackupMeta, error) {
	out := []BackupMeta{}
	err := s.db.ReadTx(ctx, database.System, func(tx pgx.Tx) error {
		org, _, err := s.deviceFor(ctx, tx, c, device, rbac.PermGPOView)
		if err != nil {
			return err
		}
		dom := domainOf(ctx, tx, device)
		if dom == "" {
			return nil
		}
		q := `SELECT id, backup_id, gpo_id, gpo_name, kind, action, actor_label, reason, size_bytes, sha256, computer_version, user_version, created_at
			FROM gpo_backups WHERE organization_id = $1 AND domain = $2`
		args := []any{org, dom}
		if gpo != nil {
			q += ` AND gpo_id = $3`
			args = append(args, *gpo)
		}
		rows, err := tx.Query(ctx, q+` ORDER BY created_at DESC, id LIMIT 200`, args...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var m BackupMeta
			if err := rows.Scan(&m.ID, &m.BackupID, &m.GPOID, &m.GPOName, &m.Kind, &m.Action, &m.ActorLabel, &m.Reason, &m.Size, &m.SHA256, &m.ComputerVersion, &m.UserVersion, &m.CreatedAt); err != nil {
				return err
			}
			m.Parts = chunks(m.Size)
			out = append(out, m)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, wrap(err, "listing backups")
	}
	return out, nil
}

// Chunk is one piece of a backup, in base64, to be sent to the controller before a restore.
type Chunk struct {
	Index int    `json:"index"`
	Count int    `json:"count"`
	Chunk string `json:"chunk"`
}

func (s *Service) backupZip(ctx context.Context, c access.Caller, device, id uuid.UUID) (raw []byte, name string, err error) {
	err = s.db.ReadTx(ctx, database.System, func(tx pgx.Tx) error {
		org, _, err := s.deviceFor(ctx, tx, c, device, rbac.PermGPOManage)
		if err != nil {
			return err
		}
		var gname string
		if err := tx.QueryRow(ctx, `SELECT zip, gpo_name FROM gpo_backups WHERE id = $1 AND organization_id = $2`, id, org).Scan(&raw, &gname); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return apperr.NotFound()
			}
			return err
		}
		name = gname
		return nil
	})
	return raw, name, wrap(err, "reading a backup")
}

// BackupChunk returns piece index of a backup for a restore. It needs gpo.manage.
func (s *Service) BackupChunk(ctx context.Context, c access.Caller, device, id uuid.UUID, index int) (*Chunk, error) {
	raw, _, err := s.backupZip(ctx, c, device, id)
	if err != nil {
		return nil, err
	}
	b64 := base64.StdEncoding.EncodeToString(raw)
	n := chunks(len(raw))
	if index < 0 || index >= n {
		return nil, apperr.NotFound()
	}
	end := min((index+1)*ChunkChars, len(b64))
	return &Chunk{Index: index, Count: n, Chunk: b64[index*ChunkChars : end]}, nil
}

// DownloadBackup returns a backup's zip. It needs gpo.manage and is audited.
func (s *Service) DownloadBackup(ctx context.Context, c access.Caller, device, id uuid.UUID) ([]byte, string, error) {
	raw, name, err := s.backupZip(ctx, c, device, id)
	if err != nil {
		return nil, "", err
	}
	err = s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		org, site, err := s.deviceFor(ctx, tx, c, device, rbac.PermGPOManage)
		if err != nil {
			return err
		}
		return s.audit.Write(ctx, tx, audit.Event{
			Actor: c.Actor, Action: "group_policy.backup_download", Outcome: audit.Success, OrganizationID: org, SiteID: site, DeviceID: device,
			TargetType: "gpo_backup", TargetID: id.String(), Details: map[string]any{"gpoName": truncate(name, 256), "size": len(raw)},
		})
	})
	return raw, name, wrap(err, "auditing a download")
}

// DomainSummary is one domain on the organization's card.
type DomainSummary struct {
	Domain     string     `json:"domain"`
	DeviceID   uuid.UUID  `json:"deviceId"`
	Controller string     `json:"controller"`
	GPOCount   int        `json:"gpoCount"`
	Empty      int        `json:"empty"`
	Unlinked   *int       `json:"unlinked"`
	ReadAt     *time.Time `json:"readAt"`
}

// Summary is the organization card (ADR-0083 section 8): what the last status read of each domain said, and how many
// requests wait. It reads stored results and sends no job.
type Summary struct {
	Enabled          bool            `json:"enabled"`
	Domains          []DomainSummary `json:"domains"`
	PendingApprovals int             `json:"pendingApprovals"`
}

// Summary reads the card. It needs gpo.view.
func (s *Service) Summary(ctx context.Context, c access.Caller, org uuid.UUID) (*Summary, error) {
	if !c.CanInOrg(rbac.PermGPOView, org) {
		return nil, apperr.NotFound()
	}
	out := &Summary{Domains: []DomainSummary{}}
	err := s.db.ReadTx(ctx, database.System, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT d.id, d.site_id, st.data, st.taken_at
			FROM devices d JOIN windows_module_snapshots st ON st.device_id = d.id AND st.action = 'group_policy.status' AND st.params_hash = ''
			WHERE d.organization_id = $1 AND d.platform = 'windows' AND d.roles @> '[{"name":"gpmc"}]' ORDER BY st.taken_at DESC`, org)
		if err != nil {
			return err
		}
		seen := map[string]bool{}
		for rows.Next() {
			var id, site uuid.UUID
			var data []byte
			var at time.Time
			if err := rows.Scan(&id, &site, &data, &at); err != nil {
				rows.Close()
				return err
			}
			if !c.Can(rbac.PermGPOView, rbac.Site(org, site)) || !s.mods.Allowed(ctx, org, site, modules.GroupPolicy) {
				continue
			}
			out.Enabled = true
			var st Status
			if json.Unmarshal(data, &st) != nil || st.Domain == "" || seen[st.Domain] {
				continue
			}
			seen[st.Domain] = true
			out.Domains = append(out.Domains, DomainSummary{Domain: st.Domain, DeviceID: id, Controller: st.Controller, GPOCount: st.GPOCount, Empty: st.Empty, Unlinked: st.Unlinked, ReadAt: &at})
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		return tx.QueryRow(ctx, `SELECT count(*) FROM gpo_change_requests WHERE organization_id = $1 AND status = 'pending' AND expires_at > now()`, org).Scan(&out.PendingApprovals)
	})
	if err != nil {
		return nil, wrap(err, "reading the card")
	}
	return out, nil
}
