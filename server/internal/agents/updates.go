package agents

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/server/internal/access"
	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/devices"
	"github.com/paulmataruso/easyrmm/server/internal/devscope"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
)

// Agent self-update (ADR-0027). A device whose agent runs another build
// than the one the server serves for its platform is told, in a heartbeat
// answer, to replace itself; at most UpdatePolicy.MaxConcurrent devices
// update at once, and an attempt that does not come back with the new build
// is retried a few times, then given up until someone asks again.

// UpdateMode is how the server rolls out its agent build.
type UpdateMode string

// Update modes.
const (
	// UpdateAutomatic updates every device whose agent runs another build.
	UpdateAutomatic UpdateMode = "automatic"
	// UpdateManual updates the devices someone asked for in the console.
	UpdateManual UpdateMode = "manual"
	// UpdateOff starts no updates.
	UpdateOff UpdateMode = "off"
)

// UpdatePolicy is the rollout's setting.
type UpdatePolicy struct {
	Mode UpdateMode `json:"mode"`
	// MaxConcurrent is how many devices may update at once.
	MaxConcurrent int `json:"maxConcurrent"`
	// SignedOnly has the server hand out signed Windows builds only
	// (ADR-0049): with none for the release's version, the newest signed
	// build of an older version, or none.
	SignedOnly bool `json:"signedOnly"`
}

// DefaultUpdatePolicy applies until someone changes the setting.
var DefaultUpdatePolicy = UpdatePolicy{Mode: UpdateAutomatic, MaxConcurrent: 20}

const (
	// MaxConcurrentUpdates bounds UpdatePolicy.MaxConcurrent.
	MaxConcurrentUpdates = 1000
	// UpdateTimeout is how long a device has to come back with the new
	// build before the attempt counts as failed.
	UpdateTimeout = 15 * time.Minute
	// UpdateAttempts is how many attempts an update gets.
	UpdateAttempts = 3
	// updateValidity is how long an agent may act on an instruction.
	updateValidity = 10 * time.Minute
	// updatePolicyKey is the setting's key in the settings table.
	updatePolicyKey = "agent_updates"
	// updateLock serializes the rollout's slot count.
	updateLock = 0x45524d4d55504454 // "ERMMUPDT"
)

// updateBackoff is the wait before the next attempt after n failed ones.
func updateBackoff(n int) time.Duration {
	if n <= 1 {
		return 15 * time.Minute
	}
	return time.Hour
}

// SetUpdates turns agent updates on: the builds the server serves and the
// job key that signs update instructions.
func (s *Service) SetUpdates(b *Builds, key ed25519.PrivateKey) {
	s.builds, s.updateKey = b, key
}

// SetStable gives the service the stable builds: what every organization
// outside the dev scope is offered while one is set (package devscope).
func (s *Service) SetStable(b *Builds) { s.stable = b }

// BuildsFor is the set of builds handed to an organization's devices and
// installers: the server's builds, or while a dev scope is set and the
// organization is outside it, the stable ones. uuid.Nil, a download tied to
// no organization, is outside any scope. It is nil when there is none: with
// a scope set and no stable builds loaded, nothing is offered.
func (s *Service) BuildsFor(org uuid.UUID) *Builds {
	if devscope.Allowed(org) {
		return s.builds
	}
	return s.stable
}

// BuildLookup finds the server's build for a platform, for devices. With
// only signed builds handed out, and none signed from the release's build
// (ADR-0049), it says so, with the older signed build served or none.
func (s *Service) BuildLookup(org uuid.UUID, platform, arch string) (devices.ServedBuild, bool) {
	builds := s.BuildsFor(org)
	if builds == nil {
		return devices.ServedBuild{}, false
	}
	waiting := builds.Waiting(platform, arch)
	b, ok := builds.For(platform, arch)
	if !ok {
		return devices.ServedBuild{WaitingFor: waiting}, waiting != ""
	}
	return devices.ServedBuild{SHA256: b.SHA256, Version: b.Version, WaitingFor: waiting}, true
}

// ReleaseHashes are the SHA-256 of the bundled builds for a platform and
// architecture, whatever is served in their place.
func (s *Service) ReleaseHashes(org uuid.UUID, platform, arch string) []string {
	builds := s.BuildsFor(org)
	if builds == nil {
		return nil
	}
	var out []string
	for _, b := range builds.Release() {
		if b.OS == platform && b.Arch == arch {
			out = append(out, b.SHA256)
		}
	}
	return out
}

// Validate checks a policy.
func (p UpdatePolicy) Validate() error {
	f := apperr.Fields{}
	f.Check(p.Mode == UpdateAutomatic || p.Mode == UpdateManual || p.Mode == UpdateOff, "mode", "Choose automatic, manual or off.")
	f.Check(p.MaxConcurrent >= 1 && p.MaxConcurrent <= MaxConcurrentUpdates, "maxConcurrent",
		fmt.Sprintf("Allow between 1 and %d devices at once.", MaxConcurrentUpdates))
	return f.Err()
}

// storedPolicy is the policy as the settings table holds it.
type storedPolicy struct {
	UpdatePolicy
	updatedAt time.Time
	updatedBy *string // the e-mail of who changed it
	stored    bool
}

func loadPolicy(ctx context.Context, tx pgx.Tx) (storedPolicy, error) {
	out := storedPolicy{UpdatePolicy: DefaultUpdatePolicy}
	var raw []byte
	err := tx.QueryRow(ctx, `SELECT s.value, s.updated_at, u.email FROM settings s LEFT JOIN users u ON u.id = s.updated_by
		WHERE s.key = $1`, updatePolicyKey).
		Scan(&raw, &out.updatedAt, &out.updatedBy)
	if errors.Is(err, pgx.ErrNoRows) {
		return out, nil
	}
	if err != nil {
		return out, err
	}
	var p UpdatePolicy
	if err := json.Unmarshal(raw, &p); err != nil || p.Validate() != nil {
		return out, fmt.Errorf("agents: the stored update setting is not valid: %s", raw)
	}
	out.UpdatePolicy, out.stored = p, true
	return out, nil
}

// update is a row of agent_updates.
type update struct {
	target, version  string
	state            string
	requested        bool
	requestedBy      *uuid.UUID
	attempt          *uuid.UUID
	attempts         int
	sentAt, retry    *time.Time
	from, err        string
	isNew, isChanged bool
}

func loadUpdate(ctx context.Context, tx pgx.Tx, device uuid.UUID) (*update, error) {
	u := &update{}
	err := tx.QueryRow(ctx, `SELECT target_sha256, target_version, state, requested, requested_by, attempt_id, attempts,
			sent_at, retry_after, from_version, error
		FROM agent_updates WHERE device_id = $1 FOR UPDATE`, device).
		Scan(&u.target, &u.version, &u.state, &u.requested, &u.requestedBy, &u.attempt, &u.attempts,
			&u.sentAt, &u.retry, &u.from, &u.err)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return u, err
}

func saveUpdate(ctx context.Context, tx pgx.Tx, device uuid.UUID, u *update) error {
	_, err := tx.Exec(ctx, `INSERT INTO agent_updates (device_id, target_sha256, target_version, state, requested, requested_by,
			attempt_id, attempts, sent_at, retry_after, from_version, error)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
		ON CONFLICT (device_id) DO UPDATE SET target_sha256 = $2, target_version = $3, state = $4, requested = $5,
			requested_by = $6, attempt_id = $7, attempts = $8, sent_at = $9, retry_after = $10, from_version = $11,
			error = $12, updated_at = now()`,
		device, u.target, u.version, u.state, u.requested, u.requestedBy, u.attempt, u.attempts, u.sentAt, u.retry,
		u.from, u.err)
	return err
}

// retarget points an update at another build, as a fresh one.
func (u *update) retarget(b Build) {
	u.target, u.version, u.state = b.SHA256, b.Version, "queued"
	u.attempt, u.attempts, u.sentAt, u.retry, u.err = nil, 0, nil, nil, ""
}

// planUpdate settles the device's update in its heartbeat and returns the
// instruction to send, if any. It runs in the heartbeat's transaction.
func (s *Service) planUpdate(ctx context.Context, tx pgx.Tx, d *Device, f facts, report *agentproto.UpdateReport, ip netip.Addr) (*agentproto.SignedUpdate, error) {
	builds := s.BuildsFor(d.OrganizationID)
	if builds == nil || s.updateKey == nil {
		return nil, nil
	}
	b, haveBuild := builds.For(f.platform, f.arch)
	u, err := loadUpdate(ctx, tx, d.ID)
	if err != nil {
		return nil, err
	}
	actor := audit.Actor{Type: audit.ActorAgent, ID: d.ID, Label: f.hostname, SourceIP: ip}
	event := func(outcome audit.Outcome, details map[string]any) error {
		return s.audit.Write(ctx, tx, audit.Event{
			Actor: actor, Action: "device.agent_update", Outcome: outcome,
			OrganizationID: d.OrganizationID, SiteID: d.SiteID, DeviceID: d.ID, TargetType: "device", TargetID: d.ID.String(),
			Details: details,
		})
	}
	// The device runs the update's build: it is done.
	if u != nil && f.sha256 != "" && f.sha256 == u.target {
		if u.state != "queued" || u.attempts > 0 {
			if err := event(audit.Success, map[string]any{
				"device": f.hostname, "from": u.from, "to": f.version, "sha256": f.sha256, "attempts": u.attempts + 1,
			}); err != nil {
				return nil, err
			}
		}
		if _, err := tx.Exec(ctx, `DELETE FROM agent_updates WHERE device_id = $1`, d.ID); err != nil {
			return nil, err
		}
		u = nil
	}
	// Nothing to update to, an agent that cannot update itself, or one that
	// already runs the build.
	if !haveBuild || f.sha256 == "" || f.sha256 == b.SHA256 {
		if u != nil {
			_, err := tx.Exec(ctx, `DELETE FROM agent_updates WHERE device_id = $1`, d.ID)
			return nil, err
		}
		return nil, nil
	}
	now := s.now().UTC()
	if u != nil && u.target != b.SHA256 {
		u.retarget(b) // the server serves another build now
		u.isChanged = true
	}
	if u != nil && u.state == "sent" {
		failed := ""
		switch {
		case report != nil && u.attempt != nil && report.ID == u.attempt.String():
			failed = clean(report.Error, agentproto.MaxUpdateError)
			if failed == "" {
				failed = "The agent reported a failure without a reason."
			}
		case u.sentAt != nil && now.Sub(*u.sentAt) > UpdateTimeout:
			failed = fmt.Sprintf("The agent did not come back with the new build within %d minutes.", int(UpdateTimeout.Minutes()))
		}
		if failed != "" {
			u.attempts++
			u.err, u.attempt, u.sentAt, u.isChanged = failed, nil, nil, true
			if u.attempts >= UpdateAttempts {
				u.state, u.retry = "failed", nil
				if err := event(audit.Failure, map[string]any{
					"device": f.hostname, "from": f.version, "to": u.version, "sha256": u.target,
					"attempts": u.attempts, "error": failed,
				}); err != nil {
					return nil, err
				}
			} else {
				next := now.Add(updateBackoff(u.attempts))
				u.state, u.retry = "queued", &next
			}
		}
	}
	if u == nil || u.state == "queued" {
		p, err := loadPolicy(ctx, tx)
		if err != nil {
			return nil, err
		}
		if u == nil {
			if p.Mode != UpdateAutomatic {
				return nil, nil
			}
			u = &update{isNew: true}
			u.retarget(b)
		}
		due := u.retry == nil || !now.Before(*u.retry)
		wanted := p.Mode == UpdateAutomatic || (p.Mode == UpdateManual && u.requested)
		if due && wanted {
			ok, err := takeSlot(ctx, tx, p.MaxConcurrent, now)
			if err != nil {
				return nil, err
			}
			if ok {
				id := uuid.New()
				u.state, u.attempt, u.sentAt, u.retry, u.from = "sent", &id, &now, nil, f.version
				u.isChanged = true
			}
		}
	}
	if u.isNew || u.isChanged {
		if err := saveUpdate(ctx, tx, d.ID, u); err != nil {
			return nil, err
		}
	}
	if u.state != "sent" {
		return nil, nil
	}
	// Sent again while in flight: the last answer may not have arrived.
	signed, err := agentproto.SignUpdate(s.updateKey, agentproto.UpdatePayload{
		V: agentproto.UpdatePayloadVersion, ID: u.attempt.String(), DeviceID: d.ID.String(),
		File: b.File, Size: b.Size, SHA256: b.SHA256, Version: b.Version,
		IssuedAt: now, ExpiresAt: now.Add(updateValidity),
	})
	if err != nil {
		return nil, err
	}
	return &signed, nil
}

// takeSlot reports whether another update may start under the limit:
// updates sent within UpdateTimeout count. The lock holds until the
// heartbeat's transaction ends, so two heartbeats never count the same free
// slot.
func takeSlot(ctx context.Context, tx pgx.Tx, limit int, now time.Time) (bool, error) {
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, int64(updateLock)); err != nil {
		return false, err
	}
	var n int
	err := tx.QueryRow(ctx, `SELECT count(*) FROM agent_updates WHERE state = 'sent' AND sent_at > $1`,
		now.Add(-UpdateTimeout)).Scan(&n)
	return n < limit, err
}

// UpdateSettings is the rollout's setting and where the fleet stands, as
// the console shows them.
type UpdateSettings struct {
	UpdatePolicy
	// Stored is false while the default applies.
	Stored    bool       `json:"stored"`
	UpdatedAt *time.Time `json:"updatedAt"`
	UpdatedBy string     `json:"updatedBy,omitempty"`
	// Version is the version of the server's builds, "" when unknown.
	Version string `json:"version"`
	// Builds are the builds served; Release the release's, whatever is
	// served: its Windows builds are what an operator signs (ADR-0049).
	Builds  []Build `json:"builds"`
	Release []Build `json:"release"`
	// Signed are the signed Windows builds the server keeps, newest first.
	Signed []SignedBuild `json:"signed"`
	// Withheld are the Windows architectures for which no build is handed
	// out: only signed builds are, and there is none for them.
	Withheld []string `json:"withheld"`
	Fleet    Fleet    `json:"fleet"`
}

// Fleet counts the enrolled devices by where their agent stands; the keys
// are devices.Update* statuses and "none" (no build for the platform).
type Fleet map[string]int

// UpdateSettings returns the rollout's setting and the fleet's state.
func (s *Service) UpdateSettings(ctx context.Context, c access.Caller) (*UpdateSettings, error) {
	if err := c.RequireGlobal(rbac.PermSettingsManage); err != nil {
		return nil, err
	}
	out := &UpdateSettings{Builds: []Build{}, Release: []Build{}, Signed: []SignedBuild{}, Withheld: []string{}, Fleet: Fleet{}}
	if s.builds != nil {
		out.Version, out.Builds, out.Release = s.builds.Version(), s.builds.List(), s.builds.Release()
		for _, b := range out.Release {
			if b.OS == windowsOS && s.builds.Withheld(b.OS, b.Arch) {
				out.Withheld = append(out.Withheld, b.Arch)
			}
		}
	}
	err := s.db.ReadTx(ctx, database.System, func(tx pgx.Tx) error {
		p, err := loadPolicy(ctx, tx)
		if err != nil {
			return err
		}
		signed, err := listSigned(ctx, tx)
		if err != nil {
			return err
		}
		for i := range signed {
			signed[i].Served = s.builds != nil && s.served(signed[i].SHA256)
		}
		out.Signed = signed
		out.UpdatePolicy, out.Stored = p.UpdatePolicy, p.stored
		if p.stored {
			out.UpdatedAt = &p.updatedAt
			if p.updatedBy != nil {
				out.UpdatedBy = *p.updatedBy
			}
		}
		rows, err := tx.Query(ctx, `SELECT d.organization_id, d.platform, coalesce(d.agent_arch, ''), coalesce(d.agent_sha256, ''),
				coalesce(u.state, ''), coalesce(u.target_sha256, ''), count(*)
			FROM devices d LEFT JOIN agent_updates u ON u.device_id = d.id
			WHERE d.agent_public_key IS NOT NULL
			GROUP BY 1, 2, 3, 4, 5, 6`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var org uuid.UUID
			var platform, arch, sha, state, target string
			var n int
			if err := rows.Scan(&org, &platform, &arch, &sha, &state, &target, &n); err != nil {
				return err
			}
			build, ok := s.BuildLookup(org, platform, arch)
			switch {
			case !ok:
				out.Fleet["none"] += n
			case build.SHA256 == "":
				out.Fleet[devices.UpdateWaiting] += n
			default:
				out.Fleet[devices.UpdateStatus(sha, build.SHA256, state, target)] += n
			}
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("agents: reading the update setting: %w", err)
	}
	return out, nil
}

// SetUpdatePolicy changes the rollout's setting.
func (s *Service) SetUpdatePolicy(ctx context.Context, c access.Caller, p UpdatePolicy) (*UpdateSettings, error) {
	if err := c.RequireGlobal(rbac.PermSettingsManage); err != nil {
		return nil, err
	}
	if err := p.Validate(); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}
	err = s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		old, err := loadPolicy(ctx, tx)
		if err != nil {
			return err
		}
		if p.SignedOnly && !old.SignedOnly {
			var have bool
			if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM signed_agent_builds)`).Scan(&have); err != nil {
				return err
			}
			if !have {
				return apperr.Conflict("no_signed_builds", "Upload a signed Windows build first: with none, no Windows agent could be installed.")
			}
		}
		if _, err := tx.Exec(ctx, `INSERT INTO settings (key, value, updated_at, updated_by) VALUES ($1, $2, now(), $3)
			ON CONFLICT (key) DO UPDATE SET value = $2, updated_at = now(), updated_by = $3`,
			updatePolicyKey, raw, userID(c)); err != nil {
			return err
		}
		return s.audit.Write(ctx, tx, audit.Event{
			Actor: c.Actor, Action: "agent_updates.update", Outcome: audit.Success,
			TargetType: "agent_updates", TargetID: updatePolicyKey,
			Details: map[string]any{
				"mode": p.Mode, "maxConcurrent": p.MaxConcurrent, "signedOnly": p.SignedOnly,
				"previousMode": old.Mode, "previousMaxConcurrent": old.MaxConcurrent, "previousSignedOnly": old.SignedOnly,
			},
		})
	})
	if err != nil {
		return nil, err
	}
	if err := s.LoadSignedBuilds(ctx); err != nil {
		return nil, err
	}
	return s.UpdateSettings(ctx, c)
}

// RequestUpdate asks for a device's agent to be updated to the server's
// build: it goes out in manual mode too, and a failed update starts over.
func (s *Service) RequestUpdate(ctx context.Context, c access.Caller, deviceID uuid.UUID) error {
	d, err := devices.Lookup(ctx, s.db, c, deviceID)
	if err != nil {
		return err
	}
	if err := c.Require(rbac.PermDeviceEdit, rbac.Site(d.OrganizationID, d.SiteID)); err != nil {
		return err
	}
	if d.Agent == nil {
		return apperr.Conflict("no_agent", "This device has no EasyRMM agent.")
	}
	var b Build
	ok := false
	if builds := s.BuildsFor(d.OrganizationID); builds != nil && s.updateKey != nil {
		b, ok = builds.For(d.Platform, d.Agent.Arch)
	}
	switch {
	case !ok:
		return apperr.Conflict("no_build", "The server has no agent build for this device's platform.")
	case d.Agent.SHA256 == "":
		return apperr.Conflict("agent_too_old", "This agent is too old to update itself. Run the install command on the device again.")
	case d.Agent.SHA256 == b.SHA256:
		return apperr.Conflict("agent_current", "The agent already runs the server's build.")
	}
	_, err = s.request(ctx, c, []uuid.UUID{d.ID}, b, false)
	return err
}

// RequestAll asks for every outdated agent that can update itself to be
// updated, failed ones included, and returns how many were asked for. With a
// dev scope set, each device is asked for its own organization's build.
func (s *Service) RequestAll(ctx context.Context, c access.Caller) (int, error) {
	if err := c.RequireGlobal(rbac.PermSettingsManage); err != nil {
		return 0, err
	}
	if s.updateKey == nil {
		return 0, nil
	}
	// The organizations a set of builds is for: all of them, or with a dev
	// scope the one inside it for the server's builds and the rest for the
	// stable ones.
	type pass struct {
		builds *Builds
		where  string
		args   []any
	}
	passes := []pass{{builds: s.builds, where: "TRUE"}}
	if org, ok := devscope.Org(); ok {
		passes = []pass{
			{builds: s.builds, where: "d.organization_id = $4", args: []any{org}},
			{builds: s.stable, where: "d.organization_id <> $4", args: []any{org}},
		}
	}
	total := 0
	for _, ps := range passes {
		if ps.builds == nil {
			continue
		}
		for _, b := range ps.builds.List() {
			var ids []uuid.UUID
			err := s.db.ReadTx(ctx, database.System, func(tx pgx.Tx) error {
				rows, err := tx.Query(ctx, `SELECT d.id FROM devices d
					WHERE d.agent_public_key IS NOT NULL AND d.platform = $1 AND d.agent_arch = $2
					  AND d.agent_sha256 IS NOT NULL AND d.agent_sha256 <> $3 AND `+ps.where,
					append([]any{b.OS, b.Arch, b.SHA256}, ps.args...)...)
				if err != nil {
					return err
				}
				ids, err = pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
				return err
			})
			if err != nil {
				return 0, err
			}
			if len(ids) == 0 {
				continue
			}
			n, err := s.request(ctx, c, ids, b, true)
			if err != nil {
				return 0, err
			}
			total += n
		}
	}
	return total, nil
}

// request marks updates of devices to build b as asked for, one device or
// all outdated ones. An update in flight to b stays in flight; any other
// starts over.
func (s *Service) request(ctx context.Context, c access.Caller, ids []uuid.UUID, b Build, all bool) (int, error) {
	var n int
	err := s.db.InTx(ctx, c.Scope, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `INSERT INTO agent_updates (device_id, target_sha256, target_version, state, requested, requested_by)
			SELECT d.id, $2, $3, 'queued', true, $4 FROM devices d WHERE d.id = ANY ($1)
			ON CONFLICT (device_id) DO UPDATE SET requested = true, requested_by = $4, updated_at = now(),
				target_sha256 = $2, target_version = $3,
				state = CASE WHEN agent_updates.state = 'sent' AND agent_updates.target_sha256 = $2 THEN 'sent' ELSE 'queued' END,
				attempt_id = CASE WHEN agent_updates.state = 'sent' AND agent_updates.target_sha256 = $2 THEN agent_updates.attempt_id END,
				sent_at = CASE WHEN agent_updates.state = 'sent' AND agent_updates.target_sha256 = $2 THEN agent_updates.sent_at END,
				attempts = CASE WHEN agent_updates.state = 'sent' AND agent_updates.target_sha256 = $2 THEN agent_updates.attempts ELSE 0 END,
				retry_after = NULL,
				error = CASE WHEN agent_updates.state = 'sent' AND agent_updates.target_sha256 = $2 THEN agent_updates.error ELSE '' END`,
			ids, b.SHA256, b.Version, userID(c))
		if err != nil {
			return err
		}
		n = int(tag.RowsAffected())
		details := map[string]any{"to": b.Version, "sha256": b.SHA256, "platform": b.OS, "arch": b.Arch}
		if !all {
			var org, site uuid.UUID
			var name string
			if err := tx.QueryRow(ctx, `SELECT organization_id, site_id, name FROM devices WHERE id = $1`, ids[0]).
				Scan(&org, &site, &name); err != nil {
				return err
			}
			details["device"] = name
			return s.audit.Write(ctx, tx, audit.Event{
				Actor: c.Actor, Action: "device.agent_update_request", Outcome: audit.Success,
				OrganizationID: org, SiteID: site, DeviceID: ids[0], TargetType: "device", TargetID: ids[0].String(),
				Details: details,
			})
		}
		details["devices"] = n
		return s.audit.Write(ctx, tx, audit.Event{
			Actor: c.Actor, Action: "agent_updates.request_all", Outcome: audit.Success,
			TargetType: "agent_updates", TargetID: updatePolicyKey, Details: details,
		})
	})
	return n, err
}
