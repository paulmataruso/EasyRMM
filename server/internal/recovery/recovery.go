// Package recovery repairs agents that stopped working (ADR-0069, Part R).
// A repair has a target, the agent that carries it out and steps tried in
// order. The server hands the current step to the carrying agent in a
// heartbeat answer, settles the agent's report, waits for the target to come
// back and moves on to the next step or ends the repair.
package recovery

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/internal/logredact"
	"github.com/paulmataruso/easyrmm/server/internal/access"
	"github.com/paulmataruso/easyrmm/server/internal/agentlogs"
	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/devices"
	"github.com/paulmataruso/easyrmm/server/internal/devscope"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
)

// Timing.
const (
	// StepValid is how long an instruction is valid, and how long the
	// carrying agent has to take a step before the repair gives up on it.
	StepValid = 15 * time.Minute
	// ManualWait is how long a target gets to come back after a step of a
	// repair someone asked for, before the next step is tried.
	ManualWait = 2 * time.Minute
	// MaxRunning is the longest a repair may run.
	MaxRunning = time.Hour
	// Interval is how often the loop looks at running repairs.
	Interval = 15 * time.Second
	// Keep is how long finished repairs are kept.
	Keep = 90 * 24 * time.Hour
	// ListMax is how many repairs a device's list shows.
	ListMax = 10
	// ManualWaitPatching is the same for the EasyPatch agent, whose check-in
	// reaches EasyRMM through the engine every 5 minutes.
	ManualWaitPatching = 7 * time.Minute
	// MaxDiagnostics is the most bytes of diagnostics kept for a repair.
	MaxDiagnostics = 256 * 1024
	// AgentFresh is how recently the EasyRMM agent must have checked in to
	// count as back, as the conditions count a check-in.
	AgentFresh = 3 * time.Minute
)

// lockAdvance is the advisory lock that keeps two servers on one database
// from advancing repairs at the same time.
const lockAdvance = 7302265818152

// Repair states.
const (
	Running   = "running"
	Succeeded = "succeeded"
	Failed    = "failed"
)

// Step states.
const (
	StepPending = "pending"
	StepSent    = "sent"
	StepDone    = "done"
	StepFailed  = "failed"
)

// Carriers of a repair.
const carrierPatching = agentproto.TargetEasyPatchAgent

// Triggers.
const (
	TriggerManual    = "manual"
	TriggerAutomatic = "automatic"
)

// Step is one step of a repair.
type Step struct {
	ID     string     `json:"id"`
	Step   string     `json:"step"`
	State  string     `json:"state"`
	SentAt *time.Time `json:"sentAt,omitempty"`
	DoneAt *time.Time `json:"doneAt,omitempty"`
	Error  string     `json:"error,omitempty"`
	// JobID is the patching engine's job, for a step the EasyPatch agent
	// carries; Note what that agent said of a step that went well.
	JobID string `json:"jobId,omitempty"`
	Note  string `json:"note,omitempty"`
}

// Repair is a repair as the console shows it.
type Repair struct {
	ID        uuid.UUID  `json:"id"`
	Target    string     `json:"target"`
	CarriedBy string     `json:"carriedBy"`
	Trigger   string     `json:"trigger"`
	State     string     `json:"state"`
	Steps     []Step     `json:"steps"`
	StartedAt time.Time  `json:"startedAt"`
	EndedAt   *time.Time `json:"endedAt"`
	// Error says why a failed repair failed.
	Error string `json:"error"`
}

// Patching is what recovery needs of patching (package easypatch): whether
// the EasyPatch agents' check-ins can be trusted now, and the package that
// repairs one in place.
type Patching interface {
	// AgentsSettled says whether conditions about EasyPatch agents may be
	// judged: the engine answers, and has for a while.
	AgentsSettled(now time.Time) bool
	// RepairOffer builds what repairing a device's EasyPatch agent in place
	// needs; why says what stops it.
	RepairOffer(ctx context.Context, deviceID uuid.UUID) (offer *agentproto.RepairEasyPatch, why string, err error)
	// StartCompanion has the device's EasyPatch agent carry out a step on
	// the EasyRMM agent (a RepairCompanion job): it returns the engine's
	// job; why says what stops it for good, err that the engine could not
	// be reached.
	StartCompanion(ctx context.Context, deviceID uuid.UUID, target, step, expectedSHA256 string) (jobID, why string, err error)
	// CompanionResult says how that job stands: done when it ended, ok
	// when it did what it was asked, its message and diagnostics.
	CompanionResult(ctx context.Context, jobID string) (done, ok bool, message, diagnostics string, err error)
	// CancelCompanion cancels a job that did not run in time.
	CancelCompanion(ctx context.Context, jobID string)
}

// MeshLink says whether EasyRMM's own connection to MeshCentral is up and
// since when (ADR-0069: nothing is judged while it is down).
type MeshLink func() (connected bool, since time.Time)

// Service plans, hands out and settles repairs.
type Service struct {
	db     *database.DB
	audit  *audit.Logger
	log    *slog.Logger
	now    func() time.Time
	key    ed25519.PrivateKey
	remote bool
	link   MeshLink
	patch  Patching
	// published lists the SHA-256 of the release's builds for an
	// organization's devices, a platform and an architecture (SetBuilds):
	// the stable set outside the dev scope.
	published func(org uuid.UUID, platform, arch string) []string
	wake      chan struct{}
}

// New builds the service. remote says whether this server runs remote
// access, the only thing a repair is for in this slice.
func New(db *database.DB, auditLog *audit.Logger, remote bool, log *slog.Logger) *Service {
	return &Service{db: db, audit: auditLog, remote: remote, log: log, now: time.Now, wake: make(chan struct{}, 1)}
}

// SetKey sets the job key repair instructions are signed with. Without it
// no repair is asked for.
func (s *Service) SetKey(k ed25519.PrivateKey) { s.key = k }

// SetBuilds tells the service which builds the server bundles, by platform
// and architecture. A recovery copy is only checked against a hash the
// server itself publishes (ADR-0069); without this no repair step is asked
// for.
func (s *Service) SetBuilds(published func(org uuid.UUID, platform, arch string) []string) {
	s.published = published
}

// UsePatching gives the service the patching side; without it the EasyPatch
// agent is not repaired.
func (s *Service) UsePatching(p Patching) { s.patch = p }

// FollowMesh makes repairs wait while EasyRMM's connection to MeshCentral
// is down.
func (s *Service) FollowMesh(l MeshLink) { s.link = l }

func (s *Service) kick() {
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

// carriedBy returns the agent that carries a repair of the target out, or
// "" for a target this server cannot repair yet.
func carriedBy(target string) string {
	switch target {
	case agentproto.TargetMeshAgent, agentproto.TargetEasyPatchAgent:
		return agentproto.TargetEasyRMMAgent
	case agentproto.TargetEasyRMMAgent:
		// The EasyRMM agent cannot repair itself while it is silent: the
		// EasyPatch agent does, through the patching engine.
		return carrierPatching
	}
	return ""
}

// waitFor is how long a target gets to come back after a step before the
// next one is tried, and after the last.
func waitFor(target, trigger string) time.Duration {
	switch {
	case trigger == TriggerAutomatic && target == agentproto.TargetMeshAgent:
		return AutoWaitMesh
	case trigger == TriggerAutomatic:
		return AutoWaitPatching
	case target == agentproto.TargetEasyPatchAgent:
		return ManualWaitPatching
	}
	return ManualWait
}

// errRunning is a repair of the target that is running already.
var errRunning = errors.New("recovery: a repair of this is already running")

// repairSteps are the steps of a repair, tried in order.
var repairSteps = []string{agentproto.StepRestart, agentproto.StepRepair}

// Request starts a repair someone asked for in the console: "Reconnect
// remote access" is a repair of MeshAgent through the EasyRMM agent, and
// "Repair patching agent" one of the EasyPatch agent; both need device.edit
// on the device. "Repair EasyRMM agent through patching" is a repair of the
// EasyRMM agent through the EasyPatch agent and needs patch.manage.
func (s *Service) Request(ctx context.Context, c access.Caller, deviceID uuid.UUID, target string) (*Repair, error) {
	carrier := carriedBy(target)
	if carrier == "" {
		return nil, apperr.Invalid("target", "Choose meshagent, easypatch-agent or easyrmm-agent.")
	}
	d, err := devices.Lookup(ctx, s.db, c, deviceID)
	if err != nil {
		return nil, err
	}
	perm := rbac.PermDeviceEdit
	if carrier == carrierPatching {
		perm = rbac.PermPatchManage
	}
	if err := c.Require(perm, rbac.Site(d.OrganizationID, d.SiteID)); err != nil {
		return nil, err
	}
	viaPatching := carrier == carrierPatching
	switch {
	case target == agentproto.TargetMeshAgent && !s.remote:
		return nil, apperr.Conflict("no_remote_access", "This server runs without remote access.")
	case (target == agentproto.TargetEasyPatchAgent || viaPatching) && s.patch == nil:
		return nil, apperr.Conflict("no_patching", "This server runs without patching.")
	case d.Agent == nil && viaPatching:
		return nil, apperr.Conflict("no_agent", "The device has no EasyRMM agent to repair.")
	case d.Agent == nil:
		return nil, apperr.Conflict("no_agent", "The device has no EasyRMM agent to repair with.")
	case viaPatching && d.Agent.Online:
		return nil, apperr.Conflict("agent_online", "The EasyRMM agent is checking in, so there is nothing to repair through patching.")
	case !viaPatching && s.key == nil:
		return nil, apperr.Conflict("no_job_key", "The server cannot sign instructions to agents.")
	case !viaPatching && !d.Agent.Online:
		return nil, apperr.Conflict("device_offline", "The device is not checking in, so nothing can be repaired from here.")
	}
	var out *Repair
	err = s.db.InTx(ctx, c.Scope, func(tx pgx.Tx) error {
		var leaving, orgLinked, linked bool
		var seen *time.Time
		if err := tx.QueryRow(ctx, `SELECT `+devices.LeavingSQL+`,
				EXISTS (SELECT 1 FROM easypatch_organizations l WHERE l.organization_id = d.organization_id),
				EXISTS (SELECT 1 FROM easypatch_devices e WHERE e.device_id = d.id AND e.state = 'linked'),
				(SELECT e.agent_seen_at FROM easypatch_devices e WHERE e.device_id = d.id AND e.state = 'linked')
			FROM devices d WHERE d.id = $1`, d.ID).Scan(&leaving, &orgLinked, &linked, &seen); err != nil {
			return err
		}
		switch {
		case leaving:
			return apperr.Conflict("device_leaving", "The device is being removed; nothing is repaired on it.")
		case target == agentproto.TargetEasyPatchAgent && !orgLinked:
			return apperr.Conflict("patching_off", "Patching is not set up for this device's organization, so the device has no EasyPatch agent to repair.")
		case target == agentproto.TargetEasyPatchAgent && !linked:
			return apperr.Conflict("no_patching_agent", "This device has no EasyPatch agent that is linked to it. Install it from the Patching page first.")
		case viaPatching && !orgLinked:
			return apperr.Conflict("patching_off", "Patching is not set up for this device's organization, so there is no EasyPatch agent to repair the EasyRMM agent with.")
		case viaPatching && !linked:
			return apperr.Conflict("no_patching_agent", "This device has no EasyPatch agent that is linked to it, so nothing can repair the EasyRMM agent from here.")
		case viaPatching && (seen == nil || s.now().Sub(*seen) >= SilentAfter):
			return apperr.Conflict("patching_agent_silent", "The EasyPatch agent has not checked in with the patching engine in the last 10 minutes, so it cannot repair the EasyRMM agent.")
		}
		var by *uuid.UUID
		if c.Principal != nil {
			by = &c.Principal.UserID
		}
		r, err := s.insert(ctx, tx, d.ID, target, TriggerManual, by)
		if err != nil {
			return err
		}
		out = r
		return s.audit.Write(ctx, tx, audit.Event{
			Actor: c.Actor, Action: "device.repair_request", Outcome: audit.Success,
			OrganizationID: d.OrganizationID, SiteID: d.SiteID, DeviceID: d.ID, TargetType: "device", TargetID: d.ID.String(),
			Details: map[string]any{"device": d.Name, "target": target, "repair": r.ID.String()},
		})
	})
	if errors.Is(err, errRunning) || database.IsUniqueViolation(err) {
		return nil, apperr.Conflict("repair_running", "A repair of this is already running.")
	}
	if err != nil {
		return nil, err
	}
	return out, nil
}

// insert starts a repair of target on a device, its first step pending.
func (s *Service) insert(ctx context.Context, tx pgx.Tx, deviceID uuid.UUID, target, trigger string, by *uuid.UUID) (*Repair, error) {
	id := uuid.New()
	var list []Step
	for i, st := range repairSteps {
		list = append(list, Step{ID: fmt.Sprintf("%s.%d", id, i), Step: st, State: StepPending})
	}
	b, err := json.Marshal(list)
	if err != nil {
		return nil, err
	}
	now := s.now()
	tag, err := tx.Exec(ctx, `INSERT INTO agent_repairs (id, device_id, target, carried_by, trigger, requested_by, state, steps, step, wait_seconds, next_at, started_at)
		VALUES ($1, $2, $3, $4, $5, $6, 'running', $7, 0, $8, $9, $10)
		ON CONFLICT (device_id, target) WHERE state = 'running' DO NOTHING`,
		id, deviceID, target, carriedBy(target), trigger, by, b, int(waitFor(target, trigger).Seconds()), now.Add(StepValid), now)
	if err != nil {
		return nil, err
	}
	if tag.RowsAffected() == 0 {
		return nil, errRunning
	}
	s.kick()
	return &Repair{ID: id, Target: target, CarriedBy: carriedBy(target), Trigger: trigger, State: Running, Steps: list, StartedAt: now}, nil
}

const repairColumns = `id, target, carried_by, trigger, state, steps, started_at, ended_at, error`

func scanRepair(row pgx.Row) (*Repair, error) {
	var (
		r Repair
		b []byte
	)
	if err := row.Scan(&r.ID, &r.Target, &r.CarriedBy, &r.Trigger, &r.State, &b, &r.StartedAt, &r.EndedAt, &r.Error); err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, &r.Steps); err != nil {
		return nil, err
	}
	return &r, nil
}

// List returns a device's latest repairs, newest first. It needs the
// device to be visible to the caller.
func (s *Service) List(ctx context.Context, c access.Caller, deviceID uuid.UUID) ([]*Repair, error) {
	if _, err := devices.Lookup(ctx, s.db, c, deviceID); err != nil {
		return nil, err
	}
	out := []*Repair{}
	err := s.db.ReadTx(ctx, c.Scope, func(tx pgx.Tx) error {
		out = out[:0]
		rows, err := tx.Query(ctx, `SELECT `+repairColumns+` FROM agent_repairs WHERE device_id = $1 ORDER BY started_at DESC, id LIMIT $2`, deviceID, ListMax)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			r, err := scanRepair(rows)
			if err != nil {
				return err
			}
			out = append(out, r)
		}
		return rows.Err()
	})
	return out, err
}

// AgentHeartbeat settles the outcome an agent reported and returns the
// repair step it is to carry out now, nil for none. It is called with each
// heartbeat: a failure is logged and the heartbeat still counts.
func (s *Service) AgentHeartbeat(ctx context.Context, deviceID uuid.UUID, rep *agentproto.RepairReport) *agentproto.SignedRepair {
	if s.key == nil {
		return nil
	}
	var cur *current
	err := s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		cur = nil
		if rep != nil {
			if err := s.settle(ctx, tx, deviceID, *rep); err != nil {
				return err
			}
		}
		var (
			id     uuid.UUID
			raw    []byte
			step   int
			target string
		)
		// Nothing is handed to a device that is leaving.
		err := tx.QueryRow(ctx, `SELECT r.id, r.steps, r.step, r.target FROM agent_repairs r JOIN devices d ON d.id = r.device_id
			WHERE r.device_id = $1 AND r.state = 'running' AND r.carried_by = 'easyrmm-agent' AND NOT `+devices.LeavingSQL+`
			  AND (r.target <> 'easypatch-agent' OR `+patchedSQL+`)
			FOR UPDATE OF r`, deviceID).Scan(&id, &raw, &step, &target)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		var list []Step
		if err := json.Unmarshal(raw, &list); err != nil {
			return err
		}
		if step >= len(list) || (list[step].State != StepPending && list[step].State != StepSent) {
			return nil
		}
		now := s.now().UTC()
		if list[step].SentAt == nil {
			list[step].SentAt, list[step].State = &now, StepSent
			b, err := json.Marshal(list)
			if err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `UPDATE agent_repairs SET steps = $2 WHERE id = $1`, id, b); err != nil {
				return err
			}
		}
		cur = &current{stepID: list[step].ID, step: list[step].Step, target: target, now: now}
		return nil
	})
	if err != nil {
		s.log.Error("recovery: settling a heartbeat failed", "error", err, "device_id", deviceID)
		return nil
	}
	if cur == nil {
		return nil
	}
	p := agentproto.RepairPayload{
		V: agentproto.RepairPayloadVersion, ID: cur.stepID, DeviceID: deviceID.String(), Target: cur.target, Step: cur.step,
		IssuedAt: cur.now, ExpiresAt: cur.now.Add(StepValid),
	}
	if cur.target == agentproto.TargetEasyPatchAgent && cur.step == agentproto.StepRepair {
		// The package comes from the patching engine, outside the
		// transaction. A repair that cannot be offered ends as failed, with
		// the reason.
		why := "This server runs without patching."
		var offer *agentproto.RepairEasyPatch
		if s.patch != nil {
			offer, why, err = s.patch.RepairOffer(ctx, deviceID)
			if err != nil {
				s.log.Error("recovery: preparing the EasyPatch agent's repair failed", "error", err, "device_id", deviceID)
				why = "EasyRMM could not prepare the repair. The server log has the details."
			}
		}
		if offer == nil {
			s.failStep(ctx, deviceID, cur.stepID, why)
			return nil
		}
		p.EasyPatch = offer
	}
	sr, err := agentproto.SignRepair(s.key, p)
	if err != nil {
		s.log.Error("recovery: signing a repair step failed", "error", err, "device_id", deviceID)
		return nil
	}
	// What the agent would refuse is refused here, with its reason.
	if pub, ok := s.key.Public().(ed25519.PublicKey); ok {
		if _, err := agentproto.VerifyRepair(pub, sr, deviceID.String(), cur.now); err != nil {
			s.failStep(ctx, deviceID, cur.stepID, "The patching engine's address or packages are not in a form the agent accepts: "+
				strings.TrimPrefix(err.Error(), "agentproto: ")+".")
			return nil
		}
	}
	return &sr
}

// patchedSQL holds for a device (aliased d) whose organization is patched:
// only then does it have an EasyPatch agent to repair.
const patchedSQL = `EXISTS (SELECT 1 FROM easypatch_organizations lo WHERE lo.organization_id = d.organization_id)`

// current is the step an agent is to carry out now.
type current struct {
	stepID, step, target string
	now                  time.Time
}

// failStep ends a step the server could not hand out as failed, as if the
// agent had reported it.
func (s *Service) failStep(ctx context.Context, deviceID uuid.UUID, stepID, why string) {
	err := s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		return s.settle(ctx, tx, deviceID, agentproto.RepairReport{ID: stepID, Error: why})
	})
	if err != nil {
		s.log.Error("recovery: ending a repair step failed", "error", err, "device_id", deviceID)
	}
}

// settle records the outcome of the step an agent reports. A report for a
// step that is not the one in hand (repeated until an hour after it ended,
// or for a repair that is over) changes nothing.
func (s *Service) settle(ctx context.Context, tx pgx.Tx, deviceID uuid.UUID, rep agentproto.RepairReport) error {
	return s.settleStep(ctx, tx, agentproto.TargetEasyRMMAgent, deviceID, rep, "", "")
}

// settleStep records the outcome of a step of a repair that carrier carries
// out (settle's, and the EasyPatch agent's through the engine, which
// brings a note on a step that went well and diagnostics).
func (s *Service) settleStep(ctx context.Context, tx pgx.Tx, carrier string, deviceID uuid.UUID, rep agentproto.RepairReport, note, diagnostics string) error {
	var (
		id    uuid.UUID
		steps []byte
		step  int
		wait  int
	)
	err := tx.QueryRow(ctx, `SELECT id, steps, step, wait_seconds FROM agent_repairs
		WHERE device_id = $1 AND state = 'running' AND carried_by = $2 FOR UPDATE`, deviceID, carrier).Scan(&id, &steps, &step, &wait)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	var list []Step
	if err := json.Unmarshal(steps, &list); err != nil {
		return err
	}
	if step >= len(list) || list[step].ID != rep.ID || list[step].State == StepDone || list[step].State == StepFailed {
		return nil
	}
	now := s.now().UTC()
	list[step].DoneAt = &now
	if diagnostics = keepDiagnostics(diagnostics); diagnostics != "" {
		// The step's diagnostics go into the device's agent log, where the
		// Logs tab shows them with the other sources (ADR-0069, amended
		// 2026-11-26). The carrier is the EasyPatch agent: it is the only
		// one that returns them.
		level := agentproto.LogInfo
		if !rep.OK {
			level = agentproto.LogWarn
		}
		if err := agentlogs.StoreText(ctx, tx, deviceID, agentproto.LogSourceEasyPatch, level, now, diagnostics,
			map[string]string{"repair": id.String(), "step": list[step].Step}); err != nil {
			return err
		}
	}
	if rep.OK {
		list[step].State, list[step].Note = StepDone, truncate(logredact.Text(note), agentproto.MaxRepairError)
		b, err := json.Marshal(list)
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `UPDATE agent_repairs SET steps = $2, next_at = $3 WHERE id = $1`, id, b, now.Add(time.Duration(wait)*time.Second))
		return err
	}
	list[step].State, list[step].Error = StepFailed, truncate(logredact.Text(rep.Error), agentproto.MaxRepairError)
	// The step failed: the next one is tried at once, the repair ends when
	// there is none.
	return s.nextStep(ctx, tx, id, list, step, now, "The last step failed: "+list[step].Error)
}

// nextStep moves a repair on from a step that did not bring the target
// back: to the next step, or to its end when there is none.
func (s *Service) nextStep(ctx context.Context, tx pgx.Tx, id uuid.UUID, list []Step, step int, now time.Time, why string) error {
	b, err := json.Marshal(list)
	if err != nil {
		return err
	}
	if step+1 < len(list) {
		_, err = tx.Exec(ctx, `UPDATE agent_repairs SET steps = $2, step = $3, next_at = $4 WHERE id = $1`, id, b, step+1, now.Add(StepValid))
		return err
	}
	return s.end(ctx, tx, id, Failed, b, why, now)
}

// end finishes a repair and audits how it ended. An automatic repair that
// fails raises the Repair failed alert.
func (s *Service) end(ctx context.Context, tx pgx.Tx, id uuid.UUID, state string, steps []byte, why string, now time.Time) error {
	return s.finish(ctx, tx, id, state, steps, why, now, false)
}

// endQuiet is end for a repair that stops because it is no longer wanted:
// it raises no alert.
func (s *Service) endQuiet(ctx context.Context, tx pgx.Tx, id uuid.UUID, why string, now time.Time) error {
	return s.finish(ctx, tx, id, Failed, nil, why, now, true)
}

func (s *Service) finish(ctx context.Context, tx pgx.Tx, id uuid.UUID, state string, steps []byte, why string, now time.Time, quiet bool) error {
	var (
		dev     uuid.UUID
		org     uuid.UUID
		site    uuid.UUID
		name    string
		target  string
		trigger string
	)
	err := tx.QueryRow(ctx, `UPDATE agent_repairs r SET state = $2, steps = coalesce($3, steps), error = $4, ended_at = $5, next_at = NULL
		FROM devices d WHERE r.id = $1 AND d.id = r.device_id
		RETURNING d.id, d.organization_id, d.site_id, d.name, r.target, r.trigger`, id, state, steps, truncate(why, 1000), now).Scan(&dev, &org, &site, &name, &target, &trigger)
	if err != nil {
		return err
	}
	outcome := audit.Success
	if state != Succeeded {
		outcome = audit.Failure
	}
	if err := s.audit.Write(ctx, tx, audit.Event{
		Actor: audit.SystemActor("recovery"), Action: "device.repair_end", Outcome: outcome,
		OrganizationID: org, SiteID: site, DeviceID: dev, TargetType: "device", TargetID: dev.String(),
		Details: map[string]any{"device": name, "target": target, "repair": id.String(), "state": state, "error": why},
	}); err != nil {
		return err
	}
	if state == Failed && trigger == TriggerAutomatic && !quiet {
		return s.raiseFailed(ctx, tx, dev, target, why, now)
	}
	return nil
}

// targetLabel names a repair target for people.
func targetLabel(target string) string {
	switch target {
	case agentproto.TargetMeshAgent:
		return "MeshAgent"
	case agentproto.TargetEasyPatchAgent:
		return "EasyPatch agent"
	}
	return "EasyRMM agent"
}

// raiseFailed opens the Repair failed alert, a warning, for a device whose
// automatic repair ended with its target still broken: its detail is the
// last step's diagnostics. A device has one per target until the target is
// back (Evaluate resolves it); another failed attempt updates it.
func (s *Service) raiseFailed(ctx context.Context, tx pgx.Tx, device uuid.UUID, target, why string, now time.Time) error {
	detail := "Repairing the " + targetLabel(target) + " did not bring it back. " + why
	_, err := tx.Exec(ctx, `INSERT INTO alerts (policy_id, device_id, name, kind, threshold, minutes, severity, subject, subject_label, detail, value, last_value, opened_at)
		VALUES (NULL, $1, 'Repair failed', 'repair_failed', NULL, 0, 'warning', $2, $3, left($4, 500), 0, 0, $5)
		ON CONFLICT (device_id, subject) WHERE kind = 'repair_failed' AND status <> 'resolved' DO UPDATE SET detail = excluded.detail`,
		device, target, targetLabel(target), detail, now)
	return err
}

// Run looks at the running repairs every Interval (or when one starts) and
// forgets old ones, until ctx ends.
func (s *Service) Run(ctx context.Context) {
	tick := time.NewTicker(Interval)
	defer tick.Stop()
	var lastPurge time.Time
	for {
		if err := s.Advance(ctx); err != nil && ctx.Err() == nil {
			s.log.Error("recovery: advancing repairs failed", "error", err)
		}
		if err := s.Dispatch(ctx); err != nil && ctx.Err() == nil {
			s.log.Error("recovery: carrying steps out through the patching engine failed", "error", err)
		}
		if err := s.Evaluate(ctx); err != nil && ctx.Err() == nil {
			s.log.Error("recovery: judging conditions for automatic repairs failed", "error", err)
		}
		if s.now().Sub(lastPurge) >= time.Hour {
			if err := s.purge(ctx); err != nil && ctx.Err() == nil {
				s.log.Error("recovery: removing old repairs failed", "error", err)
			} else if err == nil {
				lastPurge = s.now()
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		case <-s.wake:
		}
	}
}

func (s *Service) purge(ctx context.Context) error {
	return s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `DELETE FROM agent_repairs WHERE state <> 'running' AND ended_at < $1`, s.now().Add(-Keep)); err != nil {
			return err
		}
		return nil
	})
}

// Advance settles what the running repairs wait for: a target that came
// back ends its repair; a step whose wait is over gives way to the next, or
// to the end of the repair; a step the carrying agent never took ends it.
// A device that is leaving ends its repair, and so does turning automatic
// repairs off for an automatic one. Nothing is judged while EasyRMM cannot
// see MeshCentral (for MeshAgent) or the patching engine (for the EasyPatch
// agent).
func (s *Service) Advance(ctx context.Context) error {
	return s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		var locked bool
		if err := tx.QueryRow(ctx, `SELECT pg_try_advisory_xact_lock($1)`, int64(lockAdvance)).Scan(&locked); err != nil || !locked {
			return err
		}
		now := s.now().UTC()
		connected := true
		if s.link != nil {
			connected, _ = s.link()
		}
		patchOK := s.patch != nil && s.patch.AgentsSettled(now)
		rows, err := tx.Query(ctx, `SELECT r.id, r.target, r.trigger, r.steps, r.step, r.next_at, r.started_at, d.remote_online, d.remote_changed_at,
				e.agent_seen_at, d.agent_last_seen_at, o.auto_repair, `+patchedSQL+`, `+devices.LeavingSQL+`
			FROM agent_repairs r JOIN devices d ON d.id = r.device_id JOIN organizations o ON o.id = d.organization_id
			LEFT JOIN easypatch_devices e ON e.device_id = d.id AND e.state = 'linked'
			WHERE r.state = 'running' ORDER BY r.started_at FOR UPDATE OF r`)
		if err != nil {
			return err
		}
		type row struct {
			id          uuid.UUID
			target      string
			trigger     string
			steps       []byte
			step        int
			nextAt      *time.Time
			startedAt   time.Time
			facts       targetFacts
			autoRepair  bool
			patched     bool
			leaving     bool
			list        []Step
			stepsParsed error
		}
		var list []row
		for rows.Next() {
			var r row
			if err := rows.Scan(&r.id, &r.target, &r.trigger, &r.steps, &r.step, &r.nextAt, &r.startedAt, &r.facts.online, &r.facts.changedAt,
				&r.facts.patchSeen, &r.facts.agentSeen, &r.autoRepair, &r.patched, &r.leaving); err != nil {
				rows.Close()
				return err
			}
			r.stepsParsed = json.Unmarshal(r.steps, &r.list)
			list = append(list, r)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		for _, r := range list {
			switch {
			case r.stepsParsed != nil || r.step >= len(r.list):
				if err := s.end(ctx, tx, r.id, Failed, nil, "The repair's record is damaged.", now); err != nil {
					return err
				}
			case r.leaving:
				if err := s.endQuiet(ctx, tx, r.id, "The device is being removed.", now); err != nil {
					return err
				}
			case (r.target == agentproto.TargetEasyPatchAgent || r.target == agentproto.TargetEasyRMMAgent) && !r.patched:
				if err := s.endQuiet(ctx, tx, r.id, "Patching is off for the device's organization, so it has no EasyPatch agent to repair it with.", now); err != nil {
					return err
				}
			case r.trigger == TriggerAutomatic && !r.autoRepair:
				if err := s.endQuiet(ctx, tx, r.id, "Automatic repairs were turned off for the organization.", now); err != nil {
					return err
				}
			case now.Sub(r.startedAt) >= maxRunning(r.trigger):
				if err := s.end(ctx, tx, r.id, Failed, nil, "The repair took longer than "+maxRunning(r.trigger).String()+".", now); err != nil {
					return err
				}
			default:
				judge := connected
				switch r.target {
				case agentproto.TargetEasyPatchAgent:
					judge = patchOK
				case agentproto.TargetEasyRMMAgent:
					// Whether the EasyRMM agent is back is what its own
					// heartbeats say.
					judge = true
				}
				if err := s.advanceOne(ctx, tx, now, judge, r.id, r.target, r.list, r.step, r.nextAt, r.facts); err != nil {
					return err
				}
			}
		}
		return nil
	})
}

// lockDispatch keeps two servers on one database from carrying steps out
// through the engine at once: the engine refuses a second job for a step.
const lockDispatch = 7302265818154

// Dispatch carries the steps the EasyPatch agent is to take, through the
// patching engine (ADR-0069): it asks the engine for the RepairCompanion job
// of a step that waits, and reads the result of one that was asked for. A
// step the agent does not take within StepValid is canceled in the engine,
// so that it cannot run after the repair moved on, and fails. A repair of a
// device that is leaving is left to Advance, which ends it.
func (s *Service) Dispatch(ctx context.Context) error {
	if s.patch == nil {
		return nil
	}
	return s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		var locked bool
		if err := tx.QueryRow(ctx, `SELECT pg_try_advisory_xact_lock($1)`, int64(lockDispatch)).Scan(&locked); err != nil || !locked {
			return err
		}
		type row struct {
			id, device, org uuid.UUID
			target          string
			steps           []byte
			step            int
			sha             *string
			platform        string
			arch            *string
		}
		rows, err := tx.Query(ctx, `SELECT r.id, r.device_id, r.target, r.steps, r.step, d.agent_sha256, d.platform, d.agent_arch, d.organization_id
			FROM agent_repairs r JOIN devices d ON d.id = r.device_id
			WHERE r.state = 'running' AND r.carried_by = 'easypatch-agent' AND NOT `+devices.LeavingSQL+` AND `+patchedSQL+`
			ORDER BY r.started_at LIMIT 100`)
		if err != nil {
			return err
		}
		var list []row
		for rows.Next() {
			var r row
			if err := rows.Scan(&r.id, &r.device, &r.target, &r.steps, &r.step, &r.sha, &r.platform, &r.arch, &r.org); err != nil {
				rows.Close()
				return err
			}
			list = append(list, r)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		for _, r := range list {
			var steps []Step
			if err := json.Unmarshal(r.steps, &steps); err != nil || r.step >= len(steps) {
				continue // Advance ends a repair whose record is damaged
			}
			cur := steps[r.step]
			switch cur.State {
			case StepPending:
				if err := s.startStep(ctx, tx, r.id, r.device, r.org, r.target, r.sha, r.platform, r.arch, steps, r.step); err != nil {
					return err
				}
			case StepSent:
				if err := s.readStep(ctx, tx, r.device, steps, r.step); err != nil {
					return err
				}
			}
		}
		return nil
	})
}

// startStep asks the engine for the job of a step that waits. A refusal
// ends the step with its reason; an engine that cannot be reached leaves it
// waiting (Advance fails it after StepValid).
func (s *Service) startStep(ctx context.Context, tx pgx.Tx, id, device, org uuid.UUID, target string, sha *string, platform string, arch *string, steps []Step, step int) error {
	cur := steps[step]
	expected := ""
	why := ""
	if cur.Step == agentproto.StepRepair {
		// The recovery copy must be a build this server publishes for the
		// device's platform and architecture. The device reports its own
		// hash, so it is not trusted to name what its copy is checked
		// against. Restarts need no hash.
		switch {
		case sha == nil || *sha == "":
			why = "EasyRMM has no record of the build this device runs, so there is nothing to check the recovery copy against."
		case !s.publishes(ctx, tx, org, platform, arch, strings.ToLower(*sha)):
			why = "The build this device runs is not one this server publishes, so its recovery copy cannot be trusted to repair it. Update the agent, or reinstall it."
		default:
			expected = strings.ToLower(*sha)
		}
	}
	jobID := ""
	if why == "" {
		var err error
		jobID, why, err = s.patch.StartCompanion(ctx, device, target, cur.Step, expected)
		if err != nil {
			s.log.Warn("recovery: the patching engine could not be asked for a step", "error", err, "device_id", device)
			return nil
		}
	}
	if why != "" {
		return s.settleStep(ctx, tx, carrierPatching, device, agentproto.RepairReport{ID: cur.ID, Error: why}, "", "")
	}
	now := s.now().UTC()
	steps[step].State, steps[step].SentAt, steps[step].JobID = StepSent, &now, jobID
	b, err := json.Marshal(steps)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `UPDATE agent_repairs SET steps = $2 WHERE id = $1`, id, b)
	return err
}

// publishes says whether the server publishes a build of the platform and
// architecture with the SHA-256: a bundled one, or a signed Windows build an
// operator uploaded. org is the device's organization: outside the dev scope
// only the stable builds count, and a signed build only when it was made from
// one of them.
func (s *Service) publishes(ctx context.Context, tx pgx.Tx, org uuid.UUID, platform string, arch *string, sha string) bool {
	if arch == nil || *arch == "" {
		return false
	}
	var release []string
	if s.published != nil {
		release = s.published(org, platform, *arch)
	}
	if slices.Contains(release, sha) {
		return true
	}
	if platform != "windows" {
		return false
	}
	var ok bool
	var err error
	if devscope.Allowed(org) {
		err = tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM signed_agent_builds WHERE arch = $1 AND sha256 = $2)`, *arch, sha).Scan(&ok)
	} else {
		err = tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM signed_agent_builds WHERE arch = $1 AND sha256 = $2 AND release_sha256 = ANY ($3))`, *arch, sha, release).Scan(&ok)
	}
	return err == nil && ok
}

// readStep reads the result of a step whose job was asked for.
func (s *Service) readStep(ctx context.Context, tx pgx.Tx, device uuid.UUID, steps []Step, step int) error {
	cur := steps[step]
	done, ok, msg, diagnostics, err := s.patch.CompanionResult(ctx, cur.JobID)
	if err != nil {
		s.log.Warn("recovery: the patching engine could not be asked how a step went", "error", err, "device_id", device)
		done = false
	}
	if !done {
		if cur.SentAt != nil && s.now().Sub(*cur.SentAt) >= StepValid {
			s.patch.CancelCompanion(ctx, cur.JobID)
			return s.settleStep(ctx, tx, carrierPatching, device, agentproto.RepairReport{ID: cur.ID,
				Error: "The EasyPatch agent did not carry the step out within 15 minutes."}, "", "")
		}
		return nil
	}
	return s.settleStep(ctx, tx, carrierPatching, device, agentproto.RepairReport{ID: cur.ID, OK: ok, Error: msg}, msg, diagnostics)
}

// maxRunning is the longest a repair may run: automatic repairs wait longer
// between their steps.
func maxRunning(trigger string) time.Duration {
	if trigger == TriggerAutomatic {
		return 2 * MaxRunning
	}
	return MaxRunning
}

// targetFacts is what says whether a target is back.
type targetFacts struct {
	// online and changedAt are MeshCentral's view of MeshAgent: connected,
	// and since when; patchSeen is the EasyPatch agent's last check-in.
	online    bool
	changedAt *time.Time
	patchSeen *time.Time
	// agentSeen is the EasyRMM agent's last heartbeat.
	agentSeen *time.Time
}

// back reports whether the target is back after a step done at doneAt,
// where waitOver says its wait is over.
func (f targetFacts) back(target string, now time.Time, doneAt *time.Time, waitOver bool) bool {
	if target == agentproto.TargetEasyRMMAgent {
		// Checked in since the step, or, when the wait is over, recently.
		if f.agentSeen == nil {
			return false
		}
		return (doneAt != nil && !f.agentSeen.Before(*doneAt)) || (waitOver && now.Sub(*f.agentSeen) < AgentFresh)
	}
	if target == agentproto.TargetEasyPatchAgent {
		// Checked in since the step, or, when the wait is over, recently.
		if f.patchSeen == nil {
			return false
		}
		return (doneAt != nil && !f.patchSeen.Before(*doneAt)) || (waitOver && now.Sub(*f.patchSeen) < SilentAfter)
	}
	return f.online && ((f.changedAt != nil && doneAt != nil && !f.changedAt.Before(*doneAt)) || waitOver)
}

func (s *Service) advanceOne(ctx context.Context, tx pgx.Tx, now time.Time, judge bool, id uuid.UUID, target string, list []Step, step int, nextAt *time.Time, f targetFacts) error {
	cur := list[step]
	due := nextAt != nil && !now.Before(*nextAt)
	switch cur.State {
	case StepPending, StepSent:
		if due {
			// The carrying agent never took the step: it is not checking in.
			carrier := "EasyRMM agent"
			if target == agentproto.TargetEasyRMMAgent {
				carrier = "EasyPatch agent"
			}
			cur.State, cur.Error = StepFailed, "The "+carrier+" did not take the instruction within 15 minutes."
			list[step] = cur
			b, err := json.Marshal(list)
			if err != nil {
				return err
			}
			return s.end(ctx, tx, id, Failed, b, cur.Error, now)
		}
	case StepDone:
		if !judge {
			return nil // MeshCentral or the patching engine cannot be asked
		}
		if f.back(target, now, cur.DoneAt, due) {
			return s.end(ctx, tx, id, Succeeded, nil, "", now)
		}
		if due {
			why := "MeshAgent did not connect to MeshCentral after the last step."
			switch target {
			case agentproto.TargetEasyPatchAgent:
				why = "The EasyPatch agent did not check in with the patching engine after the last step."
			case agentproto.TargetEasyRMMAgent:
				why = "The EasyRMM agent did not check in after the last step."
			}
			return s.nextStep(ctx, tx, id, list, step, now, why)
		}
	}
	return nil
}

// keepDiagnostics redacts what a step returned once more, as the server
// does before it stores a log (the agent redacted it already), and keeps its
// last MaxDiagnostics bytes, from the start of a line.
func keepDiagnostics(s string) string {
	s = logredact.Text(strings.ToValidUTF8(s, ""))
	if len(s) <= MaxDiagnostics {
		return s
	}
	s = s[len(s)-MaxDiagnostics:]
	if i := strings.IndexByte(s, '\n'); i >= 0 && i < len(s)-1 {
		s = s[i+1:]
	}
	return strings.ToValidUTF8(s, "")
}

func truncate(s string, n int) string {
	if r := []rune(s); len(r) > n {
		return string(r[:n])
	}
	return s
}
