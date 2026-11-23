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
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/server/internal/access"
	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/devices"
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
	wake   chan struct{}
}

// New builds the service. remote says whether this server runs remote
// access, the only thing a repair is for in this slice.
func New(db *database.DB, auditLog *audit.Logger, remote bool, log *slog.Logger) *Service {
	return &Service{db: db, audit: auditLog, remote: remote, log: log, now: time.Now, wake: make(chan struct{}, 1)}
}

// SetKey sets the job key repair instructions are signed with. Without it
// no repair is asked for.
func (s *Service) SetKey(k ed25519.PrivateKey) { s.key = k }

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
	if target == agentproto.TargetMeshAgent {
		return agentproto.TargetEasyRMMAgent
	}
	return ""
}

// repairSteps are the steps of a repair, tried in order.
var repairSteps = []string{agentproto.StepRestart, agentproto.StepRepair}

// Request starts a repair someone asked for in the console: "Reconnect
// remote access" is a repair of MeshAgent through the EasyRMM agent. It
// needs device.edit on the device.
func (s *Service) Request(ctx context.Context, c access.Caller, deviceID uuid.UUID, target string) (*Repair, error) {
	carrier := carriedBy(target)
	if carrier == "" {
		return nil, apperr.Invalid("target", "Choose meshagent.")
	}
	d, err := devices.Lookup(ctx, s.db, c, deviceID)
	if err != nil {
		return nil, err
	}
	if err := c.Require(rbac.PermDeviceEdit, rbac.Site(d.OrganizationID, d.SiteID)); err != nil {
		return nil, err
	}
	switch {
	case !s.remote:
		return nil, apperr.Conflict("no_remote_access", "This server runs without remote access.")
	case d.Agent == nil:
		return nil, apperr.Conflict("no_agent", "The device has no EasyRMM agent to repair remote access with.")
	case s.key == nil:
		return nil, apperr.Conflict("no_job_key", "The server cannot sign instructions to agents.")
	case !d.Agent.Online:
		return nil, apperr.Conflict("device_offline", "The device is not checking in, so nothing can be repaired from here.")
	}
	var out *Repair
	err = s.db.InTx(ctx, c.Scope, func(tx pgx.Tx) error {
		var leaving bool
		if err := tx.QueryRow(ctx, `SELECT `+devices.LeavingSQL+` FROM devices d WHERE d.id = $1`, d.ID).Scan(&leaving); err != nil {
			return err
		}
		if leaving {
			return apperr.Conflict("device_leaving", "The device is being removed; nothing is repaired on it.")
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
	if database.IsUniqueViolation(err) {
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
	if _, err := tx.Exec(ctx, `INSERT INTO agent_repairs (id, device_id, target, carried_by, trigger, requested_by, state, steps, step, wait_seconds, next_at, started_at)
		VALUES ($1, $2, $3, $4, $5, $6, 'running', $7, 0, $8, $9, $10)`,
		id, deviceID, target, carriedBy(target), trigger, by, b, int(ManualWait.Seconds()), now.Add(StepValid), now); err != nil {
		return nil, err
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
	var out *agentproto.SignedRepair
	err := s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		out = nil
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
		sr, err := agentproto.SignRepair(s.key, agentproto.RepairPayload{
			V: agentproto.RepairPayloadVersion, ID: list[step].ID, DeviceID: deviceID.String(), Target: target, Step: list[step].Step,
			IssuedAt: now, ExpiresAt: now.Add(StepValid),
		})
		if err != nil {
			return err
		}
		out = &sr
		return nil
	})
	if err != nil {
		s.log.Error("recovery: settling a heartbeat failed", "error", err, "device_id", deviceID)
		return nil
	}
	return out
}

// settle records the outcome of the step an agent reports. A report for a
// step that is not the one in hand (repeated until an hour after it ended,
// or for a repair that is over) changes nothing.
func (s *Service) settle(ctx context.Context, tx pgx.Tx, deviceID uuid.UUID, rep agentproto.RepairReport) error {
	var (
		id    uuid.UUID
		steps []byte
		step  int
		wait  int
	)
	err := tx.QueryRow(ctx, `SELECT id, steps, step, wait_seconds FROM agent_repairs
		WHERE device_id = $1 AND state = 'running' AND carried_by = 'easyrmm-agent' FOR UPDATE`, deviceID).Scan(&id, &steps, &step, &wait)
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
	if rep.OK {
		list[step].State = StepDone
		b, err := json.Marshal(list)
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `UPDATE agent_repairs SET steps = $2, next_at = $3 WHERE id = $1`, id, b, now.Add(time.Duration(wait)*time.Second))
		return err
	}
	list[step].State, list[step].Error = StepFailed, truncate(rep.Error, agentproto.MaxRepairError)
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

// end finishes a repair and audits how it ended.
func (s *Service) end(ctx context.Context, tx pgx.Tx, id uuid.UUID, state string, steps []byte, why string, now time.Time) error {
	var (
		dev    uuid.UUID
		org    uuid.UUID
		site   uuid.UUID
		name   string
		target string
	)
	err := tx.QueryRow(ctx, `UPDATE agent_repairs r SET state = $2, steps = coalesce($3, steps), error = $4, ended_at = $5, next_at = NULL
		FROM devices d WHERE r.id = $1 AND d.id = r.device_id
		RETURNING d.id, d.organization_id, d.site_id, d.name, r.target`, id, state, steps, truncate(why, 1000), now).Scan(&dev, &org, &site, &name, &target)
	if err != nil {
		return err
	}
	outcome := audit.Success
	if state != Succeeded {
		outcome = audit.Failure
	}
	return s.audit.Write(ctx, tx, audit.Event{
		Actor: audit.SystemActor("recovery"), Action: "device.repair_end", Outcome: outcome,
		OrganizationID: org, SiteID: site, DeviceID: dev, TargetType: "device", TargetID: dev.String(),
		Details: map[string]any{"device": name, "target": target, "repair": id.String(), "state": state, "error": why},
	})
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
		_, err := tx.Exec(ctx, `DELETE FROM agent_repairs WHERE state <> 'running' AND ended_at < $1`, s.now().Add(-Keep))
		return err
	})
}

// Advance settles what the running repairs wait for: a target that came
// back ends its repair; a step whose wait is over gives way to the next, or
// to the end of the repair; a step the carrying agent never took ends it.
// A device that is leaving ends its repair. Nothing is judged while
// EasyRMM cannot see MeshCentral.
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
		rows, err := tx.Query(ctx, `SELECT r.id, r.target, r.steps, r.step, r.next_at, r.started_at, d.remote_online, d.remote_changed_at,
				`+devices.LeavingSQL+`
			FROM agent_repairs r JOIN devices d ON d.id = r.device_id
			WHERE r.state = 'running' ORDER BY r.started_at FOR UPDATE OF r`)
		if err != nil {
			return err
		}
		type row struct {
			id          uuid.UUID
			target      string
			steps       []byte
			step        int
			nextAt      *time.Time
			startedAt   time.Time
			online      bool
			changedAt   *time.Time
			leaving     bool
			list        []Step
			stepsParsed error
		}
		var list []row
		for rows.Next() {
			var r row
			if err := rows.Scan(&r.id, &r.target, &r.steps, &r.step, &r.nextAt, &r.startedAt, &r.online, &r.changedAt, &r.leaving); err != nil {
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
				if err := s.end(ctx, tx, r.id, Failed, nil, "The device is being removed.", now); err != nil {
					return err
				}
			case now.Sub(r.startedAt) >= MaxRunning:
				if err := s.end(ctx, tx, r.id, Failed, nil, "The repair took longer than an hour.", now); err != nil {
					return err
				}
			default:
				if err := s.advanceOne(ctx, tx, now, connected, r.id, r.list, r.step, r.nextAt, r.online, r.changedAt); err != nil {
					return err
				}
			}
		}
		return nil
	})
}

func (s *Service) advanceOne(ctx context.Context, tx pgx.Tx, now time.Time, connected bool, id uuid.UUID, list []Step, step int, nextAt *time.Time, online bool, changedAt *time.Time) error {
	cur := list[step]
	due := nextAt != nil && !now.Before(*nextAt)
	switch cur.State {
	case StepPending, StepSent:
		if due {
			// The carrying agent never took the step: it is not checking in.
			cur.State, cur.Error = StepFailed, "The EasyRMM agent did not take the instruction within 15 minutes."
			list[step] = cur
			b, err := json.Marshal(list)
			if err != nil {
				return err
			}
			return s.end(ctx, tx, id, Failed, b, cur.Error, now)
		}
	case StepDone:
		if !connected {
			return nil // MeshCentral cannot be asked
		}
		// Back: connected after the step, or still connected when its wait is
		// over.
		if online && ((changedAt != nil && cur.DoneAt != nil && !changedAt.Before(*cur.DoneAt)) || due) {
			return s.end(ctx, tx, id, Succeeded, nil, "", now)
		}
		if due {
			return s.nextStep(ctx, tx, id, list, step, now, "MeshAgent did not connect to MeshCentral after the last step.")
		}
	}
	return nil
}

func truncate(s string, n int) string {
	if r := []rune(s); len(r) > n {
		return string(r[:n])
	}
	return s
}
