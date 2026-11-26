// Package modsnap keeps the snapshots of ADR-0073's Windows management
// modules: the typed result of a module's read action, per device, action
// and parameters, with its age. A tab reads the cached snapshot at once and a
// stale one starts a refresh; the server also refreshes, on a schedule, the
// reads that alerts need; and old snapshots are deleted. ADR-0074 to 0077
// read module state from here.
package modsnap

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/server/internal/access"
	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/devices"
	"github.com/paulmataruso/easyrmm/server/internal/jobs"
	"github.com/paulmataruso/easyrmm/server/internal/modules"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
	"github.com/paulmataruso/easyrmm/server/internal/winmod"
)

// Retention of snapshots (ADR-0073 section 5).
const (
	Keep          = 7 * 24 * time.Hour
	KeepSensitive = 15 * time.Minute
)

// AutoReadAge is how old a result may be before a tab that opens starts a read
// on its own, whatever the action's own freshness (a longer one is cut to
// this). The owner's rule: what a person looks at is at most about two
// minutes old.
const AutoReadAge = 2 * time.Minute

// SweepInterval is how often scheduled reads are started and old snapshots
// deleted.
const SweepInterval = time.Minute

// MaxPerSweep bounds the scheduled reads one sweep starts, so a large fleet
// is read over several minutes rather than all at once.
const MaxPerSweep = 200

// Runner starts a module action; *jobs.Service is the one implementation.
type Runner interface {
	RunWinmod(ctx context.Context, c access.Caller, in jobs.WinmodInput) (*jobs.WinmodRun, error)
}

// Gate is modules.Service.Allowed: the toggle and the development scope.
type Gate interface {
	Allowed(ctx context.Context, org, site uuid.UUID, m modules.Module) bool
}

// Service reads, refreshes and retires snapshots.
type Service struct {
	db      *database.DB
	catalog *winmod.Catalog
	modules *modules.Service
	gate    Gate
	runner  Runner
	log     *slog.Logger
	now     func() time.Time
}

// New returns a Service. The modules service answers the 404 rule; gate
// guards every read the server starts on its own.
func New(db *database.DB, catalog *winmod.Catalog, mods *modules.Service, gate Gate, runner Runner, log *slog.Logger) *Service {
	return &Service{db: db, catalog: catalog, modules: mods, gate: gate, runner: runner, log: log, now: time.Now}
}

// Snapshot is what a tab shows: the stored value with its age.
type Snapshot struct {
	Action string `json:"action"`
	// TakenAt is nil when the action has never been read here.
	TakenAt *time.Time `json:"takenAt"`
	// Stale says the snapshot is older than the action's freshness (or
	// missing).
	Stale bool            `json:"stale"`
	Data  json.RawMessage `json:"data"`
	// Refreshing says a read is on its way; Offline that none was started
	// because the computer is not checking in.
	Refreshing bool `json:"refreshing"`
	Offline    bool `json:"offline"`
	// RunID is the read on its way, started by this call or found already
	// running: the console follows it for the result.
	RunID *uuid.UUID `json:"runId,omitempty"`
}

// Get returns the cached snapshot of a snapshot action at once and starts a
// refresh when it is stale (ADR-0073 section 5). The module must be offered
// on the device (404 otherwise) and the caller must hold the action's
// permission, and for a sensitive action its sensitive permission. No job is
// started for a computer that is offline.
func (s *Service) Get(ctx context.Context, c access.Caller, deviceID uuid.UUID, action string, params json.RawMessage) (*Snapshot, error) {
	return s.GetWithin(ctx, c, deviceID, action, params, AutoReadAge)
}

// GetWithin is Get for a result that may be at most maxAge old (never more
// than AutoReadAge or the action's own freshness): a tab that shows a running
// operation asks for a short age.
func (s *Service) GetWithin(ctx context.Context, c access.Caller, deviceID uuid.UUID, action string, params json.RawMessage, maxAge time.Duration) (*Snapshot, error) {
	a, d, key, err := s.open(ctx, c, deviceID, action, params)
	if err != nil {
		return nil, err
	}
	out := &Snapshot{Action: a.Name, Stale: true}
	var taken time.Time
	var data []byte
	err = s.db.ReadTx(ctx, database.System, func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx, `SELECT taken_at, data FROM windows_module_snapshots
			WHERE device_id = $1 AND action = $2 AND params_hash = $3`, deviceID, a.Name, key).Scan(&taken, &data)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("modsnap: reading a snapshot: %w", err)
	}
	if data != nil {
		out.TakenAt, out.Data = &taken, data
		out.Stale = s.now().Sub(taken) > min(a.Freshness, maxAge, AutoReadAge)
	}
	// An action that keeps no snapshot (a sensitive page of leases) is
	// always read afresh; its result comes by the run.
	if out.Stale {
		out.Refreshing, out.Offline, out.RunID, err = s.refresh(ctx, c, d, a, params, key, true)
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}

// Refresh starts a read now, whatever the snapshot's age (the tab's Refresh
// button), unless one is already on its way.
func (s *Service) Refresh(ctx context.Context, c access.Caller, deviceID uuid.UUID, action string, params json.RawMessage) (*Snapshot, error) {
	a, d, key, err := s.open(ctx, c, deviceID, action, params)
	if err != nil {
		return nil, err
	}
	out := &Snapshot{Action: a.Name, Stale: true}
	out.Refreshing, out.Offline, out.RunID, err = s.refresh(ctx, c, d, a, params, key, false)
	return out, err
}

func (s *Service) open(ctx context.Context, c access.Caller, deviceID uuid.UUID, action string, params json.RawMessage) (winmod.Action, *devices.Device, string, error) {
	a, ok := s.catalog.Lookup(action)
	if !ok || !a.IsPlainRead() {
		return a, nil, "", apperr.NotFound()
	}
	d, err := s.modules.Offered(ctx, c, deviceID, a.Module)
	if err != nil {
		return a, nil, "", err
	}
	res := rbac.Site(d.OrganizationID, d.SiteID)
	// A computer outside the development scope, or whose module is off, is
	// never read on its own and is not found.
	if !s.gate.Allowed(ctx, d.OrganizationID, d.SiteID, a.Module) {
		return a, nil, "", apperr.NotFound()
	}
	if !c.Can(a.Permission, res) || (a.Sensitive && !c.Can(a.SensitivePermission, res)) {
		return a, nil, "", apperr.NotFound()
	}
	chk, err := a.Validate(params)
	if err != nil {
		return a, nil, "", err
	}
	key, err := winmod.ParamsKey(chk.Params)
	return a, d, key, err
}

// refresh starts the read unless the computer is offline or a read of the
// same action is queued or running (one in flight per device and action).
// automatic marks the job, and its audit rows, as started by the console on
// its own rather than by a person's request.
func (s *Service) refresh(ctx context.Context, c access.Caller, d *devices.Device, a winmod.Action, params json.RawMessage, key string, automatic bool) (refreshing, offline bool, run *uuid.UUID, err error) {
	var online bool
	var inflight uuid.UUID
	err = s.db.ReadTx(ctx, database.System, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `SELECT coalesce(agent_online_until > $2::timestamptz, false)
			FROM devices WHERE id = $1`, d.ID, s.now()).Scan(&online); err != nil {
			return err
		}
		err := tx.QueryRow(ctx, `SELECT r.id FROM job_runs r JOIN jobs j ON j.id = r.job_id
			WHERE r.device_id = $1 AND j.kind = 'winmod' AND j.winmod->>'action' = $2 AND r.status IN ('queued', 'sent', 'running')
			  AND coalesce(j.params, '{}'::jsonb) = $3::jsonb
			ORDER BY r.created_at DESC LIMIT 1`, d.ID, a.Name, asJSON(params)).Scan(&inflight)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		return err
	})
	if err != nil {
		return false, false, nil, fmt.Errorf("modsnap: checking for a read on its way: %w", err)
	}
	switch {
	case inflight != uuid.Nil:
		return true, !online, &inflight, nil
	case !online:
		return false, true, nil, nil
	}
	r, err := s.runner.RunWinmod(ctx, c, jobs.WinmodInput{DeviceID: d.ID, Action: a.Name, Params: params, Automatic: automatic})
	if err != nil {
		return false, false, nil, err
	}
	return true, false, &r.RunID, nil
}

// asJSON is the parameters as the job keeps them: an empty object when none.
func asJSON(p json.RawMessage) string {
	if len(bytes.TrimSpace(p)) == 0 || string(bytes.TrimSpace(p)) == "null" {
		return "{}"
	}
	return string(p)
}

// inflightSQL is a condition that is true when a run of the action is queued,
// sent or running on the device; the arguments are SQL expressions.
func inflightSQL(device, action string) string {
	return `EXISTS (SELECT 1 FROM job_runs r JOIN jobs j ON j.id = r.job_id
		WHERE r.device_id = ` + device + ` AND j.kind = 'winmod' AND j.winmod->>'action' = ` + action + `
		AND r.status IN ('queued', 'sent', 'running'))`
}

// OnRoleRemoved is the framework's hook for a role that disappeared: the
// module's snapshots of the device are deleted (ADR-0073 section 1). Register
// it with modules.Service.OnRoleRemoved.
func OnRoleRemoved(ctx context.Context, tx pgx.Tx, deviceID, _ uuid.UUID, m modules.Module) error {
	if _, err := tx.Exec(ctx, `DELETE FROM windows_module_snapshots WHERE device_id = $1 AND module = $2`, deviceID, string(m)); err != nil {
		return fmt.Errorf("modsnap: clearing %s snapshots: %w", m, err)
	}
	return nil
}

// Sweep starts the scheduled reads: for every action with a schedule, each
// computer that is online, has the module's role and no snapshot newer than
// the schedule, where the module is on and the organization is allowed
// (modules.Service.Allowed). It returns how many reads it started.
func (s *Service) Sweep(ctx context.Context) (int, error) {
	started := 0
	sys := access.System("modsnap")
	for _, a := range s.catalog.Actions() {
		if a.Schedule <= 0 {
			continue
		}
		def, ok := modules.Lookup(a.Module)
		if !ok {
			continue
		}
		type target struct{ id, org, site uuid.UUID }
		var due []target
		err := s.db.ReadTx(ctx, database.System, func(tx pgx.Tx) error {
			rows, err := tx.Query(ctx, `SELECT d.id, d.organization_id, d.site_id FROM devices d
				WHERE d.platform = 'windows' AND d.agent_public_key IS NOT NULL
				  AND d.agent_online_until > $1::timestamptz
				  AND jsonb_path_exists(coalesce(d.roles, '[]'::jsonb),
					'$[*] ? (@.name == $role && (@.state == "present" || @.state == "passive"))', jsonb_build_object('role', $2::text))
				  AND NOT EXISTS (SELECT 1 FROM windows_module_snapshots s WHERE s.device_id = d.id AND s.action = $3 AND s.params_hash = ''
					AND s.taken_at > $1::timestamptz - make_interval(secs => $4))
				  AND NOT `+inflightSQL("d.id", "$3::text")+`
				ORDER BY d.id LIMIT $5`, s.now(), def.Role, a.Name, a.Schedule.Seconds(), MaxPerSweep)
			if err != nil {
				return err
			}
			defer rows.Close()
			for rows.Next() {
				var t target
				if err := rows.Scan(&t.id, &t.org, &t.site); err != nil {
					return err
				}
				due = append(due, t)
			}
			return rows.Err()
		})
		if err != nil {
			return started, fmt.Errorf("modsnap: finding the reads that are due: %w", err)
		}
		for _, t := range due {
			if !s.gate.Allowed(ctx, t.org, t.site, a.Module) {
				continue
			}
			if _, err := s.runner.RunWinmod(ctx, sys, jobs.WinmodInput{DeviceID: t.id, Action: a.Name, Automatic: true}); err != nil {
				s.log.Warn("modsnap: a scheduled read was not started", "action", a.Name, "device", t.id, "error", err)
				continue
			}
			started++
		}
	}
	return started, nil
}

// Purge deletes snapshots past their retention: seven days, and fifteen
// minutes for a sensitive one. A module that is off stops being read, so its
// rows age out here.
func (s *Service) Purge(ctx context.Context) (int64, error) {
	var n int64
	err := s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `DELETE FROM windows_module_snapshots
			WHERE taken_at < $1 OR (sensitive AND taken_at < $2)`, s.now().Add(-Keep), s.now().Add(-KeepSensitive))
		n = tag.RowsAffected()
		return err
	})
	return n, err
}

// Run sweeps and purges every minute until ctx ends.
func (s *Service) Run(ctx context.Context) {
	tick := time.NewTicker(SweepInterval)
	defer tick.Stop()
	for {
		if _, err := s.Sweep(ctx); err != nil && ctx.Err() == nil {
			s.log.Error("modsnap: scheduled module reads failed", "error", err)
		}
		if _, err := s.Purge(ctx); err != nil && ctx.Err() == nil {
			s.log.Error("modsnap: snapshot retention failed", "error", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}
