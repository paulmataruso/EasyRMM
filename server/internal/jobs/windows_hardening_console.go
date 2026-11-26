package jobs

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/server/internal/access"
	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/devices"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
)

// What the hardening console of Windows computers reads and does beyond a
// device's findings (ADR-0054, W3): the catalog of settings with their
// tiers, a device's guards, keeping an armed guard's change, and the fleet.

// WindowsCatalogSetting is one setting of the catalog, as the console lists
// it under its module.
type WindowsCatalogSetting struct {
	ID   string `json:"id"`
	What string `json:"what"`
	// Tier is 0 (reported only) to 3 (can cut access).
	Tier int `json:"tier"`
	// Cite is how the setting stands against its rules: meets, differs or
	// not_set.
	Cite string `json:"cite"`
	// Option is the switch that lets the setting be changed where the
	// default leaves it alone, empty without one.
	Option string `json:"option,omitempty"`
}

// WindowsCatalogModule is a module of the catalog.
type WindowsCatalogModule struct {
	ID       string                  `json:"id"`
	Tier     int                     `json:"tier"`
	Settings []WindowsCatalogSetting `json:"settings"`
	// Switches are the module's options without a value, by the name the
	// request's options use.
	Switches []string `json:"switches"`
}

// WindowsCatalog is every module in the order the script runs them, with
// its settings. It is static, the same for everyone.
func WindowsCatalog() []WindowsCatalogModule {
	out := make([]WindowsCatalogModule, 0, len(WindowsHardeningModules))
	at := map[string]int{}
	for _, m := range WindowsHardeningModules {
		at[m] = len(out)
		out = append(out, WindowsCatalogModule{ID: m, Tier: windowsModuleTiers[m], Settings: []WindowsCatalogSetting{}, Switches: []string{}})
	}
	for _, sw := range windowsSwitches {
		if i, ok := at[sw.module]; ok {
			out[i].Switches = append(out[i].Switches, sw.field)
		}
	}
	for _, s := range windowsSettings {
		i, ok := at[s.Module]
		if !ok {
			continue
		}
		cite := s.Cite
		if cite == "" {
			cite = "meets"
		}
		out[i].Settings = append(out[i].Settings, WindowsCatalogSetting{ID: s.ID, What: s.What, Tier: windowsSettingTier(s), Cite: cite, Option: s.Option})
	}
	return out
}

// HardeningGuard is one guard of a device: a change waiting for the agent's
// confirmation, or how that ended.
type HardeningGuard struct {
	ApplyJobID uuid.UUID `json:"applyJobId"`
	// Settings are the setting IDs the apply changed.
	Settings   []string  `json:"settings"`
	ArmedAt    time.Time `json:"armedAt"`
	RollbackAt time.Time `json:"rollbackAt"`
	// State is armed, confirmed or timed_out.
	State     string     `json:"state"`
	DecidedAt *time.Time `json:"decidedAt"`
	// KeepRequestedAt is when someone pressed Keep and the server queued a
	// new confirmation, which waits for the agent.
	KeepRequestedAt *time.Time `json:"keepRequestedAt"`
}

// DeviceGuards are a device's most recent guards, newest first. It needs
// device.view.
func (s *Service) DeviceGuards(ctx context.Context, c access.Caller, deviceID uuid.UUID) ([]HardeningGuard, error) {
	d, err := devices.Lookup(ctx, s.db, c, deviceID)
	if err != nil {
		return nil, err
	}
	if !c.Can(rbac.PermDeviceView, rbac.Site(d.OrganizationID, d.SiteID)) {
		return nil, apperr.Forbidden()
	}
	out := []HardeningGuard{}
	err = s.db.ReadTx(ctx, c.Scope, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT apply_job_id, settings, armed_at, rollback_at, state, decided_at, keep_requested_at
			FROM hardening_guards WHERE device_id = $1 ORDER BY armed_at DESC LIMIT 20`, deviceID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var g HardeningGuard
			if err := rows.Scan(&g.ApplyJobID, &g.Settings, &g.ArmedAt, &g.RollbackAt, &g.State, &g.DecidedAt, &g.KeepRequestedAt); err != nil {
				return err
			}
			out = append(out, g)
		}
		return rows.Err()
	})
	return out, err
}

// KeepGuard asks for the armed guard's change to stand now: it queues a new
// confirm job, which ends the computer's timer where the agent is reachable
// before the timer fires. It needs device.harden, as the apply did.
func (s *Service) KeepGuard(ctx context.Context, c access.Caller, deviceID uuid.UUID) (*HardeningGuard, error) {
	d, err := devices.Lookup(ctx, s.db, c, deviceID)
	if err != nil {
		return nil, err
	}
	if !c.Can(rbac.PermDeviceHarden, rbac.Site(d.OrganizationID, d.SiteID)) {
		return nil, apperr.Forbidden()
	}
	var g HardeningGuard
	// The guard table is written by the system only; the caller's right to
	// do this was checked above.
	err = s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx, `SELECT apply_job_id, settings, armed_at, rollback_at, state, decided_at, keep_requested_at
			FROM hardening_guards WHERE device_id = $1 AND state = 'armed' ORDER BY armed_at DESC LIMIT 1 FOR UPDATE`, deviceID).
			Scan(&g.ApplyJobID, &g.Settings, &g.ArmedAt, &g.RollbackAt, &g.State, &g.DecidedAt, &g.KeepRequestedAt)
		if errors.Is(err, pgx.ErrNoRows) {
			return apperr.Conflict("no_armed_guard", "No change on this computer is waiting for confirmation.")
		}
		if err != nil {
			return err
		}
		now := s.now()
		// The job must be able to run, and end the timer, before it fires.
		expires := g.RollbackAt.Add(-time.Minute)
		if !expires.After(now) {
			return apperr.Conflict("guard_too_late", "The computer's timer is about to undo the change; it can no longer be kept from here.")
		}
		jobID, runID, _, err := s.insertConfirmJob(ctx, tx, deviceID, d.OrganizationID, d.SiteID, now, expires)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE hardening_guards SET confirm_job_id = $2, keep_requested_at = $3 WHERE apply_job_id = $1`,
			g.ApplyJobID, jobID, now); err != nil {
			return err
		}
		g.KeepRequestedAt = &now
		return s.audit.Write(ctx, tx, audit.Event{
			Actor: c.Actor, Action: "device.hardening.guard_keep", Outcome: audit.Success,
			OrganizationID: d.OrganizationID, SiteID: d.SiteID, DeviceID: deviceID, TargetType: "job_run", TargetID: runID.String(),
			Details: map[string]any{"jobId": jobID.String(), "appliedBy": g.ApplyJobID.String(), "settings": g.Settings},
		})
	})
	if err != nil {
		return nil, err
	}
	return &g, nil
}

// FleetScope narrows the fleet to an organization, a site or a group; the
// most specific one given counts.
type FleetScope struct {
	OrganizationID, SiteID, GroupID uuid.UUID
}

// FleetModule counts the Windows computers by the state of one module.
type FleetModule struct {
	Module string         `json:"module"`
	States map[string]int `json:"states"`
}

// FleetDevice is one Windows computer of the fleet.
type FleetDevice struct {
	ID        uuid.UUID      `json:"id"`
	Name      string         `json:"name"`
	SiteName  string         `json:"siteName"`
	GroupName string         `json:"groupName"`
	CheckedAt *time.Time     `json:"checkedAt"`
	States    map[string]int `json:"states"`
	// Guard is the state of the device's latest guard, empty without one.
	Guard string `json:"guard"`
}

// Fleet is the Windows hardening of the computers in a scope.
type Fleet struct {
	Devices []FleetDevice `json:"devices"`
	Modules []FleetModule `json:"modules"`
	// Truncated: more computers match than are listed.
	Truncated bool `json:"truncated"`
}

// maxFleet bounds the computers a fleet lists.
const maxFleet = 500

// HardeningFleet sums up the Windows computers the caller can see in a
// scope, with an EasyRMM agent. It needs device.view at the scope.
func (s *Service) HardeningFleet(ctx context.Context, c access.Caller, sc FleetScope) (*Fleet, error) {
	// The database's row security limits the rows to what the caller sees;
	// a named organization is also checked.
	if sc.OrganizationID != uuid.Nil && !c.Can(rbac.PermDeviceView, rbac.Org(sc.OrganizationID)) {
		return nil, apperr.Forbidden()
	}
	out := &Fleet{Devices: []FleetDevice{}, Modules: []FleetModule{}}
	err := s.db.ReadTx(ctx, c.Scope, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT d.id, d.name, s.name, coalesce(g.name, ''), hc.checked_at, coalesce(hs.states, '{}'::jsonb), coalesce(gd.state, '')
			FROM devices d
			JOIN sites s ON s.id = d.site_id
			LEFT JOIN device_groups g ON g.id = d.device_group_id
			LEFT JOIN device_hardening_checks hc ON hc.device_id = d.id
			LEFT JOIN LATERAL (SELECT jsonb_object_agg(x.state, x.n) AS states
				FROM (SELECT h.state, count(*) AS n FROM device_hardening h WHERE h.device_id = d.id GROUP BY h.state) x) hs ON true
			LEFT JOIN LATERAL (SELECT state FROM hardening_guards WHERE device_id = d.id ORDER BY armed_at DESC LIMIT 1) gd ON true
			WHERE d.platform = 'windows' AND d.enrolled_at IS NOT NULL
			  AND ($1::uuid IS NULL OR d.organization_id = $1)
			  AND ($2::uuid IS NULL OR d.site_id = $2)
			  AND ($3::uuid IS NULL OR d.device_group_id = $3)
			ORDER BY lower(d.name), d.id LIMIT $4`,
			nullID(sc.OrganizationID), nullID(sc.SiteID), nullID(sc.GroupID), maxFleet+1)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var d FleetDevice
			if err := rows.Scan(&d.ID, &d.Name, &d.SiteName, &d.GroupName, &d.CheckedAt, &d.States, &d.Guard); err != nil {
				return err
			}
			out.Devices = append(out.Devices, d)
		}
		if err := rows.Err(); err != nil {
			return err
		}
		if len(out.Devices) > maxFleet {
			out.Devices, out.Truncated = out.Devices[:maxFleet], true
		}
		ids := make([]uuid.UUID, len(out.Devices))
		for i, d := range out.Devices {
			ids[i] = d.ID
		}
		mrows, err := tx.Query(ctx, `SELECT module, state, count(*) FROM device_hardening WHERE device_id = ANY($1)
			GROUP BY module, state`, ids)
		if err != nil {
			return err
		}
		defer mrows.Close()
		by := map[string]map[string]int{}
		for mrows.Next() {
			var m, st string
			var n int
			if err := mrows.Scan(&m, &st, &n); err != nil {
				return err
			}
			if by[m] == nil {
				by[m] = map[string]int{}
			}
			by[m][st] = n
		}
		for _, m := range WindowsHardeningModules {
			if st, ok := by[m]; ok {
				out.Modules = append(out.Modules, FleetModule{Module: m, States: st})
			}
		}
		return mrows.Err()
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func nullID(id uuid.UUID) any {
	if id == uuid.Nil {
		return nil
	}
	return id
}
