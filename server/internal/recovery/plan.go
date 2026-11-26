package recovery

import (
	"context"
	"errors"
	"strings"
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

// One Repair button (ADR-0069, "Amended 2026-11-26: one Repair button").
// Decide is the decision table: from what is down and what runs it names the
// repairs to start. The console's button and automatic repairs both read it,
// and a repair it names is an ordinary repair (Request's checks, the signed
// instruction, the repair records); it adds no way of repairing.

// Refusal codes of a plan.
const (
	RefuseNothingDown  = "nothing_to_repair"
	RefuseNoRunning    = "no_running_agent"
	RefuseRunning      = "repair_running"
	RefuseLeaving      = "device_leaving"
	RefuseNoAgent      = "no_agent"
	RefuseNoJobKey     = "no_job_key"
	RefuseNoPatching   = "no_patching"
	RefuseNothingToTry = "nothing_to_try"
)

// Facts are what Decide reads about a device.
type Facts struct {
	// Enrolled: the device has an EasyRMM agent.
	Enrolled bool
	// RMMUp: the EasyRMM agent checked in within AgentFresh.
	RMMUp bool
	// MeshExpected: this server runs remote access and the device is meant
	// to have MeshAgent; MeshUp: MeshCentral sees it connected.
	MeshExpected, MeshUp bool
	// PatchExpected: the device's organization is patched and its EasyPatch
	// agent is linked; PatchUp: the engine heard from it within SilentAfter.
	PatchExpected, PatchUp bool
	// Leaving: the device is being removed.
	Leaving bool
	// HasKey: the server can sign instructions; HasPatching: it runs patching.
	HasKey, HasPatching bool
	// Running: targets with a repair that runs.
	Running map[string]bool
}

// Action is one repair of a plan.
type Action struct {
	Target    string `json:"target"`
	CarriedBy string `json:"carriedBy"`
}

// Plan is what pressing Repair does for a device now.
type Plan struct {
	// Down are the agents that are not working, in the order EasyRMM agent,
	// MeshAgent, EasyPatch agent.
	Down []string `json:"down"`
	// Repairs are started now, together.
	Repairs []Action `json:"repairs"`
	// Later are down too but cannot be repaired until the EasyRMM agent is
	// back: pressing Repair again, or the automatic repair, takes them then.
	Later []string `json:"later"`
	// Running are targets whose repair runs already; nothing is started for them.
	Running []string `json:"running"`
	// Summary is the "what will happen" line.
	Summary string `json:"summary"`
	// Refusal is set when nothing can be started, with Summary saying why.
	Refusal string `json:"refusal,omitempty"`
}

var names = map[string]string{
	agentproto.TargetEasyRMMAgent:   "the EasyRMM agent",
	agentproto.TargetMeshAgent:      "MeshAgent",
	agentproto.TargetEasyPatchAgent: "the EasyPatch agent",
}

func list(targets []string) string {
	var n []string
	for _, t := range targets {
		n = append(n, names[t])
	}
	switch len(n) {
	case 0:
		return ""
	case 1:
		return n[0]
	}
	return strings.Join(n[:len(n)-1], ", ") + " and " + n[len(n)-1]
}

func upper(s string) string { return strings.ToUpper(s[:1]) + s[1:] }

// Decide is the decision table of ADR-0069's one Repair button.
func Decide(f Facts) Plan {
	var p Plan
	refuse := func(code, why string) Plan {
		p.Refusal, p.Summary = code, why
		return p
	}
	if f.Enrolled && !f.RMMUp {
		p.Down = append(p.Down, agentproto.TargetEasyRMMAgent)
	}
	if f.Enrolled && f.MeshExpected && !f.MeshUp {
		p.Down = append(p.Down, agentproto.TargetMeshAgent)
	}
	if f.Enrolled && f.PatchExpected && !f.PatchUp {
		p.Down = append(p.Down, agentproto.TargetEasyPatchAgent)
	}
	switch {
	case f.Leaving:
		return refuse(RefuseLeaving, "The device is being removed; nothing is repaired on it.")
	case !f.Enrolled:
		return refuse(RefuseNoAgent, "The device has no EasyRMM agent, so there is nothing to repair it with.")
	case len(p.Down) == 0:
		return refuse(RefuseNothingDown, "Everything that should run on this device is running.")
	}
	var todo []Action
	if f.RMMUp {
		// The EasyRMM agent runs: it repairs MeshAgent and the EasyPatch agent.
		if !f.HasKey {
			return refuse(RefuseNoJobKey, "The server cannot sign instructions to agents.")
		}
		for _, t := range p.Down {
			if t == agentproto.TargetEasyPatchAgent && !f.HasPatching {
				continue
			}
			todo = append(todo, Action{Target: t, CarriedBy: agentproto.TargetEasyRMMAgent})
		}
	} else if f.PatchExpected && f.PatchUp && f.HasPatching {
		// The EasyRMM agent is down and the EasyPatch agent runs: it repairs
		// the EasyRMM agent, which then repairs the rest.
		todo = append(todo, Action{Target: agentproto.TargetEasyRMMAgent, CarriedBy: agentproto.TargetEasyPatchAgent})
		for _, t := range p.Down {
			if t != agentproto.TargetEasyRMMAgent {
				p.Later = append(p.Later, t)
			}
		}
	} else {
		return refuse(RefuseNoRunning, "The EasyRMM agent is not checking in and the EasyPatch agent is not running, so no agent on the device can repair anything. MeshAgent cannot repair the others. Reinstall the EasyRMM agent on the device.")
	}
	for _, a := range todo {
		if f.Running[a.Target] {
			p.Running = append(p.Running, a.Target)
			continue
		}
		p.Repairs = append(p.Repairs, a)
	}
	if len(p.Repairs) == 0 {
		if len(p.Running) > 0 {
			return refuse(RefuseRunning, upper(list(p.Running))+" is already being repaired.")
		}
		return refuse(RefuseNothingToTry, "Nothing that is down can be repaired from here.")
	}
	p.Summary = summary(p, f)
	return p
}

func summary(p Plan, f Facts) string {
	var s []string
	for _, a := range p.Repairs {
		switch {
		case a.CarriedBy == agentproto.TargetEasyPatchAgent:
			s = append(s, "The EasyPatch agent will restart the EasyRMM agent and, if that does not bring it back, put it back from its recovery copy")
		case a.Target == agentproto.TargetMeshAgent:
			s = append(s, "The EasyRMM agent will restart MeshAgent and, if that does not bring it back, put its program and settings back, keeping its identity")
		default:
			s = append(s, "The EasyRMM agent will restart the EasyPatch agent and, if that does not bring it back, reinstall its package of the same version, keeping its enrollment")
		}
	}
	out := strings.Join(s, ". ") + "."
	if len(p.Later) > 0 {
		out += " " + upper(list(p.Later)) + " is down too; once the EasyRMM agent is back, press Repair again for it."
	}
	if len(p.Running) > 0 {
		out += " " + upper(list(p.Running)) + " is being repaired already."
	}
	return out
}

// FactsFor reads what Decide needs about a device.
func (s *Service) FactsFor(ctx context.Context, c access.Caller, deviceID uuid.UUID) (*devices.Device, Facts, error) {
	d, err := devices.Lookup(ctx, s.db, c, deviceID)
	if err != nil {
		return nil, Facts{}, err
	}
	var f Facts
	// The caller may see the device (Lookup); the facts include rows no
	// caller's scope shows, such as the site's MeshCentral group.
	err = s.db.ReadTx(ctx, database.System, func(tx pgx.Tx) error { return s.loadFacts(ctx, tx, d.ID, &f) })
	return d, f, err
}

func (s *Service) loadFacts(ctx context.Context, tx pgx.Tx, id uuid.UUID, f *Facts) error {
	now := s.now()
	var seen *time.Time
	var meshSite, orgLinked, linked bool
	var onlineUntil *time.Time
	if err := tx.QueryRow(ctx, `SELECT d.agent_public_key IS NOT NULL, d.agent_online_until, d.remote_online, `+devices.LeavingSQL+`,
			EXISTS (SELECT 1 FROM mesh_sites ms WHERE ms.site_id = d.site_id),
			EXISTS (SELECT 1 FROM easypatch_organizations l WHERE l.organization_id = d.organization_id),
			EXISTS (SELECT 1 FROM easypatch_devices e WHERE e.device_id = d.id AND e.state = 'linked'),
			(SELECT e.agent_seen_at FROM easypatch_devices e WHERE e.device_id = d.id AND e.state = 'linked')
		FROM devices d WHERE d.id = $1`, id).Scan(&f.Enrolled, &onlineUntil, &f.MeshUp, &f.Leaving, &meshSite, &orgLinked, &linked, &seen); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return apperr.NotFound()
		}
		return err
	}
	f.RMMUp = onlineUntil != nil && onlineUntil.After(now)
	f.MeshExpected = s.remote && meshSite
	f.PatchExpected = orgLinked && linked
	f.PatchUp = seen != nil && now.Sub(*seen) < SilentAfter
	f.HasKey, f.HasPatching = s.key != nil, s.patch != nil
	f.Running = map[string]bool{}
	rows, err := tx.Query(ctx, `SELECT target FROM agent_repairs WHERE device_id = $1 AND state = 'running'`, id)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var t string
		if err := rows.Scan(&t); err != nil {
			return err
		}
		f.Running[t] = true
	}
	return rows.Err()
}

// Plan says what pressing Repair would do for a device now. It needs
// device.edit or patch.manage on the device.
func (s *Service) Plan(ctx context.Context, c access.Caller, deviceID uuid.UUID) (*Plan, error) {
	d, f, err := s.FactsFor(ctx, c, deviceID)
	if err != nil {
		return nil, err
	}
	r := rbac.Site(d.OrganizationID, d.SiteID)
	if !c.Can(rbac.PermDeviceEdit, r) && !c.Can(rbac.PermPatchManage, r) {
		return nil, c.Require(rbac.PermDeviceEdit, r)
	}
	p := Decide(f)
	return &p, nil
}

// Outcome is what Repair did.
type Outcome struct {
	ID      uuid.UUID `json:"id"`
	Plan    Plan      `json:"plan"`
	Repairs []*Repair `json:"repairs"`
}

// RepairDevice is the one Repair button: it decides the plan, starts its
// repairs through Request (the same checks, instructions and records as any
// repair), and audits the plan with the repairs it started. Each repair
// needs the permission it always needed: device.edit for those the EasyRMM
// agent carries, patch.manage for the EasyRMM agent through patching.
func (s *Service) RepairDevice(ctx context.Context, c access.Caller, deviceID uuid.UUID) (*Outcome, error) {
	d, f, err := s.FactsFor(ctx, c, deviceID)
	if err != nil {
		return nil, err
	}
	r := rbac.Site(d.OrganizationID, d.SiteID)
	p := Decide(f)
	if p.Refusal != "" {
		if !c.Can(rbac.PermDeviceEdit, r) && !c.Can(rbac.PermPatchManage, r) {
			return nil, c.Require(rbac.PermDeviceEdit, r)
		}
		return nil, apperr.Conflict(p.Refusal, p.Summary)
	}
	for _, a := range p.Repairs {
		perm := rbac.PermDeviceEdit
		if a.CarriedBy == carrierPatching {
			perm = rbac.PermPatchManage
		}
		if err := c.Require(perm, r); err != nil {
			return nil, err
		}
	}
	out := &Outcome{ID: uuid.New(), Plan: p}
	for _, a := range p.Repairs {
		rep, err := s.Request(ctx, c, d.ID, a.Target)
		if err != nil {
			if len(out.Repairs) == 0 {
				return nil, err
			}
			// A repair that started before the others failed stays; the
			// outcome lists what did start.
			s.log.Warn("one repair of a plan did not start", "device", d.ID, "target", a.Target, "err", err)
			continue
		}
		out.Repairs = append(out.Repairs, rep)
	}
	var started []string
	for _, rep := range out.Repairs {
		started = append(started, rep.ID.String())
	}
	err = s.db.InTx(ctx, c.Scope, func(tx pgx.Tx) error {
		return s.audit.Write(ctx, tx, audit.Event{
			Actor: c.Actor, Action: "device.repair_plan", Outcome: audit.Success,
			OrganizationID: d.OrganizationID, SiteID: d.SiteID, DeviceID: d.ID, TargetType: "device", TargetID: d.ID.String(),
			Details: map[string]any{"device": d.Name, "plan": out.ID.String(), "down": p.Down, "later": p.Later, "repairs": started},
		})
	})
	return out, err
}
