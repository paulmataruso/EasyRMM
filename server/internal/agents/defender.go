package agents

import (
	"context"
	"encoding/json"
	"net/netip"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/audit"
)

// DefenderScope says where the agent may manage Microsoft Defender
// exclusions and report the hashes of what is installed (ADR-0070).
//
// The development-scope guard is built apart: wire devscope.Allowed in
// where the Service is built (server/internal/app/app.go, after
// agents.New) with
//
//	d.Agents.SetDefenderScope(agents.ScopeFunc(devscope.Allowed))
//
// Until then every organization is allowed, which is what devscope.Allowed
// answers while no scope is set.
type DefenderScope interface {
	Allowed(org uuid.UUID) bool
}

// ScopeFunc makes a function a DefenderScope.
type ScopeFunc func(org uuid.UUID) bool

// Allowed calls f.
func (f ScopeFunc) Allowed(org uuid.UUID) bool { return f(org) }

// SetDefenderScope sets where the Defender work is allowed.
func (s *Service) SetDefenderScope(sc DefenderScope) { s.scope = sc }

// OnAgentVersion has f called with an agent version a device reports that
// it did not report before, so that the hash list can hold it (ADR-0070).
func (s *Service) OnAgentVersion(f func(version string)) { s.version = f }

func (s *Service) defenderAllowed(org uuid.UUID) bool {
	return s.scope == nil || s.scope.Allowed(org)
}

// defenderReports are the validated Defender fields of a heartbeat.
type defenderReports struct {
	defender  []byte
	installed []byte
	events    []agentproto.DefenderEvent
}

// checkDefenderReport validates what a heartbeat reports of Defender and of
// the installed files: one that is too large or malformed is refused.
func checkDefenderReport(req agentproto.HeartbeatRequest) (*defenderReports, error) {
	r := &defenderReports{}
	if req.Defender != nil {
		if err := req.Defender.Check(); err != nil {
			return nil, apperr.Invalid("defender", err.Error())
		}
		r.events = req.Defender.Events
		stored := *req.Defender
		stored.Events = nil
		b, err := json.Marshal(stored)
		if err != nil {
			return nil, err
		}
		r.defender = b
	}
	if req.InstalledFiles != nil {
		if err := req.InstalledFiles.Check(); err != nil {
			return nil, apperr.Invalid("installedFiles", err.Error())
		}
		b, err := json.Marshal(req.InstalledFiles)
		if err != nil {
			return nil, err
		}
		r.installed = b
	}
	return r, nil
}

// storeDefender keeps what the agent reported and writes its events into
// the audit chain.
func (s *Service) storeDefender(ctx context.Context, tx pgx.Tx, d *Device, hostname string, ip netip.Addr, r *defenderReports) error {
	if r.defender != nil {
		if _, err := tx.Exec(ctx, `UPDATE devices SET defender = $2::jsonb, defender_at = now() WHERE id = $1`, d.ID, r.defender); err != nil {
			return err
		}
	}
	if r.installed != nil {
		if _, err := tx.Exec(ctx, `UPDATE devices SET installed_files = $2::jsonb, installed_files_at = now() WHERE id = $1`, d.ID, r.installed); err != nil {
			return err
		}
	}
	for _, e := range r.events {
		outcome := audit.Success
		if e.Kind == agentproto.DefenderEventRefuse || e.Kind == agentproto.DefenderEventNotLocked {
			outcome = audit.Failure
		}
		err := s.audit.Write(ctx, tx, audit.Event{
			Actor:  audit.Actor{Type: audit.ActorAgent, ID: d.ID, Label: hostname, SourceIP: ip},
			Action: agentproto.DefenderAuditAction(e.Kind), Outcome: outcome,
			OrganizationID: d.OrganizationID, SiteID: d.SiteID, DeviceID: d.ID, TargetType: "device", TargetID: d.ID.String(),
			Details: map[string]any{"path": e.Path, "exclusionKind": e.ExclusionKind, "reason": e.Reason, "at": e.At},
		})
		if err != nil {
			return err
		}
	}
	return nil
}

// DefenderLog stores a heartbeat's Defender events and says whether the agent
// should read its log (defenderlog.Store). It runs in the heartbeat's
// transaction.
type DefenderLog interface {
	// Enabled is whether the module is on for the device and its role is
	// there.
	Enabled(ctx context.Context, tx pgx.Tx, device, org, site uuid.UUID) bool
	Ingest(ctx context.Context, tx pgx.Tx, device, org, site uuid.UUID, b *agentproto.DefenderLogBatch) (*agentproto.DefenderLogAck, error)
}

// SetDefenderLog has heartbeats' Defender events stored in l (ADR-0074).
func (s *Service) SetDefenderLog(l DefenderLog) { s.dlog = l }

// storeDefenderLog stores a batch and returns the policy answer's event
// fields: whether the agent is to read its log, and the acknowledgement. A
// failure never fails the heartbeat; the events are sent again.
func (s *Service) storeDefenderLog(ctx context.Context, tx pgx.Tx, d *Device, b *agentproto.DefenderLogBatch) (bool, *agentproto.DefenderLogAck) {
	if s.dlog == nil {
		return false, nil
	}
	sp, err := tx.Begin(ctx)
	if err != nil {
		return false, nil
	}
	if !s.dlog.Enabled(ctx, sp, d.ID, d.OrganizationID, d.SiteID) {
		_ = sp.Rollback(ctx)
		return false, nil
	}
	ack, err := s.dlog.Ingest(ctx, sp, d.ID, d.OrganizationID, d.SiteID, b)
	if err != nil {
		s.log.Warn("agents: storing Defender events failed", "error", err, "device_id", d.ID)
		_ = sp.Rollback(ctx)
		return true, nil
	}
	if err := sp.Commit(ctx); err != nil {
		return true, nil
	}
	return true, ack
}
