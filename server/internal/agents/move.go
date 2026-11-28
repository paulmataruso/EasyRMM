package agents

import (
	"context"
	"errors"
	"net/netip"

	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/database"
)

// Moving an agent between addresses (ADR-0061, slice 1). The server confirms
// an address to an enrolled device that asks, and records what an agent
// reports of changing address. Nothing here moves an agent: no instruction
// is sent.

// ErrNoKey is returned by ConfirmAddress when the server holds no key to sign
// with, as a server without a ring does in tests.
var ErrNoKey = errors.New("agents: the server has no key to confirm an address with")

// ConfirmAddress answers the signed request p, which asked whether this
// server answers on address, with a confirmation signed with the job key the
// device trusts, recorded as issued by the request's nonce in the transaction
// that signs (ADR-0057). The caller has checked that the server serves agents
// on address and that the request arrived there; this signs for an enrolled
// device only, as a request that reached it has already shown.
func (s *Service) ConfirmAddress(ctx context.Context, p *SignedRequest, address string) (agentproto.AddressAnswer, error) {
	if s.keys == nil {
		return agentproto.AddressAnswer{}, ErrNoKey
	}
	if p.device.Retired {
		return agentproto.AddressAnswer{}, ErrUnknownDevice
	}
	var ans agentproto.AddressAnswer
	err := s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		key, _, err := s.keys.Issue(ctx, tx, p.device.ID, agentproto.InstructionAddress, p.auth.Nonce)
		if err != nil {
			return err
		}
		ans = agentproto.SignAddress(key, p.auth, address)
		return nil
	})
	if err != nil {
		s.log.Error("agents: confirming an address failed", "error", err, "device_id", p.device.ID)
		return agentproto.AddressAnswer{}, err
	}
	return ans, nil
}

// Moved records an agent's report that it changed address, or could not: the
// audit log names the device, the way, both addresses and any error. The
// addresses are taken as the agent sent them, cleaned and bounded; they
// decide nothing.
func (s *Service) Moved(ctx context.Context, d *Device, ip netip.Addr, rep agentproto.MoveReport) error {
	if !agentproto.ValidMoveKind(rep.Kind) || len(rep.From) > 300 || len(rep.To) > 300 {
		return ErrBadReport
	}
	rep.Error = clean(rep.Error, agentproto.MaxMoveError)
	details := map[string]any{"kind": rep.Kind, "from": clean(rep.From, 300), "to": clean(rep.To, 300), "device": d.Hostname}
	ev := audit.Event{
		Actor:          audit.Actor{Type: audit.ActorAgent, ID: d.ID, Label: d.Hostname, SourceIP: ip},
		OrganizationID: d.OrganizationID, SiteID: d.SiteID, DeviceID: d.ID, TargetType: "device", TargetID: d.ID.String(),
		Details: details,
	}
	switch {
	case rep.Moved:
		ev.Action, ev.Outcome = "device.address_change", audit.Success
	default:
		ev.Action, ev.Outcome = "device.address_change_failed", audit.Failure
		details["error"] = nonEmpty(rep.Error, "The agent did not say why.")
	}
	return s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		return s.audit.Write(ctx, tx, ev)
	})
}
