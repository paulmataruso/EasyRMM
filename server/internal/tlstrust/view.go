package tlstrust

import (
	"context"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/server/internal/access"
	"github.com/paulmataruso/easyrmm/server/internal/devices"
)

// Check is one chain's verification on a device, as the console shows it.
type Check struct {
	// Scope is whose trust was checked: "agent", or "easypatch".
	Scope string `json:"scope"`
	Host  string `json:"host"`
	// Purpose is "served", "fallback" or "target".
	Purpose string `json:"purpose"`
	// State is "pending" (not reported), "passed" or "failed".
	State string `json:"state"`
	Error string `json:"error,omitempty"`
	// StandIn marks a Linux device's EasyPatch result: the EasyRMM agent
	// checked it against the system's bundle, which the EasyPatch agent
	// (.NET) may not read the same way (ADR-0055).
	StandIn     bool       `json:"standIn,omitempty"`
	RequestedAt time.Time  `json:"requestedAt"`
	CheckedAt   *time.Time `json:"checkedAt,omitempty"`
}

// Reinstall is the offer of Reinstall through a remote session.
type Reinstall struct {
	// Reason says why the device looks cut off.
	Reason string `json:"reason"`
	// Fix is what to do about the error the device reported.
	Fix string `json:"fix"`
}

// View is a device's trust, for its page.
type View struct {
	// Capable is true once the agent reported that it understands trust
	// instructions; an older one reports nothing, which is "not verified".
	Capable bool   `json:"capable"`
	Origin  string `json:"origin,omitempty"`
	// Trusts is what the agent says it trusts: "system", "ca-file" or
	// "system+ca-file". Informational: nothing counts it as proof.
	Trusts     string     `json:"trusts,omitempty"`
	Widened    bool       `json:"widened"`
	ReportedAt *time.Time `json:"reportedAt,omitempty"`
	// Refused is the last refusal the agent reported for an instruction.
	Refused string  `json:"refused,omitempty"`
	Checks  []Check `json:"checks"`
	// Unprotected: the device failed the chain its name falls back to, so it
	// would be cut off if the name fell back (ADR-0055).
	Unprotected bool       `json:"unprotected"`
	Reinstall   *Reinstall `json:"reinstall,omitempty"`
	// CanTerminal says the caller can open a terminal through MeshAgent,
	// which checks no TLS chain, to reinstall.
	CanTerminal bool   `json:"canTerminal"`
	Platform    string `json:"platform"`
	SiteID      string `json:"siteId"`
}

// StaleAfter is how long a question may go unanswered, on a device that is not
// connected, before the device looks cut off.
const StaleAfter = time.Hour

// Device returns a device's trust for a caller who may view the device.
func (s *Service) Device(ctx context.Context, c access.Caller, id uuid.UUID) (*View, error) {
	d, err := devices.Lookup(ctx, s.db, c, id)
	if err != nil {
		return nil, err
	}
	v := &View{Checks: []Check{}, CanTerminal: d.CanTerminal, Platform: d.Platform, SiteID: d.SiteID.String()}
	err = s.db.ReadTx(ctx, c.Scope, func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx, `SELECT capable, origin, trusts, widened, reported_at, refused FROM device_tls_state WHERE device_id = $1`, id).
			Scan(&v.Capable, &v.Origin, &v.Trusts, &v.Widened, &v.ReportedAt, &v.Refused)
		if err != nil && err != pgx.ErrNoRows {
			return err
		}
		rows, err := tx.Query(ctx, `SELECT scope, host, purpose, state, error, requested_at, checked_at, sent_at FROM device_tls_trust
			WHERE device_id = $1 ORDER BY scope, host, purpose`, id)
		if err != nil {
			return err
		}
		defer rows.Close()
		now := s.now()
		for rows.Next() {
			var ch Check
			var sent *time.Time
			if err := rows.Scan(&ch.Scope, &ch.Host, &ch.Purpose, &ch.State, &ch.Error, &ch.RequestedAt, &ch.CheckedAt, &sent); err != nil {
				return err
			}
			ch.StandIn = ch.Scope == agentproto.TrustScopeEasyPatch && d.Platform == "linux"
			v.Checks = append(v.Checks, ch)
			if ch.Purpose == agentproto.TrustFallback && ch.State == "failed" {
				v.Unprotected = true
			}
			if !d.Online && v.Reinstall == nil && ch.Scope == agentproto.TrustScopeAgent {
				switch {
				case ch.State == "failed":
					v.Reinstall = &Reinstall{Reason: "The agent reported that it cannot verify the server's certificate, and it is not connected now.", Fix: FixFor(ch.Error)}
				case ch.State == "pending" && ch.Purpose == agentproto.TrustTarget && sent != nil && now.Sub(*sent) > StaleAfter:
					v.Reinstall = &Reinstall{Reason: "The agent was asked to verify the new certificate more than an hour ago and has not answered; it may no longer reach the server.", Fix: FixFor("")}
				}
			}
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return v, nil
}

// FixFor says what to do about an error an agent reported for a chain: the
// computer's root certificates, its clock, or the name the certificate is for.
func FixFor(err string) string {
	e := strings.ToLower(err)
	switch {
	case strings.Contains(e, "unknown authority"):
		return "Update the computer's root certificates (on Windows, Windows Update's root certificate update; on Linux, the ca-certificates package), or reinstall the agent with --ca-file pointing at the server's certificate authority."
	case strings.Contains(e, "expired") || strings.Contains(e, "not yet valid"):
		return "Check the computer's date and time, then reinstall the agent if it still cannot connect."
	case strings.Contains(e, "valid for"):
		return "The certificate does not cover the name this agent connects to. Reinstall the agent through a name the certificate covers."
	default:
		return "Reinstall the agent through the remote session, with --ca-file pointing at the server's certificate authority if the computer cannot be given the public roots."
	}
}
