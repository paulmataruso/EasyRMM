package easypatch

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/database"
)

// The EasyPatch agent's last check-in and repairs of it (ADR-0069, Part R).

// Timing.
const (
	// PollEvery is how often the engine is asked when its agents last
	// checked in.
	PollEvery = 5 * time.Minute
	// EngineSettle is how long the engine must have answered before
	// conditions about its agents are judged again: an outage of the
	// engine must not look like every agent going silent.
	EngineSettle = 15 * time.Minute
	// maxAgentPages bounds one organization's list in one pass.
	maxAgentPages = 100
)

// agentPoll is what the polls remember about the engine's reachability.
type agentPoll struct {
	mu sync.Mutex
	// okSince is when the polls began to succeed without a failure, zero
	// after one failed or before the first.
	okSince, lastOK time.Time
}

// SetClock sets the clock the service judges time by; tests set it.
func (s *Service) SetClock(now func() time.Time) { s.now = now }

// AgentsSettled reports whether conditions about the EasyPatch agents may
// be judged at now: the engine has answered every poll for EngineSettle, and
// the last one is recent. It is false while the engine is unreachable,
// for EngineSettle after it returns, and after the server starts.
func (s *Service) AgentsSettled(now time.Time) bool {
	s.poll.mu.Lock()
	defer s.poll.mu.Unlock()
	return !s.poll.okSince.IsZero() && now.Sub(s.poll.okSince) >= EngineSettle && now.Sub(s.poll.lastOK) < 2*PollEvery+time.Minute
}

func (s *Service) pollResult(ok bool, now time.Time) {
	s.poll.mu.Lock()
	defer s.poll.mu.Unlock()
	if !ok {
		s.poll.okSince = time.Time{}
		return
	}
	if s.poll.okSince.IsZero() {
		s.poll.okSince = now
	}
	s.poll.lastOK = now
}

// RunAgentPoll polls the engine every PollEvery until ctx ends.
func (s *Service) RunAgentPoll(ctx context.Context) {
	tick := time.NewTicker(PollEvery)
	defer tick.Stop()
	for {
		if err := s.PollAgents(ctx); err != nil && ctx.Err() == nil {
			s.log.Warn("easypatch: reading the agents' check-ins failed", "error", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

// PollAgents reads, with one list call per engine organization (more pages
// when it has more than the engine returns at once), when each linked
// endpoint's agent last checked in, and stores it as
// easypatch_devices.agent_seen_at. A failed call is a failed poll: nothing
// is judged until the engine has answered for EngineSettle.
func (s *Service) PollAgents(ctx context.Context) error {
	r, c, err := s.conn(ctx)
	if err != nil || r == nil {
		return err
	}
	var orgs []uuid.UUID
	err = s.db.ReadTx(ctx, database.System, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT easypatch_id FROM easypatch_organizations ORDER BY easypatch_id`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var id uuid.UUID
			if err := rows.Scan(&id); err != nil {
				return err
			}
			orgs = append(orgs, id)
		}
		return rows.Err()
	})
	if err != nil {
		return err
	}
	var ids []uuid.UUID
	var seen []time.Time
	for _, org := range orgs {
		for page := 1; page <= maxAgentPages; page++ {
			p, err := c.Endpoints(ctx, org, page)
			if err != nil {
				s.noteError(err)
				s.pollResult(false, s.now())
				return fmt.Errorf("listing the endpoints of organization %s: %w", org, err)
			}
			for _, e := range p.Items {
				if e.LastCheckInAt != nil {
					ids, seen = append(ids, e.ID), append(seen, e.LastCheckInAt.UTC())
				}
			}
			if len(p.Items) == 0 || page*PageSize >= p.TotalCount {
				break
			}
		}
	}
	if len(ids) > 0 {
		err = s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `UPDATE easypatch_devices e SET agent_seen_at = x.seen
				FROM unnest($1::uuid[], $2::timestamptz[]) AS x(endpoint, seen)
				WHERE e.endpoint_id = x.endpoint AND e.state = 'linked' AND e.agent_seen_at IS DISTINCT FROM x.seen`, ids, seen)
			return err
		})
		if err != nil {
			return err
		}
	}
	s.pollResult(true, s.now())
	return nil
}

// RepairOffer builds what repairing a device's EasyPatch agent in place
// needs: the packages of the version the device has, which the patching
// engine hosts, and the certificate authority to download them with. why
// says what stops it, "" when nothing does.
func (s *Service) RepairOffer(ctx context.Context, deviceID uuid.UUID) (_ *agentproto.RepairEasyPatch, why string, err error) {
	r, cl, err := s.operable(ctx)
	if err != nil {
		var ae *apperr.Error
		if errors.As(err, &ae) {
			return nil, ae.Message, nil
		}
		return nil, "", err
	}
	var t installTarget
	err = s.db.ReadTx(ctx, database.System, func(tx pgx.Tx) (err error) {
		t, err = loadTarget(ctx, tx, deviceID)
		return err
	})
	if err != nil {
		return nil, "", err
	}
	switch {
	case t.optedOut || t.removing:
		return nil, "The device is leaving patching.", nil
	case t.easyPatchOrg == nil:
		return nil, "The device's organization is not patched.", nil
	case formats(t.platform) == nil:
		return nil, "The EasyPatch agent is for Windows and Linux only.", nil
	case agentproto.EasyPatchArch(t.arch) == "":
		return nil, fmt.Sprintf("There is no EasyPatch agent for %s processors.", t.arch), nil
	}
	// The version the device reported; an agent whose program is gone
	// reports none, and the engine remembers the one it last saw.
	version := ""
	if t.report != nil {
		version = t.report.Version
	}
	if version == "" {
		var endpoint *uuid.UUID
		err = s.db.ReadTx(ctx, database.System, func(tx pgx.Tx) error {
			err := tx.QueryRow(ctx, `SELECT endpoint_id FROM easypatch_devices WHERE device_id = $1 AND state = 'linked'`, deviceID).Scan(&endpoint)
			if errors.Is(err, pgx.ErrNoRows) {
				return nil
			}
			return err
		})
		if err != nil {
			return nil, "", err
		}
		if endpoint != nil {
			d, err := cl.Endpoint(ctx, *endpoint)
			if err != nil {
				s.noteError(err)
				return nil, "The patching engine could not say which version of the EasyPatch agent this device has: " + message(epError(err)), nil
			}
			version = d.Summary.AgentVersion
		}
	}
	if version == "" {
		return nil, "EasyRMM does not know which version of the EasyPatch agent this device has, so it cannot offer the same one.", nil
	}
	server := strings.TrimRight(r.publicURL, "/")
	if server == "" {
		return nil, "The patching engine has no public address for agents to download from. Check that it runs with EASYRMM_PUBLIC_URL.", nil
	}
	list, err := cl.AgentPackages(ctx)
	if err != nil {
		s.noteError(err)
		return nil, "The patching engine could not list its agent packages: " + message(epError(err)), nil
	}
	arch := agentproto.EasyPatchArch(t.arch)
	var out []agentproto.EasyPatchPackage
	for _, f := range formats(t.platform) {
		for _, p := range list {
			if !strings.EqualFold(p.Format, f) || !strings.EqualFold(p.Architecture, arch) || !agentproto.SameVersion(p.Version, version) {
				continue
			}
			u := p.DownloadURL
			if !strings.HasPrefix(u, "https://") {
				u = server + "/" + strings.TrimLeft(u, "/")
			}
			out = append(out, agentproto.EasyPatchPackage{FileName: p.FileName, URL: u, Format: f, Arch: arch, Version: p.Version,
				Size: p.SizeBytes, SHA256: strings.ToLower(p.SHA256)})
			break
		}
	}
	if len(out) == 0 {
		return nil, fmt.Sprintf("The patching engine no longer offers version %s of the EasyPatch agent for %s %s, so it cannot be repaired in place. Update the EasyPatch agent instead.",
			version, platformName(t.platform), arch), nil
	}
	return &agentproto.RepairEasyPatch{CACert: caForAgent(r.caCert), Packages: out}, "", nil
}
