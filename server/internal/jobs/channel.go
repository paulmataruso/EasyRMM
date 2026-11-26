package jobs

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/server/internal/database"
)

// OnWork has f called with the devices that have work to claim: runs queued
// or canceled. The agent channel (ADR-0059) uses it to claim for a live
// device and push, where an agent without one has its poll woken.
func (s *Service) OnWork(f func(devices []uuid.UUID)) { s.hub.after = f }

// ClaimFor claims what is due for a device the agent channel holds and
// returns it for a jobs frame, as a poll would: the same claim, the same
// accepts the device last kept. A claim whose frame would pass maxBytes is
// put back as it was (queued, or a cancellation not yet sent) and returned
// all the same, so that the caller can tell the heartbeat to have the agent
// poll; the poll then takes it.
func (s *Service) ClaimFor(ctx context.Context, device uuid.UUID, maxBytes int) (*agentproto.PollResponse, error) {
	var accepts []string
	err := s.db.ReadTx(ctx, database.System, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT `+acceptsNow+` FROM devices d WHERE d.id = $1`, device).Scan(&accepts)
	})
	if err != nil {
		return nil, fmt.Errorf("jobs: reading what the agent accepts: %w", err)
	}
	resp, err := s.claim(ctx, device, accepts)
	if err != nil || (len(resp.Jobs) == 0 && len(resp.Cancel) == 0) {
		return resp, err
	}
	if b, err := json.Marshal(resp); err == nil && len(b) <= maxBytes {
		return resp, nil
	}
	if err := s.unclaim(ctx, resp); err != nil {
		return nil, err
	}
	return resp, nil
}

// unclaim puts a claim back: its runs queued again, as if never sent, and
// its cancellations due again.
func (s *Service) unclaim(ctx context.Context, resp *agentproto.PollResponse) error {
	var runs, cancels []uuid.UUID
	for _, j := range resp.Jobs {
		p, _, err := agentproto.DecodeJob(j)
		if err == nil {
			if id, err := uuid.Parse(p.RunID); err == nil {
				runs = append(runs, id)
			}
		}
	}
	for _, c := range resp.Cancel {
		if id, err := uuid.Parse(c); err == nil {
			cancels = append(cancels, id)
		}
	}
	return s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `UPDATE job_runs SET status = 'queued', sent_at = NULL, deliveries = greatest(deliveries - 1, 0)
			WHERE id = ANY($1) AND status = 'sent'`, runs); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `UPDATE job_runs SET cancel_sent_at = NULL WHERE id = ANY($1) AND status = 'running'`, cancels)
		return err
	})
}

// Waiting says whether the device has work a poll would claim now: runs due
// and not held back, or cancellations to send. A live device's heartbeat
// answer says so (jobsWaiting) when the channel did not carry it.
func (s *Service) Waiting(ctx context.Context, device uuid.UUID) (bool, error) {
	var waiting bool
	err := s.db.ReadTx(ctx, database.System, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT EXISTS (
				SELECT 1 FROM job_runs r JOIN jobs j ON j.id = r.job_id JOIN devices d ON d.id = r.device_id
				WHERE r.device_id = $1 AND r.expires_at > now() AND r.cancel_requested_at IS NULL
				  AND (r.status = 'queued' OR (r.status = 'sent' AND r.sent_at < now() - make_interval(secs => $2)))
				  AND j.requires <@ coalesce(`+acceptsNow+`, '{}'::text[])
				  AND `+oneChangeAtATime+`
			) OR EXISTS (
				SELECT 1 FROM job_runs WHERE device_id = $1 AND status = 'running' AND cancel_requested_at IS NOT NULL
				  AND (cancel_sent_at IS NULL OR cancel_sent_at < now() - make_interval(secs => $3))
			)`, device, RedeliverAfter.Seconds(), CancelResend.Seconds()).Scan(&waiting)
	})
	return waiting, err
}
