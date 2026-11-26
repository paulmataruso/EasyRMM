package notify

import (
	"context"
	"encoding/json"
	"slices"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/devscope"
)

// The classes of delivery: a slow mail server never holds a webhook back.
const (
	classWebhook = "webhook"
	classEmail   = "email"
)

// In flight at once (ADR-0053, "Fair share").
const (
	maxWebhooks  = 8
	maxEmail     = 4
	perOrgFlight = 2
	platformCap  = 4
	leaseSlack   = time.Minute
	leaseTime    = 30*time.Second + leaseSlack
)

// flightState is what is being sent now, and who was served last. One
// worker holds the lock across servers, so memory is enough.
type flightState struct {
	total   map[string]int
	perOrg  map[string]int
	perChan map[uuid.UUID]bool
	served  map[string]time.Time
}

func newFlight() flightState {
	return flightState{total: map[string]int{}, perOrg: map[string]int{}, perChan: map[uuid.UUID]bool{}, served: map[string]time.Time{}}
}

func classCap(class string) int {
	if class == classEmail {
		return maxEmail
	}
	return maxWebhooks
}

func orgCap(org uuid.UUID) int {
	if org == uuid.Nil {
		return platformCap
	}
	return perOrgFlight
}

func orgKey(class string, org uuid.UUID) string { return class + "/" + org.String() }

// candidate is a channel with something due.
type candidate struct {
	channel, owner, charged uuid.UUID
	class                   string
}

func (s *Service) candidates(ctx context.Context) ([]candidate, error) {
	var out []candidate
	err := s.db.ReadTx(ctx, database.System, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT DISTINCT ON (d.channel_id) d.channel_id, c.owner, d.charged_org, c.kind
			FROM notification_deliveries d JOIN notification_channels c ON c.id = d.channel_id
			WHERE d.status = 'pending' AND d.next_attempt_at <= $1 AND (d.lease_until IS NULL OR d.lease_until <= $1)
			ORDER BY d.channel_id, (d.kind = 'test') DESC, d.queued_at LIMIT 500`, s.now())
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var c candidate
			var kind string
			if err := rows.Scan(&c.channel, &c.owner, &c.charged, &kind); err != nil {
				return err
			}
			c.class = classWebhook
			if kind == KindEmail {
				c.class = classEmail
			}
			out = append(out, c)
		}
		return rows.Err()
	})
	return out, err
}

// pick chooses what to send now: round-robin over the organizations charged
// (the platform among them), at most 2 in flight per organization and 4 for
// the platform, 1 per channel, and 8 webhooks and 4 email sessions in all.
// What it picks is counted in flight until done is called.
func (s *Service) pick(cands []candidate) (picked []candidate) {
	s.fmu.Lock()
	defer s.fmu.Unlock()
	f := &s.flight
	queues := map[string][]candidate{}
	var keys []string
	for _, c := range cands {
		if c.class == classEmail && s.mailPaused() {
			continue
		}
		k := orgKey(c.class, c.charged)
		if _, ok := queues[k]; !ok {
			keys = append(keys, k)
		}
		queues[k] = append(queues[k], c)
	}
	// Whoever was served longest ago goes first.
	slices.SortStableFunc(keys, func(a, b string) int { return f.served[a].Compare(f.served[b]) })
	for progress := true; progress; {
		progress = false
		for _, k := range keys {
			q := queues[k]
			for len(q) > 0 {
				c := q[0]
				q = q[1:]
				if f.perChan[c.channel] || f.total[c.class] >= classCap(c.class) || f.perOrg[k] >= orgCap(c.charged) {
					continue
				}
				f.total[c.class]++
				f.perOrg[k]++
				f.perChan[c.channel] = true
				f.served[k] = s.now()
				picked = append(picked, c)
				progress = true
				break
			}
			queues[k] = q
		}
	}
	return picked
}

func (s *Service) done(c candidate) {
	s.fmu.Lock()
	defer s.fmu.Unlock()
	f := &s.flight
	f.total[c.class]--
	f.perOrg[orgKey(c.class, c.charged)]--
	delete(f.perChan, c.channel)
}

// Run is the worker: one per server, holding a session advisory lock on one
// connection for its whole life. If the connection is lost it stops sending
// and takes the lock again. It also plans the journal's rows, sweeps the
// transports and purges what has ended. While the server is held
// (ADR-0052) it does nothing.
func (s *Service) Run(ctx context.Context) {
	lead := s.db.Leader(lockWorker)
	defer lead.Close()
	t := time.NewTicker(2 * time.Second)
	defer t.Stop()
	var lastPlan, lastSweep, lastPurge time.Time
	for {
		select {
		case <-ctx.Done():
			s.wg.Wait()
			return
		case <-t.C:
		case <-s.wake:
		}
		if s.held() {
			continue
		}
		ok, err := lead.Lead(ctx)
		if err != nil {
			if ctx.Err() == nil {
				s.log.Warn("notifications: taking the sender's lock failed", "error", err)
			}
			continue
		}
		if !ok {
			continue
		}
		s.tick(ctx)
		now := s.now()
		if now.Sub(lastPlan) >= 15*time.Second {
			lastPlan = now
			if err := s.Plan(ctx); err != nil && ctx.Err() == nil {
				s.log.Warn("notifications: planning failed", "error", err)
			}
		}
		if now.Sub(lastSweep) >= time.Minute {
			lastSweep = now
			s.sweepTransports()
		}
		if now.Sub(lastPurge) >= time.Hour {
			lastPurge = now
			if err := s.Purge(ctx); err != nil && ctx.Err() == nil {
				s.log.Warn("notifications: purging failed", "error", err)
			}
		}
	}
}

// tick starts what is due. The attempts run on their own; wait for them
// with s.wg.
func (s *Service) tick(ctx context.Context) {
	cands, err := s.candidates(ctx)
	if err != nil {
		if ctx.Err() == nil {
			s.log.Warn("notifications: reading what is due failed", "error", err)
		}
		return
	}
	for _, c := range s.pick(cands) {
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer s.done(c)
			defer s.Kick()
			s.sendNext(ctx, c)
		}()
	}
}

// delivery is a claimed delivery.
type delivery struct {
	id          uuid.UUID
	owner       uuid.UUID
	charged     uuid.UUID
	channel     uuid.UUID
	kind, event string
	about       []uuid.UUID
	message     json.RawMessage
	attempts    int
	queuedAt    time.Time
	subjects    []string
	nextAttempt time.Time
	leaseUntil  *time.Time
}

func disjoint(a, b []string) bool {
	for _, x := range a {
		if slices.Contains(b, x) {
			return false
		}
	}
	return true
}

// claim chooses and leases a channel's next delivery, under the channel's
// lock, in the channel owner's scope. A channel's deliveries go in the order
// they were queued while the earliest unsent one is retried; after an hour a
// later one may go before it, but never one that shares a subject with any
// earlier unsent one. Tests go ahead of the queue.
func (s *Service) claim(ctx context.Context, c candidate) (*delivery, error) {
	var got *delivery
	err := s.db.InTx(ctx, ownerScope(c.owner), func(tx pgx.Tx) error {
		if err := lockChannel(ctx, tx, c.channel); err != nil {
			return err
		}
		now := s.now()
		rows, err := tx.Query(ctx, `SELECT id, owner, charged_org, kind, event, subjects, about, message, attempts, queued_at, next_attempt_at, lease_until
			FROM notification_deliveries WHERE channel_id = $1 AND status = 'pending' ORDER BY queued_at, id LIMIT 200`, c.channel)
		if err != nil {
			return err
		}
		var all []*delivery
		for rows.Next() {
			d := &delivery{channel: c.channel}
			if err := rows.Scan(&d.id, &d.owner, &d.charged, &d.kind, &d.event, &d.subjects, &d.about, &d.message, &d.attempts, &d.queuedAt, &d.nextAttempt, &d.leaseUntil); err != nil {
				rows.Close()
				return err
			}
			all = append(all, d)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		leased := func(d *delivery) bool { return d.leaseUntil != nil && d.leaseUntil.After(now) }
		due := func(d *delivery) bool { return !d.nextAttempt.After(now) && !leased(d) }
		var pick *delivery
		for _, d := range all {
			if d.kind == DeliveryTest && due(d) {
				pick = d
				break
			}
		}
		if pick == nil {
			// One sending per channel: a lease still current holds the rest back.
			for _, d := range all {
				if leased(d) {
					return nil
				}
			}
			// Order is kept among one organization's deliveries: a platform
			// channel is shared, and one organization's message waiting for
			// room under its quota must not hold another's back.
			type line struct {
				first   *delivery
				earlier []string
			}
			lines := map[uuid.UUID]*line{}
			for _, d := range all {
				if d.kind == DeliveryTest {
					continue
				}
				ln := lines[d.charged]
				if ln == nil {
					ln = &line{}
					lines[d.charged] = ln
				}
				if ln.first == nil {
					ln.first = d
					if due(d) {
						pick = d
						break
					}
				} else if now.Sub(ln.first.queuedAt) >= OrderRelaxAfter && due(d) && disjoint(d.subjects, ln.earlier) {
					pick = d
					break
				}
				ln.earlier = append(ln.earlier, d.subjects...)
			}
		}
		if pick == nil {
			return nil
		}
		tag, err := tx.Exec(ctx, `UPDATE notification_deliveries SET lease_until = $2 WHERE id = $1 AND status = 'pending' AND (lease_until IS NULL OR lease_until <= $3)`,
			pick.id, now.Add(leaseTime), now)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 1 {
			got = pick
		}
		return nil
	})
	return got, err
}

func (s *Service) sendNext(ctx context.Context, c candidate) {
	d, err := s.claim(ctx, c)
	if err != nil {
		if ctx.Err() == nil {
			s.log.Warn("notifications: choosing a delivery failed", "error", err)
		}
		return
	}
	if d == nil {
		return
	}
	// A send must finish, and be recorded, even as the server stops.
	s.attempt(context.WithoutCancel(ctx), d)
}

// allowed says whether devscope lets the delivery go: an automatic send
// about an organization outside the dev scope is never made. A person's own
// test is not automatic.
func allowed(d *delivery) bool {
	if d.kind == DeliveryTest {
		return true
	}
	if d.charged != uuid.Nil && !devscope.Allowed(d.charged) {
		return false
	}
	for _, o := range d.about {
		if !devscope.Allowed(o) {
			return false
		}
	}
	return true
}

// SendDue sends what is due now and waits for it, for tests.
func (s *Service) SendDue(ctx context.Context) {
	s.tick(ctx)
	s.wg.Wait()
}
