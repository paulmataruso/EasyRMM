package notify

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/server/internal/access"
	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
)

// attempt makes one attempt at a claimed delivery and records how it went.
func (s *Service) attempt(ctx context.Context, d *delivery) {
	if !allowed(d) {
		s.end(ctx, d, StatusDropped, "The organization is outside this server's development scope.")
		return
	}
	l, err := s.load(ctx, d)
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && !l.enabled) {
		s.end(ctx, d, StatusDropped, "The channel is gone or turned off.")
		return
	}
	if err != nil {
		s.log.Warn("notifications: reading a channel failed", "error", err)
		s.release(ctx, d)
		return
	}
	if wait, err := s.overQuota(ctx, d, l); err != nil {
		s.log.Warn("notifications: reading the quota failed", "error", err)
		s.release(ctx, d)
		return
	} else if wait {
		return
	}
	var res result
	switch l.kind {
	case KindWebhook:
		res = s.sendWebhook(ctx, d, l)
	case KindEmail:
		res = s.sendEmail(ctx, d, l)
		s.circuitRecord(res.mailFailure, res.mailOK)
	default:
		s.end(ctx, d, StatusFailed, "EasyRMM cannot send to this kind of channel.")
		return
	}
	if res.approval {
		// The address policy refuses a private destination until a super
		// administrator approves it: ask, once, and say so.
		if _, err := s.ask(ctx, d.owner, d.channel, audit.SystemActor("notifications")); err != nil && !isAlready(err) {
			s.log.Warn("notifications: asking for an approval failed", "error", err)
		}
	}
	if err := s.record(ctx, d, l, res); err != nil {
		s.log.Warn("notifications: recording a delivery failed", "error", err)
	}
}

func isAlready(err error) bool {
	ae, ok := apperr.As(err)
	return ok && ae.Code == "already_approved"
}

// release gives a lease back, to try again at the next tick.
func (s *Service) release(ctx context.Context, d *delivery) {
	_ = s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE notification_deliveries SET lease_until = NULL WHERE id = $1`, d.id)
		return err
	})
}

// end ends a delivery without sending.
func (s *Service) end(ctx context.Context, d *delivery, status, why string) {
	err := s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `UPDATE notification_deliveries SET status = $2, ended_at = $3, lease_until = NULL, last_error = $4
			WHERE id = $1 AND status = 'pending'`, d.id, status, s.now(), why); err != nil {
			return err
		}
		if d.kind != DeliveryTest && status != StatusSent {
			return s.notSent(ctx, tx, d)
		}
		return nil
	})
	if err != nil {
		s.log.Warn("notifications: ending a delivery failed", "error", err)
	}
}

// overQuota holds a delivery back while its organization has used its
// messages for the hour: it waits for room, the 24 hours still running, and
// the organization's managers and super administrators are told. Tests have
// a quota of their own, and the platform's own deliveries none.
func (s *Service) overQuota(ctx context.Context, d *delivery, l *loaded) (bool, error) {
	if d.charged == uuid.Nil || d.kind == DeliveryTest {
		return false, nil
	}
	need := max(len(l.pending), 1)
	wait := false
	err := s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		q, err := quotaOf(ctx, tx, d.charged)
		if err != nil {
			return err
		}
		n, err := messagesLastHour(ctx, tx, d.charged, s.now())
		if err != nil {
			return err
		}
		org := d.charged
		if n+need > q.MessagesPerHour {
			wait = true
			if _, err := tx.Exec(ctx, `UPDATE notification_deliveries SET next_attempt_at = $2, lease_until = NULL,
				last_error = 'Waiting for room under the organization''s hourly message quota.' WHERE id = $1`, d.id, s.now().Add(time.Minute)); err != nil {
				return err
			}
			return openNotice(ctx, tx, &org, NoticeQuotaReached, "messages_per_hour", "The hourly message quota is reached",
				fmt.Sprintf("This organization's notifications reached %d messages in an hour. Further messages wait for room, and are given up after 24 hours.", q.MessagesPerHour))
		}
		return resolveNotice(ctx, tx, &org, NoticeQuotaReached, "messages_per_hour")
	})
	return wait, err
}

func backoff(attempts int) time.Duration {
	if attempts < 1 {
		attempts = 1
	}
	d := RetryFirst
	for i := 1; i < attempts && d < RetryMax; i++ {
		d *= 2
	}
	return min(d, RetryMax)
}

// record writes an attempt's outcome: each recipient's, the delivery's, and
// the channel's health, in one transaction under the channel's lock.
func (s *Service) record(ctx context.Context, d *delivery, l *loaded, res result) error {
	return s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		if err := lockChannel(ctx, tx, d.channel); err != nil {
			return err
		}
		var status string
		if err := tx.QueryRow(ctx, `SELECT status FROM notification_deliveries WHERE id = $1`, d.id).Scan(&status); err != nil {
			return err
		}
		if status != StatusPending {
			// Dropped meanwhile (the channel was turned off, or unshared): what was sent was sent.
			return nil
		}
		now := s.now()
		org := orgPtr(d.owner)
		isTest := d.kind == DeliveryTest
		for r, o := range res.recips {
			switch o.status {
			case StatusSent:
				_, err := tx.Exec(ctx, `UPDATE notification_delivery_recipients SET status = 'sent', attempts = attempts + 1, error = NULL, reply = $3, sent_at = $4
					WHERE delivery_id = $1 AND recipient = $2`, d.id, r, clip(o.reply, 500), now)
				if err != nil {
					return err
				}
			case StatusFailed:
				if _, err := tx.Exec(ctx, `UPDATE notification_delivery_recipients SET status = 'failed', attempts = attempts + 1, error = $3, reply = $4
					WHERE delivery_id = $1 AND recipient = $2`, d.id, r, clip(o.err, 500), clip(o.reply, 500)); err != nil {
					return err
				}
			default:
				if _, err := tx.Exec(ctx, `UPDATE notification_delivery_recipients SET attempts = attempts + 1, error = $3, reply = $4
					WHERE delivery_id = $1 AND recipient = $2`, d.id, r, clip(o.err, 500), clip(o.reply, 500)); err != nil {
					return err
				}
			}
		}
		var pending, sent int
		if err := tx.QueryRow(ctx, `SELECT count(*) FILTER (WHERE status = 'pending'), count(*) FILTER (WHERE status = 'sent')
			FROM notification_delivery_recipients WHERE delivery_id = $1`, d.id).Scan(&pending, &sent); err != nil {
			return err
		}
		attempts := d.attempts
		waiting := res.approval
		if !waiting {
			attempts++
		}
		givenUp := false
		final := ""
		switch {
		case pending == 0 && sent > 0:
			final = StatusSent
		case pending == 0:
			final = StatusFailed
		case !waiting && ((isTest && attempts >= TestAttempts) || (!isTest && now.Sub(d.queuedAt) >= GiveUpAfter)):
			// Given up: what is still pending is failed.
			givenUp, final = true, StatusFailed
			if _, err := tx.Exec(ctx, `UPDATE notification_delivery_recipients SET status = 'failed' WHERE delivery_id = $1 AND status = 'pending'`, d.id); err != nil {
				return err
			}
		}
		lastErr := res.err
		if waiting {
			lastErr = "Waiting for approval: a super administrator must approve this private destination."
		}
		if final != "" {
			var errText *string
			if final == StatusFailed {
				errText = &lastErr
			}
			if _, err := tx.Exec(ctx, `UPDATE notification_deliveries SET status = $2, attempts = $3, ended_at = $4, lease_until = NULL, last_error = $5, last_reply = NULLIF($6, '')
				WHERE id = $1`, d.id, final, attempts, now, errText, clip(res.reply, 500)); err != nil {
				return err
			}
		} else {
			wait := backoff(attempts)
			switch {
			case waiting:
				wait = time.Minute
			case res.retryAfter > wait:
				wait = min(res.retryAfter, RetryMax)
			}
			if _, err := tx.Exec(ctx, `UPDATE notification_deliveries SET attempts = $2, next_attempt_at = $3, lease_until = NULL, last_error = $4, last_reply = NULLIF($5, '')
				WHERE id = $1`, d.id, attempts, now.Add(wait), lastErr, clip(res.reply, 500)); err != nil {
				return err
			}
		}
		if waiting && org != nil {
			if err := openNotice(ctx, tx, org, NoticeWaitingApproval, d.channel.String(), "A webhook is waiting for approval",
				fmt.Sprintf("The webhook's destination %s:%d is a private or local address. A super administrator must approve it before EasyRMM sends to it.", l.host, l.port)); err != nil {
				return err
			}
		}
		if isTest {
			if final == StatusSent {
				// A successful test retries the channel's earliest unsent delivery at once.
				_, err := tx.Exec(ctx, `UPDATE notification_deliveries SET next_attempt_at = $2 WHERE id = (
					SELECT id FROM notification_deliveries WHERE channel_id = $1 AND status = 'pending' AND kind <> 'test' ORDER BY queued_at, id LIMIT 1)`, d.channel, now)
				return err
			}
			return nil
		}
		if waiting {
			return nil
		}
		if err := s.health(ctx, tx, d, org, final, givenUp, res, lastErr, now); err != nil {
			return err
		}
		if final == StatusFailed {
			return s.notSent(ctx, tx, d)
		}
		return nil
	})
}

// health updates a channel's failing state from an attempt (tests do not
// count). A channel is failing once a delivery to it has failed for 15
// minutes without a success since, has been given up, or has a permanent
// answer: at once for 401, 403, 404 and 410, after 3 messages in a row for
// the others. It recovers at its next success.
func (s *Service) health(ctx context.Context, tx pgx.Tx, d *delivery, org *uuid.UUID, final string, givenUp bool, res result, lastErr string, now time.Time) error {
	if final == StatusSent {
		if _, err := tx.Exec(ctx, `UPDATE notification_channel_details SET failing = false, failing_since = NULL, failures_in_row = 0,
			last_error = NULL, last_success_at = $2, last_attempt_at = $2 WHERE channel_id = $1`, d.channel, now); err != nil {
			return err
		}
		return resolveNotice(ctx, tx, org, NoticeChannelFailing, d.channel.String())
	}
	var since *time.Time
	var rows int
	if err := tx.QueryRow(ctx, `SELECT failing_since, failures_in_row FROM notification_channel_details WHERE channel_id = $1`, d.channel).Scan(&since, &rows); err != nil {
		return err
	}
	if since == nil {
		since = &now
	}
	permanent := final == StatusFailed && !givenUp
	if final == StatusFailed {
		rows++
	}
	failing := givenUp || res.hard || (permanent && rows >= FailingMessages) || now.Sub(*since) >= FailingAfter
	if _, err := tx.Exec(ctx, `UPDATE notification_channel_details SET failing = failing OR $2, failing_since = $3, failures_in_row = $4, last_error = $5, last_attempt_at = $6
		WHERE channel_id = $1`, d.channel, failing, *since, rows, clip(lastErr, 500), now); err != nil {
		return err
	}
	if !failing {
		return nil
	}
	var name string
	if err := tx.QueryRow(ctx, `SELECT name FROM notification_channels WHERE id = $1`, d.channel).Scan(&name); err != nil {
		return err
	}
	return openNotice(ctx, tx, org, NoticeChannelFailing, d.channel.String(), fmt.Sprintf("Notification channel %q is failing", name), lastErr)
}

// notSent raises, or updates, the notice that messages to a channel were
// not sent: "N messages to channel X were not sent".
func (s *Service) notSent(ctx context.Context, tx pgx.Tx, d *delivery) error {
	var name string
	var n int
	if err := tx.QueryRow(ctx, `SELECT name FROM notification_channels WHERE id = $1`, d.channel).Scan(&name); err != nil {
		return err
	}
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM notification_deliveries WHERE channel_id = $1 AND kind <> 'test' AND status IN ('failed', 'dropped') AND ended_at > $2`,
		d.channel, s.now().Add(-24*time.Hour)).Scan(&n); err != nil {
		return err
	}
	word := "messages"
	if n == 1 {
		word = "message"
	}
	return openNotice(ctx, tx, orgPtr(d.owner), NoticeNotSent, d.channel.String(), "Notification messages were not sent",
		fmt.Sprintf("%d %s to channel %q were not sent.", n, word, name))
}

// TestResult is how a channel's test went.
type TestResult struct {
	DeliveryID uuid.UUID `json:"deliveryId"`
	// Status is sent, failed, dropped, or pending when it has not ended yet.
	Status  string `json:"status"`
	Message string `json:"message"`
}

// Test queues a test message to the channel, ahead of its queue, and waits
// for the outcome. At most one per channel every 30 seconds, and 20 an hour
// per organization by default. The text is fixed, EasyRMM's own.
func (s *Service) Test(ctx context.Context, c access.Caller, id uuid.UUID) (TestResult, error) {
	owner, kind, err := s.manage(ctx, c, id)
	if err != nil {
		return TestResult{}, err
	}
	msg, _ := json.Marshal(testMessage)
	did := uuid.New()
	// The quota is the platform's to read.
	quota := DefaultQuota
	if owner != uuid.Nil {
		if err := s.db.ReadTx(ctx, database.System, func(tx pgx.Tx) error {
			var err error
			quota, err = quotaOf(ctx, tx, owner)
			return err
		}); err != nil {
			return TestResult{}, err
		}
	}
	err = s.db.InTx(ctx, ownerScope(owner), func(tx pgx.Tx) error {
		if err := lockChannel(ctx, tx, id); err != nil {
			return err
		}
		var enabled bool
		var recipients []string
		if err := tx.QueryRow(ctx, `SELECT c.enabled, d.recipients FROM notification_channels c JOIN notification_channel_details d ON d.channel_id = c.id WHERE c.id = $1`, id).
			Scan(&enabled, &recipients); err != nil {
			return err
		}
		if !enabled {
			return apperr.Conflict("channel_off", "The channel is turned off. Turn it on to test it.")
		}
		var wait *float64
		if err := tx.QueryRow(ctx, `SELECT extract(epoch FROM max(queued_at) + make_interval(secs => $2) - $3)::float8 FROM notification_deliveries
			WHERE channel_id = $1 AND kind = 'test' AND queued_at > $3 - make_interval(secs => $2)`, id, TestInterval.Seconds(), s.now()).Scan(&wait); err != nil {
			return err
		}
		if wait != nil && *wait > 0 {
			return apperr.TooMany("test_rate_limited", "A test went less than 30 seconds ago. Try again in a few seconds.", time.Duration(*wait*float64(time.Second))+time.Second)
		}
		if owner != uuid.Nil {
			var n int
			if err := tx.QueryRow(ctx, `SELECT count(*) FROM notification_deliveries WHERE charged_org = $1 AND kind = 'test' AND queued_at > $2`, owner, s.now().Add(-time.Hour)).Scan(&n); err != nil {
				return err
			}
			if n >= quota.TestsPerHour {
				return apperr.TooMany("test_quota", "This organization has used its tests for the hour.", 5*time.Minute)
			}
		}
		about := []uuid.UUID{}
		if owner != uuid.Nil {
			about = append(about, owner)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO notification_deliveries (id, owner, charged_org, channel_id, kind, event, about, message, queued_at, next_attempt_at)
			VALUES ($1, $2, $2, $3, 'test', 'test', $4, $5, $6, $6)`, did, owner, id, about, msg, s.now()); err != nil {
			return err
		}
		rs := recipients
		if kind == KindWebhook {
			rs = []string{webhookRecipient}
		}
		for _, r := range rs {
			if _, err := tx.Exec(ctx, `INSERT INTO notification_delivery_recipients (delivery_id, recipient) VALUES ($1, $2)`, did, r); err != nil {
				return err
			}
		}
		return s.audit.Write(ctx, tx, audit.Event{Actor: c.Actor, Action: ActionTest, OrganizationID: owner, TargetType: "notification_channel",
			TargetID: id.String(), Outcome: audit.Success, Details: map[string]any{"deliveryId": did.String()}})
	})
	if err != nil {
		return TestResult{}, err
	}
	s.Kick()
	return s.awaitTest(ctx, owner, did), nil
}

func (s *Service) awaitTest(ctx context.Context, owner, did uuid.UUID) TestResult {
	deadline := time.Now().Add(s.testWait)
	for {
		res := TestResult{DeliveryID: did, Status: StatusPending}
		var lastErr *string
		var attempts int
		_ = s.db.ReadTx(ctx, ownerScope(owner), func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT status, last_error, attempts FROM notification_deliveries WHERE id = $1`, did).Scan(&res.Status, &lastErr, &attempts)
		})
		if lastErr != nil {
			res.Message = *lastErr
		}
		switch res.Status {
		case StatusSent:
			res.Message = "Sent. The receiver accepted the test message."
			return res
		case StatusFailed, StatusDropped:
			return res
		}
		if lastErr != nil && (attempts > 0 || *lastErr != "") {
			// Tried, and waiting to try again (or for an approval): the reason is the answer.
			return res
		}
		if time.Now().After(deadline) || ctx.Err() != nil {
			if res.Message == "" {
				res.Message = "The test is queued and has not been sent yet."
			}
			return res
		}
		select {
		case <-ctx.Done():
		case <-time.After(200 * time.Millisecond):
		}
	}
}

// DeliveryLog is a delivery as the log shows it.
type DeliveryLog struct {
	ID         uuid.UUID      `json:"id"`
	ChannelID  *uuid.UUID     `json:"channelId"`
	Kind       string         `json:"kind"`
	Event      string         `json:"event"`
	Status     string         `json:"status"`
	Attempts   int            `json:"attempts"`
	QueuedAt   time.Time      `json:"queuedAt"`
	EndedAt    *time.Time     `json:"endedAt,omitempty"`
	NextAt     *time.Time     `json:"nextAttemptAt,omitempty"`
	LastError  string         `json:"lastError,omitempty"`
	MailReply  string         `json:"mailReply,omitempty"`
	Recipients []RecipientLog `json:"recipients"`
}

// RecipientLog is one recipient's outcome.
type RecipientLog struct {
	Recipient string     `json:"recipient"`
	Status    string     `json:"status"`
	Error     string     `json:"error,omitempty"`
	SentAt    *time.Time `json:"sentAt,omitempty"`
}

// Deliveries is the delivery log (30 days) of a channel, or of an owner's
// channels. The mail server's own reply is for super administrators only.
func (s *Service) Deliveries(ctx context.Context, c access.Caller, org *uuid.UUID, channel *uuid.UUID, status string, limit int) ([]DeliveryLog, error) {
	owner := uuid.Nil
	if channel != nil {
		var err error
		if owner, _, err = s.manage(ctx, c, *channel); err != nil {
			return nil, err
		}
	} else {
		if org != nil {
			owner = *org
		}
		if err := authorize(c, owner); err != nil {
			return nil, err
		}
	}
	super := c.CanGlobal(rbac.PermSettingsManage)
	scope := ownerScope(owner)
	if channel == nil && org == nil {
		scope = database.System
	}
	if limit < 1 || limit > 500 {
		limit = 100
	}
	out := []DeliveryLog{}
	err := s.db.ReadTx(ctx, scope, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT id, channel_id, kind, event, status, attempts, queued_at, ended_at, CASE WHEN status = 'pending' THEN next_attempt_at END,
				coalesce(last_error, ''), coalesce(last_reply, '')
			FROM notification_deliveries WHERE ($1::uuid IS NULL OR channel_id = $1) AND ($2 = '' OR status = $2)
			  AND ($3::uuid IS NULL OR owner = $3) ORDER BY queued_at DESC, id LIMIT $4`, channel, status, orgPtr(ownerFilter(channel, org, owner)), limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		byID := map[uuid.UUID]int{}
		for rows.Next() {
			var l DeliveryLog
			if err := rows.Scan(&l.ID, &l.ChannelID, &l.Kind, &l.Event, &l.Status, &l.Attempts, &l.QueuedAt, &l.EndedAt, &l.NextAt, &l.LastError, &l.MailReply); err != nil {
				return err
			}
			if !super {
				l.MailReply = ""
			}
			l.Recipients = []RecipientLog{}
			byID[l.ID] = len(out)
			out = append(out, l)
		}
		rows.Close()
		for _, l := range out {
			rr, err := tx.Query(ctx, `SELECT recipient, status, coalesce(error, ''), sent_at FROM notification_delivery_recipients WHERE delivery_id = $1 ORDER BY recipient`, l.ID)
			if err != nil {
				return err
			}
			for rr.Next() {
				var r RecipientLog
				if err := rr.Scan(&r.Recipient, &r.Status, &r.Error, &r.SentAt); err != nil {
					rr.Close()
					return err
				}
				out[byID[l.ID]].Recipients = append(out[byID[l.ID]].Recipients, r)
			}
			rr.Close()
		}
		return nil
	})
	return out, err
}

// ownerFilter is the owner a log is narrowed to: none for a channel's own
// log or a platform-wide listing.
func ownerFilter(channel, org *uuid.UUID, owner uuid.UUID) uuid.UUID {
	if channel != nil || org == nil {
		return uuid.Nil
	}
	return owner
}

// Purge removes what has ended: deliveries 30 days after they end, planned
// journal rows after 7 days, resolved notices after 90.
func (s *Service) Purge(ctx context.Context) error {
	return s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		now := s.now()
		if _, err := tx.Exec(ctx, `DELETE FROM notification_deliveries WHERE ended_at < $1`, now.Add(-DeliveryRetention)); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM notification_events WHERE status = 'planned' AND planned_at < $1`, now.Add(-JournalRetention)); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM notices WHERE resolved_at < $1`, now.Add(-NoticeRetention)); err != nil {
			return err
		}
		// Incidents resolved a week ago, with what was recorded about them; outages and holds after a month.
		cut := now.Add(-JournalRetention)
		if _, err := tx.Exec(ctx, `DELETE FROM alert_notifications WHERE subject_type = 'notice' AND done AND created_at < $1`, cut); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM alert_notifications WHERE subject_type = 'incident' AND subject_id IN (SELECT id FROM alert_incidents WHERE status = 'resolved' AND resolved_at < $1)`, cut); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM alert_incident_alerts WHERE incident_id IN (SELECT id FROM alert_incidents WHERE status = 'resolved' AND resolved_at < $1)`, cut); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM alert_incidents WHERE status = 'resolved' AND resolved_at < $1`, cut); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM alert_notifications WHERE subject_type = 'outage' AND subject_id IN (SELECT id FROM site_outages WHERE ended_at < $1)`, now.Add(-NoticeRetention)); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM site_outages WHERE ended_at < $1`, now.Add(-NoticeRetention)); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `DELETE FROM fleet_silences WHERE ended_at < $1`, now.Add(-NoticeRetention))
		return err
	})
}
