package notify

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Queueing (ADR-0053, "The sender"): only the planner's transaction queues
// deliveries, under the channel's advisory lock. A channel read by people
// has at most one unsent digest, which what is queued merges into; a generic
// webhook's deliveries are events, which do not merge.

// MaxPending is how many unsent deliveries an organization may have; past
// it, new events to its webhooks are dropped and counted.
const MaxPending = 2000

// What happened, for the digest's sections.
type op int

const (
	opOpened op = iota
	opResolved
	opReminder
	opAck
	opDown
	opUp
	opNoticeOpened
	opNoticeResolved
)

// outEvent is one thing to tell a channel.
type outEvent struct {
	name   string
	op     op
	alert  *AlertItem
	outage *OutageItem
	notice *NoticeBody
}

// enqueue queues an event to a channel. about is the organization the event
// is about (the nil UUID for the platform's); charged is the organization
// whose rule produced it.
func (s *Service) enqueue(ctx context.Context, tx pgx.Tx, ch chInfo, charged, about uuid.UUID, subjects []string, ev outEvent) error {
	if err := lockChannel(ctx, tx, ch.id); err != nil {
		return err
	}
	var err error
	if ch.kind == KindWebhook {
		err = s.enqueueEvent(ctx, tx, ch, charged, about, subjects, ev)
	} else {
		err = s.enqueueDigest(ctx, tx, ch, charged, about, subjects, ev)
	}
	if err == nil {
		s.Kick()
	}
	return err
}

func aboutOf(org uuid.UUID) []uuid.UUID {
	if org == uuid.Nil {
		return []uuid.UUID{}
	}
	return []uuid.UUID{org}
}

// dropUnsent drops a channel's unsent webhook deliveries of one event about
// one subject: the receiver never heard of them.
func dropUnsent(ctx context.Context, tx pgx.Tx, channel uuid.UUID, event, subject, why string, now time.Time) (int64, error) {
	tag, err := tx.Exec(ctx, `UPDATE notification_deliveries SET status = 'dropped', ended_at = $5, last_error = $4
		WHERE channel_id = $1 AND status = 'pending' AND kind = 'event' AND event = $2 AND subjects @> ARRAY[$3]::text[]
		  AND attempts = 0 AND (lease_until IS NULL OR lease_until < $5)`, channel, event, subject, why, now)
	return tag.RowsAffected(), err
}

func (s *Service) enqueueEvent(ctx context.Context, tx pgx.Tx, ch chInfo, charged, about uuid.UUID, subjects []string, ev outEvent) error {
	subject := ""
	if len(subjects) > 0 {
		subject = subjects[0]
	}
	switch ev.op {
	case opResolved:
		// An opened never sent is dropped with the resolution that follows it.
		n, err := dropUnsent(ctx, tx, ch.id, EventAlertOpened, subject, "Dropped: the alert was resolved before it was sent.", s.now())
		if err != nil {
			return err
		}
		if _, err := dropUnsent(ctx, tx, ch.id, EventAlertReminder, subject, "Dropped: the alert was resolved.", s.now()); err != nil {
			return err
		}
		if n > 0 {
			return nil
		}
	case opAck, opReminder:
		// A newer event about the same alert replaces an unsent reminder.
		if _, err := dropUnsent(ctx, tx, ch.id, EventAlertReminder, subject, "Dropped: superseded by a newer event.", s.now()); err != nil {
			return err
		}
	}
	if charged != uuid.Nil {
		var pending int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM notification_deliveries WHERE charged_org = $1 AND status = 'pending'`, charged).Scan(&pending); err != nil {
			return err
		}
		if pending >= MaxPending {
			org := charged
			return openNotice(ctx, tx, &org, NoticeQueueFull, "pending", "Notifications are piling up",
				fmt.Sprintf("%d notifications wait to be sent. New events to webhooks are dropped until the queue is below %d.", pending, MaxPending))
		}
	}
	msg := Message{Subject: eventSubject(ev), Summary: eventSummary(ev)}
	if ev.alert != nil {
		msg.Alerts = []AlertItem{*ev.alert}
	}
	msg.Outage, msg.Notice = ev.outage, ev.notice
	raw, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	now := s.stamp()
	var id uuid.UUID
	if err := tx.QueryRow(ctx, `INSERT INTO notification_deliveries (owner, charged_org, channel_id, kind, event, subjects, about, message, queued_at, next_attempt_at)
		VALUES ($1, $2, $3, 'event', $4, $5, $6, $7, $8, $9) RETURNING id`, ch.owner, charged, ch.id, ev.name, subjects, aboutOf(about), raw, now, s.now()).Scan(&id); err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO notification_delivery_recipients (delivery_id, recipient) VALUES ($1, $2)`, id, webhookRecipient)
	return err
}

func eventSubject(ev outEvent) string {
	switch {
	case ev.alert != nil:
		return fmt.Sprintf("%s: %s", sev(ev.alert.Severity), ev.alert.Name)
	case ev.outage != nil && ev.op == opDown:
		return fmt.Sprintf("Site %s: all %d devices offline", ev.outage.Site, ev.outage.Devices)
	case ev.outage != nil:
		return fmt.Sprintf("Site %s is back online: %d of %d devices", ev.outage.Site, ev.outage.Back, ev.outage.Devices)
	case ev.notice != nil:
		return ev.notice.Title
	}
	return ev.name
}

func eventSummary(ev outEvent) string {
	switch {
	case ev.alert != nil:
		a := ev.alert
		verb := map[op]string{opOpened: "opened", opResolved: "resolved", opReminder: "is still open", opAck: "was acknowledged"}[ev.op]
		return fmt.Sprintf("%s on %s at %s %s.", a.Name, a.Device, a.Site, verb)
	case ev.notice != nil:
		return ev.notice.Detail
	}
	return eventSubject(ev)
}

// digestOf reads a delivery's digest, or starts one.
func digestOf(raw []byte) (*Digest, error) {
	var m Message
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	if m.Digest == nil {
		m.Digest = &Digest{}
	}
	return m.Digest, nil
}

func removeOutage(items []OutageItem, id uuid.UUID) ([]OutageItem, bool) {
	out := items[:0:0]
	found := false
	for _, it := range items {
		if it.ID == id {
			found = true
			continue
		}
		out = append(out, it)
	}
	return out, found
}

func removeNotice(items []NoticeBody, id uuid.UUID) ([]NoticeBody, bool) {
	out := items[:0:0]
	found := false
	for _, it := range items {
		if it.ID == id {
			found = true
			continue
		}
		out = append(out, it)
	}
	return out, found
}

const digestCap = 1000

// merge folds one event into a digest that has not been sent: an alert
// opened and resolved before it went is left out.
func (d *Digest) merge(ev outEvent) {
	switch ev.op {
	case opOpened:
		if ev.alert != nil {
			d.Open, _ = without(d.Open, ev.alert.ID)
			d.New, _ = without(d.New, ev.alert.ID)
			if len(d.New) < digestCap {
				d.New = append(d.New, *ev.alert)
			}
		}
	case opReminder:
		if ev.alert != nil {
			if _, inNew := without(d.New, ev.alert.ID); inNew {
				return
			}
			d.Open, _ = without(d.Open, ev.alert.ID)
			if len(d.Open) < digestCap {
				d.Open = append(d.Open, *ev.alert)
			}
		}
	case opResolved:
		if ev.alert == nil {
			return
		}
		var wasNew bool
		d.New, wasNew = without(d.New, ev.alert.ID)
		d.Open, _ = without(d.Open, ev.alert.ID)
		if !wasNew && len(d.Resolved) < digestCap {
			d.Resolved = append(d.Resolved, *ev.alert)
		}
	case opDown:
		if ev.outage != nil {
			d.Down, _ = removeOutage(d.Down, ev.outage.ID)
			d.Down = append(d.Down, *ev.outage)
		}
	case opUp:
		if ev.outage != nil {
			var wasDown bool
			d.Down, wasDown = removeOutage(d.Down, ev.outage.ID)
			if !wasDown {
				d.Up = append(d.Up, *ev.outage)
			}
		}
	case opNoticeOpened:
		if ev.notice != nil {
			d.Notices, _ = removeNotice(d.Notices, ev.notice.ID)
			d.Notices = append(d.Notices, *ev.notice)
		}
	case opNoticeResolved:
		if ev.notice != nil {
			var wasOpen bool
			d.Notices, wasOpen = removeNotice(d.Notices, ev.notice.ID)
			if !wasOpen {
				n := *ev.notice
				n.Title = "Resolved: " + n.Title
				d.Notices = append(d.Notices, n)
			}
		}
	}
}

// enqueueDigest merges an event into the channel's unsent digest, or starts
// one: at most one unsent digest per channel and organization charged,
// besides one being sent.
func (s *Service) enqueueDigest(ctx context.Context, tx pgx.Tx, ch chInfo, charged, about uuid.UUID, subjects []string, ev outEvent) error {
	if ev.op == opAck {
		return nil // only generic webhooks are told of acknowledgements
	}
	var (
		id    uuid.UUID
		raw   []byte
		subj  []string
		found = true
	)
	err := tx.QueryRow(ctx, `SELECT id, message, subjects FROM notification_deliveries
		WHERE channel_id = $1 AND charged_org = $2 AND kind = 'digest' AND status = 'pending' AND (lease_until IS NULL OR lease_until < $3)
		ORDER BY queued_at LIMIT 1 FOR UPDATE`, ch.id, charged, s.now()).Scan(&id, &raw, &subj)
	if errors.Is(err, pgx.ErrNoRows) {
		found = false
	} else if err != nil {
		return err
	}
	d := &Digest{}
	if found {
		if d, err = digestOf(raw); err != nil {
			return err
		}
	}
	d.merge(ev)
	if d.empty() {
		if found {
			_, err := tx.Exec(ctx, `UPDATE notification_deliveries SET status = 'dropped', ended_at = $2, last_error = 'Dropped: nothing was left to tell.' WHERE id = $1`, id, s.now())
			return err
		}
		return nil
	}
	subj = unionStrings(subj, subjects)
	msg, err := json.Marshal(Message{Subject: d.subjectLine(), Summary: d.subjectLine(), Digest: d})
	if err != nil {
		return err
	}
	if found {
		_, err = tx.Exec(ctx, `UPDATE notification_deliveries SET message = $2, subjects = $3, about = (SELECT coalesce(array_agg(DISTINCT x), '{}') FROM unnest(about || $4::uuid[]) x) WHERE id = $1`,
			id, msg, subj, aboutOf(about))
		return err
	}
	if charged != uuid.Nil {
		var pending int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM notification_deliveries WHERE charged_org = $1 AND status = 'pending'`, charged).Scan(&pending); err != nil {
			return err
		}
		if pending >= MaxPending {
			return nil
		}
	}
	if err := tx.QueryRow(ctx, `INSERT INTO notification_deliveries (owner, charged_org, channel_id, kind, event, subjects, about, message, queued_at, next_attempt_at)
		VALUES ($1, $2, $3, 'digest', $4, $5, $6, $7, $8, $9) RETURNING id`, ch.owner, charged, ch.id, EventDigest, subj, aboutOf(about), msg, s.stamp(), s.now()).Scan(&id); err != nil {
		return err
	}
	for _, r := range ch.recipients {
		if _, err := tx.Exec(ctx, `INSERT INTO notification_delivery_recipients (delivery_id, recipient) VALUES ($1, $2) ON CONFLICT DO NOTHING`, id, r); err != nil {
			return err
		}
	}
	return nil
}

func unionStrings(a, b []string) []string {
	out := slices.Clone(a)
	for _, x := range b {
		if !slices.Contains(out, x) {
			out = append(out, x)
		}
	}
	return out
}
