package notify

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
)

// Quota is one organization's limits, in messages (a webhook delivery is
// one message; an email delivery is one per recipient).
type Quota struct {
	Channels        int `json:"channels"`
	Rules           int `json:"rules"`
	TestsPerHour    int `json:"testsPerHour"`
	MessagesPerHour int `json:"messagesPerHour"`
}

// DefaultQuota is what an organization has until a super administrator
// changes it.
var DefaultQuota = Quota{Channels: DefaultChannels, Rules: DefaultRules, TestsPerHour: DefaultTestsPerHour, MessagesPerHour: DefaultMessagesPerHour}

func quotaOf(ctx context.Context, tx pgx.Tx, org uuid.UUID) (Quota, error) {
	q := DefaultQuota
	err := tx.QueryRow(ctx, `SELECT channels, rules, tests_per_hour, messages_per_hour FROM notification_quotas WHERE organization_id = $1`, org).
		Scan(&q.Channels, &q.Rules, &q.TestsPerHour, &q.MessagesPerHour)
	if errors.Is(err, pgx.ErrNoRows) {
		return DefaultQuota, nil
	}
	return q, err
}

// GetQuota reads an organization's quota, for whoever manages it.
func (s *Service) GetQuota(ctx context.Context, c access.Caller, org uuid.UUID) (Quota, error) {
	if err := authorize(c, org); err != nil {
		return Quota{}, err
	}
	var q Quota
	err := s.db.ReadTx(ctx, database.System, func(tx pgx.Tx) error {
		var err error
		q, err = quotaOf(ctx, tx, org)
		return err
	})
	return q, err
}

// SetQuota changes an organization's quota: super administrators only.
func (s *Service) SetQuota(ctx context.Context, c access.Caller, org uuid.UUID, q Quota) (Quota, error) {
	if err := authorize(c, uuid.Nil); err != nil {
		return Quota{}, err
	}
	f := apperr.Fields{}
	f.Check(q.Channels >= 0 && q.Channels <= 10000, "channels", "Between 0 and 10,000.")
	f.Check(q.Rules >= 0 && q.Rules <= 10000, "rules", "Between 0 and 10,000.")
	f.Check(q.TestsPerHour >= 0 && q.TestsPerHour <= 10000, "testsPerHour", "Between 0 and 10,000.")
	f.Check(q.MessagesPerHour >= 0 && q.MessagesPerHour <= 1000000, "messagesPerHour", "Between 0 and 1,000,000.")
	if err := f.Err(); err != nil {
		return Quota{}, err
	}
	err := s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO notification_quotas (organization_id, channels, rules, tests_per_hour, messages_per_hour, updated_by)
			VALUES ($1, $2, $3, $4, $5, $6)
			ON CONFLICT (organization_id) DO UPDATE SET channels = $2, rules = $3, tests_per_hour = $4, messages_per_hour = $5, updated_by = $6, updated_at = now()`,
			org, q.Channels, q.Rules, q.TestsPerHour, q.MessagesPerHour, actorID(c.Actor)); err != nil {
			if database.IsForeignKeyViolation(err) {
				return apperr.NotFound()
			}
			return err
		}
		return s.audit.Write(ctx, tx, audit.Event{Actor: c.Actor, Action: ActionQuota, OrganizationID: org, TargetType: "organization",
			TargetID: org.String(), Outcome: audit.Success, Details: map[string]any{"channels": q.Channels, "rules": q.Rules,
				"testsPerHour": q.TestsPerHour, "messagesPerHour": q.MessagesPerHour}})
	})
	return q, err
}

// messagesLastHour counts the messages sent for an organization's account in
// the last hour.
func messagesLastHour(ctx context.Context, tx pgx.Tx, org uuid.UUID, now time.Time) (int, error) {
	var n int
	err := tx.QueryRow(ctx, `SELECT count(*) FROM notification_delivery_recipients r JOIN notification_deliveries d ON d.id = r.delivery_id
		WHERE d.charged_org = $1 AND d.kind <> 'test' AND r.sent_at > $2`, org, now.Add(-time.Hour)).Scan(&n)
	return n, err
}
