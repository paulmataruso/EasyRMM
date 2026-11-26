// Package notify is EasyRMM's one notification sender (ADR-0053, slice 3):
// channels (email and generic webhooks), the outbox and the worker that
// sends from it, quotas and retries, notices and their journal, and the
// approvals the address policy asks for.
package notify

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"log/slog"
	"net/netip"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/server/internal/addrpolicy"
	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/mailer"
	"github.com/paulmataruso/easyrmm/server/internal/secrets"
)

// Channel kinds this slice sends. Slack and Teams come with slice 5.
const (
	KindEmail   = "email"
	KindWebhook = "webhook"
)

// Delivery kinds, and statuses.
const (
	DeliveryTest  = "test"
	DeliveryEvent = "event"

	StatusPending = "pending"
	StatusSent    = "sent"
	StatusFailed  = "failed"
	StatusDropped = "dropped"
)

// Notice kinds this slice raises.
const (
	NoticeChannelFailing  = "channel_failing"
	NoticeNotSent         = "messages_not_sent"
	NoticeQuotaReached    = "quota_reached"
	NoticeWaitingApproval = "channel_waiting_approval"
)

// Audit actions (ADR-0007, ADR-0053). None carries a URL or a secret.
const (
	ActionCreate          = "notification_channel.create"
	ActionUpdate          = "notification_channel.update"
	ActionDelete          = "notification_channel.delete"
	ActionTest            = "notification_channel.test"
	ActionReveal          = "notification_channel.reveal"
	ActionRotate          = "notification_channel.rotate_secret"
	ActionShare           = "notification_channel.share"
	ActionUnshare         = "notification_channel.unshare"
	ActionApprovalRequest = "notification_channel.approval_request"
	ActionApprove         = "notification_channel.approve"
	ActionWithdraw        = "notification_channel.approval_withdraw"
	ActionQuota           = "notification_quota.update"
)

// Limits (ADR-0053): the defaults of open questions 1 and 2.
const (
	MaxRecipients   = 20
	MaxNameLength   = 100
	TestInterval    = 30 * time.Second
	GiveUpAfter     = 24 * time.Hour
	TestAttempts    = 3
	FailingAfter    = 15 * time.Minute
	FailingMessages = 3
	OrderRelaxAfter = time.Hour
	RetryFirst      = time.Minute
	RetryMax        = time.Hour
	ResponseLimit   = 64 << 10

	// Retention of what ends (ADR-0053, "Retention").
	DeliveryRetention = 30 * 24 * time.Hour
	JournalRetention  = 7 * 24 * time.Hour
	NoticeRetention   = 90 * 24 * time.Hour
)

// Default quotas per organization; super administrators change them.
const (
	DefaultChannels        = 20
	DefaultRules           = 50
	DefaultTestsPerHour    = 20
	DefaultMessagesPerHour = 600
)

// Mailer sends the email deliveries: one message per recipient, through the
// mail server in force (mailserver.Service).
type Mailer interface {
	SendNotification(ctx context.Context, to []string, msg mailer.Message) ([]mailer.Outcome, error)
}

// Service keeps the channels and sends from the outbox.
type Service struct {
	db     *database.DB
	audit  *audit.Logger
	sealer *secrets.Sealer
	log    *slog.Logger
	env    *addrpolicy.Environment
	mail   Mailer

	// held reports that the server is held for an upgrade (ADR-0052).
	held func() bool
	now  func() time.Time
	// resolve looks a destination's name up: nil is the system resolver.
	resolve func(ctx context.Context, host string) ([]netip.Addr, error)
	wake    chan struct{}
	// testWait is how long Test waits for the outcome.
	testWait   time.Duration
	consoleURL string

	tmu        sync.Mutex
	transports map[uuid.UUID]*transport

	wg     sync.WaitGroup
	fmu    sync.Mutex
	flight flightState

	cmu     sync.Mutex
	circuit circuitState

	// ps is the planner's memory; floor is the earliest moment a device
	// counts as seen (monitoring's serving floor), so that a restart never
	// starts or ends the fleet-wide hold.
	ps    planState
	floor func(time.Time) time.Time
	// pmu serializes planning in this process; qstamp is the last time a
	// delivery was queued at, kept increasing so that deliveries keep the
	// order they were queued in even when the clock has not moved.
	pmu    sync.Mutex
	qstamp time.Time
}

// stamp is the time to queue a delivery at: now, or just after the last.
// Planning holds pmu.
func (s *Service) stamp() time.Time {
	t := s.now()
	if !t.After(s.qstamp) {
		t = s.qstamp.Add(time.Microsecond)
	}
	s.qstamp = t
	return t
}

// New builds the service. env is the address policy's view of the server;
// nil reads it once, and mail may be nil (email deliveries then wait).
func New(db *database.DB, auditLog *audit.Logger, sealer *secrets.Sealer, env *addrpolicy.Environment, mail Mailer, log *slog.Logger) *Service {
	if env == nil {
		env = addrpolicy.NewEnvironment(nil, nil)
	}
	if log == nil {
		log = slog.Default()
	}
	return &Service{db: db, audit: auditLog, sealer: sealer, env: env, mail: mail, log: log,
		held: func() bool { return false }, now: time.Now, wake: make(chan struct{}, 1), testWait: 35 * time.Second,
		transports: map[uuid.UUID]*transport{}, flight: newFlight(), floor: func(time.Time) time.Time { return time.Time{} }}
}

// SetSeenFloor gives the planner the moment before which the server's own
// start makes devices look silent (monitoring's seenFloor).
func (s *Service) SetSeenFloor(f func(time.Time) time.Time) { s.floor = f }

// SetHeld gives the sender the hold of ADR-0052: while it reports true,
// nothing is sent or planned.
func (s *Service) SetHeld(f func() bool) { s.held = f }

// SetConsoleURL gives the console's address, which webhook bodies carry.
func (s *Service) SetConsoleURL(u string) { s.consoleURL = u }

// Kick wakes the worker, after something was queued.
func (s *Service) Kick() {
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

// ownerScope is the scope an owner's rows are read in: platform scope for
// the platform's, otherwise that one organization.
func ownerScope(owner uuid.UUID) database.Scope {
	if owner == uuid.Nil {
		return database.System
	}
	return database.Scope{Orgs: []uuid.UUID{owner}}
}

// Advisory locks (ADR-0053): the two-key form, a constant for channels and a
// hash of the channel's ID, so that a collision only makes two channels wait.
const (
	lockChannelClass int32 = 0x4e4f5443 // "NOTC"
	// The one-key locks.
	lockWorker  int64 = 5309142807761
	lockPlanner int64 = 5309142807762
)

func lockChannel(ctx context.Context, tx pgx.Tx, id uuid.UUID) error {
	h := sha256.Sum256(id[:])
	_, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1, $2)`, lockChannelClass, int32(binary.BigEndian.Uint32(h[:4]))) //nolint:gosec // a hash, wrapped on purpose
	return err
}

func actorID(a audit.Actor) *uuid.UUID {
	if a.ID == uuid.Nil {
		return nil
	}
	id := a.ID
	return &id
}

// orgPtr is the organization a row belongs to: nil for the platform.
func orgPtr(owner uuid.UUID) *uuid.UUID {
	if owner == uuid.Nil {
		return nil
	}
	return &owner
}

// messageKey is the Message-ID's local part for one recipient of one
// delivery: the same on every attempt (ADR-0053, "At least once").
func messageKey(delivery uuid.UUID, recipient string) string {
	h := sha256.Sum256([]byte(delivery.String() + "\x00" + recipient))
	return hex.EncodeToString(h[:16])
}
