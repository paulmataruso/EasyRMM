// Package audit records security-relevant events in the tamper-evident audit
// log. Records are appended through the easyrmm_audit_append database
// function, which links each record to the previous one with SHA-256; the
// runtime database role cannot insert, update or delete audit rows directly.
package audit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/server/internal/database"
)

// ActorType identifies who performed an action.
type ActorType string

const (
	ActorUser   ActorType = "user"
	ActorAgent  ActorType = "agent"
	ActorSystem ActorType = "system"
)

// Outcome is the result of the audited action.
type Outcome string

const (
	Success Outcome = "success"
	Failure Outcome = "failure"
	Denied  Outcome = "denied"
)

// Actor describes the party responsible for an event.
type Actor struct {
	Type      ActorType
	ID        uuid.UUID
	Label     string // e-mail, hostname or component name, kept even if the actor is later deleted
	SourceIP  netip.Addr
	UserAgent string
}

// SystemActor is used for events the platform performs on its own.
func SystemActor(component string) Actor {
	return Actor{Type: ActorSystem, Label: component}
}

// Event is one audit record.
type Event struct {
	Actor          Actor
	Action         string // dotted, e.g. "auth.login", "organization.create"
	OrganizationID uuid.UUID
	SiteID         uuid.UUID
	DeviceID       uuid.UUID
	TargetType     string
	TargetID       string
	Outcome        Outcome
	Details        map[string]any
}

var actionPattern = regexp.MustCompile(`^[a-z][a-z0-9_]*(\.[a-z0-9_]+)+$`)

const (
	maxLabel     = 320
	maxUserAgent = 512
	maxDetails   = 16 * 1024
)

// ErrInvalidEvent reports an event that cannot be recorded.
var ErrInvalidEvent = errors.New("audit: invalid event")

func (e Event) validate() error {
	if !actionPattern.MatchString(e.Action) {
		return fmt.Errorf("%w: action %q", ErrInvalidEvent, e.Action)
	}
	switch e.Actor.Type {
	case ActorUser, ActorAgent, ActorSystem:
	default:
		return fmt.Errorf("%w: actor type %q", ErrInvalidEvent, e.Actor.Type)
	}
	switch e.Outcome {
	case Success, Failure, Denied:
	default:
		return fmt.Errorf("%w: outcome %q", ErrInvalidEvent, e.Outcome)
	}
	return nil
}

// Clock returns the current time; replaced in tests.
type Clock func() time.Time

// Logger writes audit records.
type Logger struct {
	db  *database.DB
	now Clock
}

// New returns a Logger.
func New(db *database.DB, now Clock) *Logger {
	if now == nil {
		now = time.Now
	}
	return &Logger{db: db, now: now}
}

// Write appends an event inside an existing transaction, so the record
// commits or rolls back together with the change it describes.
func (l *Logger) Write(ctx context.Context, tx pgx.Tx, e Event) error {
	if err := e.validate(); err != nil {
		return err
	}
	details := e.Details
	if details == nil {
		details = map[string]any{}
	}
	raw, err := json.Marshal(details)
	if err != nil {
		return fmt.Errorf("audit: encoding details: %w", err)
	}
	if len(raw) > maxDetails {
		raw, _ = json.Marshal(map[string]any{"truncated": true, "size": len(raw)})
	}
	st := l.Stamp(e.Actor)
	_, err = tx.Exec(ctx, `SELECT easyrmm_audit_append($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12::inet, $13, $14::jsonb)`,
		st.At, st.ActorType, st.ActorID, st.ActorLabel,
		nullUUID(e.OrganizationID), nullUUID(e.SiteID), nullUUID(e.DeviceID),
		e.Action, truncate(e.TargetType, 64), truncate(e.TargetID, 128), string(e.Outcome),
		st.SourceIP, st.UserAgent, string(raw))
	if err != nil {
		return fmt.Errorf("audit: appending %s: %w", e.Action, err)
	}
	return nil
}

// Stamp is who acts and when, as a record stores them. A database function
// that appends its own record, so that a read and its record cannot be
// separated (ADR-0063), takes these values.
type Stamp struct {
	At         time.Time
	ActorType  string
	ActorID    *uuid.UUID
	ActorLabel string
	SourceIP   *string
	UserAgent  string
}

// Stamp returns the actor and the current time as Write records them.
func (l *Logger) Stamp(a Actor) Stamp {
	var ip *string
	if a.SourceIP.IsValid() {
		s := a.SourceIP.Unmap().String()
		ip = &s
	}
	return Stamp{
		// PostgreSQL stores microseconds; truncate so the hashed value
		// matches what is read back.
		At:        l.now().UTC().Truncate(time.Microsecond),
		ActorType: string(a.Type), ActorID: nullUUID(a.ID), ActorLabel: truncate(a.Label, maxLabel),
		SourceIP: ip, UserAgent: truncate(a.UserAgent, maxUserAgent),
	}
}

// Record appends an event in its own transaction. Use it for events that are
// not tied to a data change, such as failed logins.
func (l *Logger) Record(ctx context.Context, e Event) error {
	// Audit writes must not be lost because the triggering request was
	// canceled (for example a client disconnecting after a failed login).
	ctx = context.WithoutCancel(ctx)
	return l.db.InTx(ctx, database.System, func(tx pgx.Tx) error { return l.Write(ctx, tx, e) })
}

// Entry is a stored audit record.
type Entry struct {
	ID             int64          `json:"id"`
	OccurredAt     time.Time      `json:"occurredAt"`
	ActorType      ActorType      `json:"actorType"`
	ActorID        *uuid.UUID     `json:"actorId,omitempty"`
	ActorLabel     string         `json:"actorLabel"`
	OrganizationID *uuid.UUID     `json:"organizationId,omitempty"`
	SiteID         *uuid.UUID     `json:"siteId,omitempty"`
	DeviceID       *uuid.UUID     `json:"deviceId,omitempty"`
	Action         string         `json:"action"`
	TargetType     string         `json:"targetType"`
	TargetID       string         `json:"targetId"`
	Outcome        Outcome        `json:"outcome"`
	SourceIP       *netip.Addr    `json:"sourceIp,omitempty"`
	UserAgent      string         `json:"userAgent"`
	Details        map[string]any `json:"details"`
}

// Query filters audit records. Zero values mean "any".
type Query struct {
	OrganizationID uuid.UUID
	ActorID        uuid.UUID
	DeviceID       uuid.UUID
	ActionPrefix   string
	Before         int64 // return records with id < Before (keyset pagination)
	Limit          int
}

// List returns records visible within scope, newest first.
func (l *Logger) List(ctx context.Context, scope database.Scope, q Query) ([]Entry, error) {
	if q.Limit <= 0 || q.Limit > 500 {
		q.Limit = 100
	}
	var out []Entry
	err := l.db.ReadTx(ctx, scope, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT id, occurred_at, actor_type, actor_id, actor_label, organization_id, site_id, device_id,
			       action, target_type, target_id, outcome, source_ip, user_agent, details
			FROM audit_log
			WHERE ($1::uuid IS NULL OR organization_id = $1)
			  AND ($2::uuid IS NULL OR actor_id = $2)
			  AND ($3::uuid IS NULL OR device_id = $3)
			  AND ($4 = '' OR action = $4 OR left(action, length($4) + 1) = $4 || '.')
			  AND ($5 = 0 OR id < $5)
			ORDER BY id DESC
			LIMIT $6`,
			nullUUID(q.OrganizationID), nullUUID(q.ActorID), nullUUID(q.DeviceID), q.ActionPrefix, q.Before, q.Limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var e Entry
			var actorType, outcome string
			var details []byte
			if err := rows.Scan(&e.ID, &e.OccurredAt, &actorType, &e.ActorID, &e.ActorLabel, &e.OrganizationID,
				&e.SiteID, &e.DeviceID, &e.Action, &e.TargetType, &e.TargetID, &outcome, &e.SourceIP,
				&e.UserAgent, &details); err != nil {
				return err
			}
			e.ActorType, e.Outcome = ActorType(actorType), Outcome(outcome)
			if err := json.Unmarshal(details, &e.Details); err != nil {
				return err
			}
			out = append(out, e)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("audit: listing: %w", err)
	}
	return out, nil
}

// VerifyResult reports the outcome of a chain verification.
type VerifyResult struct {
	Checked    int64  `json:"checked"`
	FirstBadID *int64 `json:"firstBadId,omitempty"`
}

// Verify recomputes the hash chain for up to maxRows records after afterID.
func (l *Logger) Verify(ctx context.Context, afterID int64, maxRows int) (VerifyResult, error) {
	var r VerifyResult
	err := l.db.ReadTx(ctx, database.System, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT checked, first_bad_id FROM easyrmm_audit_verify($1, $2)`, afterID, maxRows).
			Scan(&r.Checked, &r.FirstBadID)
	})
	if err != nil {
		return VerifyResult{}, fmt.Errorf("audit: verifying: %w", err)
	}
	return r, nil
}

func nullUUID(id uuid.UUID) *uuid.UUID {
	if id == uuid.Nil {
		return nil
	}
	return &id
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	// Cut on a rune boundary.
	for n > 0 && !utf8RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

func utf8RuneStart(b byte) bool { return b&0xC0 != 0x80 }
