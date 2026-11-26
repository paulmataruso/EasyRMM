package keystore

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/server/internal/access"
	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/devscope"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
)

// Reading a recovery key (ADR-0081 sections 6 and 7). The plaintext exists in
// two places on the server's side: the slice Client.ReadEscrow returns, and
// the caller's response writer; both are zeroed by whoever holds them
// (Service.Read's caller, through ReadResult.Wipe). It never reaches the
// database, a log, an error or an audit detail.

// Audit actions of reads (ADR-0007). None carries a key.
const (
	ActionRead      = "recovery_key.read"
	ActionRequested = "recovery_key.read_requested"
	ActionApproved  = "recovery_key.read_approved"
	ActionDenied    = "recovery_key.read_denied"
	ActionSetting   = "keystore.two_person"
)

// ReadLimits are the server's own limits on reads (section 7); the
// keystore's, which hold when the server is skipped, are its own.
type ReadLimits struct {
	UserHour, UserDay int
	OrgHour, OrgDay   int
}

// DefaultReadLimits: per user 5 an hour and 20 a day, per organization 10 an
// hour and 40 a day.
var DefaultReadLimits = ReadLimits{UserHour: 5, UserDay: 20, OrgHour: 10, OrgDay: 40}

// Timings of the two-person rule (section 6).
const (
	// RequestWait is how long a request waits for an approver.
	RequestWait = 30 * time.Minute
	// ApprovalValid is how long an approval can be used.
	ApprovalValid = 10 * time.Minute
	// MinReason is the shortest reason a read takes.
	MinReason = 10
	maxReason = 500
	maxTicket = 64
)

// StepUpVerifier is httpapi.Sessions' VerifyStepUp (ADR-0055).
type StepUpVerifier interface {
	VerifyStepUp(ctx context.Context) error
}

// SetStepUp gives the service the step-up check. Without one every read and
// approval is refused.
func (s *Service) SetStepUp(v StepUpVerifier) { s.stepUp = v }

// SetClock sets the service's clock; tests use it to pass the reconciliation's
// grace period.
func (s *Service) SetClock(now func() time.Time) { s.now = now }

// SetReadLimits overrides the server's limits; tests use it.
func (s *Service) SetReadLimits(l ReadLimits) { s.limits = l }

// ReadInput is what a person gives to read a key.
type ReadInput struct {
	Volume, Protector string
	// Reason is the free text kept in the audit record: at least ten
	// characters, and never a key.
	Reason string
	Ticket string
	// RequestID names an approved two-person request to use.
	RequestID uuid.UUID
}

// KeyRequest is a two-person request, as the console shows it.
type KeyRequest struct {
	ID        uuid.UUID  `json:"id"`
	DeviceID  uuid.UUID  `json:"deviceId"`
	Device    string     `json:"device"`
	Volume    string     `json:"volume"`
	Protector string     `json:"protector"`
	Requester string     `json:"requester"`
	Reason    string     `json:"reason"`
	Ticket    string     `json:"ticket,omitempty"`
	State     string     `json:"state"`
	Approver  string     `json:"approver,omitempty"`
	CreatedAt time.Time  `json:"createdAt"`
	ExpiresAt time.Time  `json:"expiresAt"`
	DecidedAt *time.Time `json:"decidedAt,omitempty"`
	// Mine: the caller made it. CanDecide: the caller may approve or deny it.
	Mine      bool `json:"mine"`
	CanDecide bool `json:"canDecide"`
}

// ReadResult is the outcome of a read: the key, or the request that now waits
// for a second person. Wipe it when done with the key.
type ReadResult struct {
	Key     []byte
	Pending *KeyRequest
}

// Wipe zeroes the key.
func (r *ReadResult) Wipe() {
	if r != nil {
		clear(r.Key)
	}
}

// keyShaped finds a BitLocker recovery password, or a run of letters as long as
// a LUKS passphrase, typed where it must not go (a reason or a ticket reference).
var keyShaped = regexp.MustCompile(`\d{6}\W{0,3}\d{6}\W{0,3}\d{6}|[a-z2-7]{32,}`)

// escrowRef is the verified record a read opens, with what the keystore needs.
type escrowRef struct {
	id                uuid.UUID
	org, site, device uuid.UUID
	hostname          string
	volume, protector string
	orgKey            uuid.UUID
	wrapped           string
	enc, ct, finger   []byte
	kind              string
}

// refuse writes the audit record of a read that did not happen, in its own
// transaction, and returns err.
func (s *Service) refuse(ctx context.Context, c access.Caller, org, site, dev uuid.UUID, in ReadInput, code string, err error) error {
	d := map[string]any{"code": code, "volume": in.Volume, "protector": in.Protector}
	if r := strings.TrimSpace(in.Reason); utf8.RuneCountInString(r) <= maxReason && !keyShaped.MatchString(r) {
		d["reason"] = r
	}
	werr := s.audit.Record(context.WithoutCancel(ctx), audit.Event{
		Actor: c.Actor, Action: ActionRead, Outcome: audit.Denied, OrganizationID: org, SiteID: site, DeviceID: dev,
		TargetType: "device", TargetID: dev.String(), Details: d,
	})
	s.warn("auditing a refused read", werr)
	return err
}

// Read releases one recovery key to the person who holds the permission, after
// step-up, with a reason, within the limits and, where the organization asks
// for two people, after a second person's approval. The audit record is written
// in the transaction that calls the keystore and is committed before the key
// is returned; a failed commit discards the key.
func (s *Service) Read(ctx context.Context, c access.Caller, deviceID uuid.UUID, in ReadInput) (*ReadResult, error) {
	if c.IsSystem() || c.Principal == nil {
		return nil, apperr.Forbidden()
	}
	var org, site uuid.UUID
	var hostname string
	err := s.db.ReadTx(ctx, c.Scope, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT organization_id, site_id, hostname FROM devices WHERE id = $1`, deviceID).Scan(&org, &site, &hostname)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, apperr.NotFound()
	}
	if err != nil {
		return nil, err
	}
	if !c.Can(rbac.PermDeviceView, rbac.Site(org, site)) {
		return nil, apperr.NotFound()
	}
	if !c.Can(rbac.PermRecoveryKeyRead, rbac.Site(org, site)) {
		return nil, s.refuse(ctx, c, org, site, deviceID, in, "no_permission", apperr.Forbidden())
	}
	// A human's explicit act is not gated by the dev scope, but nothing is
	// released for an organization outside it.
	if !devscope.Allowed(org) {
		return nil, s.refuse(ctx, c, org, site, deviceID, in, "out_of_scope",
			apperr.Conflict("escrow_off", "Recovery-key escrow is off for this organization."))
	}
	if s.stepUp == nil {
		return nil, s.refuse(ctx, c, org, site, deviceID, in, "no_step_up", apperr.Forbidden())
	}
	if err := s.stepUp.VerifyStepUp(ctx); err != nil {
		return nil, s.refuse(ctx, c, org, site, deviceID, in, "step_up_required", err)
	}
	in.Reason, in.Ticket = strings.TrimSpace(in.Reason), strings.TrimSpace(in.Ticket)
	two, err := s.twoPerson(ctx, org)
	if err != nil {
		return nil, err
	}
	// With an approved request, its reason is the one on record.
	if !two || in.RequestID == uuid.Nil {
		if fe := checkReason(in); fe != nil {
			return nil, s.refuse(ctx, c, org, site, deviceID, in, "bad_reason", fe)
		}
	}
	if s.ks == nil {
		return nil, apperr.Unavailable("keystore_unavailable", "The keystore cannot be reached.")
	}
	if err := s.ready(ctx); err != nil {
		return nil, s.refuse(ctx, c, org, site, deviceID, in, "keystore_not_ready", unavailableErr(err))
	}
	e, err := s.findEscrow(ctx, org, deviceID, in.Volume, in.Protector)
	if err != nil {
		return nil, err
	}
	if e == nil {
		return nil, s.refuse(ctx, c, org, site, deviceID, in, "no_verified_key",
			apperr.Conflict("no_verified_key", "There is no verified recovery key for that protector."))
	}
	e.org, e.site, e.device, e.hostname = org, site, deviceID, hostname
	user := c.Principal.UserID
	if lerr := s.overLimit(ctx, user, org); lerr != nil {
		s.limitAlert(ctx, org, "The server's limit on reads was reached in this organization.", "limit-hit")
		return nil, s.refuse(ctx, c, org, site, deviceID, in, "limit", lerr)
	}
	var approver string
	if two {
		if in.RequestID == uuid.Nil {
			req, err := s.openRequest(ctx, c, e, in)
			if err != nil {
				return nil, err
			}
			return &ReadResult{Pending: req}, nil
		}
		reason, ticket, who, err := s.checkApproved(ctx, in.RequestID, user, e)
		if err != nil {
			return nil, s.refuse(ctx, c, org, site, deviceID, in, "approval", err)
		}
		in.Reason, in.Ticket, approver = reason, ticket, who
	}
	return s.release(ctx, c, e, in, approver)
}

func checkReason(in ReadInput) error {
	switch {
	case utf8.RuneCountInString(in.Reason) < MinReason:
		return apperr.Invalid("reason", "Say why you need the key, in at least 10 characters.")
	case utf8.RuneCountInString(in.Reason) > maxReason:
		return apperr.Invalid("reason", "Keep the reason under 500 characters.")
	case keyShaped.MatchString(in.Reason):
		return apperr.Invalid("reason", "Do not type a recovery key into the reason.")
	case utf8.RuneCountInString(in.Ticket) > maxTicket:
		return apperr.Invalid("ticket", "The ticket reference is too long.")
	case keyShaped.MatchString(in.Ticket):
		return apperr.Invalid("ticket", "Do not type a recovery key into the ticket reference.")
	}
	return nil
}

func unavailableErr(err error) error {
	if errors.Is(err, ErrUnavailable) {
		return apperr.Unavailable("keystore_unavailable", "The keystore cannot be reached.")
	}
	return apperr.Unavailable("keystore_not_ready", "The keystore is not ready: it is sealed, or its recovery has not been verified.")
}

// findEscrow loads the verified record of a protector with the organization
// key that wraps it. nil when there is none.
func (s *Service) findEscrow(ctx context.Context, org, device uuid.UUID, volume, protector string) (*escrowRef, error) {
	var e escrowRef
	err := s.db.ReadTx(ctx, database.System, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT r.id, r.org_key_id, k.wrapped_private, r.enc, r.ciphertext, r.fingerprint, r.volume_id, r.protector_id, r.kind
			FROM recovery_key_escrows r JOIN keystore_org_keys k ON k.id = r.org_key_id
			WHERE r.organization_id = $1 AND r.device_id = $2 AND r.volume_id = $3 AND r.protector_id = $4 AND r.state = 'verified'`,
			org, device, volume, protector).Scan(&e.id, &e.orgKey, &e.wrapped, &e.enc, &e.ct, &e.finger, &e.volume, &e.protector, &e.kind)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &e, nil
}

// overLimit counts the reads that succeeded in the audit log, per user and per
// organization, against the server's limits.
func (s *Service) overLimit(ctx context.Context, user, org uuid.UUID) error {
	now := s.now()
	var uh, ud, oh, od int
	err := s.db.ReadTx(ctx, database.System, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT
			count(*) FILTER (WHERE actor_id = $1 AND occurred_at > $3),
			count(*) FILTER (WHERE actor_id = $1),
			count(*) FILTER (WHERE organization_id = $2 AND occurred_at > $3),
			count(*) FILTER (WHERE organization_id = $2)
			FROM audit_log WHERE action = $5 AND outcome = 'success' AND occurred_at > $4`,
			user, org, now.Add(-time.Hour), now.Add(-24*time.Hour), ActionRead).Scan(&uh, &ud, &oh, &od)
	})
	if err != nil {
		return err
	}
	l := s.limits
	if uh*2 >= l.UserHour || oh*2 >= l.OrgHour || ud*2 >= l.UserDay || od*2 >= l.OrgDay {
		s.limitAlert(ctx, org, "Reads in this organization reached half of a limit.", "half")
	}
	switch {
	case uh >= l.UserHour || oh >= l.OrgHour:
		return apperr.TooMany("read_limit", "Too many recovery keys were read in the last hour. Try again later.", time.Hour)
	case ud >= l.UserDay || od >= l.OrgDay:
		return apperr.TooMany("read_limit", "Too many recovery keys were read today. Try again tomorrow.", 6*time.Hour)
	}
	return nil
}

// twoPerson says whether the organization asks for two people.
func (s *Service) twoPerson(ctx context.Context, org uuid.UUID) (bool, error) {
	on := false
	err := s.db.ReadTx(ctx, database.System, func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx, `SELECT two_person FROM keystore_org_settings WHERE organization_id = $1`, org).Scan(&on)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		return err
	})
	return on, err
}

// release is the audited read: audit row, keystore call and the notice in one
// transaction, committed before the key goes back. A refusal or failure after
// the keystore was asked is audited with the request ID the keystore's log
// holds, so that the hourly reconciliation can account for it.
func (s *Service) release(ctx context.Context, c access.Caller, e *escrowRef, in ReadInput, approver string) (*ReadResult, error) {
	rid := uuid.New().String()
	var key []byte
	asked := false
	err := s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		if in.RequestID != uuid.Nil {
			tag, err := tx.Exec(ctx, `UPDATE recovery_key_requests SET state = 'used', used_at = now()
				WHERE id = $1 AND state = 'approved' AND requested_by = $2 AND decided_at > $3`, in.RequestID, c.Principal.UserID, s.now().Add(-ApprovalValid))
			if err != nil {
				return err
			}
			if tag.RowsAffected() != 1 {
				return apperr.Conflict("approval_used", "That approval was already used or has expired.")
			}
		}
		d := map[string]any{
			"requestId": rid, "escrowId": e.id.String(), "volume": e.volume, "protector": e.protector,
			"reason": in.Reason, "ticket": in.Ticket,
		}
		if approver != "" {
			d["approver"] = approver
			d["approvalRequest"] = in.RequestID.String()
		}
		if err := s.audit.Write(ctx, tx, audit.Event{
			Actor: c.Actor, Action: ActionRead, Outcome: audit.Success, OrganizationID: e.org, SiteID: e.site, DeviceID: e.device,
			TargetType: "device", TargetID: e.device.String(), Details: d,
		}); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO keystore_notices (organization_id, site_id, device_id, device_name, actor_id, actor_label, approver_label, reason)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`, e.org, e.site, e.device, e.hostname, c.Principal.UserID, c.Actor.Label, approver, in.Reason); err != nil {
			return err
		}
		asked = true
		var kerr error
		key, kerr = s.ks.ReadEscrow(ctx, rid, e.id.String(), e.wrapped, EscrowContext{
			Org: e.org.String(), Device: e.device.String(), Volume: e.volume, Protector: e.protector, OrgKey: e.orgKey.String(), Kind: e.kind,
		}, e.enc, e.ct, e.finger)
		return kerr
	})
	if err != nil {
		clear(key) // a failed commit discards the key
		code, out := mapReadError(err)
		if code == CodeLimit {
			s.limitAlert(ctx, e.org, "The keystore's own limit on reads was reached.", "keystore-limit")
		}
		if asked {
			// The keystore may have logged a key leaving: the record that
			// accounts for it carries the same request ID.
			werr := s.audit.Record(context.WithoutCancel(ctx), audit.Event{
				Actor: c.Actor, Action: ActionRead, Outcome: audit.Failure, OrganizationID: e.org, SiteID: e.site, DeviceID: e.device,
				TargetType: "device", TargetID: e.device.String(),
				Details: map[string]any{"requestId": rid, "escrowId": e.id.String(), "volume": e.volume, "protector": e.protector, "code": code},
			})
			s.warn("auditing a failed read", werr)
		}
		return nil, out
	}
	go s.notifyRead(context.WithoutCancel(ctx), e, c.Actor.Label, approver, in.Reason)
	return &ReadResult{Key: key}, nil
}

// limitAlert raises the warning that reads reached half of a limit or hit one.
func (s *Service) limitAlert(ctx context.Context, org uuid.UUID, detail, which string) {
	_, err := s.raiseAlert(context.WithoutCancel(ctx), &org, AlertReadLimit, "warning", org.String()+"/"+which, detail)
	s.warn("raising a read-limit alert", err)
}

func mapReadError(err error) (string, error) {
	var re *RemoteError
	if errors.As(err, &re) {
		switch re.Code {
		case CodeLimit:
			return re.Code, apperr.TooMany("keystore_limit", "The keystore's own limit on reads was reached. Try again later.", time.Hour)
		case CodeSealed, CodeNotVerified, CodeUninitialised, CodeVersionLost, CodeTPMPolicy, CodeLogBroken:
			return re.Code, apperr.Unavailable("keystore_not_ready", "The keystore is not ready: it is sealed, or its recovery has not been verified.")
		case CodeRefused:
			return re.Code, apperr.Conflict("record_not_verified", "The keystore could not confirm that key. It is checked again soon.")
		}
		return re.Code, apperr.Unavailable("keystore_failed", "The keystore could not return that key.")
	}
	var ae *apperr.Error
	if errors.As(err, &ae) {
		return ae.Code, err
	}
	if errors.Is(err, ErrUnavailable) {
		return "unavailable", apperr.Unavailable("keystore_unavailable", "The keystore cannot be reached.")
	}
	return "internal", err
}
