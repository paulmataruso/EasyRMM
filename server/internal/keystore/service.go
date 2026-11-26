package keystore

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/devscope"
)

// Audit actions (ADR-0007, ADR-0081 section 6). None carries a key.
const (
	ActionOrgKeyCreated = "keystore.org_key_created"
	ActionEscrowed      = "recovery_key.escrowed"
	ActionVerified      = "recovery_key.verified"
	ActionStale         = "recovery_key.stale"
	ActionConflict      = "recovery_key.conflict"
)

// Limits on uploads (ADR-0081 section 5): one per volume per five minutes and
// twenty per device per hour.
const (
	VolumeEvery   = 5 * time.Minute
	DeviceHourMax = 20
)

// statusTTL is how long the server trusts the keystore's last status.
const statusTTL = 20 * time.Second

// Device is the device an agent's request came from.
type Device struct {
	ID, Org, Site uuid.UUID
	Hostname      string
}

// Verifier is what the service asks of the keystore: the socket client, or
// in tests a real keystore process over a real socket.
type Verifier interface {
	Status(ctx context.Context) (Status, error)
	CreateOrgKey(ctx context.Context, org, keyID, purpose string) (MadeKey, error)
	VerifyEscrow(ctx context.Context, requestID, wrappedPrivate string, ec EscrowContext, enc, ct, fingerprint []byte) (string, error)
	ReadEscrow(ctx context.Context, requestID, record, wrappedPrivate string, ec EscrowContext, enc, ct, fingerprint []byte) ([]byte, error)
	Log(ctx context.Context, seq int64, limit int) (LogPage, error)
}

var _ Verifier = (*Client)(nil)

// Service stores the escrow and runs the checks. It holds no key: the
// keystore process does every wrap and check.
type Service struct {
	db    *database.DB
	audit *audit.Logger
	ks    Verifier
	// signKey is the job key (ADR-0057) that signs the escrow-key
	// instruction.
	signKey ed25519.PrivateKey
	log     *slog.Logger
	now     func() time.Time

	stepUp   StepUpVerifier
	notifier Notifier
	limits   ReadLimits

	mu       sync.Mutex
	status   Status
	statusAt time.Time
	// down counts failed status checks in a row; sealedAt is when the monitor
	// first saw the keystore sealed.
	down     int
	sealedAt time.Time
	keys     map[uuid.UUID]cachedKey
}

type cachedKey struct {
	id      uuid.UUID
	version int
	pub     []byte
	until   time.Time
}

// New builds a Service. ks may be nil when no keystore is configured; the
// service then reports it unavailable and starts nothing.
func New(db *database.DB, auditLog *audit.Logger, ks Verifier, signKey ed25519.PrivateKey, log *slog.Logger) *Service {
	return &Service{db: db, audit: auditLog, ks: ks, signKey: signKey, log: log, now: time.Now, keys: map[uuid.UUID]cachedKey{}, limits: DefaultReadLimits}
}

// Errors the service reports.
var (
	// ErrNotReady: the keystore is up but cannot wrap (uninitialised, sealed,
	// recovery not verified).
	ErrNotReady = errors.New("keystore: not ready")
)

func (s *Service) warn(what string, err error) {
	if err != nil {
		s.log.Warn("keystore: "+what+" failed", "error", err)
	}
}

// CurrentStatus is the keystore's status as of a few seconds ago, with its
// KEK versions' metadata mirrored into PostgreSQL. A keystore that cannot be
// reached is StateUnavailable, never an error.
func (s *Service) CurrentStatus(ctx context.Context) Status {
	s.mu.Lock()
	if s.statusAt.Add(statusTTL).After(s.now()) {
		st := s.status
		s.mu.Unlock()
		return st
	}
	s.mu.Unlock()
	return s.RefreshStatus(ctx)
}

// RefreshStatus asks the keystore now.
func (s *Service) RefreshStatus(ctx context.Context) Status {
	st := Status{State: StateUnavailable, Versions: []KEKVersion{}}
	if s.ks != nil {
		cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		got, err := s.ks.Status(cctx)
		cancel()
		if err == nil {
			st = got
			s.mirrorVersions(ctx, got)
		} else {
			s.log.Warn("keystore: not reachable", "error", err)
		}
	}
	s.mu.Lock()
	s.status, s.statusAt = st, s.now()
	s.mu.Unlock()
	return st
}

func (s *Service) mirrorVersions(ctx context.Context, st Status) {
	if len(st.Versions) == 0 {
		return
	}
	err := s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		for _, v := range st.Versions {
			cv, err := hexBytes(v.CheckValue)
			if err != nil {
				continue
			}
			if _, err := tx.Exec(ctx, `INSERT INTO keystore_kek_versions (version, check_value, mode, state, created_at, recovery_verified_at, seen_at)
				VALUES ($1, $2, $3, $4, $5, $6, now())
				ON CONFLICT (version) DO UPDATE SET state = EXCLUDED.state, recovery_verified_at = EXCLUDED.recovery_verified_at, seen_at = now()`,
				v.Version, cv, v.Mode, v.State, v.CreatedAt, v.RecoveryVerifiedAt); err != nil {
				return err
			}
		}
		return nil
	})
	s.warn("recording the KEK versions", err)
}

func hexBytes(s string) ([]byte, error) {
	if len(s) != 32 {
		return nil, errors.New("not a check value")
	}
	b := make([]byte, 16)
	for i := range b {
		var v byte
		for j := range 2 {
			c := s[i*2+j]
			switch {
			case c >= '0' && c <= '9':
				c -= '0'
			case c >= 'a' && c <= 'f':
				c = c - 'a' + 10
			default:
				return nil, errors.New("not hex")
			}
			v = v<<4 | c
		}
		b[i] = v
	}
	return b, nil
}

// ready says whether the keystore can wrap and check now.
func (s *Service) ready(ctx context.Context) error {
	st := s.CurrentStatus(ctx)
	switch {
	case st.State == StateUnavailable:
		return ErrUnavailable
	case st.State != StateUnsealed || !st.RecoveryVerified:
		return fmt.Errorf("%w: %s", ErrNotReady, st.State)
	}
	return nil
}

// EscrowKey is an organization's active escrow key as agents and checks use it.
type EscrowKey struct {
	ID      uuid.UUID
	Version int
	Public  []byte
	Wrapped string
}

// activeKey reads an organization's active escrow key, nil when none.
func (s *Service) activeKey(ctx context.Context, tx pgx.Tx, org uuid.UUID) (*EscrowKey, error) {
	var k EscrowKey
	err := tx.QueryRow(ctx, `SELECT id, version, public_key, wrapped_private FROM keystore_org_keys
		WHERE organization_id = $1 AND purpose = 'escrow' AND state = 'active'`, org).Scan(&k.ID, &k.Version, &k.Public, &k.Wrapped)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return &k, err
}

// EnsureEscrowKey returns the organization's active escrow key, making it on
// the first escrow. It is an automatic behavior, so the dev-scope guard
// answers first: an organization outside it gets no key.
func (s *Service) EnsureEscrowKey(ctx context.Context, org uuid.UUID) (*EscrowKey, error) {
	if !devscope.Allowed(org) {
		return nil, nil
	}
	var key *EscrowKey
	if err := s.db.ReadTx(ctx, database.System, func(tx pgx.Tx) (err error) {
		key, err = s.activeKey(ctx, tx, org)
		return err
	}); err != nil {
		return nil, err
	}
	if key != nil {
		return key, nil
	}
	if s.ks == nil {
		return nil, ErrUnavailable
	}
	if err := s.ready(ctx); err != nil {
		return nil, err
	}
	id := uuid.New()
	made, err := s.ks.CreateOrgKey(ctx, org.String(), id.String(), "escrow")
	if err != nil {
		var re *RemoteError
		if errors.As(err, &re) {
			s.mu.Lock()
			s.statusAt = time.Time{} // look again next time
			s.mu.Unlock()
			return nil, fmt.Errorf("%w: %s", ErrNotReady, re.Code)
		}
		return nil, fmt.Errorf("%w: %w", ErrUnavailable, err)
	}
	err = s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		cur, err := s.activeKey(ctx, tx, org)
		if err != nil || cur != nil {
			key = cur // a concurrent request made one first; the wrapped copy is dropped
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO keystore_org_keys (id, organization_id, purpose, version, public_key, wrapped_private, kek_version)
			VALUES ($1, $2, 'escrow', 1, $3, $4, $5)`, id, org, made.PublicKey, made.WrappedPrivate, made.KEKVersion); err != nil {
			return err
		}
		key = &EscrowKey{ID: id, Version: 1, Public: made.PublicKey, Wrapped: made.WrappedPrivate}
		return s.audit.Write(ctx, tx, audit.Event{
			Actor: audit.SystemActor("keystore"), Action: ActionOrgKeyCreated, Outcome: audit.Success,
			OrganizationID: org, TargetType: "organization", TargetID: org.String(),
			Details: map[string]any{"keyId": id.String(), "kekVersion": made.KEKVersion},
		})
	})
	return key, err
}

// Instruction is the signed escrow key an agent gets in its heartbeat answer
// (ADR-0081 section 5): for a Windows or Linux device whose agent announced the
// capability, in an organization the dev-scope guard allows, once the
// keystore can wrap. It is nil in every other case and never an error: the
// heartbeat does not depend on the keystore.
func (s *Service) Instruction(ctx context.Context, d Device, platform string, caps []string) *agentproto.SignedEscrowKey {
	if (platform != "windows" && platform != "linux") || !hasCap(caps) || !devscope.Allowed(d.Org) || s.ks == nil || len(s.signKey) == 0 {
		return nil
	}
	key := s.cachedKey(d.Org)
	if key == nil {
		k, err := s.EnsureEscrowKey(ctx, d.Org)
		if err != nil || k == nil {
			if err != nil && !errors.Is(err, ErrNotReady) && !errors.Is(err, ErrUnavailable) {
				s.log.Warn("keystore: getting the organization's escrow key failed", "error", err, "organization_id", d.Org)
			}
			return nil
		}
		key = &cachedKey{id: k.ID, version: k.Version, pub: k.Public, until: s.now().Add(time.Minute)}
		s.mu.Lock()
		s.keys[d.Org] = *key
		s.mu.Unlock()
	}
	now := s.now().UTC()
	signed, err := agentproto.SignEscrowKey(s.signKey, agentproto.EscrowKeyPayload{
		V: agentproto.EscrowKeyPayloadVersion, DeviceID: d.ID.String(), OrgID: d.Org.String(),
		KeyID: key.id.String(), KeyVersion: key.version, PublicKey: base64.StdEncoding.EncodeToString(key.pub),
		IssuedAt: now, ExpiresAt: now.Add(agentproto.EscrowKeyValid),
	})
	if err != nil {
		s.log.Error("keystore: signing the escrow key failed", "error", err)
		return nil
	}
	return &signed
}

func hasCap(caps []string) bool {
	for _, c := range caps {
		if c == agentproto.CapEscrow {
			return true
		}
	}
	return false
}

func (s *Service) cachedKey(org uuid.UUID) *cachedKey {
	s.mu.Lock()
	defer s.mu.Unlock()
	if k, ok := s.keys[org]; ok && s.now().Before(k.until) {
		return &k
	}
	return nil
}

// actor is the agent that made a request.
func actor(d Device, ip netip.Addr) audit.Actor {
	return audit.Actor{Type: audit.ActorAgent, ID: d.ID, Label: d.Hostname, SourceIP: ip}
}
