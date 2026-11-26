// Package agents enrolls EasyRMM agents with deployment tokens and serves
// their signed requests: heartbeats and the MeshAgent install (ADR-0015).
package agents

import (
	"context"
	"crypto/ed25519"
	"errors"
	"log/slog"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/auth"
	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/meshcentral"
	"github.com/paulmataruso/easyrmm/server/internal/secrets"
)

// HeartbeatInterval is how often agents report.
const HeartbeatInterval = 60 * time.Second

// MeshAgents is the remote-access side of enrollment: where a site's
// MeshAgent comes from. It is nil when remote access is disabled.
type MeshAgents interface {
	// Group returns the MeshCentral device group of a site, or "" when the
	// site has none yet.
	Group(ctx context.Context, siteID uuid.UUID) (string, error)
	// Binary opens the MeshAgent for a MeshCentral architecture number.
	Binary(ctx context.Context, arch int) (*meshcentral.Download, error)
	// Settings returns the settings that join a device group.
	Settings(ctx context.Context, meshID string) ([]byte, error)
	// Linked is told when a device's MeshAgent link changes, so devices
	// are refreshed from MeshCentral soon.
	Linked()
}

// Service enrolls agents and serves their requests.
type Service struct {
	db    *database.DB
	audit *audit.Logger
	mesh  MeshAgents
	// meshHosts: each site's MeshCentral host, as the settings it gets name it.
	meshHosts meshHosts
	log       *slog.Logger
	now       func() time.Time
	// enroll limits new devices per address, lookups every enrollment
	// request per address, polls a waiting device's requests per key.
	enroll, lookups, polls *auth.KeyedLimiter
	waits                  *waitHub
	approvalWait           time.Duration
	jobKey                 string
	// Agent updates (ADR-0027); nil without builds. updateKey is the job
	// key, which also signs uninstall instructions (ADR-0050).
	builds *Builds
	// stable is what organizations outside the dev scope are offered
	// (SetStable).
	stable    *Builds
	updateKey ed25519.PrivateKey
	// tokens seals the secrets of new deployment and approval tokens, so
	// they can be shown again (ADR-0047); nil keeps only their hashes.
	tokens *secrets.Sealer
	// removed is called once a device was deleted (ADR-0050); nil for none.
	removed func()
	// gone is called with a device's id once it was deleted.
	gone func(uuid.UUID)
	// meshBins keeps the MeshAgent binaries fetched from MeshCentral.
	meshBins meshCache
	// scope decides where the agent may manage Defender exclusions and
	// report installed-file hashes (ADR-0070); nil allows every device.
	scope DefenderScope
	// version is called with an agent version the first heartbeat reports
	// for a device (ADR-0070); nil for none.
	version func(version string)
	// builtChanged is called after the served builds were loaded.
	builtChanged func()
	// roles stores what a heartbeat reports of the device's Windows roles
	// (ADR-0073); nil ignores them.
	roles RoleStore
}

// RoleStore keeps the roles an agent reported (modules.Service). It runs in
// the heartbeat's transaction and says whether the agent is to rescan.
type RoleStore interface {
	StoreRoles(ctx context.Context, tx pgx.Tx, deviceID, orgID uuid.UUID, reported []agentproto.Role) (rescan bool, err error)
}

// SetRoleStore has heartbeats' roles stored in rs (ADR-0073).
func (s *Service) SetRoleStore(rs RoleStore) { s.roles = rs }

// OnRemoved has f called after a device is deleted, such as to have the
// patching engine told at once to remove the device's EasyPatch agent.
func (s *Service) OnRemoved(f func()) { s.removed = f }

// OnDeviceGone has f called with a device's id once it was deleted, such as
// to close its agent channel connection (ADR-0059).
func (s *Service) OnDeviceGone(f func(uuid.UUID)) { s.gone = f }

// SetSealer keeps new tokens' secrets, sealed with sl, so that their install
// commands can be shown again (ADR-0047).
func (s *Service) SetSealer(sl *secrets.Sealer) { s.tokens = sl }

// New returns a Service. mesh may be nil.
func New(db *database.DB, auditLog *audit.Logger, mesh MeshAgents, log *slog.Logger) *Service {
	return &Service{
		db: db, audit: auditLog, mesh: mesh, log: log, now: time.Now,
		// A whole office may enroll at once from one address; the limit
		// only keeps junk from loading the database. Tokens cannot be
		// guessed.
		enroll: auth.NewKeyedLimiter(250*time.Millisecond, 120, 10_000),
		// Devices waiting for approval ask again every ApprovalWait or so,
		// possibly thousands behind one address.
		lookups:      auth.NewKeyedLimiter(20*time.Millisecond, 1000, 10_000),
		polls:        auth.NewKeyedLimiter(2*time.Second, 5, MaxWaiting),
		waits:        newWaitHub(),
		approvalWait: agentproto.ApprovalWait,
	}
}

// SetJobKey sets the job-signing public key (agentproto.EncodeKey) that
// enrollment and heartbeat answers carry for agents to pin (ADR-0017).
func (s *Service) SetJobKey(key string) { s.jobKey = key }

// Errors the agent API maps to responses.
var (
	// ErrTokenInvalid covers unknown, expired, revoked and used-up tokens
	// alike, so a caller learns nothing about tokens it does not hold.
	ErrTokenInvalid = errors.New("agents: deployment token not valid")
	// ErrKeyInUse means another device already enrolled with this key.
	ErrKeyInUse = errors.New("agents: public key already enrolled")
	// ErrUnauthorized is a signature that does not verify.
	ErrUnauthorized = errors.New("agents: request not authenticated")
	// ErrClockSkew is a request timestamp too far from the server's clock.
	ErrClockSkew = errors.New("agents: request time outside the allowed skew")
	// ErrReplay is a nonce seen before.
	ErrReplay = errors.New("agents: request replayed")
	// ErrUnknownDevice is a device that does not exist (any more).
	ErrUnknownDevice = errors.New("agents: unknown device")
	// ErrRateLimited is too many enrollments from one address.
	ErrRateLimited = errors.New("agents: too many enrollments")
	// ErrMeshUnavailable means MeshAgent cannot be delivered now.
	ErrMeshUnavailable = errors.New("agents: MeshAgent is not available")
)

// NonceInterval is how often Run removes nonces that can no longer be
// replayed. Every signed request stores one for six minutes (MaxSkew and a
// minute's grace), so removing them each minute keeps the table at about seven
// minutes of requests. Removed hourly, an hour of 2000 agents left 63 MB of
// nonces and one large delete (docs/development/drills.md).
const NonceInterval = time.Minute

// Run removes expired nonces every NonceInterval until ctx ends.
func (s *Service) Run(ctx context.Context) {
	tick := time.NewTicker(NonceInterval)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
		if err := s.PruneNonces(ctx); err != nil && ctx.Err() == nil {
			s.log.Error("agents: removing expired nonces failed", "error", err)
		}
	}
}

// PruneNonces removes nonces that can no longer be replayed.
func (s *Service) PruneNonces(ctx context.Context) error {
	return s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `DELETE FROM agent_nonces WHERE expires_at < now()`); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `DELETE FROM retired_agent_nonces WHERE expires_at < now()`)
		return err
	})
}

// Cleanup removes expired nonces, enrollment requests nobody needs any
// more, and removed devices no longer waited for (ADR-0050).
func (s *Service) Cleanup(ctx context.Context) error {
	if err := s.PruneNonces(ctx); err != nil {
		return err
	}
	return s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		if err := cleanupRequests(ctx, tx); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `DELETE FROM retired_devices WHERE expires_at < now()`)
		return err
	})
}

// facts are validated, cleaned device facts.
type facts struct {
	hostname, os, platform, arch, version string
	meshNode                              string            // MeshCentral encoding, "" if none
	sha256                                string            // the agent's executable, "" if not reported
	meshSettings                          string            // the MeshAgent settings the agent applied, "" if not reported
	roles                                 []agentproto.Role // the roles the agent detected, nil if not reported (ADR-0073)
}

// cleanFacts validates what an agent reports. Free text is cut to the
// column sizes and stripped of control characters rather than refused, so
// an odd OS name never stops a device from enrolling.
func cleanFacts(f agentproto.Facts) (facts, error) {
	out := facts{
		hostname: clean(f.Hostname, 255),
		os:       clean(f.OS, 500),
		arch:     clean(f.Arch, 32),
		version:  clean(f.AgentVersion, 64),
	}
	if out.hostname == "" {
		return facts{}, errors.New("hostname is required")
	}
	switch f.Platform {
	case "windows", "linux", "macos":
		out.platform = f.Platform
	default:
		out.platform = "other"
	}
	if agentproto.ValidSHA256(f.AgentSHA256) {
		out.sha256 = f.AgentSHA256
	}
	out.roles = f.Roles
	if agentproto.ValidSHA256(f.MeshSettingsSHA256) {
		out.meshSettings = f.MeshSettingsSHA256
	}
	if f.MeshNodeID != "" {
		key, err := agentproto.MeshNodeKey(f.MeshNodeID)
		if err != nil {
			return facts{}, err
		}
		out.meshNode = key
	}
	return out, nil
}

func clean(s string, maxRunes int) string {
	s = strings.ToValidUTF8(s, "")
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, s)
	s = strings.TrimSpace(s)
	if utf8.RuneCountInString(s) > maxRunes {
		s = string([]rune(s)[:maxRunes])
	}
	return s
}
