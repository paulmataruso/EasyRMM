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
	log   *slog.Logger
	now   func() time.Time
	// enroll limits new devices per address, lookups every enrollment
	// request per address, polls a waiting device's requests per key.
	enroll, lookups, polls *auth.KeyedLimiter
	waits                  *waitHub
	approvalWait           time.Duration
	jobKey                 string
	// Agent updates (ADR-0027); nil without builds.
	builds    *Builds
	updateKey ed25519.PrivateKey
}

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

// Cleanup removes nonces that can no longer be replayed and enrollment
// requests nobody needs any more.
func (s *Service) Cleanup(ctx context.Context) error {
	return s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `DELETE FROM agent_nonces WHERE expires_at < now()`); err != nil {
			return err
		}
		return cleanupRequests(ctx, tx)
	})
}

// facts are validated, cleaned device facts.
type facts struct {
	hostname, os, platform, arch, version string
	meshNode                              string // MeshCentral encoding, "" if none
	sha256                                string // the agent's executable, "" if not reported
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
