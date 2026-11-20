package easypatch

import (
	"context"
	"crypto/ed25519"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/database"
)

// Service is EasyRMM's side of the patching engine in this deployment
// (UseEngine): what EasyRMM's organizations, sites and devices are there,
// and the console's patch views and actions.
type Service struct {
	db      *database.DB
	audit   *audit.Logger
	version string
	log     *slog.Logger
	now     func() time.Time

	fleet fleetCache

	// signer signs install instructions (ADR-0031); nil sends none.
	signer ed25519.PrivateKey
	// engine is the patching engine (UseEngine); nil until then, when
	// patching is not set up.
	engine *engine

	// kick starts a reconcile pass (Kick); sync is what passes remember.
	kick chan struct{}
	sync syncState
}

// New builds the service; UseEngine gives it the engine.
func New(db *database.DB, auditLog *audit.Logger, version string, log *slog.Logger) *Service {
	return &Service{db: db, audit: auditLog, version: version, log: log, now: time.Now,
		fleet: fleetCache{entries: map[uuid.UUID]fleetEntry{}}, kick: make(chan struct{}, 1)}
}

// Connection is the patching engine as Settings shows it.
type Connection struct {
	// Configured says the engine is set up; it is, in every deployment.
	Configured    bool       `json:"configured"`
	URL           string     `json:"url"`
	CACert        string     `json:"caCert"`
	ServerVersion string     `json:"serverVersion"`
	PublicURL     string     `json:"publicUrl"`
	CheckedAt     *time.Time `json:"checkedAt,omitempty"`
	LastError     string     `json:"lastError,omitempty"`
	LastErrorAt   *time.Time `json:"lastErrorAt,omitempty"`
}

// connRow is what EasyRMM knows of the engine: where it is, what it said
// last, and the last failure.
type connRow struct {
	url, caCert, version, publicURL, lastError string
	// importedURLs are an imported EasyPatch's addresses, which the engine
	// answers for its agents (AgentHostnames).
	importedURLs           []string
	checkedAt, lastErrorAt *time.Time
}

// imported reports whether an agent enrolled with serverURL reaches this
// server through one of an imported EasyPatch's names.
func (r *connRow) imported(serverURL string) bool {
	for _, u := range r.importedURLs {
		if SameServer(serverURL, u) {
			return true
		}
	}
	return false
}

func (r *connRow) view() Connection {
	if r == nil {
		return Connection{}
	}
	return Connection{Configured: true, URL: r.url, CACert: r.caCert, ServerVersion: r.version, PublicURL: r.publicURL,
		CheckedAt: r.checkedAt, LastError: r.lastError, LastErrorAt: r.lastErrorAt}
}

// Connection returns the engine and what the last check found.
func (s *Service) Connection(ctx context.Context) (Connection, error) {
	if s.engine == nil {
		return (*connRow)(nil).view(), nil
	}
	return s.engine.row(ctx, s.now(), false).view(), nil
}

// conn returns the engine and its client; nil when patching is not set up.
func (s *Service) conn(ctx context.Context) (*connRow, *Client, error) {
	if s.engine == nil {
		return nil, nil, nil
	}
	return s.engine.row(ctx, s.now(), false), s.engine.client, nil
}

// CheckConnection checks the engine again and records what it found.
func (s *Service) CheckConnection(ctx context.Context) (Connection, error) {
	if s.engine == nil {
		return Connection{}, apperr.NotFound()
	}
	return s.engine.row(ctx, s.now(), true).view(), nil
}

// noteError records that a call to the engine failed, for Settings to
// show. Only failures that make the engine unusable are recorded: no
// answer, a server error, or EasyRMM's statements refused. The engine
// refusing one request (a duplicate scan) says nothing about it.
func (s *Service) noteError(err error) {
	var e *Error
	if !errors.As(err, &e) || s.engine == nil {
		return
	}
	if e.Status != 0 && e.Status < 500 && e.Status != http.StatusUnauthorized && e.Status != http.StatusForbidden {
		return
	}
	s.engine.noted(e.Error(), s.now())
}

// cut keeps s under n bytes, on a character boundary.
func cut(s string, n int) string {
	if len(s) <= n {
		return s
	}
	// A rune split by the cut is invalid UTF-8, and dropped.
	return strings.ToValidUTF8(s[:n], "")
}
