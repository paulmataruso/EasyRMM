package easypatch

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"errors"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/secrets"
)

// tokenAD binds the sealed token to its column.
var tokenAD = []byte("easypatch_connection.token_sealed")

// Service is the EasyPatch connector.
type Service struct {
	db      *database.DB
	audit   *audit.Logger
	sealer  *secrets.Sealer
	version string
	log     *slog.Logger
	now     func() time.Time

	mu        sync.Mutex
	client    *Client
	clientFor time.Time // the updated_at of the settings client was built from

	fleet fleetCache

	// signer signs install instructions (ADR-0031); nil sends none.
	signer ed25519.PrivateKey
	// local reaches an EasyPatch co-hosted behind the edge over loopback
	// (ADR-0035); zero when there is none.
	local LocalRoute
}

// SetLocalRoute makes the connector reach the EasyPatch co-hosted on this
// server through its loopback listener (ADR-0035). Call it before use.
func (s *Service) SetLocalRoute(r LocalRoute) { s.local = r }

// New builds the connector.
func New(db *database.DB, auditLog *audit.Logger, sealer *secrets.Sealer, version string, log *slog.Logger) *Service {
	return &Service{db: db, audit: auditLog, sealer: sealer, version: version, log: log, now: time.Now,
		fleet: fleetCache{entries: map[uuid.UUID]fleetEntry{}}}
}

// Connection is the EasyPatch server as Settings shows it. The token is
// never shown again.
type Connection struct {
	Configured    bool       `json:"configured"`
	URL           string     `json:"url"`
	CACert        string     `json:"caCert"`
	ServerVersion string     `json:"serverVersion"`
	PublicURL     string     `json:"publicUrl"`
	Capabilities  []string   `json:"capabilities"`
	CanOperate    bool       `json:"canOperate"`
	CheckedAt     *time.Time `json:"checkedAt,omitempty"`
	LastError     string     `json:"lastError,omitempty"`
	LastErrorAt   *time.Time `json:"lastErrorAt,omitempty"`
	UpdatedAt     *time.Time `json:"updatedAt,omitempty"`
	UpdatedBy     string     `json:"updatedBy,omitempty"`
}

// ConnectionInput sets the EasyPatch server.
type ConnectionInput struct {
	URL string `json:"url"`
	// Token is an EasyPatch API token (ept_…). Left empty, the stored token
	// is kept, as long as the server is the same.
	Token  string `json:"token"`
	CACert string `json:"caCert"`
}

type connRow struct {
	url, sealed, caCert, version, publicURL, lastError string
	capabilities                                       []string
	canOperate                                         bool
	checkedAt, lastErrorAt                             *time.Time
	updatedAt                                          time.Time
	updatedBy                                          *string
}

func loadConn(ctx context.Context, tx pgx.Tx, lock bool) (*connRow, error) {
	q := `SELECT c.url, c.token_sealed, c.ca_cert, c.server_version, c.public_url, c.capabilities, c.can_operate, c.checked_at,
		c.last_error, c.last_error_at, c.updated_at, u.email
		FROM easypatch_connection c LEFT JOIN users u ON u.id = c.updated_by`
	if lock {
		q += ` FOR UPDATE OF c`
	}
	var r connRow
	err := tx.QueryRow(ctx, q).Scan(&r.url, &r.sealed, &r.caCert, &r.version, &r.publicURL, &r.capabilities, &r.canOperate, &r.checkedAt,
		&r.lastError, &r.lastErrorAt, &r.updatedAt, &r.updatedBy)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return &r, err
}

func (r *connRow) view() Connection {
	if r == nil {
		return Connection{Capabilities: []string{}}
	}
	c := Connection{Configured: true, URL: r.url, CACert: r.caCert, ServerVersion: r.version, PublicURL: r.publicURL,
		Capabilities: r.capabilities, CanOperate: r.canOperate, CheckedAt: r.checkedAt, LastError: r.lastError, LastErrorAt: r.lastErrorAt,
		UpdatedAt: &r.updatedAt}
	if r.updatedBy != nil {
		c.UpdatedBy = *r.updatedBy
	}
	if c.Capabilities == nil {
		c.Capabilities = []string{}
	}
	return c
}

func (r *connRow) can(capability string) bool {
	return r != nil && slices.Contains(r.capabilities, capability)
}

// Connection returns the settings and what the last check found.
func (s *Service) Connection(ctx context.Context) (Connection, error) {
	var r *connRow
	err := s.db.ReadTx(ctx, database.System, func(tx pgx.Tx) (err error) {
		r, err = loadConn(ctx, tx, false)
		return err
	})
	return r.view(), err
}

// conn returns the settings and a client for them; nil when EasyPatch is not
// set up.
func (s *Service) conn(ctx context.Context) (*connRow, *Client, error) {
	var r *connRow
	err := s.db.ReadTx(ctx, database.System, func(tx pgx.Tx) (err error) {
		r, err = loadConn(ctx, tx, false)
		return err
	})
	if err != nil || r == nil {
		return nil, nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.client != nil && s.clientFor.Equal(r.updatedAt) {
		return r, s.client, nil
	}
	token, err := s.sealer.Open(r.sealed, tokenAD)
	if err != nil {
		return nil, nil, apperr.Unavailable("easypatch_token", "The EasyPatch API token cannot be opened with this server's secret key. Enter it again in Settings → EasyPatch.")
	}
	c, err := NewClient(r.url, string(token), r.caCert, s.version, WithLocalRoute(s.local))
	if err != nil {
		return nil, nil, err
	}
	s.client, s.clientFor = c, r.updatedAt
	return r, c, nil
}

// probe is what a check of the server found.
type probe struct {
	info       ServerInfo
	canOperate bool
}

func check(ctx context.Context, c *Client) (probe, error) {
	info, err := c.ServerInfo(ctx)
	if err != nil {
		return probe{}, err
	}
	if info.Version == "" {
		return probe{}, &Error{Detail: "The server does not answer like EasyPatch (no version in /api/v1/server-info)."}
	}
	can, err := c.CanOperate(ctx)
	if err != nil {
		return probe{}, err
	}
	if info.Capabilities == nil {
		info.Capabilities = []string{}
	}
	return probe{info: info, canOperate: can}, nil
}

func validToken(t string) bool {
	return strings.HasPrefix(t, "ept_") && len(t) >= 20 && len(t) <= 200 && !strings.ContainsAny(t, " \t\r\n")
}

// UpdateConnection checks and saves the EasyPatch server. Nothing is saved
// unless EasyPatch accepts the token. A different server forgets every
// organization and device link, which name the old server's ids.
func (s *Service) UpdateConnection(ctx context.Context, actor audit.Actor, in ConnectionInput) (Connection, error) {
	in.Token, in.CACert = strings.TrimSpace(in.Token), strings.TrimSpace(in.CACert)
	var stored *connRow
	if err := s.db.ReadTx(ctx, database.System, func(tx pgx.Tx) (err error) {
		stored, err = loadConn(ctx, tx, false)
		return err
	}); err != nil {
		return Connection{}, err
	}
	f := apperr.Fields{}
	u, err := ParseURL(in.URL)
	if err != nil {
		f.Add("url", err.Error())
	}
	sameServer := u != nil && stored != nil && SameServer(stored.url, u.String())
	token := in.Token
	switch {
	case token != "":
		f.Check(validToken(token), "token", "must be an EasyPatch API token (it starts with ept_)")
	case sameServer:
		b, err := s.sealer.Open(stored.sealed, tokenAD)
		if err != nil {
			f.Add("token", "the stored token cannot be opened with this server's secret key; enter it again")
		}
		token = string(b)
	default:
		f.Add("token", "is required")
	}
	if len(in.CACert) > 65536 {
		f.Add("caCert", "must be under 64 KiB")
	} else if in.CACert != "" && !x509.NewCertPool().AppendCertsFromPEM([]byte(in.CACert)) {
		f.Add("caCert", "must be one or more PEM certificates (-----BEGIN CERTIFICATE-----)")
	}
	if err := f.Err(); err != nil {
		return Connection{}, err
	}
	c, err := NewClient(u.String(), token, in.CACert, s.version, WithLocalRoute(s.local))
	if err != nil {
		return Connection{}, apperr.Invalid("url", err.Error())
	}
	p, err := check(ctx, c)
	if err != nil {
		var e *Error
		if errors.As(err, &e) && (e.Status == http.StatusUnauthorized || e.Status == http.StatusForbidden) {
			return Connection{}, apperr.Invalid("token", "EasyPatch refused the token: "+e.Detail)
		}
		return Connection{}, apperr.Invalid("url", err.Error())
	}
	sealed, err := s.sealer.Seal([]byte(token), tokenAD)
	if err != nil {
		return Connection{}, err
	}
	var out *connRow
	err = s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		var updatedBy *uuid.UUID
		if actor.ID != uuid.Nil {
			updatedBy = &actor.ID
		}
		if _, err := tx.Exec(ctx, `INSERT INTO easypatch_connection (id, url, token_sealed, ca_cert, server_version, public_url, capabilities,
				can_operate, checked_at, last_error, last_error_at, updated_at, updated_by)
			VALUES (true, $1, $2, $3, $4, $5, $6, $7, now(), '', NULL, now(), $8)
			ON CONFLICT (id) DO UPDATE SET url = $1, token_sealed = $2, ca_cert = $3, server_version = $4, public_url = $5,
				capabilities = $6, can_operate = $7, checked_at = now(), last_error = '', last_error_at = NULL, updated_at = now(),
				updated_by = $8`,
			u.String(), sealed, in.CACert, cut(p.info.Version, 64), cut(p.info.PublicURL, 500), p.info.Capabilities, p.canOperate,
			updatedBy); err != nil {
			return err
		}
		forgot := false
		if stored != nil && !sameServer {
			if _, err := tx.Exec(ctx, `DELETE FROM easypatch_devices`); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `DELETE FROM easypatch_organizations`); err != nil {
				return err
			}
			forgot = true
		}
		if err := s.audit.Write(ctx, tx, audit.Event{
			Actor: actor, Action: "easypatch.connection_update", TargetType: "easypatch", TargetID: "connection", Outcome: audit.Success,
			Details: map[string]any{"url": u.String(), "serverVersion": p.info.Version, "canOperate": p.canOperate,
				"capabilities": p.info.Capabilities, "tokenChanged": in.Token != "", "caCert": in.CACert != "", "linksForgotten": forgot},
		}); err != nil {
			return err
		}
		out, err = loadConn(ctx, tx, false)
		return err
	})
	if err != nil {
		return Connection{}, err
	}
	s.fleet.clear()
	return out.view(), nil
}

// DeleteConnection forgets the EasyPatch server and every link.
func (s *Service) DeleteConnection(ctx context.Context, actor audit.Actor) error {
	err := s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `DELETE FROM easypatch_connection`)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return apperr.NotFound()
		}
		if _, err := tx.Exec(ctx, `DELETE FROM easypatch_devices`); err != nil {
			return err
		}
		// Installs from that server: their tokens expire within the hour.
		if _, err := tx.Exec(ctx, `DELETE FROM easypatch_installs`); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM easypatch_organizations`); err != nil {
			return err
		}
		return s.audit.Write(ctx, tx, audit.Event{Actor: actor, Action: "easypatch.connection_delete", TargetType: "easypatch",
			TargetID: "connection", Outcome: audit.Success})
	})
	if err == nil {
		s.fleet.clear()
	}
	return err
}

// CheckConnection checks the saved server again and records what it found.
func (s *Service) CheckConnection(ctx context.Context) (Connection, error) {
	r, c, err := s.conn(ctx)
	if err != nil {
		return Connection{}, err
	}
	if r == nil {
		return Connection{}, apperr.NotFound()
	}
	p, checkErr := check(ctx, c)
	err = s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		if checkErr != nil {
			_, err := tx.Exec(ctx, `UPDATE easypatch_connection SET last_error = $1, last_error_at = now()`, cut(checkErr.Error(), 1000))
			return err
		}
		_, err := tx.Exec(ctx, `UPDATE easypatch_connection SET server_version = $1, public_url = $2, capabilities = $3, can_operate = $4,
			checked_at = now(), last_error = '', last_error_at = NULL`,
			cut(p.info.Version, 64), cut(p.info.PublicURL, 500), p.info.Capabilities, p.canOperate)
		return err
	})
	if err != nil {
		return Connection{}, err
	}
	return s.Connection(ctx)
}

// noteError records that a call to EasyPatch failed, for Settings and the
// product switch to show. Only failures that make EasyPatch unusable are
// recorded: no answer, a server error, or EasyRMM's token refused. EasyPatch
// refusing one request (a duplicate scan) says nothing about the server.
func (s *Service) noteError(ctx context.Context, err error) {
	var e *Error
	if !errors.As(err, &e) {
		return
	}
	if e.Status != 0 && e.Status < 500 && e.Status != http.StatusUnauthorized && e.Status != http.StatusForbidden {
		return
	}
	ctx = context.WithoutCancel(ctx)
	if dbErr := s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE easypatch_connection SET last_error = $1, last_error_at = now()`, cut(e.Error(), 1000))
		return err
	}); dbErr != nil {
		s.log.Warn("easypatch: could not record an error", "err", dbErr)
	}
}

// cut keeps s under n bytes, on a character boundary.
func cut(s string, n int) string {
	if len(s) <= n {
		return s
	}
	// A rune split by the cut is invalid UTF-8, and dropped.
	return strings.ToValidUTF8(s[:n], "")
}
