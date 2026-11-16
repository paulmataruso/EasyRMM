package auditfwd

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"log/slog"
	"net/netip"
	"regexp"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/secrets"
)

// lockForward keeps two servers on one database from forwarding at once,
// and settings changes from landing in the middle of a batch.
const lockForward = 6107215593021

const (
	// BatchSize is how many records one round sends.
	BatchSize = 500
	// PollInterval is how often the forwarder looks for new records.
	PollInterval = 2 * time.Second
	maxBackoff   = time.Minute
	// countCap bounds the backlog count shown in the console.
	countCap = 100_000
)

// keyAD binds the sealed client key to its column.
var keyAD = []byte("audit_forwarding.client_key")

// Service forwards the audit log and manages its settings.
type Service struct {
	db       *database.DB
	audit    *audit.Logger
	sealer   *secrets.Sealer
	hostname string
	version  string
	log      *slog.Logger

	// Owned by Run.
	conn    *conn
	connKey string
	failing string
}

// New returns a Service. hostname is sent as each message's HOSTNAME: the
// server's public name.
func New(db *database.DB, auditLog *audit.Logger, sealer *secrets.Sealer, hostname, version string, log *slog.Logger) *Service {
	return &Service{db: db, audit: auditLog, sealer: sealer, hostname: hostname, version: version, log: log}
}

// Settings is the forwarding configuration and its state, as the console
// shows it. The client key is never returned.
type Settings struct {
	Configured   bool       `json:"configured"`
	Enabled      bool       `json:"enabled"`
	Transport    string     `json:"transport"`
	Host         string     `json:"host"`
	Port         int        `json:"port"`
	Facility     int        `json:"facility"`
	CACert       string     `json:"caCert"`
	ClientCert   string     `json:"clientCert"`
	ClientKeySet bool       `json:"clientKeySet"`
	Hostname     string     `json:"hostname"`
	UpdatedAt    *time.Time `json:"updatedAt,omitempty"`
	UpdatedBy    string     `json:"updatedBy,omitempty"`
	Status       Status     `json:"status"`
}

// Status is how far forwarding has got.
type Status struct {
	LastID      int64      `json:"lastId"`
	LastSentAt  *time.Time `json:"lastSentAt,omitempty"`
	LastError   string     `json:"lastError,omitempty"`
	LastErrorAt *time.Time `json:"lastErrorAt,omitempty"`
	// Backlog counts records not yet forwarded, up to 100,000 (BacklogMore
	// when there are more); OldestPendingAt is the oldest one's time.
	Backlog         int64      `json:"backlog"`
	BacklogMore     bool       `json:"backlogMore"`
	OldestPendingAt *time.Time `json:"oldestPendingAt,omitempty"`
	// Stored counts every record in the log the same way, for the choice of
	// where forwarding starts.
	Stored     int64 `json:"stored"`
	StoredMore bool  `json:"storedMore"`
	// Stopping is forwarding that was turned off still delivering the
	// records up to the change that turned it off.
	Stopping bool `json:"stopping"`
}

// Input is a settings change, or the settings to test.
type Input struct {
	Enabled    bool   `json:"enabled"`
	Transport  string `json:"transport"`
	Host       string `json:"host"`
	Port       int    `json:"port"`
	Facility   int    `json:"facility"`
	CACert     string `json:"caCert"`
	ClientCert string `json:"clientCert"`
	// ClientKey is write-only. Left empty, the stored key is kept as long as
	// the certificate is unchanged.
	ClientKey string `json:"clientKey"`
	// StartFrom moves where forwarding resumes: "now" skips the records
	// already in the log, "beginning" sends all of them. Empty keeps the
	// position (new settings start at the beginning).
	StartFrom string `json:"startFrom"`
}

// row is the stored settings.
type row struct {
	enabled                       bool
	transport, host               string
	port, facility                int
	caCert, clientCert, sealedKey string
	lastID, drainUntil            int64
	lastSentAt, lastErrorAt       *time.Time
	lastError                     string
	updatedAt                     time.Time
	updatedBy                     *string
}

func (r *row) destination(sealer *secrets.Sealer) (Destination, error) {
	d := Destination{Transport: r.transport, Host: r.host, Port: r.port, CACert: r.caCert, ClientCert: r.clientCert}
	if r.sealedKey != "" {
		key, err := sealer.Open(r.sealedKey, keyAD)
		if err != nil {
			return d, errors.New("the stored client key cannot be opened with this server's secret key; enter it again")
		}
		d.ClientKey = key
	}
	return d, nil
}

// stopping reports whether forwarding was turned off and still has records
// to deliver up to the change.
func (r *row) stopping() bool { return !r.enabled && r.lastID < r.drainUntil }

func loadRow(ctx context.Context, tx pgx.Tx, lock bool) (*row, error) {
	q := `SELECT f.enabled, f.transport, f.host, f.port, f.facility, f.ca_cert, f.client_cert, f.client_key_sealed,
		f.last_id, f.drain_until, f.last_sent_at, f.last_error, f.last_error_at, f.updated_at, u.email
		FROM audit_forwarding f LEFT JOIN users u ON u.id = f.updated_by`
	if lock {
		q += ` FOR UPDATE OF f`
	}
	var r row
	err := tx.QueryRow(ctx, q).Scan(&r.enabled, &r.transport, &r.host, &r.port, &r.facility, &r.caCert, &r.clientCert,
		&r.sealedKey, &r.lastID, &r.drainUntil, &r.lastSentAt, &r.lastError, &r.lastErrorAt, &r.updatedAt, &r.updatedBy)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return &r, err
}

// Get returns the settings and status.
func (s *Service) Get(ctx context.Context) (Settings, error) {
	out := Settings{Hostname: headerField(s.hostname, 255), Facility: DefaultFacility, Transport: TLS, Port: 6514}
	err := s.db.ReadTx(ctx, database.System, func(tx pgx.Tx) error {
		r, err := loadRow(ctx, tx, false)
		if err != nil {
			return err
		}
		var after int64
		if r != nil {
			out.Configured, out.Enabled, out.Transport, out.Host, out.Port = true, r.enabled, r.transport, r.host, r.port
			out.Facility, out.CACert, out.ClientCert, out.ClientKeySet = r.facility, r.caCert, r.clientCert, r.sealedKey != ""
			out.UpdatedAt = &r.updatedAt
			if r.updatedBy != nil {
				out.UpdatedBy = *r.updatedBy
			}
			out.Status = Status{LastID: r.lastID, LastSentAt: r.lastSentAt, LastError: r.lastError, LastErrorAt: r.lastErrorAt,
				Stopping: r.stopping()}
			after = r.lastID
		}
		if out.Status.Backlog, out.Status.BacklogMore, err = countAfter(ctx, tx, after); err != nil {
			return err
		}
		if out.Status.Stored, out.Status.StoredMore, err = countAfter(ctx, tx, 0); err != nil {
			return err
		}
		err = tx.QueryRow(ctx, `SELECT occurred_at FROM audit_log WHERE id > $1 ORDER BY id LIMIT 1`, after).Scan(&out.Status.OldestPendingAt)
		if errors.Is(err, pgx.ErrNoRows) {
			err = nil
		}
		return err
	})
	return out, err
}

func countAfter(ctx context.Context, tx pgx.Tx, after int64) (int64, bool, error) {
	var n int64
	err := tx.QueryRow(ctx, `SELECT count(*) FROM (SELECT 1 FROM audit_log WHERE id > $1 LIMIT $2) s`, after, countCap+1).Scan(&n)
	if n > countCap {
		return countCap, true, err
	}
	return n, false, err
}

var hostLabel = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$`)

// validHost accepts an IP address or a DNS name.
func validHost(h string) bool {
	if _, err := netip.ParseAddr(h); err == nil {
		return true
	}
	if len(h) > 253 {
		return false
	}
	for _, l := range strings.Split(strings.TrimSuffix(h, "."), ".") {
		if !hostLabel.MatchString(l) {
			return false
		}
	}
	return true
}

// check validates in and works out the destination, using the stored key
// when the certificate is unchanged and no key was given.
func (s *Service) check(in *Input, stored *row) (Destination, error) {
	f := apperr.Fields{}
	in.Transport = strings.ToLower(strings.TrimSpace(in.Transport))
	in.Host = strings.TrimSpace(in.Host)
	in.CACert, in.ClientCert, in.ClientKey = strings.TrimSpace(in.CACert), strings.TrimSpace(in.ClientCert), strings.TrimSpace(in.ClientKey)
	if strings.HasPrefix(in.Host, "[") && strings.HasSuffix(in.Host, "]") {
		in.Host = in.Host[1 : len(in.Host)-1]
	}
	if in.Facility == 0 {
		in.Facility = DefaultFacility
	}
	f.Check(in.Transport == UDP || in.Transport == TCP || in.Transport == TLS, "transport", "must be udp, tcp or tls")
	switch {
	case in.Host == "":
		f.Add("host", "is required")
	case !validHost(in.Host):
		f.Add("host", "must be a host name or an IP address, without a scheme or port")
	}
	f.Check(in.Port >= 1 && in.Port <= 65535, "port", "must be between 1 and 65535")
	f.Check(slices.Contains(Facilities, in.Facility), "facility", "must be auth (4), authpriv (10), log audit (13) or local0 to local7 (16 to 23)")
	f.Check(in.StartFrom == "" || in.StartFrom == "now" || in.StartFrom == "beginning", "startFrom", "must be now or beginning")
	if in.Transport != TLS {
		f.Check(in.CACert == "", "caCert", "is used only with TLS")
		f.Check(in.ClientCert == "" && in.ClientKey == "", "clientCert", "is used only with TLS")
	}
	if len(in.CACert) > 65536 || len(in.ClientCert) > 65536 || len(in.ClientKey) > 65536 {
		f.Add("caCert", "certificates and keys must be under 64 KiB")
	}
	if in.CACert != "" && !x509.NewCertPool().AppendCertsFromPEM([]byte(in.CACert)) {
		f.Add("caCert", "must be one or more PEM certificates (-----BEGIN CERTIFICATE-----)")
	}
	d := Destination{Transport: in.Transport, Host: in.Host, Port: in.Port, CACert: in.CACert, ClientCert: in.ClientCert}
	switch {
	case in.ClientCert == "" && in.ClientKey != "":
		f.Add("clientCert", "is required with a client key")
	case in.ClientCert == "":
	case in.ClientKey != "":
		d.ClientKey = []byte(in.ClientKey)
	case stored != nil && stored.sealedKey != "" && stored.clientCert == in.ClientCert:
		key, err := s.sealer.Open(stored.sealedKey, keyAD)
		if err != nil {
			f.Add("clientKey", "the stored key cannot be opened with this server's secret key; paste it again")
		}
		d.ClientKey = key
	default:
		f.Add("clientKey", "is required with a client certificate")
	}
	if in.ClientCert != "" && len(d.ClientKey) > 0 {
		if block, _ := pem.Decode(d.ClientKey); block != nil && strings.Contains(block.Type, "ENCRYPTED") {
			f.Add("clientKey", "must not be encrypted with a passphrase")
		} else if _, err := tls.X509KeyPair([]byte(in.ClientCert), d.ClientKey); err != nil {
			f.Add("clientKey", "does not match the client certificate, or one of them is not PEM")
		}
	}
	return d, f.Err()
}

// Update changes the settings and records the change in the audit log.
func (s *Service) Update(ctx context.Context, actor audit.Actor, in Input) (Settings, error) {
	err := s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		// Wait for a batch in flight, so the position set here is not
		// overwritten by its end.
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, int64(lockForward)); err != nil {
			return err
		}
		stored, err := loadRow(ctx, tx, true)
		if err != nil {
			return err
		}
		d, err := s.check(&in, stored)
		if err != nil {
			return err
		}
		sealed := ""
		switch {
		case in.ClientCert == "":
		case in.ClientKey == "":
			sealed = stored.sealedKey // checked above: unchanged certificate
		default:
			if sealed, err = s.sealer.Seal(d.ClientKey, keyAD); err != nil {
				return err
			}
		}
		lastID := int64(0)
		if stored != nil {
			lastID = stored.lastID
		}
		switch in.StartFrom {
		case "now":
			if err := tx.QueryRow(ctx, `SELECT coalesce(max(id), 0) FROM audit_log`).Scan(&lastID); err != nil {
				return err
			}
		case "beginning":
			lastID = 0
		}
		moved := stored == nil || stored.transport != in.Transport || stored.host != in.Host || stored.port != in.Port ||
			stored.caCert != in.CACert || stored.clientCert != in.ClientCert || in.ClientKey != ""
		var updatedBy *uuid.UUID
		if actor.ID != uuid.Nil {
			updatedBy = &actor.ID
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO audit_forwarding (id, enabled, transport, host, port, facility, ca_cert, client_cert, client_key_sealed,
				last_id, updated_at, updated_by)
			VALUES (true, $1, $2, $3, $4, $5, $6, $7, $8, $9, now(), $10)
			ON CONFLICT (id) DO UPDATE SET enabled = $1, transport = $2, host = $3, port = $4, facility = $5, ca_cert = $6,
				client_cert = $7, client_key_sealed = $8, last_id = $9, updated_at = now(), updated_by = $10,
				last_error = CASE WHEN $11 THEN '' ELSE audit_forwarding.last_error END,
				last_error_at = CASE WHEN $11 THEN NULL ELSE audit_forwarding.last_error_at END`,
			in.Enabled, in.Transport, in.Host, in.Port, in.Facility, in.CACert, in.ClientCert, sealed, lastID, updatedBy, moved); err != nil {
			return err
		}
		details := map[string]any{
			"enabled": in.Enabled, "transport": in.Transport, "host": in.Host, "port": in.Port, "facility": in.Facility,
			"caCert": in.CACert != "", "clientCert": in.ClientCert != "",
		}
		if in.StartFrom != "" {
			details["startFrom"] = in.StartFrom
			details["position"] = lastID
		}
		if err := s.audit.Write(ctx, tx, audit.Event{
			Actor: actor, Action: "audit_forwarding.update", TargetType: "audit_forwarding", TargetID: d.Address(),
			Outcome: audit.Success, Details: details,
		}); err != nil {
			return err
		}
		// Turning forwarding off is itself forwarded, with everything before
		// it: a collector that stops hearing from EasyRMM learns why. This
		// transaction holds the audit log's append lock, so the newest record
		// is the one just written.
		drain := `UPDATE audit_forwarding SET drain_until = 0`
		if stored != nil && stored.enabled && !in.Enabled {
			drain = `UPDATE audit_forwarding SET drain_until = (SELECT max(id) FROM audit_log)`
		}
		_, err = tx.Exec(ctx, drain)
		return err
	})
	if err != nil {
		return Settings{}, err
	}
	return s.Get(ctx)
}

// TestResult is the outcome of a test message.
type TestResult struct {
	OK      bool   `json:"ok"`
	Message string `json:"message"`
}

// Test sends one message to the destination in in (saved or not) and records
// the attempt in the audit log.
func (s *Service) Test(ctx context.Context, actor audit.Actor, in Input) (TestResult, error) {
	var stored *row
	if err := s.db.ReadTx(ctx, database.System, func(tx pgx.Tx) error {
		var err error
		stored, err = loadRow(ctx, tx, false)
		return err
	}); err != nil {
		return TestResult{}, err
	}
	d, err := s.check(&in, stored)
	if err != nil {
		return TestResult{}, err
	}
	res := s.sendTest(ctx, d, in.Facility, actor)
	outcome := audit.Success
	details := map[string]any{"transport": d.Transport, "host": d.Host, "port": d.Port}
	if !res.OK {
		outcome = audit.Failure
		details["error"] = res.Message
	}
	err = s.audit.Record(ctx, audit.Event{
		Actor: actor, Action: "audit_forwarding.test", TargetType: "audit_forwarding", TargetID: d.Address(),
		Outcome: outcome, Details: details,
	})
	return res, err
}

func (s *Service) sendTest(ctx context.Context, d Destination, facility int, actor audit.Actor) TestResult {
	ctx, cancel := context.WithTimeout(ctx, dialTimeout+writeTimeout)
	defer cancel()
	c, err := dial(ctx, d)
	if err != nil {
		return TestResult{Message: describe(d, err)}
	}
	defer c.close()
	now := time.Now().UTC()
	body, _ := json.Marshal(map[string]any{
		"test": true, "message": "EasyRMM audit forwarding test", "requestedBy": actor.Label, "at": now.Format(time.RFC3339Nano),
	})
	if err := c.send([][]byte{newFormatter(facility, s.hostname, s.version).format(now, 6, "test", body)}); err != nil {
		return TestResult{Message: describe(d, err)}
	}
	if c.refused(500 * time.Millisecond) {
		return TestResult{Message: describe(d, syscall.ECONNREFUSED)}
	}
	switch d.Transport {
	case UDP:
		return TestResult{OK: true, Message: "Sent. UDP does not confirm delivery: check that the collector received it."}
	case TLS:
		return TestResult{OK: true, Message: "Connected over TLS, the collector's certificate checked out, and the message was sent."}
	}
	return TestResult{OK: true, Message: "Connected and sent the message."}
}

// Run forwards records until ctx ends.
func (s *Service) Run(ctx context.Context) {
	defer s.closeConn()
	backoff := time.Duration(0)
	for {
		n, err := s.Forward(ctx)
		wait := PollInterval
		switch {
		case ctx.Err() != nil:
			return
		case err != nil:
			backoff = min(max(2*backoff, time.Second), maxBackoff)
			wait = backoff
		case n == BatchSize:
			backoff, wait = 0, 0
		default:
			backoff = 0
		}
		t := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		}
	}
}

// Forward sends one batch of records and returns how many it sent. Only one
// server forwards at a time; the others find nothing to do.
func (s *Service) Forward(ctx context.Context) (int, error) {
	var sent int
	var failed error
	err := s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		var locked bool
		if err := tx.QueryRow(ctx, `SELECT pg_try_advisory_xact_lock($1)`, int64(lockForward)).Scan(&locked); err != nil {
			return err
		}
		if !locked {
			return nil
		}
		r, err := loadRow(ctx, tx, false)
		if err != nil {
			return err
		}
		if r == nil || !r.enabled && !r.stopping() {
			s.closeConn()
			return nil
		}
		batch, err := readAfter(ctx, tx, r.lastID, BatchSize)
		if err != nil {
			return err
		}
		if !r.enabled {
			for len(batch) > 0 && batch[len(batch)-1].ID > r.drainUntil {
				batch = batch[:len(batch)-1]
			}
		}
		if len(batch) == 0 {
			return nil
		}
		d, err := r.destination(s.sealer)
		if err == nil {
			err = s.connect(ctx, d, r.updatedAt.String())
		}
		if err == nil {
			f := newFormatter(r.facility, s.hostname, s.version)
			msgs := make([][]byte, 0, len(batch))
			for _, rec := range batch {
				m, ferr := f.message(rec, s.conn.limit)
				if ferr != nil {
					return ferr
				}
				msgs = append(msgs, m)
			}
			if err = s.conn.send(msgs); err != nil {
				s.closeConn()
			}
		}
		if err != nil {
			failed = err
			msg := describe(d, err)
			if msg != s.failing {
				s.log.Warn("audit forwarding: cannot deliver to the collector", "error", msg, "collector", d.Address(), "transport", d.Transport)
				s.failing = msg
			}
			_, uerr := tx.Exec(ctx, `UPDATE audit_forwarding SET last_error = $1, last_error_at = now()`, msg)
			return uerr
		}
		if s.failing != "" {
			s.log.Info("audit forwarding: delivering again", "collector", d.Address())
			s.failing = ""
		}
		sent = len(batch)
		_, err = tx.Exec(ctx, `UPDATE audit_forwarding SET last_id = $1, last_sent_at = now()`, batch[len(batch)-1].ID)
		return err
	})
	if err != nil {
		return 0, err
	}
	return sent, failed
}

// connect reuses the open connection while the settings are unchanged and
// the collector has not closed it.
func (s *Service) connect(ctx context.Context, d Destination, key string) error {
	if s.conn != nil && s.connKey == key && s.conn.alive() {
		return nil
	}
	s.closeConn()
	dctx, cancel := context.WithTimeout(ctx, dialTimeout)
	defer cancel()
	c, err := dial(dctx, d)
	if err != nil {
		return err
	}
	s.conn, s.connKey = c, key
	return nil
}

func (s *Service) closeConn() {
	if s.conn != nil {
		s.conn.close()
		s.conn, s.connKey = nil, ""
	}
}

func readAfter(ctx context.Context, tx pgx.Tx, after int64, limit int) ([]stored, error) {
	rows, err := tx.Query(ctx, `
		SELECT id, occurred_at, actor_type, actor_id, actor_label, organization_id, site_id, device_id,
		       action, target_type, target_id, outcome, source_ip, user_agent, details, prev_hash, entry_hash
		FROM audit_log WHERE id > $1 ORDER BY id LIMIT $2`, after, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []stored
	for rows.Next() {
		var e stored
		var actorType, outcome string
		var details []byte
		if err := rows.Scan(&e.ID, &e.OccurredAt, &actorType, &e.ActorID, &e.ActorLabel, &e.OrganizationID, &e.SiteID,
			&e.DeviceID, &e.Action, &e.TargetType, &e.TargetID, &outcome, &e.SourceIP, &e.UserAgent, &details,
			&e.prevHash, &e.entryHash); err != nil {
			return nil, err
		}
		e.ActorType, e.Outcome = audit.ActorType(actorType), audit.Outcome(outcome)
		if err := json.Unmarshal(details, &e.Details); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}
