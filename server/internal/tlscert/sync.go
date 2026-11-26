package tlscert

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"strings"
	"time"

	"github.com/caddyserver/certmagic"
	"github.com/jackc/pgx/v5"
	"github.com/mholt/acmez/v3/acme"

	"github.com/paulmataruso/easyrmm/server/internal/database"
)

var errNoCertificate = errors.New("tls: no certificate stored")

// readStored reads a name's certificate from storage: its leaf, and ARI as
// CertMagic's maintenance loop keeps it in the certificate's metadata.
func (s *Service) readStored(ctx context.Context, name string) (certInfo, error) {
	ik := s.issuerKey()
	crt, err := s.store.Load(ctx, certmagic.StorageKeys.SiteCert(ik, name))
	if errors.Is(err, fs.ErrNotExist) {
		return certInfo{}, errNoCertificate
	}
	if err != nil {
		return certInfo{}, err
	}
	b, _ := pem.Decode(crt)
	if b == nil {
		return certInfo{}, fmt.Errorf("tls: the stored certificate for %q is not PEM", name)
	}
	leaf, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		return certInfo{}, err
	}
	ci := certInfo{Serial: serialHex(leaf), Issuer: leaf.Issuer.CommonName, NotBefore: leaf.NotBefore, NotAfter: leaf.NotAfter}
	if meta, err := s.store.Load(ctx, certmagic.StorageKeys.SiteMeta(ik, name)); err == nil {
		var m struct {
			IssuerData json.RawMessage `json:"issuer_data"`
		}
		var ac acme.Certificate
		if json.Unmarshal(meta, &m) == nil && len(m.IssuerData) > 0 && json.Unmarshal(m.IssuerData, &ac) == nil && ac.RenewalInfo != nil {
			ci.AriStart, ci.AriEnd = ac.RenewalInfo.SuggestedWindow.Start, ac.RenewalInfo.SuggestedWindow.End
			ci.AriSelected, ci.AriExplanation = ac.RenewalInfo.SelectedTime, ac.RenewalInfo.ExplanationURL
		}
	}
	return ci, nil
}

func serialHex(c *x509.Certificate) string {
	if c.SerialNumber == nil {
		sum := sha256.Sum256(c.Raw)
		return hex.EncodeToString(sum[:8])
	}
	return c.SerialNumber.Text(16)
}

// syncName brings the row, CertMagic's cache and MeshCentral's slot in line
// with what storage holds for the name, which another server may have
// renewed.
func (s *Service) syncName(ctx context.Context, name string) error {
	ci, err := s.readStored(ctx, name)
	if err != nil {
		return err
	}
	now := s.deps.Now()
	prev, _ := s.loadRow(ctx, name)
	s.mu.Lock()
	have := s.cached[name]
	s.mu.Unlock()
	var cert certmagic.Certificate
	if have != ci.Serial {
		cert, err = s.magic.CacheManagedCertificate(ctx, name)
		if err != nil {
			return err
		}
		s.mu.Lock()
		s.cached[name] = ci.Serial
		s.mu.Unlock()
	}
	if err := s.storeCert(ctx, name, ci, false, now); err != nil {
		return err
	}
	if name == s.set.MeshName && !cert.Empty() {
		urgent := prev.AriMoved && !prev.AriEnd.IsZero() && !prev.AriEnd.After(now)
		s.slot.Offer(&cert.Certificate, ci.Serial, now, urgent)
		s.persistSlot(ctx, name)
	}
	return nil
}

// persistSlot writes the serial served and the one waiting for MeshCentral's name.
func (s *Service) persistSlot(ctx context.Context, name string) {
	served, pending, ready := s.slot.State()
	err := s.deps.DB.InTx(ctx, database.System, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE tls_certificates SET served_serial = nullif($2, ''), pending_serial = nullif($3, ''),
			pending_ready_at = CASE WHEN $3 = '' THEN NULL ELSE $4 END WHERE name = $1`, name, served, pending, ready)
		return err
	})
	if err != nil {
		s.deps.Log.Warn("tls: recording MeshCentral's certificate failed", "error", err)
	}
}

func (s *Service) lastMeshRead(ctx context.Context) (t time.Time, ok bool) {
	err := s.deps.DB.ReadTx(ctx, database.System, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT last_read_at FROM tls_mesh_reads WHERE instance = $1`, s.set.Instance).Scan(&t)
	})
	return t, err == nil
}

// RecordMeshRead notes a read of certUrl by MeshCentral, in memory and, so
// that a restart does not forget it, in the database.
func (s *Service) RecordMeshRead(t time.Time) {
	s.slot.RecordRead(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := s.deps.DB.InTx(ctx, database.System, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO tls_mesh_reads (instance, last_read_at) VALUES ($1, $2)
			ON CONFLICT (instance) DO UPDATE SET last_read_at = EXCLUDED.last_read_at`, s.set.Instance, t)
		return err
	})
	if err != nil {
		s.deps.Log.Debug("tls: recording MeshCentral's read failed", "error", err)
	}
}

// Run is the scheduler: every interval, in one server at a time (an advisory
// lock), it takes the names that need a certificate or a renewal and whose
// next attempt has come, and makes one attempt for each. It also listens for
// another server's NOTIFY and compares the serials in storage with those
// served, every minute and after every reconnection.
func (s *Service) Run(ctx context.Context) {
	select {
	case <-ctx.Done():
		return
	case <-s.serving:
	}
	s.mu.Lock()
	started := s.started
	s.mu.Unlock()
	if !started {
		return // Start failed: nothing is managed, and the log says why
	}
	go s.listen(ctx)
	lead := s.deps.DB.Leader(lockScheduler)
	defer lead.Close()
	t := time.NewTicker(s.set.Interval)
	defer t.Stop()
	for {
		s.tick(ctx, lead)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// lockScheduler is the advisory lock that makes one server the scheduler.
const lockScheduler int64 = 0x4561737952_4d4d02

func (s *Service) tick(ctx context.Context, lead interface {
	Lead(context.Context) (bool, error)
}) {
	// Everyone follows storage and applies MeshCentral's waiting certificate;
	// only the scheduler makes attempts.
	for _, n := range s.set.Names {
		if err := s.syncName(ctx, n); err != nil && !errors.Is(err, errNoCertificate) {
			s.deps.Log.Warn("tls: syncing a certificate failed", "name", n, "error", err)
		}
	}
	if s.slot.Tick(s.deps.Now()) && s.set.MeshName != "" {
		s.persistSlot(ctx, s.set.MeshName)
		s.deps.Log.Info("tls: applied the new certificate for MeshCentral's name")
	}
	if ok, err := lead.Lead(ctx); err != nil || !ok {
		if err != nil {
			s.deps.Log.Warn("tls: taking the scheduler's lock failed", "error", err)
		}
		return
	}
	if err := s.ensureAccount(ctx); err != nil {
		s.deps.Log.Warn("tls: the ACME account is not established; no attempt is made", "error", err)
		return
	}
	for _, n := range s.set.Names {
		if ctx.Err() != nil {
			return
		}
		s.consider(ctx, n)
	}
	for _, n := range s.set.Names {
		s.evaluate(ctx, n)
	}
}

// consider decides whether the scheduler makes an attempt for a name now.
func (s *Service) consider(ctx context.Context, name string) {
	row, err := s.loadRow(ctx, name)
	if err != nil {
		return
	}
	need := !row.HasCertificate()
	if !need {
		if cert, err := s.magic.CacheManagedCertificate(ctx, name); err == nil {
			need = cert.NeedsRenewal(s.magic)
		}
	}
	if !need {
		_ = s.setWaitingDNS(ctx, name, time.Time{})
		return
	}
	now := s.deps.Now()
	if now.Before(row.NextAttemptAt) || s.deps.Held() {
		return
	}
	if !row.OrderAnyway {
		if _, err := s.lookup(ctx, name); err != nil {
			_ = s.setWaitingDNS(ctx, name, now)
			return
		}
		_ = s.setWaitingDNS(ctx, name, time.Time{})
	}
	if err := s.attempt(ctx, name, kindScheduled); err != nil && !errors.Is(err, ErrBusy) {
		s.deps.Log.Debug("tls: a scheduled attempt did not succeed", "name", name, "error", err)
	}
}

// evaluate opens or resolves the alert of a name, on a change of level.
func (s *Service) evaluate(ctx context.Context, name string) {
	row, err := s.loadRow(ctx, name)
	if err != nil {
		return
	}
	level, reason := alertFor(row, s.deps.Now())
	if level == row.AlertLevel {
		return
	}
	ev := Event{Key: "tls:" + name, Name: name}
	if level == LevelNone {
		ev.Open = false
	} else {
		ev.Open, ev.Severity, ev.Summary, ev.LastError = true, level, fmt.Sprintf("The certificate for %s: %s", name, reason), row.LastError
	}
	s.publish(ctx, ev)
	if err := s.setAlertLevel(ctx, name, level); err != nil {
		s.deps.Log.Error("tls: recording an alert's level failed", "name", name, "error", err)
	}
}

// listen follows PostgreSQL's NOTIFY: another server stored a certificate.
// A notification is lost while the connection is down, so the scheduler's
// tick compares serials as well, which also runs after every reconnection.
func (s *Service) listen(ctx context.Context) {
	for ctx.Err() == nil {
		func() {
			c, err := s.deps.DB.Pool.Acquire(ctx)
			if err != nil {
				return
			}
			conn := c.Hijack()
			defer func() {
				cctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				_ = conn.Close(cctx)
			}()
			if _, err := conn.Exec(ctx, `LISTEN `+notifyChannel); err != nil {
				return
			}
			for _, n := range s.set.Names { // after a reconnection, compare at once
				_ = s.syncName(ctx, n)
			}
			for {
				note, err := conn.WaitForNotification(ctx)
				if err != nil {
					return
				}
				if s.Managed(note.Payload) {
					_ = s.syncName(ctx, note.Payload)
				}
			}
		}()
		select {
		case <-ctx.Done():
		case <-time.After(5 * time.Second):
		}
	}
}

// checkProbe answers a check's request: a token under a path of its own,
// only for a name being checked. Anything else goes on.
func checkKey(host string) string { return "easyrmm/check/" + strings.ToLower(host) }

func (s *Service) checkProbe(w http.ResponseWriter, r *http.Request, next func()) {
	const prefix = "/.well-known/easyrmm-check/"
	if !strings.HasPrefix(r.URL.Path, prefix) {
		next()
		return
	}
	token := strings.TrimPrefix(r.URL.Path, prefix)
	host := strings.ToLower(r.Host)
	if i := strings.LastIndex(host, ":"); i > 0 && !strings.HasSuffix(host, "]") {
		host = host[:i]
	}
	// The token is in storage, not in memory: `easyrmm-server tls check`
	// runs in a process of its own, and this one answers for it.
	if !s.Managed(host) {
		http.NotFound(w, r)
		return
	}
	want, err := s.store.Load(r.Context(), checkKey(host))
	if err != nil || string(want) != token {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/plain")
	_, _ = w.Write([]byte(token))
}

// CheckHandler wraps the console's handler so that the checks can find the
// server at its own ports (the path is served only for a name being checked).
func (s *Service) CheckHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.checkProbe(w, r, func() { next.ServeHTTP(w, r) })
	})
}
