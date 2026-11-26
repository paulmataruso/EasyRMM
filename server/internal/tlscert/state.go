package tlscert

import (
	"context"
	"errors"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/server/internal/database"
)

// Row is what EasyRMM keeps of one name (tls_certificates).
type Row struct {
	Name            string
	Serial          string
	Issuer          string
	NotBefore       time.Time
	NotAfter        time.Time
	AriStart        time.Time
	AriEnd          time.Time
	AriSelected     time.Time
	AriExplanation  string
	NextAttemptAt   time.Time
	FailedAt        []time.Time
	FailingSince    time.Time
	LastError       string
	LastAttemptAt   time.Time
	LastAttemptKind string
	Failures        int
	WaitingDNSSince time.Time
	OrderAnyway     bool
	Imported        bool
	ServedSerial    string
	PendingSerial   string
	PendingReadyAt  time.Time
	MissingSince    time.Time
	AriMoved        bool
	AlertLevel      string
}

// HasCertificate reports whether a certificate is known for the name.
func (r Row) HasCertificate() bool { return r.Serial != "" }

const rowColumns = `name, coalesce(serial, ''), coalesce(issuer, ''), not_before, not_after, ari_start, ari_end, ari_selected,
	coalesce(ari_explanation, ''), next_attempt_at, failed_at, failing_since, coalesce(last_error, ''), last_attempt_at,
	coalesce(last_attempt_kind, ''), failures, waiting_dns_since, order_anyway, imported, coalesce(served_serial, ''),
	coalesce(pending_serial, ''), pending_ready_at, missing_since, ari_moved, alert_level`

func scanRow(r pgx.Row) (Row, error) {
	var x Row
	var nb, na, as, ae, asel, fs, la, wd, pr *time.Time
	err := r.Scan(&x.Name, &x.Serial, &x.Issuer, &nb, &na, &as, &ae, &asel, &x.AriExplanation, &x.NextAttemptAt, &x.FailedAt, &fs,
		&x.LastError, &la, &x.LastAttemptKind, &x.Failures, &wd, &x.OrderAnyway, &x.Imported, &x.ServedSerial, &x.PendingSerial, &pr,
		&x.MissingSince, &x.AriMoved, &x.AlertLevel)
	if err != nil {
		return x, err
	}
	set := func(dst *time.Time, src *time.Time) {
		if src != nil {
			*dst = *src
		}
	}
	set(&x.NotBefore, nb)
	set(&x.NotAfter, na)
	set(&x.AriStart, as)
	set(&x.AriEnd, ae)
	set(&x.AriSelected, asel)
	set(&x.FailingSince, fs)
	set(&x.LastAttemptAt, la)
	set(&x.WaitingDNSSince, wd)
	set(&x.PendingReadyAt, pr)
	return x, nil
}

func nz(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}

// ErrNoName is returned for a name EasyRMM does not manage.
var ErrNoName = errors.New("tls: no such name")

func (s *Service) loadRow(ctx context.Context, name string) (Row, error) {
	var r Row
	err := s.deps.DB.ReadTx(ctx, database.System, func(tx pgx.Tx) error {
		var err error
		r, err = scanRow(tx.QueryRow(ctx, `SELECT `+rowColumns+` FROM tls_certificates WHERE name = $1`, name))
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return r, ErrNoName
	}
	return r, err
}

func (s *Service) loadRows(ctx context.Context) ([]Row, error) {
	var out []Row
	err := s.deps.DB.ReadTx(ctx, database.System, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+rowColumns+` FROM tls_certificates ORDER BY name`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			r, err := scanRow(rows)
			if err != nil {
				return err
			}
			out = append(out, r)
		}
		return rows.Err()
	})
	return out, err
}

// ensureRows creates a row for each managed name and drops those of names
// the environment no longer lists, returning the dropped ones.
func (s *Service) ensureRows(ctx context.Context, names []string) (dropped []string, err error) {
	err = s.deps.DB.InTx(ctx, database.System, func(tx pgx.Tx) error {
		for _, n := range names {
			if _, err := tx.Exec(ctx, `INSERT INTO tls_certificates (name) VALUES ($1) ON CONFLICT DO NOTHING`, n); err != nil {
				return err
			}
		}
		rows, err := tx.Query(ctx, `DELETE FROM tls_certificates WHERE NOT (name = ANY($1)) RETURNING name`, names)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var n string
			if err := rows.Scan(&n); err != nil {
				return err
			}
			dropped = append(dropped, n)
		}
		return rows.Err()
	})
	return dropped, err
}

// certInfo is what is read from a stored certificate.
type certInfo struct {
	Serial, Issuer      string
	NotBefore, NotAfter time.Time
	AriStart, AriEnd    time.Time
	AriSelected         time.Time
	AriExplanation      string
}

// storeCert records the certificate in storage as the name's current one.
// A success clears the failures and the alert's reason. The ARI window that
// moved earlier is noted for the alert.
func (s *Service) storeCert(ctx context.Context, name string, ci certInfo, imported bool, now time.Time) error {
	return s.deps.DB.InTx(ctx, database.System, func(tx pgx.Tx) error {
		var oldSerial string
		var oldStart *time.Time
		if err := tx.QueryRow(ctx, `SELECT coalesce(serial, ''), ari_start FROM tls_certificates WHERE name = $1 FOR UPDATE`, name).Scan(&oldSerial, &oldStart); err != nil {
			return err
		}
		sameCert := oldSerial == ci.Serial
		moved := sameCert && oldStart != nil && !ci.AriStart.IsZero() && ci.AriStart.Before(*oldStart)
		if sameCert && !moved {
			// Only ARI (or nothing) changed.
			_, err := tx.Exec(ctx, `UPDATE tls_certificates SET ari_start = $2, ari_end = $3, ari_selected = $4, ari_explanation = $5, updated_at = now() WHERE name = $1`,
				name, nz(ci.AriStart), nz(ci.AriEnd), nz(ci.AriSelected), ci.AriExplanation)
			return err
		}
		if sameCert {
			_, err := tx.Exec(ctx, `UPDATE tls_certificates SET ari_start = $2, ari_end = $3, ari_selected = $4, ari_explanation = $5,
				ari_moved = true, updated_at = now() WHERE name = $1`, name, nz(ci.AriStart), nz(ci.AriEnd), nz(ci.AriSelected), ci.AriExplanation)
			return err
		}
		_, err := tx.Exec(ctx, `UPDATE tls_certificates SET serial = $2, issuer = $3, not_before = $4, not_after = $5,
			ari_start = $6, ari_end = $7, ari_selected = $8, ari_explanation = $9,
			failures = 0, failed_at = '{}', failing_since = NULL, last_error = NULL, waiting_dns_since = NULL,
			order_anyway = false, ari_moved = false, imported = $10, next_attempt_at = $11, updated_at = now() WHERE name = $1`,
			name, ci.Serial, ci.Issuer, ci.NotBefore, ci.NotAfter, nz(ci.AriStart), nz(ci.AriEnd), nz(ci.AriSelected), ci.AriExplanation, imported, now)
		return err
	})
}

// recordAttempt notes that an attempt starts.
func (s *Service) recordAttempt(ctx context.Context, name, kind string, now time.Time) error {
	return s.deps.DB.InTx(ctx, database.System, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE tls_certificates SET last_attempt_at = $2, last_attempt_kind = $3, updated_at = now() WHERE name = $1`, name, now, kind)
		return err
	})
}

// recordFailure notes a failed attempt: the time of the next, the failures of
// the last hour, and when the name began to fail.
func (s *Service) recordFailure(ctx context.Context, name, reason string, now time.Time) (Row, error) {
	var out Row
	err := s.deps.DB.InTx(ctx, database.System, func(tx pgx.Tx) error {
		r, err := scanRow(tx.QueryRow(ctx, `SELECT `+rowColumns+` FROM tls_certificates WHERE name = $1 FOR UPDATE`, name))
		if err != nil {
			return err
		}
		failed := append(pruneHour(r.FailedAt, now), now)
		fails := r.Failures + 1
		since := r.FailingSince
		if since.IsZero() {
			since = now
		}
		_, w := renewalWindow(r)
		next := now.Add(retryDelay(fails, w))
		if _, err := tx.Exec(ctx, `UPDATE tls_certificates SET failures = $2, failed_at = $3, failing_since = $4, last_error = $5,
			next_attempt_at = $6, updated_at = now() WHERE name = $1`, name, fails, failed, since, clip(reason, 1000), next); err != nil {
			return err
		}
		r.Failures, r.FailedAt, r.FailingSince, r.LastError, r.NextAttemptAt = fails, failed, since, clip(reason, 1000), next
		out = r
		return nil
	})
	return out, err
}

func (s *Service) setWaitingDNS(ctx context.Context, name string, since time.Time) error {
	return s.deps.DB.InTx(ctx, database.System, func(tx pgx.Tx) error {
		if since.IsZero() {
			_, err := tx.Exec(ctx, `UPDATE tls_certificates SET waiting_dns_since = NULL WHERE name = $1 AND waiting_dns_since IS NOT NULL`, name)
			return err
		}
		_, err := tx.Exec(ctx, `UPDATE tls_certificates SET waiting_dns_since = $2 WHERE name = $1 AND waiting_dns_since IS NULL`, name, since)
		return err
	})
}

func clip(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}

// pruneHour keeps the failures of the last hour.
func pruneHour(in []time.Time, now time.Time) []time.Time {
	out := make([]time.Time, 0, len(in)+1)
	for _, t := range in {
		if now.Sub(t) < time.Hour {
			out = append(out, t)
		}
	}
	slices.SortFunc(out, func(a, b time.Time) int { return a.Compare(b) })
	return out
}

// Failure budget (ADR-0055): automatic attempts stop after 3 failed
// validations of a name within an hour; Retry now stops at 4, since Let's
// Encrypt allows 5.
const (
	autoBudget  = 3
	retryBudget = 4
)

// withinBudget reports whether another attempt may start, and when it could
// otherwise: the moment the failures of the last hour fall below the limit.
func withinBudget(failed []time.Time, limit int, now time.Time) (ok bool, retryAt time.Time) {
	recent := pruneHour(failed, now)
	if len(recent) < limit {
		return true, time.Time{}
	}
	// The (len-limit+1)th oldest failure must age out.
	return false, recent[len(recent)-limit].Add(time.Hour)
}

// retryDelay follows Let's Encrypt's guide: after 1, 10 and 100 minutes,
// then once a day, each wait capped at a tenth of the renewal window so that
// a short-lived certificate still gets several attempts.
func retryDelay(failures int, window time.Duration) time.Duration {
	waits := []time.Duration{time.Minute, 10 * time.Minute, 100 * time.Minute}
	d := 24 * time.Hour
	if failures >= 1 && failures <= len(waits) {
		d = waits[failures-1]
	}
	if window > 0 {
		d = min(d, max(window/10, time.Second))
	}
	return d
}

// renewalWindow returns when renewal became due (the start of ARI's window,
// or two thirds of the lifetime) and W, the time from then to expiry. All
// thresholds are fractions of W, so they hold for any lifetime.
func renewalWindow(r Row) (due time.Time, w time.Duration) {
	if r.NotAfter.IsZero() {
		return time.Time{}, 0
	}
	life := r.NotAfter.Sub(r.NotBefore)
	due = r.NotAfter.Add(-life / 3)
	if !r.AriStart.IsZero() && r.AriStart.Before(r.NotAfter) {
		due = r.AriStart
		if due.Before(r.NotBefore) {
			due = r.NotBefore
		}
	}
	return due, r.NotAfter.Sub(due)
}

// Alert levels.
const (
	LevelNone     = "none"
	LevelWarning  = "warning"
	LevelCritical = "critical"
)

// alertFor says whether a name needs a warning or is critical, and why.
func alertFor(r Row, now time.Time) (level, reason string) {
	if !r.HasCertificate() {
		if now.Sub(r.MissingSince) >= time.Hour {
			if !r.WaitingDNSSince.IsZero() {
				return LevelWarning, "no certificate for an hour: the name does not resolve on this server"
			}
			return LevelWarning, "no certificate for an hour: orders are failing"
		}
		return LevelNone, ""
	}
	if !now.Before(r.NotAfter) {
		return LevelCritical, "the certificate has expired"
	}
	due, w := renewalWindow(r)
	if w > 0 && r.NotAfter.Sub(now) < w/4 {
		return LevelCritical, "less than a quarter of the renewal window is left"
	}
	if !r.FailingSince.IsZero() && r.AriMoved {
		return LevelCritical, "the renewal fails after the CA moved its renewal window earlier"
	}
	if !r.FailingSince.IsZero() && w > 0 && now.After(due) {
		if now.Sub(r.FailingSince) >= min(w/4, 24*time.Hour) {
			return LevelWarning, "the renewal keeps failing"
		}
	}
	if r.PendingSerial != "" && now.Sub(r.PendingReadyAt) > meshCap {
		return LevelWarning, "a new certificate is still not applied for MeshCentral's name"
	}
	return LevelNone, ""
}

func (s *Service) setAlertLevel(ctx context.Context, name, level string) error {
	return s.deps.DB.InTx(ctx, database.System, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE tls_certificates SET alert_level = $2 WHERE name = $1`, name, level)
		return err
	})
}
