// Package jobs is the script library and the jobs that run scripts on
// devices (ADR-0017): validation and permissions, delivery to agents
// through a signed long poll, results, cancellation and retention.
package jobs

import (
	"context"
	"crypto/ed25519"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/secrets"
	"github.com/paulmataruso/easyrmm/server/internal/winmod"
)

// Limits of scripts and jobs.
const (
	MaxBody        = 64 << 10
	MaxName        = 200
	MaxDescription = 2000
	MaxArgs        = 32
	MaxArgBytes    = 1024
	MinTimeout     = 1
	MaxTimeout     = 4 * 3600
	DefaultTimeout = 300
	// MaxDevices bounds the devices of one job.
	MaxDevices = 500
	// Waits for an offline device, in hours.
	MinWaitHours     = 1
	MaxWaitHours     = 7 * 24
	DefaultWaitHours = 24
	// MaxList bounds one list response.
	MaxList = 200
)

// Delivery timing.
const (
	// RedeliverAfter is how long a delivered run may stay unstarted before
	// it is delivered again.
	RedeliverAfter = 2 * time.Minute
	// DeadlineGrace is added to a run's timeout before it counts as lost.
	DeadlineGrace = 5 * time.Minute
	// CancelResend is how often a cancellation is repeated to the agent.
	CancelResend = time.Minute
	// SweepInterval is how often runs are expired and marked lost.
	SweepInterval = 30 * time.Second
)

// Run statuses.
const (
	StatusQueued    = "queued"
	StatusSent      = "sent"
	StatusRunning   = "running"
	StatusSucceeded = agentproto.RunSucceeded
	StatusFailed    = agentproto.RunFailed
	StatusTimedOut  = agentproto.RunTimedOut
	StatusCanceled  = agentproto.RunCanceled
	StatusExpired   = "expired"
	StatusLost      = "lost"
)

// Statuses lists every run status.
var Statuses = []string{StatusQueued, StatusSent, StatusRunning, StatusSucceeded, StatusFailed, StatusTimedOut, StatusCanceled, StatusExpired, StatusLost}

// Errors the agent API maps to responses.
var (
	// ErrRunNotFound is a run that does not exist or is not the device's.
	ErrRunNotFound = errors.New("jobs: no such run for this device")
	// ErrBadResult is a result the server cannot accept.
	ErrBadResult = errors.New("jobs: result not valid")
)

// Service manages scripts and jobs.
type Service struct {
	db        *database.DB
	audit     *audit.Logger
	key       ed25519.PrivateKey
	retention time.Duration
	// outputRetention is how long a run's output is kept after it arrived
	// (ADR-0063); the run stays for retention.
	outputRetention time.Duration
	log             *slog.Logger
	now             func() time.Time
	hub             *hub
	// pollWait is how long a poll without work is held; tests shorten it.
	pollWait time.Duration
	// stepUp checks a step-up proof for changes of the highest risk tier
	// (ADR-0055); nil until it is wired, when those changes are refused.
	stepUp StepUpVerifier
	// catalog, gate and sealer run the winmod kind (ADR-0073); without
	// them no winmod job is made.
	catalog *winmod.Catalog
	gate    ModuleGate
	sealer  *secrets.Sealer
}

// New returns a Service. key signs jobs; retention is how long finished jobs
// are kept, outputRetention how long their runs' output is.
func New(db *database.DB, auditLog *audit.Logger, key ed25519.PrivateKey, retention, outputRetention time.Duration, log *slog.Logger) *Service {
	return &Service{db: db, audit: auditLog, key: key, retention: retention, outputRetention: outputRetention, log: log,
		now: time.Now, hub: newHub(), pollWait: agentproto.PollWait}
}

// PublicKey is the job-signing public key in the form agents pin.
func (s *Service) PublicKey() string {
	return agentproto.EncodeKey(s.key.Public().(ed25519.PublicKey))
}

// Close releases every waiting poll, so the server can shut down without
// waiting for them.
func (s *Service) Close() { s.hub.close() }

// Run expires and marks lost runs, and removes output and jobs past
// retention, until ctx ends.
func (s *Service) Run(ctx context.Context) {
	tick := time.NewTicker(SweepInterval)
	defer tick.Stop()
	var lastPurge time.Time
	for {
		if _, err := s.Sweep(ctx); err != nil && ctx.Err() == nil {
			s.log.Error("jobs: sweeping runs failed", "error", err)
		}
		if _, err := s.QueueDailyChecks(ctx); err != nil && ctx.Err() == nil {
			s.log.Error("jobs: queueing daily hardening checks failed", "error", err)
		}
		if time.Since(lastPurge) >= time.Hour {
			if p, err := s.Purge(ctx); err != nil && ctx.Err() == nil {
				s.log.Error("jobs: retention failed", "error", err)
			} else if err == nil {
				lastPurge = time.Now()
				if p.Outputs > 0 {
					s.log.Info("jobs: removed output past retention", "count", p.Outputs, "retention", s.outputRetention.String())
				}
				if p.Jobs > 0 {
					s.log.Info("jobs: removed jobs past retention", "count", p.Jobs, "retention", s.retention.String())
				}
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

// Swept counts what a sweep changed.
type Swept struct {
	Expired int64
	Lost    int64
	// GuardsTimedOut counts Windows hardening guards whose confirmation did
	// not come: the computer's own timer undoes those changes.
	GuardsTimedOut int64
}

// Sweep expires runs no device picked up in time and marks lost the runs
// that started but never reported.
func (s *Service) Sweep(ctx context.Context) (Swept, error) {
	var out Swept
	err := s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		// A run held for a capability says which (ADR-0064); only job.pwsh
		// is required today.
		tag, err := tx.Exec(ctx, `UPDATE job_runs r SET status = 'expired', finished_at = now(),
				error = CASE `+heldSQL+`
					WHEN 'unable' THEN 'The device''s agent cannot run PowerShell 7 scripts, so the run waited until it expired. Update the agent.'
					WHEN 'unreported' THEN 'The device''s agent did not say whether it can run PowerShell 7 scripts before the run expired. Update the agent if this happens again.'
					ELSE 'The device did not pick up the job before it expired.' END
			FROM jobs j, devices d
			WHERE j.id = r.job_id AND d.id = r.device_id AND r.status IN ('queued', 'sent') AND r.expires_at <= now()`)
		if err != nil {
			return err
		}
		out.Expired = tag.RowsAffected()
		tag, err = tx.Exec(ctx, `UPDATE job_runs SET status = 'lost', finished_at = now(),
				error = 'The device did not report a result before the deadline.'
			WHERE status = 'running' AND deadline_at <= now()`)
		out.Lost = tag.RowsAffected()
		if err != nil {
			return err
		}
		// A secret is never held waiting: it goes at expiry, or when no run of
		// its job is open (ADR-0073).
		if _, err = tx.Exec(ctx, `DELETE FROM winmod_job_secrets s WHERE s.expires_at <= now()
			OR NOT EXISTS (SELECT 1 FROM job_runs r WHERE r.job_id = s.job_id AND r.status IN ('queued', 'sent', 'running'))`); err != nil {
			return err
		}
		out.GuardsTimedOut, err = s.timeOutGuards(ctx, tx)
		return err
	})
	return out, err
}

// Purged counts what a purge removed.
type Purged struct {
	// Outputs is how many runs had their output emptied.
	Outputs int64
	// Jobs is how many jobs were removed with their runs.
	Jobs int64
}

// Purge empties output that arrived longer ago than the output retention,
// and removes jobs older than the retention whose runs have all finished.
func (s *Service) Purge(ctx context.Context) (Purged, error) {
	var p Purged
	err := s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE job_runs SET `+emptyOutput+`
			WHERE output_stored_at < now() - make_interval(secs => $1)`, s.outputRetention.Seconds())
		if err != nil {
			return err
		}
		p.Outputs = tag.RowsAffected()
		tag, err = tx.Exec(ctx, `DELETE FROM jobs j WHERE j.created_at < now() - make_interval(secs => $1)
			AND NOT EXISTS (SELECT 1 FROM job_runs r WHERE r.job_id = j.id AND r.status IN ('queued', 'sent', 'running'))`,
			s.retention.Seconds())
		if err != nil {
			return err
		}
		p.Jobs = tag.RowsAffected()
		// Daily checks are kept for seven days only (ADR-0054's amendment
		// of ADR-0017); the last result per device and module stays.
		tag, err = tx.Exec(ctx, `DELETE FROM jobs j WHERE j.batch_id IS NOT NULL AND j.created_at < now() - make_interval(secs => $1)
			AND NOT EXISTS (SELECT 1 FROM job_runs r WHERE r.job_id = j.id AND r.status IN ('queued', 'sent', 'running'))`,
			DailyCheckRetention.Seconds())
		if err != nil {
			return err
		}
		p.Jobs += tag.RowsAffected()
		// A winmod job, its params and its typed result go after the time
		// its action says: an hour for a read, days for a change, minutes
		// for a sensitive result. The audit rows stay (ADR-0073).
		tag, err = tx.Exec(ctx, `DELETE FROM jobs j WHERE j.kind = 'winmod'
			AND j.created_at < now() - make_interval(secs => (j.winmod->>'keepSeconds')::int)
			AND NOT EXISTS (SELECT 1 FROM job_runs r WHERE r.job_id = j.id AND r.status IN ('queued', 'sent', 'running'))`)
		if err != nil {
			return err
		}
		p.Jobs += tag.RowsAffected()
		return nil
	})
	return p, err
}

// hub wakes the polls of devices that have new work on this instance.
type hub struct {
	mu      sync.Mutex
	waiters map[uuid.UUID]map[chan struct{}]struct{}
	done    chan struct{}
	closed  bool
}

func newHub() *hub {
	return &hub{waiters: map[uuid.UUID]map[chan struct{}]struct{}{}, done: make(chan struct{})}
}

// subscribe returns a channel that receives when the device has work.
func (h *hub) subscribe(device uuid.UUID) chan struct{} {
	ch := make(chan struct{}, 1)
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.waiters[device] == nil {
		h.waiters[device] = map[chan struct{}]struct{}{}
	}
	h.waiters[device][ch] = struct{}{}
	return ch
}

func (h *hub) unsubscribe(device uuid.UUID, ch chan struct{}) {
	h.mu.Lock()
	defer h.mu.Unlock()
	delete(h.waiters[device], ch)
	if len(h.waiters[device]) == 0 {
		delete(h.waiters, device)
	}
}

// notify wakes the devices' polls.
func (h *hub) notify(devices ...uuid.UUID) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, d := range devices {
		for ch := range h.waiters[d] {
			select {
			case ch <- struct{}{}:
			default:
			}
		}
	}
}

func (h *hub) close() {
	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.closed {
		h.closed = true
		close(h.done)
	}
}

// cleanText removes NUL and other control characters except tab and line
// breaks, repairs UTF-8 and trims, for names and descriptions.
func cleanText(s string, keepNewlines bool) string {
	s = strings.ToValidUTF8(s, "�")
	s = strings.Map(func(r rune) rune {
		if r == '\t' || (keepNewlines && r == '\n') {
			return r
		}
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, s)
	return strings.TrimSpace(s)
}

// cleanOutput makes a stream storable: valid UTF-8 without NUL, at most
// agentproto.MaxStreamBytes. It reports whether it had to cut it.
func cleanOutput(s string) (string, bool) {
	s = strings.ToValidUTF8(s, "�")
	s = strings.ReplaceAll(s, "\x00", "")
	if len(s) <= agentproto.MaxStreamBytes {
		return s, false
	}
	cut := agentproto.MaxStreamBytes
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut], true
}

// truncateRunes cuts s to at most n runes.
func truncateRunes(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	return string([]rune(s)[:n])
}
