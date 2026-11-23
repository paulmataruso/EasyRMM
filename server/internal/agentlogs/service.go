// Package agentlogs keeps what devices' agents log (ADR-0069, Part L): the
// records the EasyRMM agent sends, its own and those it reads from the
// EasyPatch agent's log and MeshAgent's; the verbose mode a technician
// turns on for a device or a group; who is watching a device's logs; and
// the retention that removes old records. Reading needs log.view, turning
// verbose mode on or off device.edit.
package agentlogs

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/internal/logredact"
	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/database"
)

// Limits.
const (
	// DailyCap is the most records one device stores in a UTC day.
	DailyCap = 200_000
	// MinRetentionDays and MaxRetentionDays bound the deployment setting
	// EASYRMM_AGENT_LOG_RETENTION_DAYS; DefaultRetentionDays is its default.
	MinRetentionDays     = 1
	MaxRetentionDays     = 90
	DefaultRetentionDays = 14
	// FollowFor is how long a read by the console keeps the agent sending
	// every two seconds: a little longer than the console's refresh.
	FollowFor = 20 * time.Second
	// purgeBatch is how many records one delete removes.
	purgeBatch = 5000
)

// ErrBadBatch is a batch the server cannot read.
var ErrBadBatch = errors.New("agentlogs: not a valid batch of log records")

// Service stores and reads agent logs.
type Service struct {
	db        *database.DB
	audit     *audit.Logger
	retention time.Duration
	log       *slog.Logger
}

// New builds the service. Records are kept retentionDays days, which New
// keeps within MinRetentionDays and MaxRetentionDays.
func New(db *database.DB, auditLog *audit.Logger, retentionDays int, log *slog.Logger) *Service {
	days := min(max(retentionDays, MinRetentionDays), MaxRetentionDays)
	return &Service{db: db, audit: auditLog, retention: time.Duration(days) * 24 * time.Hour, log: log}
}

// levels orders the levels.
var levels = map[string]int{agentproto.LogDebug: 0, agentproto.LogInfo: 1, agentproto.LogWarn: 2, agentproto.LogError: 3}

// sources are the sources a record may name.
var sources = map[string]bool{agentproto.LogSourceAgent: true, agentproto.LogSourceEasyPatch: true, agentproto.LogSourceMeshAgent: true}

// clean is a record as stored.
type clean struct {
	seq     int64
	source  string
	at      time.Time
	level   string
	message string
	attrs   string // JSON
}

// text cuts s to at most max bytes at a character boundary, and removes
// what PostgreSQL cannot store in text.
func text(s string, max int) string {
	s = strings.ToValidUTF8(strings.ReplaceAll(s, "\x00", ""), "�")
	if len(s) <= max {
		return s
	}
	s = s[:max]
	for !utf8.ValidString(s) {
		s = s[:len(s)-1]
	}
	return s
}

// cleanRecord applies the server's rules to a record: its time within a
// sane range, the level and source it knows, bounded text, and the
// redaction the agent applied, again.
func cleanRecord(r agentproto.LogRecord, now time.Time) clean {
	c := clean{seq: r.Seq, source: r.Source, level: strings.ToLower(r.Level), at: r.Time.UTC()}
	if !sources[c.source] {
		c.source = agentproto.LogSourceAgent
	}
	if _, ok := levels[c.level]; !ok {
		c.level = agentproto.LogInfo
	}
	if c.at.IsZero() || c.at.After(now.Add(5*time.Minute)) || c.at.Before(now.Add(-30*24*time.Hour)) {
		c.at = now
	}
	c.message = logredact.Text(text(r.Message, agentproto.MaxLogMessage))
	attrs := map[string]string{}
	for k, v := range r.Attrs {
		if len(attrs) >= agentproto.MaxLogAttributes {
			break
		}
		k = text(k, agentproto.MaxLogAttrName)
		if k == "" {
			continue
		}
		attrs[k] = logredact.Attr(k, text(v, agentproto.MaxLogAttrValue))
	}
	c.attrs = jsonObject(attrs)
	return c
}

// jsonObject encodes strings as a JSON object; a map of strings always
// encodes.
func jsonObject(m map[string]string) string {
	b, _ := json.Marshal(m)
	return string(b)
}

// Ingest stores a batch of a device's records and returns what the agent
// needs back: the highest sequence the server has taken care of, stored,
// stored before or refused (the agent drops every record up to it), and the
// device's logging instructions. A record already stored is kept once; the
// device stores at most DailyCap records a UTC day, and says in a record of
// the server's own how many it refused and how many the agent dropped.
func (s *Service) Ingest(ctx context.Context, deviceID uuid.UUID, b agentproto.LogBatch) (agentproto.LogAck, error) {
	if len(b.Records) > agentproto.MaxLogBatch || b.Dropped < 0 {
		return agentproto.LogAck{}, ErrBadBatch
	}
	var ack agentproto.LogAck
	for _, r := range b.Records {
		if r.Seq < 0 {
			return agentproto.LogAck{}, ErrBadBatch
		}
		ack.Seq = max(ack.Seq, r.Seq)
	}
	err := s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		var now time.Time
		var day time.Time
		if err := tx.QueryRow(ctx, `SELECT now(), (now() AT TIME ZONE 'UTC')::date`).Scan(&now, &day); err != nil {
			return err
		}
		// The device's row for the day, locked so that two batches count in turn.
		var stored int
		if err := tx.QueryRow(ctx, `INSERT INTO agent_log_days (device_id, day) VALUES ($1, $2)
			ON CONFLICT (device_id, day) DO UPDATE SET device_id = excluded.device_id
			RETURNING stored`, deviceID, day).Scan(&stored); err != nil {
			return err
		}
		room := max(DailyCap-stored, 0)
		recs := b.Records
		refused := 0
		if len(recs) > room {
			refused = len(recs) - room
			recs = recs[:room]
		}
		inserted := 0
		if len(recs) > 0 {
			n, err := insert(ctx, tx, deviceID, recs, now)
			if err != nil {
				return err
			}
			inserted = n
		}
		var notes []string
		if b.Dropped > 0 {
			notes = append(notes, fmt.Sprintf("%d log records were dropped on the device before they could be sent: its buffer was full.", b.Dropped))
		}
		if refused > 0 {
			notes = append(notes, fmt.Sprintf("%d log records were not stored: the device passed its limit of %d records a day.", refused, DailyCap))
		}
		for _, n := range notes {
			if _, err := tx.Exec(ctx, `INSERT INTO agent_log_records (device_id, seq, source, logged_at, level, message)
				VALUES ($1, -1, 'agent', $2, 'warn', $3)`, deviceID, now, n); err != nil {
				return err
			}
		}
		if _, err := tx.Exec(ctx, `UPDATE agent_log_days SET stored = stored + $3, refused = refused + $4
			WHERE device_id = $1 AND day = $2`, deviceID, day, inserted, refused); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return agentproto.LogAck{}, fmt.Errorf("agentlogs: storing a batch: %w", err)
	}
	ack.Logs, err = s.Instructions(ctx, deviceID)
	return ack, err
}

// insert stores recs and returns how many were new.
func insert(ctx context.Context, tx pgx.Tx, deviceID uuid.UUID, recs []agentproto.LogRecord, now time.Time) (int, error) {
	n := len(recs)
	seqs, srcs, ats, lvls, msgs, attrs := make([]int64, 0, n), make([]string, 0, n), make([]time.Time, 0, n),
		make([]string, 0, n), make([]string, 0, n), make([]string, 0, n)
	for _, r := range recs {
		c := cleanRecord(r, now)
		seqs, srcs, ats, lvls, msgs, attrs = append(seqs, c.seq), append(srcs, c.source), append(ats, c.at),
			append(lvls, c.level), append(msgs, c.message), append(attrs, c.attrs)
	}
	// In sequence order, so that ids rise with it.
	tag, err := tx.Exec(ctx, `INSERT INTO agent_log_records (device_id, seq, source, logged_at, level, message, attrs)
		SELECT $1, t.seq, t.source, t.at, t.level, t.message, t.attrs::jsonb
		FROM unnest($2::bigint[], $3::text[], $4::timestamptz[], $5::text[], $6::text[], $7::text[])
			WITH ORDINALITY AS t(seq, source, at, level, message, attrs, n)
		ORDER BY t.seq, t.n
		ON CONFLICT (device_id, seq) WHERE seq >= 0 DO NOTHING`, deviceID, seqs, srcs, ats, lvls, msgs, attrs)
	return int(tag.RowsAffected()), err
}

// Instructions returns how the device's agent should log: verbose until
// the latest end of the device's own verbose mode and its group's, and
// following while someone watches. Nil when neither applies.
func (s *Service) Instructions(ctx context.Context, deviceID uuid.UUID) (*agentproto.LogInstructions, error) {
	var verbose, follow *time.Time
	err := s.db.ReadTx(ctx, database.System, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT
			(SELECT max(v.until) FROM agent_log_verbose v WHERE v.until > now()
				AND (v.device_id = $1 OR v.group_id = (SELECT device_group_id FROM devices WHERE id = $1))),
			(SELECT f.until FROM agent_log_follow f WHERE f.device_id = $1 AND f.until > now())`, deviceID).Scan(&verbose, &follow)
	})
	if err != nil {
		return nil, fmt.Errorf("agentlogs: reading instructions: %w", err)
	}
	if verbose == nil && follow == nil {
		return nil, nil
	}
	out := &agentproto.LogInstructions{}
	if verbose != nil {
		out.VerboseUntil = verbose.Unix()
	}
	if follow != nil {
		out.FollowUntil = follow.Unix()
	}
	return out, nil
}

// Purge deletes records past the retention, in batches of its own so that
// no delete holds many rows, and the day counts, ended verbose modes and
// follows with them.
func (s *Service) Purge(ctx context.Context) error {
	var total int64
	for {
		var n int64
		err := s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
			tag, err := tx.Exec(ctx, `DELETE FROM agent_log_records WHERE id IN
				(SELECT id FROM agent_log_records WHERE received_at < now() - $1::interval ORDER BY id LIMIT $2)`,
				s.retention, purgeBatch)
			n = tag.RowsAffected()
			return err
		})
		if err != nil {
			return fmt.Errorf("agentlogs: removing records: %w", err)
		}
		total += n
		if n < purgeBatch {
			break
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
	}
	err := s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `DELETE FROM agent_log_days WHERE day < ((now() - $1::interval) AT TIME ZONE 'UTC')::date`, s.retention); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM agent_log_verbose WHERE until < now() - interval '1 day'`); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `DELETE FROM agent_log_follow WHERE until < now() - interval '1 hour'`)
		return err
	})
	if err != nil {
		return fmt.Errorf("agentlogs: removing day counts: %w", err)
	}
	if total > 0 {
		s.log.Info("agent logs: removed records past retention", "count", total, "retention", s.retention.String())
	}
	return nil
}
