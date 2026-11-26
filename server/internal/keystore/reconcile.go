package keystore

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/devscope"
	"github.com/paulmataruso/easyrmm/server/internal/mailer"
)

// Reconciliation of the keystore's own log against the server's audit
// (ADR-0081 section 7, decided in review). Every hour the server reads the
// keystore's log since its cursor, checks the hash chain, and requires each
// entry that returned a key to be accounted for by audit records carrying its
// request ID. A key that left with no audit record, or more of them than the
// audit holds, means someone with the server process asked the keystore for a
// key without the process the console controls: a critical alert.
const (
	// ReconcileEvery is how often the job runs.
	ReconcileEvery = time.Hour
	// ReconcileGrace leaves an entry alone this long, since the audit record of
	// a read is committed just after the keystore answers.
	ReconcileGrace = 2 * time.Minute
	reconcilePage  = 500

	AlertUnauditedRead = "unaudited_read"
	AlertLogChain      = "keystore_log_broken"
	AlertReadLimit     = "read_limit"
)

// Report is what one reconciliation found.
type Report struct {
	Entries   int
	Reads     int
	Mismatch  int
	ChainOK   bool
	Checked   bool
	LastSeq   int64
	Unaudited []string
}

// Reconcile runs one pass. It reads the keystore's log in pages until it
// reaches an entry younger than ReconcileGrace or the end.
func (s *Service) Reconcile(ctx context.Context) (Report, error) {
	rep := Report{ChainOK: true}
	if s.ks == nil {
		return rep, nil
	}
	var seq int64
	var hash string
	if err := s.db.ReadTx(ctx, database.System, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT last_seq, last_hash FROM keystore_log_cursor WHERE id`).Scan(&seq, &hash)
	}); err != nil {
		return rep, err
	}
	for {
		page, err := s.ks.Log(ctx, seq, reconcilePage)
		var re *RemoteError
		if errors.As(err, &re) && re.Code == CodeLogBroken {
			// The keystore itself found its log damaged.
			rep.ChainOK = false
			return rep, s.logBroken(ctx)
		}
		if err != nil {
			return rep, err
		}
		rep.Checked = true
		if len(page.Entries) == 0 {
			break
		}
		// The page must continue the chain from where the last run stopped
		// (an empty hash at the very start).
		if page.Prev != hash {
			rep.ChainOK = false
		} else if _, _, err := VerifyLog(hash, seq, page.Entries); err != nil {
			rep.ChainOK = false
		}
		if !rep.ChainOK {
			return rep, s.logBroken(ctx)
		}
		// Only entries past the grace period count this time.
		var ready []LogEntry
		for _, e := range page.Entries {
			if s.now().Sub(e.At) < ReconcileGrace {
				break
			}
			ready = append(ready, e)
		}
		if err := s.reconcileEntries(ctx, ready, &rep); err != nil {
			return rep, err
		}
		if len(ready) > 0 {
			last := ready[len(ready)-1]
			seq, hash = last.Seq, last.Hash
			if err := s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
				_, err := tx.Exec(ctx, `UPDATE keystore_log_cursor SET last_seq = $1, last_hash = $2, reconciled_at = now() WHERE id`, seq, hash)
				return err
			}); err != nil {
				return rep, err
			}
		}
		if len(ready) < len(page.Entries) || len(page.Entries) < reconcilePage {
			break
		}
	}
	rep.LastSeq = seq
	return rep, nil
}

// logBroken raises the critical alert of a log whose chain does not hold.
func (s *Service) logBroken(ctx context.Context) error {
	created, err := s.raiseAlert(ctx, nil, AlertLogChain, "critical", "keystore",
		"The keystore's own log does not verify: a line was changed, removed or added after the fact. Reads cannot be reconciled until a person looks at the keystore host.")
	if created {
		s.notifyAdmins(ctx, uuid.Nil, "Critical: the keystore's log does not verify", "The keystore's own log does not verify. See the keystore page in the console.")
	}
	return err
}

func (s *Service) reconcileEntries(ctx context.Context, entries []LogEntry, rep *Report) error {
	rep.Entries += len(entries)
	byRID := map[string][]LogEntry{}
	for _, e := range entries {
		if e.Op == OpReadEscrow && e.Plaintext {
			rep.Reads++
			byRID[e.RequestID] = append(byRID[e.RequestID], e)
		}
	}
	if len(byRID) == 0 {
		return nil
	}
	rids := make([]string, 0, len(byRID))
	for r := range byRID {
		rids = append(rids, r)
	}
	counts := map[string]int{}
	err := s.db.ReadTx(ctx, database.System, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT details->>'requestId', count(*) FROM audit_log
			WHERE action = $1 AND details->>'requestId' = ANY($2) GROUP BY 1`, ActionRead, rids)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var rid string
			var n int
			if err := rows.Scan(&rid, &n); err != nil {
				return err
			}
			counts[rid] = n
		}
		return rows.Err()
	})
	if err != nil {
		return err
	}
	for rid, es := range byRID {
		if len(es) <= counts[rid] {
			continue
		}
		rep.Mismatch++
		rep.Unaudited = append(rep.Unaudited, rid)
		org, perr := uuid.Parse(es[0].Org)
		if perr != nil || !devscope.Allowed(org) {
			if perr == nil {
				continue // an organization outside the dev scope gets no alert
			}
			org = uuid.Nil
		}
		var op *uuid.UUID
		if org != uuid.Nil {
			op = &org
		}
		detail := fmt.Sprintf("The keystore returned a recovery key (request %s, record %s) that the server's audit log does not account for (%d returned, %d audited). Someone with the server process asked the keystore for a key without the console.",
			rid, es[0].Record, len(es), counts[rid])
		created, err := s.raiseAlert(ctx, op, AlertUnauditedRead, "critical", rid, detail)
		if err != nil {
			return err
		}
		if created {
			if err := s.audit.Record(ctx, audit.Event{
				Actor: audit.SystemActor("keystore"), Action: "keystore.alert", Outcome: audit.Failure, OrganizationID: org,
				TargetType: "keystore", TargetID: "log", Details: map[string]any{"kind": AlertUnauditedRead, "requestId": rid, "record": es[0].Record, "logged": len(es), "audited": counts[rid]},
			}); err != nil {
				return err
			}
			s.notifyAdmins(ctx, org, "Critical: a recovery key was read outside the console", detail)
		}
	}
	return nil
}

// notifyAdmins mails an alert to the super administrators and, when org is
// set, that organization's administrators.
func (s *Service) notifyAdmins(ctx context.Context, org uuid.UUID, subject, text string) {
	if s.notifier == nil || !s.notifier.Available(ctx) {
		return
	}
	to, err := s.admins(ctx, org)
	if err != nil {
		s.warn("listing the administrators to alert", err)
		return
	}
	msg, err := mailer.Letter{Subject: subject, Before: []string{text}}.Message()
	if err != nil {
		return
	}
	for _, r := range to {
		cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		s.warn("mailing a keystore alert", s.notifier.SendAccountMail(cctx, r.email, msg, mailer.AccountMail{Account: r.id, Organization: org}))
		cancel()
	}
}

// reconcileLoop runs the hourly job until ctx ends. It is an automatic
// behavior; the dev-scope guard is applied per organization inside.
func (s *Service) reconcileLoop(ctx context.Context) {
	t := time.NewTicker(ReconcileEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if _, err := s.Reconcile(ctx); err != nil && ctx.Err() == nil && !errors.Is(err, ErrUnavailable) {
				s.warn("reconciling the keystore's log", err)
			}
		}
	}
}
