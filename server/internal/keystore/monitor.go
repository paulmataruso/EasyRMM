package keystore

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/server/internal/access"
	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
)

// The keystore's own condition alerts (ADR-0081 section 7), raised from the
// server's checks of the keystore's status. They are conditions, not events:
// when the condition ends the alert closes by itself (resolved_by stays empty);
// a person who resolves one while the condition still holds is not told again
// for a day.
const (
	AlertUnreachable      = "keystore_unreachable"
	AlertSealed           = "keystore_sealed"
	AlertFileMode         = "keystore_file_mode"
	AlertTPMPolicy        = "keystore_tpm_policy"
	AlertRecoveryUnproved = "recovery_not_verified"
	AlertKEKOverdue       = "kek_verification_overdue"
	AlertEscrowConflict   = "escrow_conflict"

	ActionAlertResolved = "keystore.alert_resolved"

	// MonitorEvery is how often the status is checked.
	MonitorEvery = time.Minute
	// UnreachableAfter is how many failed checks in a row make the keystore
	// "unreachable": a restart of its container is not an alert.
	UnreachableAfter = 3
	// SealedAfter is how long a sealed keystore may wait for its unseal.
	SealedAfter = 15 * time.Minute
	// UnprovedAfter is how long a version may wait for its recovery to be
	// proved before the console and the alerts say so.
	UnprovedAfter = 24 * time.Hour
	// OverdueAfter is the age at which a pending KEK version is "overdue".
	OverdueAfter = 7 * 24 * time.Hour
	// ResolvedQuiet is how long a person's resolution silences a standing
	// condition.
	ResolvedQuiet = 24 * time.Hour
)

// conditionKinds are the kinds the monitor owns and closes by itself.
var conditionKinds = []string{AlertUnreachable, AlertSealed, AlertFileMode, AlertTPMPolicy, AlertRecoveryUnproved, AlertKEKOverdue}

// condition is one alert the monitor wants open now.
type condition struct {
	kind, severity, subject, detail string
}

// conditionsOf derives the alerts a status calls for. down is how many checks
// in a row could not reach the keystore, sealedFor how long it has been
// sealed.
func conditionsOf(st Status, down int, sealedFor time.Duration, now time.Time) []condition {
	var out []condition
	if st.State == StateUnavailable {
		if down >= UnreachableAfter {
			out = append(out, condition{AlertUnreachable, "critical", "keystore",
				"The keystore cannot be reached, so no recovery key is escrowed, checked or read. Check that its container is running on the host."})
		}
		return out
	}
	if st.State == StateUninitialised {
		return out
	}
	if st.State == StateSealed && sealedFor >= SealedAfter {
		out = append(out, condition{AlertSealed, "critical", "keystore",
			"The keystore has been sealed for more than 15 minutes and waits for an unseal at the host. Escrowed keys are safe, but nothing new is checked and no key can be read."})
	}
	if strings.Contains(st.Detail, "TPM policy changed") {
		out = append(out, condition{AlertTPMPolicy, "critical", "keystore",
			"The TPM refused to unseal the keystore's key: its policy changed (Secure Boot state or firmware). Restore from the recovery bundle at the host."})
	}
	if st.Mode == ModeFile {
		out = append(out, condition{AlertFileMode, "warning", "keystore",
			"The keystore's key is protected by a file on its own host, the stand-in mode. Anyone with the host's files can open every escrowed key; switch to TPM or passphrase mode."})
	}
	if len(st.Versions) > 0 && st.Primary == 0 {
		out = append(out, condition{AlertRecoveryUnproved, "warning", "keystore",
			"No KEK version has had its recovery proved, so the keystore wraps nothing. Run verify-recovery at the host with the recovery code."})
	}
	for _, v := range st.Versions {
		if v.RecoveryVerifiedAt != nil || v.State != "pending" {
			continue
		}
		age := now.Sub(v.CreatedAt)
		if age >= OverdueAfter {
			out = append(out, condition{AlertKEKOverdue, "warning", fmt.Sprintf("v%d", v.Version),
				fmt.Sprintf("KEK version %d was made %d days ago and its recovery is still not proved. Until it is, the old version stays primary.", v.Version, int(age.Hours()/24))})
		} else if age >= UnprovedAfter && st.Primary != 0 {
			out = append(out, condition{AlertRecoveryUnproved, "warning", fmt.Sprintf("v%d", v.Version),
				fmt.Sprintf("KEK version %d has waited more than a day for its recovery to be proved (verify-recovery at the host).", v.Version)})
		}
	}
	return out
}

// Monitor makes one check: it asks the keystore for its status and opens,
// refreshes or closes the condition alerts. Keystore-wide alerts are not for
// one organization, so the dev-scope guard has nothing to decide here; no
// alert is raised for a keystore that is not configured at all.
func (s *Service) Monitor(ctx context.Context) error {
	if s.ks == nil {
		return nil
	}
	st := s.RefreshStatus(ctx)
	now := s.now()
	s.mu.Lock()
	if st.State == StateUnavailable {
		s.down++
	} else {
		s.down = 0
	}
	if st.State == StateSealed {
		if s.sealedAt.IsZero() {
			s.sealedAt = now
			if st.SealedSince != nil {
				s.sealedAt = *st.SealedSince
			}
		}
	} else {
		s.sealedAt = time.Time{}
	}
	down, sealedFor := s.down, time.Duration(0)
	if !s.sealedAt.IsZero() {
		sealedFor = now.Sub(s.sealedAt)
	}
	s.mu.Unlock()

	want := conditionsOf(st, down, sealedFor, now)
	for _, c := range want {
		created, err := s.raiseCondition(ctx, c)
		if err != nil {
			return err
		}
		if created {
			subject := map[string]string{"critical": "Critical: ", "warning": "Warning: "}[c.severity] + "the keystore needs attention"
			s.notifyAdmins(ctx, uuid.Nil, subject, c.detail)
		}
	}
	return s.closeConditions(ctx, want)
}

// raiseCondition opens a condition alert unless a person resolved the same one
// lately.
func (s *Service) raiseCondition(ctx context.Context, c condition) (bool, error) {
	var created bool
	err := s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		var quiet bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM keystore_alerts WHERE kind = $1 AND subject = $2
			AND resolved_at > now() - make_interval(secs => $3) AND resolved_by IS NOT NULL)`, c.kind, c.subject, ResolvedQuiet.Seconds()).Scan(&quiet); err != nil {
			return err
		}
		if quiet {
			return nil
		}
		tag, err := tx.Exec(ctx, `UPDATE keystore_alerts SET last_seen_at = now(), detail = left($3, 1000) WHERE kind = $1 AND subject = $2 AND resolved_at IS NULL`, c.kind, c.subject, c.detail)
		if err != nil {
			return err
		}
		if tag.RowsAffected() > 0 {
			return nil
		}
		created = true
		if _, err := tx.Exec(ctx, `INSERT INTO keystore_alerts (organization_id, kind, severity, subject, detail) VALUES (NULL, $1, $2, $3, left($4, 1000))`,
			c.kind, c.severity, c.subject, c.detail); err != nil {
			return err
		}
		return s.audit.Write(ctx, tx, audit.Event{
			Actor: audit.SystemActor("keystore"), Action: "keystore.alert", Outcome: audit.Failure,
			TargetType: "keystore", TargetID: c.subject, Details: map[string]any{"kind": c.kind, "severity": c.severity},
		})
	})
	return created, err
}

// closeConditions closes the open condition alerts the status no longer calls
// for.
func (s *Service) closeConditions(ctx context.Context, want []condition) error {
	keep := make([]string, 0, len(want))
	for _, c := range want {
		keep = append(keep, c.kind+"\x1f"+c.subject)
	}
	return s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE keystore_alerts SET resolved_at = now()
			WHERE resolved_at IS NULL AND kind = ANY($1::text[]) AND NOT (kind || chr(31) || subject) = ANY($2::text[])`, conditionKinds, keep)
		return err
	})
}

// monitorLoop checks the keystore's status every minute until ctx ends.
func (s *Service) monitorLoop(ctx context.Context) {
	t := time.NewTicker(MonitorEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := s.Monitor(ctx); err != nil && ctx.Err() == nil {
				s.warn("checking the keystore's status for alerts", err)
			}
		}
	}
}

// RaiseConflict opens the alert of an escrow conflict: a different key arrived
// for a protector that already has a verified one, which stays current. It is
// part of an agent's upload, which the dev-scope guard already admitted.
func (s *Service) raiseConflict(ctx context.Context, d Device, volume, protector string) {
	detail := fmt.Sprintf("A different recovery key arrived for volume %s of the device %s than the verified one. The verified key stays current; a compromised or confused agent may be sending keys it should not.", volume, d.Hostname)
	org := d.Org
	created, err := s.raiseAlert(context.WithoutCancel(ctx), &org, AlertEscrowConflict, "warning", d.ID.String()+"/"+volume+"/"+protector, detail)
	s.warn("raising the escrow conflict alert", err)
	if created {
		s.notifyAdmins(ctx, org, "Warning: a recovery key conflicts with the verified one", detail)
	}
}

// ResolveAlert closes an alert at a person's request: the platform's keystore
// alerts for whoever manages platform settings, an organization's for its
// administrators. The act is audited with who did it.
func (s *Service) ResolveAlert(ctx context.Context, c access.Caller, id uuid.UUID) error {
	if c.IsSystem() || c.Principal == nil {
		return apperr.Forbidden()
	}
	var org *uuid.UUID
	var kind, subject string
	err := s.db.ReadTx(ctx, c.Scope, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT organization_id, kind, subject FROM keystore_alerts WHERE id = $1 AND resolved_at IS NULL`, id).Scan(&org, &kind, &subject)
	})
	if err != nil {
		if err == pgx.ErrNoRows { //nolint:errorlint // pgx returns the sentinel itself
			return apperr.NotFound()
		}
		return err
	}
	if (org == nil && !c.CanGlobal(rbac.PermSettingsManage)) || (org != nil && !c.Can(rbac.PermUserManage, rbac.Org(*org))) {
		return apperr.NotFound()
	}
	return s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE keystore_alerts SET resolved_at = now(), resolved_by = $2, resolved_by_label = left($3, 320)
			WHERE id = $1 AND resolved_at IS NULL`, id, c.Principal.UserID, c.Actor.Label)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return apperr.NotFound()
		}
		ev := audit.Event{
			Actor: c.Actor, Action: ActionAlertResolved, Outcome: audit.Success,
			TargetType: "keystore", TargetID: id.String(), Details: map[string]any{"kind": kind, "subject": subject},
		}
		if org != nil {
			ev.OrganizationID = *org
		}
		return s.audit.Write(ctx, tx, ev)
	})
}
