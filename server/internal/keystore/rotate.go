package keystore

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/server/internal/access"
	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/devscope"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
)

// Rotation (ADR-0081 sections 5, 6 and 10).
const (
	// RotateAfterRead is how long after a read the agent starts the rotation:
	// the person has had time to type the key.
	RotateAfterRead = 10 * time.Minute
	// RotationOverdue is how long a rotation may stand open before it is
	// alerted: the old key is still the one escrowed, and the volume is never
	// without one, but it was read and should not stay in use.
	RotationOverdue = 24 * time.Hour
	// AlertRotationUnverified is a rotation that could not verify or finish.
	AlertRotationUnverified = "rotation_unverified"
	// AlertRewrapDrift: an organization key's recorded KEK version is not the
	// one its wrapped form names.
	AlertRewrapDrift = "keystore_rewrap_drift"

	rotationBatch = 50
)

// rotationSubject is the alert subject of a protector's rotation.
func rotationSubject(device uuid.UUID, volume, protector string) string {
	return device.String() + "/" + volume + "/" + protector
}

// RewrapKEK moves every organization key that a KEK version older than the
// primary wraps to the primary (ADR-0081 section 10). It is the resumable
// re-wrap job of a KEK rotation: what is left is what a query finds, so a
// restart, a failure or a keystore that went away halfway only means the next
// run takes the rest. The keystore does each unwrap and wrap; the key's
// plaintext never leaves it, and the server writes the new wrapped form and
// its version in one update that only succeeds on the form it read. Nothing
// older is deleted: the old version stays in the keystore. It returns how many
// keys moved.
func (s *Service) RewrapKEK(ctx context.Context) (int, error) {
	if s.ks == nil {
		return 0, nil
	}
	if err := s.ready(ctx); err != nil {
		return 0, nil //nolint:nilerr // a keystore that is not ready is not a failure: the keys wait
	}
	primary := s.CurrentStatus(ctx).Primary
	if primary < 2 {
		return 0, nil
	}
	type held struct {
		id, org uuid.UUID
		purpose string
		wrapped string
		version int
	}
	var todo []held
	if err := s.db.ReadTx(ctx, database.System, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT id, organization_id, purpose, wrapped_private, kek_version FROM keystore_org_keys
			WHERE kek_version < $1 AND state IN ('active', 'retired') ORDER BY created_at, id LIMIT $2`, primary, rotationBatch)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var h held
			if err := rows.Scan(&h.id, &h.org, &h.purpose, &h.wrapped, &h.version); err != nil {
				return err
			}
			todo = append(todo, h)
		}
		return rows.Err()
	}); err != nil {
		return 0, err
	}
	n := 0
	for _, h := range todo {
		if ctx.Err() != nil {
			break
		}
		// An automatic behavior: the dev-scope guard answers first.
		if !devscope.Allowed(h.org) {
			continue
		}
		cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		made, err := s.ks.RewrapOrgKey(cctx, h.org.String(), h.id.String(), h.purpose, h.wrapped)
		cancel()
		if err != nil {
			var re *RemoteError
			if errors.As(err, &re) || errors.Is(err, ErrUnavailable) {
				s.warn("re-wrapping an organization key", err)
				if errors.Is(err, ErrUnavailable) {
					break
				}
				continue
			}
			return n, err
		}
		if made.WrappedPrivate == h.wrapped {
			continue
		}
		moved := false
		if err := s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
			tag, err := tx.Exec(ctx, `UPDATE keystore_org_keys SET wrapped_private = $2, kek_version = $3 WHERE id = $1 AND wrapped_private = $4`,
				h.id, made.WrappedPrivate, made.KEKVersion, h.wrapped)
			if err != nil || tag.RowsAffected() != 1 {
				return err // somebody else moved or changed it: leave it
			}
			moved = true
			return s.audit.Write(ctx, tx, audit.Event{
				Actor: audit.SystemActor("keystore"), Action: ActionRewrapped, Outcome: audit.Success,
				OrganizationID: h.org, TargetType: "organization", TargetID: h.org.String(),
				Details: map[string]any{"keyId": h.id.String(), "purpose": h.purpose, "fromKekVersion": h.version, "toKekVersion": made.KEKVersion},
			})
		}); err != nil {
			s.warn("recording a re-wrapped organization key", err)
			continue
		}
		if moved {
			n++
		}
	}
	s.mu.Lock()
	clear(s.keys) // a cached public key is unchanged, but nothing here may outlive a rotation
	s.mu.Unlock()
	return n, nil //nolint:nilerr // a keystore that went away or refused one key is tried again at the next run
}

// KEKUse is how many organization keys each KEK version still wraps.
type KEKUse struct {
	Version int `json:"version"`
	Keys    int `json:"keys"`
}

// KEKUsage counts, per KEK version, the organization keys it wraps. A version
// no key uses is one only a retained backup may still need.
func (s *Service) KEKUsage(ctx context.Context) ([]KEKUse, error) {
	out := []KEKUse{}
	err := s.db.ReadTx(ctx, database.System, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT kek_version, count(*) FROM keystore_org_keys WHERE state IN ('active', 'retired')
			GROUP BY kek_version ORDER BY kek_version`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var u KEKUse
			if err := rows.Scan(&u.Version, &u.Keys); err != nil {
				return err
			}
			out = append(out, u)
		}
		return rows.Err()
	})
	return out, err
}

// ReconcileKEK compares what the database records for each organization key
// with what the key itself says: the KEK version in the name of its wrapped
// form. A key whose record names another version would be unwrapped with the
// wrong one, so a difference is a critical alert (a re-wrap interrupted by
// something other than this job, or a tampered row), and it closes when none
// is left. It returns how many differ.
func (s *Service) ReconcileKEK(ctx context.Context) (int, error) {
	var drift int
	err := s.db.ReadTx(ctx, database.System, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM keystore_org_keys
			WHERE state IN ('active', 'retired') AND split_part(wrapped_private, '.', 2) <> kek_version::text`).Scan(&drift)
	})
	if err != nil {
		return 0, err
	}
	if drift > 0 {
		_, err = s.raiseAlert(ctx, nil, AlertRewrapDrift, "critical", "kek",
			fmt.Sprintf("%d organization keys record a KEK version other than the one their wrapped form names. Reads for those organizations will fail until it is looked at.", drift))
		return drift, err
	}
	err = s.closeAlert(ctx, AlertRewrapDrift, "kek")
	return 0, err
}

// closeAlert resolves the open alert of a kind and subject, when there is one.
func (s *Service) closeAlert(ctx context.Context, kind, subject string) error {
	return s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE keystore_alerts SET resolved_at = now() WHERE kind = $1 AND subject = $2 AND resolved_at IS NULL`, kind, subject)
		return err
	})
}

// RotateOrgKey makes a new escrow key for an organization, retires the old
// one and has the keystore re-seal every verified record to the new key inside
// itself (ADR-0081 section 10). Agents get the new public key by the signed
// instruction at their next heartbeat; the old key is kept, wrapped, until
// every record has moved and, after that, until the backups that hold keys
// wrapped by it have expired. It is a person's act (organization manager,
// with a step-up), audited, and refused for an organization outside the dev
// scope.
func (s *Service) RotateOrgKey(ctx context.Context, c access.Caller, org uuid.UUID) error {
	if err := c.Require(rbac.PermOrgManage, rbac.Org(org)); err != nil {
		return err
	}
	if c.Principal == nil || s.stepUp == nil {
		return apperr.Forbidden()
	}
	if !devscope.Allowed(org) {
		return apperr.NotFound()
	}
	if err := s.stepUp.VerifyStepUp(ctx); err != nil {
		return err
	}
	if s.ks == nil {
		return unavailableErr(ErrUnavailable)
	}
	if err := s.ready(ctx); err != nil {
		return unavailableErr(err)
	}
	id := uuid.New()
	made, err := s.ks.CreateOrgKey(ctx, org.String(), id.String(), "escrow")
	if err != nil {
		return unavailableErr(err)
	}
	var oldID uuid.UUID
	err = s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		var version int
		err := tx.QueryRow(ctx, `UPDATE keystore_org_keys SET state = 'retired', retired_at = now()
			WHERE organization_id = $1 AND purpose = 'escrow' AND state = 'active' RETURNING id, version`, org).Scan(&oldID, &version)
		if errors.Is(err, pgx.ErrNoRows) {
			return apperr.Conflict("no_escrow_key", "This organization has no escrow key yet: it is made when its first device escrows.")
		}
		if err != nil {
			return err
		}
		var next int
		if err := tx.QueryRow(ctx, `SELECT max(version) + 1 FROM keystore_org_keys WHERE organization_id = $1 AND purpose = 'escrow'`, org).Scan(&next); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO keystore_org_keys (id, organization_id, purpose, version, public_key, wrapped_private, kek_version)
			VALUES ($1, $2, 'escrow', $3, $4, $5, $6)`, id, org, next, made.PublicKey, made.WrappedPrivate, made.KEKVersion); err != nil {
			return err
		}
		return s.audit.Write(ctx, tx, audit.Event{
			Actor: c.Actor, Action: ActionOrgKeyRotated, Outcome: audit.Success, OrganizationID: org,
			TargetType: "organization", TargetID: org.String(),
			Details: map[string]any{"retiredKeyId": oldID.String(), "newKeyId": id.String(), "version": next, "kekVersion": made.KEKVersion},
		})
	})
	if err != nil {
		return err
	}
	s.mu.Lock()
	delete(s.keys, org)
	s.mu.Unlock()
	// The first pass need not wait for the loop.
	go func() {
		bg := context.WithoutCancel(ctx)
		if _, err := s.ResealRecords(bg); err != nil {
			s.warn("re-sealing records to a new organization key", err)
		}
	}()
	return nil
}

// ResealRecords moves the verified records sealed to a retired escrow key to
// the organization's active key (ADR-0081 section 10). The keystore opens each
// under the old key and seals it to the new one, and the server checks the
// result with a second call to the keystore, which opens it under the new key,
// before it replaces the stored record, so a record is never swapped for one
// that does not open. Each swap only succeeds on the record it read. Records
// that were stale are of no use and are superseded; pending ones are left for
// the check that settles them. When a retired key has no record left that
// needs it, it is marked drained, once; it is kept, since retained backups may
// still hold keys wrapped by it. It returns how many records moved.
func (s *Service) ResealRecords(ctx context.Context) (int, error) {
	if s.ks == nil {
		return 0, nil
	}
	if err := s.ready(ctx); err != nil {
		return 0, nil //nolint:nilerr // a keystore that is not ready is not a failure: the records wait
	}
	type move struct {
		escrowRow
		oldKey, newKey EscrowKey
		state          string
	}
	var todo []move
	if err := s.db.ReadTx(ctx, database.System, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT e.id, e.device_id, e.organization_id, e.site_id, e.volume_id, e.protector_id, e.kind, e.enc, e.ciphertext, e.fingerprint, e.state,
				o.id, o.version, o.wrapped_private, n.id, n.version, n.public_key, n.wrapped_private
			FROM recovery_key_escrows e
			JOIN keystore_org_keys o ON o.id = e.org_key_id AND o.state = 'retired' AND o.purpose = 'escrow'
			JOIN keystore_org_keys n ON n.organization_id = o.organization_id AND n.purpose = 'escrow' AND n.state = 'active'
			WHERE e.state IN ('verified', 'conflict') ORDER BY e.created_at, e.id LIMIT $1`, rotationBatch)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var m move
			if err := rows.Scan(&m.id, &m.deviceID, &m.org, &m.site, &m.volume, &m.protector, &m.kind, &m.enc, &m.ct, &m.fp, &m.state,
				&m.oldKey.ID, &m.oldKey.Version, &m.oldKey.Wrapped, &m.newKey.ID, &m.newKey.Version, &m.newKey.Public, &m.newKey.Wrapped); err != nil {
				return err
			}
			todo = append(todo, m)
		}
		return rows.Err()
	}); err != nil {
		return 0, err
	}
	n := 0
	for _, m := range todo {
		if ctx.Err() != nil {
			break
		}
		if !devscope.Allowed(m.org) {
			continue
		}
		oldCtx := EscrowContext{Org: m.org.String(), Device: m.deviceID.String(), Volume: m.volume, Protector: m.protector, OrgKey: m.oldKey.ID.String(), Kind: m.kind}
		newCtx := oldCtx
		newCtx.OrgKey = m.newKey.ID.String()
		cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		enc, ct, err := s.ks.ResealEscrow(cctx, uuid.NewString(), m.id.String(), m.oldKey.Wrapped, oldCtx, newCtx, m.newKey.Wrapped, m.enc, m.ct, m.fp)
		if err == nil {
			var res string
			res, err = s.ks.VerifyEscrow(cctx, m.id.String(), m.newKey.Wrapped, newCtx, enc, ct, m.fp)
			if err == nil && res != Match {
				err = errors.New("the re-sealed record does not open under the new key")
			}
		}
		cancel()
		if err != nil {
			s.warn("re-sealing an escrow record", err)
			if errors.Is(err, ErrUnavailable) {
				break
			}
			continue
		}
		var moved bool
		if err := s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
			tag, err := tx.Exec(ctx, `UPDATE recovery_key_escrows SET org_key_id = $2, enc = $3, ciphertext = $4, updated_at = now()
				WHERE id = $1 AND org_key_id = $5 AND enc = $6 AND state = $7`, m.id, m.newKey.ID, enc, ct, m.oldKey.ID, m.enc, m.state)
			if err != nil || tag.RowsAffected() != 1 {
				return err
			}
			moved = true
			return s.audit.Write(ctx, tx, audit.Event{
				Actor: audit.SystemActor("keystore"), Action: ActionResealed, Outcome: audit.Success,
				OrganizationID: m.org, SiteID: m.site, DeviceID: m.deviceID, TargetType: "device", TargetID: m.deviceID.String(),
				Details: map[string]any{"volumeId": m.volume, "protectorId": m.protector, "escrowId": m.id.String(), "kind": m.kind,
					"fromKeyId": m.oldKey.ID.String(), "toKeyId": m.newKey.ID.String()},
			})
		}); err != nil {
			s.warn("recording a re-sealed escrow record", err)
			continue
		}
		if moved {
			n++
		}
	}
	return n, s.drainRetired(ctx)
}

// drainRetired supersedes the stale records of retired keys, and marks each
// retired key that no record needs any more as drained, writing its audit
// record once.
func (s *Service) drainRetired(ctx context.Context) error {
	return s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `UPDATE recovery_key_escrows e SET state = 'superseded', updated_at = now()
			FROM keystore_org_keys k WHERE k.id = e.org_key_id AND k.state = 'retired' AND e.state = 'stale'`); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `UPDATE keystore_org_keys k SET drained_at = now()
			WHERE k.state = 'retired' AND k.purpose = 'escrow' AND k.drained_at IS NULL
			  AND NOT EXISTS (SELECT 1 FROM recovery_key_escrows e WHERE e.org_key_id = k.id AND e.state IN ('verified', 'conflict', 'pending', 'stale'))
			RETURNING k.id, k.organization_id`)
		if err != nil {
			return err
		}
		type d struct{ id, org uuid.UUID }
		var done []d
		for rows.Next() {
			var x d
			if err := rows.Scan(&x.id, &x.org); err != nil {
				rows.Close()
				return err
			}
			done = append(done, x)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		for _, x := range done {
			if err := s.audit.Write(ctx, tx, audit.Event{
				Actor: audit.SystemActor("keystore"), Action: ActionOrgKeyDrained, Outcome: audit.Success, OrganizationID: x.org,
				TargetType: "organization", TargetID: x.org.String(), Details: map[string]any{"keyId": x.id.String()},
			}); err != nil {
				return err
			}
		}
		return nil
	})
}

// rotationFailed raises the alert for a rotation that could not verify: the
// old key stays in place and is still the one escrowed, and a person should
// look. Called from the upload that failed and from the watch for a rotation
// that never finished.
func (s *Service) rotationFailed(ctx context.Context, d Device, volume, protector, why string) {
	org := d.Org
	if !devscope.Allowed(org) {
		return
	}
	detail := fmt.Sprintf("The rotation of the recovery key of volume %s on %s could not be completed (%s). The old key is still the escrowed one and the volume was left as it was; the key was read and should be replaced.", volume, d.Hostname, why)
	created, err := s.raiseAlert(context.WithoutCancel(ctx), &org, AlertRotationUnverified, "warning", rotationSubject(d.ID, volume, protector), detail)
	s.warn("raising the rotation alert", err)
	if created {
		s.recordRotationFailure(ctx, d, volume, protector, why)
		s.notifyAdmins(ctx, org, "Warning: a recovery key rotation could not be verified", detail)
	}
}

func (s *Service) recordRotationFailure(ctx context.Context, d Device, volume, protector, why string) {
	err := s.audit.Record(context.WithoutCancel(ctx), audit.Event{
		Actor: audit.SystemActor("keystore"), Action: ActionRotationFailed, Outcome: audit.Failure,
		OrganizationID: d.Org, SiteID: d.Site, DeviceID: d.ID, TargetType: "device", TargetID: d.ID.String(),
		Details: map[string]any{"volumeId": volume, "protectorId": protector, "why": why},
	})
	s.warn("auditing a failed rotation", err)
}

// inRotation says whether the protector's volume has a verified record whose
// rotation is due: an upload that fails to verify then belongs to the rotation.
func (s *Service) inRotation(ctx context.Context, device uuid.UUID, volume string) (protector string, yes bool, err error) {
	err = s.db.ReadTx(ctx, database.System, func(tx pgx.Tx) error {
		e := tx.QueryRow(ctx, `SELECT protector_id FROM recovery_key_escrows
			WHERE device_id = $1 AND volume_id = $2 AND state = 'verified' AND rotation_due ORDER BY rotation_due_at LIMIT 1`, device, volume).Scan(&protector)
		if errors.Is(e, pgx.ErrNoRows) {
			return nil
		}
		yes = e == nil
		return e
	})
	return protector, yes, err
}

// WatchRotations raises the alert for a rotation due for more than a day (the
// device may be off, or its agent unable to finish) and closes the alert of
// one that is done. Automatic, so behind the dev-scope guard.
func (s *Service) WatchRotations(ctx context.Context) error {
	type due struct {
		dev  Device
		vol  string
		prot string
	}
	var overdue []due
	open := []string{}
	err := s.db.ReadTx(ctx, database.System, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT e.device_id, e.organization_id, e.site_id, coalesce(d.hostname, ''), e.volume_id, e.protector_id
			FROM recovery_key_escrows e JOIN devices d ON d.id = e.device_id
			WHERE e.state = 'verified' AND e.rotation_due AND e.rotation_due_at < now() - make_interval(secs => $1)`, RotationOverdue.Seconds())
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var x due
			if err := rows.Scan(&x.dev.ID, &x.dev.Org, &x.dev.Site, &x.dev.Hostname, &x.vol, &x.prot); err != nil {
				return err
			}
			overdue = append(overdue, x)
		}
		return rows.Err()
	})
	if err != nil {
		return err
	}
	for _, x := range overdue {
		s.rotationFailed(ctx, x.dev, x.vol, x.prot, "it was not finished within a day")
		open = append(open, rotationSubject(x.dev.ID, x.vol, x.prot))
	}
	// Close what is no longer overdue (done, or the device is gone).
	return s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE keystore_alerts SET resolved_at = now()
			WHERE kind = $1 AND resolved_at IS NULL AND NOT (subject = ANY($2::text[]))`, AlertRotationUnverified, open)
		return err
	})
}

// RotationStep is one pass of the rotation jobs, run with the pending-record
// check: re-wrap under the newest KEK version, re-seal to a new organization
// key, reconcile, and watch the rotations after reads.
func (s *Service) RotationStep(ctx context.Context) {
	if _, err := s.RewrapKEK(ctx); err != nil && ctx.Err() == nil {
		s.warn("re-wrapping the organization keys", err)
	}
	if _, err := s.ResealRecords(ctx); err != nil && ctx.Err() == nil {
		s.warn("re-sealing the records", err)
	}
	if _, err := s.ReconcileKEK(ctx); err != nil && ctx.Err() == nil {
		s.warn("reconciling the KEK versions", err)
	}
	if err := s.WatchRotations(ctx); err != nil && ctx.Err() == nil {
		s.warn("watching the rotations", err)
	}
}

// completeRotation marks the old record of a rotation superseded once the
// protector it names is gone from the volume and a newer record is verified,
// audits it, and closes the rotation's alert. It runs in the report's
// transaction, which has the volume's protectors in hand.
func (s *Service) completeRotation(ctx context.Context, tx pgx.Tx, d Device, volume, kind string, present []string) error {
	rows, err := tx.Query(ctx, `UPDATE recovery_key_escrows e SET state = 'superseded', rotation_due = false, updated_at = now()
		WHERE e.device_id = $1 AND e.volume_id = $2 AND e.kind = $3 AND e.state = 'verified' AND e.rotation_due
			AND NOT (e.protector_id = ANY($4::text[]))
			AND EXISTS (SELECT 1 FROM recovery_key_escrows o WHERE o.device_id = e.device_id AND o.volume_id = e.volume_id
				AND o.state = 'verified' AND o.id <> e.id AND NOT o.rotation_due)
		RETURNING e.id, e.protector_id`, d.ID, volume, kind, present)
	if err != nil {
		return err
	}
	type done struct {
		id   uuid.UUID
		prot string
	}
	var all []done
	for rows.Next() {
		var x done
		if err := rows.Scan(&x.id, &x.prot); err != nil {
			rows.Close()
			return err
		}
		all = append(all, x)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, x := range all {
		if err := s.audit.Write(ctx, tx, audit.Event{
			Actor: actor(d, netip.Addr{}), Action: ActionRotated, Outcome: audit.Success,
			OrganizationID: d.Org, SiteID: d.Site, DeviceID: d.ID, TargetType: "device", TargetID: d.ID.String(),
			Details: map[string]any{"volumeId": volume, "protectorId": x.prot, "escrowId": x.id.String(), "kind": kind},
		}); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE keystore_alerts SET resolved_at = now() WHERE kind = $1 AND subject = $2 AND resolved_at IS NULL`,
			AlertRotationUnverified, rotationSubject(d.ID, volume, x.prot)); err != nil {
			return err
		}
	}
	return nil
}

// rotationNeeds says what the agent must do for the rotations due on a
// volume it just reported: the rotation of each verified record whose time has
// come, and the removal of the old protector once a newer verified record is
// on the volume. present are the protector IDs the agent reported for it.
func (s *Service) rotationNeeds(ctx context.Context, tx pgx.Tx, d Device, v agentproto.EscrowVolume, kind string, present []string, out *agentproto.EscrowVolumesAnswer) error {
	rows, err := tx.Query(ctx, `SELECT protector_id FROM recovery_key_escrows
		WHERE device_id = $1 AND volume_id = $2 AND kind = $3 AND state = 'verified' AND rotation_due
			AND rotation_due_at <= now() - make_interval(secs => $4) AND protector_id = ANY($5::text[]) ORDER BY rotation_due_at`,
		d.ID, v.ID, kind, RotateAfterRead.Seconds(), present)
	if err != nil {
		return err
	}
	var olds []string
	for rows.Next() {
		var p string
		if err := rows.Scan(&p); err != nil {
			rows.Close()
			return err
		}
		olds = append(olds, p)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	if len(olds) == 0 {
		return nil
	}
	// A verified record that is not itself due, on a protector that is on the
	// volume, is the successor: the old protector can go.
	var successor string
	err = tx.QueryRow(ctx, `SELECT protector_id FROM recovery_key_escrows
		WHERE device_id = $1 AND volume_id = $2 AND kind = $3 AND state = 'verified' AND NOT rotation_due AND protector_id = ANY($4::text[])
		ORDER BY verified_at DESC NULLS LAST LIMIT 1`, d.ID, v.ID, kind, present).Scan(&successor)
	switch {
	case err == nil:
		out.Need = append(out.Need, agentproto.EscrowNeed{VolumeID: v.ID, Remove: olds, Successor: successor})
		return nil
	case !errors.Is(err, pgx.ErrNoRows):
		return err
	}
	// A new record that is waiting for the keystore: do nothing yet.
	var waiting bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM recovery_key_escrows
		WHERE device_id = $1 AND volume_id = $2 AND kind = $3 AND state = 'pending')`, d.ID, v.ID, kind).Scan(&waiting); err != nil {
		return err
	}
	if waiting {
		return nil
	}
	if kind == agentproto.EscrowLUKS {
		// A new slot, escrowed, and then the old ones removed.
		out.Need = append(out.Need, agentproto.EscrowNeed{VolumeID: v.ID, Replace: olds})
	} else {
		out.Need = append(out.Need, agentproto.EscrowNeed{VolumeID: v.ID, Rotating: olds[0]})
	}
	return nil
}

// rotationUnverified is called when a record did not verify: if its volume has
// a rotation under way, the new key is the one that failed, and the alert says
// so. A volume with no rotation due is none of its business.
func (s *Service) rotationUnverified(ctx context.Context, d Device, volume, protector string) {
	old, yes, err := s.inRotation(ctx, d.ID, volume)
	if err != nil || !yes || old == protector {
		s.warn("looking for a rotation", err)
		return
	}
	s.rotationFailed(ctx, d, volume, old, "the new key did not verify")
}

// EnableReady is the server's half of the verified-escrow gate for BitLocker's
// enable action (ADR-0081 section 5): the organization is in the development
// scope, the keystore can wrap and verify, and the organization has an escrow
// key (made now if this is its first). It makes no job; it only says whether
// one may be made.
func (s *Service) EnableReady(ctx context.Context, org, device uuid.UUID) error {
	if !devscope.Allowed(org) {
		return apperr.NotFound()
	}
	if s.ks == nil {
		return unavailableErr(ErrUnavailable)
	}
	if err := s.ready(ctx); err != nil {
		return unavailableErr(err)
	}
	key, err := s.EnsureEscrowKey(ctx, org)
	if err != nil {
		return unavailableErr(err)
	}
	if key == nil {
		return apperr.Conflict("no_escrow_key", "This organization has no escrow key, so BitLocker cannot be turned on here.")
	}
	return nil
}
