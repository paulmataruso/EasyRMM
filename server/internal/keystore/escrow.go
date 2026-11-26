package keystore

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/devscope"
)

// Errors an upload can end in, which the agent API maps to HTTP answers.
var (
	ErrOutOfScope     = errors.New("keystore: escrow is off for this organization")
	ErrNoEscrowKey    = errors.New("keystore: the organization has no escrow key yet")
	ErrKeyOutdated    = errors.New("keystore: the record was sealed to another escrow key than the organization's current one")
	ErrUnknownVolume  = errors.New("keystore: the volume or protector was not reported")
	ErrTooFrequent    = errors.New("keystore: too many escrow uploads from this device or for this volume")
	ErrRecordMismatch = errors.New("keystore: the record is not valid")
)

type protectorRef struct {
	ID   string `json:"id"`
	Hash string `json:"hash,omitempty"`
}

// ReportVolumes stores the volumes and protectors an agent found (identifiers
// only), forgets volumes of that kind it no longer reports, and says which
// protectors need escrow now. An organization outside the dev scope stores
// nothing and needs nothing.
//
// For LUKS the protectors are the key slots of EasyRMM's own tokens. A verified
// record whose slot is gone, or whose slot's header hash is no longer the one
// the key was made with, becomes stale at once; a volume the agent can unlock by
// itself and that has no current record needs one (ADR-0081 section 5).
func (s *Service) ReportVolumes(ctx context.Context, d Device, rep agentproto.EscrowVolumesReport) (agentproto.EscrowVolumesAnswer, error) {
	out := agentproto.EscrowVolumesAnswer{Need: []agentproto.EscrowNeed{}}
	if !devscope.Allowed(d.Org) {
		return out, nil
	}
	if err := rep.Check(); err != nil {
		return out, fmt.Errorf("%w: %w", ErrRecordMismatch, err)
	}
	kind := rep.KindOrDefault()
	luksOn := false
	if kind == agentproto.EscrowLUKS {
		var err error
		if luksOn, err = s.luksEscrowOn(ctx, d.Org); err != nil {
			return out, err
		}
	}
	err := s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		keep := make([]string, 0, len(rep.Volumes))
		for _, v := range rep.Volumes {
			ps := make([]protectorRef, 0, len(v.Protectors))
			for _, p := range v.Protectors {
				ps = append(ps, protectorRef{ID: p.ID, Hash: p.Hash})
			}
			b, err := json.Marshal(ps)
			if err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `INSERT INTO device_encrypted_volumes (device_id, volume_id, organization_id, site_id, kind, mount, status, protectors, escrow_state, reason, reported_at)
				VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb, $9, $10, now())
				ON CONFLICT (device_id, volume_id) DO UPDATE SET kind = EXCLUDED.kind, mount = EXCLUDED.mount, status = EXCLUDED.status,
					protectors = EXCLUDED.protectors, escrow_state = EXCLUDED.escrow_state, reason = EXCLUDED.reason, reported_at = now()`,
				d.ID, v.ID, d.Org, d.Site, kind, v.Mount, v.Status, b, v.State, v.Reason); err != nil {
				return err
			}
			keep = append(keep, v.ID)
		}
		if _, err := tx.Exec(ctx, `DELETE FROM device_encrypted_volumes WHERE device_id = $1 AND kind = $2 AND volume_id <> ALL($3::text[])`, d.ID, kind, keep); err != nil {
			return err
		}
		for _, v := range rep.Volumes {
			if kind == agentproto.EscrowLUKS {
				if err := s.needLUKS(ctx, tx, d, v, luksOn, &out); err != nil {
					return err
				}
				continue
			}
			// What needs escrow: a protector with no current record, or whose
			// only record is stale, unless an upload was made lately.
			for _, p := range v.Protectors {
				var verified, pending bool
				var last *time.Time
				if err := tx.QueryRow(ctx, `SELECT
						coalesce(bool_or(state = 'verified'), false), coalesce(bool_or(state = 'pending'), false), max(created_at)
					FROM recovery_key_escrows WHERE device_id = $1 AND volume_id = $2 AND protector_id = $3`,
					d.ID, v.ID, p.ID).Scan(&verified, &pending, &last); err != nil {
					return err
				}
				if verified || pending || (last != nil && s.now().Sub(*last) < VolumeEvery) {
					continue
				}
				out.Need = append(out.Need, agentproto.EscrowNeed{VolumeID: v.ID, ProtectorID: p.ID})
			}
		}
		return nil
	})
	return out, err
}

// needLUKS judges one LUKS volume of a report: it marks the records whose slot
// is gone or changed as stale and says whether the agent must make a new key.
func (s *Service) needLUKS(ctx context.Context, tx pgx.Tx, d Device, v agentproto.EscrowVolume, on bool, out *agentproto.EscrowVolumesAnswer) error {
	if v.State != agentproto.LUKSEscrowable || !on {
		return nil // escrow off for the organization: reported, never asked // cannot escrow, or managed elsewhere: nothing to ask, nothing to rewrite
	}
	ids := make([]string, 0, len(v.Protectors))
	for _, p := range v.Protectors {
		ids = append(ids, p.ID)
	}
	stale := func(why string, rows pgx.Rows) error {
		defer rows.Close()
		var marked []uuid.UUID
		var prots []string
		for rows.Next() {
			var id uuid.UUID
			var prot string
			if err := rows.Scan(&id, &prot); err != nil {
				return err
			}
			marked, prots = append(marked, id), append(prots, prot)
		}
		if err := rows.Err(); err != nil {
			return err
		}
		rows.Close()
		for i, id := range marked {
			if err := s.audit.Write(ctx, tx, audit.Event{
				Actor: actor(d, netip.Addr{}), Action: ActionStale, Outcome: audit.Failure,
				OrganizationID: d.Org, SiteID: d.Site, DeviceID: d.ID, TargetType: "device", TargetID: d.ID.String(),
				Details: map[string]any{"volumeId": v.ID, "protectorId": prots[i], "escrowId": id.String(), "kind": "luks", "why": why},
			}); err != nil {
				return err
			}
		}
		return nil
	}
	// A slot that is gone: nothing can unlock with the escrowed key any more.
	rows, err := tx.Query(ctx, `UPDATE recovery_key_escrows SET state = 'stale', updated_at = now()
		WHERE device_id = $1 AND volume_id = $2 AND kind = 'luks' AND state = 'verified' AND NOT (protector_id = ANY($3::text[]))
		RETURNING id, protector_id`, d.ID, v.ID, ids)
	if err != nil {
		return err
	}
	if err := stale("slot_gone", rows); err != nil {
		return err
	}
	// A slot whose header area changed since the key was made.
	for _, p := range v.Protectors {
		if p.Hash == "" {
			continue
		}
		h, err := hex.DecodeString(p.Hash)
		if err != nil {
			continue
		}
		rows, err := tx.Query(ctx, `UPDATE recovery_key_escrows SET state = 'stale', updated_at = now()
			WHERE device_id = $1 AND volume_id = $2 AND protector_id = $3 AND kind = 'luks' AND state = 'verified'
				AND slot_hash IS NOT NULL AND slot_hash <> $4 RETURNING id, protector_id`, d.ID, v.ID, p.ID, h)
		if err != nil {
			return err
		}
		if err := stale("slot_changed", rows); err != nil {
			return err
		}
	}
	// A slot that went stale and is no longer there is replaced for good once
	// another record on the volume is verified.
	if _, err := tx.Exec(ctx, `UPDATE recovery_key_escrows e SET state = 'superseded', updated_at = now()
		WHERE e.device_id = $1 AND e.volume_id = $2 AND e.kind = 'luks' AND e.state = 'stale' AND NOT (e.protector_id = ANY($3::text[]))
			AND EXISTS (SELECT 1 FROM recovery_key_escrows o WHERE o.device_id = e.device_id AND o.volume_id = e.volume_id AND o.state = 'verified')`, d.ID, v.ID, ids); err != nil {
		return err
	}
	var current bool
	var last *time.Time
	if err := tx.QueryRow(ctx, `SELECT coalesce(bool_or(state IN ('verified', 'pending') AND protector_id = ANY($3::text[])), false), max(created_at)
		FROM recovery_key_escrows WHERE device_id = $1 AND volume_id = $2`, d.ID, v.ID, ids).Scan(&current, &last); err != nil {
		return err
	}
	if current || (last != nil && s.now().Sub(*last) < VolumeEvery) {
		return nil
	}
	// The reported slots have no current record: they are the stale ones to replace.
	out.Need = append(out.Need, agentproto.EscrowNeed{VolumeID: v.ID, Replace: ids})
	return nil
}

// escrowRow is a record as the checks read it.
type escrowRow struct {
	id          uuid.UUID
	deviceID    uuid.UUID
	org, site   uuid.UUID
	volume      string
	protector   string
	keyID       uuid.UUID
	enc, ct, fp []byte
	kind        string
	slotHash    []byte
}

// Upload takes one sealed record from an agent: it is stored at once as
// pending and then checked by the keystore, which opens it and returns only
// match or mismatch. A match marks it verified; a mismatch marks it stale and
// has the agent send it again. Nothing is ever replaced by a record that does
// not match: a record for a protector that already has a verified one must
// carry the same fingerprint, or it is stored as a conflict beside the old
// one, which stays current (ADR-0081 section 5).
func (s *Service) Upload(ctx context.Context, d Device, ip netip.Addr, rec agentproto.EscrowRecord) (agentproto.EscrowAnswer, error) {
	if !devscope.Allowed(d.Org) {
		return agentproto.EscrowAnswer{}, ErrOutOfScope
	}
	if err := rec.Check(); err != nil {
		return agentproto.EscrowAnswer{}, fmt.Errorf("%w: %w", ErrRecordMismatch, err)
	}
	if rec.Kind == agentproto.EscrowLUKS {
		if on, err := s.luksEscrowOn(ctx, d.Org); err != nil {
			return agentproto.EscrowAnswer{}, err
		} else if !on {
			return agentproto.EscrowAnswer{}, ErrOutOfScope
		}
	}
	enc, _ := base64.StdEncoding.DecodeString(rec.Enc)
	ct, _ := base64.StdEncoding.DecodeString(rec.Ciphertext)
	fp, err := hex.DecodeString(rec.Fingerprint)
	if err != nil || len(fp) != 16 {
		return agentproto.EscrowAnswer{}, fmt.Errorf("%w: fingerprint", ErrRecordMismatch)
	}
	keyID, err := uuid.Parse(rec.KeyID)
	if err != nil {
		return agentproto.EscrowAnswer{}, fmt.Errorf("%w: key id", ErrRecordMismatch)
	}
	in := &escrowRow{deviceID: d.ID, org: d.Org, site: d.Site, volume: rec.VolumeID, protector: rec.ProtectorID, keyID: keyID, enc: enc, ct: ct, fp: fp, kind: rec.Kind}
	if rec.SlotHash != "" {
		if in.slotHash, err = hex.DecodeString(rec.SlotHash); err != nil {
			return agentproto.EscrowAnswer{}, fmt.Errorf("%w: slot hash", ErrRecordMismatch)
		}
	}

	// Step 1, in one transaction: limits, what the record may be, and the
	// record itself stored as pending when no verified one stands.
	var key *EscrowKey
	var verified *escrowRow
	err = s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, d.ID.String()+"|"+rec.VolumeID+"|"+rec.ProtectorID); err != nil {
			return err
		}
		var perVolume, perHour int
		if err := tx.QueryRow(ctx, `SELECT
				count(*) FILTER (WHERE volume_id = $2 AND created_at > now() - make_interval(secs => $3)),
				count(*) FILTER (WHERE created_at > now() - interval '1 hour')
			FROM recovery_key_escrows WHERE device_id = $1`, d.ID, rec.VolumeID, VolumeEvery.Seconds()).Scan(&perVolume, &perHour); err != nil {
			return err
		}
		if perVolume > 0 || perHour >= DeviceHourMax {
			return ErrTooFrequent
		}
		var known bool
		if rec.Kind == agentproto.EscrowLUKS {
			// A new key slot is not in the last report: the volume must be
			// one the agent said it can unlock by itself.
			err = tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM device_encrypted_volumes
				WHERE device_id = $1 AND volume_id = $2 AND kind = 'luks' AND escrow_state = 'escrowable')`, d.ID, rec.VolumeID).Scan(&known)
		} else {
			err = tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM device_encrypted_volumes
				WHERE device_id = $1 AND volume_id = $2 AND kind = 'bitlocker' AND protectors @> jsonb_build_array(jsonb_build_object('id', $3::text)))`,
				d.ID, rec.VolumeID, rec.ProtectorID).Scan(&known)
		}
		if err != nil {
			return err
		}
		if !known {
			return ErrUnknownVolume
		}
		if key, err = s.activeKey(ctx, tx, d.Org); err != nil {
			return err
		}
		if key == nil {
			return ErrNoEscrowKey
		}
		if key.ID != keyID {
			return ErrKeyOutdated
		}
		verified, err = s.currentVerified(ctx, tx, d.ID, rec.VolumeID, rec.ProtectorID)
		if err != nil {
			return err
		}
		// An older pending or stale record for the protector is replaced.
		if _, err := tx.Exec(ctx, `UPDATE recovery_key_escrows SET state = 'superseded', updated_at = now()
			WHERE device_id = $1 AND volume_id = $2 AND protector_id = $3 AND state IN ('pending', 'stale')`,
			d.ID, rec.VolumeID, rec.ProtectorID); err != nil {
			return err
		}
		if verified != nil {
			return nil // judged below, and stored then
		}
		in.id = uuid.New()
		_, err = tx.Exec(ctx, `INSERT INTO recovery_key_escrows (id, organization_id, site_id, device_id, volume_id, kind, protector_id, org_key_id, enc, ciphertext, fingerprint, state, slot_hash)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, 'pending', $12)`,
			in.id, d.Org, d.Site, d.ID, rec.VolumeID, rec.Kind, rec.ProtectorID, key.ID, enc, ct, fp, in.slotHash)
		if err != nil {
			return err
		}
		return s.audit.Write(ctx, tx, audit.Event{
			Actor: actor(d, ip), Action: ActionEscrowed, Outcome: audit.Success,
			OrganizationID: d.Org, SiteID: d.Site, DeviceID: d.ID, TargetType: "device", TargetID: d.ID.String(),
			Details: map[string]any{"volumeId": rec.VolumeID, "protectorId": rec.ProtectorID, "escrowId": in.id.String(), "kind": rec.Kind},
		})
	})
	if err != nil {
		return agentproto.EscrowAnswer{}, err
	}

	// Step 2, outside any transaction: the keystore opens it and says match
	// or mismatch.
	result, err := s.check(ctx, key, in)
	if err != nil {
		if verified != nil {
			// Not stored, since the verified one stands: say the keystore is
			// not available and have the agent try later.
			return agentproto.EscrowAnswer{}, err
		}
		s.warn("checking an escrow record", err)
		return agentproto.EscrowAnswer{State: agentproto.EscrowPending}, nil
	}

	// Step 3: record the verdict.
	var answer agentproto.EscrowAnswer
	err = s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		answer, err = s.settle(ctx, tx, d, ip, in, verified, result)
		return err
	})
	if err == nil && answer.State == agentproto.EscrowConflict {
		s.raiseConflict(ctx, d, in.volume, in.protector)
	}
	return answer, err
}

// currentVerified is the verified record of a protector, nil when none.
func (s *Service) currentVerified(ctx context.Context, tx pgx.Tx, device uuid.UUID, volume, protector string) (*escrowRow, error) {
	var r escrowRow
	err := tx.QueryRow(ctx, `SELECT id, fingerprint FROM recovery_key_escrows
		WHERE device_id = $1 AND volume_id = $2 AND protector_id = $3 AND state = 'verified'`, device, volume, protector).Scan(&r.id, &r.fp)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return &r, err
}

// check has the keystore open a record and compare its fingerprint.
func (s *Service) check(ctx context.Context, key *EscrowKey, r *escrowRow) (string, error) {
	if s.ks == nil {
		return "", ErrUnavailable
	}
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	res, err := s.ks.VerifyEscrow(cctx, r.id.String(), key.Wrapped, EscrowContext{
		Org: r.org.String(), Device: r.deviceID.String(), Volume: r.volume, Protector: r.protector, OrgKey: key.ID.String(), Kind: r.kind,
	}, r.enc, r.ct, r.fp)
	if err != nil {
		var re *RemoteError
		if errors.As(err, &re) {
			s.mu.Lock()
			s.statusAt = time.Time{}
			s.mu.Unlock()
			return "", fmt.Errorf("%w: %s", ErrNotReady, re.Code)
		}
		return "", err
	}
	return res, nil
}

// settle records a keystore verdict on a record. verified is the protector's
// verified record when there was one, in which case in is not stored yet.
func (s *Service) settle(ctx context.Context, tx pgx.Tx, d Device, ip netip.Addr, in, verified *escrowRow, result string) (agentproto.EscrowAnswer, error) {
	details := map[string]any{"volumeId": in.volume, "protectorId": in.protector, "kind": in.kind}
	event := func(action string, outcome audit.Outcome, id uuid.UUID) error {
		dd := map[string]any{}
		for k, v := range details {
			dd[k] = v
		}
		dd["escrowId"] = id.String()
		return s.audit.Write(ctx, tx, audit.Event{
			Actor: actor(d, ip), Action: action, Outcome: outcome,
			OrganizationID: d.Org, SiteID: d.Site, DeviceID: d.ID, TargetType: "device", TargetID: d.ID.String(), Details: dd,
		})
	}
	insert := func(state string) error {
		in.id = uuid.New()
		_, err := tx.Exec(ctx, `INSERT INTO recovery_key_escrows (id, organization_id, site_id, device_id, volume_id, kind, protector_id, org_key_id, enc, ciphertext, fingerprint, state, verified_at, slot_hash)
			VALUES ($1, $2, $3, $4, $5, $12, $6, $7, $8, $9, $10, $11, CASE WHEN $11 = 'verified' THEN now() END, $13)`,
			in.id, d.Org, d.Site, d.ID, in.volume, in.protector, in.keyID, in.enc, in.ct, in.fp, state, in.kind, in.slotHash)
		return err
	}
	switch {
	case verified == nil && result == Match:
		if _, err := tx.Exec(ctx, `UPDATE recovery_key_escrows SET state = 'verified', verified_at = now(), updated_at = now()
			WHERE id = $1 AND state = 'pending'`, in.id); err != nil {
			return agentproto.EscrowAnswer{}, err
		}
		return agentproto.EscrowAnswer{State: agentproto.EscrowVerified}, event(ActionVerified, audit.Success, in.id)
	case verified == nil:
		if _, err := tx.Exec(ctx, `UPDATE recovery_key_escrows SET state = 'stale', updated_at = now()
			WHERE id = $1 AND state = 'pending'`, in.id); err != nil {
			return agentproto.EscrowAnswer{}, err
		}
		return agentproto.EscrowAnswer{State: agentproto.EscrowStale, Again: true}, event(ActionStale, audit.Failure, in.id)
	case result == Match && bytes.Equal(in.fp, verified.fp):
		// The same key again (after an organization key rotation, say): the
		// new record supersedes the old, which is kept 30 days.
		if _, err := tx.Exec(ctx, `UPDATE recovery_key_escrows SET state = 'superseded', updated_at = now() WHERE id = $1`, verified.id); err != nil {
			return agentproto.EscrowAnswer{}, err
		}
		if err := insert("verified"); err != nil {
			return agentproto.EscrowAnswer{}, err
		}
		return agentproto.EscrowAnswer{State: agentproto.EscrowVerified}, event(ActionVerified, audit.Success, in.id)
	case result == Match:
		// A record for a protector that has a verified one, with another
		// fingerprint: stored beside it; the old one stays current.
		if err := insert("conflict"); err != nil {
			return agentproto.EscrowAnswer{}, err
		}
		return agentproto.EscrowAnswer{State: agentproto.EscrowConflict}, event(ActionConflict, audit.Failure, in.id)
	default:
		if err := insert("stale"); err != nil {
			return agentproto.EscrowAnswer{}, err
		}
		return agentproto.EscrowAnswer{State: agentproto.EscrowStale, Again: true}, event(ActionStale, audit.Failure, in.id)
	}
}

// VerifyPending checks the records stored while the keystore could not (it
// was sealed or away). It returns how many it settled. Run by the server's
// background loop.
func (s *Service) VerifyPending(ctx context.Context) (int, error) {
	if s.ks == nil {
		return 0, nil
	}
	if err := s.ready(ctx); err != nil {
		return 0, nil //nolint:nilerr // a keystore that is not ready is not a failure: the records wait
	}
	type pend struct {
		escrowRow
		key *EscrowKey
		dev Device
	}
	var todo []pend
	err := s.db.ReadTx(ctx, database.System, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT e.id, e.device_id, e.organization_id, e.site_id, e.volume_id, e.protector_id, e.org_key_id, e.enc, e.ciphertext, e.fingerprint,
				k.version, k.public_key, k.wrapped_private, coalesce(d.hostname, ''), e.kind, e.slot_hash
			FROM recovery_key_escrows e
			JOIN keystore_org_keys k ON k.id = e.org_key_id
			JOIN devices d ON d.id = e.device_id
			WHERE e.state = 'pending' ORDER BY e.created_at LIMIT 50`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var p pend
			p.key = &EscrowKey{}
			if err := rows.Scan(&p.id, &p.deviceID, &p.org, &p.site, &p.volume, &p.protector, &p.keyID, &p.enc, &p.ct, &p.fp,
				&p.key.Version, &p.key.Public, &p.key.Wrapped, &p.dev.Hostname, &p.kind, &p.slotHash); err != nil {
				return err
			}
			p.key.ID = p.keyID
			p.dev.ID, p.dev.Org, p.dev.Site = p.deviceID, p.org, p.site
			todo = append(todo, p)
		}
		return rows.Err()
	})
	if err != nil {
		return 0, err
	}
	n := 0
	for _, p := range todo {
		// Every automatic behavior asks the dev-scope guard first.
		if !devscope.Allowed(p.org) {
			continue
		}
		result, err := s.check(ctx, p.key, &p.escrowRow)
		if err != nil {
			if errors.Is(err, ErrNotReady) || errors.Is(err, ErrUnavailable) {
				break
			}
			s.warn("checking a pending escrow record", err)
			continue
		}
		in := p.escrowRow
		if err := s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
			_, err := s.settle(ctx, tx, p.dev, netip.Addr{}, &in, nil, result)
			return err
		}); err != nil {
			s.warn("recording an escrow verdict", err)
			continue
		}
		n++
	}
	return n, nil
}

// Run checks pending records every half minute until ctx ends.
func (s *Service) Run(ctx context.Context) {
	go s.reconcileLoop(ctx)
	go s.monitorLoop(ctx)
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if _, err := s.VerifyPending(ctx); err != nil && ctx.Err() == nil {
				s.warn("checking the pending escrow records", err)
			}
		}
	}
}
