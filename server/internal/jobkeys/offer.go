package jobkeys

import (
	"context"
	"crypto/ed25519"
	"errors"
	"slices"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
)

// Statements are what a heartbeat answer carries to move a device between
// keys: at most one of the two.
type Statements struct {
	Handover *agentproto.SignedKeyStatement
	Cutover  *agentproto.SignedKeyStatement
}

// Offerer is a Source that decides which statements a device is offered.
type Offerer interface {
	Offer(ctx context.Context, tx pgx.Tx, device uuid.UUID) (Statements, error)
}

// statementPlan is what the rules of ADR-0057, "What the server offers each
// device", decide, before anything is signed.
type statementPlan struct {
	kind   string // agentproto.InstructionHandover, InstructionCutover or ""
	signer Key    // the key that signs: one the device trusts and the ring holds
	about  Key    // the key the statement names
}

// plan applies the five rules to a device's report. keys is the ring.
func plan(keys []Key, floor Key, report []reported) statementPlan {
	if len(report) == 0 {
		return statementPlan{}
	}
	newest := keys[len(keys)-1]
	byPub := func(pub []byte) (Key, bool) {
		i := slices.IndexFunc(keys, func(k Key) bool { return k.Public.Equal(ed25519.PublicKey(pub)) })
		if i < 0 {
			return Key{}, false
		}
		return keys[i], true
	}
	// The device's keys, oldest first, by the generation it reports.
	trusted := slices.Clone(report)
	slices.SortFunc(trusted, func(a, b reported) int { return int(a.Generation - b.Generation) })
	var (
		older       bool // trusts a key older than the floor
		hasFloor    bool
		hasNewest   bool
		newestTrust = trusted[len(trusted)-1]
		heldTrusted []Key // the keys it trusts that the ring holds, newest last
	)
	for _, t := range trusted {
		if t.Generation < floor.Generation {
			older = true
		}
		if ed25519.PublicKey(t.Key).Equal(floor.Public) {
			hasFloor = true
		}
		if ed25519.PublicKey(t.Key).Equal(newest.Public) {
			hasNewest = true
		}
		if k, ok := byPub(t.Key); ok && k.Held() {
			heldTrusted = append(heldTrusted, k)
		}
	}
	target, hasTarget := newest, hasNewest
	if older {
		target, hasTarget = floor, hasFloor
	}
	switch {
	case hasTarget:
		// 2: the cut-over, when the target is the floor and the newest key
		// the device trusts, and it trusts others too.
		if len(trusted) > 1 && target.Generation == floor.Generation && target.Held() &&
			ed25519.PublicKey(newestTrust.Key).Equal(target.Public) {
			return statementPlan{kind: agentproto.InstructionCutover, signer: target, about: target}
		}
		return statementPlan{}
	case len(heldTrusted) == 0:
		// 5: needs re-pinning.
		return statementPlan{}
	case len(trusted) == 1:
		// 4: one key the server holds: the hand-over to the target.
		return statementPlan{kind: agentproto.InstructionHandover, signer: heldTrusted[0], about: target}
	}
	// 3: several keys, none of them the target.
	if k, ok := byPub(newestTrust.Key); ok && k.Held() {
		return statementPlan{kind: agentproto.InstructionCutover, signer: k, about: k}
	}
	// The newest key it trusts is one the server never held, or no longer
	// holds: the hand-over at once, signed with the newest held key it trusts,
	// and only when the target's generation is above that key's.
	if target.Generation <= newestTrust.Generation {
		return statementPlan{}
	}
	return statementPlan{kind: agentproto.InstructionHandover, signer: heldTrusted[len(heldTrusted)-1], about: target}
}

// Offer decides, signs and records the statement a device is offered in its
// heartbeat answer (ADR-0057, "What the server offers each device"). The
// caller does not ask while an agent update is open for the device, for a
// device being removed, or for an organization outside the dev scope. A
// cut-over is recorded on the device's row, so that the key chosen for it
// follows until a later report lacks the key.
func (r *Ring) Offer(ctx context.Context, tx pgx.Tx, device uuid.UUID) (Statements, error) {
	st, err := readState(ctx, tx, device)
	if err != nil {
		return Statements{}, err
	}
	var devicePub []byte
	if err := tx.QueryRow(ctx, `SELECT agent_public_key FROM devices WHERE id = $1`, device).Scan(&devicePub); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Statements{}, nil
		}
		return Statements{}, err
	}
	if len(devicePub) != ed25519.PublicKeySize || !st.hasEverSent {
		return Statements{}, nil
	}
	p := plan(r.Keys(), r.Floor(), st.report)
	if p.kind == "" || !p.signer.Held() {
		return Statements{}, nil
	}
	now := r.now().UTC()
	s := agentproto.KeyStatement{
		V: agentproto.KeyStatementVersion, ID: uuid.NewString(), DeviceID: device.String(),
		Install: agentproto.InstallID(devicePub), Key: p.about.Encoded(), Generation: p.about.Generation,
		IssuedAt: now, ExpiresAt: now.Add(agentproto.KeyStatementValid),
	}
	var out Statements
	if p.kind == agentproto.InstructionCutover {
		signed, err := agentproto.SignCutover(p.signer.Private, s)
		if err != nil {
			return Statements{}, err
		}
		out.Cutover = &signed
		if _, err := tx.Exec(ctx, `UPDATE devices SET job_key_cutover_generation = $2, job_key_cutover_at = $3 WHERE id = $1`,
			device, p.about.Generation, now); err != nil {
			return Statements{}, err
		}
	} else {
		signed, err := agentproto.SignHandover(p.signer.Private, s)
		if err != nil {
			return Statements{}, err
		}
		out.Handover = &signed
	}
	// Recorded in the transaction that signs, like every instruction; the ID
	// is the fingerprint of the key it introduces.
	_, err = tx.Exec(ctx, `INSERT INTO issued_instructions (kind, instruction_id, device_id, generation)
		SELECT $1, $2, $3, $4
		WHERE NOT EXISTS (SELECT 1 FROM issued_instructions WHERE device_id = $3 AND kind = $1 AND instruction_id = $2 AND generation = $4)`,
		p.kind, p.about.Fingerprint(), device, p.signer.Generation)
	return out, err
}

var _ Offerer = (*Ring)(nil)
