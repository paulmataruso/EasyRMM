package jobkeys

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"slices"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
)

// Choice is the key that signs for one device.
type Choice struct {
	Key Key
	// NeedsRepinning is true when the device trusts no key this server holds:
	// the key chosen is the floor's, and the agent will refuse what it signs.
	NeedsRepinning bool
}

// Source is what the services that sign for a device, and the heartbeat that
// hears what the device trusts, use of the ring: it picks the key that signs
// each device's instruction, records what is signed, and takes the device's
// report and log. *Ring is the server's; Static serves tests and tools with
// one key and no ring, which records and flags nothing.
type Source interface {
	// For is the key that signs for a device, by the rule below.
	For(ctx context.Context, tx pgx.Tx, device uuid.UUID) (Choice, error)
	// Issue picks the key for the device and records the instruction (its
	// kind and ID, the device, the generation of the key) in the same
	// transaction, so that nothing leaves the server unrecorded. A redelivery
	// signed with the same key records nothing more; one signed with another
	// adds a row.
	Issue(ctx context.Context, tx pgx.Tx, device uuid.UUID, kind, id string) (ed25519.PrivateKey, Key, error)
	// Newest is the ring's newest key, which enrollment gives.
	Newest() Key
	// Observe stores what a request says its device trusts (Ring.Observe).
	Observe(ctx context.Context, tx pgx.Tx, o Observation) error
	// RefusedStatement audits a statement an agent refused.
	RefusedStatement(ctx context.Context, tx pgx.Tx, o Observation, ref agentproto.KeyRefusal) error
	// Logs reports whether the source takes the agents' instruction logs: the
	// heartbeat answer then lists the feature (agentproto.FeatureInstructionLog).
	Logs() bool
	// AcceptLog takes a device's instruction log (Ring.AcceptLog).
	AcceptLog(ctx context.Context, tx pgx.Tx, d LogDevice, rep agentproto.InstructionLogReport, now time.Time) (LogResult, error)
}

// Static is a Source with one fixed key and no ring: nothing is recorded.
func Static(priv ed25519.PrivateKey) Source {
	if priv == nil {
		return nil
	}
	return static{Key{Generation: 1, Public: priv.Public().(ed25519.PublicKey), Private: priv, Reason: ReasonInitial}}
}

type static struct{ k Key }

func (s static) For(context.Context, pgx.Tx, uuid.UUID) (Choice, error) {
	return Choice{Key: s.k}, nil
}
func (s static) Issue(context.Context, pgx.Tx, uuid.UUID, string, string) (ed25519.PrivateKey, Key, error) {
	return s.k.Private, s.k, nil
}
func (s static) Logs() bool                                         { return false }
func (s static) Newest() Key                                        { return s.k }
func (s static) Observe(context.Context, pgx.Tx, Observation) error { return nil }
func (s static) RefusedStatement(context.Context, pgx.Tx, Observation, agentproto.KeyRefusal) error {
	return nil
}
func (s static) AcceptLog(_ context.Context, _ pgx.Tx, _ LogDevice, rep agentproto.InstructionLogReport, _ time.Time) (LogResult, error) {
	return LogResult{Ack: rep.Acked}, nil
}

// reported is one key of a device's report, as the database keeps it.
type reported struct {
	Key        []byte `json:"key"`
	Generation int64  `json:"generation"`
}

// deviceKeyState is what the rule reads of a device (or of a removed device).
type deviceKeyState struct {
	report      []reported
	reportAt    *time.Time
	reportSHA   *string
	build       *string // the build the device runs now; nil when not known
	cutoverGen  *int64
	cutoverAt   *time.Time
	givenGen    *int64
	hasEverSent bool
}

// readState loads the rule's inputs for a device, from devices or, for a
// removed device, retired_devices.
func readState(ctx context.Context, q pgx.Tx, device uuid.UUID) (deviceKeyState, error) {
	var (
		st  deviceKeyState
		raw []byte
	)
	err := q.QueryRow(ctx, `SELECT job_keys_report, job_keys_report_at, job_keys_report_sha, agent_sha256,
			job_key_cutover_generation, job_key_cutover_at, job_key_given_generation
		FROM devices WHERE id = $1`, device).
		Scan(&raw, &st.reportAt, &st.reportSHA, &st.build, &st.cutoverGen, &st.cutoverAt, &st.givenGen)
	if errors.Is(err, pgx.ErrNoRows) {
		// A removed device keeps its last report, in the rows it left (ADR-0050).
		err = q.QueryRow(ctx, `SELECT job_keys_report, job_keys_report_at, job_keys_report_sha,
				job_key_cutover_generation, job_key_cutover_at, job_key_given_generation
			FROM retired_devices WHERE device_id = $1`, device).
			Scan(&raw, &st.reportAt, &st.reportSHA, &st.cutoverGen, &st.cutoverAt, &st.givenGen)
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return deviceKeyState{}, nil // a device the server does not know: nothing reported
	}
	if err != nil {
		return deviceKeyState{}, err
	}
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &st.report); err != nil {
			return deviceKeyState{}, err
		}
	}
	st.hasEverSent = len(st.report) > 0
	return st, nil
}

// choose is the rule of ADR-0057, "The key the server signs with", from what
// the device's row says. The server writes a request's report to the row
// before it signs, when the request is newer than the stored one, so "the
// newer of the request's report and the stored one" is the row.
//
//  1. After the server sent the device a cut-over to K, K, until a later
//     report lacks K.
//  2. A device that never sent a report gets the key it was given at
//     enrollment: generation 1 for devices enrolled before the ring.
//  3. A device whose build changed since its stored report (an update or its
//     rollback), while its request carries none, gets the oldest key of the
//     stored report until it reports again.
//  4. Otherwise the newest key of its report whose seed the ring holds.
//
// With none of them the device trusts no key the ring holds.
func (r *Ring) choose(st deviceKeyState) Choice {
	keys := r.Keys()
	held := func(g int64) (Key, bool) {
		i := slices.IndexFunc(keys, func(k Key) bool { return k.Generation == g && k.Held() })
		if i < 0 {
			return Key{}, false
		}
		return keys[i], true
	}
	floor := r.Floor()
	// 1: a cut-over sent.
	if st.cutoverGen != nil {
		k, ok := held(*st.cutoverGen)
		lacks := false
		if ok && st.cutoverAt != nil && st.reportAt != nil && st.reportAt.After(*st.cutoverAt) {
			lacks = !slices.ContainsFunc(st.report, func(rp reported) bool { return k.Public.Equal(ed25519.PublicKey(rp.Key)) })
		}
		if ok && !lacks {
			return Choice{Key: k}
		}
	}
	// 2: never reported.
	if !st.hasEverSent {
		g := int64(1)
		if st.givenGen != nil {
			g = *st.givenGen
		}
		if k, ok := held(g); ok {
			return Choice{Key: k}
		}
		if k := r.Newest(); k.Held() {
			return Choice{Key: k}
		}
		return Choice{Key: floor, NeedsRepinning: !floor.Held()}
	}
	// The keys of the report that the ring holds, oldest first.
	var mine []Key
	for _, rp := range st.report {
		if i := slices.IndexFunc(keys, func(k Key) bool { return k.Held() && k.Public.Equal(ed25519.PublicKey(rp.Key)) }); i >= 0 {
			mine = append(mine, keys[i])
		}
	}
	slices.SortFunc(mine, func(a, b Key) int { return int(a.Generation - b.Generation) })
	if len(mine) == 0 {
		return Choice{Key: floor, NeedsRepinning: true}
	}
	// 3: the build changed since the report.
	if st.build != nil && st.reportSHA != nil && *st.build != *st.reportSHA {
		return Choice{Key: mine[0]}
	}
	// 4: the newest it trusts.
	return Choice{Key: mine[len(mine)-1]}
}

// For implements Source.
func (r *Ring) For(ctx context.Context, tx pgx.Tx, device uuid.UUID) (Choice, error) {
	st, err := readState(ctx, tx, device)
	if err != nil {
		return Choice{}, err
	}
	return r.choose(st), nil
}

// Issue implements Source.
func (r *Ring) Issue(ctx context.Context, tx pgx.Tx, device uuid.UUID, kind, id string) (ed25519.PrivateKey, Key, error) {
	c, err := r.For(ctx, tx, device)
	if err != nil {
		return nil, Key{}, err
	}
	if !c.Key.Held() {
		return nil, Key{}, errors.New("jobkeys: the server holds no key to sign with")
	}
	if len(id) > 200 {
		id = id[:200]
	}
	if _, err := tx.Exec(ctx, `INSERT INTO issued_instructions (kind, instruction_id, device_id, generation)
		SELECT $1, $2, $3, $4
		WHERE NOT EXISTS (SELECT 1 FROM issued_instructions WHERE device_id = $3 AND kind = $1 AND instruction_id = $2 AND generation = $4)`,
		kind, id, device, c.Key.Generation); err != nil {
		return nil, Key{}, err
	}
	return c.Key.Private, c.Key, nil
}

// Logs implements Source.
func (r *Ring) Logs() bool { return true }

var _ Source = (*Ring)(nil)
