// Package jobkeys is the server's ring of job keys (ADR-0057). One Ed25519
// key signs everything the server asks an agent to do; this package holds
// every key the server ever made, each with its generation, picks the key
// that signs for each device from what that device reports it trusts, and
// records what it signs, so that an instruction an agent ran that the server
// never issued shows. The jobs, agents, EasyPatch, recovery, keystore and
// trust services ask it for the key to sign each device's instruction; none
// keeps a key of its own.
//
// The first slice has no way to rotate: the ring holds the one key it was
// born with, moved from the settings table (or made by a fresh install). What
// it already does is the rest: the agents report what they trust, a key a
// device reports that this server never held is flagged, and an instruction
// an agent logged that the server never issued is flagged.
package jobkeys

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/secrets"
)

const (
	// ringLock is the advisory lock every change to the ring takes: the move
	// from settings, a new key, a reseal.
	ringLock = 0x4a4f424b45595247 // "JOBKEYRG"
	// settingKey is where the first key lived, before the ring.
	settingKey = "jobs.signing_key" //nolint:gosec // a settings key, not a credential
	// settingAAD is the additional data that key was sealed with.
	settingAAD = "easyrmm:" + settingKey
)

// Reload timing (ADR-0057).
const (
	// ReloadEvery is how often every server reloads the ring.
	ReloadEvery = 30 * time.Second
	// ReloadOnUnknown is the least time between two reloads a report of a key
	// the server has not loaded causes.
	ReloadOnUnknown = 5 * time.Second
	// InstanceSeenWithin is how recently an instance must have reloaded to be
	// counted as running.
	InstanceSeenWithin = 2 * time.Minute
)

// tombstone is the JSON string the settings row holds once the key has moved
// into the ring. An older server's LoadKey reads the row into a struct and
// cannot read a string into it, so it refuses to start against the migrated
// database instead of finding no row and making a key of its own.
var tombstone = json.RawMessage(`"moved to the job_keys table by ADR-0057; a server from before that ADR cannot start against this database"`)

// aad is the additional data a seed is sealed with: it names the generation.
func aad(generation int64) []byte { return fmt.Appendf(nil, "easyrmm:job_key:%d", generation) }

// Reason is why a key was made.
type Reason string

// The reasons a key is made. Only ReasonInitial is made in the first slice.
const (
	ReasonInitial         Reason = "initial"
	ReasonPlanned         Reason = "planned"
	ReasonMoving          Reason = "moving"
	ReasonCompromised     Reason = "compromised"
	ReasonLostReplacement Reason = "lost_replacement"
)

// Key is one key of the ring.
type Key struct {
	Generation int64
	Public     ed25519.PublicKey
	// Private is nil when the server no longer holds the seed: deleted, or
	// marked lost.
	Private                                         ed25519.PrivateKey
	Reason                                          Reason
	CreatedAt                                       time.Time
	CutOverAt, CompromisedAt, LostAt, SeedDeletedAt *time.Time
}

// Fingerprint is the key's name wherever a person reads it.
func (k Key) Fingerprint() string { return agentproto.Fingerprint(k.Public) }

// Encoded is the key as agents pin it (agentproto.EncodeKey).
func (k Key) Encoded() string { return agentproto.EncodeKey(k.Public) }

// Held reports whether the server can sign with the key.
func (k Key) Held() bool { return len(k.Private) == ed25519.PrivateKeySize }

// Ring is the server's job keys.
type Ring struct {
	db     *database.DB
	sealer *secrets.Sealer
	audit  *audit.Logger
	log    *slog.Logger
	now    func() time.Time
	// ID is this server process's, in server_instances.
	id      string
	version string
	started time.Time
	held    func() bool
	// host is a ring made for a host command: nothing loaded, nothing recorded.
	host bool
	// guard says whether the updater holds the server or an upgrade is under
	// way; changes to the ring check it inside the ring's lock.
	guard   func() error
	onFloor func(from, to int64)

	mu         sync.RWMutex
	keys       []Key // ascending by generation
	loadedAt   time.Time
	unknown    map[string]time.Time // fingerprints looked for and not found, until the next periodic reload
	lastHeld   bool
	lastReload time.Time
}

// Options are what Open needs besides the database.
type Options struct {
	// Version is this server's version, recorded in server_instances.
	Version string
	// Audit records the unknown keys and entries; nil records nothing.
	Audit *audit.Logger
	// Now is the clock; nil is time.Now.
	Now func() time.Time
}

// Open makes the ring ready: on the first start with ADR-0057 it moves the
// key from settings (or makes the first key), in one transaction under an
// advisory lock; then it loads every key, sealing again those sealed with an
// encryption key that is no longer the primary one, and records this server
// in server_instances. It refuses to start when a key's seed cannot be
// opened: a mistaken EASYRMM_SECRET_KEY is fixed in .env, not by losing the
// key.
func Open(ctx context.Context, db *database.DB, sealer *secrets.Sealer, log *slog.Logger, o Options) (*Ring, error) {
	r := &Ring{db: db, sealer: sealer, audit: o.Audit, log: log, now: o.Now, id: uuid.NewString(), version: o.Version,
		unknown: map[string]time.Time{}}
	if r.now == nil {
		r.now = time.Now
	}
	if r.version == "" {
		r.version = "unknown"
	}
	r.started = r.now()
	if err := r.move(ctx); err != nil {
		return nil, err
	}
	if err := r.Reload(ctx); err != nil {
		return nil, err
	}
	return r, nil
}

// SetHeld gives the ring the updater's hold, which server_instances records.
func (r *Ring) SetHeld(held func() bool) {
	r.mu.Lock()
	r.held = held
	r.mu.Unlock()
}

// ID is this server process's identifier in server_instances.
func (r *Ring) ID() string { return r.id }

// move makes the ring's first key: the key settings holds, sealed again under
// the new additional data (the same seed and public key), or a new one on a
// fresh install; recorded as cut over to, so that the floor is generation 1
// from the start. The settings row becomes a tombstone.
func (r *Ring) move(ctx context.Context) error {
	return r.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, int64(ringLock)); err != nil {
			return err
		}
		var n int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM job_keys`).Scan(&n); err != nil {
			return err
		}
		var raw []byte
		err := tx.QueryRow(ctx, `SELECT value FROM settings WHERE key = $1`, settingKey).Scan(&raw)
		missing := errors.Is(err, pgx.ErrNoRows)
		if err != nil && !missing {
			return err
		}
		if n > 0 {
			if missing {
				// A ring with no tombstone: written again, so that a server from
				// before the ring still refuses to start.
				return writeTombstone(ctx, tx)
			}
			return nil
		}
		var seed []byte
		switch {
		case missing:
			_, fresh, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				return err
			}
			seed = fresh.Seed()
		default:
			var stored struct {
				Sealed string `json:"sealed"`
			}
			if err := json.Unmarshal(raw, &stored); err != nil || stored.Sealed == "" {
				return errors.New("jobkeys: the settings row jobs.signing_key holds a tombstone, but the ring is empty: the job keys table was lost; restore it from a backup")
			}
			seed, err = r.sealer.Open(stored.Sealed, []byte(settingAAD))
			if err != nil {
				return fmt.Errorf("jobkeys: opening the stored signing key (was EASYRMM_SECRET_KEY changed without listing the old key in EASYRMM_SECRET_KEYS_PREVIOUS?): %w", err)
			}
			if len(seed) != ed25519.SeedSize {
				return errors.New("jobkeys: the stored signing key is not an Ed25519 seed")
			}
		}
		key := ed25519.NewKeyFromSeed(seed)
		sealed, err := r.sealer.Seal(seed, aad(1))
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO job_keys (generation, public_key, sealed_seed, reason, created_at, cut_over_at)
			VALUES (1, $1, $2, 'initial', $3, $3)`, []byte(key.Public().(ed25519.PublicKey)), sealed, r.now()); err != nil {
			return err
		}
		return writeTombstone(ctx, tx)
	})
}

func writeTombstone(ctx context.Context, tx pgx.Tx) error {
	_, err := tx.Exec(ctx, `INSERT INTO settings (key, value) VALUES ($1, $2)
		ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()`, settingKey, []byte(tombstone))
	return err
}

// Reload reads the ring again, and records this server in server_instances.
// Every server does it every ReloadEvery.
func (r *Ring) Reload(ctx context.Context) error {
	var keys []Key
	err := r.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT generation, public_key, sealed_seed, reason, created_at, cut_over_at, compromised_at, lost_at, seed_deleted_at
			FROM job_keys ORDER BY generation`)
		if err != nil {
			return err
		}
		type reseal struct {
			generation int64
			seed       []byte
		}
		var again []reseal
		for rows.Next() {
			var (
				k      Key
				pub    []byte
				sealed *string
				reason string
			)
			if err := rows.Scan(&k.Generation, &pub, &sealed, &reason, &k.CreatedAt, &k.CutOverAt, &k.CompromisedAt, &k.LostAt, &k.SeedDeletedAt); err != nil {
				rows.Close()
				return err
			}
			k.Public, k.Reason = ed25519.PublicKey(pub), Reason(reason)
			// A lost key's seed is kept sealed and not opened; a deleted one is gone.
			if sealed != nil && k.LostAt == nil {
				seed, err := r.sealer.Open(*sealed, aad(k.Generation))
				if err != nil {
					rows.Close()
					return fmt.Errorf("jobkeys: opening the job key of generation %d (was EASYRMM_SECRET_KEY changed without listing the old key in EASYRMM_SECRET_KEYS_PREVIOUS?): %w", k.Generation, err)
				}
				if len(seed) != ed25519.SeedSize {
					rows.Close()
					return fmt.Errorf("jobkeys: the job key of generation %d is not an Ed25519 seed", k.Generation)
				}
				k.Private = ed25519.NewKeyFromSeed(seed)
				if !k.Private.Public().(ed25519.PublicKey).Equal(k.Public) {
					rows.Close()
					return fmt.Errorf("jobkeys: the seed of generation %d does not match its public key", k.Generation)
				}
				if r.sealer.NeedsReseal(*sealed) {
					again = append(again, reseal{k.Generation, seed})
				}
			}
			keys = append(keys, k)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		if len(keys) == 0 {
			return errors.New("jobkeys: the ring is empty")
		}
		for _, a := range again {
			// Sealed again under the primary encryption key, under the
			// ring's lock like every change to it.
			if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, int64(ringLock)); err != nil {
				return err
			}
			sealed, err := r.sealer.Seal(a.seed, aad(a.generation))
			if err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `UPDATE job_keys SET sealed_seed = $2 WHERE generation = $1 AND sealed_seed IS NOT NULL`, a.generation, sealed); err != nil {
				return err
			}
		}
		return r.recordInstance(ctx, tx)
	})
	if err != nil {
		return err
	}
	r.mu.Lock()
	before, had := int64(0), len(r.keys) > 0
	if had {
		before = floorOf(r.keys).Generation
	}
	r.keys, r.loadedAt, r.lastReload = keys, r.now(), r.now()
	r.unknown = map[string]time.Time{}
	after := floorOf(keys).Generation
	f := r.onFloor
	r.mu.Unlock()
	// The floor moved: every server sees it, the one that moved it at once and
	// the others with their next reload (ADR-0057, ADR-0059 "closing").
	if had && before != after && f != nil {
		f(before, after)
	}
	return nil
}

// floorOf is the newest key that has been cut over to, or the oldest.
func floorOf(keys []Key) Key {
	for i := len(keys) - 1; i >= 0; i-- {
		if keys[i].CutOverAt != nil {
			return keys[i]
		}
	}
	return keys[0]
}

// OnFloorChange sets what is told, with the old and the new floor generation,
// when a reload finds the floor changed. The agent channel closes its
// connections with "refresh" on it. f must not block.
func (r *Ring) OnFloorChange(f func(from, to int64)) {
	r.mu.Lock()
	r.onFloor = f
	r.mu.Unlock()
}

// recordInstance writes this server's row in server_instances.
func (r *Ring) recordInstance(ctx context.Context, tx pgx.Tx) error {
	held := r.isHeld()
	_, err := tx.Exec(ctx, `INSERT INTO server_instances (id, version, started_at, reloaded_at, held, seen_at)
		VALUES ($1, $2, $3, now(), $4, now())
		ON CONFLICT (id) DO UPDATE SET reloaded_at = now(), held = EXCLUDED.held, seen_at = now()`,
		r.id, r.version, r.started, held)
	if err == nil {
		r.mu.Lock()
		r.lastHeld = held
		r.mu.Unlock()
	}
	return err
}

func (r *Ring) isHeld() bool {
	r.mu.RLock()
	f := r.held
	r.mu.RUnlock()
	return f != nil && f()
}

// Run keeps the ring current until ctx ends: it reloads every ReloadEvery,
// writes this server's hold the moment it changes, purges what the ring keeps
// for 90 days, and removes this server's row when it stops.
func (r *Ring) Run(ctx context.Context) {
	reload := time.NewTicker(ReloadEvery)
	held := time.NewTicker(time.Second)
	purge := time.NewTicker(time.Hour)
	defer reload.Stop()
	defer held.Stop()
	defer purge.Stop()
	for {
		select {
		case <-ctx.Done():
			// The context has ended: remove the row with a fresh one.
			rm, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
			if err := r.Remove(rm); err != nil {
				r.log.Warn("jobkeys: removing this server's row failed", "error", err)
			}
			cancel()
			return
		case <-reload.C:
			if err := r.Reload(ctx); err != nil && ctx.Err() == nil {
				r.log.Error("jobkeys: reloading the ring failed", "error", err)
			}
		case <-held.C:
			r.mu.RLock()
			changed := r.isHeldLocked() != r.lastHeld
			r.mu.RUnlock()
			if changed {
				if err := r.db.InTx(ctx, database.System, func(tx pgx.Tx) error { return r.recordInstance(ctx, tx) }); err != nil && ctx.Err() == nil {
					r.log.Error("jobkeys: recording the hold failed", "error", err)
				}
			}
		case <-purge.C:
			if err := r.Purge(ctx); err != nil && ctx.Err() == nil {
				r.log.Error("jobkeys: purging failed", "error", err)
			}
			// A seed no device may still trust is deleted (ADR-0057); refused
			// while the updater holds the server, and tried again next hour.
			if _, err := r.SweepSeeds(ctx); err != nil && ctx.Err() == nil && !errors.Is(err, ErrHeld) && !errors.Is(err, ErrUpgrading) {
				r.log.Error("jobkeys: deleting unneeded seeds failed", "error", err)
			}
		}
	}
}

func (r *Ring) isHeldLocked() bool { return r.held != nil && r.held() }

// Remove deletes this server's row in server_instances; a server does it when
// it stops.
func (r *Ring) Remove(ctx context.Context) error {
	return r.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `DELETE FROM server_instances WHERE id = $1`, r.id)
		return err
	})
}

// IssuedKeep is how long what the server signed is kept.
const IssuedKeep = 90 * 24 * time.Hour

// Purge deletes the issued instructions older than IssuedKeep and the rows of
// servers not seen for a day (one that died without removing its row).
func (r *Ring) Purge(ctx context.Context) error {
	return r.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `DELETE FROM issued_instructions WHERE issued_at < $1`, r.now().Add(-IssuedKeep)); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `DELETE FROM server_instances WHERE seen_at < now() - interval '1 day' AND id <> $1`, r.id)
		return err
	})
}

// Keys returns the ring, ascending by generation.
func (r *Ring) Keys() []Key {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return slices.Clone(r.keys)
}

// Newest is the ring's newest key: the one enrollment gives.
func (r *Ring) Newest() Key {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.keys[len(r.keys)-1]
}

// Floor is the newest key that has been cut over to: generation 1 until the
// first cut-over, since the ring starts with it recorded as cut over to.
func (r *Ring) Floor() Key {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return floorOf(r.keys)
}

// ByPublic finds a key by its public key.
func (r *Ring) ByPublic(pub []byte) (Key, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, k := range r.keys {
		if k.Public.Equal(ed25519.PublicKey(pub)) {
			return k, true
		}
	}
	return Key{}, false
}

// ByFingerprint finds a key by its fingerprint.
func (r *Ring) ByFingerprint(fp string) (Key, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, k := range r.keys {
		if k.Fingerprint() == fp {
			return k, true
		}
	}
	return Key{}, false
}

// ByGeneration finds a key by its generation.
func (r *Ring) ByGeneration(g int64) (Key, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, k := range r.keys {
		if k.Generation == g {
			return k, true
		}
	}
	return Key{}, false
}

// lookup is ByPublic that reloads the ring, at most once every
// ReloadOnUnknown, when a report names a key it has not loaded. A key still
// unknown after a reload is remembered as unknown until the next periodic
// reload, so repeated reports of it cause no more reloads.
func (r *Ring) lookup(ctx context.Context, pub []byte) (Key, bool) {
	if k, ok := r.ByPublic(pub); ok {
		return k, true
	}
	fp := agentproto.Fingerprint(pub)
	r.mu.Lock()
	_, remembered := r.unknown[fp]
	due := r.now().Sub(r.lastReload) >= ReloadOnUnknown
	if !remembered && !due {
		r.mu.Unlock()
		return Key{}, false
	}
	r.mu.Unlock()
	if !remembered {
		if err := r.Reload(ctx); err != nil {
			r.log.Warn("jobkeys: reloading for a key a device reported failed", "error", err)
		} else if k, ok := r.ByPublic(pub); ok {
			return k, true
		}
	}
	r.mu.Lock()
	r.unknown[fp] = r.now()
	r.mu.Unlock()
	return Key{}, false
}

// Instance is a server sharing the database.
type Instance struct {
	ID        string
	Version   string
	StartedAt time.Time
	Reloaded  time.Time
	Held      bool
}

// Instances lists the servers that reloaded the ring within InstanceSeenWithin.
func (r *Ring) Instances(ctx context.Context) ([]Instance, error) {
	var out []Instance
	err := r.db.ReadTx(ctx, database.System, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT id, version, started_at, reloaded_at, held FROM server_instances
			WHERE seen_at > now() - make_interval(secs => $1) ORDER BY started_at`, InstanceSeenWithin.Seconds())
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var i Instance
			if err := rows.Scan(&i.ID, &i.Version, &i.StartedAt, &i.Reloaded, &i.Held); err != nil {
				return err
			}
			out = append(out, i)
		}
		return rows.Err()
	})
	return out, err
}
