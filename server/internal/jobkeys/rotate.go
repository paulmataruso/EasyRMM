package jobkeys

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/secrets"
)

// MinOverlap is the least time a planned rotation, or one for a move, stays
// open before it may be finished: ADR-0052's window for rolling back a
// confirmed upgrade.
const MinOverlap = 24 * time.Hour

// Refusals. Each is a conflict with a stable code, so that the API and the
// host commands say the same thing.
var (
	ErrInProgress = apperr.Conflict("job_key_rotation_in_progress", "A rotation is already in progress. Finish it first, or start one for a compromise.")
	ErrNoRotation = apperr.Conflict("job_key_no_rotation", "No planned rotation is in progress.")
	ErrTooEarly   = apperr.Conflict("job_key_too_early", "A rotation can be finished 24 hours after it started.")
	ErrBackup     = apperr.Conflict("job_key_backup_unconfirmed", "Confirm that a backup was taken since the rotation started.")
	ErrOlderSrv   = apperr.Conflict("job_key_older_server", "A server older than this one is running against the database. Wait for the rolling upgrade to end.")
	ErrHeld       = apperr.Conflict("job_key_held", "The updater holds the server. Try again when the upgrade has ended.")
	ErrUpgrading  = apperr.Conflict("job_key_upgrade_underway", "An upgrade is under way. Try again when it has ended.")
	ErrNoSuchKey  = apperr.Conflict("job_key_unknown_generation", "There is no key with that generation.")
	ErrNewestKey  = apperr.Conflict("job_key_newest", "The newest key cannot be forgotten.")
	ErrNoSeed     = apperr.Conflict("job_key_no_seed", "The server no longer holds that key's seed.")
	ErrNotLost    = apperr.Conflict("job_key_not_lost", "That key is not marked lost.")
	ErrNothing    = apperr.Conflict("job_key_nothing_lost", "Every job key's seed opens: nothing is lost.")
	ErrEnvDiffers = apperr.Conflict("job_key_env_mismatch", ".env does not match this database: other sealed values do not open with the current encryption key.")
	ErrOpens      = apperr.Conflict("job_key_seed_unopened", "The key's seed does not open with the current encryption key or EASYRMM_SECRET_KEYS_PREVIOUS.")
)

// Via is where a change was asked for.
type Via string

// The places a change comes from.
const (
	ViaConsole Via = "console"
	ViaHost    Via = "host"
)

// By is who changes the ring.
type By struct {
	// Actor is the audit actor: the signed-in person, or the host command.
	Actor audit.Actor
	// User is the person, when the console asked; the zero value for the host.
	User uuid.UUID
	Via  Via
}

// HostBy is the actor of a host command.
func HostBy() By {
	return By{Actor: audit.SystemActor("easyrmm-server job-key"), Via: ViaHost}
}

// NewHost makes a Ring for the host commands: it reads and changes the
// database under the ring's lock but loads nothing, so it works when the
// server cannot start (a seed that does not open), and it records no
// server_instances row.
func NewHost(db *database.DB, sealer *secrets.Sealer, auditLog *audit.Logger, log *slog.Logger, version string, guard func() error) *Ring {
	if version == "" {
		version = "unknown"
	}
	return &Ring{db: db, sealer: sealer, audit: auditLog, log: log, now: time.Now, id: uuid.NewString(), version: version,
		started: time.Now(), unknown: map[string]time.Time{}, guard: guard, host: true}
}

// SetGuard gives the ring the check of the updater's hold and status, which
// every change to the ring makes again inside its lock.
func (r *Ring) SetGuard(g func() error) {
	r.mu.Lock()
	r.guard = g
	r.mu.Unlock()
}

// row is a key as the table holds it, its seed not opened.
type row struct {
	Key
	sealed *string
}

func readRows(ctx context.Context, tx pgx.Tx) ([]row, error) {
	rs, err := tx.Query(ctx, `SELECT generation, public_key, sealed_seed, reason, created_at, cut_over_at, compromised_at, lost_at, seed_deleted_at
		FROM job_keys ORDER BY generation`)
	if err != nil {
		return nil, err
	}
	defer rs.Close()
	var out []row
	for rs.Next() {
		var (
			k      row
			pub    []byte
			reason string
		)
		if err := rs.Scan(&k.Generation, &pub, &k.sealed, &reason, &k.CreatedAt, &k.CutOverAt, &k.CompromisedAt, &k.LostAt, &k.SeedDeletedAt); err != nil {
			return nil, err
		}
		k.Public, k.Reason = ed25519.PublicKey(pub), Reason(reason)
		out = append(out, k)
	}
	return out, rs.Err()
}

// inProgress is the planned rotation, or the one for a move, that has not
// been finished: the newest key, when it was made for one and has not been cut
// over to, and nothing marked it compromised or lost.
func inProgress(rows []row) (row, bool) {
	if len(rows) == 0 {
		return row{}, false
	}
	k := rows[len(rows)-1]
	open := k.CutOverAt == nil && k.CompromisedAt == nil && k.LostAt == nil && (k.Reason == ReasonPlanned || k.Reason == ReasonMoving)
	return k, open
}

// Progress is the rotation that is under way, if any.
func (r *Ring) Progress() (Key, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if len(r.keys) == 0 {
		return Key{}, false
	}
	k := r.keys[len(r.keys)-1]
	open := k.CutOverAt == nil && k.CompromisedAt == nil && k.LostAt == nil && (k.Reason == ReasonPlanned || k.Reason == ReasonMoving)
	return k, open
}

// change runs fn in one transaction that takes the ring's advisory lock and
// then, inside it, checks again that the updater does not hold the server and
// has no upgrade under way and, when older is true, that no server older than
// the ring is seen. Such a change either commits before the updater can read
// the ring under the same lock, or finds the hold and is refused (ADR-0052,
// "Rollback guards"). The ring is loaded again afterwards.
func (r *Ring) change(ctx context.Context, older bool, fn func(tx pgx.Tx, rows []row) error) error {
	err := r.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, int64(ringLock)); err != nil {
			return err
		}
		if err := r.checkGuard(); err != nil {
			return err
		}
		if older {
			if err := r.checkOlder(ctx, tx); err != nil {
				return err
			}
		}
		rows, err := readRows(ctx, tx)
		if err != nil {
			return err
		}
		if len(rows) == 0 {
			return errors.New("jobkeys: the ring is empty")
		}
		return fn(tx, rows)
	})
	if err != nil {
		return err
	}
	if !r.host {
		if err := r.Reload(ctx); err != nil {
			r.log.Error("jobkeys: reloading after a change failed", "error", err)
		}
	}
	return nil
}

func (r *Ring) checkGuard() error {
	r.mu.RLock()
	g := r.guard
	r.mu.RUnlock()
	if g == nil {
		return nil
	}
	err := g()
	switch {
	case err == nil:
		return nil
	case strings.Contains(err.Error(), "under way"):
		return ErrUpgrading
	default:
		return ErrHeld
	}
}

// checkOlder refuses while a server older than the ring is seen: a database
// connection named plain easyrmm-server, which only builds from before the
// ring use, or a recorded instance seen in the last two minutes of a version
// older than this server's.
func (r *Ring) checkOlder(ctx context.Context, tx pgx.Tx) error {
	var plain int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM pg_stat_activity WHERE datname = current_database() AND application_name = 'easyrmm-server'`).Scan(&plain); err != nil {
		return err
	}
	if plain > 0 {
		return ErrOlderSrv
	}
	rs, err := tx.Query(ctx, `SELECT version FROM server_instances WHERE id <> $1 AND seen_at > now() - make_interval(secs => $2)`,
		r.id, InstanceSeenWithin.Seconds())
	if err != nil {
		return err
	}
	defer rs.Close()
	for rs.Next() {
		var v string
		if err := rs.Scan(&v); err != nil {
			return err
		}
		if olderVersion(v, r.version) {
			return ErrOlderSrv
		}
	}
	return rs.Err()
}

// olderVersion reports whether a is a release older than b. A version either
// cannot read (a development build) is never older.
func olderVersion(a, b string) bool {
	pa, ok1 := parseVersion(a)
	pb, ok2 := parseVersion(b)
	if !ok1 || !ok2 {
		return false
	}
	for i := range pa {
		if pa[i] != pb[i] {
			return pa[i] < pb[i]
		}
	}
	return false
}

func parseVersion(v string) ([3]int, bool) {
	var out [3]int
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	if i := strings.IndexAny(v, "-+"); i >= 0 {
		v = v[:i]
	}
	parts := strings.Split(v, ".")
	if len(parts) == 0 || len(parts) > 3 {
		return out, false
	}
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return out, false
		}
		out[i] = n
	}
	return out, true
}

func (r *Ring) event(by By, action string, details map[string]any) audit.Event {
	details["via"] = string(by.Via)
	return audit.Event{Actor: by.Actor, Action: action, Outcome: audit.Success, TargetType: "job_key", Details: details}
}

func (r *Ring) createdBy(by By) *uuid.UUID {
	if by.User == uuid.Nil {
		return nil
	}
	u := by.User
	return &u
}

func (r *Ring) makeKey(ctx context.Context, tx pgx.Tx, reason Reason, by By, cutOver bool) (Key, error) {
	now := r.now()
	gen, err := r.NextGeneration(ctx, tx, now)
	if err != nil {
		return Key{}, err
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return Key{}, err
	}
	sealed, err := r.sealer.Seal(priv.Seed(), aad(gen))
	if err != nil {
		return Key{}, err
	}
	var cut *time.Time
	if cutOver {
		cut = &now
	}
	via := string(by.Via)
	if _, err := tx.Exec(ctx, `INSERT INTO job_keys (generation, public_key, sealed_seed, reason, created_at, created_by, created_via, cut_over_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`, gen, []byte(pub), sealed, string(reason), now, r.createdBy(by), via, cut); err != nil {
		return Key{}, err
	}
	return Key{Generation: gen, Public: pub, Private: priv, Reason: reason, CreatedAt: now, CutOverAt: cut}, nil
}

// Started is what Start did.
type Started struct {
	Key Key
	// Follows is the generation of the key the new one follows.
	Follows int64
	// Compromised are the generations marked compromised, for a rotation for
	// a compromise.
	Compromised []int64
	// Ended is the generation of the planned rotation's key a compromise
	// ended, 0 when none.
	Ended int64
}

// Start makes a new key (ADR-0057, "A rotation", step 1) under the ring's
// lock. A planned rotation, or one for a move, leaves the key to be cut over
// to when it is finished; one for a compromise marks every older key
// compromised and makes the new key the floor at once, ending a planned
// rotation that was open. It is refused while a rotation is open (except one
// for a compromise), while the updater holds the server or an upgrade is under
// way, and while a server older than the ring is seen.
func (r *Ring) Start(ctx context.Context, reason Reason, by By) (Started, error) {
	if reason != ReasonPlanned && reason != ReasonMoving && reason != ReasonCompromised {
		return Started{}, apperr.Invalid("reason", "Give planned, moving or compromised.")
	}
	var out Started
	err := r.change(ctx, true, func(tx pgx.Tx, rows []row) error {
		open, isOpen := inProgress(rows)
		if isOpen && reason != ReasonCompromised {
			return ErrInProgress
		}
		out = Started{Follows: rows[len(rows)-1].Generation}
		if reason == ReasonCompromised {
			for _, k := range rows {
				if k.CompromisedAt == nil {
					out.Compromised = append(out.Compromised, k.Generation)
				}
			}
			if isOpen {
				out.Ended = open.Generation
			}
		}
		k, err := r.makeKey(ctx, tx, reason, by, reason == ReasonCompromised)
		if err != nil {
			return err
		}
		if reason == ReasonCompromised {
			if _, err := tx.Exec(ctx, `UPDATE job_keys SET compromised_at = $2 WHERE compromised_at IS NULL AND generation <> $1`, k.Generation, r.now()); err != nil {
				return err
			}
		}
		out.Key = k
		d := map[string]any{"reason": string(reason), "fingerprint": k.Fingerprint(), "generation": k.Generation, "follows": out.Follows,
			"markedCompromised": out.Compromised}
		if out.Ended != 0 {
			d["endedPlannedRotation"] = out.Ended
		}
		return r.write(ctx, tx, r.event(by, "job_key.rotate", d))
	})
	out.Key.Private = nil
	return out, err
}

// Finished is what Finish did.
type Finished struct {
	Key Key
	// Moved and NotMoved count the enrolled devices that report the new key
	// and those that do not yet.
	Moved, NotMoved int
}

// FinishInput is what Finish takes.
type FinishInput struct {
	// BackupTaken confirms a backup taken since the rotation started.
	BackupTaken bool
	// Now skips the 24 hours; only the host asks, and the record says so.
	Now bool
	By  By
}

// Finish cuts over to the key of the planned rotation, or the one for a move,
// that is open (A rotation, step 3).
func (r *Ring) Finish(ctx context.Context, in FinishInput) (Finished, error) {
	var out Finished
	err := r.change(ctx, true, func(tx pgx.Tx, rows []row) error {
		k, ok := inProgress(rows)
		if !ok {
			return ErrNoRotation
		}
		if !in.BackupTaken {
			return ErrBackup
		}
		now := r.now()
		if !in.Now && now.Before(k.CreatedAt.Add(MinOverlap)) {
			return apperr.Conflict(ErrTooEarly.Code, fmt.Sprintf("A rotation can be finished 24 hours after it started: at %s.", k.CreatedAt.Add(MinOverlap).UTC().Format(time.RFC3339)))
		}
		if _, err := tx.Exec(ctx, `UPDATE job_keys SET cut_over_at = $2 WHERE generation = $1`, k.Generation, now); err != nil {
			return err
		}
		moved, total, err := countReporting(ctx, tx, k.Public)
		if err != nil {
			return err
		}
		out = Finished{Key: k.Key, Moved: moved, NotMoved: total - moved}
		out.Key.CutOverAt = &now
		return r.write(ctx, tx, r.event(in.By, "job_key.finish", map[string]any{
			"fingerprint": k.Fingerprint(), "generation": k.Generation, "devicesMoved": moved, "devicesNotMoved": total - moved,
			"backupTaken": in.BackupTaken, "skippedMinimum": in.Now && now.Before(k.CreatedAt.Add(MinOverlap)),
		}))
	})
	return out, err
}

func b64(pub []byte) string { return base64.StdEncoding.EncodeToString(pub) }

// countReporting counts the enrolled devices and those whose report has the
// key.
func countReporting(ctx context.Context, tx pgx.Tx, pub []byte) (reporting, total int, err error) {
	err = tx.QueryRow(ctx, `SELECT count(*) FILTER (WHERE job_keys_report IS NOT NULL AND EXISTS (
				SELECT 1 FROM jsonb_array_elements(job_keys_report) e WHERE e->>'key' = $1)),
			count(*) FROM devices WHERE agent_public_key IS NOT NULL`, b64(pub)).Scan(&reporting, &total)
	return
}

// needRepin counts the devices whose report has the key and none of the held
// ones: those that would trust nothing the server can sign with.
func needRepin(ctx context.Context, tx pgx.Tx, pub []byte, held []string) (int, error) {
	var n int
	err := tx.QueryRow(ctx, `SELECT count(*) FROM devices WHERE job_keys_report IS NOT NULL
			AND EXISTS (SELECT 1 FROM jsonb_array_elements(job_keys_report) e WHERE e->>'key' = $1)
			AND NOT EXISTS (SELECT 1 FROM jsonb_array_elements(job_keys_report) e WHERE e->>'key' = ANY($2))`, b64(pub), held).Scan(&n)
	return n, err
}

func heldOthers(rows []row, except int64) []string {
	held := []string{}
	for _, k := range rows {
		if k.Generation != except && k.sealed != nil && k.LostAt == nil {
			held = append(held, b64(k.Public))
		}
	}
	return held
}

// Forget deletes a key's seed (A rotation, step 4): never the newest key. The
// devices still on it then need re-pinning.
func (r *Ring) Forget(ctx context.Context, generation int64, by By) (leftRepinning int, err error) {
	err = r.change(ctx, false, func(tx pgx.Tx, rows []row) error {
		var k *row
		for i := range rows {
			if rows[i].Generation == generation {
				k = &rows[i]
			}
		}
		switch {
		case k == nil:
			return ErrNoSuchKey
		case k.Generation == rows[len(rows)-1].Generation:
			return ErrNewestKey
		case k.sealed == nil:
			return ErrNoSeed
		}
		n, err := needRepin(ctx, tx, k.Public, heldOthers(rows, generation))
		if err != nil {
			return err
		}
		leftRepinning = n
		if _, err := tx.Exec(ctx, `UPDATE job_keys SET sealed_seed = NULL, seed_deleted_at = $2 WHERE generation = $1`, generation, r.now()); err != nil {
			return err
		}
		return r.write(ctx, tx, r.event(by, "job_key.forget", map[string]any{
			"fingerprint": k.Fingerprint(), "generation": generation, "by": "person", "devicesNeedingRepinning": n}))
	})
	return leftRepinning, err
}

// SweepSeeds deletes the seed of every key older than the floor that no
// device may still trust: an enrolled device whose last report has it, one
// that never reported and was given it at enrollment, or a removed device
// (retired_devices) in the same case. Its public key and its record stay. A
// lost key's seed is kept. It does nothing while the updater holds the server.
func (r *Ring) SweepSeeds(ctx context.Context) (int, error) {
	var gone int
	err := r.change(ctx, false, func(tx pgx.Tx, rows []row) error {
		floor := int64(0)
		for _, k := range rows {
			if k.CutOverAt != nil {
				floor = k.Generation
			}
		}
		for _, k := range rows {
			if k.Generation >= floor || k.sealed == nil || k.LostAt != nil {
				continue
			}
			var needed bool
			if err := tx.QueryRow(ctx, `SELECT EXISTS (
					SELECT 1 FROM (SELECT job_keys_report, job_key_given_generation FROM devices
						UNION ALL SELECT job_keys_report, job_key_given_generation FROM retired_devices) d
					WHERE (job_keys_report IS NOT NULL AND EXISTS (SELECT 1 FROM jsonb_array_elements(job_keys_report) e WHERE e->>'key' = $1))
						OR (job_keys_report IS NULL AND coalesce(job_key_given_generation, 1) = $2))`, b64(k.Public), k.Generation).Scan(&needed); err != nil {
				return err
			}
			if needed {
				continue
			}
			if _, err := tx.Exec(ctx, `UPDATE job_keys SET sealed_seed = NULL, seed_deleted_at = $2 WHERE generation = $1`, k.Generation, r.now()); err != nil {
				return err
			}
			gone++
			if err := r.write(ctx, tx, r.event(By{Actor: audit.SystemActor("jobkeys")}, "job_key.forget", map[string]any{
				"fingerprint": k.Fingerprint(), "generation": k.Generation, "by": "server", "devicesNeedingRepinning": 0})); err != nil {
				return err
			}
		}
		return nil
	})
	return gone, err
}

// sealedSettings are the other values the server opens at start, by settings
// key and additional data.
var sealedSettings = []struct{ key, aad string }{
	{"tls.internal_ca", "easyrmm:tls.internal_ca"},
	{"meshcentral.secrets", "setting:meshcentral.secrets"},
}

// checkEnv refuses unless every other sealed value the database holds opens
// with the current encryption key: a seed lost because .env is wrong is fixed
// in .env, not by replacing the key.
func (r *Ring) checkEnv(ctx context.Context, tx pgx.Tx) error {
	for _, s := range sealedSettings {
		var raw []byte
		err := tx.QueryRow(ctx, `SELECT value FROM settings WHERE key = $1`, s.key).Scan(&raw)
		if errors.Is(err, pgx.ErrNoRows) {
			continue
		}
		if err != nil {
			return err
		}
		var v struct {
			Sealed string `json:"sealed"`
		}
		if json.Unmarshal(raw, &v) != nil || v.Sealed == "" {
			continue
		}
		if _, err := r.sealer.Open(v.Sealed, []byte(s.aad)); err != nil {
			return ErrEnvDiffers
		}
	}
	return nil
}

// ReplaceLost marks every key whose seed does not open lost and makes a new
// key, with no hand-over, that is the floor at once, in one transaction under
// the ring's lock. It is for the host. A planned rotation in progress ends
// there; the devices on the lost key need re-pinning.
func (r *Ring) ReplaceLost(ctx context.Context, by By) (lost []int64, k Key, err error) {
	err = r.change(ctx, false, func(tx pgx.Tx, rows []row) error {
		for _, k := range rows {
			if k.sealed == nil || k.LostAt != nil {
				continue
			}
			if _, err := r.sealer.Open(*k.sealed, aad(k.Generation)); err != nil {
				lost = append(lost, k.Generation)
			}
		}
		if len(lost) == 0 {
			return ErrNothing
		}
		if err := r.checkEnv(ctx, tx); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE job_keys SET lost_at = $2 WHERE generation = ANY($1) AND lost_at IS NULL`, lost, r.now()); err != nil {
			return err
		}
		nk, err := r.makeKey(ctx, tx, ReasonLostReplacement, by, true)
		if err != nil {
			return err
		}
		k = nk
		return r.write(ctx, tx, r.event(by, "job_key.replace_lost", map[string]any{
			"lostGenerations": lost, "fingerprint": k.Fingerprint(), "generation": k.Generation}))
	})
	k.Private = nil
	return lost, k, err
}

// Recover opens the sealed seed of a key marked lost with the current
// encryption key or one of EASYRMM_SECRET_KEYS_PREVIOUS; if it opens, the key
// is held again, and the devices still on it get the hand-over to the floor.
// It returns how many devices no longer need re-pinning.
func (r *Ring) Recover(ctx context.Context, generation int64, by By) (stopped int, err error) {
	err = r.change(ctx, false, func(tx pgx.Tx, rows []row) error {
		var k *row
		for i := range rows {
			if rows[i].Generation == generation {
				k = &rows[i]
			}
		}
		switch {
		case k == nil:
			return ErrNoSuchKey
		case k.LostAt == nil:
			return ErrNotLost
		case k.sealed == nil:
			return ErrNoSeed
		}
		seed, err := r.sealer.Open(*k.sealed, aad(generation))
		if err != nil || len(seed) != ed25519.SeedSize || !ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey).Equal(k.Public) {
			return ErrOpens
		}
		n, err := needRepin(ctx, tx, k.Public, heldOthers(rows, generation))
		if err != nil {
			return err
		}
		stopped = n
		if _, err := tx.Exec(ctx, `UPDATE job_keys SET lost_at = NULL WHERE generation = $1`, generation); err != nil {
			return err
		}
		return r.write(ctx, tx, r.event(by, "job_key.recover", map[string]any{
			"fingerprint": k.Fingerprint(), "generation": generation, "devicesNoLongerNeedingRepinning": n}))
	})
	return stopped, err
}

// Snapshot reads the ring from the database without opening any seed: what
// the host's status command prints, which works when the server cannot start.
func (r *Ring) Snapshot(ctx context.Context) ([]Key, error) {
	var keys []Key
	err := r.db.ReadTx(ctx, database.System, func(tx pgx.Tx) error {
		rows, err := readRows(ctx, tx)
		for _, k := range rows {
			keys = append(keys, k.Key)
		}
		return err
	})
	return keys, err
}
