package jobs

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/secrets"
)

const (
	keySetting = "jobs.signing_key" //nolint:gosec // a settings key, not a credential
	keyAAD     = "easyrmm:" + keySetting
)

// storedKey is the sealed settings value.
type storedKey struct {
	Sealed string `json:"sealed"`
}

// LoadKey reads the job-signing key from the settings table, creating it on
// first use. When two servers start at once, the first one stored wins. The
// key is sealed under the server's secret key; agents pin its public half,
// so it must outlive restarts.
func LoadKey(ctx context.Context, db *database.DB, sealer *secrets.Sealer) (ed25519.PrivateKey, error) {
	var seed []byte
	err := db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		var raw []byte
		err := tx.QueryRow(ctx, `SELECT value FROM settings WHERE key = $1`, keySetting).Scan(&raw)
		if errors.Is(err, pgx.ErrNoRows) {
			_, fresh, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				return err
			}
			value, err := sealKey(sealer, fresh.Seed())
			if err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `INSERT INTO settings (key, value) VALUES ($1, $2) ON CONFLICT (key) DO NOTHING`, keySetting, value); err != nil {
				return err
			}
			err = tx.QueryRow(ctx, `SELECT value FROM settings WHERE key = $1`, keySetting).Scan(&raw)
			if err != nil {
				return err
			}
		} else if err != nil {
			return err
		}
		var s storedKey
		if err := json.Unmarshal(raw, &s); err != nil {
			return fmt.Errorf("jobs: reading the stored signing key: %w", err)
		}
		seed, err = sealer.Open(s.Sealed, []byte(keyAAD))
		if err != nil {
			return fmt.Errorf("jobs: opening the stored signing key (was EASYRMM_SECRET_KEY changed without listing the old key in EASYRMM_SECRET_KEYS_PREVIOUS?): %w", err)
		}
		if len(seed) != ed25519.SeedSize {
			return errors.New("jobs: the stored signing key is not an Ed25519 seed")
		}
		if !sealer.NeedsReseal(s.Sealed) {
			return nil
		}
		value, err := sealKey(sealer, seed)
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `UPDATE settings SET value = $2, updated_at = now() WHERE key = $1`, keySetting, value)
		return err
	})
	if err != nil {
		return nil, err
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

func sealKey(sealer *secrets.Sealer, seed []byte) ([]byte, error) {
	sealed, err := sealer.Seal(seed, []byte(keyAAD))
	if err != nil {
		return nil, err
	}
	return json.Marshal(storedKey{Sealed: sealed})
}
