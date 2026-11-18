// Package remote integrates MeshCentral for remote desktop, terminal and
// file access (ADR-0004, ADR-0005): it keeps MeshCentral's device groups,
// accounts and rights in step with EasyRMM, discovers devices, launches
// remote sessions, and gates browser access to the MeshCentral hostname.
package remote

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/meshcentral"
	"github.com/paulmataruso/easyrmm/server/internal/secrets"
)

// Secrets are the values EasyRMM shares with MeshCentral.
type Secrets struct {
	// LoginKey is MeshCentral's loginCookieEncryptionKey.
	LoginKey []byte
	// SessionKey encrypts MeshCentral's own session cookies.
	SessionKey string
}

const (
	secretsSetting = "meshcentral.secrets" //nolint:gosec // a settings key, not a credential
	secretsAAD     = "setting:" + secretsSetting
)

type sealedSecrets struct {
	Sealed string `json:"sealed"`
}

type plainSecrets struct {
	LoginKey   string `json:"loginKey"`
	SessionKey string `json:"sessionKey"`
}

// LoadSecrets returns the shared secrets, generating and storing them
// (sealed with the server's secret key) on first use. Values sealed with a
// previous secret key are resealed with the current one.
func LoadSecrets(ctx context.Context, db *database.DB, sealer *secrets.Sealer) (*Secrets, error) {
	var out *Secrets
	err := db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		// Serialize concurrent first starts.
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, secretsSetting); err != nil {
			return err
		}
		var raw []byte
		err := tx.QueryRow(ctx, `SELECT value FROM settings WHERE key = $1`, secretsSetting).Scan(&raw)
		switch {
		case errors.Is(err, pgx.ErrNoRows):
			s, err := newSecrets()
			if err != nil {
				return err
			}
			if err := storeSecrets(ctx, tx, sealer, s); err != nil {
				return err
			}
			out = s
			return nil
		case err != nil:
			return err
		}
		var stored sealedSecrets
		if err := json.Unmarshal(raw, &stored); err != nil {
			return fmt.Errorf("decoding %s: %w", secretsSetting, err)
		}
		plain, err := sealer.Open(stored.Sealed, []byte(secretsAAD))
		if err != nil {
			return fmt.Errorf("opening %s (was EASYRMM_SECRET_KEY changed without listing the old key in EASYRMM_SECRET_KEYS_PREVIOUS?): %w", secretsSetting, err)
		}
		var p plainSecrets
		if err := json.Unmarshal(plain, &p); err != nil {
			return fmt.Errorf("decoding %s: %w", secretsSetting, err)
		}
		key, err := hex.DecodeString(p.LoginKey)
		if err != nil || len(key) != meshcentral.KeySize || len(p.SessionKey) < 32 {
			return fmt.Errorf("%s is malformed", secretsSetting)
		}
		out = &Secrets{LoginKey: key, SessionKey: p.SessionKey}
		if sealer.NeedsReseal(stored.Sealed) {
			return storeSecrets(ctx, tx, sealer, out)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("remote access secrets: %w", err)
	}
	return out, nil
}

func newSecrets() (*Secrets, error) {
	key, err := meshcentral.NewKey()
	if err != nil {
		return nil, err
	}
	sk := make([]byte, 48)
	if _, err := rand.Read(sk); err != nil {
		return nil, err
	}
	return &Secrets{LoginKey: key, SessionKey: hex.EncodeToString(sk)}, nil
}

func storeSecrets(ctx context.Context, tx pgx.Tx, sealer *secrets.Sealer, s *Secrets) error {
	//nolint:gosec // sealed below before it is stored
	plain, err := json.Marshal(plainSecrets{LoginKey: meshcentral.KeyHex(s.LoginKey), SessionKey: s.SessionKey})
	if err != nil {
		return err
	}
	sealed, err := sealer.Seal(plain, []byte(secretsAAD))
	if err != nil {
		return err
	}
	value, err := json.Marshal(sealedSecrets{Sealed: sealed})
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO settings (key, value) VALUES ($1, $2)
		ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()`, secretsSetting, value)
	return err
}
