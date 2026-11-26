package keystored

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"
)

// What the state directory holds (ADR-0081, section 2). It is outside the
// data root and the deployment directory, so no backup copies it.
const (
	stateFileName = "state.json"
	recoveryDir   = "recovery"
	stateFormat   = 1
)

// versionRecord is one KEK version's metadata; the key itself is in
// kek-v<N>.sealed, protected by the mode.
type versionRecord struct {
	Version    int       `json:"version"`
	CheckValue []byte    `json:"checkValue"`
	Mode       string    `json:"mode"`
	State      string    `json:"state"` // "active" or "pending"
	CreatedAt  time.Time `json:"createdAt"`
	// RecoveryVerifiedAt is set when verify-recovery proved the version's
	// bundle opens with the code.
	RecoveryVerifiedAt *time.Time `json:"recoveryVerifiedAt,omitempty"`
}

// stateFile is state.json. It holds no key.
type stateFile struct {
	Format int    `json:"format"`
	Mode   string `json:"mode"`
	// Salt is the passphrase mode's Argon2id salt.
	Salt []byte `json:"salt,omitempty"`
	// RecoverySalt and RecoveryPub are all the keystore keeps of the
	// recovery code: the salt it was stretched with and the public half of
	// the key pair derived from it.
	RecoverySalt []byte          `json:"recoverySalt"`
	RecoveryPub  []byte          `json:"recoveryPub"`
	Versions     []versionRecord `json:"versions"`
}

func (s *stateFile) version(v int) *versionRecord {
	for i := range s.Versions {
		if s.Versions[i].Version == v {
			return &s.Versions[i]
		}
	}
	return nil
}

func (s *stateFile) newest() int {
	n := 0
	for _, v := range s.Versions {
		n = max(n, v.Version)
	}
	return n
}

// primary is the newest version whose recovery was proved, or 0.
func (s *stateFile) primary() int {
	n := 0
	for _, v := range s.Versions {
		if v.State == "active" && v.RecoveryVerifiedAt != nil {
			n = max(n, v.Version)
		}
	}
	return n
}

func loadState(dir string) (*stateFile, error) {
	b, err := os.ReadFile(filepath.Join(dir, stateFileName)) //nolint:gosec // the keystore's own state directory
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var s stateFile
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, fmt.Errorf("keystore: the state file is damaged: %w", err)
	}
	if s.Format != stateFormat {
		return nil, fmt.Errorf("keystore: the state file has format %d; this build reads %d", s.Format, stateFormat)
	}
	return &s, nil
}

func saveState(dir string, s *stateFile) error {
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(filepath.Join(dir, stateFileName), b, 0o600)
}

// writeFileAtomic writes through a temporary file and a rename, and syncs
// both the file and its directory, so that a crash leaves the old or the new
// file and never half of one.
func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	name := f.Name()
	ok := false
	defer func() {
		if !ok {
			_ = os.Remove(name)
		}
	}()
	if err := f.Chmod(mode); err != nil {
		_ = f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, path); err != nil {
		return err
	}
	ok = true
	if d, err := os.Open(dir); err == nil { //nolint:gosec // the state directory
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}
