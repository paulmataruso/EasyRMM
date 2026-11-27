package updater

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
)

// StatusFile is the updater's status document in the status directory.
const StatusFile = "status.json"

// Errors Guard returns.
var (
	// ErrHeldByUpdater is returned while the hold file exists.
	ErrHeldByUpdater = errors.New("updater: the updater holds the server")
	// ErrUpgradeUnderway is returned while the updater's status shows an
	// upgrade or a rollback that has not ended.
	ErrUpgradeUnderway = errors.New("updater: an upgrade is under way")
)

// Guard returns a check of the status directory for what a change to the
// job key ring must not run beside (ADR-0057, "One lock for every change to
// the ring"): the hold file, looked at itself on every call and not through
// the flag Hold keeps, and an upgrade or a rollback the status shows as
// running. A directory or a file that does not exist means no updater and
// nothing is held; a status that cannot be read is not believed to be
// idle, so it holds too.
func Guard(dir string) func() error {
	return func() error {
		if dir == "" {
			return nil
		}
		if _, err := os.Lstat(filepath.Join(dir, HoldFile)); !errors.Is(err, fs.ErrNotExist) {
			return ErrHeldByUpdater // present, or not readable: held
		}
		b, err := os.ReadFile(filepath.Join(dir, StatusFile)) //nolint:gosec // the status directory is the operator's configuration, not a request
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		if err != nil {
			return ErrUpgradeUnderway
		}
		var s struct {
			Attempt *struct {
				Result string `json:"result"`
			} `json:"attempt"`
		}
		if err := json.Unmarshal(b, &s); err != nil {
			return ErrUpgradeUnderway
		}
		if s.Attempt != nil && s.Attempt.Result == "running" {
			return ErrUpgradeUnderway
		}
		return nil
	}
}
