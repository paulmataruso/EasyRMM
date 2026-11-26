// Package defender manages the Microsoft Defender exclusions of the EasyRMM
// agent (ADR-0070): it locks each working folder down, verifies it, adds
// the exclusions, keeps a record of exactly what it added, reports whether
// they work, and removes what it recorded. The logic is here, apart from
// the Windows calls it needs (Backend, System), so it is tested everywhere.
package defender

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
)

// RecordFile is the record's name in the agent's state folder. install.ps1
// writes the same file in the same format before the agent exists.
const RecordFile = "defender-exclusions.json"

// Entry is one exclusion the agent added.
type Entry struct {
	Kind         string    `json:"kind"`
	Path         string    `json:"path"`
	At           time.Time `json:"at"`
	AgentVersion string    `json:"agentVersion"`
}

// Record is exactly what the agent added to Defender's lists.
type Record struct {
	Version int     `json:"version"`
	Entries []Entry `json:"entries"`
}

// ErrCorrupt is a record that cannot be read.
var ErrCorrupt = errors.New("the Defender record cannot be read")

// Norm is the form in which paths are compared: absolute, cleaned,
// case-insensitive (Windows paths are).
func Norm(p string) string {
	p = strings.ReplaceAll(strings.TrimSpace(p), "/", `\`)
	for len(p) > 3 && strings.HasSuffix(p, `\`) {
		p = p[:len(p)-1]
	}
	return strings.ToLower(p)
}

func same(a, b string) bool { return Norm(a) == Norm(b) }

// Has reports whether the record holds the exclusion.
func (r *Record) Has(kind, path string) bool { return r.index(kind, path) >= 0 }

func (r *Record) index(kind, path string) int {
	for i, e := range r.Entries {
		if e.Kind == kind && same(e.Path, path) {
			return i
		}
	}
	return -1
}

// Put records an exclusion, once.
func (r *Record) Put(e Entry) {
	if !r.Has(e.Kind, e.Path) {
		r.Entries = append(r.Entries, e)
	}
}

// Drop forgets an exclusion.
func (r *Record) Drop(kind, path string) {
	if i := r.index(kind, path); i >= 0 {
		r.Entries = append(r.Entries[:i], r.Entries[i+1:]...)
	}
}

// LoadRecord reads the record. found is false when there is none; a file
// that is not a record is ErrCorrupt.
func LoadRecord(file string) (r Record, found bool, err error) {
	b, err := os.ReadFile(file) //nolint:gosec // the agent's protected state folder
	if errors.Is(err, fs.ErrNotExist) {
		return Record{Version: 1}, false, nil
	}
	if err != nil {
		return Record{Version: 1}, false, err
	}
	if err := json.Unmarshal(b, &r); err != nil || r.Version != 1 {
		return Record{Version: 1}, true, ErrCorrupt
	}
	for _, e := range r.Entries {
		if !validKind(e.Kind) || e.Path == "" {
			return Record{Version: 1}, true, ErrCorrupt
		}
	}
	return r, true, nil
}

func validKind(k string) bool {
	for _, x := range agentproto.DefenderKinds {
		if x == k {
			return true
		}
	}
	return false
}

// Save writes the record, replacing the file whole.
func (r Record) Save(file string) error {
	r.Version = 1
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(file), 0o700); err != nil {
		return err
	}
	tmp := file + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return fmt.Errorf("writing the Defender record: %w", err)
	}
	if err := os.Rename(tmp, file); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("writing the Defender record: %w", err)
	}
	return nil
}
