package jobs

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
)

// Journal states of a run.
const (
	stateReceived = "received"
	stateStarted  = "started"
	stateFinished = "finished"
)

// record is one run in the journal.
type record struct {
	RunID     string                    `json:"runId"`
	JobID     string                    `json:"jobId"`
	State     string                    `json:"state"`
	ExpiresAt time.Time                 `json:"expiresAt"`
	Result    *agentproto.ResultRequest `json:"result,omitempty"`
}

// journal keeps a file per run the agent has not finished reporting, so a
// restarted agent never runs a job twice and still reports what it ran.
// Each file is replaced atomically and synced before the agent acts on it.
type journal struct {
	dir string
}

func (j journal) path(runID string) (string, error) {
	if _, err := uuid.Parse(runID); err != nil {
		return "", fmt.Errorf("run id %q is not a UUID", runID)
	}
	return filepath.Join(j.dir, runID+".json"), nil
}

func (j journal) put(r record) error {
	p, err := j.path(r.RunID)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(j.dir, 0o700); err != nil {
		return err
	}
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(j.dir, ".tmp-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if _, err := tmp.Write(b); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), p)
}

func (j journal) remove(runID string) error {
	p, err := j.path(runID)
	if err != nil {
		return err
	}
	if err := os.Remove(p); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}

// load reads every record; unreadable files are skipped and reported.
func (j journal) load() ([]record, []error) {
	entries, err := os.ReadDir(j.dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, []error{err}
	}
	var (
		out  []record
		errs []error
	)
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".json") || strings.HasPrefix(name, ".") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(j.dir, name)) //nolint:gosec // inside the agent's state directory
		if err != nil {
			errs = append(errs, err)
			continue
		}
		var r record
		if err := json.Unmarshal(b, &r); err != nil || r.RunID+".json" != name {
			errs = append(errs, fmt.Errorf("journal entry %s is damaged", name))
			continue
		}
		out = append(out, r)
	}
	return out, errs
}
