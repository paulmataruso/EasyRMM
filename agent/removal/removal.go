// Package removal acts on the server's instruction to uninstall the agent
// (ADR-0050). The agent cannot remove itself from inside its own service:
// stopping the service stops the uninstall too. So it writes the signed
// instruction where the uninstaller finds it and starts the uninstaller
// outside the service, which removes the service, MeshAgent and the agent's
// files and tells the server how that went.
package removal

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
)

// File is the instruction's name in the agent's state folder.
const File = "removal.json"

// Remover starts the uninstaller when a heartbeat answer says so.
type Remover struct {
	DeviceID string
	// Key returns the pinned job key, nil while none is pinned.
	Key func() ed25519.PublicKey
	// Dir is the agent's state folder.
	Dir string
	Log *slog.Logger
	// Launch starts the uninstaller with the instruction at file. inline
	// means there is no service to leave: the agent stops and uninstalls
	// itself in its own process.
	Launch func(ctx context.Context, file string) (inline bool, err error)
	// Report tells the server that the uninstall could not start.
	Report func(ctx context.Context, r agentproto.RemovedReport) error
	// Now is the clock, replaced by tests.
	Now func() time.Time

	// The removal last started, so that the instructions repeated with
	// each heartbeat do not start it again while it runs.
	started   string
	startedAt time.Time
}

// Apply verifies an uninstall instruction and starts the uninstaller. It
// returns true when the agent must stop and uninstall itself in its own
// process (Launch said inline).
func (r *Remover) Apply(ctx context.Context, u *agentproto.SignedUninstall) bool {
	if u == nil {
		return false
	}
	now := time.Now()
	if r.Now != nil {
		now = r.Now()
	}
	p, err := agentproto.VerifyUninstall(r.Key(), *u, r.DeviceID, now)
	if err != nil {
		r.Log.Error("refused an uninstall instruction", "error", err)
		return false
	}
	if p.ID == r.started && now.Sub(r.startedAt) < agentproto.UninstallRunning {
		return false // the uninstaller runs; it stops this agent
	}
	file := filepath.Join(r.Dir, File)
	b, err := json.Marshal(u)
	if err == nil {
		err = os.WriteFile(file, b, 0o600)
	}
	inline := false
	if err == nil {
		inline, err = r.Launch(ctx, file)
	}
	if err != nil {
		r.Log.Error("starting the uninstall failed", "error", err)
		rep := agentproto.RemovedReport{ID: p.ID, Error: fmt.Sprintf("Starting the uninstall failed: %v", err)}
		if err := r.Report(ctx, rep); err != nil {
			r.Log.Warn("reporting the failed uninstall failed", "error", err)
		}
		return false
	}
	r.started, r.startedAt = p.ID, now
	r.Log.Info("the server asked for this agent to be uninstalled", "removal", p.ID, "inline", inline)
	return inline
}
