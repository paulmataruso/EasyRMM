package quickassist

import (
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"path/filepath"
	"runtime"
	"time"

	"github.com/paulmataruso/easyrmm/agent/client"
	"github.com/paulmataruso/easyrmm/agent/meshagent"
	"github.com/paulmataruso/easyrmm/internal/agentproto"
)

// meshRun is the MeshAgent a session starts, with the exact identity it
// was given.
type meshRun struct {
	mgr    *meshagent.Manager
	name   string
	dir    string
	cancel context.CancelFunc
}

// serviceName is the per-session identity (ADR-0071, ADR-0080): its folder,
// database, node key, registry key and certificate subject all follow from
// it, and it is never "Mesh Agent" or "EasyRMMMeshAgent".
func serviceName(sessionID string) string {
	id := sessionID
	b, _ := hex.DecodeString(stripDashes(sessionID))
	if len(b) >= 4 {
		id = hex.EncodeToString(b[:4])
	}
	return "EasyRMMQA-" + id
}

func stripDashes(s string) string {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		if s[i] != '-' {
			out = append(out, s[i])
		}
	}
	return string(out)
}

// startMesh downloads our MeshAgent, checks the server's signature on it and
// on its settings, gives the settings this session's name and tag, and
// starts it as a confined child with "meshagent connect": nothing is
// installed. It reports the node to the server once MeshAgent has made its
// identity. A server without remote access answers an error, which is said
// to the user and the session goes on without remote control.
func startMesh(ctx context.Context, c *client.Client, o Options, cf *confiner, dir string, res *client.QAEnrollResult) (*meshRun, error) {
	key, err := agentproto.DecodeKey(res.JobKey)
	if err != nil {
		return nil, fmt.Errorf("the server's key: %w", err)
	}
	settings, sig, err := c.MeshSettings(ctx)
	if err != nil {
		return nil, fmt.Errorf("fetching MeshAgent's settings: %w", err)
	}
	if err := sig.Verify(key); err != nil {
		return nil, fmt.Errorf("MeshAgent's settings are not signed by the server: %w", err)
	}
	name := serviceName(res.SessionID)
	settings = meshagent.WithServiceName(settings, name)
	settings = append(settings, []byte("\nTag="+stripDashes(res.SessionID)+"\n")...)
	mdir := filepath.Join(dir, "mesh")
	ctx, cancel := context.WithCancel(ctx)
	m := meshagent.NewManager(mdir, meshagent.ModeAdHoc, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	m.Confine, m.Started = cf.Confine, cf.Started
	err = m.Install(ctx, func(w io.Writer) error {
		sig, err := c.MeshAgent(ctx, runtime.GOOS, runtime.GOARCH, w)
		if err != nil {
			return err
		}
		return sig.Verify(key)
	}, settings)
	if err != nil {
		cancel()
		return nil, err
	}
	mr := &meshRun{mgr: m, name: name, dir: mdir, cancel: cancel}
	go func() {
		// MeshAgent creates its identity within seconds of its first start.
		for i := 0; i < 60; i++ {
			select {
			case <-ctx.Done():
				return
			case <-time.After(2 * time.Second):
			}
			if id, err := m.NodeID(ctx); err == nil && id != "" {
				_ = c.QAMesh(ctx, id)
				return
			}
		}
	}()
	return mr, nil
}

// stop ends the MeshAgent child by the exact image path in the session
// folder (never by name) and removes what it made outside that folder.
func (r *meshRun) stop(ctx context.Context) []string {
	if r == nil {
		return nil
	}
	r.cancel()
	r.mgr.Stop()
	return removeNodeKeys(r.name)
}
