package removal

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
)

type rig struct {
	r        *Remover
	priv     ed25519.PrivateKey
	now      time.Time
	launches []string
	inline   bool
	fail     error
	reports  []agentproto.RemovedReport
}

func newRig(t *testing.T) *rig {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(nil)
	g := &rig{priv: priv, now: time.Now()}
	g.r = &Remover{
		DeviceID: "dev-1", Key: func() ed25519.PublicKey { return pub }, Dir: t.TempDir(),
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Launch: func(_ context.Context, file string) (bool, error) {
			g.launches = append(g.launches, file)
			return g.inline, g.fail
		},
		Report: func(_ context.Context, r agentproto.RemovedReport) error {
			g.reports = append(g.reports, r)
			return nil
		},
		Now: func() time.Time { return g.now },
	}
	return g
}

func (g *rig) instruction(t *testing.T, id, device string) *agentproto.SignedUninstall {
	t.Helper()
	u, err := agentproto.SignUninstall(g.priv, agentproto.UninstallPayload{
		V: agentproto.UninstallPayloadVersion, ID: id, DeviceID: device, IssuedAt: g.now, ExpiresAt: g.now.Add(10 * time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}
	return &u
}

func TestApply(t *testing.T) {
	g := newRig(t)
	ctx := context.Background()
	if g.r.Apply(ctx, nil) || len(g.launches) != 0 {
		t.Fatal("no instruction started something")
	}
	// Another device's, or another server's, instruction is refused.
	if g.r.Apply(ctx, g.instruction(t, "r1", "dev-2")) || len(g.launches) != 0 {
		t.Error("another device's instruction started the uninstall")
	}
	_, other, _ := ed25519.GenerateKey(nil)
	forged, _ := agentproto.SignUninstall(other, agentproto.UninstallPayload{V: 1, ID: "r1", DeviceID: "dev-1", ExpiresAt: g.now.Add(time.Minute)})
	if g.r.Apply(ctx, &forged) || len(g.launches) != 0 {
		t.Error("a forged instruction started the uninstall")
	}

	// The instruction is saved for the uninstaller, private to the agent.
	u := g.instruction(t, "r1", "dev-1")
	if g.r.Apply(ctx, u) {
		t.Error("inline without being told")
	}
	if len(g.launches) != 1 || g.launches[0] != filepath.Join(g.r.Dir, File) {
		t.Fatalf("launches %v", g.launches)
	}
	b, err := os.ReadFile(g.launches[0])
	var saved agentproto.SignedUninstall
	if err != nil || json.Unmarshal(b, &saved) != nil || saved != *u {
		t.Errorf("saved %q %v", b, err)
	}
	if st, err := os.Stat(g.launches[0]); runtime.GOOS != "windows" && (err != nil || st.Mode().Perm() != 0o600) {
		t.Errorf("file mode %v %v", st.Mode(), err)
	}
	// Repeated with each heartbeat while the uninstaller runs: started once.
	g.now = g.now.Add(time.Minute)
	g.r.Apply(ctx, g.instruction(t, "r1", "dev-1"))
	if len(g.launches) != 1 {
		t.Errorf("started again at once: %d", len(g.launches))
	}
	// Still asked after the uninstaller had its time: started again.
	g.now = g.now.Add(agentproto.UninstallRunning)
	g.r.Apply(ctx, g.instruction(t, "r1", "dev-1"))
	if len(g.launches) != 2 {
		t.Errorf("not started again: %d", len(g.launches))
	}
	// Another removal starts at once.
	g.r.Apply(ctx, g.instruction(t, "r2", "dev-1"))
	if len(g.launches) != 3 {
		t.Errorf("another removal not started: %d", len(g.launches))
	}
	if len(g.reports) != 0 {
		t.Errorf("reports %+v", g.reports)
	}

	// Without a service, the agent uninstalls itself in its own process.
	g.inline = true
	if !g.r.Apply(ctx, g.instruction(t, "r3", "dev-1")) {
		t.Error("inline not passed on")
	}
}

func TestApplyLaunchFails(t *testing.T) {
	g := newRig(t)
	g.fail = errors.New("systemd-run: exit status 1")
	if g.r.Apply(context.Background(), g.instruction(t, "r1", "dev-1")) {
		t.Error("stop after a failed launch")
	}
	if len(g.reports) != 1 || g.reports[0].ID != "r1" || g.reports[0].Removed || !strings.Contains(g.reports[0].Error, "systemd-run: exit status 1") {
		t.Fatalf("reports %+v", g.reports)
	}
	// The next instruction tries again.
	g.fail = nil
	g.r.Apply(context.Background(), g.instruction(t, "r1", "dev-1"))
	if len(g.launches) != 2 {
		t.Errorf("launches %d", len(g.launches))
	}
	// A state folder that cannot be written: reported, nothing launched.
	g.r.Dir = filepath.Join(g.r.Dir, "missing")
	g.r.Apply(context.Background(), g.instruction(t, "r9", "dev-1"))
	if len(g.launches) != 2 || len(g.reports) != 2 {
		t.Errorf("launches %d, reports %d", len(g.launches), len(g.reports))
	}
}

// TestFileName: the agent checks its state folder by name before reading
// it (state.layout); the instruction is checked as removal.json.
func TestFileName(t *testing.T) {
	if File != "removal.json" {
		t.Errorf("File = %s: rename it in state.layout too", File)
	}
}
