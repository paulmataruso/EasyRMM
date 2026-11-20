//go:build !windows

package easypatch

import (
	"context"
	"strings"
	"testing"
	"time"
)

// A program past its deadline is asked to stop and given time to, as apt-get
// and dnf need to leave their databases sound.
func TestRunAsksToStopFirst(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 300*time.Millisecond)
	defer cancel()
	script := `trap 'echo stopped cleanly; exit 7' TERM; sleep 30 >/dev/null 2>&1 & wait`
	_, out, err := run(ctx, "", nil, "/bin/sh", "-c", script)
	if err == nil || !strings.Contains(err.Error(), "sh did not finish in time") {
		t.Errorf("err: %v", err)
	}
	if !strings.Contains(string(out), "stopped cleanly") {
		t.Errorf("not asked to stop: %q", out)
	}
}

// One that does not stop when asked is killed after the grace period.
func TestRunKillsWhatDoesNotStop(t *testing.T) {
	old := stopGrace
	stopGrace = 300 * time.Millisecond
	t.Cleanup(func() { stopGrace = old })
	ctx, cancel := context.WithTimeout(t.Context(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, _, err := run(ctx, "", nil, "/bin/sh", "-c", `trap '' TERM; sleep 5`)
	if err == nil || !strings.Contains(err.Error(), "did not finish in time") {
		t.Errorf("err: %v", err)
	}
	if took := time.Since(start); took > 3*time.Second {
		t.Errorf("took %v: not killed after the grace period", took)
	}
}

// A program that finished well, leaving something it started holding its
// output (a service a package's script started, say), has succeeded.
func TestRunFinishedButOutputHeld(t *testing.T) {
	old := stopGrace
	stopGrace = 200 * time.Millisecond
	t.Cleanup(func() { stopGrace = old })
	code, out, err := run(t.Context(), "", nil, "/bin/sh", "-c", `sleep 3 & echo installed`)
	if err != nil || code != 0 || !strings.Contains(string(out), "installed") {
		t.Errorf("code %d, err %v, out %q", code, err, out)
	}
}
