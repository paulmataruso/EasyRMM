//go:build !windows

package meshagent

import (
	"context"
	"strings"
	"sync"
	"testing"
)

const infoAgent = `#!/bin/sh
if [ "$1" = -info ]; then printf 'Compiled on: Jan 1 2026\nAgent Version: 1.2.3\n'; exit 0; fi
exec sleep 2
`

func TestObserverRecordsStateChangesAndBuild(t *testing.T) {
	m := newManager(t, ModeChild, nil)
	var mu sync.Mutex
	var got []string
	o := &Observer{M: m, Emit: func(level, msg string, _ map[string]string) {
		mu.Lock()
		got = append(got, level+": "+msg)
		mu.Unlock()
	}}
	all := func() string { mu.Lock(); defer mu.Unlock(); return strings.Join(got, "\n") }
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	o.Poll(ctx) // nothing installed: nothing to say
	if all() != "" {
		t.Fatalf("records for a machine without MeshAgent: %q", all())
	}
	runCtx, stop := context.WithCancel(ctx)
	defer stop()
	// Installing starts the child MeshAgent under runCtx.
	if err := m.Install(runCtx, download(infoAgent), []byte("MeshID=0x1\n")); err != nil {
		t.Fatal(err)
	}
	o.Poll(ctx)
	out := all()
	if !strings.Contains(out, "info: MeshAgent is installed and is running.") || !strings.Contains(out, "Agent Version: 1.2.3") {
		t.Errorf("after install: %q", out)
	}
	o.Poll(ctx) // the same build is read once
	if strings.Count(all(), "-info") != 1 {
		t.Errorf("-info read again: %q", all())
	}

	stop()
	m.Wait()
	o.Poll(ctx)
	if !strings.Contains(all(), "warn: MeshAgent stopped.") {
		t.Errorf("after stop: %q", all())
	}
	// A failed restart is MeshAgent's error.
	m.errMu.Lock()
	m.lastErr = "restart failed"
	m.errMu.Unlock()
	o.Poll(ctx)
	if !strings.Contains(all(), "error: MeshAgent: restart failed") {
		t.Errorf("after an error: %q", all())
	}
}
