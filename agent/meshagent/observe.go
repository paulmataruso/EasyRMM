package meshagent

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"
)

// What MeshAgent itself logs (ADR-0071 lists meshagent.log, which the agent
// tails, but a stock MeshAgent writes it only for its own diagnostics, not
// for its connection to MeshCentral or its restarts), so the agent also
// records what it can observe: the state of MeshAgent's service or child
// process, its errors, and what "meshagent -info" prints about the build.
const (
	// ObserveEvery is how often the state is read.
	ObserveEvery = 30 * time.Second
	infoTimeout  = 20 * time.Second
	// infoMax bounds what is read of the -info output, and infoLines how
	// many of its lines are kept.
	infoMax   = 4 << 10
	infoLines = 12
)

// Observer turns changes in MeshAgent's state into records for the device's
// log. It reads, never changes anything, and sends nothing itself.
type Observer struct {
	M *Manager
	// Emit receives a record of the meshagent source.
	Emit func(level, message string, attrs map[string]string)
	// Every is the interval of Run (ObserveEvery).
	Every time.Duration

	seen      bool
	installed bool
	running   bool
	lastErr   string
	build     string
}

// Run polls until ctx ends.
func (o *Observer) Run(ctx context.Context) {
	every := o.Every
	if every <= 0 {
		every = ObserveEvery
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		o.Poll(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// Poll reads MeshAgent's state once and records what changed since the
// last poll.
func (o *Observer) Poll(ctx context.Context) {
	st := o.M.State(ctx)
	defer func() { o.seen, o.installed, o.running, o.lastErr = true, st.Installed, st.Running, st.Error }()
	if !st.Installed {
		if o.seen && o.installed {
			o.Emit("warn", "MeshAgent is no longer installed.", nil)
		}
		return
	}
	switch {
	case !o.seen:
		o.Emit("info", "MeshAgent "+runState(st.Running)+" when the EasyRMM agent started watching.", nil)
	case !o.installed:
		o.Emit("info", "MeshAgent is installed and "+runState(st.Running)+".", nil)
	case st.Running && !o.running:
		o.Emit("info", "MeshAgent started.", nil)
	case !st.Running && o.running:
		o.Emit("warn", "MeshAgent stopped.", nil)
	}
	if st.Error != "" && st.Error != o.lastErr {
		o.Emit("error", "MeshAgent: "+st.Error, nil)
	}
	o.reportBuild(ctx)
}

func runState(running bool) string {
	if running {
		return "is running"
	}
	return "is not running"
}

// reportBuild records what "-info" prints once per build of MeshAgent's
// program (its size and time), which is its version and build date.
func (o *Observer) reportBuild(ctx context.Context) {
	fi, err := os.Stat(o.M.binary())
	if err != nil {
		return
	}
	key := fmt.Sprintf("%d-%d", fi.Size(), fi.ModTime().UnixNano())
	if key == o.build {
		return
	}
	o.build = key
	ctx, cancel := context.WithTimeout(ctx, infoTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, o.M.binary(), "-info") //nolint:gosec // our own installed MeshAgent
	cmd.Dir = o.M.Dir
	pipe, err := cmd.StdoutPipe()
	if err != nil {
		return
	}
	if err := cmd.Start(); err != nil {
		o.Emit("warn", "MeshAgent -info did not run: "+err.Error(), nil)
		return
	}
	b, _ := io.ReadAll(io.LimitReader(pipe, infoMax))
	_ = cmd.Wait()
	var lines []string
	for l := range strings.SplitSeq(string(b), "\n") {
		if l = strings.TrimSpace(l); l != "" {
			lines = append(lines, l)
		}
		if len(lines) == infoLines {
			break
		}
	}
	if len(lines) == 0 {
		o.Emit("warn", "MeshAgent -info printed nothing.", nil)
		return
	}
	o.Emit("info", "MeshAgent build (-info): "+strings.Join(lines, "; "), nil)
}
