package winevent

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"time"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/internal/eventrules"
)

// Main is the builtin's entry point: "easyrmm-agent builtin eventlog". It
// reads the typed input from the file named by EASYRMM_JOB_INPUT, writes its
// result lines to the file named by EASYRMM_JOB_RESULT, and prints only
// diagnostics. The agent starts it with a pipe on its standard input and
// closes the pipe to cancel it (ADR-0068).
func Main(version string) error {
	in, out := os.Getenv("EASYRMM_JOB_INPUT"), os.Getenv("EASYRMM_JOB_RESULT")
	if in == "" || out == "" {
		return errors.New("the eventlog builtin is started by the agent, with EASYRMM_JOB_INPUT and EASYRMM_JOB_RESULT set")
	}
	return RunFiles(in, out, version, os.Stdin, nil)
}

// grace is how long past its own limit the watchdog waits before it cancels
// the queries: the engine ends its page at the limit by itself.
const grace = 2 * time.Second

// RunFiles is Main with the files named, the child's input and, for tests, a
// Backend; nil opens the computer's event logs. A watchdog goroutine waits for
// the input to close or for the run's limit, then cancels the queries the
// run's thread is using (EvtCancel), so that the Event Log service is told to
// stop; the run writes its last line and returns.
func RunFiles(inputPath, resultPath, version string, stdin io.Reader, be Backend) error {
	raw, err := os.ReadFile(inputPath) //nolint:gosec // named by the agent in the run's environment
	if err != nil {
		return fmt.Errorf("reading the input: %w", err)
	}
	if len(raw) > agentproto.MaxInputBytes {
		return errors.New("the input is too large")
	}
	input, err := eventrules.DecodeInput(raw)
	if err != nil {
		return err
	}
	if be == nil {
		if be, err = NewBackend(); err != nil {
			return err
		}
	}
	limit := eventrules.InfoSeconds * time.Second
	if input.Op == eventrules.OpQuery {
		limit = eventrules.QuerySeconds * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), limit+grace)
	defer cancel()
	if stdin != nil {
		go func() {
			_, _ = io.Copy(io.Discard, stdin)
			cancel()
		}()
	}
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			be.Cancel()
		case <-done:
		}
	}()
	f, err := os.OpenFile(resultPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600) //nolint:gosec // named by the agent in the run's environment
	if err != nil {
		return fmt.Errorf("opening the result file: %w", err)
	}
	// A query handle belongs to the thread that made it.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	runErr := Run(ctx, input, be, f, Options{AgentVersion: version, Arch: archName(), Deadline: limit})
	if cerr := f.Close(); runErr == nil {
		runErr = cerr
	}
	return runErr
}

func archName() string {
	switch runtime.GOARCH {
	case "amd64":
		return agentproto.ArchX64
	case "arm64":
		return agentproto.ArchARM64
	}
	return runtime.GOARCH
}
