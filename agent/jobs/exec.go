package jobs

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
)

// KillGrace is how long a script has between SIGTERM and SIGKILL. Windows
// has no SIGTERM for a script: it is stopped at once.
var KillGrace = 10 * time.Second

// Why a run was stopped.
var (
	errCanceled = errors.New("canceled")
	errStopping = errors.New("the agent stopped while the script ran")
)

// program is what a run starts: the program, what the run's result
// reports of it, read just before it starts (ADR-0064), and what the run's
// environment adds. release, where set, lets go of the files held open
// since their check, once the process is created or will not be.
type program struct {
	path    string
	info    agentproto.Interpreter
	env     []string
	release func()
}

// Execute runs a job's script in a private directory under workRoot and
// reports how it ended, with the program it started. Canceling ctx with
// cause errCanceled stops it as canceled; any other cancellation stops it
// as failed.
func Execute(ctx context.Context, p agentproto.JobPayload, workRoot string) agentproto.ResultRequest {
	res := agentproto.ResultRequest{StartedAt: time.Now().UTC()}
	fail := func(msg string) agentproto.ResultRequest {
		res.Status, res.Error, res.FinishedAt = agentproto.RunFailed, msg, time.Now().UTC()
		return res
	}
	prog, err := interpreter(p)
	if err != nil {
		return fail(sentence(err.Error()))
	}
	release := sync.OnceFunc(func() {
		if prog.release != nil {
			prog.release()
		}
	})
	defer release()
	if err := os.MkdirAll(workRoot, 0o700); err != nil {
		return fail("Could not prepare a working directory: " + err.Error())
	}
	dir, err := os.MkdirTemp(workRoot, "run-")
	if err != nil {
		return fail("Could not prepare a working directory: " + err.Error())
	}
	defer func() { _ = os.RemoveAll(dir) }()
	script, err := writeScript(dir, p.Shell, p.Script)
	if err != nil {
		return fail("Could not write the script: " + err.Error())
	}
	stdout, stderr := newCapture(), newCapture()
	// A signed job from the server (ADR-0017). Not CommandContext: stopping
	// is handled below, for everything the script started.
	cmd, err := command(prog.path, p.Shell, script, p.Args)
	if err != nil {
		return fail(err.Error())
	}
	cmd.Dir = dir
	cmd.Env = withEnv(environment(p, dir), prog.env)
	cmd.Stdout, cmd.Stderr = stdout, stderr
	// Params go to the script's standard input and nowhere else: a pipe,
	// never the command line, the environment or a file (ADR-0073).
	if len(p.Params) > 0 {
		cmd.Stdin = bytes.NewReader(p.Params)
	}
	// Background children may hold the output open; stop waiting for them
	// soon after the script itself exits.
	cmd.WaitDelay = 5 * time.Second
	g, err := start(cmd)
	release()
	if err != nil {
		return fail("Could not start " + prog.path + ": " + err.Error())
	}
	defer g.release()
	res.Interpreter = &prog.info
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	timeout := time.NewTimer(time.Duration(p.TimeoutSeconds) * time.Second)
	defer timeout.Stop()

	var stopped error
	var waitErr error
	select {
	case waitErr = <-done:
	case <-timeout.C:
		stopped = context.DeadlineExceeded
	case <-ctx.Done():
		stopped = context.Cause(ctx)
	}
	if stopped != nil {
		g.terminate()
		select {
		case waitErr = <-done:
		case <-time.After(KillGrace):
			g.kill()
			waitErr = <-done
		}
	}
	res.FinishedAt = time.Now().UTC()
	res.Stdout, res.StdoutTruncated = stdout.Text()
	res.Stderr, res.StderrTruncated = stderr.Text()
	switch {
	case errors.Is(stopped, context.DeadlineExceeded):
		res.Status = agentproto.RunTimedOut
		res.Error = fmt.Sprintf("Stopped after the %s timeout.", time.Duration(p.TimeoutSeconds)*time.Second)
		return res
	case errors.Is(stopped, errCanceled):
		res.Status, res.Error = agentproto.RunCanceled, "Stopped on request."
		return res
	case stopped != nil:
		res.Status, res.Error = agentproto.RunFailed, capitalize(errStopping.Error())+"."
		return res
	}
	var exitErr *exec.ExitError
	switch {
	case waitErr == nil:
		code := 0
		res.ExitCode, res.Status = &code, agentproto.RunSucceeded
	case errors.As(waitErr, &exitErr) && exitErr.ExitCode() >= 0:
		code := exitErr.ExitCode()
		res.ExitCode, res.Status = &code, agentproto.RunFailed
	case errors.As(waitErr, &exitErr):
		res.Status, res.Error = agentproto.RunFailed, "The script was killed: "+exitErr.String()+"."
	case errors.Is(waitErr, exec.ErrWaitDelay):
		code := cmd.ProcessState.ExitCode()
		res.ExitCode = &code
		res.Status = agentproto.RunFailed
		if code == 0 {
			res.Status = agentproto.RunSucceeded
		}
	default:
		res.Status, res.Error = agentproto.RunFailed, "Waiting for the script failed: "+waitErr.Error()
	}
	return res
}

func capitalize(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

// sentence capitalizes s and ends it with a full stop.
func sentence(s string) string {
	s = capitalize(s)
	if !strings.HasSuffix(s, ".") {
		s += "."
	}
	return s
}

// withEnv sets variables in env, replacing any of the same name, whose case
// Windows ignores.
func withEnv(env, set []string) []string {
	if len(set) == 0 {
		return env
	}
	out := make([]string, 0, len(env)+len(set))
	for _, kv := range env {
		k, _, _ := strings.Cut(kv, "=")
		if !slices.ContainsFunc(set, func(s string) bool { n, _, _ := strings.Cut(s, "="); return strings.EqualFold(n, k) }) {
			out = append(out, kv)
		}
	}
	return append(out, set...)
}
