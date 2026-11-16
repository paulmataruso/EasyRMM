package jobs

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
)

// searchPath is where interpreters are looked up and what scripts get as
// PATH: the system directories, never the agent's own environment.
var searchPath = []string{"/usr/local/sbin", "/usr/local/bin", "/usr/sbin", "/usr/bin", "/sbin", "/bin"}

// KillGrace is how long a script has between SIGTERM and SIGKILL.
var KillGrace = 10 * time.Second

// Why a run was stopped.
var (
	errCanceled = errors.New("canceled")
	errStopping = errors.New("the agent stopped while the script ran")
)

// interpreter finds a shell's program.
func interpreter(shell string) (string, error) {
	for _, dir := range searchPath {
		p := filepath.Join(dir, shell)
		if st, err := os.Stat(p); err == nil && !st.IsDir() && st.Mode()&0o111 != 0 {
			return p, nil
		}
	}
	return "", fmt.Errorf("%s is not installed on this device", shell)
}

// environment is a script's whole environment.
func environment(p agentproto.JobPayload, home string) []string {
	return []string{
		"PATH=" + strings.Join(searchPath, ":"),
		"HOME=" + home,
		"LANG=C.UTF-8",
		"EASYRMM_JOB_ID=" + p.JobID,
		"EASYRMM_RUN_ID=" + p.RunID,
	}
}

// Execute runs a job's script in a private directory under workRoot and
// reports how it ended. Canceling ctx with cause errCanceled stops it as
// canceled; any other cancellation stops it as failed.
func Execute(ctx context.Context, p agentproto.JobPayload, workRoot string) agentproto.ResultRequest {
	res := agentproto.ResultRequest{StartedAt: time.Now().UTC()}
	fail := func(msg string) agentproto.ResultRequest {
		res.Status, res.Error, res.FinishedAt = agentproto.RunFailed, msg, time.Now().UTC()
		return res
	}
	prog, err := interpreter(p.Shell)
	if err != nil {
		return fail(capitalize(err.Error()) + ".")
	}
	if err := os.MkdirAll(workRoot, 0o700); err != nil {
		return fail("Could not prepare a working directory: " + err.Error())
	}
	dir, err := os.MkdirTemp(workRoot, "run-")
	if err != nil {
		return fail("Could not prepare a working directory: " + err.Error())
	}
	defer func() { _ = os.RemoveAll(dir) }()
	script := filepath.Join(dir, "script")
	if err := os.WriteFile(script, []byte(p.Script), 0o600); err != nil {
		return fail("Could not write the script: " + err.Error())
	}
	stdout, stderr := newCapture(), newCapture()
	// A signed job from the server (ADR-0017). Not CommandContext: stopping
	// is handled below, for the whole process group and with a grace period.
	cmd := exec.Command(prog, append([]string{script}, p.Args...)...) //nolint:gosec,noctx // see above
	cmd.Dir = dir
	cmd.Env = environment(p, dir)
	cmd.Stdout, cmd.Stderr = stdout, stderr
	// Background children may hold the output open; stop waiting for them
	// soon after the script itself exits.
	cmd.WaitDelay = 5 * time.Second
	isolate(cmd)
	if err := cmd.Start(); err != nil {
		return fail("Could not start " + p.Shell + ": " + err.Error())
	}
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
		terminate(cmd)
		select {
		case waitErr = <-done:
		case <-time.After(KillGrace):
			kill(cmd)
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
