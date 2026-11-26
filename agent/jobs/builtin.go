package jobs

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
)

// AgentVersion is the version of this build, which a structured run reports
// (ResultRequest.AgentVersion). The agent's program sets it.
var AgentVersion string

// builtinMemoryLimit is the job-object memory limit of a builtin's child
// (ADR-0067): a runaway allocation ends the child and not the agent.
const builtinMemoryLimit = 512 << 20

// builtinProgram is the program and arguments that run a builtin: the
// agent's own program, with the builtin's name and nothing else on its
// command line. Tests replace it.
var builtinProgram = func(name string) (string, []string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", nil, err
	}
	return exe, []string{"builtin", name}, nil
}

// builtins are the builtins this build has, with the input versions each reads.
var builtins = map[string]bool{agentproto.BuiltinRegistry: true}

// Names of the files in a structured run's folder.
const (
	inputFile  = "input.json"
	resultFile = "result.jsonl"
)

// executeBuiltin runs a structured job: a builtin of the agent's own
// program, as a child process in the run's job object, given the signed
// input in a file and writing its result to another, both in the run's
// private folder and named in the environment, never on the command line.
// Whatever way the child ends (its exit, the timeout, a cancel, a crash), the
// whole lines of its result file are sent.
func executeBuiltin(ctx context.Context, p agentproto.JobPayload, workRoot string) agentproto.ResultRequest {
	res := agentproto.ResultRequest{StartedAt: time.Now().UTC(), AgentVersion: AgentVersion}
	fail := func(msg string) agentproto.ResultRequest {
		res.Status, res.Error, res.FinishedAt = agentproto.RunFailed, msg, time.Now().UTC()
		return res
	}
	if !builtins[p.Builtin] {
		return fail("This agent does not have the " + p.Builtin + " builtin.")
	}
	prog, args, err := builtinProgram(p.Builtin)
	if err != nil {
		return fail("Could not find the agent's own program: " + err.Error())
	}
	if err := os.MkdirAll(workRoot, 0o700); err != nil {
		return fail("Could not prepare a working directory: " + err.Error())
	}
	dir, err := os.MkdirTemp(workRoot, "run-")
	if err != nil {
		return fail("Could not prepare a working directory: " + err.Error())
	}
	defer func() { _ = os.RemoveAll(dir) }()
	inPath, outPath := filepath.Join(dir, inputFile), filepath.Join(dir, resultFile)
	if err := os.WriteFile(inPath, p.Input, 0o600); err != nil {
		return fail("Could not write the input: " + err.Error())
	}
	stdout, stderr := newCapture(), newCapture()
	cmd := exec.Command(prog, args...) //nolint:gosec,noctx // the agent's own program; stopped by its job object
	cmd.Dir = dir
	cmd.Env = withEnv(environment(p, dir), []string{"EASYRMM_JOB_INPUT=" + inPath, "EASYRMM_JOB_RESULT=" + outPath})
	cmd.Stdout, cmd.Stderr = stdout, stderr
	cmd.WaitDelay = 5 * time.Second
	g, err := startLimited(cmd, builtinMemoryLimit)
	if err != nil {
		return fail("Could not start " + prog + ": " + err.Error())
	}
	defer g.release()
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	timeout := time.NewTimer(time.Duration(p.TimeoutSeconds) * time.Second)
	defer timeout.Stop()
	var stopped, waitErr error
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
	attachResult(&res, outPath)
	var exitErr *exec.ExitError
	switch {
	case errors.Is(stopped, context.DeadlineExceeded):
		res.Status = agentproto.RunTimedOut
		res.Error = fmt.Sprintf("Stopped after the %s timeout.", time.Duration(p.TimeoutSeconds)*time.Second)
	case errors.Is(stopped, errCanceled):
		res.Status, res.Error = agentproto.RunCanceled, "Stopped on request."
	case stopped != nil:
		res.Status, res.Error = agentproto.RunFailed, capitalize(errStopping.Error())+"."
	case waitErr == nil:
		code := 0
		res.ExitCode, res.Status = &code, agentproto.RunSucceeded
	case errors.As(waitErr, &exitErr) && exitErr.ExitCode() >= 0:
		code := exitErr.ExitCode()
		res.ExitCode, res.Status = &code, agentproto.RunFailed
		res.Error = fmt.Sprintf("The %s builtin exited with code %d.", p.Builtin, code)
	case errors.As(waitErr, &exitErr):
		res.Status, res.Error = agentproto.RunFailed, "The "+p.Builtin+" builtin was killed: "+exitErr.String()+"."
	default:
		res.Status, res.Error = agentproto.RunFailed, "Waiting for the "+p.Builtin+" builtin failed: "+waitErr.Error()
	}
	fitResult(&res)
	return res
}

// attachResult puts the whole lines of the result file in the request,
// base64-encoded: a cut last line is dropped, and a file over
// agentproto.MaxResultFile is read only that far.
func attachResult(res *agentproto.ResultRequest, path string) {
	f, err := os.Open(path) //nolint:gosec // the run's own result file, in its private folder
	if err != nil {
		return
	}
	defer func() { _ = f.Close() }()
	buf := make([]byte, agentproto.MaxResultFile+1)
	n := 0
	for n < len(buf) {
		m, err := f.Read(buf[n:])
		n += m
		if err != nil {
			break
		}
	}
	data := buf[:n]
	if n > agentproto.MaxResultFile {
		data = data[:agentproto.MaxResultFile]
		res.ResultCut = true
	}
	lines := agentproto.SplitResultLines(data)
	if len(lines) == 0 {
		return
	}
	res.Result = base64.StdEncoding.EncodeToString(joinLines(lines))
}

func joinLines(lines [][]byte) []byte {
	var b bytes.Buffer
	for _, l := range lines {
		b.Write(l)
		b.WriteByte('\n')
	}
	return b.Bytes()
}

// fitResult checks the whole request against agentproto.MaxResultBody before
// it is sent. If it would pass, result lines are dropped from the end, never
// the first, and the result is marked cut.
func fitResult(res *agentproto.ResultRequest) {
	if res.Result == "" {
		return
	}
	if requestSize(*res) <= agentproto.MaxResultBody {
		return
	}
	raw, err := base64.StdEncoding.DecodeString(res.Result)
	if err != nil {
		res.Result = ""
		return
	}
	lines := agentproto.SplitResultLines(raw)
	res.ResultCut = true
	for len(lines) > 1 {
		// Drop a tenth of what is left, then check again.
		lines = lines[:len(lines)-max(1, len(lines)/10)]
		res.Result = base64.StdEncoding.EncodeToString(joinLines(lines))
		if requestSize(*res) <= agentproto.MaxResultBody {
			return
		}
	}
	if requestSize(*res) > agentproto.MaxResultBody {
		res.Result = ""
	}
}

// requestSize is the size of the result request as it is sent.
func requestSize(res agentproto.ResultRequest) int {
	b, err := json.Marshal(res)
	if err != nil {
		return agentproto.MaxResultBody + 1
	}
	return len(b)
}
