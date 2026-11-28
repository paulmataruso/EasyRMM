package quickassist

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"

	"github.com/paulmataruso/easyrmm/agent/client"
)

// The EasyPatch agent's file, looked for beside the runner (ADR-0080 QA6).
// The runner does not download it: whoever builds the runner's package
// puts it there.
var easyPatchNames = []string{"EasyPatch.Agent", "EasyPatchAgent"}

// epRun is the EasyPatch agent a session started, in its ad-hoc mode: a
// confined child with a data directory, registry key and lock of its own,
// which enrolls with the session's token and patches until the session ends.
type epRun struct {
	cmd  *exec.Cmd
	dir  string
	key  string
	done chan struct{}
}

// epBinary finds the EasyPatch agent beside the runner, or the file
// Options.EasyPatch names.
func epBinary(o Options) string {
	if o.EasyPatch != "" {
		return o.EasyPatch
	}
	base := filepath.Dir(o.Self)
	for _, n := range easyPatchNames {
		if runtime.GOOS == "windows" {
			n += ".exe"
		}
		p := filepath.Join(base, n)
		if st, err := os.Stat(p); err == nil && st.Mode().IsRegular() {
			return p
		}
	}
	return ""
}

// wantEasyPatch says whether the session starts the EasyPatch agent, and
// when it does not but the server offered a token, why in words for the
// user. It needs an elevated runner (the agent scans and installs updates),
// the token the server gave and no EasyPatch of this computer's own.
func wantEasyPatch(o Options, st *client.QAState) (bool, string) {
	switch {
	case st.EasyPatchToken == "":
		return false, ""
	case !o.Elevated:
		return false, "Patching needs administrator rights."
	}
	if found := existingEasyPatch(); found != "" {
		return false, "EasyPatch is already installed on this computer (" + found + "); its patching applies."
	}
	return true, ""
}

// startEasyPatch starts the agent with "run --adhoc" as a confined child.
// The token and server go in its environment, not its command line, which
// other users can read.
func startEasyPatch(o Options, cf *confiner, dir, sessionID string, st *client.QAState) (*epRun, error) {
	bin := epBinary(o)
	if bin == "" {
		return nil, errors.New("the EasyPatch agent is not beside this program")
	}
	data := filepath.Join(dir, "EasyPatch")
	if err := os.Mkdir(data, 0o700); err != nil {
		return nil, err
	}
	cmd := exec.CommandContext(context.Background(), bin, "run", "--adhoc", "--data-dir", data, //nolint:gosec // the agent beside this program
		"--registry-key", sessionID, "--lock", "easyrmm-qa-ep-"+sessionID)
	cmd.Env = append(os.Environ(), "EASYPATCH_ENROLLMENT_TOKEN="+st.EasyPatchToken, "EASYPATCH_SERVER="+st.EasyPatchServer)
	cf.Confine(cmd)
	if err := cmd.Start(); err != nil {
		_ = os.RemoveAll(data)
		return nil, fmt.Errorf("starting the EasyPatch agent: %w", err)
	}
	cf.Started(cmd.Process)
	r := &epRun{cmd: cmd, dir: data, key: sessionID, done: make(chan struct{})}
	go func() {
		_ = cmd.Wait()
		close(r.done)
	}()
	return r, nil
}

// stop ends the child, removes its data directory and the registry key it
// made, and returns what could not be removed.
func (r *epRun) stop(ctx context.Context) []string {
	if r == nil {
		return nil
	}
	_ = r.cmd.Process.Kill()
	select {
	case <-r.done:
	case <-ctx.Done():
	case <-time.After(10 * time.Second):
	}
	for i := 0; i < 3; i++ {
		if os.RemoveAll(r.dir) == nil {
			break
		}
		time.Sleep(time.Second)
	}
	var left []string
	if _, err := os.Stat(r.dir); err == nil {
		left = append(left, r.dir)
	}
	return append(left, removeEPKey(r.key)...)
}

// epChecks are the cleanup report's check for the EasyPatch agent; none when
// no agent ran.
func epChecks(r *epRun, left []string) []client.QACheck {
	if r == nil {
		return nil
	}
	c := client.QACheck{Name: "easypatch_removed", OK: len(left) == 0}
	if !c.OK {
		c.Detail = fmt.Sprint(left)
	}
	return []client.QACheck{c}
}
