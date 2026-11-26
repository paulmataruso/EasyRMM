package defender

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"time"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
)

// EasyPatch asks the EasyPatch agent for its own Defender report, by
// running `EasyPatch.Agent.exe defender status` (ADR-0070 slice B), so the
// device page shows both agents together.
type EasyPatch struct {
	Run Exec
	// Exe is the exact path of the EasyPatch agent under Program Files;
	// never found by a search and never taken from the server.
	Exe     string
	Timeout time.Duration
}

// maxEasyPatchOutput bounds what is read of the command's answer.
const maxEasyPatchOutput = 64 * 1024

// Status returns the EasyPatch agent's report, nil when it is not installed
// or does not answer a valid one. It changes nothing on the machine.
func (e EasyPatch) Status(ctx context.Context) *agentproto.DefenderReport {
	if e.Exe == "" || e.Run == nil {
		return nil
	}
	if fi, err := os.Stat(e.Exe); err != nil || !fi.Mode().IsRegular() {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, e.Timeout)
	defer cancel()
	out, err := e.Run(ctx, nil, e.Exe, "defender", "status")
	if err != nil {
		return nil
	}
	return ParseEasyPatch(out)
}

// ParseEasyPatch reads the command's answer: a JSON document, possibly
// after log lines. Nil when it is not a valid report.
func ParseEasyPatch(out []byte) *agentproto.DefenderReport {
	if len(out) > maxEasyPatchOutput {
		return nil
	}
	start := bytes.LastIndex(out, []byte("\n{"))
	switch {
	case start >= 0:
		out = out[start+1:]
	case !bytes.HasPrefix(bytes.TrimSpace(out), []byte("{")):
		return nil
	}
	var r agentproto.DefenderReport
	if err := json.Unmarshal(out, &r); err != nil {
		return nil
	}
	r.Events, r.EasyPatch = nil, nil
	if r.Check() != nil {
		return nil
	}
	return &r
}
