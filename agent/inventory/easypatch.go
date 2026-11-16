package inventory

import (
	"context"
	"encoding/json"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
)

// easyPatchTimeout bounds `status --json`, which only reads the agent's
// state file.
const easyPatchTimeout = 30 * time.Second

// easyPatchStatus runs the EasyPatch agent at bin with `status --json` and
// reads its answer (ADR-0030). The agent prints its status even when it
// exits with an error, so the output is read whatever the exit code.
func (c Collector) easyPatchStatus(ctx context.Context, bin string) *agentproto.EasyPatchAgent {
	run := c.Run
	if run == nil {
		run = output
	}
	ctx, cancel := context.WithTimeout(ctx, easyPatchTimeout)
	defer cancel()
	out, err := run(ctx, bin, "status", "--json")
	if st := parseEasyPatch(out); st != nil {
		return st
	}
	msg := "status --json printed nothing EasyRMM understands"
	if err != nil {
		msg = "status --json failed: " + err.Error()
	}
	return &agentproto.EasyPatchAgent{Status: "Unknown", Error: short(msg)}
}

// short trims a value the EasyPatch agent printed and keeps it under 512
// bytes, on a character boundary.
func short(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) <= 512 {
		return s
	}
	s = s[:512]
	for !utf8.ValidString(s) {
		s = s[:len(s)-1]
	}
	return s
}

// parseEasyPatch reads `easypatch-agent status --json`; nil when it is not
// that.
func parseEasyPatch(out []byte) *agentproto.EasyPatchAgent {
	var s struct {
		AgentVersion   string `json:"agentVersion"`
		Status         string `json:"status"`
		Error          string `json:"error"`
		ServerURL      string `json:"serverUrl"`
		EndpointID     string `json:"endpointId"`
		KeyFingerprint string `json:"keyFingerprint"`
	}
	if err := json.Unmarshal(out, &s); err != nil || (s.Status == "" && s.AgentVersion == "") {
		return nil
	}
	return &agentproto.EasyPatchAgent{
		Version: short(s.AgentVersion), Status: short(s.Status), ServerURL: strings.TrimRight(short(s.ServerURL), "/"),
		EndpointID: strings.ToLower(short(s.EndpointID)), KeyFingerprint: short(s.KeyFingerprint), Error: short(s.Error),
	}
}
