//go:build windows

package jobs

import (
	"context"
	"encoding/base64"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
)

// TestRegistryBuiltinAsSystem: a signed structured job runs the real agent
// program as a child ("easyrmm-agent.exe builtin registry"), in a job
// object with its memory limit, as LocalSystem, and the whole path (input
// file, environment, result file, result request) works against the
// machine's registry. CI's job builds the agent and names it in
// EASYRMM_TEST_AGENT_EXE.
func TestRegistryBuiltinAsSystem(t *testing.T) {
	if os.Getenv("EASYRMM_TEST_SYSTEM") == "" {
		t.Skip("runs as LocalSystem on a computer made for it; CI's job sets EASYRMM_TEST_SYSTEM")
	}
	exe := os.Getenv("EASYRMM_TEST_AGENT_EXE")
	if exe == "" {
		t.Skip("EASYRMM_TEST_AGENT_EXE names the agent's program")
	}
	old := builtinProgram
	builtinProgram = func(name string) (string, []string, error) { return exe, []string{"builtin", name}, nil }
	defer func() { builtinProgram = old }()
	AgentVersion = "test"

	in := `{"v":1,"op":"list","hive":"HKLM","view":"64","path":["SOFTWARE","Microsoft","Windows NT","CurrentVersion"],"rules":1}`
	p := agentproto.JobPayload{V: 3, RunID: "r", JobID: "j", DeviceID: "d", Executor: agentproto.ExecutorBuiltin, Builtin: "registry",
		Lane: agentproto.LaneQuick, Input: []byte(in), TimeoutSeconds: 60}
	res := Execute(context.Background(), p, t.TempDir())
	if res.Status != agentproto.RunSucceeded || res.Result == "" {
		t.Fatalf("%+v", res)
	}
	raw, _ := base64.StdEncoding.DecodeString(res.Result)
	r, err := agentproto.ParseRegistryLines(agentproto.SplitResultLines(raw))
	if err != nil || r.End == nil || !r.End.Complete || r.Begin.AgentVersion != "test" {
		t.Fatalf("%v %+v", err, r)
	}
	found := false
	for _, v := range r.Values {
		if v.Name == "ProductName" && v.Text != nil && strings.Contains(*v.Text, "Windows") {
			found = true
		}
	}
	if !found {
		t.Errorf("no ProductName in %d values", len(r.Values))
	}
	// An input the agent does not accept writes no result and fails the run.
	p.Input = []byte(`{"v":1,"op":"delete","hive":"HKLM","view":"64","path":[],"rules":1}`)
	if res := Execute(context.Background(), p, t.TempDir()); res.Status != agentproto.RunFailed || res.Result != "" {
		t.Errorf("a write operation: %+v", res)
	}
	// Accepts lists the editor on Windows.
	if !strings.Contains(strings.Join(Accepts(), ","), "builtin.registry.v1") {
		t.Errorf("accepts %v", Accepts())
	}
}

// TestEventlogBuiltinAsSystem: a signed structured job runs the real agent
// program as "easyrmm-agent.exe builtin eventlog", in a job object, with a
// pipe on its input: a channel list comes back, and a cancel ends a long
// search through the input and not through the job object's kill.
func TestEventlogBuiltinAsSystem(t *testing.T) {
	if os.Getenv("EASYRMM_TEST_SYSTEM") == "" {
		t.Skip("runs as LocalSystem on a computer made for it; CI's job sets EASYRMM_TEST_SYSTEM")
	}
	exe := os.Getenv("EASYRMM_TEST_AGENT_EXE")
	if exe == "" {
		t.Skip("EASYRMM_TEST_AGENT_EXE names the agent's program")
	}
	old := builtinProgram
	builtinProgram = func(name string) (string, []string, error) { return exe, []string{"builtin", name}, nil }
	defer func() { builtinProgram = old }()
	AgentVersion = "test"
	payload := func(in string, timeout int) agentproto.JobPayload {
		return agentproto.JobPayload{V: 3, RunID: "r", JobID: "j", DeviceID: "d", Executor: agentproto.ExecutorBuiltin, Builtin: "eventlog",
			Lane: agentproto.LaneQuick, Input: []byte(in), TimeoutSeconds: timeout}
	}
	res := Execute(context.Background(), payload(`{"v":1,"op":"channels","rules":1,"sensitive":false}`, 60), t.TempDir())
	if res.Status != agentproto.RunSucceeded || res.Result == "" {
		t.Fatalf("%+v", res)
	}
	raw, _ := base64.StdEncoding.DecodeString(res.Result)
	ls := agentproto.SplitResultLines(raw)
	if len(ls) < 10 || !strings.Contains(string(ls[len(ls)-1]), `"t":"end"`) {
		t.Fatalf("%d lines", len(ls))
	}
	// A cancel closes the child's input; it writes its last line and exits.
	ctx, cancel := context.WithCancelCause(context.Background())
	time.AfterFunc(time.Second, func() { cancel(errCanceled) })
	start := time.Now()
	res = Execute(ctx, payload(`{"v":1,"op":"query","rules":1,"sensitive":false,"channels":["System","Application"],"text":"easyrmm-no-event-holds-this"}`, 60), t.TempDir())
	t.Logf("cancelled after %s: %s", time.Since(start), res.Status)
	if res.Status != agentproto.RunCanceled {
		t.Fatalf("%+v", res)
	}
	if res.Result != "" {
		raw, _ := base64.StdEncoding.DecodeString(res.Result)
		ls := agentproto.SplitResultLines(raw)
		if !strings.Contains(string(ls[len(ls)-1]), `"t":"end"`) {
			t.Errorf("the child was killed before its last line: %s", ls[len(ls)-1])
		}
	}
	if !strings.Contains(strings.Join(Accepts(), ","), "builtin.eventlog.v1") {
		t.Errorf("accepts %v", Accepts())
	}
}
