package jobs

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
)

// The builtin's child is this test binary, started again with an environment
// variable that makes it act as the child. The input says what it does.

// TestBuiltinChildProcess is the child: it does something only when the agent's
// run environment (EASYRMM_JOB_INPUT) is set, which a normal test run does
// not have.
func TestBuiltinChildProcess(t *testing.T) {
	if os.Getenv("EASYRMM_JOB_INPUT") == "" {
		t.Skip("this test is the builtin's child process")
	}
	childMain()
}

// childMain plays the registry builtin. Its input is a line: a mode.
func childMain() {
	in, out := os.Getenv("EASYRMM_JOB_INPUT"), os.Getenv("EASYRMM_JOB_RESULT")
	raw, err := os.ReadFile(in)
	if err != nil {
		fmt.Fprintln(os.Stderr, "no input:", err)
		os.Exit(9)
	}
	mode := strings.TrimSpace(string(raw))
	f, _ := os.Create(out)
	line := func(s string) { _, _ = f.WriteString(s + "\n") }
	line(`{"t":"begin","v":1,"op":"list","hive":"HKLM","view":"64","path":[],"rules":1,"agentVersion":"child"}`)
	switch mode {
	case "ok":
		line(`{"t":"end","complete":true,"elapsedMs":1}`)
	case "cut":
		line(`{"t":"subkey","name":"a","subkeys":0,"values":0}`)
		_, _ = f.WriteString(`{"t":"subkey","name":"b`)
	case "hang":
		line(`{"t":"subkey","name":"a","subkeys":0,"values":0}`)
		_ = f.Sync()
		time.Sleep(time.Hour)
	case "crash":
		line(`{"t":"subkey","name":"a","subkeys":0,"values":0}`)
		_ = f.Sync()
		os.Exit(3)
	case "huge":
		pad := strings.Repeat("x", 900)
		for range 3500 {
			line(`{"t":"subkey","name":"` + pad + `","subkeys":0,"values":0}`)
		}
	case "env":
		env := map[string]string{}
		for _, kv := range os.Environ() {
			k, v, _ := strings.Cut(kv, "=")
			if strings.HasPrefix(k, "EASYRMM_") || strings.EqualFold(k, "TEMP") || strings.EqualFold(k, "TMP") || k == "HOME" {
				env[strings.ToUpper(k)] = v
			}
		}
		b, _ := json.Marshal(map[string]any{"t": "subkey", "name": "env", "subkeys": 0, "values": 0, "label": toJSON(env), "args": os.Args[1:]})
		line(strings.Replace(string(b), `"label"`, `"label"`, 1))
	}
	_ = f.Close()
}

func toJSON(v any) string { b, _ := json.Marshal(v); return string(b) }

// useChild points the builtin at this test binary.
func useChild(t *testing.T) {
	t.Helper()
	old := builtinProgram
	builtinProgram = func(string) (string, []string, error) {
		return os.Args[0], []string{"-test.run=^TestBuiltinChildProcess$"}, nil
	}
	t.Cleanup(func() { builtinProgram = old })
}

func builtinPayload(mode string, timeout int) agentproto.JobPayload {
	return agentproto.JobPayload{V: 3, RunID: "55555555-5555-4555-8555-555555555551", JobID: "44444444-4444-4444-8444-444444444444",
		DeviceID: "33333333-3333-4333-8333-333333333333", Executor: agentproto.ExecutorBuiltin, Builtin: "registry", Lane: "quick", Input: []byte(mode), TimeoutSeconds: timeout}
}

func lines(t *testing.T, res agentproto.ResultRequest) [][]byte {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(res.Result)
	if err != nil {
		t.Fatal(err)
	}
	return agentproto.SplitResultLines(raw)
}

func TestBuiltinRunsAChildAndSendsItsResult(t *testing.T) {
	useChild(t)
	AgentVersion = "1.5.0"
	root := t.TempDir()
	res := Execute(context.Background(), builtinPayload("ok", 20), root)
	if res.Status != agentproto.RunSucceeded || res.ExitCode == nil || *res.ExitCode != 0 || res.AgentVersion != "1.5.0" {
		t.Fatalf("%+v", res)
	}
	ls := lines(t, res)
	if len(ls) != 2 || !strings.Contains(string(ls[1]), `"end"`) || res.ResultCut {
		t.Errorf("lines %q", ls)
	}
	// The input and the result are gone with the run's folder.
	if left, _ := os.ReadDir(root); len(left) != 0 {
		t.Errorf("left in the work folder: %v", left)
	}
}

func TestBuiltinGetsItsEnvironmentAndNothingOnItsCommandLine(t *testing.T) {
	useChild(t)
	root := t.TempDir()
	res := Execute(context.Background(), builtinPayload("env", 20), root)
	ls := lines(t, res)
	if len(ls) < 2 {
		t.Fatalf("%+v", res)
	}
	var got struct {
		Label string   `json:"label"`
		Args  []string `json:"args"`
	}
	b, _ := json.Marshal(json.RawMessage(ls[1]))
	// The child's line is a subkey line with extra fields in test; read them loosely.
	var loose map[string]any
	_ = json.Unmarshal(b, &loose)
	got.Label, _ = loose["label"].(string)
	var env map[string]string
	if err := json.Unmarshal([]byte(got.Label), &env); err != nil {
		t.Fatalf("%v: %s", err, ls[1])
	}
	dir := filepath.Dir(env["EASYRMM_JOB_INPUT"])
	// A script's folder is TEMP and TMP on Windows and HOME elsewhere.
	home := env["HOME"]
	if runtime.GOOS == "windows" {
		home = env["TEMP"]
		if env["TMP"] != dir {
			t.Errorf("TMP %q", env["TMP"])
		}
	}
	if !strings.HasPrefix(dir, root) || home != dir || filepath.Dir(env["EASYRMM_JOB_RESULT"]) != dir {
		t.Errorf("run folder %q, env %v", dir, env)
	}
	if env["EASYRMM_JOB_ID"] != "44444444-4444-4444-8444-444444444444" || env["EASYRMM_RUN_ID"] != "55555555-5555-4555-8555-555555555551" {
		t.Errorf("ids %v", env)
	}
	for k := range env {
		switch k {
		case "TEMP", "TMP", "HOME", "EASYRMM_JOB_INPUT", "EASYRMM_JOB_RESULT", "EASYRMM_JOB_ID", "EASYRMM_RUN_ID":
		default:
			t.Errorf("a variable leaked: %s", k)
		}
	}
	if len(loose) == 0 {
		t.Fatal("no line")
	}
	if args, _ := loose["args"].([]any); len(args) != 1 || !strings.HasPrefix(fmt.Sprint(args[0]), "-test.run") {
		t.Errorf("the command line: %v", args)
	}
}

func TestBuiltinSendsWholeLinesHoweverTheChildEnded(t *testing.T) {
	useChild(t)
	// A cut last line is dropped.
	res := Execute(context.Background(), builtinPayload("cut", 20), t.TempDir())
	ls := lines(t, res)
	if res.Status != agentproto.RunSucceeded || len(ls) != 2 || strings.Contains(string(ls[1]), `"b`) {
		t.Errorf("cut: %q %+v", ls, res)
	}
	// A crash: the lines it wrote are sent, the run failed with its exit code.
	res = Execute(context.Background(), builtinPayload("crash", 20), t.TempDir())
	if res.Status != agentproto.RunFailed || res.ExitCode == nil || *res.ExitCode != 3 || len(lines(t, res)) != 2 {
		t.Errorf("crash: %+v", res)
	}
	// The timeout stops the child and sends what it wrote.
	old := KillGrace
	KillGrace = time.Second
	defer func() { KillGrace = old }()
	start := time.Now()
	res = Execute(context.Background(), builtinPayload("hang", 1), t.TempDir())
	if res.Status != agentproto.RunTimedOut || len(lines(t, res)) != 2 || time.Since(start) > 15*time.Second {
		t.Errorf("timeout: %+v after %s", res, time.Since(start))
	}
	// A cancel does the same.
	ctx, cancel := context.WithCancelCause(context.Background())
	time.AfterFunc(500*time.Millisecond, func() { cancel(errCanceled) })
	res = Execute(ctx, builtinPayload("hang", 30), t.TempDir())
	if res.Status != agentproto.RunCanceled || len(lines(t, res)) != 2 {
		t.Errorf("cancel: %+v", res)
	}
	// The agent stopping is a failure, with the lines too.
	ctx2, cancel2 := context.WithCancelCause(context.Background())
	time.AfterFunc(500*time.Millisecond, func() { cancel2(errStopping) })
	res = Execute(ctx2, builtinPayload("hang", 30), t.TempDir())
	if res.Status != agentproto.RunFailed || len(lines(t, res)) != 2 {
		t.Errorf("stopping: %+v", res)
	}
}

func TestBuiltinResultIsReadOnlyUpToItsBound(t *testing.T) {
	useChild(t)
	res := Execute(context.Background(), builtinPayload("huge", 60), t.TempDir())
	raw, _ := base64.StdEncoding.DecodeString(res.Result)
	if len(raw) > agentproto.MaxResultFile || !res.ResultCut {
		t.Errorf("%d bytes, cut %v", len(raw), res.ResultCut)
	}
	// Whole lines only.
	if raw[len(raw)-1] != '\n' {
		t.Error("a cut line was sent")
	}
}

func TestAResultRequestOverMaxResultBodyIsCutFromTheEnd(t *testing.T) {
	var b strings.Builder
	b.WriteString(`{"t":"begin","v":1}` + "\n")
	for i := range 2000 {
		fmt.Fprintf(&b, `{"t":"subkey","name":"%04d%s"}`+"\n", i, strings.Repeat("y", 1000))
	}
	req := agentproto.ResultRequest{Status: agentproto.RunSucceeded, Result: base64.StdEncoding.EncodeToString([]byte(b.String())),
		Stdout: strings.Repeat("\"", 3<<20)}
	if requestSize(req) <= agentproto.MaxResultBody {
		t.Fatal("the request is not over the bound")
	}
	fitResult(&req)
	if size := requestSize(req); size > agentproto.MaxResultBody {
		t.Errorf("still %d bytes", size)
	}
	raw, _ := base64.StdEncoding.DecodeString(req.Result)
	ls := agentproto.SplitResultLines(raw)
	if !req.ResultCut || len(ls) < 2 || len(ls) >= 2001 || !strings.Contains(string(ls[0]), `"begin"`) {
		t.Errorf("%d lines kept, cut=%v", len(ls), req.ResultCut)
	}
	// A request within the bound is left alone.
	small := agentproto.ResultRequest{Result: base64.StdEncoding.EncodeToString([]byte("{}\n"))}
	fitResult(&small)
	if small.ResultCut || small.Result == "" {
		t.Error("a small request was cut")
	}
}

func TestBuiltinNamesTheProblemWhenItCannotRun(t *testing.T) {
	p := builtinPayload("ok", 20)
	p.Builtin = "nothing"
	if res := Execute(context.Background(), p, t.TempDir()); res.Status != agentproto.RunFailed || !strings.Contains(res.Error, "does not have the nothing builtin") {
		t.Errorf("%+v", res)
	}
	old := builtinProgram
	builtinProgram = func(string) (string, []string, error) { return filepath.Join(t.TempDir(), "missing"), nil, nil }
	defer func() { builtinProgram = old }()
	if res := Execute(context.Background(), builtinPayload("ok", 20), t.TempDir()); res.Status != agentproto.RunFailed || !strings.Contains(res.Error, "Could not start") {
		t.Errorf("%+v", res)
	}
}

func TestAcceptsListsTheEditorWhereItRuns(t *testing.T) {
	got := Accepts()
	has := func(c string) bool {
		for _, a := range got {
			if a == c {
				return true
			}
		}
		return false
	}
	if windows := has(agentproto.CapJobPwsh); has(agentproto.CapJobStructured) != windows || has(agentproto.CapBuiltin("registry", 1)) != windows {
		t.Errorf("accepts %v", got)
	}
	if !has(agentproto.CapJobParams) {
		t.Errorf("accepts %v", got)
	}
}
