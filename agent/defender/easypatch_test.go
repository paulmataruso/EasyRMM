package defender

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

const epReport = `{
  "state": "effective",
  "kinds": [{"kind": "path", "state": "effective"}, {"kind": "asr", "state": "not_needed", "reason": "no Attack Surface Reduction rule is set"}],
  "folders": [{"path": "C:\\ProgramData\\EasyPatch", "listed": true, "ours": true}],
  "method": "powershell",
  "agentVersion": "1.13.0"
}`

func TestParseEasyPatchReadsTheReportAfterLogLines(t *testing.T) {
	r := ParseEasyPatch([]byte("info: Defender exclusions\n" + epReport + "\n"))
	if r == nil || r.State != "effective" || r.AgentVersion != "1.13.0" || len(r.Folders) != 1 || !r.Folders[0].Ours {
		t.Fatalf("report = %+v", r)
	}
	if ParseEasyPatch([]byte(epReport)) == nil {
		t.Fatal("a bare document is a report")
	}
}

func TestParseEasyPatchRefusesWhatIsNotAValidReport(t *testing.T) {
	for name, out := range map[string]string{
		"empty":         "",
		"text":          "error: not elevated",
		"unknown state": `{"state":"fine","kinds":[],"folders":[]}`,
		"too long":      string(make([]byte, maxEasyPatchOutput+1)),
	} {
		if ParseEasyPatch([]byte(out)) != nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

func TestParseEasyPatchDropsNestedReportsAndEvents(t *testing.T) {
	r := ParseEasyPatch([]byte(`{"state":"effective","kinds":[],"folders":[],"events":[{"kind":"add","path":"x","at":"2026-01-01T00:00:00Z"}],"easypatch":{"state":"effective","kinds":[],"folders":[]}}`))
	if r == nil || len(r.Events) != 0 || r.EasyPatch != nil {
		t.Fatalf("report = %+v", r)
	}
}

func TestEasyPatchStatusRunsTheExactPathOnceWithStatus(t *testing.T) {
	exe := filepath.Join(t.TempDir(), "EasyPatch.Agent.exe")
	if err := os.WriteFile(exe, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	var gotName string
	var gotArgs []string
	e := EasyPatch{Exe: exe, Timeout: time.Second, Run: func(_ context.Context, _ []string, name string, args ...string) ([]byte, error) {
		gotName, gotArgs = name, args
		return []byte(epReport), nil
	}}
	if r := e.Status(context.Background()); r == nil || r.State != "effective" {
		t.Fatalf("report = %+v", r)
	}
	if gotName != exe || len(gotArgs) != 2 || gotArgs[0] != "defender" || gotArgs[1] != "status" {
		t.Fatalf("ran %q %v", gotName, gotArgs)
	}

	e.Run = func(context.Context, []string, string, ...string) ([]byte, error) { return nil, errors.New("exit 1") }
	if e.Status(context.Background()) != nil {
		t.Fatal("a failed command is no report")
	}
	e.Exe = filepath.Join(t.TempDir(), "missing.exe")
	e.Run = func(context.Context, []string, string, ...string) ([]byte, error) {
		t.Fatal("ran a missing program")
		return nil, nil
	}
	if e.Status(context.Background()) != nil {
		t.Fatal("not installed is no report")
	}
}
