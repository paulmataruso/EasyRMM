package quickassist

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/paulmataruso/easyrmm/agent/client"
)

// fakeAgent is a real program that records how it was started and then
// waits, as the EasyPatch agent does.
func fakeAgent(t *testing.T) (bin, record string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the stand-in agent is a shell script")
	}
	dir := t.TempDir()
	record = filepath.Join(dir, "record")
	bin = filepath.Join(dir, "EasyPatch.Agent")
	script := "#!/bin/sh\n{ echo \"$@\"; echo \"token=$EASYPATCH_ENROLLMENT_TOKEN\"; echo \"server=$EASYPATCH_SERVER\"; } > '" + record + "'\n" +
		"echo data > \"$4/state\"\nexec sleep 60\n"
	if err := os.WriteFile(bin, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	return bin, record
}

func TestEasyPatchStartsOnlyElevatedAndWithAToken(t *testing.T) {
	bin, _ := fakeAgent(t)
	tok := &client.QAState{State: "active", EasyPatchToken: "tok", EasyPatchServer: "https://patch.example.test"}
	cases := []struct {
		name     string
		elevated bool
		st       *client.QAState
		want     bool
		said     string
	}{
		{"elevated with a token", true, tok, true, ""},
		{"not elevated", false, tok, false, "administrator"},
		{"no token", true, &client.QAState{State: "active"}, false, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var out bytes.Buffer
			o := Options{Elevated: c.elevated, EasyPatch: bin, Out: &out}
			sess := &sessionState{cf: &confiner{}, dir: t.TempDir()}
			r := beginEasyPatch(o, sess, "11111111-2222-3333-4444-555555555555", c.st)
			defer r.stop(context.Background())
			if (r != nil) != c.want {
				t.Fatalf("started=%v want %v\n%s", r != nil, c.want, out.String())
			}
			if c.said == "" && !c.want && out.Len() != 0 {
				t.Errorf("said %q with nothing to say", out.String())
			}
			if c.said != "" && !strings.Contains(out.String(), c.said) {
				t.Errorf("said %q, want it to mention %q", out.String(), c.said)
			}
		})
	}
}

func TestEasyPatchChildGetsItsOwnSpaceAndLeavesNothing(t *testing.T) {
	bin, record := fakeAgent(t)
	dir := t.TempDir()
	sess := "11111111-2222-3333-4444-555555555555"
	o := Options{Elevated: true, EasyPatch: bin, Out: &bytes.Buffer{}}
	r, err := startEasyPatch(o, &confiner{}, dir, sess, &client.QAState{EasyPatchToken: "secret-token", EasyPatchServer: "https://patch.example.test"})
	if err != nil {
		t.Fatal(err)
	}
	var got string
	for i := 0; i < 100 && !strings.Contains(got, "server="); i++ {
		time.Sleep(50 * time.Millisecond)
		b, _ := os.ReadFile(record)
		got = string(b)
	}
	data := filepath.Join(dir, "EasyPatch")
	for _, want := range []string{
		"run --adhoc --data-dir " + data + " --registry-key " + sess + " --lock easyrmm-qa-ep-" + sess,
		"token=secret-token", "server=https://patch.example.test",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("the agent was started without %q:\n%s", want, got)
		}
	}
	// The token is in the environment only, where other users cannot read it.
	if first, _, _ := strings.Cut(got, "\n"); strings.Contains(first, "secret-token") {
		t.Error("the token is on the command line")
	}
	left := r.stop(context.Background())
	if len(left) != 0 {
		t.Errorf("left %v", left)
	}
	if _, err := os.Stat(data); !os.IsNotExist(err) {
		t.Error("the data directory is still there")
	}
	select {
	case <-r.done:
	default:
		t.Error("the child still runs")
	}
	if cs := epChecks(r, left); len(cs) != 1 || !cs[0].OK || cs[0].Name != "easypatch_removed" {
		t.Errorf("checks %+v", cs)
	}
	if epChecks(nil, nil) != nil {
		t.Error("a session without the agent reports a check for it")
	}
}

func TestEasyPatchMissingBinaryIsSaidNotFatal(t *testing.T) {
	var out bytes.Buffer
	o := Options{Elevated: true, Self: filepath.Join(t.TempDir(), "runner"), Out: &out}
	sess := &sessionState{cf: &confiner{}, dir: t.TempDir()}
	if r := beginEasyPatch(o, sess, "s", &client.QAState{EasyPatchToken: "t"}); r != nil {
		t.Fatal("started without a binary")
	}
	if !strings.Contains(out.String(), "not beside this program") {
		t.Errorf("said %q", out.String())
	}
}
