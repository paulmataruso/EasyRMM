package printsrv

import (
	"flag"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
)

var update = flag.Bool("update", false, "rewrite pins.go from the scripts")

// scriptFiles lists the action scripts (not the libraries).
func scriptFiles(t *testing.T) []string {
	t.Helper()
	entries, err := scriptFS.ReadDir("scripts")
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range entries {
		if n := e.Name(); !strings.HasPrefix(n, "_") {
			out = append(out, strings.TrimSuffix(n, ".ps1"))
		}
	}
	slices.Sort(out)
	return out
}

// TestPins checks every script's pin; `go test -run TestPins -update` writes
// the new pins, which then go through review like any change to a script.
func TestPins(t *testing.T) {
	files := scriptFiles(t)
	if *update {
		var b strings.Builder
		b.WriteString("package printsrv\n\n// pins are the SHA-256 of each action's assembled script (see Script).\nvar pins = map[string]string{\n")
		for _, f := range files {
			fmt.Fprintf(&b, "\t%q: %q,\n", f, agentproto.HashScript(Script(f)))
		}
		b.WriteString("}\n")
		if err := os.WriteFile("pins.go", []byte(b.String()), 0o644); err != nil { //nolint:gosec // a source file
			t.Fatal(err)
		}
		return
	}
	for _, f := range files {
		if got := agentproto.HashScript(Script(f)); pins[f] != got {
			t.Errorf("%s: pin is %q, the script hashes to %q (run with -update after review)", f, pins[f], got)
		}
	}
	if len(pins) != len(files) {
		t.Errorf("%d pins for %d scripts", len(pins), len(files))
	}
}
