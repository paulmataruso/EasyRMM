// Package realtest pins the output formats of the catalog scripts to what a
// real computer printed: each file of a module's testdata/real folder is the
// stdout of one action run in Windows PowerShell 5.1 on a Windows Server 2025
// domain controller (names, addresses and SIDs replaced with made-up ones),
// and the action's own ParseResult must read it. When a script's output
// changes, rerun it on a real server and replace the file.
package realtest

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/paulmataruso/easyrmm/server/internal/winmod"
)

// Parse reads every testdata/real/<action>.txt of the module's folder, named
// by the action's full name ("dns.status.txt"), and requires the action to
// parse it. A file named <action>.<case>.txt ("dns.record_remove.record_not_found.txt")
// is another output of the same action, usually a refusal; one with no case is
// a success. A fixture with no action fails: a renamed action would otherwise
// leave a stale file.
func Parse(t *testing.T, prefix string, actions []winmod.Action) {
	t.Helper()
	files, err := filepath.Glob(filepath.Join("testdata", "real", "*.txt"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no real-output fixtures: %v", err)
	}
	byName := map[string]winmod.Action{}
	for _, a := range actions {
		byName[a.Name] = a
	}
	for _, f := range files {
		base := strings.TrimSuffix(filepath.Base(f), ".txt")
		rest, ok := strings.CutPrefix(base, prefix+".")
		if !ok {
			t.Fatalf("fixture %s does not belong to module %s", base, prefix)
		}
		name, kase, _ := strings.Cut(rest, ".")
		t.Run(base, func(t *testing.T) {
			a, ok := byName[prefix+"."+name]
			if !ok {
				t.Fatalf("no action %s.%s for this fixture", prefix, name)
			}
			raw, err := os.ReadFile(f) //nolint:gosec // G304: a file of the module's own testdata folder
			if err != nil {
				t.Fatal(err)
			}
			res, err := a.ParseResult(string(raw))
			if err != nil {
				t.Fatalf("%s: %v", a.Name, err)
			}
			if kase == "" && !res.OK {
				t.Fatalf("%s: a fixture without a case name is a success, got %+v", a.Name, res.Error)
			}
		})
	}
}
