//go:build windows

package grouppolicy

import (
	"bytes"
	"context"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/paulmataruso/easyrmm/server/internal/winmod"
)

// TestScriptsOnWindows runs every pinned script in Windows PowerShell on
// empty parameters, as the agent does, and decodes the answer by the
// catalog's schema. A hosted runner is not a domain controller, so what is
// asserted is the role-absent path: module_missing (or, if the runner has the
// tools, a typed failure because there is no domain). What it says is
// logged for the job summary. Real-controller behavior is a manual step.
func TestScriptsOnWindows(t *testing.T) {
	c, err := winmod.NewCatalog(Actions()...)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	for _, a := range c.Actions() {
		name := strings.TrimPrefix(a.Name, "group_policy.")
		file := filepath.Join(dir, name+".ps1")
		if err := writeScript(file, a.Script); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		cmd := exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", file)
		cmd.Stdin = strings.NewReader(`{}`)
		var out, errOut bytes.Buffer
		cmd.Stdout, cmd.Stderr = &out, &errOut
		err := cmd.Run()
		cancel()
		if err != nil {
			t.Fatalf("%s failed: %v\nstdout: %s\nstderr: %s", name, err, out.String(), errOut.String())
		}
		res, err := a.ParseResult(out.String())
		if err != nil {
			t.Fatalf("%s: not a valid result: %v\n%s", name, err, out.String())
		}
		if res.OK {
			t.Fatalf("%s: succeeded with no directory", name)
		}
		t.Logf("%s: %s", name, res.Error.Code)
	}
}
