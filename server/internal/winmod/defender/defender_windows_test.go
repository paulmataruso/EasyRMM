//go:build windows

package defender

import (
	"bytes"
	"context"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/paulmataruso/easyrmm/server/internal/winmod"
)

// TestStatusScriptOnWindows runs the pinned script of defender.status in
// Windows PowerShell on stdin params, as the agent does, and decodes its
// result by the catalog's schema. The runner may have Defender in any
// state, so what it says is logged for the job summary, not assumed; a
// computer without the module must say module_missing.
func TestStatusScriptOnWindows(t *testing.T) {
	c, err := winmod.NewCatalog(Actions()...)
	if err != nil {
		t.Fatal(err)
	}
	a, _ := c.Lookup("defender.status")
	dir := t.TempDir()
	script := dir + `\status.ps1`
	if err := writeFile(script, a.Script); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", script)
	cmd.Stdin = strings.NewReader(`{}`)
	var out, errOut bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errOut
	if err := cmd.Run(); err != nil {
		t.Fatalf("the script failed: %v\nstdout: %s\nstderr: %s", err, out.String(), errOut.String())
	}
	res, err := a.ParseResult(out.String())
	if err != nil {
		t.Fatalf("not a valid result: %v\n%s", err, out.String())
	}
	if !res.OK {
		if res.Error.Code != "module_missing" {
			t.Fatalf("the action failed: %+v", res.Error)
		}
		t.Logf("defender.status: the runner has no Defender module (module_missing)")
		return
	}
	t.Logf("defender.status on the runner: %s", res.Data)
}
