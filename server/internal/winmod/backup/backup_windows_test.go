//go:build windows

package backup

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/paulmataruso/easyrmm/server/internal/winmod"
)

// TestReadScriptsOnWindows runs the pinned scripts of the read-only actions
// (and stop, which changes nothing when nothing runs) in Windows PowerShell on
// stdin params, as the agent does, and decodes each result by the catalog's
// schema. A runner without Windows Server Backup must answer module_missing
// (status: installed false); one with it must answer ok or a typed refusal.
// What the runner says is logged, not assumed. The role itself is not tested
// here: a server with a policy and a target is a manual step (ADR-0077, R1
// to R12), and nothing here installs the feature or starts a backup.
func TestReadScriptsOnWindows(t *testing.T) {
	c, err := winmod.NewCatalog(Actions()...)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"status", "sensitive", "versions", "disks", "job", "versions_prune_preview", "stop"} {
		t.Run(name, func(t *testing.T) {
			a, _ := c.Lookup("windows_backup." + name)
			script := t.TempDir() + `\` + name + `.ps1`
			if err := os.WriteFile(script, []byte(a.Script), 0o600); err != nil {
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
			if res.OK {
				t.Logf("%s on the runner: %s", name, res.Data)
				return
			}
			switch res.Error.Code {
			case "module_missing", "not_running", "no_policy":
				t.Logf("%s: %s (%s)", name, res.Error.Code, res.Error.Message)
			default:
				t.Fatalf("the action failed: %+v", res.Error)
			}
		})
	}
}
