//go:build windows

// Package rolekittest runs a role's catalog scripts in Windows PowerShell
// as the agent does, for the "Agent tests on Windows" job. A runner has none
// of the roles, so what it can show is the role-absent path (every action
// says module_missing before it reads a parameter) and that each script
// parses and answers in the result format.
package rolekittest

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/paulmataruso/easyrmm/server/internal/winmod"
)

// ModuleInstalled says whether the computer has a PowerShell module.
func ModuleInstalled(t *testing.T, name string) bool {
	t.Helper()
	// The module name is one of this repository's own constants.
	out, err := exec.CommandContext(context.Background(), "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", //nolint:gosec // G204: fixed program, a constant module name
		"if (Get-Module -ListAvailable -Name '"+name+"') { 'yes' } else { 'no' }").Output()
	if err != nil {
		t.Fatalf("checking for module %s: %v", name, err)
	}
	return strings.TrimSpace(string(out)) == "yes"
}

// Run runs the action's script with params on standard input and parses its
// result by the catalog's schema.
func Run(t *testing.T, a winmod.Action, params string) *winmod.Result {
	t.Helper()
	script := filepath.Join(t.TempDir(), "action.ps1")
	if err := os.WriteFile(script, []byte(a.Script), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", script) //nolint:gosec // G204: fixed program; the script is a catalog entry written to a private temp folder
	cmd.Stdin = strings.NewReader(params)
	var out, errOut bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errOut
	if err := cmd.Run(); err != nil {
		t.Fatalf("%s failed: %v\nstdout: %s\nstderr: %s", a.Name, err, out.String(), errOut.String())
	}
	res, err := a.ParseResult(out.String())
	if err != nil {
		t.Fatalf("%s: not a valid result: %v\n%s", a.Name, err, out.String())
	}
	return res
}

// RoleAbsentPath runs every action of a module with empty parameters on a
// computer without its PowerShell module and requires module_missing. Where
// the module is there (a developer's server), only the reads run, and each
// must answer in the result format; a change is never run with empty
// parameters.
func RoleAbsentPath(t *testing.T, module string, actions []winmod.Action) {
	t.Helper()
	installed := ModuleInstalled(t, module)
	for _, a := range actions {
		t.Run(a.Name, func(t *testing.T) {
			if installed {
				if a.Changes {
					t.Skip("the module is installed; a change is not run with empty parameters")
				}
				res := Run(t, a, `{}`)
				t.Logf("%s on a computer with %s: ok=%v", a.Name, module, res.OK)
				return
			}
			res := Run(t, a, `{}`)
			if res.OK || res.Error == nil || res.Error.Code != "module_missing" {
				t.Fatalf("%s: want module_missing, got %+v", a.Name, res)
			}
		})
	}
}
