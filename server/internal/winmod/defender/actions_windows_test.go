//go:build windows

package defender

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

// runAction runs an action's pinned script in Windows PowerShell on stdin
// params, as the agent does, and decodes its result by the catalog's schema.
func runAction(t *testing.T, name, params string) *winmod.Result {
	t.Helper()
	c, err := winmod.NewCatalog(Actions()...)
	if err != nil {
		t.Fatal(err)
	}
	a, ok := c.Lookup("defender." + name)
	if !ok {
		t.Fatalf("no action %s", name)
	}
	script := filepath.Join(t.TempDir(), name+".ps1")
	if err := writeFile(script, a.Script); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", script)
	cmd.Stdin = strings.NewReader(params)
	var out, errOut bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errOut
	if err := cmd.Run(); err != nil {
		t.Fatalf("%s failed: %v\nstdout: %s\nstderr: %s", name, err, out.String(), errOut.String())
	}
	res, err := a.ParseResult(out.String())
	if err != nil {
		t.Fatalf("%s: not a valid result: %v\n%s", name, err, out.String())
	}
	return res
}

// TestReadActionsOnWindows runs every read on the runner. Defender may be in
// any state there (and absent), so what each says is logged, not assumed:
// the check is that each returns a result of its schema, or module_missing.
func TestReadActionsOnWindows(t *testing.T) {
	for _, n := range []string{"preferences_read", "asr_read", "cfa_read", "exclusions_read", "threats_read", "quarantine_read"} {
		res := runAction(t, n, `{}`)
		if !res.OK {
			if res.Error.Code != "module_missing" {
				t.Errorf("%s failed: %+v", n, res.Error)
			}
			t.Logf("%s: the runner has no Defender module", n)
			continue
		}
		t.Logf("%s on the runner: %.300s", n, res.Data)
	}
}

// TestWriteRefusalsOnWindows runs writes that must refuse before they change
// anything: ours is never removed (the script's own guard, with a short name
// and an environment variable), a field the module does not own is not
// allowed, and a hostile value is only ever a value. Where the runner has no
// Defender, or it is passive, the script says so and the test logs it.
func TestWriteRefusalsOnWindows(t *testing.T) {
	refused := func(name, params string, codes ...string) {
		t.Helper()
		res := runAction(t, name, params)
		if res.OK {
			t.Errorf("%s %s was not refused: %s", name, params, res.Data)
			return
		}
		for _, c := range append(codes, "module_missing", "passive_mode", "unsupported") {
			if res.Error.Code == c {
				t.Logf("%s refused with %s", name, c)
				return
			}
		}
		t.Errorf("%s %s refused with %q, want one of %v", name, params, res.Error.Code, codes)
	}
	refused("exclusion_remove", `{"kind":"path","value":"C:\\Program Files\\EasyRMM\\Agent"}`, "protected_exclusion", "managed_by_policy")
	refused("exclusion_remove", `{"kind":"path","value":"%ProgramFiles%\\EasyRMM\\Agent\\"}`, "protected_exclusion", "managed_by_policy")
	refused("exclusion_remove", `{"kind":"path","value":"C:\\PROGRA~1\\EasyRMM\\Agent"}`, "protected_exclusion", "managed_by_policy")
	refused("exclusion_remove", `{"kind":"process","value":"C:\\Program Files\\EasyRMM\\MeshAgent\\meshagent.exe"}`, "protected_exclusion", "managed_by_policy")
	refused("cfa_app_remove", `{"path":"C:\\Program Files\\EasyPatch Agent\\EasyPatch.Agent.exe"}`, "protected_exclusion", "managed_by_policy")
	refused("preferences_set", `{"field":"DisableLocalAdminMerge","value":"true"}`, "not_allowed")
	refused("preferences_set", `{"field":"MAPSReporting","value":"2'); Start-Process calc; ('"}`, "not_allowed", "command_failed")
	refused("exclusion_remove", `{"kind":"path","value":"$(Start-Process calc)"}`, "not_in_list", "managed_by_policy")
}
