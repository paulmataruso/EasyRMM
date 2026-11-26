package agentapi

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/paulmataruso/easyrmm/server/internal/httpapi"
)

// TestInstallScriptRestartsOnNewBuild runs the Linux installer against stub
// system tools: a reinstall of a new build restarts the service and reports
// the new version, a reinstall of the same build restarts nothing.
func TestInstallScriptRestartsOnNewBuild(t *testing.T) {
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("no sh")
	}
	a := newAPI(t, testCA)
	script := serve(a, "/api/agent/v1/install.sh", &httpapi.Origin{Console: "https://rmm.example.com"}).Body.String()
	dir := t.TempDir()
	bin := filepath.Join(dir, "easyrmm-agent")
	script = strings.ReplaceAll(script, "/usr/local/bin/easyrmm-agent", bin)
	scriptPath := filepath.Join(dir, "install.sh")
	write := func(path, body string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(body), 0o700); err != nil { //nolint:gosec // test stubs must be executable
			t.Fatal(err)
		}
	}
	write(scriptPath, script)
	stubs := filepath.Join(dir, "stubs")
	if err := os.Mkdir(stubs, 0o700); err != nil {
		t.Fatal(err)
	}
	calls := filepath.Join(dir, "calls")
	write(filepath.Join(stubs, "uname"), "#!/bin/sh\nif [ \"$1\" = -m ]; then echo x86_64; else echo Linux; fi\n")
	write(filepath.Join(stubs, "id"), "#!/bin/sh\necho 0\n")
	write(filepath.Join(stubs, "systemctl"), "#!/bin/sh\necho \"systemctl $*\" >>"+calls+"\n")
	// The download is the file named by VERSION; its checksum list is made
	// from it.
	write(filepath.Join(stubs, "curl"), `#!/bin/sh
while [ $# -gt 0 ]; do case "$1" in -o) out="$2"; shift 2;; *) url="$1"; shift;; esac; done
cat >/dev/null
agent="$(cat `+dir+`/payload)"
case "$url" in
*SHA256SUMS) printf '%s  easyrmm-agent-linux-amd64\n' "$(sha256sum `+dir+`/payload | cut -d' ' -f1)" >"$out" ;;
*) cp `+dir+`/payload "$out" ;;
esac
`)
	run := func(version string) (string, string) {
		t.Helper()
		write(filepath.Join(dir, "payload"), "#!/bin/sh\ncase \"$1\" in version) echo \"easyrmm-agent "+version+"\";; install) echo installed;; esac\n")
		_ = os.Remove(calls)
		cmd := exec.CommandContext(t.Context(), sh, scriptPath) //nolint:gosec // test-controlled
		cmd.Env = []string{"PATH=" + stubs + ":" + os.Getenv("PATH"), "EASYRMM_TOKEN=t"}
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("install %s: %v %s", version, err, out)
		}
		c, _ := os.ReadFile(calls) //nolint:gosec // the test's own file
		return string(out), string(c)
	}
	if out, c := run("1.0.0"); c != "" || !strings.Contains(out, "easyrmm-agent 1.0.0") {
		t.Errorf("first install: restarts %q out %q", c, out)
	}
	if out, c := run("1.0.0"); c != "" || !strings.Contains(out, "easyrmm-agent 1.0.0") {
		t.Errorf("same build: restarts %q out %q", c, out)
	}
	out, c := run("1.1.0")
	if !strings.Contains(c, "try-restart easyrmm-agent.service") || !strings.Contains(out, "easyrmm-agent 1.1.0") {
		t.Errorf("new build: restarts %q out %q", c, out)
	}
}
