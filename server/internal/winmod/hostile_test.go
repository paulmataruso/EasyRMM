package winmod

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"unicode/utf16"
)

// hostileValues are parameter values meant to break out of a string, a
// command line or a filter: every quoting style PowerShell has (including
// the typographic quotes it treats as quotes), sub-expressions, backticks,
// line breaks, comment openers, operators, wildcards, and Unicode that
// looks like or reorders code. Each one that would run code tries to create
// a file named canary_*, in the folder the script runs in.
func hostileValues() []string {
	return []string{
		"'; New-Item -ItemType File canary_1; '",
		`"; New-Item -ItemType File canary_2; "`,
		"$(New-Item -ItemType File canary_3)",
		"${env:USERNAME} $env:PATH $(Get-Date) $_ $PSItem $?",
		"`n$(New-Item -ItemType File canary_4)`",
		"first\nNew-Item -ItemType File canary_5\nlast",
		"crlf\r\nNew-Item -ItemType File canary_6\r\n",
		"| New-Item -ItemType File canary_7",
		"& New-Item -ItemType File canary_8 #",
		"<# comment #> New-Item -ItemType File canary_9 <#",
		"-Force -Recurse *",
		"*", "?", "[a-z]", "%", "..\\..\\Windows", "\\\\?\\C:\\", "C:\\Windows\\System32\\*",
		"Robert'); DROP TABLE Students;--",
		"(&{New-Item -ItemType File canary_10})",
		"@'\nNew-Item -ItemType File canary_11\n'@",
		"\u2019; New-Item -ItemType File canary_12; \u2018",
		"\u201d; New-Item -ItemType File canary_13; \u201c",
		"Zo\u00eb \u2603 \U0001F600 \u65e5\u672c\u8a9e",
		"e\u0301 \u200b \u202e\u2066 \ufb01",
		"\uff2e\uff25\uff37\uff0d\uff29\uff34\uff25\uff2d canary_14",
		strings.Repeat("A'\"`$(", 600),
		"",
		" leading and trailing ",
	}
}

type hostileItem struct {
	Value        string `json:"value"`
	Length       int    `json:"length"`
	SHA256       string `json:"sha256"`
	ViaFunction  bool   `json:"viaFunction"`
	ViaSplat     bool   `json:"viaSplat"`
	ViaOutput    bool   `json:"viaOutput"`
	ViaObject    bool   `json:"viaObject"`
	AsPathExists bool   `json:"asPathExists"`
}

// powerShell finds the shell the agent would run a script with: Windows
// PowerShell on Windows; elsewhere PowerShell 7 when it is installed (or the
// program named by EASYRMM_TEST_PWSH), else the test is skipped.
func powerShell(t *testing.T) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		return "powershell.exe"
	}
	if p := os.Getenv("EASYRMM_TEST_PWSH"); p != "" {
		return p
	}
	p, err := exec.LookPath("pwsh")
	if err != nil {
		t.Skip("PowerShell is not installed here; the Windows runner job runs this test")
	}
	return p
}

// TestHostileValuesOnWindows sends hostile values to a script through the
// real parameter path (MarshalParams, standard input, `$p = [Console]::In...`)
// and proves each one arrives unchanged and unevaluated, however it is used
// as an argument. The name makes the Windows runner job run it with Windows
// PowerShell 5.1; where PowerShell 7 is installed it runs there too.
func TestHostileValuesOnWindows(t *testing.T) {
	shell := powerShell(t)
	values := hostileValues()
	stdin, err := MarshalParams(map[string]any{"values": values})
	if err != nil {
		t.Fatal(err)
	}
	if len(stdin) > 16*1024*4 {
		t.Fatalf("the test document is %d bytes", len(stdin))
	}
	script, err := filepath.Abs("testdata/hostile.ps1")
	if err != nil {
		t.Fatal(err)
	}
	work := t.TempDir()
	cmd := exec.Command(shell, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", script)
	cmd.Dir = work
	cmd.Stdin = strings.NewReader(string(stdin))
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("the script failed: %v\n%s", err, out)
	}
	var line string
	for _, l := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(l, "EASYRMM-WINMOD-RESULT-V1 ") {
			line = strings.TrimSpace(strings.TrimPrefix(l, "EASYRMM-WINMOD-RESULT-V1 "))
		}
	}
	if line == "" {
		t.Fatalf("no result line:\n%s", out)
	}
	var res struct {
		OK   bool `json:"ok"`
		Data struct {
			Items []hostileItem `json:"items"`
		} `json:"data"`
	}
	if err := json.Unmarshal([]byte(line), &res); err != nil {
		t.Fatalf("the result is not JSON: %v\n%s", err, line)
	}
	if !res.OK || len(res.Data.Items) != len(values) {
		t.Fatalf("got %d items for %d values (ok %v)", len(res.Data.Items), len(values), res.OK)
	}
	for i, want := range values {
		it := res.Data.Items[i]
		sum := sha256.Sum256([]byte(want))
		switch {
		case it.Value != want:
			t.Errorf("value %d changed: %q became %q", i, want, it.Value)
		case it.SHA256 != hex.EncodeToString(sum[:]):
			t.Errorf("value %d: the script saw other bytes (%s)", i, it.SHA256)
		case it.Length != len(utf16.Encode([]rune(want))):
			t.Errorf("value %d: length %d", i, it.Length)
		case !it.ViaFunction || !it.ViaSplat || !it.ViaOutput || !it.ViaObject:
			t.Errorf("value %d changed on its way through an argument: %+v", i, it)
		}
	}
	left, err := os.ReadDir(work)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range left {
		t.Errorf("a value was evaluated: %s was created", f.Name())
	}
}
