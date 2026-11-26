//go:build windows

package defender

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/paulmataruso/easyrmm/agent/inventory"
	"github.com/paulmataruso/easyrmm/internal/agentproto"
)

// ADR-0070's checks on a real Windows with Microsoft Defender running (CI's
// windows-defender job runs them as LocalSystem, as the agent runs). They
// make folders and exclusions of their own, named EasyRMM-CI-<random>, and
// remove them. Where the image's Defender is not the active antivirus the
// tests that need it say so and stop; nothing here turns AMSI off, and only
// the not-applicable test turns real-time protection off, putting it back.

func system(t *testing.T) {
	t.Helper()
	if os.Getenv("EASYRMM_TEST_SYSTEM") == "" {
		t.Skip("runs as LocalSystem on a computer made for it; CI's job sets EASYRMM_TEST_SYSTEM")
	}
}

func psOut(t *testing.T, script string) string {
	t.Helper()
	out, err := NewPowerShell(RunExec).script(context.Background(), nil, script)
	if err != nil {
		t.Fatalf("PowerShell: %v\n%s\n%s", err, script, out)
	}
	return strings.TrimSpace(string(out))
}

type ci struct {
	m                   *Manager
	pdAgent, pfAgent    string
	pfMesh, agentExe    string
	meshExe, pdRoot, id string
}

func newCI(t *testing.T) *ci {
	t.Helper()
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	id := hex.EncodeToString(b)
	c := &ci{id: id}
	c.pdRoot = filepath.Join(os.Getenv("ProgramData"), "EasyRMM-CI-"+id)
	c.pdAgent = filepath.Join(c.pdRoot, "Agent")
	pf := filepath.Join(os.Getenv("ProgramFiles"), "EasyRMM-CI-"+id)
	c.pfAgent, c.pfMesh = filepath.Join(pf, "Agent"), filepath.Join(pf, "MeshAgent")
	c.agentExe, c.meshExe = filepath.Join(c.pfAgent, "easyrmm-agent.exe"), filepath.Join(c.pfMesh, "meshagent.exe")
	c.m = &Manager{
		Backend: NewPowerShell(RunExec), System: NewSystem(),
		Folders: []string{c.pdAgent, c.pfAgent, c.pfMesh}, Programs: []string{c.agentExe, c.meshExe},
		RecordFile: filepath.Join(c.pdAgent, RecordFile), Version: "ci", Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	t.Cleanup(func() {
		_, _ = c.m.Remove(context.Background())
		for _, p := range []string{c.pdRoot, pf} {
			_ = exec.Command("icacls", p, "/reset", "/T", "/C", "/Q").Run()
			_ = os.RemoveAll(p)
		}
	})
	return c
}

// prefs reads Defender's lists as they are.
func prefs(t *testing.T) Prefs {
	t.Helper()
	p, err := NewPowerShell(RunExec).Read(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// needDefender stops a test where Defender is not the active antivirus.
func needDefender(t *testing.T, r *agentproto.DefenderReport) {
	t.Helper()
	if r.State == agentproto.DefenderNotApplicable || r.State == agentproto.DefenderUnavailable {
		t.Skipf("Defender is not usable on this runner: %s: %s", r.State, r.Reason)
	}
}

func TestExclusionsAddedAndRemovedAsSystem(t *testing.T) {
	system(t)
	c := newCI(t)
	byHand := `C:\EasyRMM-CI-byhand-` + c.id
	psOut(t, "Add-MpPreference -ExclusionPath '"+byHand+"'")
	t.Cleanup(func() {
		_, _ = NewPowerShell(RunExec).script(context.Background(), nil, "Remove-MpPreference -ExclusionPath '"+byHand+"'")
	})

	r := c.m.Reconcile(context.Background())
	needDefender(t, r)
	// Step 1: every folder is locked down and listed, the programs too, and nothing that is not ours.
	p := prefs(t)
	for _, f := range c.m.Folders {
		if !listed(p.Lists["path"], f) || !listed(p.Lists["asr"], f) {
			t.Errorf("%s is not in ExclusionPath and the ASR exclusions: %v", f, p.Lists)
		}
		if err := c.m.System.Verify(f); err != nil {
			t.Errorf("%s was excluded but does not verify: %v", f, err)
		}
	}
	for _, x := range c.m.Programs {
		if !listed(p.Lists["process"], x) || !listed(p.Lists["cfa"], x) {
			t.Errorf("%s is not in ExclusionProcess and the Controlled Folder Access allowed applications", x)
		}
	}
	for _, never := range []string{os.TempDir(), `C:\Windows\Temp`, filepath.Join(os.Getenv("SystemRoot"), `System32\WindowsPowerShell\v1.0\powershell.exe`)} {
		for kind, list := range p.Lists {
			if listed(list, never) {
				t.Errorf("%s is in the %s list", never, kind)
			}
		}
	}
	// Step 2: the facts say effective, unless a policy on the image says otherwise.
	if p.DisableLocalAdminMerge {
		t.Logf("the image has DisableLocalAdminMerge set; state = %s", r.State)
	} else if r.State != agentproto.DefenderEffective {
		t.Errorf("state = %s (%s)", r.State, r.Reason)
	}
	// Step 3: uninstall removes exactly those, and not the path added by hand.
	if _, err := c.m.Remove(context.Background()); err != nil {
		t.Fatal(err)
	}
	p = prefs(t)
	for _, f := range c.m.Folders {
		if listed(p.Lists["path"], f) || listed(p.Lists["asr"], f) {
			t.Errorf("%s is still listed after the removal", f)
		}
	}
	for _, x := range c.m.Programs {
		if listed(p.Lists["process"], x) || listed(p.Lists["cfa"], x) {
			t.Errorf("%s is still listed after the removal", x)
		}
	}
	if !listed(p.Lists["path"], byHand) {
		t.Error("an exclusion added by hand was removed")
	}
}

func TestDisableLocalAdminMergeIsReportedAsSystem(t *testing.T) {
	system(t)
	c := newCI(t)
	needDefender(t, c.m.Reconcile(context.Background()))
	before := psOut(t, "[string](Get-MpPreference).DisableLocalAdminMerge")
	if _, err := NewPowerShell(RunExec).script(context.Background(), nil, "Set-MpPreference -DisableLocalAdminMerge $true"); err != nil {
		t.Skipf("this image does not let DisableLocalAdminMerge be set: %v", err)
	}
	t.Cleanup(func() {
		_, _ = NewPowerShell(RunExec).script(context.Background(), nil, "Set-MpPreference -DisableLocalAdminMerge $"+strings.ToLower(before))
	})
	r := c.m.Reconcile(context.Background())
	if r.State != agentproto.DefenderNotEffective || !strings.Contains(r.Reason, "DisableLocalAdminMerge") {
		t.Fatalf("state = %s (%s)", r.State, r.Reason)
	}
	if rec, _, _ := LoadRecord(c.m.RecordFile); len(rec.Entries) == 0 {
		t.Error("what was added is not recorded")
	}
}

func TestAFolderUsersMayWriteIsNeverExcludedAsSystem(t *testing.T) {
	system(t)
	c := newCI(t)
	r := c.m.Reconcile(context.Background())
	needDefender(t, r)
	if !listed(prefs(t).Lists["path"], c.pfMesh) {
		t.Fatal("the mesh folder was not excluded first")
	}
	// Step 4: its parent becomes writable by Users, so it cannot verify.
	parent := filepath.Dir(c.pfMesh)
	if out, err := exec.Command("icacls", parent, "/grant", "*S-1-5-32-545:(OI)(CI)(W)").CombinedOutput(); err != nil {
		t.Fatalf("icacls: %v: %s", err, out)
	}
	r = c.m.Reconcile(context.Background())
	if r.State != agentproto.DefenderNotLocked {
		t.Fatalf("state = %s (%s)", r.State, r.Reason)
	}
	if listed(prefs(t).Lists["path"], c.pfMesh) {
		t.Error("an exclusion for a folder that became writable was not removed")
	}
	if !strings.Contains(r.Reason, "can be changed") && !strings.Contains(r.Reason, "BUILTIN") && !strings.Contains(r.Reason, "S-1-5-32-545") {
		t.Errorf("reason = %q", r.Reason)
	}
}

const eicar = "AMSI Test Sample: 7e72c3ce-861b-4339-8740-0ac1484c1386"

// blocked runs a script with the program given and says whether AMSI stopped it.
func blocked(t *testing.T, program, script string) bool {
	t.Helper()
	if err := os.WriteFile(script, []byte("'"+eicar+"'\r\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(program, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", script).CombinedOutput()
	return err != nil && strings.Contains(strings.ToLower(string(out)), "malicious")
}

// TestAMSIStaysOnAsSystem is the probe of ADR-0070's section 3. The result is
// logged, for the ADR: whether a script run by PowerShell from an excluded
// folder, or by an excluded process, is still scanned. The test fails if
// AMSI is not what it was: its provider registered, and the test string
// blocked from a folder that is not excluded.
func TestAMSIStaysOnAsSystem(t *testing.T) {
	system(t)
	c := newCI(t)
	powershell := filepath.Join(os.Getenv("SystemRoot"), `System32\WindowsPowerShell\v1.0\powershell.exe`)
	plain := filepath.Join(t.TempDir(), "probe.ps1")
	if !strings.Contains(psOut(t, "Get-MpPreference | Select-Object -ExpandProperty DisableRealtimeMonitoring"), "False") {
		t.Skip("real-time protection is off on this image; AMSI cannot be judged")
	}
	if psOut(t, `(Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\AMSI\Providers' -ErrorAction SilentlyContinue | Measure-Object).Count`) == "0" {
		t.Fatal("no AMSI provider is registered")
	}
	baseline := blocked(t, powershell, plain)
	if !baseline {
		t.Skip("the AMSI test string is not blocked from a plain folder on this image, so there is nothing to compare")
	}
	r := c.m.Reconcile(context.Background())
	needDefender(t, r)
	// A copy of Windows PowerShell stands in for the excluded program, at the path the agent's own is excluded by.
	if err := os.MkdirAll(c.pfAgent, 0o755); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(powershell)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(c.agentExe, data, 0o755); err != nil { //nolint:gosec // an executable the test runs
		t.Fatal(err)
	}
	inFolder := blocked(t, powershell, filepath.Join(c.pdAgent, "probe.ps1"))
	byProcess := blocked(t, c.agentExe, filepath.Join(os.TempDir(), "probe-"+c.id+".ps1"))
	t.Logf("AMSI probe (ADR-0070): the test string is blocked from a folder that is excluded: %v; run by an excluded process: %v", inFolder, byProcess)
	if !blocked(t, powershell, plain) {
		t.Error("with the exclusions in place the test string is no longer blocked from a folder that is not excluded")
	}
	if _, err := c.m.Remove(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !blocked(t, powershell, plain) {
		t.Error("after the removal the test string is not blocked")
	}
}

func TestNotApplicableWhereDefenderIsNotActiveAsSystem(t *testing.T) {
	system(t)
	c := newCI(t)
	needDefender(t, c.m.Reconcile(context.Background()))
	_, _ = c.m.Remove(context.Background())
	if _, err := NewPowerShell(RunExec).script(context.Background(), nil, "Set-MpPreference -DisableRealtimeMonitoring $true"); err != nil {
		t.Skipf("this image does not let real-time protection be turned off: %v", err)
	}
	t.Cleanup(func() {
		_, _ = NewPowerShell(RunExec).script(context.Background(), nil, "Set-MpPreference -DisableRealtimeMonitoring $false")
	})
	if p := prefs(t); p.RealTimeOn {
		t.Skip("real-time protection stayed on (Tamper Protection)")
	}
	r := c.m.Reconcile(context.Background())
	if r.State != agentproto.DefenderNotApplicable {
		t.Fatalf("state = %s (%s)", r.State, r.Reason)
	}
	if listed(prefs(t).Lists["path"], c.pdAgent) {
		t.Error("it added an exclusion where Defender is not the active antivirus")
	}
	if _, err := os.Stat(c.pdAgent); err != nil {
		t.Error("it still locks the folders down")
	}
}

func TestInstalledHashesAreTheFilesOwnAsSystem(t *testing.T) {
	system(t)
	file := filepath.Join(t.TempDir(), "easyrmm-agent.exe")
	if err := os.WriteFile(file, []byte("a build"), 0o600); err != nil {
		t.Fatal(err)
	}
	r := (&inventory.Installed{AgentExe: file, AgentVersion: "ci"}).Due(context.Background())
	if r == nil || len(r.Files) != 1 {
		t.Fatalf("report = %+v", r)
	}
	for algo, got := range map[string]string{"SHA256": r.Files[0].SHA256, "MD5": r.Files[0].MD5} {
		want := strings.ToLower(psOut(t, "(Get-FileHash -Algorithm "+algo+" -LiteralPath '"+file+"').Hash"))
		if got != want {
			t.Errorf("%s: reported %s, Windows says %s", algo, got, want)
		}
	}
}
