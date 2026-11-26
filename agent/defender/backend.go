package defender

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

// Prefs is what Defender says of itself.
type Prefs struct {
	// Missing: Defender's PowerShell module is not on this machine (a
	// Windows Server installed without Defender).
	Missing bool
	// NA is Defender's own "N/A" text, in place of a list: it hides what
	// it will not show (Tamper Protection, permissions). Never a guess.
	NA    string
	Lists map[string][]string
	// DisableLocalAdminMerge true: local exclusions are ignored in favor
	// of policy's (Intune, Group Policy, Configuration Manager).
	DisableLocalAdminMerge bool
	// CFAOn: Controlled Folder Access is on or auditing. ASRRules counts
	// the Attack Surface Reduction rules set.
	CFAOn    bool
	ASRRules int

	RunningMode     string // Normal, Passive, SxS Passive Mode, EDR Block Mode
	AntivirusOn     bool
	ServiceOn       bool
	RealTimeOn      bool
	TamperProtected bool
}

// Backend reads and changes Defender's lists. Add and Remove return a
// *Refused for Defender's own refusal.
type Backend interface {
	Read(ctx context.Context) (Prefs, error)
	Add(ctx context.Context, kind, path string) error
	Remove(ctx context.Context, kind, path string) error
	// Method is "powershell" or "wmi": which one the last call used.
	Method() string
}

// Refused is Defender saying no.
type Refused struct{ Reason string }

func (r *Refused) Error() string { return r.Reason }

// params maps a kind to the parameter of Add-MpPreference and
// Remove-MpPreference, and to the property of MSFT_MpPreference.
var params = map[string]string{
	"path":    "ExclusionPath",
	"process": "ExclusionProcess",
	"asr":     "AttackSurfaceReductionOnlyExclusions",
	"cfa":     "ControlledFolderAccessAllowedApplications",
}

// Environment variable that carries the path to a script: never joined
// into the script's text.
const pathVar = "EASYRMM_DEFENDER_PATH"

// readScript prints Defender's preference and status as one line of JSON.
// It is fixed text.
const readScript = `$ErrorActionPreference = 'Stop'
if (-not (Get-Command Get-MpPreference -ErrorAction SilentlyContinue)) { '{"missing":true}'; exit 0 }
$p = Get-MpPreference
$s = Get-MpComputerStatus
[pscustomobject]@{
  missing = $false
  path = @($p.ExclusionPath | ForEach-Object { [string]$_ })
  process = @($p.ExclusionProcess | ForEach-Object { [string]$_ })
  asr = @($p.AttackSurfaceReductionOnlyExclusions | ForEach-Object { [string]$_ })
  cfa = @($p.ControlledFolderAccessAllowedApplications | ForEach-Object { [string]$_ })
  disableLocalAdminMerge = [bool]$p.DisableLocalAdminMerge
  cfaMode = [int]$p.EnableControlledFolderAccess
  asrRules = @($p.AttackSurfaceReductionRules_Ids).Count
  runningMode = [string]$s.AMRunningMode
  antivirusEnabled = [bool]$s.AntivirusEnabled
  serviceEnabled = [bool]$s.AMServiceEnabled
  realTimeEnabled = [bool]$s.RealTimeProtectionEnabled
  tamperProtected = [bool]$s.IsTamperProtected
} | ConvertTo-Json -Compress`

type readOut struct {
	Missing                bool     `json:"missing"`
	Path                   []string `json:"path"`
	Process                []string `json:"process"`
	ASR                    []string `json:"asr"`
	CFA                    []string `json:"cfa"`
	DisableLocalAdminMerge bool     `json:"disableLocalAdminMerge"`
	CFAMode                int      `json:"cfaMode"`
	ASRRules               int      `json:"asrRules"`
	RunningMode            string   `json:"runningMode"`
	AntivirusEnabled       bool     `json:"antivirusEnabled"`
	ServiceEnabled         bool     `json:"serviceEnabled"`
	RealTimeEnabled        bool     `json:"realTimeEnabled"`
	TamperProtected        bool     `json:"tamperProtected"`
}

// ParsePrefs reads readScript's output.
func ParsePrefs(out []byte) (Prefs, error) {
	line := out
	if i := strings.LastIndex(strings.TrimSpace(string(out)), "\n"); i >= 0 {
		line = []byte(strings.TrimSpace(string(out))[i+1:])
	}
	var r readOut
	if err := json.Unmarshal([]byte(strings.TrimSpace(string(line))), &r); err != nil {
		return Prefs{}, fmt.Errorf("the answer of Defender cannot be read: %w", err)
	}
	if r.Missing {
		return Prefs{Missing: true}, nil
	}
	p := Prefs{
		Lists:                  map[string][]string{"path": r.Path, "process": r.Process, "asr": r.ASR, "cfa": r.CFA},
		DisableLocalAdminMerge: r.DisableLocalAdminMerge, CFAOn: r.CFAMode == 1 || r.CFAMode == 2, ASRRules: r.ASRRules,
		RunningMode: r.RunningMode, AntivirusOn: r.AntivirusEnabled, ServiceOn: r.ServiceEnabled,
		RealTimeOn: r.RealTimeEnabled, TamperProtected: r.TamperProtected,
	}
	for _, list := range p.Lists {
		for _, e := range list {
			if strings.HasPrefix(strings.TrimSpace(e), "N/A:") {
				p.NA = strings.TrimSpace(e)
			}
		}
	}
	return p, nil
}

// Exec runs a program with extra environment variables and returns its
// combined output.
type Exec func(ctx context.Context, env []string, name string, args ...string) ([]byte, error)

// RunExec runs for real.
func RunExec(ctx context.Context, env []string, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...) //nolint:gosec // the fixed PowerShell and fixed scripts
	cmd.Env = append(os.Environ(), env...)
	hideWindow(cmd)
	return cmd.CombinedOutput()
}

// PowerShell drives Defender through its PowerShell module, and falls back
// once, for a call that fails for a reason other than Defender's refusal,
// to the MSFT_MpPreference class.
type PowerShell struct {
	Run Exec
	// Exe is the fixed Windows PowerShell path.
	Exe    string
	method string
}

// NewPowerShell returns the backend for this machine's Windows PowerShell.
func NewPowerShell(run Exec) *PowerShell {
	root := os.Getenv("SystemRoot")
	if root == "" {
		root = `C:\Windows`
	}
	return &PowerShell{Run: run, Exe: filepath.Join(root, "System32", "WindowsPowerShell", "v1.0", "powershell.exe")}
}

func (p *PowerShell) Method() string { return p.method }

func (p *PowerShell) script(ctx context.Context, env []string, text string) ([]byte, error) {
	return p.Run(ctx, env, p.Exe, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", text)
}

func (p *PowerShell) Read(ctx context.Context) (Prefs, error) {
	out, err := p.script(ctx, nil, readScript)
	p.method = "powershell"
	if err != nil {
		return Prefs{}, fmt.Errorf("reading Defender's settings: %w: %s", err, tail(out))
	}
	return ParsePrefs(out)
}

var refusal = regexp.MustCompile(`(?i)access is denied|0x800106ba|tamper|0x80070005|managed by|group policy|blocked by`)

// IsRefusal says whether a cmdlet's error is Defender refusing.
func IsRefusal(out string) bool { return refusal.MatchString(out) }

func (p *PowerShell) Add(ctx context.Context, kind, path string) error {
	return p.change(ctx, "Add", kind, path)
}

func (p *PowerShell) Remove(ctx context.Context, kind, path string) error {
	return p.change(ctx, "Remove", kind, path)
}

func (p *PowerShell) change(ctx context.Context, verb, kind, path string) error {
	param, ok := params[kind]
	if !ok {
		return fmt.Errorf("unknown exclusion kind %q", kind)
	}
	env := []string{pathVar + "=" + path}
	cmdlet := fmt.Sprintf("$ErrorActionPreference = 'Stop'; %s-MpPreference -%s $env:%s", verb, param, pathVar)
	out, err := p.script(ctx, env, cmdlet)
	if err == nil {
		p.method = "powershell"
		return nil
	}
	if IsRefusal(string(out)) {
		p.method = "powershell"
		return &Refused{Reason: tail(out)}
	}
	// Once, for this one call: never both for the same entry that worked.
	wmi := fmt.Sprintf("$ErrorActionPreference = 'Stop'; $r = Invoke-CimMethod -Namespace root/Microsoft/Windows/Defender -ClassName MSFT_MpPreference -MethodName %s -Arguments @{%s = [string[]]@($env:%s)}; if ($r -and $r.ReturnValue) { exit 1 }", verb, param, pathVar)
	out2, err2 := p.script(ctx, env, wmi)
	p.method = "wmi"
	if err2 == nil {
		return nil
	}
	if IsRefusal(string(out2)) {
		return &Refused{Reason: tail(out2)}
	}
	return errors.New("Defender could not be changed by PowerShell (" + tail(out) + ") or by WMI (" + tail(out2) + ")")
}

func tail(out []byte) string {
	s := strings.Join(strings.Fields(string(out)), " ")
	if len(s) > 200 {
		s = s[len(s)-200:]
	}
	return s
}
