// Package powershell finds Windows PowerShell and the PowerShell 7 installs
// of a Windows computer, chooses the one a pwsh script runs in, and checks
// what that run may load (ADR-0064). What does not call Windows is here, so
// that it is tested on every system.
package powershell

import (
	"cmp"
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
)

// installFolders are the names of the folders an install may have under
// <Program Files>\PowerShell: a major version, or one followed by
// -preview, as the MSI names them.
var installFolders = regexp.MustCompile(`^([0-9]{1,3})(-preview)?$`)

// installFolder reads such a folder's name.
func installFolder(name string) (major int, preview, ok bool) {
	m := installFolders.FindStringSubmatch(strings.ToLower(name))
	if m == nil {
		return 0, false, false
	}
	major, _ = strconv.Atoi(m[1])
	return major, m[2] != "", true
}

// storePackages are the folders of PowerShell's Microsoft Store (MSIX)
// packages in <Program Files>\WindowsApps:
// Microsoft.PowerShell_7.6.0.0_x64__8wekyb3d8bbwe,
// Microsoft.PowerShell-LTS_… for a long-term release's package (which
// winget installs for 7.6), or Microsoft.PowerShellPreview_… for previews.
var storePackages = regexp.MustCompile(`^(?i)Microsoft\.PowerShell(Preview|-LTS)?_([0-9.]+)_([a-z0-9]+)__8wekyb3d8bbwe$`)

// storePackage reads a Store package's folder name.
func storePackage(name string) (version, arch string, preview, ok bool) {
	m := storePackages.FindStringSubmatch(name)
	if m == nil {
		return "", "", false, false
	}
	switch strings.ToLower(m[3]) {
	case "x64":
		arch = agentproto.ArchX64
	case "arm64":
		arch = agentproto.ArchARM64
	case "x86":
		arch = agentproto.ArchX86
	}
	return m[2], arch, strings.EqualFold(m[1], "Preview"), true
}

// productVersion is the version in a version resource's ProductVersion,
// which PowerShell 7 follows with the commit it was built from:
// "7.6.10 SHA: 1a2b…" is 7.6.10.
func productVersion(s string) string {
	f := strings.Fields(s)
	if len(f) == 0 {
		return ""
	}
	return f[0]
}

// withEngine is Windows PowerShell's version from the one its registry
// names (5.1.26100.1) and its engine's file version (10.0.26100.7019):
// the registry's first two numbers, then the engine's build and revision
// (5.1.26100.7019), as its $PSVersionTable builds PSVersion.
func withEngine(registry string, engine [4]uint16) (string, error) {
	v, ok := parseVersion(registry)
	if !ok || v.pre != "" || len(v.nums) < 2 {
		return "", fmt.Errorf("the registry names the version %q", registry)
	}
	return fmt.Sprintf("%d.%d.%d.%d", v.nums[0], v.nums[1], engine[2], engine[3]), nil
}

// version is a version as PowerShell numbers it, with the label of a
// prerelease: 7.6.0-preview.4.
type version struct {
	nums []int
	pre  string
}

func parseVersion(s string) (version, bool) {
	core, pre, _ := strings.Cut(s, "-")
	var v version
	for part := range strings.SplitSeq(core, ".") {
		n, err := strconv.Atoi(part)
		if err != nil || n < 0 {
			return version{}, false
		}
		v.nums = append(v.nums, n)
	}
	v.pre = pre
	return v, len(v.nums) > 0
}

// compare orders versions by their numbers, a missing number counting as
// 0, and a prerelease before its release.
func (v version) compare(w version) int {
	for i := range max(len(v.nums), len(w.nums)) {
		a, b := 0, 0
		if i < len(v.nums) {
			a = v.nums[i]
		}
		if i < len(w.nums) {
			b = w.nums[i]
		}
		if c := cmp.Compare(a, b); c != 0 {
			return c
		}
	}
	switch {
	case v.pre == w.pre:
		return 0
	case v.pre == "":
		return 1
	case w.pre == "":
		return -1
	}
	return strings.Compare(v.pre, w.pre)
}

// archRank is how much a pwsh run prefers an install of arch on a computer
// whose own architecture is native: its own first, then on ARM64 the x64
// builds Windows emulates. ok is false for an architecture never used: x86,
// whose PowerShell reads the 32-bit registry and is sent to SysWOW64 for
// System32, and one the computer cannot run.
func archRank(native, arch string) (rank int, ok bool) {
	switch {
	case arch == native && arch != agentproto.ArchX86:
		return 0, true
	case native == agentproto.ArchARM64 && arch == agentproto.ArchX64:
		return 1, true
	}
	return 0, false
}

// Why an install a run would not use is not used.
const (
	reasonStore   = "A Microsoft Store install: reported, never run. Install PowerShell 7 from its MSI (winget install --id Microsoft.PowerShell --installer-type wix) for scripts to use it."
	reasonPreview = "A preview: never used for scripts."
	reasonOld     = "PowerShell %d is out of support: never used for scripts."
	reasonX86     = "A 32-bit (x86) build: never used for scripts, since it sees the 32-bit registry and System32."
	reasonArch    = "Built for %s, which this computer does not run natively: never used for scripts."
	reasonVersion = "Its version could not be read: never used for scripts."
)

// assess marks an install that a pwsh run may use, before its files are
// checked, or says why it may not: a Store install, a preview, a version
// before 7, an x86 build or another architecture than the computer's.
func assess(in *agentproto.PowerShellInstall, native string) {
	in.Usable, in.Reason = false, ""
	v, ok := parseVersion(in.Version)
	_, archOK := archRank(native, in.Arch)
	switch {
	case in.Store:
		in.Reason = reasonStore
	case in.Preview || v.pre != "":
		in.Preview, in.Reason = true, reasonPreview
	case !ok:
		in.Reason = reasonVersion
	case v.nums[0] < 7:
		in.Reason = fmt.Sprintf(reasonOld, v.nums[0])
	case in.Arch == agentproto.ArchX86:
		in.Reason = reasonX86
	case !archOK:
		in.Reason = fmt.Sprintf(reasonArch, cmp.Or(in.Arch, "an unknown architecture"))
	default:
		in.Usable = true
	}
}

// order sorts what was found as the inventory lists it: Windows PowerShell
// first, then the PowerShell 7 installs a run may use, the one it uses
// first, then the rest by path.
func order(list []agentproto.PowerShellInstall, native string) {
	slices.SortStableFunc(list, func(a, b agentproto.PowerShellInstall) int {
		if c := cmp.Compare(rankOf(a), rankOf(b)); c != 0 {
			return c
		}
		if a.Usable && b.Usable {
			ra, _ := archRank(native, a.Arch)
			rb, _ := archRank(native, b.Arch)
			if c := cmp.Compare(ra, rb); c != 0 {
				return c
			}
			va, _ := parseVersion(a.Version)
			vb, _ := parseVersion(b.Version)
			if c := vb.compare(va); c != 0 {
				return c
			}
		}
		return strings.Compare(strings.ToLower(a.Path), strings.ToLower(b.Path))
	})
}

func rankOf(p agentproto.PowerShellInstall) int {
	switch {
	case p.Edition == agentproto.EditionDesktop:
		return 0
	case p.Usable:
		return 1
	}
	return 2
}

// chosen is the install a pwsh run uses from an ordered list, nil when
// none is usable.
func chosen(list []agentproto.PowerShellInstall) *agentproto.PowerShellInstall {
	for i := range list {
		if list[i].Edition == agentproto.EditionCore && list[i].Usable {
			return &list[i]
		}
	}
	return nil
}

// configModulePath reads the module folder a powershell.config.json sets
// (its PSModulePath), "" when it sets none.
func configModulePath(b []byte) (string, error) {
	var c map[string]json.RawMessage
	if err := json.Unmarshal(b, &c); err != nil {
		return "", err
	}
	raw, ok := c["PSModulePath"]
	if !ok {
		return "", nil
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return "", fmt.Errorf("its PSModulePath is not text: %w", err)
	}
	return strings.TrimSpace(s), nil
}

// expand replaces each %NAME% in s with the variable's value from lookup,
// as Windows' ExpandEnvironmentStrings does for PowerShell 7 when it reads
// a configured module path. A name lookup does not know, or an empty one,
// is an error: Windows would leave it and carry on from its closing % as if
// that opened another name, and the agent checks only what it can expand
// as Windows does. A % with no other after it stays, as Windows leaves it.
func expand(s string, lookup func(string) (string, bool)) (string, error) {
	var b strings.Builder
	for {
		i := strings.IndexByte(s, '%')
		if i < 0 {
			break
		}
		j := strings.IndexByte(s[i+1:], '%')
		if j < 0 {
			break
		}
		name := s[i+1 : i+1+j]
		v, ok := lookup(name)
		if name == "" || !ok {
			return "", fmt.Errorf("%%%s%%, which the agent does not expand: a run's environment does not set it, or each run sets its own", name)
		}
		b.WriteString(s[:i] + v)
		s = s[i+2+j:]
	}
	b.WriteString(s)
	return b.String(), nil
}

// PerRun reports whether a run's environment sets the variable name for
// each run (TEMP, TMP and EASYRMM_*, ignoring case as Windows does) rather
// than taking it from the agent's: a run's environment is built by it, and
// a configured module path may not name such a variable, as the inventory
// checks without a run.
func PerRun(name string) bool {
	u := strings.ToUpper(name)
	return u == "TEMP" || u == "TMP" || strings.HasPrefix(u, "EASYRMM_")
}

// runEnv is what a PowerShell run's environment sets over the agent's: a
// module path of Windows PowerShell's two folders, which PowerShell 7 puts
// its own three before, and PowerShell 7's telemetry and update check off.
func runEnv(windowsPS []string) []string {
	return []string{
		"PSModulePath=" + strings.Join(windowsPS, ";"),
		"POWERSHELL_TELEMETRY_OPTOUT=1",
		"POWERSHELL_UPDATECHECK=Off",
	}
}

// runLookup looks a variable up as a run's environment has it: from set,
// what the run sets over the agent's environment, then from agent, the
// agent's own (os.LookupEnv, which ignores case on Windows). A variable
// each run sets for itself (PerRun), or a name with "=" (Windows' hidden
// per-drive folders, which a run does not get), is not known.
func runLookup(set []string, agent func(string) (string, bool)) func(string) (string, bool) {
	return func(name string) (string, bool) {
		if name == "" || strings.Contains(name, "=") || PerRun(name) {
			return "", false
		}
		for i := len(set) - 1; i >= 0; i-- {
			if k, v, _ := strings.Cut(set[i], "="); strings.EqualFold(k, name) {
				return v, true
			}
		}
		return agent(name)
	}
}

// NotFound is the error of a pwsh run without a usable PowerShell 7: where
// the agent looked, and what it found there that it may not use.
type NotFound struct {
	Looked []string
	Found  []agentproto.PowerShellInstall
}

func (e *NotFound) Error() string {
	var found []string
	for _, p := range e.Found {
		if p.Edition == agentproto.EditionCore {
			found = append(found, p.Path+": "+strings.TrimSuffix(p.Reason, "."))
		}
	}
	looked := strings.Join(e.Looked, " and ")
	if len(found) == 0 {
		return "PowerShell 7 is not installed on this device (looked in " + looked + "). The script was not run."
	}
	return "No PowerShell 7 on this device can run scripts (looked in " + looked + "; found " + strings.Join(found, "; ") + "). The script was not run."
}
