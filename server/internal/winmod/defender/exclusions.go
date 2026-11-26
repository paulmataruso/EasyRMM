package defender

import (
	"regexp"
	"slices"
	"strings"

	"github.com/paulmataruso/easyrmm/server/internal/apperr"
)

// Exclusion kinds the module handles, with the Add-MpPreference parameter
// each stands for.
var exclusionKinds = map[string]string{
	"path":      "ExclusionPath",
	"process":   "ExclusionProcess",
	"extension": "ExclusionExtension",
	"asr_only":  "AttackSurfaceReductionOnlyExclusions",
}

// ExclusionKinds lists the kinds, in the order the panel shows them.
var ExclusionKinds = []string{"path", "process", "extension", "asr_only"}

// norm is the form paths are compared in: backslashes, no trailing one
// (except a drive root), lower case. It matches agent/defender.Norm.
func norm(p string) string {
	p = strings.ReplaceAll(strings.TrimSpace(p), "/", `\`)
	for len(p) > 3 && strings.HasSuffix(p, `\`) {
		p = p[:len(p)-1]
	}
	return strings.ToLower(p)
}

var (
	// ADR-0070 section 1: the five folders both agents work in. A folder
	// is "ours" only when it equals one exactly; a parent or a child of
	// one is a different value.
	oursFolder = regexp.MustCompile(`^[a-z]:\\(program files\\(easyrmm\\(agent|meshagent)|easypatch agent)|programdata\\(easyrmm\\agent|easypatch))$`)
	// ADR-0070 section 3: the three executables, by full path.
	oursExe = regexp.MustCompile(`^[a-z]:\\program files\\(easyrmm\\agent\\easyrmm-agent\.exe|easyrmm\\meshagent\\meshagent\.exe|easypatch agent\\easypatch\.agent\.exe)$`)
)

// Ours says whether a value of the given kind is one of the exclusions
// ADR-0070 adds (the server's own guard, on the fixed set; the script also
// reads both agents' records and expands variables and short names, which
// the server cannot).
func Ours(kind, value string) bool {
	v := norm(value)
	switch kind {
	case "path", "asr_only":
		return oursFolder.MatchString(v)
	case "process", "cfa_app":
		return oursExe.MatchString(v)
	}
	return false
}

var (
	deniedProcesses  = []string{"powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe", "msiexec.exe", "regsvr32.exe"}
	deniedExtensions = []string{"exe", "dll", "ps1", "psm1", "bat", "cmd", "vbs", "vbe", "js", "jse", "wsf", "wsh", "msi", "scr", "com", "hta", "lnk", "jar", "py"}
	// Folders whose exclusion is refused as too broad, compared whole.
	broadFolders = regexp.MustCompile(`^[a-z]:\\(windows|windows\\system32|program files|program files \(x86\)|programdata|users|temp)$`)
	userRoot     = regexp.MustCompile(`^[a-z]:\\users\\[^\\]+$`)
	extPattern   = regexp.MustCompile(`^[A-Za-z0-9]{1,10}$`)
	driveRoot    = regexp.MustCompile(`^[a-z]:\\?$`)
	uncRoot      = regexp.MustCompile(`^\\\\[^\\]+(\\[^\\]+)?$`)
)

func tooBroad(msg string) error {
	return &apperr.Error{Kind: apperr.KindInvalid, Code: "too_broad", Message: msg, Fields: map[string]string{"params.value": msg}}
}

// CheckExclusionValue applies ADR-0074's refusals to a value an administrator
// wants to add: nothing that stops scanning a drive, a system folder, a
// scripting host or a whole class of programs. An operator who needs one
// uses the script runner, which audits it as a script.
func CheckExclusionValue(kind, value string) error {
	if _, ok := exclusionKinds[kind]; !ok {
		return apperr.Invalid("params.kind", "Use path, process, extension or asr_only.")
	}
	v := norm(value)
	if kind == "extension" {
		e := strings.ToLower(strings.TrimPrefix(strings.TrimSpace(value), "."))
		if !extPattern.MatchString(e) {
			return apperr.Invalid("params.value", "An extension is 1 to 10 letters and digits.")
		}
		if slices.Contains(deniedExtensions, e) {
			return tooBroad("Excluding ." + e + " files would leave programs and scripts unscanned.")
		}
		return nil
	}
	if strings.ContainsAny(value, "*?") {
		return tooBroad("A wildcard in an exclusion is not allowed from the module.")
	}
	if driveRoot.MatchString(v) || uncRoot.MatchString(v) {
		return tooBroad("A drive or a whole share cannot be excluded.")
	}
	if broadFolders.MatchString(v) || userRoot.MatchString(v) {
		return tooBroad("This folder is too broad to exclude.")
	}
	if kind == "process" {
		if !strings.HasSuffix(v, ".exe") || !strings.Contains(v, `\`) {
			return apperr.Invalid("params.value", "A process exclusion is the full path to an .exe.")
		}
		base := v[strings.LastIndex(v, `\`)+1:]
		if slices.Contains(deniedProcesses, base) {
			return tooBroad("Excluding " + base + " would leave everything it runs unscanned.")
		}
	}
	return nil
}

// checkExclusionAdd is exclusion_add's Check.
func checkExclusionAdd(p map[string]any) error {
	kind, _ := p["kind"].(string)
	value, _ := p["value"].(string)
	return CheckExclusionValue(kind, value)
}

// checkExclusionRemove is exclusion_remove's Check: ours is never removed
// (the first of ADR-0074 section 5's three guards).
func checkExclusionRemove(p map[string]any) error {
	kind, _ := p["kind"].(string)
	value, _ := p["value"].(string)
	if _, ok := exclusionKinds[kind]; !ok {
		return apperr.Invalid("params.kind", "Use path, process, extension or asr_only.")
	}
	if Ours(kind, value) {
		return apperr.Conflict("protected_exclusion", "EasyRMM needs this exclusion so Defender does not block its own files; it cannot be removed here.")
	}
	return nil
}

// checkCFAApp is the Check of cfa_app_add and cfa_app_remove: an .exe by
// full path; never ours (adding ours is the agent's job, removing it would
// make Controlled Folder Access block the agents).
func checkCFAApp(p map[string]any) error {
	value, _ := p["path"].(string)
	if !strings.HasSuffix(strings.ToLower(value), ".exe") {
		return apperr.Invalid("params.path", "Use the full path to an .exe.")
	}
	if Ours("cfa_app", value) {
		return apperr.Conflict("protected_exclusion", "EasyRMM's own programs are allowed through Controlled Folder Access by the agents; this cannot be changed here.")
	}
	return nil
}
