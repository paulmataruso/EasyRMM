// Package library is the control library of ADR-0078: controls as data,
// written by EasyRMM. The Windows and Linux controls are generated from the
// settings lists of the hardening scripts (ADR-0054, ADR-0051), so each
// names a setting the script checks, and Validate proves it.
package library

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/paulmataruso/easyrmm/server/internal/compliance"
	"github.com/paulmataruso/easyrmm/server/internal/jobs"
)

// File is a controls file of the content package: one library pack.
type File struct {
	Library  Header               `json:"library"`
	Controls []compliance.Control `json:"controls"`
}

// Header names the library pack a file is.
type Header struct {
	Key          string           `json:"key"`
	Version      string           `json:"version"`
	Title        string           `json:"title"`
	LicenceClass compliance.Class `json:"licence_class"`
	SourceID     string           `json:"source_id"`
	ReviewState  string           `json:"review_state"`
}

// Parse reads a controls file, refusing unknown fields.
func Parse(b []byte) (File, error) {
	var f File
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		return File{}, err
	}
	return f, nil
}

var controlID = regexp.MustCompile(`^[a-z][a-z0-9.-]{2,95}$`)

const (
	authoredOn = "2026-11-26"
	author     = "EasyRMM"
)

type moduleInfo struct {
	severity string
	tier     string // Linux only; Windows tiers come from the script's list
}

var windowsModules = map[string]moduleInfo{
	"accounts": {severity: "medium"}, "firewall": {severity: "high"}, "defender": {severity: "high"},
	"asr": {severity: "medium"}, "smb": {severity: "high"}, "smb-signing": {severity: "medium"},
	"ntlm": {severity: "high"}, "wdigest": {severity: "high"}, "lsa-protection": {severity: "high"},
	"name-resolution": {severity: "medium"}, "powershell": {severity: "medium"}, "rdp": {severity: "high"},
	"uac": {severity: "medium"}, "autoplay": {severity: "low"}, "anonymous": {severity: "high"},
	"winrm": {severity: "medium"}, "printing": {severity: "medium"}, "features": {severity: "medium"},
	"tls": {severity: "high"}, "audit": {severity: "medium"}, "device-guard": {severity: "medium"},
	"bitlocker": {severity: "high"}, "laps": {severity: "high"},
	// ADR-0078, C3.
	"session": {severity: "medium"}, "removable": {severity: "medium"}, "mobile-code": {severity: "medium"},
	"rights": {severity: "medium"}, "time": {severity: "medium"}, "app-control": {severity: "high"},
	"office": {severity: "medium"},
}

var linuxModules = map[string]moduleInfo{
	"ssh": {"high", compliance.TierWorkflow}, "firewall": {"high", compliance.TierDangerous},
	"fail2ban": {"medium", compliance.TierWorkflow}, "kernel": {"medium", compliance.TierWorkflow},
	"audit": {"medium", compliance.TierReversible}, "permissions": {"medium", compliance.TierWorkflow},
	"services": {"medium", compliance.TierWorkflow}, "kernel-modules": {"medium", compliance.TierWorkflow},
	"sudo": {"medium", compliance.TierWorkflow}, "time": {"low", compliance.TierReversible},
	"shared-memory": {"medium", compliance.TierWorkflow}, "usb-storage": {"medium", compliance.TierWorkflow},
	"mac": {"high", compliance.TierDangerous}, "integrity": {"low", compliance.TierReversible},
	"lockout": {"medium", compliance.TierReport},
}

var windowsTiers = [...]string{compliance.TierReport, compliance.TierReversible, compliance.TierWorkflow, compliance.TierDangerous}

// reportOnlyAdvice is what to do about a Windows control that has no setting
// to change, in place of the general text (ADR-0078, C3).
var reportOnlyAdvice = map[string]string{
	"session-legal-caption":   "Write the title your organization's policy requires and set it in Group Policy (Interactive logon: message title for users attempting to log on). EasyRMM does not write the text for you.",
	"session-legal-text":      "Write the text your organization's policy requires and set it in Group Policy (Interactive logon: message text for users attempting to log on). EasyRMM does not write the text for you.",
	"rights-debug":            "Remove the accounts that should not hold this right in Group Policy (User Rights Assignment). A wrong change can lock people out, so EasyRMM only reports it.",
	"rights-take-ownership":   "Remove the accounts that should not hold this right in Group Policy (User Rights Assignment). EasyRMM only reports it.",
	"rights-load-driver":      "Remove the accounts that should not hold this right in Group Policy (User Rights Assignment). EasyRMM only reports it.",
	"rights-act-as-os":        "Remove every account from this right in Group Policy (User Rights Assignment). EasyRMM only reports it.",
	"rights-remote-logon":     "Narrow the groups allowed to sign in through Remote Desktop in Group Policy (User Rights Assignment). A wrong change can lock people out, so EasyRMM only reports it.",
	"rights-security-log":     "Remove the accounts that should not manage the auditing and security log in Group Policy (User Rights Assignment). EasyRMM only reports it.",
	"rights-audit-generate":   "Remove the accounts that should not generate security audits in Group Policy (User Rights Assignment). EasyRMM only reports it.",
	"rights-local-admins":     "Remove the accounts that do not need administrator rights from the local Administrators group, or manage the group with Restricted Groups or an account protection policy. EasyRMM only reports it.",
	"time-service-running":    "Start the Windows Time service and set it to start on its own, or run another time service on purpose and record it. EasyRMM only reports it.",
	"time-source-configured":  "Point the computer at a time source: the domain hierarchy on a domain member, or NTP servers on other computers. EasyRMM only reports it.",
	"time-synchronized":       "Find why the computer has not synchronized (a blocked UDP port 123, a stopped service or an unreachable source) and fix it. EasyRMM only reports it.",
	"app-control-enforced":    "Write an App Control for Business or AppLocker policy in audit mode first, review what it would block, then enforce it. EasyRMM only reports it.",
	"lockout-faillock-active": "Turn pam_faillock on with authselect (RHEL, Fedora) or pam-auth-update (Debian, Ubuntu). A wrong change to the sign-in stack can lock everyone out, so EasyRMM only reports it.",
	"lockout-deny-threshold":  "Set deny to a number from 1 to 10 in /etc/security/faillock.conf. EasyRMM only reports it.",
	"office-internet-macros":  "Block macros in files from the internet for each Office application (Group Policy, Office administrative templates). EasyRMM only reports it.",
}

// GenerateWindows builds the Windows library from windows-settings.json.
func GenerateWindows() File {
	f := File{Library: Header{Key: "library-windows", Version: "2026.1", Title: "Windows controls",
		LicenceClass: compliance.ClassOriginal, SourceID: "easyrmm-hardening", ReviewState: compliance.ReviewNone}}
	for _, s := range jobs.WindowsSettingCatalog() {
		tier := windowsTiers[s.Tier]
		rest := strings.TrimPrefix(s.ID, s.Module+"-")
		c := base("win."+s.Module+"."+rest, s, tier, compliance.PlatformWindows, windowsModules[s.Module].severity)
		scopes := []string{"any"}
		if s.Client {
			scopes = []string{"workstation"}
		} else if s.NotDomainController {
			scopes = []string{"workstation", "member_server"}
		}
		c.Scopes = scopes
		platform := map[string]any{"os": "windows"}
		if s.MinBuild > 0 {
			platform["min_build"] = s.MinBuild
		}
		c.Platforms = raw(platform)
		if t, ok := reportOnlyAdvice[s.ID]; ok {
			c.Remediation = t
		}
		c.NeedsRestart = s.Module == "lsa-protection" || s.Module == "device-guard" || s.ID == "session-fips"
		if s.Option != "" {
			c.Preconditions = []string{"option:" + s.Option}
		}
		if s.Cite != "" {
			c.Detect = raw(map[string]any{"summary": detectText(s), "stig_relation": s.Cite})
		}
		f.Controls = append(f.Controls, c)
	}
	return f
}

// GenerateLinux builds the Linux library from linux-settings.json.
func GenerateLinux() File {
	f := File{Library: Header{Key: "library-linux", Version: "2026.1", Title: "Linux controls",
		LicenceClass: compliance.ClassOriginal, SourceID: "easyrmm-hardening", ReviewState: compliance.ReviewNone}}
	for _, s := range jobs.LinuxSettingCatalog() {
		m := linuxModules[s.Module]
		rest := strings.TrimPrefix(s.ID, s.Module+"-")
		c := base("linux."+s.Module+"."+rest, s, m.tier, compliance.PlatformLinux, m.severity)
		if t, ok := reportOnlyAdvice[s.ID]; ok {
			c.Remediation = t
		}
		c.Scopes = []string{"any"}
		c.Platforms = raw(map[string]any{"os": "linux"})
		f.Controls = append(f.Controls, c)
	}
	return f
}

func detectText(s jobs.SettingInfo) string {
	return "Read by the EasyRMM Windows hardening check, module " + s.Module + ", setting " + s.ID + "."
}

func raw(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

// base fills what every generated control shares.
func base(id string, s jobs.SettingInfo, tier, platform, severity string) compliance.Control {
	apply := tier != compliance.TierReport
	ref := raw(compliance.HardeningRef{Platform: platform, Module: s.Module, Setting: s.ID})
	c := compliance.Control{
		ID: id, Version: 1, Title: s.What, Description: s.What + ".", Severity: severity,
		Executor: compliance.ExecHardening, ExecutorRef: ref,
		Detect:         raw(map[string]any{"summary": "Read by the EasyRMM " + platform + " hardening check, module " + s.Module + ", setting " + s.ID + "."}),
		Expected:       raw(map[string]any{"state": compliance.StateInPlace}),
		ApplySupported: apply, UndoKind: compliance.UndoNone, RiskTier: tier, Preconditions: []string{},
		Author: author, LicenceClass: compliance.ClassOriginal, ReviewState: compliance.ReviewNone,
		ApplyRef: json.RawMessage("null"), UndoRef: json.RawMessage("null"),
		Remediation: "Make this true: " + s.What + ". The hardening page applies it for you and can put the old value back.",
		Provenance: compliance.Provenance{
			Author: author, AuthoredOn: authoredOn,
			Method:   "written from vendor documentation and observed behavior of the setting; the check is EasyRMM's own hardening script",
			Sources:  []compliance.Locate{{SourceID: "easyrmm-hardening", Locator: platform + " hardening setting " + s.ID}},
			Reviewer: "pending second-person review", LicenceClass: compliance.ClassOriginal,
		},
	}
	if apply {
		c.UndoKind = compliance.UndoRestore
		c.WarningID = "warn." + strings.ToLower(tier) + ".v1"
		job := func(mode string) json.RawMessage {
			m := map[string]any{"kind": "hardening", "mode": mode, "platform": platform, "modules": []string{s.Module}}
			if platform == compliance.PlatformWindows {
				m["settings"] = []string{s.ID}
			}
			return raw(m)
		}
		c.ApplyRef, c.UndoRef = job("apply"), job("undo")
	} else {
		c.Remediation = "There is no setting to change for this: " + s.What + ". Check it by hand and record what you found."
	}
	return c
}

// Index maps control ids to controls.
type Index map[string]compliance.Control

// Build merges library files into an index, refusing a repeated id.
func Build(files ...File) (Index, error) {
	idx := Index{}
	for _, f := range files {
		for _, c := range f.Controls {
			if _, dup := idx[c.ID]; dup {
				return nil, fmt.Errorf("library: control %s is in two files", c.ID)
			}
			idx[c.ID] = c
		}
	}
	return idx, nil
}

// Validate checks a library file: each control is well formed and names a
// real check. For a hardening control that is a setting in the scripts'
// own lists, in the module it says.
func Validate(f File) []error {
	var errs []error
	add := func(c compliance.Control, format string, a ...any) {
		errs = append(errs, fmt.Errorf("control %s: %s", c.ID, fmt.Sprintf(format, a...)))
	}
	win := catalog(jobs.WindowsSettingCatalog())
	lin := catalog(jobs.LinuxSettingCatalog())
	seen := map[string]bool{}
	if !f.Library.LicenceClass.Valid() {
		errs = append(errs, fmt.Errorf("library %s: unknown licence class %q", f.Library.Key, f.Library.LicenceClass))
	}
	for _, c := range f.Controls {
		switch {
		case !controlID.MatchString(c.ID):
			add(c, "not a valid id")
		case seen[c.ID]:
			add(c, "listed twice")
		}
		seen[c.ID] = true
		if c.Version < 1 {
			add(c, "version below 1")
		}
		if !slices.Contains([]string{"info", "low", "medium", "high", "critical"}, c.Severity) {
			add(c, "unknown severity %q", c.Severity)
		}
		if !slices.Contains([]string{compliance.TierReport, compliance.TierReversible, compliance.TierWorkflow, compliance.TierDangerous}, c.RiskTier) {
			add(c, "unknown risk tier %q", c.RiskTier)
		}
		if !c.LicenceClass.Valid() || c.ReviewState != compliance.ReviewNone && c.ReviewState != compliance.ReviewNeeded {
			add(c, "licence class or review state not valid")
		}
		if c.LicenceClass.Rank() > f.Library.LicenceClass.Rank() {
			add(c, "licence class %s is more restrictive than its library's %s", c.LicenceClass, f.Library.LicenceClass)
		}
		if c.Provenance.DerivedFromContent || c.Provenance.Author == "" || c.Author == "" || c.Provenance.LicenceClass != c.LicenceClass {
			add(c, "provenance must name the author, assert derived_from_content false and repeat the licence class")
		}
		if c.ApplySupported && (c.WarningID == "") {
			add(c, "a fix needs a warning id")
		}
		if c.RiskTier == compliance.TierReport && c.ApplySupported {
			add(c, "a report-only control has no fix")
		}
		if c.RiskTier != compliance.TierReport && !c.ApplySupported && c.Remediation == "" {
			add(c, "no fix and no manual text")
		}
		if c.ApplySupported && (isNull(c.ApplyRef) || isNull(c.UndoRef) && c.UndoKind != compliance.UndoNone) {
			add(c, "a fix needs an apply reference, and an undo reference unless there is no undo")
		}
		if !c.ApplySupported && !isNull(c.ApplyRef) {
			add(c, "an apply reference without a fix")
		}
		if c.Executor != compliance.ExecHardening {
			continue
		}
		var ref compliance.HardeningRef
		if err := json.Unmarshal(c.ExecutorRef, &ref); err != nil {
			add(c, "executor_ref is not a hardening reference")
			continue
		}
		cat := win
		prefix := "win."
		if ref.Platform == compliance.PlatformLinux {
			cat, prefix = lin, "linux."
		} else if ref.Platform != compliance.PlatformWindows {
			add(c, "unknown platform %q", ref.Platform)
			continue
		}
		module, ok := cat[ref.Setting]
		switch {
		case !ok:
			add(c, "names setting %q, which no hardening check reads", ref.Setting)
		case module != ref.Module:
			add(c, "setting %q is in module %q, not %q", ref.Setting, module, ref.Module)
		case !strings.HasPrefix(c.ID, prefix+ref.Module+"."):
			add(c, "id does not start with %s%s.", prefix, ref.Module)
		}
	}
	return errs
}

func isNull(b json.RawMessage) bool { return len(b) == 0 || string(b) == "null" }

func catalog(l []jobs.SettingInfo) map[string]string {
	m := make(map[string]string, len(l))
	for _, s := range l {
		m[s.ID] = s.Module
	}
	return m
}
