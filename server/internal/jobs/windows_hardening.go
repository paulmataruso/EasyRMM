package jobs

import (
	"bytes"
	_ "embed" // the Windows script and its settings
	"encoding/json"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/paulmataruso/easyrmm/internal/winpolicy"
	"github.com/paulmataruso/easyrmm/server/internal/apperr"
)

// Hardening Windows computers and servers (ADR-0054): the same job kind,
// API and tables as Linux (ADR-0051), with Windows' own script, modules,
// options and result fields. This release checks only.

// Platforms a hardening job is for. A job names the modules of one.
const (
	HardeningLinux   = "linux"
	HardeningWindows = "windows"
)

// WindowsHardeningModules are Windows' modules, in the order the script
// runs them and the console lists them. The last four only report.
var WindowsHardeningModules = []string{
	"accounts", "firewall", "defender", "asr", "smb", "smb-signing", "ntlm", "wdigest", "lsa-protection",
	"name-resolution", "powershell", "rdp", "uac", "autoplay", "anonymous", "winrm", "printing", "features", "tls",
	"audit", "device-guard", "bitlocker", "laps",
}

// WindowsHardeningOptions are Windows' options besides the ports
// (HardeningOptions' AllowTCP and AllowUDP, for the firewall). Each applies
// to one module, except DomainController, which applies to the job.
type WindowsHardeningOptions struct {
	PortsChecked           bool     `json:"portsChecked,omitempty"`
	FirewallServer         bool     `json:"firewallServer,omitempty"`
	DomainController       bool     `json:"domainController,omitempty"`
	DefenderServerRealtime bool     `json:"defenderServerRealtime,omitempty"`
	SmartScreenBlock       bool     `json:"smartScreenBlock,omitempty"`
	CloudBlockHigh         bool     `json:"cloudBlockHigh,omitempty"`
	ASRBlock               []string `json:"asrBlock,omitempty"`
	LSAUEFILock            bool     `json:"lsaUefiLock,omitempty"`
	LSAUnaudited           bool     `json:"lsaUnaudited,omitempty"`
	LockoutExposed         bool     `json:"lockoutExposed,omitempty"`
	UACEnable              bool     `json:"uacEnable,omitempty"`
	UACBuiltinAdmin        bool     `json:"uacBuiltinAdmin,omitempty"`
	DenyUserElevation      bool     `json:"denyUserElevation,omitempty"`
	WinRMBasicOff          bool     `json:"winrmBasicOff,omitempty"`
	SpoolerOff             bool     `json:"spoolerOff,omitempty"`
}

// windowsSwitch is an option without a value: its argument, its module
// ("" for the whole job), and where the job's options hold it.
type windowsSwitch struct {
	arg, module, field string
	on                 func(*HardeningOptions) bool
}

var windowsSwitches = []windowsSwitch{
	{"ports-checked", "firewall", "portsChecked", func(o *HardeningOptions) bool { return o.PortsChecked }},
	{"firewall-server", "firewall", "firewallServer", func(o *HardeningOptions) bool { return o.FirewallServer }},
	{"domain-controller", "", "domainController", func(o *HardeningOptions) bool { return o.DomainController }},
	{"defender-server-realtime", "defender", "defenderServerRealtime", func(o *HardeningOptions) bool { return o.DefenderServerRealtime }},
	{"smartscreen-block", "defender", "smartScreenBlock", func(o *HardeningOptions) bool { return o.SmartScreenBlock }},
	{"cloud-block-high", "defender", "cloudBlockHigh", func(o *HardeningOptions) bool { return o.CloudBlockHigh }},
	{"lsa-uefi-lock", "lsa-protection", "lsaUefiLock", func(o *HardeningOptions) bool { return o.LSAUEFILock }},
	{"lsa-unaudited", "lsa-protection", "lsaUnaudited", func(o *HardeningOptions) bool { return o.LSAUnaudited }},
	{"lockout-exposed", "accounts", "lockoutExposed", func(o *HardeningOptions) bool { return o.LockoutExposed }},
	{"uac-enable", "uac", "uacEnable", func(o *HardeningOptions) bool { return o.UACEnable }},
	{"uac-builtin-admin", "uac", "uacBuiltinAdmin", func(o *HardeningOptions) bool { return o.UACBuiltinAdmin }},
	{"deny-user-elevation", "uac", "denyUserElevation", func(o *HardeningOptions) bool { return o.DenyUserElevation }},
	{"winrm-basic-off", "winrm", "winrmBasicOff", func(o *HardeningOptions) bool { return o.WinRMBasicOff }},
	{"spooler-off", "printing", "spoolerOff", func(o *HardeningOptions) bool { return o.SpoolerOff }},
}

// platform is the job's platform; jobs made before Windows have none and
// are Linux's.
func (h Hardening) platform() string {
	if h.Platform == "" {
		return HardeningLinux
	}
	return h.Platform
}

// modules are the platform's modules.
func (h Hardening) modules() []string {
	if h.platform() == HardeningWindows {
		return WindowsHardeningModules
	}
	return HardeningModules
}

// validate checks a request for either platform. A Linux job keeps no
// platform, so that its stored form is as before Windows.
func (h *Hardening) validate(f apperr.Fields) {
	switch h.Platform {
	case "", HardeningLinux:
		h.Platform = ""
		h.check(f)
		f.Check(!h.Options.anyWindows(), "options", "These options are for Windows.")
	case HardeningWindows:
		h.checkWindows(f)
	default:
		f.Add("platform", "Choose linux or windows.")
	}
}

// anyWindows reports whether any of Windows' options is set.
func (o WindowsHardeningOptions) anyWindows() bool {
	return o.ASRBlock != nil || o.PortsChecked || o.FirewallServer || o.DomainController ||
		o.DefenderServerRealtime || o.SmartScreenBlock || o.CloudBlockHigh || o.LSAUEFILock || o.LSAUnaudited ||
		o.LockoutExposed || o.UACEnable || o.UACBuiltinAdmin || o.DenyUserElevation || o.WinRMBasicOff || o.SpoolerOff
}

// checkWindows validates a Windows request and puts its modules and
// options in their canonical form.
func (h *Hardening) checkWindows(f apperr.Fields) {
	f.Check(h.Mode == HardeningCheck, "mode", "Choose check.")
	chosen := map[string]bool{}
	for _, m := range h.Modules {
		if !slices.Contains(WindowsHardeningModules, m) {
			f.Add("modules", fmt.Sprintf("There is no Windows hardening module %q.", truncateRunes(m, 40)))
			return
		}
		chosen[m] = true
	}
	if len(chosen) == 0 {
		f.Add("modules", "Choose at least one module.")
		return
	}
	h.Modules = slices.DeleteFunc(slices.Clone(WindowsHardeningModules), func(m string) bool { return !chosen[m] })
	o := &h.Options
	f.Check(len(o.Trusted) == 0 && !o.RootPasswordOff && !o.PasswordOff && !o.EPEL, "options", "These options are for Linux.")
	var bad bool
	if o.AllowTCP, bad = ports(o.AllowTCP); bad {
		f.Add("options.allowTcp", "Enter ports from 1 to 65535, or ranges such as 9000-9100, at most 64.")
	}
	if o.AllowUDP, bad = ports(o.AllowUDP); bad {
		f.Add("options.allowUdp", "Enter ports from 1 to 65535, or ranges such as 9000-9100, at most 64.")
	}
	if o.ASRBlock, bad = asrRules(o.ASRBlock); bad {
		f.Add("options.asrBlock", "Choose attack surface reduction rules from the list that may be blocked.")
	}
	needs := func(set bool, field, module string) {
		f.Check(!set || chosen[module], field, "This option applies to "+module+"; choose that module too.")
	}
	needs(len(o.AllowTCP) > 0, "options.allowTcp", "firewall")
	needs(len(o.AllowUDP) > 0, "options.allowUdp", "firewall")
	needs(len(o.ASRBlock) > 0, "options.asrBlock", "asr")
	for _, s := range windowsSwitches {
		if s.module != "" {
			needs(s.on(o), "options."+s.field, s.module)
		}
	}
}

// ASRBlockable are the attack surface reduction rules that the asr module
// audits and asr-block may block instead: every rule it audits, except
// process creations from PSExec and WMI, which it never blocks (ADR-0054).
var ASRBlockable = []string{
	"01443614-cd74-433a-b99e-2ecdc07bfc25", "c1db55ab-c21a-4637-bb3f-a12568109d35",
	"7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c", "d4f940ab-401b-4efc-aadc-ad5f3c50688a",
	"be9ba2d9-53ea-4cdc-84e5-9b1eeee46550", "5beb7efe-fd9a-4556-801d-275e5ffc04cc",
	"d3e037e1-3eb8-44c8-a917-57927947596d", "3b576869-a4ec-4529-8536-b80a7769e899",
	"75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84", "26190899-1602-49e8-8b27-eb1d0a1ce869",
	"b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4", "92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b",
}

// asrRules checks and normalizes asr-block's rules: lower case, each once,
// in ASRBlockable's order.
func asrRules(in []string) (out []string, bad bool) {
	if len(in) > len(ASRBlockable) {
		return nil, true
	}
	chosen := map[string]bool{}
	for _, r := range in {
		r = strings.ToLower(strings.TrimSpace(r))
		if !slices.Contains(ASRBlockable, r) {
			return nil, true
		}
		chosen[r] = true
	}
	for _, r := range ASRBlockable {
		if chosen[r] {
			out = append(out, r)
		}
	}
	return out, false
}

// windowsArgs are the Windows script's arguments: the mode, the modules,
// the lists, then each switch.
func (h Hardening) windowsArgs() []string {
	a := []string{h.Mode, strings.Join(h.Modules, ",")}
	for _, l := range []struct {
		name string
		v    []string
	}{{"allow-tcp", h.Options.AllowTCP}, {"allow-udp", h.Options.AllowUDP}, {"asr-block", h.Options.ASRBlock}} {
		if len(l.v) > 0 {
			a = append(a, l.name+"="+strings.Join(l.v, ","))
		}
	}
	for _, s := range windowsSwitches {
		if s.on(&h.Options) {
			a = append(a, s.arg)
		}
	}
	return a
}

// windowsLabel names a Windows job for job lists.
func (h Hardening) windowsLabel() string {
	if len(h.Modules) == len(WindowsHardeningModules) {
		return "Check Windows hardening (every module)"
	}
	return "Check Windows hardening: " + strings.Join(h.Modules, ", ")
}

//go:embed hardening/windows.ps1
var windowsHardeningSource string

//go:embed hardening/windows-settings.json
var windowsSettingsJSON []byte

// windowsIncludeLine is where the server puts the ownership reader, the
// settings and the audit table into the script.
const windowsIncludeLine = "#EASYRMM-INCLUDE"

// windowsHardeningScript is the script a Windows job runs: windows.ps1
// with internal/winpolicy's reader, the settings and ADR-0060's audit table
// in place of its include line, as here-strings it reads as JSON.
var windowsHardeningScript = buildWindowsScript(windowsHardeningSource, winpolicy.Reader())

// buildWindowsScript puts the include in place. A checkout has the .ps1
// files with CRLF line ends (.gitattributes) and a build from an archive
// may have LF: the script keeps whichever its source has, everywhere.
func buildWindowsScript(source, reader string) string {
	nl := "\n"
	if strings.Contains(source, "\r\n") {
		nl = "\r\n"
	}
	lf := func(s string) string { return strings.ReplaceAll(strings.ReplaceAll(s, "\r\n", "\n"), "\n", nl) }
	var settings bytes.Buffer
	if err := json.Compact(&settings, windowsSettingsJSON); err != nil {
		panic("jobs: windows-settings.json: " + err.Error())
	}
	include := lf(reader) + nl +
		"$ErSettingsJson = @'" + nl + settings.String() + nl + "'@" + nl +
		"$ErAuditTableJson = @'" + nl + winpolicy.AuditJSON() + nl + "'@" + nl
	line := windowsIncludeLine + nl
	if strings.Count(source, line) != 1 {
		panic("jobs: windows.ps1 must have one include line")
	}
	return strings.Replace(source, line, include, 1)
}

// windowsSetting is a row of windows-settings.json: one setting the
// script checks. The fields after Kind say how it reads the value and
// what it wants; the server uses the ID, module and citation.
type windowsSetting struct {
	ID     string `json:"id"`
	Module string `json:"module"`
	What   string `json:"what"`
	// Kind is how the script reads it: registry, secedit, smb, feature,
	// firewall, defender, smartscreen, asr, winrm, schannel, or custom (by
	// ID).
	Kind       string            `json:"kind"`
	Key        string            `json:"key,omitempty"`
	Path       string            `json:"path,omitempty"`
	Name       string            `json:"name,omitempty"`
	Profile    string            `json:"profile,omitempty"`
	Side       string            `json:"side,omitempty"`
	Property   string            `json:"property,omitempty"`
	Feature    map[string]string `json:"feature,omitempty"`
	Rule       string            `json:"rule,omitempty"`
	LocalPath  string            `json:"localPath,omitempty"`
	LocalName  string            `json:"localName,omitempty"`
	Default    *int              `json:"default,omitempty"`
	Want       string            `json:"want,omitempty"`
	Data       json.RawMessage   `json:"data,omitempty"`
	Max        *int              `json:"max,omitempty"`
	OrEq       *int              `json:"orEq,omitempty"`
	Absent     string            `json:"absent,omitempty"`
	Block      bool              `json:"block,omitempty"`
	Option     string            `json:"option,omitempty"`
	OptionData json.RawMessage   `json:"optionData,omitempty"`
	Tamper     bool              `json:"tamper,omitempty"`
	Only       *struct {
		Client   *bool    `json:"client,omitempty"`
		NotRoles []string `json:"notRoles,omitempty"`
		MinBuild int      `json:"minBuild,omitempty"`
	} `json:"only,omitempty"`
	// CSP is the Policy CSP's Area/Policy that sets the same value, read
	// while the computer is enrolled in an MDM.
	CSP string `json:"csp,omitempty"`
	// Cite is how the setting stands against its rules: meets (or empty),
	// differs (on purpose) or not_set (reported only, unless its option is
	// given).
	Cite string `json:"cite,omitempty"`
}

var windowsSettings = mustWindowsSettings(windowsSettingsJSON)

func mustWindowsSettings(b []byte) []windowsSetting {
	s, err := parseWindowsSettings(b)
	if err != nil {
		panic("jobs: windows-settings.json: " + err.Error())
	}
	return s
}

// The kinds of setting the script knows.
var windowsSettingKinds = []string{
	"registry", "secedit", "smb", "feature", "firewall", "defender", "smartscreen", "asr", "winrm", "schannel", "custom",
}

var settingID = regexp.MustCompile(`^[a-z][a-z0-9-]{0,63}$`)

// parseWindowsSettings reads the settings and checks what the server and
// the script rely on: known modules, kinds and citations, each ID once and
// prefixed with its module, options that exist and belong to the module.
func parseWindowsSettings(b []byte) ([]windowsSetting, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var file struct {
		Version  int              `json:"version"`
		Settings []windowsSetting `json:"settings"`
	}
	if err := dec.Decode(&file); err != nil {
		return nil, err
	}
	if file.Version != 1 || len(file.Settings) == 0 {
		return nil, fmt.Errorf("version 1 with settings expected")
	}
	seen := map[string]bool{}
	for _, s := range file.Settings {
		opt := -1
		for i, w := range windowsSwitches {
			if w.arg == s.Option {
				opt = i
			}
		}
		switch {
		case !settingID.MatchString(s.ID) || seen[s.ID]:
			return nil, fmt.Errorf("%q: not an ID, or listed twice", s.ID)
		case !slices.Contains(WindowsHardeningModules, s.Module) || !strings.HasPrefix(s.ID, s.Module+"-"):
			return nil, fmt.Errorf("%s: unknown module %q, or the ID does not start with it", s.ID, s.Module)
		case !slices.Contains(windowsSettingKinds, s.Kind):
			return nil, fmt.Errorf("%s: unknown kind %q", s.ID, s.Kind)
		case !slices.Contains([]string{"", "meets", "differs", "not_set"}, s.Cite):
			return nil, fmt.Errorf("%s: unknown citation %q", s.ID, s.Cite)
		case s.What == "" || !shortText(s.What, 120):
			return nil, fmt.Errorf("%s: no description", s.ID)
		case s.Option != "" && (opt < 0 || windowsSwitches[opt].module != s.Module):
			return nil, fmt.Errorf("%s: option %q is not one of its module's", s.ID, s.Option)
		case s.Kind == "asr" && !slices.Contains(ASRBlockable, s.Rule) && !s.Block && s.Rule != asrPSExec:
			return nil, fmt.Errorf("%s: rule %q is neither blocked nor blockable", s.ID, s.Rule)
		}
		seen[s.ID] = true
	}
	return file.Settings, nil
}

// asrPSExec is the rule the module audits and never blocks.
const asrPSExec = "d1e49aac-8f56-4280-b9ba-993a6d77406c"

// HardeningWindowsPlatform is what a Windows result adds to the platform.
type HardeningWindowsPlatform struct {
	Build            int    `json:"build"`
	UBR              int    `json:"ubr"`
	DisplayVersion   string `json:"displayVersion"`
	Edition          string `json:"edition"`
	InstallationType string `json:"installationType"`
	// Role is workstation, member_server, standalone_server or
	// domain_controller.
	Role string `json:"role"`
	// Joined is none, domain, entra or domain_entra.
	Joined       string `json:"joined"`
	MDM          bool   `json:"mdm"`
	Architecture string `json:"architecture"`
	// LanguageMode is PowerShell's; anything but FullLanguage stops the
	// script, and the result then has no more than the fields above.
	LanguageMode string `json:"languageMode"`
	// Owners are the owners the ownership reader found on the computer.
	Owners *HardeningOwners `json:"owners,omitempty"`
	// CheckOnlyReasons are the reasons apply would be check only here
	// (winpolicy's Reasons).
	CheckOnlyReasons []string `json:"checkOnlyReasons,omitempty"`
	Notes            []string `json:"notes,omitempty"`
	// Hardening is the Hardening folder as the script found it.
	Hardening *HardeningFolder `json:"hardening,omitempty"`
}

// HardeningOwners are the owners found on a Windows computer.
type HardeningOwners struct {
	// GroupPolicyRecord is read, off (turned off by policy) or unread.
	GroupPolicyRecord         string `json:"groupPolicyRecord"`
	GroupPolicyPreferences    bool   `json:"groupPolicyPreferences"`
	MDM                       bool   `json:"mdm"`
	MDMWinsOverGP             bool   `json:"mdmWinsOverGp"`
	DefenderForEndpoint       bool   `json:"defenderForEndpoint"`
	ConfigMgr                 bool   `json:"configMgr"`
	DSC                       bool   `json:"dsc"`
	AzureMachineConfiguration bool   `json:"azureMachineConfiguration"`
	// OSConfig are OSConfig's active scenarios, where its module is
	// installed.
	OSConfig        []string `json:"osConfig"`
	TamperProtected bool     `json:"tamperProtected"`
}

// HardeningFolder is %ProgramData%\EasyRMM\Hardening as a run found it.
type HardeningFolder struct {
	// Folder is absent, present or refused.
	Folder string `json:"folder"`
	// CopySha256 is the hash of the script's copy, where there is one.
	CopySha256 string   `json:"copySha256"`
	Warnings   []string `json:"warnings"`
	// SetAside are the paths files that failed the check were moved to.
	SetAside []string `json:"setAside"`
}

// WindowsFinding is what a Windows module's check adds to its finding.
type WindowsFinding struct {
	Settings []HardeningSetting `json:"settings,omitempty"`
	// Managed are the settings another owner holds, with the owner and its
	// value (ADR-0054, Managed elsewhere).
	Managed []HardeningManaged `json:"managed,omitempty"`
	Notes   []string           `json:"notes,omitempty"`
	// SettingsOmitted is in_place or all when the result had to leave
	// settings out to stay within its limit.
	SettingsOmitted string             `json:"settingsOmitted,omitempty"`
	Exposure        *HardeningExposure `json:"exposure,omitempty"`
}

// HardeningSetting is one setting as the check found it.
type HardeningSetting struct {
	ID string `json:"id"`
	// Item is the subcategory, log or rule a setting of several covers.
	Item string `json:"item,omitempty"`
	// State is in_place, not_in_place (apply would change it),
	// managed_elsewhere, check_only (an owner the reader cannot read may
	// hold it), not_applicable, reported (never changed), or unknown.
	State   string        `json:"state"`
	Value   string        `json:"value,omitempty"`
	Want    string        `json:"want,omitempty"`
	Note    string        `json:"note,omitempty"`
	Reasons []string      `json:"reasons,omitempty"`
	MDM     *HardeningMDM `json:"mdm,omitempty"`
}

// HardeningMDM is what the MDM reader found for a setting's CSP policy.
type HardeningMDM struct {
	CSP      string `json:"csp"`
	Config   string `json:"config"`
	Current  string `json:"current"`
	Provider string `json:"provider"`
}

// HardeningManaged is a setting another owner holds.
type HardeningManaged struct {
	// ID is the setting's, or the module's for another antivirus or
	// firewall.
	ID     string `json:"id"`
	Item   string `json:"item,omitempty"`
	Owner  string `json:"owner"`
	Policy string `json:"policy"`
	Value  string `json:"value"`
	// State is in_place (the owner's value is as strict as EasyRMM's) or
	// managed_elsewhere.
	State string `json:"state"`
}

// HardeningExposure is what the accounts module found in the Security
// log: failed sign-ins from public addresses.
type HardeningExposure struct {
	Exposed   bool     `json:"exposed"`
	Accounts  []string `json:"accounts"`
	Addresses []string `json:"addresses"`
	Since     string   `json:"since"`
}

var settingStates = []string{
	"in_place", "not_in_place", "managed_elsewhere", "check_only", "not_applicable", "reported", "unknown",
}

const (
	maxSettings      = 100
	maxSettingText   = 120
	maxExposureItems = 10
)

var sha256Hex = regexp.MustCompile(`^[0-9a-f]{64}$`)

// validWindowsPlatform checks the Windows platform of a result.
func validWindowsPlatform(p HardeningPlatform) bool {
	w := p.Windows
	if w == nil || p.ID != "windows" || p.Container != "none" || !shortText(p.VersionID, 64) {
		return false
	}
	ok := w.Build >= 0 && w.UBR >= 0 && shortText(w.DisplayVersion, 32) && shortText(w.Edition, 64) &&
		shortText(w.InstallationType, 32) && shortText(w.Architecture, 16) &&
		slices.Contains([]string{"workstation", "member_server", "standalone_server", "domain_controller"}, w.Role) &&
		slices.Contains([]string{"none", "domain", "entra", "domain_entra"}, w.Joined) &&
		slices.Contains([]string{"FullLanguage", "ConstrainedLanguage", "RestrictedLanguage", "NoLanguage"}, w.LanguageMode) &&
		validTexts(w.Notes, maxFindingText) && len(w.CheckOnlyReasons) <= len(winpolicy.Reasons)
	for _, r := range w.CheckOnlyReasons {
		ok = ok && slices.Contains(winpolicy.Reasons, r)
	}
	if o := w.Owners; o != nil {
		ok = ok && slices.Contains([]string{"read", "off", "unread"}, o.GroupPolicyRecord) && validTexts(o.OSConfig, 128)
	}
	if f := w.Hardening; f != nil {
		ok = ok && slices.Contains([]string{"absent", "present", "refused"}, f.Folder) &&
			(f.CopySha256 == "" || sha256Hex.MatchString(f.CopySha256)) &&
			validTexts(f.Warnings, maxFindingText) && validTexts(f.SetAside, maxFindingText)
	}
	return ok
}

// validTexts is a list of at most maxFindingItems short texts.
func validTexts(l []string, n int) bool {
	if len(l) > maxFindingItems {
		return false
	}
	for _, s := range l {
		if s == "" || !shortText(s, n) {
			return false
		}
	}
	return true
}

// validWindows checks a Windows module's finding: settings of that module
// in known states, owners and reasons from winpolicy, text within limits.
func (f WindowsFinding) validWindows(module string) bool {
	if len(f.Settings) > maxSettings || len(f.Managed) > maxSettings || !validTexts(f.Notes, maxFindingText) ||
		!slices.Contains([]string{"", "in_place", "all"}, f.SettingsOmitted) {
		return false
	}
	known := func(id string) bool {
		i := slices.IndexFunc(windowsSettings, func(s windowsSetting) bool { return s.ID == id })
		return i >= 0 && windowsSettings[i].Module == module
	}
	for _, s := range f.Settings {
		if !known(s.ID) || !slices.Contains(settingStates, s.State) || !shortText(s.Item, 64) ||
			!shortText(s.Value, maxSettingText) || !shortText(s.Want, maxSettingText) || !shortText(s.Note, maxFindingText) ||
			len(s.Reasons) > len(winpolicy.Reasons) {
			return false
		}
		for _, r := range s.Reasons {
			if !slices.Contains(winpolicy.Reasons, r) {
				return false
			}
		}
		if m := s.MDM; m != nil && (!shortText(m.CSP, maxSettingText) || !shortText(m.Config, 80) ||
			!shortText(m.Current, 80) || !shortText(m.Provider, 80)) {
			return false
		}
	}
	for _, m := range f.Managed {
		if (!known(m.ID) && m.ID != module) || !slices.Contains(winpolicy.Owners, m.Owner) ||
			!slices.Contains([]string{"in_place", "managed_elsewhere"}, m.State) || !shortText(m.Item, 64) ||
			!shortText(m.Policy, maxSettingText) || !shortText(m.Value, maxSettingText) {
			return false
		}
	}
	if e := f.Exposure; e != nil {
		if module != "accounts" || len(e.Accounts) > maxExposureItems || len(e.Addresses) > maxExposureItems ||
			!validTexts(e.Accounts, 64) {
			return false
		}
		if _, err := time.Parse(time.RFC3339Nano, e.Since); err != nil {
			return false
		}
		for _, a := range e.Addresses {
			if _, err := netip.ParseAddr(a); err != nil {
				return false
			}
		}
	}
	return true
}

// hasWindowsFields reports whether a finding has any of Windows' fields,
// which Linux's never have.
func (f WindowsFinding) hasWindowsFields() bool {
	return f.Settings != nil || f.Managed != nil || f.Notes != nil || f.SettingsOmitted != "" || f.Exposure != nil
}
