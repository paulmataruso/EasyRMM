// Package registryrules is the one set of rules the registry editor's
// server and agent share (ADR-0067): how a path is written and parsed, the
// paths that are refused, and the values that are masked. It is compiled into
// both, so that the two checks cannot read a path differently. A server and
// an agent of different releases may carry different rules; a result names
// the Version it used.
package registryrules

import (
	"errors"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf16"
	"unicode/utf8"
)

// Version is the version of these rules, carried by every result.
const Version = 1

// Hive is a root of the registry as the editor's input names it.
type Hive string

// The hives of an input. HKCU is not one: it asks which user, and becomes
// an HKU path before it reaches an input.
const (
	HKLM Hive = "HKLM"
	HKU  Hive = "HKU"
	HKCR Hive = "HKCR"
	HKCC Hive = "HKCC"
)

// View is the registry view: the 64-bit one, or the 32-bit (x86) one.
type View string

// The two views.
const (
	View64 View = "64"
	View32 View = "32"
)

// Limits of names and paths.
const (
	MaxNameChars      = 255
	MaxPathChars      = 2048
	MaxLevels         = 512
	MaxValueNameChars = 16383
)

// Errors of paths.
var (
	// ErrCurrentUser is a text path under HKEY_CURRENT_USER: it needs to know
	// which user.
	ErrCurrentUser = errors.New("registryrules: HKEY_CURRENT_USER needs a user; choose one of the loaded hives")
	// ErrPath is a path that cannot be read.
	ErrPath = errors.New("registryrules: not a registry path")
)

// Valid reports whether h is a hive an input may name.
func (h Hive) Valid() bool { return h == HKLM || h == HKU || h == HKCR || h == HKCC }

// Valid reports whether v is a view.
func (v View) Valid() bool { return v == View64 || v == View32 }

// utf16Len is the length of s in UTF-16 code units, which is how Windows
// counts the characters of a name.
func utf16Len(s string) int {
	n := 0
	for _, r := range s {
		n += len(utf16.Encode([]rune{r}))
	}
	return n
}

// ValidateName checks one key name: not empty, not "." or "..", at most 255
// characters, no backslash, NUL or other control character, valid text.
func ValidateName(name string) error {
	switch {
	case name == "":
		return fmt.Errorf("%w: a key name is empty", ErrPath)
	case name == "." || name == "..":
		return fmt.Errorf("%w: %q is not a key name", ErrPath, name)
	case !utf8.ValidString(name):
		return fmt.Errorf("%w: a key name is not valid text", ErrPath)
	case utf16Len(name) > MaxNameChars:
		return fmt.Errorf("%w: a key name is longer than %d characters", ErrPath, MaxNameChars)
	}
	for _, r := range name {
		if r == '\\' || unicode.IsControl(r) {
			return fmt.Errorf("%w: a key name holds a backslash or a control character", ErrPath)
		}
	}
	return nil
}

// ValidateNames checks a path under a hive: each name, at most 512 levels
// and 2,048 characters.
func ValidateNames(names []string) error {
	if len(names) > MaxLevels {
		return fmt.Errorf("%w: more than %d levels", ErrPath, MaxLevels)
	}
	total := 0
	for _, n := range names {
		if err := ValidateName(n); err != nil {
			return err
		}
		total += utf16Len(n) + 1
	}
	if total > MaxPathChars {
		return fmt.Errorf("%w: longer than %d characters", ErrPath, MaxPathChars)
	}
	return nil
}

// ValidateValueName checks a value name: valid text without NUL, at most
// 16,383 characters. The empty name is the default value.
func ValidateValueName(name string) error {
	if !utf8.ValidString(name) || strings.ContainsRune(name, 0) {
		return fmt.Errorf("%w: a value name is not valid text", ErrPath)
	}
	if utf16Len(name) > MaxValueNameChars {
		return fmt.Errorf("%w: a value name is longer than %d characters", ErrPath, MaxValueNameChars)
	}
	return nil
}

// Fold maps each character to the smallest of those Unicode's simple case
// mappings make it equal to, so that the long s, the dotless i and the
// Kelvin sign match S, I and K. It may make two names equal that Windows
// treats as different, which costs nothing: a refusal is only wider.
func Fold(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		b.WriteRune(foldRune(r))
	}
	return b.String()
}

func foldRune(r rune) rune {
	switch r {
	case 'ı', 'İ': // dotless and dotted I: Turkic mappings, which simple folding leaves out
		return 'I'
	}
	m := r
	for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
		if f < m {
			m = f
		}
	}
	return m
}

// Equal compares two names as Fold does.
func Equal(a, b string) bool { return Fold(a) == Fold(b) }

// Resolve maps HKCR and HKCC to the physical keys they show: HKCR to the
// computer's classes, HKCC to its alias's path (ADR-0067, Hives and users).
// HKLM and HKU are returned as they are.
func Resolve(h Hive, names []string) (Hive, []string) {
	switch h {
	case HKCR:
		return HKLM, append([]string{"SOFTWARE", "Classes"}, names...)
	case HKCC:
		return HKLM, append([]string{"SYSTEM", "CurrentControlSet", "Hardware Profiles", "Current"}, names...)
	}
	return h, names
}

// isWowNode is a name Windows uses for the 32-bit view's part of SOFTWARE.
func isWowNode(n string) bool {
	f := Fold(n)
	return f == Fold("WOW6432Node") || f == Fold("WowAA32Node")
}

// canonical is the path with the 32-bit nodes under SOFTWARE removed, so
// that a rule names the physical key and holds in every spelling.
func canonical(names []string) []string {
	if len(names) < 2 || !Equal(names[0], "SOFTWARE") {
		return names
	}
	out := []string{names[0]}
	i := 1
	for i < len(names) && isWowNode(names[i]) {
		i++
	}
	return append(out, names[i:]...)
}

// PhysicalNames is the path of the physical key a name in a view reaches:
// in the 32-bit view, a key under HKLM\SOFTWARE is under WOW6432Node.
// Shared keys keep their name; Windows decides what is shared.
func PhysicalNames(h Hive, v View, names []string) []string {
	h, names = Resolve(h, names)
	if h != HKLM || v != View32 || len(names) < 1 || !Equal(names[0], "SOFTWARE") {
		return names
	}
	if len(names) > 1 && isWowNode(names[1]) {
		return names
	}
	out := append([]string{names[0], "WOW6432Node"}, names[1:]...)
	return out
}

// Refusal says which rule refuses a path.
type Refusal struct {
	// Rule names the rule in words, as the console shows it.
	Rule string `json:"rule"`
	// Path is the refused key as the rule matched it: the canonical path.
	Path string `json:"path"`
}

func (r Refusal) Error() string { return "refused by EasyRMM: " + r.Rule }

type rule struct {
	prefix []string
	why    string
}

// refusedRules are the paths refused for reading and writing, in every view
// and spelling, with every key under them (ADR-0067, Refused, for reading
// and writing). The list changes only by amending the ADR.
var refusedRules = []rule{
	{[]string{"SAM"}, "the local accounts database"},
	{[]string{"SECURITY"}, "LSA secrets and cached logons"},
	{[]string{"SOFTWARE", "EasyRMM"}, "the EasyRMM agent's own keys"},
	{[]string{"SOFTWARE", "EasyPatch"}, "the EasyPatch agent's own keys"},
	{[]string{"SOFTWARE", "Open Source"}, "MeshAgent's keys"},
}

// agentServices are the services of the agents, refused under every
// control set.
var agentServices = []string{"EasyRMMAgent", "EasyRMMMeshAgent", "EasyPatchAgent"}

// isControlSet reports whether n names a control set: CurrentControlSet or
// ControlSet followed by digits.
func isControlSet(n string) bool {
	f := Fold(n)
	if f == Fold("CurrentControlSet") {
		return true
	}
	p := Fold("ControlSet")
	if !strings.HasPrefix(f, p) || len(f) == len(p) {
		return false
	}
	for _, r := range f[len(p):] {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func hasPrefix(names, prefix []string) bool {
	if len(names) < len(prefix) {
		return false
	}
	for i, p := range prefix {
		if !Equal(names[i], p) {
			return false
		}
	}
	return true
}

// Check says whether a key may be read or written at all: nil if allowed.
// It checks the physical key, in every spelling of the 32-bit view.
func Check(h Hive, v View, names []string) *Refusal {
	h, names = Resolve(h, names)
	if h != HKLM {
		return nil
	}
	c := canonical(names)
	for _, r := range refusedRules {
		if hasPrefix(c, r.prefix) {
			return &Refusal{Rule: r.why, Path: "HKLM\\" + strings.Join(c, "\\")}
		}
	}
	if len(c) >= 4 && Equal(c[0], "SYSTEM") && isControlSet(c[1]) && Equal(c[2], "Services") {
		for _, s := range agentServices {
			if Equal(c[3], s) {
				return &Refusal{Rule: "an EasyRMM or EasyPatch agent's service", Path: "HKLM\\" + strings.Join(c, "\\")}
			}
		}
	}
	return nil
}

// Prefix is a key and everything under it, in a physical hive: a copy of SAM
// or SECURITY the agent found loaded under another name, which is refused as
// the originals are.
type Prefix struct {
	Hive  Hive
	Names []string
}

// CheckWith is Check, and also refuses the keys under the extra prefixes.
func CheckWith(h Hive, v View, names []string, extra []Prefix) *Refusal {
	if r := Check(h, v, names); r != nil {
		return r
	}
	h, names = Resolve(h, names)
	for _, e := range extra {
		if e.Hive == h && hasPrefix(names, e.Names) {
			return &Refusal{Rule: "a loaded copy of SAM or SECURITY", Path: Format(h, names)}
		}
	}
	return nil
}

// ParseText reads a text path in any of the spellings ADR-0067 lists
// (HKLM, HKEY_LOCAL_MACHINE, HKLM:, Registry::HKEY_…,
// Microsoft.PowerShell.Core\Registry::HKEY_…, Computer\HKEY_…, and the
// kernel's \REGISTRY\MACHINE and \REGISTRY\USER). HKEY_CURRENT_USER answers
// ErrCurrentUser. Names are split on a backslash only: a slash is part of a
// name.
func ParseText(s string) (Hive, []string, error) {
	s = strings.TrimSpace(s)
	for _, p := range []string{`Microsoft.PowerShell.Core\Registry::`, `Registry::`, `Computer\`} {
		if len(s) >= len(p) && strings.EqualFold(s[:len(p)], p) {
			s = s[len(p):]
			break
		}
	}
	s = strings.TrimLeft(s, `\`)
	root, rest, _ := strings.Cut(s, `\`)
	root = strings.TrimSuffix(root, ":")
	var h Hive
	switch strings.ToUpper(root) {
	case "HKLM", "HKEY_LOCAL_MACHINE":
		h = HKLM
	case "HKU", "HKEY_USERS":
		h = HKU
	case "HKCR", "HKEY_CLASSES_ROOT":
		h = HKCR
	case "HKCC", "HKEY_CURRENT_CONFIG":
		h = HKCC
	case "HKCU", "HKEY_CURRENT_USER":
		return "", nil, ErrCurrentUser
	case "REGISTRY":
		sub, more, _ := strings.Cut(rest, `\`)
		switch strings.ToUpper(sub) {
		case "MACHINE":
			h = HKLM
		case "USER":
			h = HKU
		default:
			return "", nil, fmt.Errorf("%w: %q", ErrPath, s)
		}
		rest = more
	default:
		return "", nil, fmt.Errorf("%w: it does not start with a hive", ErrPath)
	}
	rest = strings.TrimRight(rest, `\`)
	var names []string
	if rest != "" {
		names = strings.Split(rest, `\`)
	}
	if err := ValidateNames(names); err != nil {
		return "", nil, err
	}
	return h, names, nil
}

// Format writes a path as Registry Editor does, with the hive's full name.
func Format(h Hive, names []string) string {
	full := map[Hive]string{HKLM: "HKEY_LOCAL_MACHINE", HKU: "HKEY_USERS", HKCR: "HKEY_CLASSES_ROOT", HKCC: "HKEY_CURRENT_CONFIG"}[h]
	if len(names) == 0 {
		return full
	}
	return full + `\` + strings.Join(names, `\`)
}

// Value types, as Windows numbers them.
const (
	TypeNone         = 0
	TypeSZ           = 1
	TypeExpandSZ     = 2
	TypeBinary       = 3
	TypeDWord        = 4
	TypeDWordBE      = 5
	TypeLink         = 6
	TypeMultiSZ      = 7
	TypeResourceList = 8
	TypeQWord        = 11
)

// maskWords are the words that make a value's name a masked one, without
// regard to case.
var maskWords = []string{"pass", "pwd", "secret", "token", "auth", "cred", "psk", "cookie", "apikey", "api_key",
	"accesskey", "privatekey", "private_key", "connectionstring"}

// IsMasked says whether a value's data is masked: a value that is not a
// number (REG_DWORD, REG_QWORD) whose name holds one of the words, and any
// value named DigitalProductId. Masking is a net, not a boundary.
func IsMasked(name string, valueType uint32) bool {
	if valueType == TypeDWord || valueType == TypeQWord {
		return false
	}
	f := Fold(name)
	if strings.HasPrefix(f, Fold("DigitalProductId")) {
		return true
	}
	for _, w := range maskWords {
		if strings.Contains(f, Fold(w)) {
			return true
		}
	}
	return false
}
