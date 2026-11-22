package extract

import (
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/paulmataruso/easyrmm/server/internal/jobs/hardening/controls"
)

// What a rule checks, read from its check text. The first kind a check
// names is its key: a rule matches a rule of another release whose key is
// the same, so that the hardening script can cite each Windows version's
// own rule. Values are not compared: releases sometimes ask different
// values of the same setting.
var (
	regHive  = regexp.MustCompile(`(?i)Registry Hive:?\s*(HKEY_[A-Z_]+)`)
	regPath  = regexp.MustCompile(`(?i)Registry Path:?\s*(\S.*)$`)
	regValue = regexp.MustCompile(`(?i)Value Name:?\s*(\S.*)$`)
	// AuditPol's form: "Account Logon >> Credential Validation - Failure".
	auditPol = regexp.MustCompile(`(?m)^\s*[A-Za-z/ ]+? >> ([A-Za-z/ -]+?) - (Success|Failure)\s*$`)
	// Group Policy's form: If "Audit Registry" is not set to "Failure".
	auditGPO = regexp.MustCompile(`If "(Audit [A-Za-z/ -]+?)" is not set to "(Success|Failure)"`)
	// Account policies, security options and user rights, by name.
	policy = regexp.MustCompile(`(?:Account Policies >>[^\n]*|Security Options|User Rights Assignment)\.?\s*\n(?:.*\n){0,6}?.*?"([^"]+)"`)
	// Windows features, by name.
	feature = regexp.MustCompile(`(?i)(?:Get-WindowsFeature \| Where Name -eq|Get-WindowsFeature -Name|FeatureName -eq|FeatureName -like)\s+\*?([A-Za-z0-9-]+)\*?`)
	// Event logs and Event Viewer, by file.
	file = regexp.MustCompile(`(?i)\b([A-Za-z]+\.evtx|Eventvwr\.exe)\b`)
	// Product names and rule IDs, which differ between releases' texts.
	productName = regexp.MustCompile(`Windows Server 20(?:16|19|22|25)|Windows 1[01]|\(?WN\w\w-\w\w-\d{6}\)?`)
)

// checkKey is what a rule checks.
type checkKey struct {
	kind   string   // registry, audit policy, security policy, Windows feature, file
	keys   []string // normalized and sorted, for comparing
	shown  []string // as the check writes them
	method string   // for audit policy: auditpol or Group Policy
}

func (k checkKey) equal(o checkKey) bool {
	return k.kind != "" && k.kind == o.kind && slices.Equal(k.keys, o.keys)
}

func (k checkKey) String() string {
	return k.kind + ": " + strings.Join(k.shown, "; ")
}

func keyOf(check string) checkKey {
	var k checkKey
	add := func(norm, shown string) {
		if !slices.Contains(k.keys, norm) {
			k.keys = append(k.keys, norm)
			k.shown = append(k.shown, shown)
		}
	}
	finish := func(kind string) checkKey {
		k.kind = kind
		slices.Sort(k.keys)
		return k
	}

	var hive, path string
	for _, line := range strings.Split(check, "\n") {
		if m := regHive.FindStringSubmatch(line); m != nil {
			hive = strings.ToUpper(m[1])
		} else if m := regPath.FindStringSubmatch(line); m != nil {
			path = strings.Trim(strings.TrimSpace(m[1]), `\`)
		} else if m := regValue.FindStringSubmatch(line); m != nil && hive != "" && path != "" {
			shown := hive + `\` + path + `\` + strings.TrimSpace(m[1])
			add(strings.ToUpper(strings.Join(strings.Fields(shown), "")), shown)
		}
	}
	if len(k.keys) > 0 {
		return finish("registry")
	}

	for _, m := range auditPol.FindAllStringSubmatch(check, -1) {
		add(strings.ToLower(subcategory(m[1])+" - "+m[2]), subcategory(m[1])+" - "+m[2])
		k.method = "auditpol"
	}
	for _, m := range auditGPO.FindAllStringSubmatch(check, -1) {
		add(strings.ToLower(subcategory(m[1])+" - "+m[2]), subcategory(m[1])+" - "+m[2])
		k.method = "Group Policy"
	}
	if len(k.keys) > 0 {
		return finish("audit policy")
	}

	for _, by := range []struct {
		kind string
		re   *regexp.Regexp
	}{{"security policy", policy}, {"Windows feature", feature}, {"file", file}} {
		for _, m := range by.re.FindAllStringSubmatch(check, -1) {
			add(strings.ToLower(m[1]), m[1])
		}
		if len(k.keys) > 0 {
			return finish(by.kind)
		}
	}
	return checkKey{}
}

// subcategory returns an audit subcategory's name as AuditPol writes it:
// Group Policy writes "Audit Registry" for Registry and "Audit Audit Policy
// Change" for Audit Policy Change.
func subcategory(s string) string {
	s = strings.TrimSpace(s)
	if s != "Audit Policy Change" {
		s = strings.TrimPrefix(s, "Audit ")
	}
	return s
}

// normalText is a check's text with product names, rule IDs and spacing
// made uniform, to find checks that are word for word the same.
func normalText(check string) string {
	return strings.Join(strings.Fields(productName.ReplaceAllString(check, "X")), " ")
}

// readMatch is a pair of rules whose checks name nothing the other names
// the same way (no registry value, policy, audit subcategory, feature or
// file), matched by reading both checks; Subject says what both check.
type readMatch struct {
	Rule, Release, Equivalent, Subject string
}

// readMatches were made by reading both rules' checks.
var readMatches = []readMatch{
	{"WN11-00-000030", "win10-v3r6", "WN10-00-000030", "BitLocker on the operating system and fixed data drives"},
	{"WN11-00-000045", "win10-v3r6", "WN10-00-000045", "an antivirus solution installed and in use"},
	{"WN11-00-000110", "win10-v3r6", "WN10-00-000110", "Simple TCP/IP Services not installed"},
	{"WN11-00-000115", "win10-v3r6", "WN10-00-000115", "Telnet Client not installed"},
	{"WN11-00-000120", "win10-v3r6", "WN10-00-000120", "TFTP Client not installed"},
	{"WN11-SO-000280", "win10-v3r6", "WN10-SO-000280", "age of the local Administrator account's password (the releases ask different ages)"},
	{"WN25-00-000020", "ws2022-v2r11", "WN22-00-000020", "age of the local Administrator account's password"},
	{"WN25-00-000020", "ws2019-v3r9", "WN19-00-000020", "age of the local Administrator account's password (the releases ask different ages)"},
	{"WN25-00-000020", "ws2016-v2r10", "WN16-00-000030", "age of the built-in Administrator account's password (the releases ask different ages)"},
	{"WN25-00-000110", "ws2022-v2r11", "WN22-00-000110", "an antivirus solution installed"},
	{"WN25-00-000110", "ws2019-v3r9", "WN19-00-000110", "an antivirus solution installed"},
	{"WN25-00-000110", "ws2016-v2r10", "WN16-00-000120", "an antivirus solution installed"},
	{"WN25-00-000250", "ws2022-v2r11", "WN22-00-000250", "data at rest encrypted where the system needs it"},
	{"WN25-00-000250", "ws2019-v3r9", "WN19-00-000250", "data at rest encrypted where the system needs it"},
	{"WN25-00-000250", "ws2016-v2r10", "WN16-00-000280", "data at rest encrypted where the system needs it"},
	{"WN25-AU-000020", "ws2022-v2r11", "WN22-AU-000020", "audit records off-loaded to another system"},
	{"WN25-AU-000020", "ws2019-v3r9", "WN19-AU-000020", "audit records off-loaded to another system"},
	{"WN25-AU-000020", "ws2016-v2r10", "WN16-AU-000020", "audit records off-loaded to another system"},
}

// equivalents finds, for every cited rule of a release in Equivalents, the
// rule of each older release that checks the same thing: by registry
// value, audit subcategory, policy name, Windows feature or file; failing
// that, by a check text that is word for word the same; failing that, by
// readMatches. A rule with no match gets an empty row.
func equivalents(cites controls.Cites, stigs map[string]stigRelease, reads []readMatch) ([][]string, error) {
	type indexed struct {
		rules map[string]stigRule
		keys  map[string]checkKey
		text  map[string]string
	}
	index := map[string]indexed{}
	for release, r := range stigs {
		ix := indexed{rules: map[string]stigRule{}, keys: map[string]checkKey{}, text: map[string]string{}}
		for _, rule := range r.rules {
			ix.rules[rule.version] = rule
			ix.keys[rule.version] = keyOf(rule.check)
			ix.text[rule.version] = normalText(rule.check)
		}
		index[release] = ix
	}
	read := map[[2]string]readMatch{}
	for _, m := range reads {
		read[[2]string{m.Rule, m.Release}] = m
	}

	var cited []string
	for _, m := range cites.Modules {
		for _, id := range m.All() {
			if release, _ := cites.ReleaseOf(id); Equivalents[release] != nil && !slices.Contains(cited, id) {
				cited = append(cited, id)
			}
		}
	}
	slices.Sort(cited)

	var rows [][]string
	used := map[[2]string]bool{}
	for _, id := range cited {
		release, _ := cites.ReleaseOf(id)
		src, ok := index[release]
		if !ok {
			return nil, fmt.Errorf("equivalents: no source for %s", release)
		}
		rule, ok := src.rules[id]
		if !ok {
			return nil, fmt.Errorf("equivalents: %s is not in %s", id, release)
		}
		key, text := src.keys[id], src.text[id]
		for _, target := range Equivalents[release] {
			tg, ok := index[target]
			if !ok {
				return nil, fmt.Errorf("equivalents: no source for %s", target)
			}
			match, how, err := matchRule(rule.version, key, text, tg.keys, tg.text)
			if err != nil {
				return nil, fmt.Errorf("equivalents: %s in %s: %w", id, target, err)
			}
			if m, ok := read[[2]string{id, target}]; ok {
				if match != "" {
					return nil, fmt.Errorf("equivalents: %s in %s is matched by %s; drop it from readMatches", id, target, how)
				}
				if _, ok := tg.rules[m.Equivalent]; !ok {
					return nil, fmt.Errorf("equivalents: %s is not in %s", m.Equivalent, target)
				}
				match, how = m.Equivalent, "read: "+m.Subject
				used[[2]string{id, target}] = true
			}
			rows = append(rows, []string{id, target, match, how})
		}
	}
	for k := range read {
		if !used[k] {
			return nil, fmt.Errorf("equivalents: readMatches names %s in %s, which is not cited", k[0], k[1])
		}
	}
	return rows, nil
}

// matchRule finds the target rule that checks what a rule checks.
func matchRule(id string, key checkKey, text string, keys map[string]checkKey, texts map[string]string) (string, string, error) {
	var found []string
	for v, k := range keys {
		if key.equal(k) {
			found = append(found, v)
		}
	}
	if len(found) > 1 { // a release that checks one setting twice, once per tool
		found = slices.DeleteFunc(found, func(v string) bool { return keys[v].method != key.method })
	}
	if len(found) > 1 {
		found = slices.DeleteFunc(found, func(v string) bool { return texts[v] != text })
	}
	switch len(found) {
	case 1:
		return found[0], key.String(), nil
	case 0:
	default:
		slices.Sort(found)
		return "", "", fmt.Errorf("%s matches %v", key, found)
	}
	for v, t := range texts {
		if t == text {
			found = append(found, v)
		}
	}
	switch len(found) {
	case 1:
		return found[0], "same check text", nil
	case 0:
		return "", "", nil
	}
	slices.Sort(found)
	return "", "", fmt.Errorf("%s's check text matches %v", id, found)
}
