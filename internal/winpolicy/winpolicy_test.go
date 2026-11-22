package winpolicy

import (
	"encoding/json"
	"regexp"
	"strings"
	"testing"
)

func TestReader(t *testing.T) {
	r := Reader()
	for i, c := range r {
		if c > 126 || (c < 32 && c != '\n' && c != '\r' && c != '\t') {
			t.Fatalf("character %q at byte %d is not printable ASCII", c, i)
		}
	}
	// The reader names each owner and reason as the Go constants do, so
	// that a result never carries a code the server does not know.
	for _, s := range append(append([]string{ResultOwner, ResultNone, ResultCannotTell}, Reasons...), Owners...) {
		if !strings.Contains(r, "'"+s+"'") {
			t.Errorf("the reader never gives %q", s)
		}
	}
	// It defines functions and runs nothing: every line at the left margin
	// is a comment, a function or a closing brace.
	for n, line := range strings.Split(r, "\n") {
		line = strings.TrimSuffix(line, "\r")
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "function ") || line == "}" ||
			strings.HasPrefix(line, " ") {
			continue
		}
		t.Errorf("line %d runs something: %q", n+1, line)
	}
}

// TestReaderAudit: the reader's table of audit subcategories knows every
// subcategory of the audit table, under its legacy category (which Group
// Policy's legacy audit policy sets) and the Policy CSP's Audit area for
// its category.
func TestReaderAudit(t *testing.T) {
	row := regexp.MustCompile(`'([0-9a-f]{2})' = @\('(Audit[A-Za-z]+)', '([A-Za-z]+)_Audit[A-Za-z]+'\)`)
	rows := map[string][]string{}
	for _, m := range row.FindAllStringSubmatch(Reader(), -1) {
		if rows[m[1]] != nil {
			t.Errorf("%s twice", m[1])
		}
		rows[m[1]] = m[2:]
	}
	if len(rows) != 59 {
		t.Errorf("%d subcategories, want Windows' 59", len(rows))
	}
	categories := map[string][2]string{
		"Account Logon": {"AuditAccountLogon", "AccountLogon"}, "Account Management": {"AuditAccountManage", "AccountManagement"},
		"Detailed Tracking": {"AuditProcessTracking", "DetailedTracking"}, "DS Access": {"AuditDSAccess", "DSAccess"},
		"Logon/Logoff": {"AuditLogonEvents", "AccountLogonLogoff"}, "Object Access": {"AuditObjectAccess", "ObjectAccess"},
		"Policy Change": {"AuditPolicyChange", "PolicyChange"}, "Privilege Use": {"AuditPrivilegeUse", "PrivilegeUse"},
		"System": {"AuditSystemEvents", "System"},
	}
	for _, s := range audit.Subcategories {
		// {0cce92xx-69ae-11d9-bed3-505054503030}
		got, want := rows[s.GUID[7:9]], categories[s.Category]
		if !strings.HasPrefix(s.GUID, "{0cce92") || !strings.HasSuffix(s.GUID, "-69ae-11d9-bed3-505054503030}") ||
			got == nil || got[0] != want[0] || got[1] != want[1] {
			t.Errorf("%s (%s, %s): the reader has %v", s.GUID, s.Category, s.Name, got)
		}
	}
}

func TestQuery(t *testing.T) {
	q := Query()
	if !strings.HasPrefix(q, Reader()) || len(q) == len(Reader()) {
		t.Fatal("Query is not the reader and query.ps1")
	}
	entry := q[len(Reader()):]
	for i, c := range entry {
		if c > 126 || (c < 32 && c != '\n' && c != '\r' && c != '\t') {
			t.Fatalf("character %q at byte %d is not printable ASCII", c, i)
		}
	}
	// One line ending throughout, as the checkout gives both files.
	if crlf := strings.Count(q, "\r\n"); crlf != 0 && crlf != strings.Count(q, "\n") {
		t.Errorf("%d of %d lines end in CRLF", crlf, strings.Count(q, "\n"))
	}
	if !strings.Contains(entry, "'"+strings.TrimSpace(QueryResultPrefix)+" '") {
		t.Errorf("query.ps1 does not print %q", QueryResultPrefix)
	}
	// It calls the reader's resolvers, each defined once, in the reader.
	for _, f := range []string{"Get-ErPolicyContext", "Resolve-ErRegistryOwner", "Resolve-ErSecurityOwner", "Resolve-ErAuditOwner",
		"New-ErWorkFolder", "ConvertTo-ErAscii"} {
		if strings.Count(q, "function "+f+" {") != 1 || !strings.Contains(entry, f+" ") {
			t.Errorf("%s: not defined once in the reader and called by query.ps1", f)
		}
	}
}

func TestAudit(t *testing.T) {
	a := audit
	if len(a.Subcategories) != 31 || len(a.Values) != 4 || len(a.Logs) != 5 || a.Source == "" {
		t.Errorf("table %d subcategories, %d values, %d logs", len(a.Subcategories), len(a.Values), len(a.Logs))
	}
	var back AuditTable
	if err := json.Unmarshal([]byte(AuditJSON()), &back); err != nil || len(back.Subcategories) != len(a.Subcategories) {
		t.Errorf("AuditJSON: %v", err)
	}
	if strings.Contains(AuditJSON(), "\n") {
		t.Error("AuditJSON is not compact")
	}
	dc := 0
	for _, s := range a.Subcategories {
		if s.DomainControllersOnly {
			dc++
		}
	}
	if dc != 4 {
		t.Errorf("%d subcategories for domain controllers only, want 4", dc)
	}
}

func TestParseAudit(t *testing.T) {
	row := func(guid, set string) string {
		return `{"guid":"` + guid + `","category":"System","name":"Security State Change","set":"` + set + `"}`
	}
	g := "{0cce9210-69ae-11d9-bed3-505054503030}"
	log := `"logs":[{"channel":"Security","minKB":1}]`
	for name, body := range map[string]string{
		"not JSON":         `{`,
		"unknown field":    `{"subcategories":[` + row(g, "success") + `],` + log + `,"extra":1}`,
		"upper case GUID":  `{"subcategories":[` + row(strings.ToUpper(g), "success") + `],` + log + `}`,
		"twice":            `{"subcategories":[` + row(g, "success") + `,` + row(g, "failure") + `],` + log + `}`,
		"unknown setting":  `{"subcategories":[` + row(g, "always") + `],` + log + `}`,
		"no name":          `{"subcategories":[{"guid":"` + g + `","category":"System","name":"","set":"success"}],` + log + `}`,
		"incomplete value": `{"subcategories":[` + row(g, "success") + `],"values":[{"id":"x","path":"","name":"y","data":1}],` + log + `}`,
		"value only with":  `{"subcategories":[` + row(g, "success") + `],"values":[{"id":"x","path":"p","name":"y","data":1,"onlyWith":"pwsh8"}],` + log + `}`,
		"incomplete log":   `{"subcategories":[` + row(g, "success") + `],"logs":[{"channel":"Security","minKB":0}]}`,
		"empty":            `{"subcategories":[],` + log + `}`,
		"no logs":          `{"subcategories":[` + row(g, "success") + `]}`,
	} {
		if _, err := parseAudit([]byte(body)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := parseAudit([]byte(`{"subcategories":[` + row(g, "left") + `],` + log + `}`)); err != nil {
		t.Errorf("a valid table: %v", err)
	}
	defer func() {
		if recover() == nil {
			t.Error("a bad table did not panic")
		}
	}()
	mustParseAudit([]byte(`{`))
}
