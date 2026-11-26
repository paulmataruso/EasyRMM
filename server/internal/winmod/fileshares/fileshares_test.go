package fileshares

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
	"github.com/paulmataruso/easyrmm/server/internal/winmod"
)

func catalog(t *testing.T) *winmod.Catalog {
	t.Helper()
	c, err := winmod.NewCatalog(Actions()...)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestCatalogLint(t *testing.T) {
	c := catalog(t)
	if got, want := len(c.Actions()), len(scriptFiles(t)); got != want {
		t.Errorf("%d actions for %d scripts", got, want)
	}
	tier3 := map[string]bool{"share_remove": true}
	tier2 := []string{"share_create", "share_set", "share_access_grant", "share_access_revoke", "share_access_block",
		"share_access_unblock", "session_close", "openfile_close"}
	for _, a := range c.Actions() {
		if agentproto.HashScript(a.Script) != a.ScriptSHA256 {
			t.Errorf("%s: pin does not match", a.Name)
		}
		if a.Changes && a.Permission != rbac.PermSharesManage {
			t.Errorf("%s: a change needs shares.manage", a.Name)
		}
		if !a.Changes && a.Permission != rbac.PermSharesView {
			t.Errorf("%s: a read needs shares.view", a.Name)
		}
		if (a.Destructive || a.Confirm) && (!a.SubjectIsDeviceName || a.Subject != "device") {
			t.Errorf("%s: confirmed on a name the server does not compare", a.Name)
		}
		if a.Destructive != tier3[strings.TrimPrefix(a.Name, "file_shares.")] {
			t.Errorf("%s: destructive = %v", a.Name, a.Destructive)
		}
		// Whoever is connected and what they have open is sensitive.
		if strings.Contains(a.Name, "session_list") || strings.Contains(a.Name, "openfile_list") {
			if !a.Sensitive || a.Keep > 15*60*1e9 {
				t.Errorf("%s: must be sensitive and short-lived", a.Name)
			}
		}
		// No script changes a share without the protected-share check.
		if a.Changes && strings.Contains(a.Name, "share_") && !strings.Contains(a.Script, "Assert-Unprotected") {
			t.Errorf("%s: the script does not refuse protected shares", a.Name)
		}
		if a.Check == nil && strings.Contains(a.Name, "share_") && a.Changes {
			t.Errorf("%s: no server-side check", a.Name)
		}
	}
	for _, n := range tier2 {
		if a, _ := c.Lookup("file_shares." + n); !a.Confirm || a.NeedsStepUp() {
			t.Errorf("%s: tier 2 is confirmed without a step-up", n)
		}
	}
	if a, _ := c.Lookup("file_shares.share_remove"); !a.NeedsStepUp() {
		t.Error("share_remove needs a step-up")
	}
	// No NTFS or quota action exists (slices F4 and F5 are not built).
	for _, a := range c.Actions() {
		if strings.Contains(a.Name, "ntfs") || strings.Contains(a.Name, "quota") {
			t.Errorf("%s: not built", a.Name)
		}
	}
	// A script never touches the files of a share, or NTFS.
	for _, a := range c.Actions() {
		for _, banned := range []string{"Set-Acl", "icacls", "takeown", "Remove-Item", "Set-SmbServerConfiguration"} {
			if strings.Contains(a.Script, banned) {
				t.Errorf("%s: names %s", a.Name, banned)
			}
		}
	}
}

func TestProtectedShares(t *testing.T) {
	for _, n := range []string{"SYSVOL", "sysvol", "NETLOGON", "Netlogon", "print$", "IPC$", "ADMIN$", "C$", "data$", "x$", " SYSVOL "} {
		if !ProtectedShare(n) {
			t.Errorf("%q must be protected", n)
		}
	}
	for _, n := range []string{"Data", "SYSVOL2", "Public", "netlogon2", "my$share"} {
		if ProtectedShare(n) {
			t.Errorf("%q must not be protected", n)
		}
	}
}

// refused runs an action's validation and returns the refusal code, or "".
func refused(t *testing.T, c *winmod.Catalog, action, params string) string {
	t.Helper()
	a, ok := c.Lookup("file_shares." + action)
	if !ok {
		t.Fatalf("no action %s", action)
	}
	_, err := a.Validate(json.RawMessage(params))
	if err == nil {
		return ""
	}
	if e, ok := apperr.As(err); ok {
		return e.Code
	}
	return "invalid: " + err.Error()
}

func TestProtectedSharesRefusedBeforeAnyJob(t *testing.T) {
	c := catalog(t)
	for _, n := range []string{"SYSVOL", "sysvol", "NETLOGON", "print$", "IPC$", "ADMIN$", "C$", "Hidden$"} {
		for action, extra := range map[string]string{
			"share_remove":         ``,
			"share_set":            `,"description":"x"`,
			"share_access_grant":   `,"account":"Alice","right":"Read"`,
			"share_access_revoke":  `,"account":"Alice"`,
			"share_access_block":   `,"account":"Alice"`,
			"share_access_unblock": `,"account":"Alice"`,
			"share_create":         `,"path":"C:\\Data"`,
		} {
			got := refused(t, c, action, `{"device":"SRV","name":"`+n+`"`+extra+`}`)
			if got != "protected_share" {
				t.Errorf("%s on %s: %q, want protected_share", action, n, got)
			}
		}
	}
	if got := refused(t, c, "share_remove", `{"device":"SRV","name":"Public"}`); got != "" {
		t.Errorf("an ordinary share: %q", got)
	}
}

func TestCreatePaths(t *testing.T) {
	c := catalog(t)
	for _, p := range []string{`C:\`, `D:`, `C:\Windows`, `C:\Windows\System32`, `c:\windows\x`, `C:\Windows\SYSVOL\sysvol`, `D:\Data\SYSVOL`} {
		got := refused(t, c, "share_create", `{"device":"SRV","name":"Data","path":"`+strings.ReplaceAll(p, `\`, `\\`)+`"}`)
		if got != "protected_path" && got != "validation_failed" {
			t.Errorf("%s: %q, want a refusal", p, got)
		}
	}
	for _, p := range []string{`C:\Shares\Data`, `D:\Public`, `C:\Windowsold\x`} {
		if got := refused(t, c, "share_create", `{"device":"SRV","name":"Data","path":"`+strings.ReplaceAll(p, `\`, `\\`)+`"}`); got != "" {
			t.Errorf("%s: %q", p, got)
		}
	}
}

func TestWeakeningRefused(t *testing.T) {
	cases := []struct {
		account, right string
		weak           bool
	}{
		{"Everyone", "Full", true}, {"everyone", "Change", true}, {"Everyone", "Read", false},
		{`NT AUTHORITY\Authenticated Users`, "Change", true}, {"Authenticated Users", "Full", true}, {"Authenticated Users", "Read", false},
		{`NT AUTHORITY\ANONYMOUS LOGON`, "Change", true}, {"Anonymous Logon", "Read", false},
		{"Users", "Full", true}, {`BUILTIN\Users`, "Full", true}, {"Users", "Change", false}, {"Users", "Read", false},
		{"S-1-1-0", "Full", true}, {"S-1-5-11", "Change", true}, {"S-1-5-7", "Full", true}, {"S-1-5-32-545", "Full", true},
		{"S-1-5-32-545", "Change", false}, {"S-1-1-0", "Read", false},
		{"Domain Users", "Full", false}, {`CORP\alice`, "Full", false}, {"S-1-5-21-1-2-3-513", "Full", false},
		{`corp\Users`, "Full", false},
	}
	for _, tc := range cases {
		if got := WeakensAccess(tc.account, tc.right); got != tc.weak {
			t.Errorf("WeakensAccess(%q, %s) = %v", tc.account, tc.right, got)
		}
	}
	c := catalog(t)
	if got := refused(t, c, "share_access_grant", `{"device":"SRV","name":"Data","account":"Everyone","right":"Full"}`); got != "weakens_access" {
		t.Errorf("a grant to Everyone: %q", got)
	}
	if got := refused(t, c, "share_access_grant", `{"device":"SRV","name":"Data","account":"Everyone","right":"Read"}`); got != "" {
		t.Errorf("a read grant to Everyone: %q", got)
	}
	if got := refused(t, c, "share_access_block", `{"device":"SRV","name":"Data","account":"BUILTIN\\Administrators"}`); got != "would_lock_out" {
		t.Errorf("blocking Administrators: %q", got)
	}
	if got := refused(t, c, "share_access_block", `{"device":"SRV","name":"Data","account":"CORP\\mallory"}`); got != "" {
		t.Errorf("blocking one user: %q", got)
	}
}

func TestHostileValuesAreRefusedOrCarried(t *testing.T) {
	c := catalog(t)
	for _, v := range []string{"a'b", "a\"b", "$(x)", "a`b", "a;b", "a\nb", "a|b", "..\\x", "a/b", "*", "a:b"} {
		b, _ := json.Marshal(map[string]string{"device": "SRV", "name": v})
		a, _ := c.Lookup("file_shares.share_remove")
		chk, err := a.Validate(b)
		if err == nil {
			// A value that passes holds none of the characters PowerShell treats
			// as syntax, outside quotes the script never builds.
			if strings.ContainsAny(v, "\"`;|\n/\\*:()") {
				t.Errorf("%q passed as a share name: %s", v, chk.Params)
			}
		}
	}
	for _, v := range []string{"Alice; Remove-Item", "a$(b)", "x\ny", "a`b", `a"b`, "*"} {
		b, _ := json.Marshal(map[string]string{"device": "SRV", "name": "Data", "account": v, "right": "Read"})
		a, _ := c.Lookup("file_shares.share_access_grant")
		if _, err := a.Validate(b); err == nil {
			t.Errorf("%q passed as an account", v)
		}
	}
	for _, v := range []string{"1; 2", "abc", "-1", "123456789012345678901", ""} {
		b, _ := json.Marshal(map[string]string{"device": "SRV", "id": v})
		a, _ := c.Lookup("file_shares.session_close")
		if _, err := a.Validate(b); err == nil {
			t.Errorf("%q passed as a session id", v)
		}
	}
}

func TestResultsDecode(t *testing.T) {
	c := catalog(t)
	a, _ := c.Lookup("file_shares.share_list")
	line := winmod.ResultPrefix + `{"ok":true,"version":1,"data":{"shares":[{"name":"Data","path":"D:\\Data","description":"","special":false,"protected":false,"scoped":false,"continuouslyAvailable":false,"encrypted":false,"caching":"Manual","folderEnumeration":"AccessBased","concurrentUserLimit":0}],"truncated":false},"error":null}`
	res, err := a.ParseResult(line)
	if err != nil || !res.OK || res.Count != 1 {
		t.Fatalf("%v %+v", err, res)
	}
	if _, err := a.ParseResult(strings.Replace(line, `"truncated"`, `"extra":1,"truncated"`, 1)); err == nil {
		t.Error("an unknown field was accepted")
	}
}
