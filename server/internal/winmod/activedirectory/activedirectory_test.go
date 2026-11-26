package activedirectory

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
	"unicode"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
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

// Every script matches its pin (the catalog's build checks it too), and the
// set of scripts is the set of actions.
func TestCatalogPinsMatchScripts(t *testing.T) {
	c := catalog(t)
	entries, err := scriptFS.ReadDir("scripts")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != len(c.Actions()) || len(pins) != len(entries) {
		t.Errorf("%d scripts, %d actions, %d pins", len(entries), len(c.Actions()), len(pins))
	}
	for _, a := range c.Actions() {
		if got := agentproto.HashScript(a.Script); got != a.ScriptSHA256 {
			t.Errorf("%s: the script hashes to %s; run gen.sh and review pins.go", a.Name, got)
		}
	}
}

// The catalog lint of ADR-0075 section 9: every change guards its targets by
// SID, every credential or destructive action asks for a step-up and a
// confirmation, and no change takes a group or a user as free text.
func TestCatalogLint(t *testing.T) {
	for _, a := range catalog(t).Actions() {
		isRead := !a.Changes
		if isRead && (a.Destructive || a.Credential) {
			t.Errorf("%s: a read that asks for a step-up", a.Name)
		}
		if isRead {
			continue
		}
		for _, p := range a.Params {
			switch p.Type {
			case winmod.SID:
				if !p.RefuseWellKnown {
					t.Errorf("%s.%s: a change takes a SID without the well-known refusal", a.Name, p.Name)
				}
			case winmod.Name:
				if p.Name == "id" || p.Name == "group" || p.Name == "member" {
					t.Errorf("%s.%s: a user or group is named by SID, not by name", a.Name, p.Name)
				}
			}
			if p.Secret && p.Type != winmod.Text {
				t.Errorf("%s.%s: a secret is text", a.Name, p.Name)
			}
		}
		if (a.Credential || a.Name == "active_directory.user_create") && !a.NeedsStepUp() {
			t.Errorf("%s: a credential action without step-up", a.Name)
		}
		if a.Credential && !a.Destructive {
			t.Errorf("%s: tier 3 needs the typed confirmation too", a.Name)
		}
		hasPassword := false
		for _, p := range a.Params {
			hasPassword = hasPassword || p.Name == "password"
		}
		if hasPassword && !a.Credential {
			t.Errorf("%s: takes a password but is not a credential action", a.Name)
		}
	}
	// The help desk's four.
	want := map[string]rbac.Permission{
		"user_unlock": rbac.PermADHelpdesk, "user_enable": rbac.PermADHelpdesk, "user_disable": rbac.PermADHelpdesk,
		"user_reset_password": rbac.PermADHelpdesk, "user_create": rbac.PermADManage, "user_delete": rbac.PermADManage,
		"group_add_member": rbac.PermADManage, "group_delete": rbac.PermADManage, "user_get": rbac.PermADViewSensitive,
	}
	c := catalog(t)
	for name, perm := range want {
		a, _ := c.Lookup("active_directory." + name)
		if a.Permission != perm {
			t.Errorf("%s needs %s, not %s", name, perm, a.Permission)
		}
	}
	if a, _ := c.Lookup("active_directory.user_get"); !a.Sensitive || a.SensitivePermission != rbac.PermADViewSensitive {
		t.Error("user_get is a sensitive read")
	}
	// What a script is told is checked on the server: a stronger use of a
	// parameter needs a stronger permission.
	reset, _ := c.Lookup("active_directory.user_reset_password")
	for _, p := range reset.Params {
		if p.Name == "serviceConfirm" && p.Needs != rbac.PermADResetPassword {
			t.Error("a service account's password reset needs ad.reset_password")
		}
	}
}

func TestSIDsOfTheDomainsPowerAreRefused(t *testing.T) {
	a, _ := catalog(t).Lookup("active_directory.user_disable")
	const dom = "S-1-5-21-1004336348-1177238915-682003330"
	for _, rid := range []string{"500", "501", "502", "512", "513", "516", "518", "519", "520", "521", "525", "526", "527", "548", "999"} {
		if _, err := a.Validate(json.RawMessage(`{"id":"` + dom + `-` + rid + `"}`)); err == nil {
			t.Errorf("RID %s was accepted", rid)
		}
	}
	for _, sid := range []string{"S-1-5-32-544", "S-1-5-32-548", "S-1-5-18", "S-1-1-0", "S-1-5-21-1-2-3"} {
		if _, err := a.Validate(json.RawMessage(`{"id":"` + sid + `"}`)); err == nil {
			t.Errorf("%s was accepted", sid)
		}
	}
	for _, rid := range []string{"1000", "1104", "40000"} {
		if _, err := a.Validate(json.RawMessage(`{"id":"` + dom + `-` + rid + `"}`)); err != nil {
			t.Errorf("RID %s: %v", rid, err)
		}
	}
	// A GUID where a SID is expected, and text.
	for _, bad := range []string{"2d1a4a7e-8c6e-4d5a-9a3e-0e6c6d7c1f10", "alice", "", "S-1-5-21-1-2-3-1104; Remove-Item *"} {
		if _, err := a.Validate(json.RawMessage(`{"id":"` + bad + `"}`)); err == nil {
			t.Errorf("%q was accepted", bad)
		}
	}
	// A read may name a built-in group.
	g, _ := catalog(t).Lookup("active_directory.group_members")
	if _, err := g.Validate(json.RawMessage(`{"id":"S-1-5-32-544"}`)); err != nil {
		t.Errorf("reading the Administrators group: %v", err)
	}
}

func TestDistinguishedNamesAndNames(t *testing.T) {
	a, _ := catalog(t).Lookup("active_directory.user_create")
	ok := `{"ou":"OU=Staff,OU=Sales,DC=corp,DC=example,DC=test","sam":"a.person-1","name":"Ann Person"}`
	chk, err := a.Validate(json.RawMessage(ok))
	if err != nil {
		t.Fatal(err)
	}
	if _, has := chk.Secrets["password"]; !has || len(chk.Generated["password"]) != 20 {
		t.Errorf("a password is generated when none is sent: %v", chk.Generated)
	}
	for _, ou := range []string{
		`OU=a,DC=x;Remove-Item`, `OU=a\,b,DC=x`, "OU=a\nOU=b,DC=x", `OU=a"b,DC=x`, `OU=$(calc),DC=x`, `OU=a,DC=x,`, `a,DC=x`, `OU=,DC=x`,
		"OU=" + strings.Repeat("a", 600) + ",DC=x", `CN=a)(objectClass=*,DC=x`, `OU=a+b,DC=x`, `OU=a<b,DC=x`,
	} {
		in, _ := json.Marshal(map[string]any{"ou": ou, "sam": "bob", "name": "Bob"})
		if _, err := a.Validate(in); err == nil {
			t.Errorf("the DN %q was accepted", ou)
		}
	}
	for _, sam := range []string{"", "has space", "a;b", "$(x)", strings.Repeat("a", 21), "a'b", `a"b`, "a\\b", "a/b", "é"} {
		in, _ := json.Marshal(map[string]any{"ou": "OU=a,DC=x", "sam": sam, "name": "Bob"})
		if _, err := a.Validate(in); err == nil {
			t.Errorf("the sAMAccountName %q was accepted", sam)
		}
	}
}

func TestPasswordsAreSecretsAndNeverShownBack(t *testing.T) {
	a, _ := catalog(t).Lookup("active_directory.user_reset_password")
	const typed = "Correct-Horse-Battery-9!"
	chk, err := a.Validate(json.RawMessage(`{"id":"S-1-5-21-1-2-3-1104","password":"` + typed + `","mustChange":false}`))
	if err != nil {
		t.Fatal(err)
	}
	if chk.Secrets["password"] != typed || len(chk.Generated) != 0 {
		t.Errorf("a typed password is sealed, not generated: %v", chk.Generated)
	}
	for name, doc := range map[string]string{"params": string(chk.Params), "audit": toJSON(chk.Audit)} {
		if strings.Contains(doc, typed) || strings.Contains(doc, "password\":\"C") {
			t.Errorf("the %s holds the password: %s", name, doc)
		}
	}
	// Too short, and the credential fallback is a secret too.
	if _, err := a.Validate(json.RawMessage(`{"id":"S-1-5-21-1-2-3-1104","password":"short"}`)); err == nil {
		t.Error("a 5 character password was accepted")
	}
	chk, err = a.Validate(json.RawMessage(`{"id":"S-1-5-21-1-2-3-1104","credUser":"CORP\\admin","credPassword":"Admin-Secret-77"}`))
	if err != nil {
		t.Fatal(err)
	}
	if chk.Secrets["credPassword"] != "Admin-Secret-77" || strings.Contains(string(chk.Params)+toJSON(chk.Audit), "Admin-Secret-77") {
		t.Errorf("the credential fallback leaked: %s %s", chk.Params, toJSON(chk.Audit))
	}
	// A generated password differs each time, and has every class.
	seen := map[string]bool{}
	for range 50 {
		c, err := a.Validate(json.RawMessage(`{"id":"S-1-5-21-1-2-3-1104"}`))
		if err != nil {
			t.Fatal(err)
		}
		pw := c.Generated["password"]
		if seen[pw] {
			t.Fatal("a generated password repeated")
		}
		seen[pw] = true
		var up, lo, di, sy bool
		for _, r := range pw {
			up, lo, di, sy = up || unicode.IsUpper(r), lo || unicode.IsLower(r), di || unicode.IsDigit(r), sy || strings.ContainsRune("!#$%&*+-=?@^_", r)
			if strings.ContainsRune("0O1lIo|", r) {
				t.Errorf("look-alike %q in %q", r, pw)
			}
		}
		if len(pw) != 20 || !up || !lo || !di || !sy {
			t.Errorf("generated %q", pw)
		}
		if c.Secrets["password"] != pw || strings.Contains(string(c.Params)+toJSON(c.Audit), pw) {
			t.Error("the generated password is in the params or the audit")
		}
	}
}

func toJSON(v any) string { b, _ := json.Marshal(v); return string(b) }

// Each action decodes the shape its script prints, and refuses one it does
// not know.
func TestResultsDecode(t *testing.T) {
	c := catalog(t)
	user := `{"id":"S-1-5-21-1-2-3-1104","sam":"ann","name":"Ann","upn":"ann@corp.test","enabled":true,"lockedOut":false,"passwordExpired":false,"protection":"none","reason":""}`
	samples := map[string]string{
		"status":             `{"domain":"corp.test","domainSid":"S-1-5-21-1-2-3","forest":"corp.test","forestRootSid":"S-1-5-21-1-2-3","domainMode":"Windows2016Domain","forestMode":"Windows2016Forest","controller":"dc1.corp.test","readOnly":false,"globalCatalog":true,"pdcEmulator":"dc1.corp.test","recycleBinEnabled":false,"passwordPolicy":{"minLength":7,"complexity":true,"historyCount":24,"maxAgeDays":42,"lockoutThreshold":0,"lockoutDurationMinutes":30,"lockoutObservationMinutes":30}}`,
		"ou_tree":            `{"parent":"DC=corp,DC=test","items":[{"dn":"OU=Staff,DC=corp,DC=test","name":"Staff","kind":"ou","protectedFromDelete":true,"writable":true}]}`,
		"user_list":          `{"items":[` + user + `],"next":null,"scanned":1,"domainSid":"S-1-5-21-1-2-3"}`,
		"group_list":         `{"items":[{"id":"S-1-5-21-1-2-3-1105","sam":"Sales","name":"Sales","scope":"global","category":"security","description":"","protection":"none","reason":""}],"next":"Sales","scanned":9,"domainSid":"S-1-5-21-1-2-3"}`,
		"group_members":      `{"items":[{"id":"S-1-5-21-1-2-3-1104","sam":"ann","name":"Ann","kind":"user","key":"ann"}],"next":null,"total":1}`,
		"user_get":           `{"id":"S-1-5-21-1-2-3-1104","sam":"ann","upn":"ann@corp.test","name":"Ann","displayName":"Ann","givenName":"","surname":"","description":"","mail":"","telephone":"","title":"","department":"","company":"","office":"","ou":"OU=Staff,DC=corp,DC=test","enabled":true,"lockedOut":false,"passwordExpired":false,"passwordNeverExpires":false,"cannotChangePassword":false,"passwordLastSetAt":"2026-11-01T08:00:00Z","accountExpiresAt":null,"createdAt":"2026-10-01T08:00:00Z","lastLogonApproxAt":null,"groups":["Sales"],"protection":"none","reason":""}`,
		"health_read":        `{"controller":"dc1.corp.test","domain":"corp.test","lockedOutCount":3,"checks":[{"name":"replication","state":"critical","detail":"x"}],"replication":{"failureCount":2,"oldestFailureAt":"2026-11-26T05:00:00Z","partners":[{"partner":"DC2","lastSuccessAt":null,"lastResult":8524}]}}`,
		"computer_list":      `{"items":[{"id":"S-1-5-21-1-2-3-1113","sam":"PC1$","name":"PC1","dnsName":"pc1.corp.test","os":"Windows 11","enabled":true,"controller":false}],"next":null,"scanned":1}`,
		"privileged_members": `{"groups":[{"id":"S-1-5-21-1-2-3-512","name":"Domain Admins","tier":1,"total":1,"changedAt":"2026-11-26T05:00:00Z","members":[{"id":"S-1-5-21-1-2-3-500","name":"Administrator","kind":"user"}]}]}`,
		"computer_disable":   `{"done":true}`,
		"user_unlock":        `{"done":true}`, "user_enable": `{"done":true}`, "user_disable": `{"done":true}`, "user_move": `{"done":true}`,
		"user_delete": `{"done":true}`, "group_add_member": `{"done":true}`, "group_remove_member": `{"done":true}`, "group_delete": `{"done":true}`,
		"user_set": `{"changed":["title"]}`, "user_create": `{"id":"S-1-5-21-1-2-3-1106","sam":"bob","name":"Bob"}`,
		"group_create":        `{"id":"S-1-5-21-1-2-3-1107","sam":"G","name":"G"}`,
		"user_reset_password": `{"mustChange":true,"unlocked":false}`,
	}
	for _, a := range c.Actions() {
		short := strings.TrimPrefix(a.Name, "active_directory.")
		doc, ok := samples[short]
		if !ok {
			t.Errorf("no sample for %s", short)
			continue
		}
		line := winmod.ResultPrefix + `{"ok":true,"version":1,"data":` + doc + `,"error":null}`
		if _, err := a.ParseResult("noise\n" + line + "\n"); err != nil {
			t.Errorf("%s: %v", short, err)
		}
		extra := winmod.ResultPrefix + `{"ok":true,"version":1,"data":` + strings.Replace(doc, "{", `{"surprise":1,`, 1) + `,"error":null}`
		if _, err := a.ParseResult(extra); err == nil {
			t.Errorf("%s: a field the schema lacks was accepted", short)
		}
		for _, code := range []string{"protected_target", "service_account_confirmation_required", "read_only_dc", "module_missing", "access_denied", "not_found", "password_policy", "adws_unavailable", "conflict", "too_many", "partial", "not_enabled"} {
			r, err := a.ParseResult(winmod.ResultPrefix + `{"ok":false,"version":1,"data":null,"error":{"code":"` + code + `","message":"m"}}`)
			if err != nil || r.OK || r.Error.Code != code {
				t.Errorf("%s: %s: %v", short, code, err)
			}
		}
	}
	// The result of a reset has no place for a password.
	reset, _ := c.Lookup("active_directory.user_reset_password")
	if _, err := reset.ParseResult(winmod.ResultPrefix + `{"ok":true,"version":1,"data":{"mustChange":true,"unlocked":false,"password":"x"},"error":null}`); err == nil {
		t.Error("a reset result carrying a password was accepted")
	}
}

// A page of the largest size stays under the result limit the script
// enforces, with realistic rows.
func TestAPageFitsTheResultLimit(t *testing.T) {
	row := UserRow{ID: "S-1-5-21-1004336348-1177238915-682003330-1104", Sam: strings.Repeat("s", 20), Name: strings.Repeat("n", 40),
		UPN: strings.Repeat("u", 50) + "@corp.example.test", Enabled: true, Protection: Protection{Level: "none"}}
	page := UserPage{Scanned: 20000}
	for range MaxPage {
		page.Items = append(page.Items, row)
	}
	b, _ := json.Marshal(page)
	if len(b) > winmod.MaxResultBytes {
		t.Errorf("a page of %d rows is %d bytes, over %d; the script trims it, but the default page should fit", MaxPage, len(b), winmod.MaxResultBytes)
	}
}

func TestReplicationAlert(t *testing.T) {
	check := func(state string, failures int) json.RawMessage {
		b, _ := json.Marshal(Health{Checks: []Check{{Name: "replication", State: state}}, Replication: Replication{FailureCount: failures}})
		return b
	}
	for _, c := range []struct {
		state    string
		failures int
		holds    bool
		na, unk  bool
	}{{"ok", 0, false, false, false}, {"critical", 3, true, false, false}, {"warning", 0, false, false, false},
		{"not_applicable", 0, false, true, false}, {"could_not_run", 0, false, false, true}, {"unknown", 0, false, false, true}} {
		v, err := evalReplication(check(c.state, c.failures), nil)
		if (err != nil) != c.unk || v.Holds != c.holds || v.NotApplicable != c.na {
			t.Errorf("%s/%d: %+v, %v", c.state, c.failures, v, err)
		}
	}
	if _, err := evalReplication(json.RawMessage(`{"checks":[]}`), nil); err == nil {
		t.Error("a snapshot without the replication check is unknown, not healthy")
	}
	if _, err := evalReplication(json.RawMessage(`nonsense`), nil); err == nil {
		t.Error("garbage is unknown")
	}
}

func TestLockoutAndPrivilegedAlerts(t *testing.T) {
	three, one, hours := 3, 1, 24
	lock := func(n *int) json.RawMessage { b, _ := json.Marshal(Health{LockedOutCount: n}); return b }
	if v, err := evalLockedOut(lock(&three), &one); err != nil || !v.Holds {
		t.Errorf("3 locked out against 1: %+v %v", v, err)
	}
	if v, err := evalLockedOut(lock(&one), &three); err != nil || v.Holds {
		t.Errorf("1 locked out against 3: %+v %v", v, err)
	}
	if _, err := evalLockedOut(lock(nil), &one); err == nil {
		t.Error("a count the controller could not give is unknown")
	}
	now := time.Now().UTC()
	old, fresh := now.Add(-48*time.Hour), now.Add(-time.Hour)
	priv := func(tier int, at *time.Time) json.RawMessage {
		b, _ := json.Marshal(Privileged{Groups: []PrivilegedGroup{{Name: "Domain Admins", Tier: tier, ChangedAt: at}}})
		return b
	}
	for _, c := range []struct {
		tier  int
		at    *time.Time
		holds bool
	}{{1, &fresh, true}, {1, &old, false}, {2, &fresh, false}, {1, nil, false}} {
		v, err := evalPrivileged(priv(c.tier, c.at), &hours)
		if err != nil || v.Holds != c.holds || (v.Holds && strings.Contains(v.Detail, "member")) {
			t.Errorf("%+v: %+v %v", c, v, err)
		}
	}
	if _, err := evalPrivileged(json.RawMessage(`x`), &hours); err == nil {
		t.Error("garbage is unknown")
	}
}

// Tier 2 changes ask for the typed confirmation (not a step-up); tier 3 asks for both.
func TestTiers(t *testing.T) {
	c := catalog(t)
	for _, n := range []string{"user_set", "user_move", "group_create", "group_remove_member"} {
		a, _ := c.Lookup("active_directory." + n)
		if !a.Confirm || a.Subject == "" || a.NeedsStepUp() {
			t.Errorf("%s: tier 2 is a confirmation without a step-up", n)
		}
	}
	for _, n := range []string{"user_enable", "user_disable", "user_reset_password", "user_create", "user_delete", "group_add_member", "group_delete", "computer_disable"} {
		a, _ := c.Lookup("active_directory." + n)
		if !a.NeedsStepUp() || a.Subject == "" {
			t.Errorf("%s: tier 3 asks for a step-up and a typed confirmation", n)
		}
	}
	if a, _ := c.Lookup("active_directory.privileged_members"); !a.Sensitive || a.Schedule == 0 {
		t.Error("privileged_members is sensitive and read on a schedule")
	}
}
