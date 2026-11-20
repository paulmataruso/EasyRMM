package easypatch

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/easypatch/eptest"
)

func TestParseURL(t *testing.T) {
	good := map[string]string{
		"https://Patch.Example.com/":      "https://patch.example.com",
		" https://patch.example.com:8443": "https://patch.example.com:8443",
		"https://patch.example.com/ep//":  "https://patch.example.com/ep",
		"https://[2001:db8::1]:443":       "https://[2001:db8::1]:443",
	}
	for in, want := range good {
		u, err := ParseURL(in)
		if err != nil || u.String() != want {
			t.Errorf("ParseURL(%q) = %v, %v; want %s", in, u, err, want)
		}
	}
	bad := map[string]string{
		"":                                    "must be an address",
		"patch.example.com":                   "must be an address",
		"http://patch.example.com":            "must start with https://",
		"https://user:pw@patch.example.com":   "user name or password",
		"https://patch.example.com/?x=1":      "query or a fragment",
		"https://patch.example.com/#top":      "query or a fragment",
		"https://patch.example.com:99999":     "invalid port",
		"https://:443":                        "must be an address",
		"ftp://patch.example.com":             "must start with https://",
		"https://patch.example.com:0":         "invalid port",
		"https://patch.example.com:notaport/": "must be an address",
	}
	for in, want := range bad {
		if _, err := ParseURL(in); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("ParseURL(%q) = %v; want an error with %q", in, err, want)
		}
	}
}

func TestSameServer(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"https://patch.example.com/", "https://PATCH.example.com", true},
		{"https://patch.example.com:443", "https://patch.example.com", true},
		{"https://patch.example.com:8443", "https://patch.example.com", false},
		{"https://patch.example.com/a", "https://patch.example.com/b", false},
		{"https://patch.example.com", "http://patch.example.com", false},
		{"", "", false},
	}
	for _, c := range cases {
		if got := SameServer(c.a, c.b); got != c.want {
			t.Errorf("SameServer(%q, %q) = %v", c.a, c.b, got)
		}
	}
}

// clientKey signs the statements of the client tests.
var clientKey = bytes.Repeat([]byte{5}, 32)

// newTestClient starts an engine and a client for it.
func newTestClient(t *testing.T) (*eptest.Server, *Client) {
	t.Helper()
	f := eptest.NewEngine(t, clientKey)
	return f, engineClient(t, f.URL(), clientKey)
}

func TestClient(t *testing.T) {
	ctx := context.Background()
	f, c := newTestClient(t)
	org := f.Org("Acme Patch")
	e := f.AddEndpoint(org, "web-01", "SN1", "1FBB-E2EA-533D-A960")

	info, err := c.ServerInfo(ctx)
	if err != nil || info.Version != "1.9.0" || info.PublicURL != "https://patch.example.com" || info.Capabilities != nil {
		t.Fatalf("ServerInfo = %+v, %v", info, err)
	}
	if can, err := c.CanOperate(ctx); !can || err != nil {
		t.Fatalf("CanOperate = %v, %v", can, err)
	}
	f.Set(func() { f.ReadOnly = true })
	if can, err := c.CanOperate(ctx); can || err != nil {
		t.Fatalf("read-only CanOperate = %v, %v", can, err)
	}
	f.Set(func() { f.ReadOnly = false })

	orgs, err := c.Organizations(ctx)
	if err != nil || len(orgs) != 1 || orgs[0].ID != org || orgs[0].Name != "Acme Patch" || !orgs[0].IsActive {
		t.Fatalf("Organizations = %+v, %v", orgs, err)
	}
	p, err := c.Endpoints(ctx, org, 1)
	if err != nil || p.TotalCount != 1 || p.Items[0].ID != e.ID || p.Items[0].ComplianceStatus != "MissingUpdates" ||
		p.Items[0].LastScanAt == nil || p.Items[0].MissingTotalCount != 2 {
		t.Fatalf("Endpoints = %+v, %v", p, err)
	}
	d, err := c.Endpoint(ctx, e.ID)
	if err != nil || d.SerialNumber != "SN1" || len(d.Credentials) != 1 || d.Credentials[0].KeyFingerprint != "1FBB-E2EA-533D-A960" ||
		d.Summary.Hostname != "web-01" {
		t.Fatalf("Endpoint = %+v, %v", d, err)
	}
	if _, err := c.Endpoint(ctx, uuid.New()); !IsStatus(err, http.StatusNotFound) {
		t.Fatalf("missing endpoint: %v", err)
	}
	ups, err := c.Updates(ctx, e.ID, "Failed")
	if err != nil || len(ups) != 1 || ups[0].State != "Failed" || ups[0].ErrorMessage != "dpkg was interrupted" ||
		ups[0].Package == nil || ups[0].Package.Name != "tzdata" || ups[0].SizeBytes == nil {
		t.Fatalf("Updates = %+v, %v", ups, err)
	}
	if got := f.RequestsTo("GET", "/api/v1/endpoints/"+e.ID.String()+"/updates"); len(got) != 1 {
		t.Fatalf("updates requests = %+v", got)
	}
	inst, err := c.InstalledUpdates(ctx, e.ID)
	if err != nil || len(inst) != 1 || inst[0].InstalledAt == nil {
		t.Fatalf("InstalledUpdates = %+v, %v", inst, err)
	}
	h, err := c.History(ctx, e.ID, 1)
	if err != nil || h.TotalCount != 1 || h.Items[0].Result != "Succeeded" {
		t.Fatalf("History = %+v, %v", h, err)
	}
	pol, err := c.EffectivePolicy(ctx, e.ID)
	if err != nil || !pol.AutoInstallEnabled || pol.MaintenanceStart != "02:00" || pol.TimeZone != "Europe/Paris" ||
		pol.MaintenanceDurationMinutes == nil || *pol.MaintenanceDurationMinutes != 180 {
		t.Fatalf("EffectivePolicy = %+v, %v", pol, err)
	}

	// Install: every eligible update, or chosen ones, for a user.
	j, err := c.Install(ctx, e.ID, nil, nil, "tess@example.com")
	if err != nil || j.Type != "InstallUpdates" || j.Status != "Queued" {
		t.Fatalf("Install = %+v, %v", j, err)
	}
	guid := uuid.New()
	at := time.Now().Add(time.Hour).UTC().Truncate(time.Second)
	if _, err := c.Install(ctx, e.ID, []uuid.UUID{guid}, &at, ""); err != nil {
		t.Fatal(err)
	}
	reqs := f.RequestsTo("POST", "/api/v1/endpoints/"+e.ID.String()+"/install-updates")
	if len(reqs) != 2 || reqs[0].Statement.Name != "tess@example.com" || reqs[0].Body["mode"] != "AllEligible" ||
		reqs[0].Body["updateGuids"] != nil || reqs[0].Body["scheduledAt"] != nil || reqs[0].Body["force"] != false {
		t.Fatalf("first install = %+v", reqs)
	}
	if reqs[1].Statement.Name != "EasyRMM" || reqs[1].Body["mode"] != "Selected" || reqs[1].Body["scheduledAt"] != at.Format(time.RFC3339) ||
		reqs[1].Body["updateGuids"].([]any)[0] != guid.String() {
		t.Fatalf("second install = %+v", reqs[1])
	}
	f.Set(func() { e.Missing = 0 })
	_, err = c.Install(ctx, e.ID, nil, nil, "")
	var epErr *Error
	if !errors.As(err, &epErr) || epErr.Status != 409 || epErr.Code != "nothing_to_install" || epErr.Detail != "web-01 has no eligible updates." {
		t.Fatalf("nothing to install: %#v", err)
	}
	if err.Error() != "The patching engine answered 409: web-01 has no eligible updates." {
		t.Fatalf("message = %q", err.Error())
	}
	f.Set(func() { e.Missing = 2 })

	br, err := c.BulkScan(ctx, []uuid.UUID{e.ID, uuid.New()}, "tess@example.com")
	if err != nil || br.Succeeded != 1 || br.Failed != 1 || !br.Results[0].Success || br.Results[0].JobID == nil ||
		br.Results[1].ErrorCode != "not_found" {
		t.Fatalf("BulkScan = %+v, %v", br, err)
	}
	br, err = c.BulkInstall(ctx, []uuid.UUID{e.ID}, &at, "tess@example.com")
	if err != nil || br.Succeeded != 1 {
		t.Fatalf("BulkInstall = %+v, %v", br, err)
	}
	if r := f.RequestsTo("POST", "/api/v1/endpoints/bulk/install-updates"); r[0].Body["scheduledAt"] != at.Format(time.RFC3339) {
		t.Fatalf("bulk install body = %+v", r[0].Body)
	}

	jobs, err := c.Jobs(ctx, JobFilter{OrganizationID: org, Active: true}, 1)
	if err != nil || jobs.TotalCount != 4 {
		t.Fatalf("Jobs = %+v, %v", jobs, err)
	}
	ej, err := c.EndpointJobs(ctx, e.ID, 1)
	if err != nil || ej.TotalCount != 4 {
		t.Fatalf("EndpointJobs = %+v, %v", ej, err)
	}
	jd, err := c.Job(ctx, jobs.Items[0].ID)
	if err != nil || len(jd.Items) != 1 || len(jd.Events) != 1 || jd.NotBefore == nil {
		t.Fatalf("Job = %+v, %v", jd, err)
	}
	jd, err = c.CancelJob(ctx, jobs.Items[0].ID, "tess@example.com")
	if err != nil || jd.Summary.Status != eptest.StatusCanceled || !jd.Summary.CancelRequested || jd.Summary.CompletedAt == nil {
		t.Fatalf("CancelJob = %+v, %v", jd, err)
	}
}

func TestClientFailures(t *testing.T) {
	ctx := context.Background()
	f, c := newTestClient(t)

	// Statements signed with another key.
	_, err := engineClient(t, f.URL(), bytes.Repeat([]byte{6}, 32)).ServerInfo(ctx)
	if !IsStatus(err, http.StatusUnauthorized) || !strings.Contains(err.Error(), "statement from EasyRMM is not valid") {
		t.Fatalf("another key: %v", err)
	}

	// The engine down.
	f.Set(func() { f.Down = true })
	if _, err := c.Organizations(ctx); !IsStatus(err, 503) || !strings.Contains(err.Error(), "database is not available") {
		t.Fatalf("down: %v", err)
	}
	f.Set(func() { f.Down = false })

	// Odd answers are refused, and a problem without a detail is given one.
	odd := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/organizations":
			_, _ = w.Write([]byte(`{"not":"a list"}`))
		case "/api/v1/endpoints/" + uuid.Nil.String():
			w.WriteHeader(http.StatusForbidden)
		case "/api/v1/server-info":
			w.WriteHeader(http.StatusUnauthorized)
		default:
			w.WriteHeader(http.StatusTeapot)
			_, _ = w.Write([]byte(`{"title":"` + strings.Repeat("é", 400) + `"}`))
		}
	}))
	defer odd.Close()
	c = engineClient(t, odd.URL, clientKey)
	if _, err := c.Organizations(ctx); err == nil || !strings.Contains(err.Error(), "not what EasyRMM expects") {
		t.Fatalf("odd answer: %v", err)
	}
	if _, err := c.Endpoint(ctx, uuid.Nil); !IsStatus(err, 403) || !strings.Contains(err.Error(), "may not do this") {
		t.Fatalf("forbidden: %v", err)
	}
	if _, err := c.ServerInfo(ctx); !IsStatus(err, 401) || !strings.Contains(err.Error(), "EASYRMM_PATCHING_KEY") {
		t.Fatalf("unauthorized: %v", err)
	}
	_, err = c.Job(ctx, uuid.New())
	var e *Error
	if !errors.As(err, &e) || len(e.Detail) > 500 || !strings.HasPrefix(e.Detail, "éé") || strings.ContainsRune(e.Detail, '�') {
		t.Fatalf("long problem: %q", e.Detail)
	}
}

func TestEPError(t *testing.T) {
	cases := []struct {
		err  error
		kind apperr.Kind
		code string
	}{
		{&Error{Detail: "Cannot reach the patching engine"}, apperr.KindUnavailable, "patching_unavailable"},
		{&Error{Status: 502, Detail: "bad gateway"}, apperr.KindUnavailable, "patching_unavailable"},
		{&Error{Status: 401, Detail: "expired"}, apperr.KindUnavailable, "patching_unavailable"},
		{&Error{Status: 404, Detail: "gone"}, apperr.KindNotFound, "not_found"},
		{&Error{Status: 409, Code: "duplicate_job", Detail: "already queued"}, apperr.KindConflict, "duplicate_job"},
		{&Error{Status: 400, Detail: "bad"}, apperr.KindConflict, "easypatch_refused"},
	}
	for _, c := range cases {
		var ae *apperr.Error
		if !errors.As(epError(c.err), &ae) || ae.Kind != c.kind || ae.Code != c.code {
			t.Errorf("epError(%v) = %#v", c.err, ae)
		}
	}
	plain := errors.New("plain")
	if !errors.Is(epError(plain), plain) {
		t.Error("a plain error changed")
	}
}

func TestHelpers(t *testing.T) {
	if cut("héllo", 2) != "h" || cut("abc", 5) != "abc" {
		t.Error("cut")
	}
	if shortHost(" Web-01.corp.example.com ") != "web-01" || shortHost("web-01") != "web-01" {
		t.Error("shortHost")
	}
	if likePattern("") != "" || likePattern(" a%b_c\\ ") != `%a\%b\_c\\%` {
		t.Errorf("likePattern = %q", likePattern(" a%b_c\\ "))
	}
	now := time.Now()
	creds := []Credential{{KeyFingerprint: "AAAA"}, {KeyFingerprint: "BBBB", RevokedAt: &now}}
	if !holdsKey(creds, "aaaa") || holdsKey(creds, "BBBB") || holdsKey(creds, " ") {
		t.Error("holdsKey")
	}
}

func TestDue(t *testing.T) {
	now := time.Now()
	ep := uuid.New()
	old := now.Add(-7 * time.Hour)
	recent := now.Add(-time.Minute)
	base := func() candidate {
		return candidate{hasRow: true, state: LinkLinked, endpointID: &ep, fingerprint: "AAAA", checkedAt: &recent,
			report: &agentproto.EasyPatchAgent{KeyFingerprint: "aaaa"}}
	}
	cases := []struct {
		name string
		edit func(*candidate)
		id   *uuid.UUID
		want bool
	}{
		{"fresh link", func(*candidate) {}, &ep, false},
		{"new device", func(c *candidate) { c.hasRow = false }, &ep, true},
		{"pending", func(c *candidate) { c.state = LinkPending }, &ep, true},
		{"never checked", func(c *candidate) { c.checkedAt = nil }, &ep, true},
		{"endpoint changed", func(*candidate) {}, ptr(uuid.New()), true},
		{"fingerprint changed", func(c *candidate) { c.report.KeyFingerprint = "BBBB" }, &ep, true},
		{"old link", func(c *candidate) { c.checkedAt = &old }, &ep, true},
		{"recently refused", func(c *candidate) { c.state = LinkUnlinked }, &ep, false},
		{"refused a while ago", func(c *candidate) { c.state = LinkUnlinked; t := now.Add(-20 * time.Minute); c.checkedAt = &t }, &ep, true},
	}
	for _, c := range cases {
		cd := base()
		c.edit(&cd)
		if got := cd.due(now, c.id); got != c.want {
			t.Errorf("%s: due = %v", c.name, got)
		}
	}
}

func ptr[T any](v T) *T { return &v }
