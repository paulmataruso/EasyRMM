// Package eptest serves the part of the patching engine's API that EasyRMM
// uses, for tests, the way net/http/httptest serves HTTP. Its answers have
// the field names and shapes EasyPatch's server sends, recorded from a real
// one and held to it by the contract test; it keeps endpoints, updates and
// jobs in memory.
package eptest

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
)

// StatusCanceled is EasyPatch's status of a canceled job, spelled as its API
// spells it.
const StatusCanceled = "Cancelled" //nolint:misspell // EasyPatch's enum value

// EngineVersion is the version the server reports: <Version> in
// easypatch/Directory.Build.props, the engine EasyRMM ships with.
const EngineVersion = "1.11.1"

// Server is a fake patching engine: plain HTTP on loopback, as in
// EasyRMM's deployment. Change its state inside Set.
type Server struct {
	srv *httptest.Server

	mu sync.Mutex
	// Version is what server-info reports, and PublicURL the address it
	// gives agents (https://patch.example.com).
	Version   string
	PublicURL string
	// ReadOnly has the engine take every statement as a ReadOnly one, as
	// when it does not let EasyRMM act as an administrator: what changes
	// something answers 403.
	ReadOnly bool
	// key checks statements.
	key []byte
	// readOnlyCall is whether the request being served may only read.
	readOnlyCall bool
	// Down makes every call answer 503.
	Down bool
	// LoseReply, when it returns true for a call, has the server do the
	// call and then answer 502, as when the connection drops after
	// EasyPatch saved the change: the caller cannot tell it happened.
	LoseReply func(method, path string) bool

	// Packages is what agent-packages lists; NewEngine fills in the
	// engine's own, and one older Windows package.
	Packages []map[string]any

	orgs      []*OrgInfo
	sites     []*SiteInfo
	endpoints map[uuid.UUID]*Endpoint
	jobs      []*Job
	tokens    []*Token
	holds     []*HoldInfo
	requests  []Request
	// policies are the levels' policies, by policyKey; tags the tags, and
	// tagged an organization's, site's or endpoint's own tags.
	policies map[string]map[string]any
	tags     []*TagInfo
	tagged   map[uuid.UUID][]uuid.UUID
	// The reports (reports.go): each organization's daily compliance, the
	// updates jobs finished with, monthly reports, their schedules, and
	// the mail settings they are emailed with.
	trend         map[uuid.UUID][]TrendDay
	installations []*InstallationInfo
	reports       []*ReportInfo
	schedules     map[uuid.UUID]*ScheduleInfo
	mail          map[string]any
	// Server-wide settings (settings.go): server settings, vulnerability
	// feeds, OS lifecycle entries and the audit log.
	settings  map[string]any
	feeds     []map[string]any
	lifecycle []*LifecycleInfo
	audit     []*AuditInfo
	auditSeq  int64
	// Alerts and notifications (alerts.go): alerts, their rules (EasyPatch's
	// own, added at first use), channels and deliveries.
	alerts      []*AlertInfo
	rules       []*RuleInfo
	rulesSeeded bool
	channels    []*ChannelInfo
	deliveries  []*DeliveryInfo
}

// Token is an enrollment token EasyPatch created.
type Token struct {
	ID, Org     uuid.UUID
	Site        *uuid.UUID
	Description string
	Secret      string
	MaxUses     int
	ExpiresIn   int
	Revoked     bool
}

// Endpoint is an EasyPatch endpoint.
type Endpoint struct {
	ID, Org     uuid.UUID
	OrgName     string
	Hostname    string
	Serial      string
	Status      string
	Compliance  string
	Missing     int
	Fingerprint string
	Revoked     bool
	// Site is the endpoint's site, if any; Notes and Esu what its update
	// keeps.
	Site     *uuid.UUID
	SiteName string
	Notes    *string
	Esu      string
	// CannotUninstall is an agent older than 1.6.0, which cannot remove
	// itself.
	CannotUninstall bool
	// RebootPending, IsServer and CannotRestart describe a pending restart
	// as the engine's restart-pending list shows it.
	RebootPending  bool
	IsServer       bool
	CannotRestart  bool
	Updates        []map[string]any
	InstalledItems []map[string]any
	// Windows makes the endpoint a Windows one, whose agent shows messages
	// and removes updates; the others are Linux endpoints, which cannot.
	Windows bool
}

// Job is an EasyPatch job.
type Job struct {
	ID, Endpoint, Org uuid.UUID
	Hostname, Type    string
	Status            string
	CreatedAt         time.Time
	NotBefore         *time.Time
	// RetryOf is the job this one retries.
	RetryOf *uuid.UUID
}

// Request is a call the server received.
type Request struct {
	Method, Path string
	Body         map[string]any
	// Statement is what EasyRMM's statement said; nil for a statement that
	// was refused.
	Statement *Statement
}

// Statement is what a valid statement from EasyRMM said (ADR-0038).
type Statement struct {
	Subject, Name, Role string
	// AllOrganizations is "orgs": "*"; otherwise Organizations lists them.
	AllOrganizations bool
	Organizations    []uuid.UUID
}

// newServer is a server's state, with the engine's packages.
func newServer() *Server {
	s := &Server{Version: EngineVersion, PublicURL: "https://patch.example.com", endpoints: map[uuid.UUID]*Endpoint{}}
	v := EngineVersion
	for _, p := range []struct {
		version, arch, format string
		latest                bool
	}{
		{v, "x64", "msi", true}, {"1.8.2", "x64", "msi", false}, {v, "x64", "deb", true}, {v, "x64", "rpm", true},
		{v, "arm64", "deb", true}, {v, "arm64", "rpm", true}, {v, "arm64", "pkg", true},
	} {
		s.Packages = append(s.Packages, Package(fmt.Sprintf("EasyPatchAgent-%s-%s.%s", p.version, p.arch, p.format), p.version, p.arch, p.format, p.latest))
	}
	return s
}

// NewEngine starts a server that answers as the patching engine in
// EasyRMM's deployment does: plain HTTP on loopback, each request with a
// statement signed with key. A statement must be signed with the key and
// made for the request, and it must not have expired; a ReadOnly one may
// only read. The server is closed when the test ends.
func NewEngine(t testing.TB, key []byte) *Server {
	t.Helper()
	s := newServer()
	s.key = append([]byte(nil), key...)
	s.srv = httptest.NewServer(http.HandlerFunc(s.handle)) // 127.0.0.1
	t.Cleanup(s.srv.Close)
	return s
}

// handle serves a call, losing its reply when LoseReply says to.
func (s *Server) handle(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	lose := s.LoseReply != nil && s.LoseReply(r.Method, r.URL.Path)
	s.mu.Unlock()
	if !lose {
		s.serve(w, r)
		return
	}
	s.serve(httptest.NewRecorder(), r)
	problem(w, http.StatusBadGateway, "", "The connection was lost.")
}

// statement checks a request's statement as the engine does, minus its
// tenant rules, which the contract tests check against the real engine.
func (s *Server) statement(r *http.Request) *Statement {
	parts := strings.Split(r.Header.Get("X-EasyRMM-Assertion"), ".")
	if len(parts) != 3 {
		return nil
	}
	mac := hmac.New(sha256.New, s.key)
	mac.Write([]byte(parts[0] + "." + parts[1]))
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || !hmac.Equal(sig, mac.Sum(nil)) {
		return nil
	}
	header, err1 := base64.RawURLEncoding.DecodeString(parts[0])
	payload, err2 := base64.RawURLEncoding.DecodeString(parts[1])
	var h struct{ Alg, Typ string }
	var c struct {
		Iss, Aud, Sub, Name, Role, Htm, Htu string
		Orgs                                json.RawMessage
		Iat, Exp                            int64
	}
	if err1 != nil || err2 != nil || json.Unmarshal(header, &h) != nil || json.Unmarshal(payload, &c) != nil ||
		h.Alg != "HS256" || h.Typ != "easyrmm-gateway+jwt" || c.Iss != "easyrmm" || c.Aud != "easypatch" ||
		c.Htm != r.Method || c.Htu != r.URL.RequestURI() || time.Now().Unix() >= c.Exp+5 || c.Exp-c.Iat > 60 {
		return nil
	}
	st := &Statement{Subject: c.Sub, Name: c.Name, Role: c.Role}
	if string(c.Orgs) == `"*"` {
		st.AllOrganizations = true
	} else if json.Unmarshal(c.Orgs, &st.Organizations) != nil {
		return nil
	}
	return st
}

// URL is the server's address.
func (s *Server) URL() string { return s.srv.URL }

// Set changes the server's state while no request reads it.
func (s *Server) Set(fn func()) {
	s.mu.Lock()
	defer s.mu.Unlock()
	fn()
}

// Package describes an agent package as agent-packages lists it, with a
// SHA-256 made from its name, in capitals as EasyPatch writes it.
func Package(file, version, arch, format string, latest bool) map[string]any {
	return map[string]any{"fileName": file, "version": version, "architecture": arch, "sizeBytes": 4096 + len(file),
		"sha256": strings.ToUpper(fmt.Sprintf("%064x", len(file)*7919)), "modifiedAt": "2026-11-02T10:00:00+00:00",
		"downloadUrl": "/downloads/agent/" + file, "isLatest": latest, "releaseKeyId": nil, "signatureProblem": nil, "format": format}
}

// Site adds a site to an organization.
func (s *Server) Site(org uuid.UUID, name string) uuid.UUID {
	s.mu.Lock()
	defer s.mu.Unlock()
	id := uuid.New()
	tz := "UTC"
	if o := s.org(org); o != nil {
		tz = o.TimeZone
	}
	s.sites = append(s.sites, &SiteInfo{ID: id, Org: org, Name: name, TimeZone: tz, Active: true})
	return id
}

// Tokens lists the enrollment tokens created, oldest first.
func (s *Server) Tokens() []Token {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Token, 0, len(s.tokens))
	for _, t := range s.tokens {
		out = append(out, *t)
	}
	return out
}

// Org adds an organization.
func (s *Server) Org(name string) uuid.UUID {
	s.mu.Lock()
	defer s.mu.Unlock()
	id := uuid.New()
	s.orgs = append(s.orgs, &OrgInfo{ID: id, Name: name, TimeZone: "UTC", Active: true})
	return id
}

// AddEndpoint adds an active endpoint with two missing updates (one failed)
// and one installed.
func (s *Server) AddEndpoint(org uuid.UUID, hostname, serial, fingerprint string) *Endpoint {
	s.mu.Lock()
	defer s.mu.Unlock()
	name := ""
	if o := s.org(org); o != nil {
		name = o.Name
	}
	e := &Endpoint{ID: uuid.New(), Org: org, OrgName: name, Hostname: hostname, Serial: serial, Status: "Active",
		Compliance: "MissingUpdates", Missing: 2, Fingerprint: fingerprint, Esu: "Auto"}
	// In the organization's first site, as an enrollment token for it puts
	// it.
	if i := slices.IndexFunc(s.sites, func(x *SiteInfo) bool { return x.Org == org && x.Active }); i >= 0 {
		e.Site, e.SiteName = &s.sites[i].ID, s.sites[i].Name
	}
	e.Updates = []map[string]any{
		update("openssl 3.5.7-1~deb13u3", "Security", "Missing"),
		update("tzdata 2026c-0+deb13u1", "Other", "Failed"),
	}
	e.InstalledItems = []map[string]any{update("libc6 2.41-12+deb13u1", "Security", "Installed")}
	s.endpoints[e.ID] = e
	return e
}

// RemoveEndpoint deletes an endpoint, as deleting it in EasyPatch does.
func (s *Server) RemoveEndpoint(id uuid.UUID) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.endpoints, id)
}

// Jobs lists the jobs, oldest first.
func (s *Server) Jobs() []Job {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Job, 0, len(s.jobs))
	for _, j := range s.jobs {
		out = append(out, *j)
	}
	return out
}

// SetJobStatus changes a job's status, as its agent's reports would. An
// uninstall that completes unenrolls its endpoint, as the agent does.
func (s *Server) SetJobStatus(id uuid.UUID, status string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, j := range s.jobs {
		if j.ID == id {
			j.Status = status
			if e := s.endpoints[j.Endpoint]; e != nil && j.Type == "UninstallAgent" && status == "Completed" {
				e.Status = "Decommissioned"
			}
		}
	}
}

// RequestsTo lists the calls of a method to a path.
func (s *Server) RequestsTo(method, path string) []Request {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []Request
	for _, r := range s.requests {
		if r.Method == method && r.Path == path {
			out = append(out, r)
		}
	}
	return out
}

func update(title, category, state string) map[string]any {
	name, version, _ := strings.Cut(title, " ")
	u := map[string]any{
		"updateGuid": UpdateGUID(title), "revisionNumber": 1, "title": title, "description": nil, "kbNumber": nil, "kbNumbers": []string{},
		"category": category, "msClassification": nil, "msrcSeverity": nil, "releaseDate": "2026-11-10T00:00:00+00:00",
		"sizeBytes": 1543210, "rebootLikely": false, "supportUrl": nil, "state": state, "isRequired": category == "Security",
		"isExcluded": false, "firstDetectedAt": "2026-11-15T10:00:00+00:00", "stateChangedAt": "2026-11-16T10:00:00+00:00",
		"installedAt": nil, "failedAttempts": 0, "errorCode": nil, "errorMessage": nil, "activeJob": nil,
		"package": map[string]any{"name": name, "architecture": "amd64", "version": version, "installedVersion": "3.5.6-1",
			"repository": "trixie-security", "advisories": []string{"DSA-6001-1"}},
		"deferredUntil": nil, "cveIds": []string{"CVE-2026-1234"}, "knownExploited": false, "kevDueDate": nil, "holdReason": nil,
	}
	switch state {
	case "Failed":
		u["failedAttempts"], u["errorCode"], u["errorMessage"] = 1, "apt_exit_100", "dpkg was interrupted"
	case "Installed":
		u["installedAt"] = "2026-11-14T03:00:00+00:00"
	}
	return u
}

func (e *Endpoint) summary() map[string]any {
	platform, os, version, build, support := "Linux", "Debian GNU/Linux 13 (trixie)", "13", any(nil), "Unknown"
	if e.Windows {
		platform, os, version, build, support = "Windows", "Windows Server 2025 Standard", "10.0.26100", "26100.2314", "Supported"
	}
	return map[string]any{
		"id": e.ID, "hostname": e.Hostname, "organizationId": e.Org, "organizationName": e.OrgName,
		"siteId": e.Site, "siteName": nullable(e.SiteName), "status": e.Status, "operatingSystem": os,
		"osVersion": version, "osBuild": build, "architecture": "X64", "agentVersion": "1.9.0", "agentOutdated": false, "isOnline": true,
		"lastCheckInAt": "2026-11-16T14:34:13.737582+00:00", "lastScanAt": "2026-11-16T14:40:00+00:00",
		"complianceStatus": e.Compliance, "missingRequiredCount": 1, "missingTotalCount": e.Missing, "failedCount": 1,
		"rebootPending": e.RebootPending, "osSupportStatus": support, "currentActivity": "Idle", "lastSeenIp": "192.0.2.10",
		"platform": platform, "missingDeferredCount": 0, "tags": []any{}, "knownExploitedMissingCount": 0,
	}
}

func (e *Endpoint) detail() map[string]any {
	var revoked any
	if e.Revoked {
		revoked = "2026-11-16T15:00:00+00:00"
	}
	var serial any
	if e.Serial != "" {
		serial = e.Serial
	}
	// As agents 1.9.0 report them: Linux agents have no tray.
	capabilities := []string{"restart", "self-update", "uninstall"}
	if e.CannotRestart {
		capabilities = capabilities[1:]
	}
	format, users, product := "deb", any(nil), any(nil)
	switch {
	case e.IsServer:
		product = "Server"
	case e.Windows:
		product = "Workstation"
	}
	if e.Windows {
		capabilities = append(capabilities, "notify-user", "tray", "windows-update-policy", "app-updates", "uninstall-updates", "download-updates")
		format, users = "msi", 1
	}
	var restart, since any
	if e.RebootPending {
		since = "2026-11-16T14:40:00+00:00"
		restart = map[string]any{"updates": []map[string]any{{"updateGuid": nil, "title": "linux-image-6.12.57+deb13-amd64",
			"kbNumbers": []string{}, "source": "Installed", "installedAt": "2026-11-16T14:39:00+00:00"}},
			"servicingPackages": []string{}, "fileOperations": []map[string]any{}, "fileOperationCount": 0, "detailsSupported": false}
	}
	return map[string]any{
		"summary": e.summary(), "dnsDomain": nil, "osProductType": product, "serialNumber": serial, "manufacturer": "QEMU",
		"lastScanAttemptAt": "2026-11-16T14:40:00+00:00", "lastScanError": nil, "rebootReasons": []string{},
		"rebootPendingSince": since, "installedCount": len(e.InstalledItems), "pendingRebootUpdateCount": 0,
		"complianceEvaluatedAt": "2026-11-16T14:40:01+00:00", "notes": e.Notes, "esuOverride": e.Esu,
		"credentials": []map[string]any{{"credentialId": "c_test", "keyFingerprint": e.Fingerprint, "createdAt": "2026-11-16T14:34:05+00:00",
			"expiresAt": "2027-11-16T14:34:05+00:00", "revokedAt": revoked, "revokedReason": nil, "lastUsedAt": nil}},
		"activeJob": nil, "agentCapabilities": capabilities, "signedInUsers": users, "trayConnectedSessions": users, "hasOwnPolicy": false,
		"agentUpdate": map[string]any{"supported": true, "architecture": "x64", "releaseKeyIds": []string{"easypatch-release-2026"},
			"automaticUpdates": true, "availableVersion": nil, "code": "agent_up_to_date",
			"message": "The agent already runs the newest package for its platform.", "packageFormat": format},
		"restart": restart, "windowsUpdatePolicy": nil, "windowsUpdatePolicyReportedAt": nil,
	}
}

func (j *Job) summary() map[string]any {
	var completed any
	if j.Status == "Completed" || j.Status == StatusCanceled {
		completed = "2026-11-16T15:10:00+00:00"
	}
	return map[string]any{
		"id": j.ID, "endpointId": j.Endpoint, "hostname": j.Hostname, "organizationId": j.Org, "organizationName": "Acme Patch",
		"type": j.Type, "status": j.Status, "trigger": "Manual", "requestedBy": "token:easyrmm", "createdAt": j.CreatedAt,
		"startedAt": nil, "completedAt": completed, "expiresAt": j.CreatedAt.Add(7 * 24 * time.Hour), "progressPercent": nil,
		"phase": nil, "progressMessage": nil, "errorCode": nil, "errorMessage": nil, "rebootRequired": false, "timedOut": false,
		"cancelRequested": j.Status == StatusCanceled, "itemCount": 0, "succeededCount": 0, "failedCount": 0,
	}
}

func (j *Job) detail() map[string]any {
	return map[string]any{
		"summary": j.summary(), "installMode": nil, "notBefore": j.NotBefore, "deliveredAt": nil, "acknowledgedAt": nil,
		"lastProgressAt": nil, "deliveryCount": 0, "retryOfJobId": nil, "cancelRequestedAt": nil,
		"items": []map[string]any{{"updateGuid": uuid.New(), "title": "openssl", "kbNumber": nil, "category": "Security",
			"status": "Pending", "skipReason": nil, "resultCode": nil, "errorCode": nil, "errorMessage": nil, "rebootRequired": false,
			"downloadPercent": nil, "installPercent": nil, "startedAt": nil, "completedAt": nil}},
		"events": []map[string]any{{"id": 1, "endpointId": j.Endpoint, "hostname": j.Hostname, "type": "JobCreated",
			"severity": "Info", "message": "Job queued.", "jobId": j.ID, "createdAt": j.CreatedAt}},
	}
}

func problem(w http.ResponseWriter, status int, code, detail string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"type": "about:blank", "title": http.StatusText(status), "status": status,
		"detail": detail, "code": code, "correlationId": "0HTEST"})
}

func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func jsonEncode(w io.Writer, v any) error { return json.NewEncoder(w).Encode(v) }

func reply(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func paged[T any](items []T, page, size int) map[string]any {
	total := len(items)
	lo := min((page-1)*size, total)
	hi := min(lo+size, total)
	return map[string]any{"items": items[lo:hi], "page": page, "pageSize": size, "totalCount": total}
}

func (s *Server) serve(w http.ResponseWriter, r *http.Request) {
	var body map[string]any
	if r.Body != nil {
		_ = json.NewDecoder(r.Body).Decode(&body)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.requests = append(s.requests, Request{Method: r.Method, Path: r.URL.Path, Body: body})
	if s.Down {
		problem(w, http.StatusServiceUnavailable, "", "The database is not available.")
		return
	}
	st := s.statement(r)
	if st == nil {
		problem(w, http.StatusUnauthorized, "unauthenticated", "The statement from EasyRMM is not valid.")
		return
	}
	s.requests[len(s.requests)-1].Statement = st
	s.readOnlyCall = s.ReadOnly || st.Role == "ReadOnly"
	q := r.URL.Query()
	pg, _ := strconv.Atoi(q.Get("page"))
	pg = max(pg, 1)
	size, _ := strconv.Atoi(q.Get("pageSize"))
	if size == 0 {
		size = 50
	}
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/v1/"), "/")
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/api/v1/server-info":
		reply(w, 200, map[string]any{"version": s.Version, "publicUrl": s.PublicURL, "serverTime": time.Now().UTC()})
	case r.Method == http.MethodGet && r.URL.Path == "/api/v1/enrollment-tokens":
		if s.readOnlyCall {
			problem(w, 403, "", "")
			return
		}
		reply(w, 200, []any{})
	case r.Method == http.MethodPost && r.URL.Path == "/api/v1/enrollment-tokens":
		s.createToken(w, body)
	case parts[0] == "enrollment-tokens" && len(parts) == 3 && parts[2] == "revoke" && r.Method == http.MethodPost:
		id, _ := uuid.Parse(parts[1])
		i := slices.IndexFunc(s.tokens, func(t *Token) bool { return t.ID == id })
		if i < 0 {
			problem(w, 404, "not_found", "Enrollment token not found.")
			return
		}
		s.tokens[i].Revoked = true
		w.WriteHeader(http.StatusNoContent)
	case r.Method == http.MethodGet && r.URL.Path == "/api/v1/agent-packages":
		reply(w, 200, s.Packages)
	case r.Method == http.MethodGet && r.URL.Path == "/api/v1/user-messages":
		reply(w, 200, messagePresets())
	case parts[0] == "policies" && len(parts) == 2 && parts[1] == "global":
		s.servePolicy(w, r, ScopeGlobal, uuid.Nil, body)
	case parts[0] == "tags":
		s.serveTags(w, r, parts, body)
	case parts[0] == "reports":
		s.serveReports(w, r, parts, q, pg, size)
	case parts[0] == "monthly-reports":
		s.serveMonthlyReports(w, r, parts, body, q, pg, size)
	case parts[0] == "notifications" && len(parts) == 2 && parts[1] == "settings":
		s.serveMail(w, r, body)
	case parts[0] == "notifications" && len(parts) >= 2 && parts[1] == "channels" && len(parts) <= 4:
		s.serveChannels(w, r, parts, body)
	case r.Method == http.MethodGet && r.URL.Path == "/api/v1/notifications/deliveries":
		s.serveDeliveries(w, q, pg, size)
	case parts[0] == "alerts" && len(parts) <= 2:
		s.serveAlerts(w, r, parts, q, body, pg, size)
	case parts[0] == "alert-rules" && len(parts) <= 2:
		s.serveAlertRules(w, r, parts, body)
	case parts[0] == "settings" && len(parts) == 1:
		s.serveSettings(w, r, body)
	case r.Method == http.MethodGet && r.URL.Path == "/api/v1/vulnerability-feeds":
		s.serveFeeds(w)
	case parts[0] == "lifecycle" && len(parts) <= 2:
		s.serveLifecycle(w, r, parts, body)
	case r.Method == http.MethodGet && r.URL.Path == "/api/v1/audit-logs":
		s.serveAudit(w, q, pg, size)
	case parts[0] == "organizations" && len(parts) == 3 && parts[2] == "report-schedule":
		id, _ := uuid.Parse(parts[1])
		o := s.org(id)
		if o == nil {
			problem(w, 404, "not_found", "Organization was not found.")
			return
		}
		s.serveSchedule(w, r, o, body)
	case (parts[0] == "organizations" || parts[0] == "sites") && len(parts) == 3 && (parts[2] == "policy" || parts[2] == "tags"):
		s.serveLevel(w, r, parts, body)
	case parts[0] == "organizations":
		s.serveOrganizations(w, r, parts, body)
	case parts[0] == "sites" && len(parts) >= 2:
		s.serveSite(w, r, parts, body)
	case r.Method == http.MethodGet && r.URL.Path == "/api/v1/endpoints":
		org, _ := uuid.Parse(q.Get("organizationId"))
		var list []map[string]any
		for _, e := range s.sorted() {
			if e.Org == org && e.Status == "Active" {
				list = append(list, e.summary())
			}
		}
		reply(w, 200, paged(list, pg, size))
	case parts[0] == "endpoints" && len(parts) == 3 && parts[1] == "bulk" && r.Method == http.MethodPost:
		s.bulk(w, parts[2], body)
	case parts[0] == "endpoints" && len(parts) >= 2:
		id, _ := uuid.Parse(parts[1])
		e := s.endpoints[id]
		if e == nil {
			problem(w, 404, "not_found", "Endpoint not found.")
			return
		}
		s.serveEndpoint(w, r, e, strings.Join(parts[2:], "/"), body, pg)
	case parts[0] == "updates":
		s.serveFleet(w, r, parts[1:], body, q, pg, size)
	case parts[0] == "update-holds":
		s.serveHolds(w, r, parts[1:], q)
	case r.Method == http.MethodGet && r.URL.Path == "/api/v1/jobs":
		org, _ := uuid.Parse(q.Get("organizationId"))
		endpoint, _ := uuid.Parse(q.Get("endpointId"))
		from, _ := time.Parse(time.RFC3339, q.Get("from"))
		to, _ := time.Parse(time.RFC3339, q.Get("to"))
		var list []map[string]any
		for i := len(s.jobs) - 1; i >= 0; i-- {
			j := s.jobs[i]
			active := j.Status == "Queued" || j.Status == "Running"
			switch {
			case j.Org != org, q.Get("active") == "true" && !active,
				endpoint != uuid.Nil && j.Endpoint != endpoint,
				q.Get("status") != "" && j.Status != q.Get("status"),
				q.Get("type") != "" && j.Type != q.Get("type"),
				// Every job of the fake is started by hand.
				q.Get("trigger") != "" && q.Get("trigger") != "Manual",
				!from.IsZero() && j.CreatedAt.Before(from),
				!to.IsZero() && !j.CreatedAt.Before(to):
				continue
			}
			list = append(list, j.summary())
		}
		reply(w, 200, paged(list, pg, size))
	case parts[0] == "jobs" && len(parts) >= 2:
		id, _ := uuid.Parse(parts[1])
		i := slices.IndexFunc(s.jobs, func(j *Job) bool { return j.ID == id })
		if i < 0 {
			problem(w, 404, "not_found", "Job not found.")
			return
		}
		j := s.jobs[i]
		if len(parts) == 3 && parts[2] == "retry" && r.Method == http.MethodPost {
			s.retry(w, j)
			return
		}
		if len(parts) == 3 && parts[2] == "cancel" && r.Method == http.MethodPost {
			if j.Status == "Completed" || j.Status == StatusCanceled {
				problem(w, 409, "job_finished", "The job has finished.")
				return
			}
			j.Status = StatusCanceled
		}
		reply(w, 200, j.detail())
	default:
		problem(w, 404, "not_found", "No such route: "+r.URL.Path)
	}
}

// createToken answers POST /api/v1/enrollment-tokens as EasyPatch does,
// with each token's plaintext once.
func (s *Server) createToken(w http.ResponseWriter, body map[string]any) {
	if s.readOnlyCall {
		problem(w, 403, "", "")
		return
	}
	org, err := uuid.Parse(fmt.Sprint(body["organizationId"]))
	hours, _ := body["expiresInHours"].(float64)
	uses, _ := body["maxUses"].(float64)
	count, _ := body["count"].(float64)
	desc, _ := body["description"].(string)
	o := s.org(org)
	if err != nil || o == nil {
		problem(w, 404, "not_found", "Organization not found.")
		return
	}
	if !o.Active {
		problem(w, 409, "archived", "The organization is archived.")
		return
	}
	if hours < 1 || hours > 720 || uses < 1 || uses > 1000 || count < 1 || count > 100 || len(desc) > 500 {
		problem(w, 400, "validation_failed", "One or more fields are invalid.")
		return
	}
	var site *uuid.UUID
	if v, ok := body["siteId"].(string); ok {
		id, err := uuid.Parse(v)
		if x := s.site(id); err != nil || x == nil || x.Org != org || !x.Active {
			problem(w, 400, "validation_failed", "The site does not belong to the organization or is archived.")
			return
		}
		site = &id
	}
	out := []map[string]any{}
	for range int(count) {
		t := &Token{ID: uuid.New(), Org: org, Site: site, Description: desc, MaxUses: int(uses), ExpiresIn: int(hours),
			Secret: "ept_" + strings.ReplaceAll(uuid.NewString(), "-", "")}
		s.tokens = append(s.tokens, t)
		out = append(out, map[string]any{
			"token": map[string]any{"id": t.ID, "organizationId": org, "organizationName": "", "siteId": site, "siteName": nil,
				"tokenPrefix": t.Secret[:8], "description": desc, "maxUses": t.MaxUses, "useCount": 0, "createdAt": time.Now().UTC(),
				"expiresAt": time.Now().Add(time.Duration(hours) * time.Hour).UTC(), "lastUsedAt": nil, "revokedAt": nil, "state": "Active"},
			"plaintextToken": t.Secret,
		})
	}
	reply(w, 200, out)
}

func (s *Server) sorted() []*Endpoint {
	list := make([]*Endpoint, 0, len(s.endpoints))
	for _, e := range s.endpoints {
		list = append(list, e)
	}
	slices.SortFunc(list, func(a, b *Endpoint) int { return strings.Compare(a.Hostname, b.Hostname) })
	return list
}

func (s *Server) newJob(e *Endpoint, typ string, notBefore *time.Time) *Job {
	j := &Job{ID: uuid.New(), Endpoint: e.ID, Org: e.Org, Hostname: e.Hostname, Type: typ, Status: "Queued",
		CreatedAt: time.Now().UTC(), NotBefore: notBefore}
	s.jobs = append(s.jobs, j)
	return j
}

func scheduled(body map[string]any) *time.Time {
	v, ok := body["scheduledAt"].(string)
	if !ok {
		return nil
	}
	t, err := time.Parse(time.RFC3339Nano, v)
	if err != nil {
		return nil
	}
	return &t
}

func (s *Server) serveEndpoint(w http.ResponseWriter, r *http.Request, e *Endpoint, sub string, body map[string]any, pg int) {
	switch {
	case r.Method == http.MethodGet && sub == "":
		d := e.detail()
		d["summary"].(map[string]any)["tags"] = s.endpointTags(e)
		d["hasOwnPolicy"] = s.policies[policyKey(ScopeEndpoint, e.ID)] != nil
		reply(w, 200, d)
	case sub == "policy":
		s.servePolicy(w, r, ScopeEndpoint, e.ID, body)
	case sub == "tags" && r.Method == http.MethodPut:
		s.serveTagAssignment(w, e.ID, body)
	case sub == "tag-policies" && r.Method == http.MethodGet:
		reply(w, 200, s.tagPolicies(e))
	case r.Method != http.MethodGet && s.readOnlyCall && (sub == "" || sub == "uninstall-agent" || sub == "revoke"):
		problem(w, 403, "forbidden", "You do not have permission.")
	case r.Method == http.MethodPut && sub == "":
		s.updateEndpoint(w, e, body)
	case r.Method == http.MethodPost && sub == "uninstall-agent":
		s.uninstall(w, e)
	case r.Method == http.MethodPost && sub == "revoke":
		s.revoke(w, e)
	case r.Method == http.MethodGet && sub == "updates":
		state := r.URL.Query().Get("state")
		list := []map[string]any{}
		for _, u := range e.Updates {
			if state == "" || u["state"] == state {
				list = append(list, u)
			}
		}
		reply(w, 200, list)
	case r.Method == http.MethodGet && sub == "installed-updates":
		reply(w, 200, e.InstalledItems)
	case r.Method == http.MethodGet && sub == "update-history":
		reply(w, 200, paged([]map[string]any{{"id": 7, "updateGuid": nil, "title": "libc6 2.41-12+deb13u1", "kbNumber": nil,
			"operation": "Installation", "resultCode": 2, "result": "Succeeded", "hResult": nil, "errorDescription": nil,
			"date": "2026-11-14T03:00:00+00:00"}}, pg, 50))
	case r.Method == http.MethodGet && sub == "jobs":
		var list []map[string]any
		for i := len(s.jobs) - 1; i >= 0; i-- {
			if s.jobs[i].Endpoint == e.ID {
				list = append(list, s.jobs[i].summary())
			}
		}
		reply(w, 200, paged(list, pg, 50))
	case r.Method == http.MethodGet && sub == "effective-policy":
		reply(w, 200, effectivePolicy())
	case r.Method == http.MethodPost && sub == "install-updates":
		if s.readOnlyCall {
			problem(w, 403, "", "")
			return
		}
		if guids, _ := body["updateGuids"].([]any); body["mode"] == "Selected" && len(guids) == 0 {
			problem(w, 400, "validation_failed", "Choose updates.")
			return
		}
		if e.Missing == 0 {
			problem(w, 409, "nothing_to_install", fmt.Sprintf("%s has no eligible updates.", e.Hostname))
			return
		}
		reply(w, 202, s.newJob(e, "InstallUpdates", scheduled(body)).summary())
	case r.Method == http.MethodGet && sub == "install-preview":
		s.preview(w, e, r.URL.Query().Get("mode"), r.URL.Query().Get("updateGuids"))
	case r.Method != http.MethodGet && s.readOnlyCall:
		problem(w, 403, "", "")
	case r.Method == http.MethodPost && sub == "exclusions":
		guid, err := uuid.Parse(fmt.Sprint(body["updateGuid"]))
		if reason, _ := body["reason"].(string); err != nil || guid == uuid.Nil || len([]rune(reason)) > 500 {
			problem(w, 400, "validation_failed", "One or more fields are invalid.")
			return
		}
		e.exclude(guid, true)
		w.WriteHeader(http.StatusNoContent)
	case r.Method == http.MethodDelete && strings.HasPrefix(sub, "exclusions/"):
		guid, _ := uuid.Parse(strings.TrimPrefix(sub, "exclusions/"))
		e.exclude(guid, false)
		w.WriteHeader(http.StatusNoContent)
	case r.Method == http.MethodPost && strings.HasPrefix(sub, "updates/") && strings.HasSuffix(sub, "/uninstall"):
		if !e.Windows {
			problem(w, 409, "not_supported_on_linux", e.Hostname+" is a Linux endpoint. Removing updates is only available on Windows.")
			return
		}
		reply(w, 202, s.newJob(e, "UninstallUpdate", nil).summary())
	default:
		problem(w, 404, "not_found", "No such route.")
	}
}

// exclude marks an update of the endpoint excluded, or not, as EasyPatch's
// compliance pass does: an excluded missing or failed update is Excluded,
// and an included one is missing or failed again.
func (e *Endpoint) exclude(guid uuid.UUID, excluded bool) {
	for _, u := range e.Updates {
		if u["updateGuid"] != guid {
			continue
		}
		u["isExcluded"] = excluded
		switch {
		case excluded && (u["state"] == "Missing" || u["state"] == "Failed"):
			u["state"], u["isRequired"] = "Excluded", false
		case !excluded && u["state"] == "Excluded" && u["failedAttempts"] != 0:
			u["state"], u["isRequired"] = "Failed", u["category"] == "Security"
		case !excluded && u["state"] == "Excluded":
			u["state"], u["isRequired"] = "Missing", u["category"] == "Security"
		}
	}
}

// preview answers GET /api/v1/endpoints/{id}/install-preview as EasyPatch
// does: missing and failed updates that are not excluded are installed, the
// others asked for are skipped with the reason's code.
func (s *Server) preview(w http.ResponseWriter, e *Endpoint, mode, guids string) {
	chosen := map[string]bool{}
	for _, g := range strings.Split(guids, ",") {
		chosen[g] = g != ""
	}
	selected := strings.EqualFold(mode, "selected")
	items, skipped := []map[string]any{}, []map[string]any{}
	size := 0
	for _, u := range e.Updates {
		id := fmt.Sprint(u["updateGuid"])
		if selected && !chosen[id] {
			continue
		}
		if u["isExcluded"] == true {
			skipped = append(skipped, map[string]any{"updateGuid": u["updateGuid"], "title": u["title"], "kbNumber": u["kbNumber"],
				"category": u["category"], "reason": "Excluded"})
			continue
		}
		size += u["sizeBytes"].(int)
		items = append(items, map[string]any{"updateGuid": u["updateGuid"], "revisionNumber": 1, "title": u["title"], "kbNumber": u["kbNumber"],
			"category": u["category"], "sizeBytes": u["sizeBytes"], "rebootBehavior": nil, "state": u["state"]})
	}
	m := "AllEligible"
	if selected {
		m = "Selected"
	}
	reply(w, 200, map[string]any{"mode": m, "items": items, "skipped": skipped, "totalSizeBytes": size, "rebootLikelyCount": 0,
		"warnings": []string{}, "filter": map[string]any{"categories": []string{"Security", "Critical"}, "includeOptional": false,
			"excludedKbs": []string{}, "excludedUpdateGuids": []string{}, "acceptEulas": true, "approvedApplications": []string{}},
		"lastScanAt": "2026-11-16T14:40:00+00:00"})
}

// effectivePolicy is an endpoint's effective policy as EasyPatch answers
// it, with values set at every layer.
func effectivePolicy() map[string]any {
	return map[string]any{"checkInIntervalSeconds": 60, "scanIntervalMinutes": 240, "inventoryIntervalMinutes": 1440,
		"jitterPercent": 10, "allowedCategories": []string{"Security", "Critical"}, "includeOptional": false, "excludedKbs": []string{"KB5005565"},
		"acceptEulas": true, "autoInstallEnabled": true, "maintenanceDays": []int{6}, "maintenanceStart": "02:00",
		"maintenanceDurationMinutes": 180, "timeZone": "Europe/Paris", "scanStaleAfterHours": 72, "maxConcurrentInstallsPerSite": 10,
		"sources": map[string]string{"AutoInstallEnabled": "Organization", "maintenanceWindow": "Organization", "RestartSchedule": "Site",
			"ScanIntervalMinutes": "Global", "WindowsUpdate.AutomaticUpdates": "Organization", "ApplicationUpdates": "Tag"},
		"trayIconEnabled": true, "installNotificationsEnabled": true,
		"restartSchedule": map[string]any{"enabled": true, "days": []int{0}, "time": "03:00", "condition": "OnlyIfPending",
			"mode": "PromptWithDeadline", "countdownMinutes": 5, "deadlineMinutes": 240, "expiryMinutes": 120},
		"windowsUpdate": map[string]any{
			"automaticUpdates": map[string]any{"mode": "AutoDownloadNotifyInstall", "scheduledInstallDay": 0, "scheduledInstallHour": 3},
			"featureUpdates":   map[string]any{"deferDays": 180, "targetProductVersion": nil, "targetReleaseVersion": nil},
			"qualityUpdates":   nil, "restartBehavior": nil},
		"windowsUpdateValues": []map[string]any{{"group": "AutomaticUpdates", "path": `HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU`,
			"name": "AUOptions", "value": "3"}},
		"agentAutoUpdateEnabled": true, "installDelayDays": 3, "securityInstallDelayDays": 0,
		"sourceTags": map[string]string{"ApplicationUpdates": "Workstations"}, "knownExploitedSkipsDelay": true,
		"applicationUpdates": map[string]any{"enabled": true, "approvedApps": []string{"Mozilla.Firefox"}}, "preDownloadHours": 0}
}

func (s *Server) bulk(w http.ResponseWriter, kind string, body map[string]any) {
	if s.readOnlyCall {
		problem(w, 403, "", "")
		return
	}
	ids, _ := body["endpointIds"].([]any)
	if len(ids) == 0 || len(ids) > 1000 {
		problem(w, 400, "validation_failed", "Select between 1 and 1000 endpoints.")
		return
	}
	succeeded, failed := 0, 0
	var items []map[string]any
	for _, raw := range ids {
		id, _ := uuid.Parse(raw.(string))
		e := s.endpoints[id]
		switch {
		case e == nil:
			items = append(items, map[string]any{"endpointId": id, "hostname": nil, "success": false, "jobId": nil,
				"errorCode": "not_found", "message": "Endpoint not found."})
			failed++
		case kind == "restart" && e.CannotRestart:
			items = append(items, map[string]any{"endpointId": id, "hostname": e.Hostname, "success": false, "jobId": nil,
				"errorCode": "unsupported", "message": e.Hostname + "'s agent cannot restart the computer."})
			failed++
		case kind == "install-updates" && e.Missing == 0:
			items = append(items, map[string]any{"endpointId": id, "hostname": e.Hostname, "success": false, "jobId": nil,
				"errorCode": "nothing_to_install", "message": e.Hostname + " has no eligible updates."})
			failed++
		case kind == "notify" && !e.Windows:
			items = append(items, map[string]any{"endpointId": id, "hostname": e.Hostname, "success": false, "jobId": nil,
				"errorCode": "not_supported_on_linux", "message": e.Hostname + " is a Linux endpoint. Messages to users are only available on Windows."})
			failed++
		default:
			typ := map[string]string{"scan": "UpdateScan", "install-updates": "InstallUpdates", "restart": "Restart", "notify": "NotifyUser",
				"agent-update": "AgentUpdate"}[kind]
			at := scheduled(body)
			if restart, ok := body["restart"].(map[string]any); ok {
				at = scheduled(restart)
			}
			j := s.newJob(e, typ, at)
			items = append(items, map[string]any{"endpointId": id, "hostname": e.Hostname, "success": true, "jobId": j.ID,
				"errorCode": nil, "message": nil})
			succeeded++
		}
	}
	reply(w, 200, map[string]any{"succeeded": succeeded, "failed": failed, "results": items})
}

// restartPending answers GET /api/v1/organizations/{id}/restart-pending.
func (s *Server) restartPending(w http.ResponseWriter, org string) {
	id, _ := uuid.Parse(org)
	if s.org(id) == nil {
		problem(w, 404, "not_found", "Organization not found.")
		return
	}
	list := []map[string]any{}
	for _, e := range s.sorted() {
		if e.Org == id && e.Status == "Active" && e.RebootPending {
			platform, os := "Linux", "Debian GNU/Linux 13 (trixie)"
			if e.IsServer {
				platform, os = "Windows", "Windows Server 2025 Standard"
			}
			list = append(list, map[string]any{"id": e.ID, "hostname": e.Hostname, "siteId": uuid.New(), "siteName": "Head office",
				"platform": platform, "operatingSystem": os, "isServer": e.IsServer, "isOnline": true,
				"rebootPendingSince": "2026-11-16T14:40:00+00:00", "canRestart": !e.CannotRestart})
		}
	}
	reply(w, 200, map[string]any{"total": len(list), "endpoints": list})
}

// retry answers POST /api/v1/jobs/{id}/retry as EasyPatch does: a finished
// job runs again as a new one.
func (s *Server) retry(w http.ResponseWriter, j *Job) {
	if s.readOnlyCall {
		problem(w, 403, "", "")
		return
	}
	if j.Status == "Queued" || j.Status == "Running" {
		problem(w, 409, "invalid_state", "Only finished jobs can be retried.")
		return
	}
	e := s.endpoints[j.Endpoint]
	if e == nil {
		problem(w, 404, "not_found", "Endpoint not found.")
		return
	}
	n := s.newJob(e, j.Type, nil)
	n.RetryOf = &j.ID
	reply(w, 202, n.summary())
}

// messagePresets is what GET /api/v1/user-messages answers.
func messagePresets() []map[string]any {
	// EasyPatch's UserMessages, word for word.
	presets := []struct{ preset, title, body string }{
		{"UpdatesInstalling", "Updates are installing",
			"Windows updates are being installed on this computer. You can keep working, but it may be slower for a while."},
		{"UpdatesInstalled", "Updates installed", "Windows updates were installed on this computer. No restart is needed."},
		{"RestartRequired", "Restart required",
			"Windows updates were installed and this computer needs to restart to finish. Please save your work and restart when you can."},
		{"SaveYourWork", "Please save your work",
			"Your IT team is about to carry out maintenance on this computer. Please save your work and close your applications."},
		{"MaintenanceTonight", "Maintenance tonight",
			"Maintenance is scheduled for this computer tonight. Please save your work and leave the computer switched on when you finish for the day."},
		{"RestartScheduled", "Restart scheduled", "This computer will restart at {time}. Please save your work before then."},
	}
	out := make([]map[string]any, 0, len(presets))
	for _, p := range presets {
		out = append(out, map[string]any{"preset": p.preset, "title": p.title, "body": p.body, "needsRestartTime": p.preset == "RestartScheduled"})
	}
	return out
}
