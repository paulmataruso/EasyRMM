// Package eptest serves the part of EasyPatch's API that EasyRMM's
// connector uses, for tests, the way net/http/httptest serves HTTP. Its
// answers have the field names and shapes EasyPatch 1.9.0 sends, recorded
// from a real server; it keeps endpoints, updates and jobs in memory.
package eptest

import (
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
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

// Server is a fake EasyPatch server over TLS with its own certificate.
// Change its state inside Set.
type Server struct {
	srv *httptest.Server
	// Token is the API token the server accepts.
	Token string
	// CAPEM is the certificate that signs the server's.
	CAPEM string

	mu sync.Mutex
	// Version is what server-info reports.
	Version string
	// Capabilities is what server-info lists; nil leaves the field out, as
	// EasyPatch 1.9.0 does.
	Capabilities []string
	// ReadOnly makes the token a ReadOnly one: operator calls answer 403.
	ReadOnly bool
	// Down makes every call answer 503.
	Down bool

	orgs      []map[string]any
	endpoints map[uuid.UUID]*Endpoint
	jobs      []*Job
	requests  []Request
}

// Endpoint is an EasyPatch endpoint.
type Endpoint struct {
	ID, Org        uuid.UUID
	OrgName        string
	Hostname       string
	Serial         string
	Status         string
	Compliance     string
	Missing        int
	Fingerprint    string
	Revoked        bool
	Updates        []map[string]any
	InstalledItems []map[string]any
}

// Job is an EasyPatch job.
type Job struct {
	ID, Endpoint, Org uuid.UUID
	Hostname, Type    string
	Status            string
	CreatedAt         time.Time
	NotBefore         *time.Time
}

// Request is a call the server received.
type Request struct {
	Method, Path string
	OnBehalfOf   string
	Body         map[string]any
}

// New starts a server, closed when the test ends.
func New(t testing.TB) *Server {
	t.Helper()
	s := &Server{Token: "ept_" + strings.Repeat("A", 43), Version: "1.9.0", endpoints: map[uuid.UUID]*Endpoint{}}
	s.srv = httptest.NewUnstartedServer(http.HandlerFunc(s.serve))
	// Tests of an untrusted certificate make the server log handshake errors.
	s.srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	s.srv.StartTLS()
	t.Cleanup(s.srv.Close)
	s.CAPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.srv.Certificate().Raw}))
	return s
}

// URL is the server's address.
func (s *Server) URL() string { return s.srv.URL }

// Set changes the server's state while no request reads it.
func (s *Server) Set(fn func()) {
	s.mu.Lock()
	defer s.mu.Unlock()
	fn()
}

// Org adds an organization.
func (s *Server) Org(name string) uuid.UUID {
	s.mu.Lock()
	defer s.mu.Unlock()
	id := uuid.New()
	s.orgs = append(s.orgs, map[string]any{"id": id, "name": name, "description": nil, "timeZone": "UTC", "isActive": true,
		"siteCount": 1, "endpointCount": 0})
	return id
}

// AddEndpoint adds an active endpoint with two missing updates (one failed)
// and one installed.
func (s *Server) AddEndpoint(org uuid.UUID, hostname, serial, fingerprint string) *Endpoint {
	s.mu.Lock()
	defer s.mu.Unlock()
	name := ""
	for _, o := range s.orgs {
		if o["id"] == org {
			name = o["name"].(string)
		}
	}
	e := &Endpoint{ID: uuid.New(), Org: org, OrgName: name, Hostname: hostname, Serial: serial, Status: "Active",
		Compliance: "MissingUpdates", Missing: 2, Fingerprint: fingerprint}
	e.Updates = []map[string]any{
		update("openssl 3.5.7-1~deb13u3", "Security", "Missing"),
		update("tzdata 2026c-0+deb13u1", "Other", "Failed"),
	}
	e.InstalledItems = []map[string]any{update("libc6 2.41-12+deb13u1", "Security", "Installed")}
	s.endpoints[e.ID] = e
	return e
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
		"updateGuid": uuid.New(), "revisionNumber": 1, "title": title, "description": nil, "kbNumber": nil, "kbNumbers": []string{},
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
	return map[string]any{
		"id": e.ID, "hostname": e.Hostname, "organizationId": e.Org, "organizationName": e.OrgName,
		"siteId": uuid.New(), "siteName": "Head office", "status": e.Status, "operatingSystem": "Debian GNU/Linux 13 (trixie)",
		"osVersion": "13", "osBuild": nil, "architecture": "X64", "agentVersion": "1.9.0", "agentOutdated": false, "isOnline": true,
		"lastCheckInAt": "2026-11-16T14:34:13.737582+00:00", "lastScanAt": "2026-11-16T14:40:00+00:00",
		"complianceStatus": e.Compliance, "missingRequiredCount": 1, "missingTotalCount": e.Missing, "failedCount": 1,
		"rebootPending": false, "osSupportStatus": "Unknown", "currentActivity": "Idle", "lastSeenIp": "192.0.2.10",
		"platform": "Linux", "missingDeferredCount": 0, "tags": []any{}, "knownExploitedMissingCount": 0,
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
	return map[string]any{
		"summary": e.summary(), "dnsDomain": nil, "serialNumber": serial, "manufacturer": "QEMU",
		"lastScanAttemptAt": "2026-11-16T14:40:00+00:00", "lastScanError": nil, "rebootReasons": []string{},
		"rebootPendingSince": nil, "installedCount": len(e.InstalledItems), "pendingRebootUpdateCount": 0,
		"complianceEvaluatedAt": "2026-11-16T14:40:01+00:00",
		"credentials": []map[string]any{{"credentialId": "c_test", "keyFingerprint": e.Fingerprint, "createdAt": "2026-11-16T14:34:05+00:00",
			"expiresAt": "2027-11-16T14:34:05+00:00", "revokedAt": revoked, "revokedReason": nil, "lastUsedAt": nil}},
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
	s.requests = append(s.requests, Request{Method: r.Method, Path: r.URL.Path, OnBehalfOf: r.Header.Get("X-EasyPatch-On-Behalf-Of"), Body: body})
	if s.Down {
		problem(w, http.StatusServiceUnavailable, "", "The database is not available.")
		return
	}
	if r.Header.Get("Authorization") != "Bearer "+s.Token {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
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
		info := map[string]any{"version": s.Version, "publicUrl": "https://patch.example.com", "serverTime": time.Now().UTC()}
		if s.Capabilities != nil {
			info["capabilities"] = s.Capabilities
		}
		reply(w, 200, info)
	case r.Method == http.MethodGet && r.URL.Path == "/api/v1/enrollment-tokens":
		if s.ReadOnly {
			problem(w, 403, "", "")
			return
		}
		reply(w, 200, []any{})
	case r.Method == http.MethodGet && r.URL.Path == "/api/v1/organizations":
		reply(w, 200, s.orgs)
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
	case r.Method == http.MethodGet && r.URL.Path == "/api/v1/jobs":
		org, _ := uuid.Parse(q.Get("organizationId"))
		var list []map[string]any
		for i := len(s.jobs) - 1; i >= 0; i-- {
			j := s.jobs[i]
			active := j.Status == "Queued" || j.Status == "Running"
			if j.Org == org && (q.Get("active") != "true" || active) {
				list = append(list, j.summary())
			}
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
		reply(w, 200, e.detail())
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
		reply(w, 200, map[string]any{"checkInIntervalSeconds": 60, "scanIntervalMinutes": 240, "inventoryIntervalMinutes": 1440,
			"jitterPercent": 10, "allowedCategories": []string{"Security", "Critical"}, "includeOptional": false, "excludedKbs": []string{},
			"acceptEulas": true, "autoInstallEnabled": true, "maintenanceDays": []int{6}, "maintenanceStart": "02:00",
			"maintenanceDurationMinutes": 180, "timeZone": "Europe/Paris", "scanStaleAfterHours": 72, "maxConcurrentInstallsPerSite": 10,
			"sources": map[string]string{"autoInstallEnabled": "Organization"}, "installDelayDays": 3, "securityInstallDelayDays": 0})
	case r.Method == http.MethodPost && sub == "install-updates":
		if s.ReadOnly {
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
	default:
		problem(w, 404, "not_found", "No such route.")
	}
}

func (s *Server) bulk(w http.ResponseWriter, kind string, body map[string]any) {
	if s.ReadOnly {
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
		case kind == "install-updates" && e.Missing == 0:
			items = append(items, map[string]any{"endpointId": id, "hostname": e.Hostname, "success": false, "jobId": nil,
				"errorCode": "nothing_to_install", "message": e.Hostname + " has no eligible updates."})
			failed++
		default:
			typ := map[string]string{"scan": "UpdateScan", "install-updates": "InstallUpdates"}[kind]
			j := s.newJob(e, typ, scheduled(body))
			items = append(items, map[string]any{"endpointId": id, "hostname": e.Hostname, "success": true, "jobId": j.ID,
				"errorCode": nil, "message": nil})
			succeeded++
		}
	}
	reply(w, 200, map[string]any{"succeeded": succeeded, "failed": failed, "results": items})
}
