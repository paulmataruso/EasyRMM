//go:build contract

// The contract tests run the connector against a real EasyPatch server built
// from the same commit's easypatch/ directory. scripts/contract/easypatch.sh
// starts one and runs them (make test-contract; CI's "EasyPatch contract"
// job). The fast tests use eptest's recorded answers; these check the
// connector against the real server, and eptest's answers against its
// answers, so neither drifts from EasyPatch unnoticed.
package easypatch

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/paulmataruso/easyrmm/server/internal/easypatch/eptest"
)

// contract is the EasyPatch server under test.
type contract struct {
	t        *testing.T
	ctx      context.Context
	url      string
	caPEM    string
	token    string
	readOnly string
	version  string
	http     *http.Client
}

func newContract(t *testing.T) *contract {
	t.Helper()
	c := &contract{
		t:        t,
		url:      os.Getenv("EASYRMM_CONTRACT_EASYPATCH_URL"),
		token:    os.Getenv("EASYRMM_CONTRACT_EASYPATCH_TOKEN"),
		readOnly: os.Getenv("EASYRMM_CONTRACT_EASYPATCH_READONLY_TOKEN"),
		version:  os.Getenv("EASYRMM_CONTRACT_EASYPATCH_VERSION"),
	}
	caFile := os.Getenv("EASYRMM_CONTRACT_EASYPATCH_CA")
	if c.url == "" || c.token == "" || c.readOnly == "" || caFile == "" {
		t.Fatal("the contract tests need a real EasyPatch server: run them with make test-contract")
	}
	ca, err := os.ReadFile(caFile)
	if err != nil {
		t.Fatal(err)
	}
	c.caPEM = string(ca)
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		t.Fatal("the CA certificate is not PEM")
	}
	c.http = &http.Client{Timeout: 30 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}}}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	t.Cleanup(cancel)
	c.ctx = ctx
	return c
}

// client is the connector's client with a token.
func (c *contract) client(token string) *Client {
	c.t.Helper()
	cl, err := NewClient(c.url, token, c.caPEM, "contract")
	if err != nil {
		c.t.Fatal(err)
	}
	return cl
}

// call sends a request to base with a token ("" for none) and returns the
// status and the body.
func call(ctx context.Context, t *testing.T, hc *http.Client, base, method, path, token string, body any, header http.Header) (int, []byte) {
	t.Helper()
	var r io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		r = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, base+path, r)
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range header {
		req.Header[k] = v
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := hc.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, data
}

// must sends a request that must answer want, and decodes the answer into
// out (nil for none).
func (c *contract) must(method, path, token string, body any, want int, out any) {
	c.t.Helper()
	status, data := call(c.ctx, c.t, c.http, c.url, method, path, token, body, nil)
	if status != want {
		c.t.Fatalf("%s %s answered %d, want %d: %s", method, path, status, want, data)
	}
	if out != nil {
		if err := json.Unmarshal(data, out); err != nil {
			c.t.Fatalf("%s %s: %v: %s", method, path, err, data)
		}
	}
}

// agent is a simulated EasyPatch agent on Debian. It stands in for a real
// agent, which the contract job does not run: it enrolls and signs its
// requests exactly as EasyPatch's agents do
// (easypatch/shared/EasyPatch.Contracts/Security/RequestSigning.cs), and
// reports what the tests need.
type agent struct {
	c           *contract
	key         *ecdsa.PrivateKey
	credential  string
	endpoint    uuid.UUID
	fingerprint string
	sequence    int64
}

func (c *contract) enroll(token, hostname string) *agent {
	c.t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		c.t.Fatal(err)
	}
	spki, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		c.t.Fatal(err)
	}
	var r struct {
		State          string    `json:"state"`
		CredentialID   string    `json:"credentialId"`
		EndpointID     uuid.UUID `json:"endpointId"`
		KeyFingerprint string    `json:"keyFingerprint"`
	}
	c.must(http.MethodPost, "/api/v1/agents/enroll", "", map[string]any{
		"enrollmentToken": token,
		"publicKey":       base64.StdEncoding.EncodeToString(spki),
		"agentVersion":    "1.10.0",
		"device": map[string]any{
			"hostname": hostname, "smbiosUuid": strings.ToUpper(uuid.NewString()), "serialNumber": "SN-" + hostname,
			"manufacturer": "QEMU", "model": "Standard PC (Q35 + ICH9, 2009)", "osCaption": "Debian GNU/Linux 13 (trixie)",
			"osBuild": "6.12.48+deb13-amd64", "architecture": "X64", "platform": "Linux", "osId": "debian", "osVersion": "13",
		},
	}, http.StatusOK, &r)
	if r.State != "Active" || !strings.HasPrefix(r.CredentialID, "c_") || r.EndpointID == uuid.Nil || r.KeyFingerprint == "" {
		c.t.Fatalf("enrollment answered %+v", r)
	}
	return &agent{c: c, key: key, credential: r.CredentialID, endpoint: r.EndpointID, fingerprint: r.KeyFingerprint}
}

// post sends a signed agent request; route is the path, which is what the
// signature covers.
func (a *agent) post(route string, body, out any) {
	t := a.c.t
	t.Helper()
	data, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	contentHash := hex.EncodeToString(sum[:])
	raw := make([]byte, 16)
	_, _ = rand.Read(raw)
	nonce := base64.RawURLEncoding.EncodeToString(raw)
	timestamp := strconv.FormatInt(time.Now().Unix(), 10)
	canonical := strings.Join([]string{"EASYPATCH-ECDSA-P256-SHA256", http.MethodPost, route, timestamp, nonce, contentHash, a.credential}, "\n")
	digest := sha256.Sum256([]byte(canonical))
	r, s, err := ecdsa.Sign(rand.Reader, a.key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	signature := make([]byte, 64) // IEEE P1363: r then s, 32 bytes each
	r.FillBytes(signature[:32])
	s.FillBytes(signature[32:])
	header := http.Header{}
	header.Set("X-EasyPatch-Credential", a.credential)
	header.Set("X-EasyPatch-Timestamp", timestamp)
	header.Set("X-EasyPatch-Nonce", nonce)
	header.Set("X-EasyPatch-Content-SHA256", contentHash)
	header.Set("X-EasyPatch-Signature", base64.StdEncoding.EncodeToString(signature))
	status, answer := call(a.c.ctx, t, a.c.http, a.c.url, http.MethodPost, route, "", json.RawMessage(data), header)
	if status < 200 || status > 299 {
		t.Fatalf("agent POST %s answered %d: %s", route, status, answer)
	}
	if out != nil {
		if err := json.Unmarshal(answer, out); err != nil {
			t.Fatalf("agent POST %s: %v: %s", route, err, answer)
		}
	}
}

// deliveredJob is a job a check-in hands the agent.
type deliveredJob struct {
	JobID uuid.UUID `json:"jobId"`
	Type  string    `json:"type"`
}

type checkIn struct {
	Jobs         []deliveredJob `json:"jobs"`
	CancelJobIDs []uuid.UUID    `json:"cancelJobIds"`
}

func (a *agent) checkIn(active ...uuid.UUID) checkIn {
	a.c.t.Helper()
	var r checkIn
	if active == nil {
		active = []uuid.UUID{} // agents send a list, never null
	}
	a.post("/api/v1/agents/check-in", map[string]any{"agentVersion": "1.10.0", "activeJobIds": active, "currentActivity": "Idle",
		"agentArchitecture": "x64", "agentPackageFormat": "deb"}, &r)
	return r
}

func (a *agent) report(job uuid.UUID, status string, items ...map[string]any) {
	a.c.t.Helper()
	a.sequence++
	if items == nil {
		items = []map[string]any{}
	}
	a.post("/api/v1/agents/jobs/"+job.String()+"/status", map[string]any{"sequence": a.sequence, "status": status, "items": items}, nil)
}

// pkg is an available Debian package upgrade as the Linux agent reports it.
func pkg(guid uuid.UUID, name, version, installed, repository string, security bool) map[string]any {
	return map[string]any{
		"updateGuid": guid, "revisionNumber": 1, "title": name + " " + version, "kbNumbers": []string{}, "categories": []any{},
		"package": map[string]any{"name": name, "architecture": "amd64", "version": version, "installedVersion": installed,
			"repository": repository, "security": security, "advisories": []string{}, "cves": []string{}, "sourcePackage": name},
	}
}

func TestContract(t *testing.T) {
	c := newContract(t)
	ep, ro := c.client(c.token), c.client(c.readOnly)
	ctx := c.ctx
	run := func(name string, fn func(t *testing.T)) {
		if !t.Run(name, fn) {
			t.FailNow() // each step needs the ones before it
		}
	}

	run("server info", func(t *testing.T) {
		info, err := ep.ServerInfo(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if c.version != "" && info.Version != c.version {
			t.Errorf("version %q, want %q", info.Version, c.version)
		}
		for _, capability := range []string{CapabilityScheduledInstalls, CapabilityOnBehalfOf} {
			if !slices.Contains(info.Capabilities, capability) {
				t.Errorf("capabilities %v lack %q", info.Capabilities, capability)
			}
		}
		if d := time.Since(info.ServerTime); d > time.Minute || d < -time.Minute {
			t.Errorf("server time %v", info.ServerTime)
		}
		if !SameServer(info.PublicURL, c.url) {
			t.Errorf("public URL %q, want %q", info.PublicURL, c.url)
		}
	})

	run("operator and read-only tokens", func(t *testing.T) {
		if ok, err := ep.CanOperate(ctx); !ok || err != nil {
			t.Errorf("operator token: CanOperate %v, %v", ok, err)
		}
		if ok, err := ro.CanOperate(ctx); ok || err != nil {
			t.Errorf("read-only token: CanOperate %v, %v", ok, err)
		}
	})

	// The connector never creates organizations or sites; the test does,
	// as an administrator would in EasyPatch's console.
	suffix := uuid.NewString()[:8]
	var org struct {
		ID uuid.UUID `json:"id"`
	}
	c.must(http.MethodPost, "/api/v1/organizations", c.token, map[string]any{"name": "Contract " + suffix, "timeZone": "UTC"},
		http.StatusCreated, &org)
	var site struct {
		ID uuid.UUID `json:"id"`
	}
	c.must(http.MethodPost, "/api/v1/organizations/"+org.ID.String()+"/sites", c.token, map[string]any{"name": "Head office", "timeZone": "UTC"},
		http.StatusCreated, &site)

	run("organizations and sites", func(t *testing.T) {
		orgs, err := ep.Organizations(ctx)
		if err != nil {
			t.Fatal(err)
		}
		i := slices.IndexFunc(orgs, func(o Organization) bool { return o.ID == org.ID })
		if i < 0 || orgs[i].Name != "Contract "+suffix || !orgs[i].IsActive {
			t.Fatalf("organizations %+v lack the new one", orgs)
		}
		sites, err := ep.Sites(ctx, org.ID)
		if err != nil || !slices.ContainsFunc(sites, func(s Site) bool { return s.ID == site.ID && s.Name == "Head office" }) {
			t.Fatalf("sites %+v, %v", sites, err)
		}
		if _, err := ro.Organizations(ctx); err != nil {
			t.Errorf("read-only token: %v", err)
		}
	})

	var a *agent
	run("enrollment tokens and an agent", func(t *testing.T) {
		token, err := ep.CreateEnrollmentToken(ctx, org.ID, &site.ID, "EasyRMM contract", "contract-enroll@example.test")
		if err != nil {
			t.Fatal(err)
		}
		if token.ID == uuid.Nil || token.Secret == "" {
			t.Fatalf("token %+v", token)
		}
		a = c.enroll(token.Secret, "contract-"+suffix)
		for range 2 { // revoking twice is harmless
			if err := ep.RevokeEnrollmentToken(ctx, token.ID, "contract-enroll@example.test"); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := ro.CreateEnrollmentToken(ctx, org.ID, nil, "read-only", ""); !IsStatus(err, http.StatusForbidden) {
			t.Errorf("read-only token created an enrollment token: %v", err)
		}
	})

	openssl, tzdata, libc := uuid.New(), uuid.New(), uuid.New()
	a.checkIn()
	now := time.Now().UTC()
	a.post("/api/v1/agents/updates/scan-results", map[string]any{
		"scanId": uuid.New(), "trigger": "Scheduled", "startedAt": now.Add(-time.Minute), "completedAt": now, "succeeded": true,
		"source": map[string]any{"type": "PackageRepositories"},
		"missing": []any{
			pkg(openssl, "openssl", "3.5.7-1~deb13u3", "3.5.6-1~deb13u1", "Debian-Security:13/trixie-security", true),
			pkg(tzdata, "tzdata", "2026c-0+deb13u1", "2026b-0+deb13u1", "Debian:13/trixie", false),
		},
		"installed": []any{pkg(libc, "libc6", "2.41-12+deb13u1", "2.41-12+deb13u1", "Debian:13/trixie", true)},
	}, nil)
	a.post("/api/v1/agents/updates/history", map[string]any{"entries": []any{map[string]any{
		"title": "libc6 2.41-12+deb13u1", "operation": "Installation", "resultCode": 2, "date": now.Add(-24 * time.Hour)}}}, nil)

	run("endpoints and their updates", func(t *testing.T) {
		page, err := ep.Endpoints(ctx, org.ID, 1)
		if err != nil {
			t.Fatal(err)
		}
		if page.TotalCount != 1 || len(page.Items) != 1 {
			t.Fatalf("endpoints %+v", page)
		}
		e := page.Items[0]
		if e.ID != a.endpoint || e.Hostname != "contract-"+suffix || e.OrganizationID != org.ID || e.SiteName != "Head office" ||
			e.Platform != "Linux" || !e.IsOnline || e.MissingTotalCount != 2 || e.LastScanAt == nil {
			t.Errorf("endpoint %+v", e)
		}
		detail, err := ep.Endpoint(ctx, a.endpoint)
		if err != nil {
			t.Fatal(err)
		}
		if detail.Summary.ID != a.endpoint || detail.SerialNumber != "SN-contract-"+suffix || len(detail.Credentials) != 1 ||
			detail.Credentials[0].CredentialID != a.credential || detail.Credentials[0].KeyFingerprint != a.fingerprint ||
			detail.Credentials[0].RevokedAt != nil {
			t.Errorf("endpoint detail %+v", detail)
		}
		updates, err := ep.Updates(ctx, a.endpoint, "")
		if err != nil {
			t.Fatal(err)
		}
		i := slices.IndexFunc(updates, func(u Update) bool { return u.UpdateGUID == openssl })
		if len(updates) != 2 || i < 0 {
			t.Fatalf("updates %+v", updates)
		}
		u := updates[i]
		if u.Title != "openssl 3.5.7-1~deb13u3" || u.State != "Missing" || u.Category != "Security" || u.Package == nil ||
			u.Package.Name != "openssl" || u.Package.Version != "3.5.7-1~deb13u3" || u.Package.InstalledVersion != "3.5.6-1~deb13u1" ||
			u.Package.Repository != "Debian-Security:13/trixie-security" || u.ActiveJob != nil {
			t.Errorf("openssl update %+v (package %+v)", u, u.Package)
		}
		if missing, err := ep.Updates(ctx, a.endpoint, "Missing"); err != nil || len(missing) != 2 {
			t.Errorf("missing updates %+v, %v", missing, err)
		}
		if installed, err := ep.InstalledUpdates(ctx, a.endpoint); err != nil ||
			!slices.ContainsFunc(installed, func(u Update) bool { return u.UpdateGUID == libc }) {
			t.Errorf("installed updates %+v, %v", installed, err)
		}
		history, err := ep.History(ctx, a.endpoint, 1)
		if err != nil || len(history.Items) != 1 || history.Items[0].Title != "libc6 2.41-12+deb13u1" || history.Items[0].Operation != "Installation" {
			t.Errorf("history %+v, %v", history, err)
		}
		policy, err := ep.EffectivePolicy(ctx, a.endpoint)
		if err != nil || policy.ScanIntervalMinutes <= 0 || policy.TimeZone == "" {
			t.Errorf("effective policy %+v, %v", policy, err)
		}
		if _, err := ro.Endpoint(ctx, a.endpoint); err != nil {
			t.Errorf("read-only token: %v", err)
		}
	})

	var install Job
	run("install, follow and cancel a job", func(t *testing.T) {
		var err error
		install, err = ep.Install(ctx, a.endpoint, []uuid.UUID{openssl}, nil, "contract-install@example.test")
		if err != nil {
			t.Fatal(err)
		}
		if install.ID == uuid.Nil || install.EndpointID != a.endpoint || install.OrganizationID != org.ID || install.Type != "InstallUpdates" ||
			install.Status != "Queued" {
			t.Fatalf("install job %+v", install)
		}
		job, err := ep.Job(ctx, install.ID)
		if err != nil {
			t.Fatal(err)
		}
		if job.InstallMode != "Selected" || len(job.Items) != 1 || job.Items[0].UpdateGUID != openssl || job.Items[0].Status != "Pending" {
			t.Errorf("job detail %+v", job)
		}
		if jobs, err := ep.EndpointJobs(ctx, a.endpoint, 1); err != nil || !slices.ContainsFunc(jobs.Items, func(j Job) bool { return j.ID == install.ID }) {
			t.Errorf("endpoint jobs %+v, %v", jobs, err)
		}
		if jobs, err := ep.Jobs(ctx, org.ID, true, 1); err != nil || !slices.ContainsFunc(jobs.Items, func(j Job) bool { return j.ID == install.ID }) {
			t.Errorf("active jobs %+v, %v", jobs, err)
		}
		if _, err := ro.Install(ctx, a.endpoint, []uuid.UUID{openssl}, nil, ""); !IsStatus(err, http.StatusForbidden) {
			t.Errorf("read-only token installed updates: %v", err)
		}

		// The agent picks the job up and starts installing.
		in := a.checkIn()
		if !slices.ContainsFunc(in.Jobs, func(j deliveredJob) bool {
			return j.JobID == install.ID
		}) {
			t.Fatalf("check-in delivered %+v, not the install", in.Jobs)
		}
		a.post("/api/v1/agents/jobs/"+install.ID.String()+"/ack", map[string]any{}, nil)
		a.report(install.ID, "Running", map[string]any{"updateGuid": openssl, "title": "openssl 3.5.7-1~deb13u3", "category": "Security",
			"status": "Installing", "installPercent": 40, "startedAt": time.Now().UTC()})
		job, err = ep.Job(ctx, install.ID)
		if err != nil {
			t.Fatal(err)
		}
		if job.Summary.Status != "Running" || job.Summary.StartedAt == nil || len(job.Items) != 1 || job.Items[0].Status != "Installing" ||
			job.Items[0].InstallPercent == nil || *job.Items[0].InstallPercent != 40 {
			t.Errorf("running job %+v", job)
		}
		updates, err := ep.Updates(ctx, a.endpoint, "")
		if err != nil {
			t.Fatal(err)
		}
		if i := slices.IndexFunc(updates, func(u Update) bool { return u.UpdateGUID == openssl }); i < 0 ||
			updates[i].ActiveJob == nil || updates[i].ActiveJob.JobID != install.ID {
			t.Errorf("updates while installing %+v", updates)
		}

		// Canceling asks the agent to stop; the job ends when it says so.
		job, err = ep.CancelJob(ctx, install.ID, "contract-cancel@example.test")
		if err != nil {
			t.Fatal(err)
		}
		if !job.Summary.CancelRequested {
			t.Errorf("canceled job %+v", job.Summary)
		}
		if in := a.checkIn(install.ID); !slices.Contains(in.CancelJobIDs, install.ID) {
			t.Fatalf("check-in did not ask to cancel: %+v", in)
		}
		a.report(install.ID, eptest.StatusCanceled, map[string]any{"updateGuid": openssl, "title": "openssl 3.5.7-1~deb13u3",
			"category": "Security", "status": eptest.StatusCanceled, "completedAt": time.Now().UTC()})
		job, err = ep.Job(ctx, install.ID)
		if err != nil || job.Summary.Status != eptest.StatusCanceled || job.Summary.CompletedAt == nil {
			t.Errorf("job after the agent stopped %+v, %v", job, err)
		}
	})

	run("scheduled installs", func(t *testing.T) {
		at := time.Now().Add(2 * time.Hour).UTC().Truncate(time.Second)
		job, err := ep.Install(ctx, a.endpoint, []uuid.UUID{tzdata}, &at, "")
		if err != nil {
			t.Fatal(err)
		}
		detail, err := ep.Job(ctx, job.ID)
		if err != nil {
			t.Fatal(err)
		}
		if detail.Summary.Status != "Queued" || detail.NotBefore == nil || !detail.NotBefore.Equal(at) {
			t.Errorf("scheduled job %+v (not before %v)", detail.Summary, detail.NotBefore)
		}
		if in := a.checkIn(); slices.ContainsFunc(in.Jobs, func(j deliveredJob) bool {
			return j.JobID == job.ID
		}) {
			t.Error("a job scheduled for later was delivered now")
		}
		detail, err = ep.CancelJob(ctx, job.ID, "")
		if err != nil || detail.Summary.Status != eptest.StatusCanceled {
			t.Errorf("canceled scheduled job %+v, %v", detail.Summary, err)
		}
	})

	run("bulk actions", func(t *testing.T) {
		unknown := uuid.New()
		scan, err := ep.BulkScan(ctx, []uuid.UUID{a.endpoint, unknown}, "")
		if err != nil {
			t.Fatal(err)
		}
		if scan.Succeeded != 1 || scan.Failed != 1 || len(scan.Results) != 2 {
			t.Fatalf("bulk scan %+v", scan)
		}
		for _, r := range scan.Results {
			switch r.EndpointID {
			case a.endpoint:
				if !r.Success || r.JobID == nil {
					t.Errorf("bulk scan of the endpoint %+v", r)
				}
			case unknown:
				if r.Success || r.ErrorCode == "" || r.Message == "" {
					t.Errorf("bulk scan of an unknown endpoint %+v", r)
				}
			default:
				t.Errorf("bulk scan result for %v", r.EndpointID)
			}
		}
		at := time.Now().Add(3 * time.Hour).UTC().Truncate(time.Second)
		bulk, err := ep.BulkInstall(ctx, []uuid.UUID{a.endpoint}, &at, "")
		if err != nil || bulk.Succeeded != 1 || len(bulk.Results) != 1 || bulk.Results[0].JobID == nil {
			t.Fatalf("bulk install %+v, %v", bulk, err)
		}
		if job, err := ep.Job(ctx, *bulk.Results[0].JobID); err != nil || job.NotBefore == nil || !job.NotBefore.Equal(at) {
			t.Errorf("bulk-scheduled job %+v, %v", job, err)
		}
		if _, err := ro.BulkScan(ctx, []uuid.UUID{a.endpoint}, ""); !IsStatus(err, http.StatusForbidden) {
			t.Errorf("read-only token scanned: %v", err)
		}
	})

	run("errors", func(t *testing.T) {
		_, err := ep.Endpoint(ctx, uuid.New())
		var e *Error
		if !IsStatus(err, http.StatusNotFound) || !errors.As(err, &e) || e.Code == "" || e.Detail == "" {
			t.Errorf("unknown endpoint: %#v", err)
		}
		if _, err := ep.Job(ctx, uuid.New()); !IsStatus(err, http.StatusNotFound) {
			t.Errorf("unknown job: %v", err)
		}
		bad, err := NewClient(c.url, "ept_"+strings.Repeat("A", 43), c.caPEM, "contract")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := bad.Organizations(ctx); !IsStatus(err, http.StatusUnauthorized) {
			t.Errorf("unknown token: %v", err)
		}
	})

	run("agent packages", func(t *testing.T) {
		if _, err := ep.AgentPackages(ctx); err != nil {
			t.Error(err)
		}
	})

	run("actions name the EasyRMM user in EasyPatch's audit log", func(t *testing.T) {
		type entry struct {
			Action  string `json:"action"`
			Details string `json:"details"`
		}
		var page struct {
			Items []entry `json:"items"`
		}
		c.must(http.MethodGet, "/api/v1/audit-logs?pageSize=100", c.token, nil, http.StatusOK, &page)
		for _, who := range []string{"contract-enroll@example.test", "contract-install@example.test", "contract-cancel@example.test"} {
			if !slices.ContainsFunc(page.Items, func(e entry) bool {
				var details struct {
					OnBehalfOf string `json:"onBehalfOf"`
				}
				return json.Unmarshal([]byte(e.Details), &details) == nil && details.OnBehalfOf == who
			}) {
				t.Errorf("no audit entry names %s", who)
			}
		}
		if t.Failed() {
			for _, e := range page.Items[:min(len(page.Items), 15)] {
				t.Logf("audit: %s %s", e.Action, e.Details)
			}
		}
	})

	run("eptest answers as EasyPatch does", func(t *testing.T) {
		checkFake(t, c, org.ID, site.ID, a.endpoint, install.ID)
	})
}

// checkFake asks eptest and the real server the same questions and checks
// that every field eptest answers with is in EasyPatch's answer, with a
// value of the same JSON type. EasyPatch may send more: the connector reads
// only what eptest sends.
func checkFake(t *testing.T, c *contract, org, site, endpoint, job uuid.UUID) {
	fake := eptest.New(t)
	fake.Set(func() { fake.Capabilities = []string{CapabilityScheduledInstalls, CapabilityOnBehalfOf} })
	fOrg := fake.Org("Contract")
	fSite := fake.Site(fOrg, "Head office")
	fEndpoint := fake.AddEndpoint(fOrg, "contract", "SN-contract", "fingerprint").ID
	fakeHTTP := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{TLSClientConfig: fakeTLS(t, fake.CAPEM)}}
	at := time.Now().Add(4 * time.Hour).UTC().Truncate(time.Second)
	install := map[string]any{"mode": "Selected", "updateGuids": []uuid.UUID{}, "force": false, "scheduledAt": at}
	// The fake's endpoint has its own update GUIDs; ask each for one of its own.
	pick := func(base string, hc *http.Client, token string, e uuid.UUID) uuid.UUID {
		_, data := call(c.ctx, t, hc, base, http.MethodGet, "/api/v1/endpoints/"+e.String()+"/updates", token, nil, nil)
		var list []struct {
			UpdateGUID uuid.UUID `json:"updateGuid"`
		}
		if err := json.Unmarshal(data, &list); err != nil || len(list) == 0 {
			t.Fatalf("updates: %v: %s", err, data)
		}
		return list[0].UpdateGUID
	}
	fakeInstall := map[string]any{"mode": "Selected", "updateGuids": []uuid.UUID{pick(fake.URL(), fakeHTTP, fake.Token, fEndpoint)},
		"force": false, "scheduledAt": at}
	install["updateGuids"] = []uuid.UUID{pick(c.url, c.http, c.token, endpoint)}

	// The fake's job comes from an install like the real one's.
	_, data := call(c.ctx, t, fakeHTTP, fake.URL(), http.MethodPost, "/api/v1/endpoints/"+fEndpoint.String()+"/install-updates", fake.Token,
		fakeInstall, nil)
	var fJob struct {
		ID uuid.UUID `json:"id"`
	}
	if err := json.Unmarshal(data, &fJob); err != nil {
		t.Fatalf("fake install: %v: %s", err, data)
	}

	type question struct {
		name, method   string
		fake, real     string
		fBody, rBody   any
		element        bool // compare one element of a list: the organization or site asked about
		fElem, rElem   uuid.UUID
		dictionaryKeys []string // objects whose keys are data, not field names
	}
	q := func(name, method, fakePath, realPath string) question {
		return question{name: name, method: method, fake: fakePath, real: realPath}
	}
	questions := []question{
		q("server info", "GET", "/api/v1/server-info", "/api/v1/server-info"),
		{name: "organizations", method: "GET", fake: "/api/v1/organizations", real: "/api/v1/organizations", element: true, fElem: fOrg, rElem: org},
		{name: "sites", method: "GET", fake: "/api/v1/organizations/" + fOrg.String() + "/sites", real: "/api/v1/organizations/" + org.String() + "/sites",
			element: true, fElem: fSite, rElem: site},
		q("endpoints", "GET", "/api/v1/endpoints?organizationId="+fOrg.String(), "/api/v1/endpoints?organizationId="+org.String()),
		q("endpoint", "GET", "/api/v1/endpoints/"+fEndpoint.String(), "/api/v1/endpoints/"+endpoint.String()),
		q("updates", "GET", "/api/v1/endpoints/"+fEndpoint.String()+"/updates", "/api/v1/endpoints/"+endpoint.String()+"/updates"),
		q("installed updates", "GET", "/api/v1/endpoints/"+fEndpoint.String()+"/installed-updates",
			"/api/v1/endpoints/"+endpoint.String()+"/installed-updates"),
		q("update history", "GET", "/api/v1/endpoints/"+fEndpoint.String()+"/update-history",
			"/api/v1/endpoints/"+endpoint.String()+"/update-history"),
		q("endpoint jobs", "GET", "/api/v1/endpoints/"+fEndpoint.String()+"/jobs", "/api/v1/endpoints/"+endpoint.String()+"/jobs"),
		q("jobs", "GET", "/api/v1/jobs?organizationId="+fOrg.String(), "/api/v1/jobs?organizationId="+org.String()),
		q("job", "GET", "/api/v1/jobs/"+fJob.ID.String(), "/api/v1/jobs/"+job.String()),
		{name: "effective policy", method: "GET", fake: "/api/v1/endpoints/" + fEndpoint.String() + "/effective-policy",
			real: "/api/v1/endpoints/" + endpoint.String() + "/effective-policy", dictionaryKeys: []string{"sources"}},
		q("not found", "GET", "/api/v1/endpoints/"+uuid.NewString(), "/api/v1/endpoints/"+uuid.NewString()),
		{name: "install", method: "POST", fake: "/api/v1/endpoints/" + fEndpoint.String() + "/install-updates",
			real: "/api/v1/endpoints/" + endpoint.String() + "/install-updates", fBody: fakeInstall, rBody: install},
		{name: "bulk scan", method: "POST", fake: "/api/v1/endpoints/bulk/scan", real: "/api/v1/endpoints/bulk/scan",
			fBody: map[string]any{"endpointIds": []uuid.UUID{fEndpoint, uuid.New()}, "force": false},
			rBody: map[string]any{"endpointIds": []uuid.UUID{endpoint, uuid.New()}, "force": false}},
		{name: "enrollment token", method: "POST", fake: "/api/v1/enrollment-tokens", real: "/api/v1/enrollment-tokens",
			fBody: map[string]any{"organizationId": fOrg, "siteId": fSite, "description": "shape", "expiresInHours": 1, "maxUses": 1, "count": 1},
			rBody: map[string]any{"organizationId": org, "siteId": site, "description": "shape", "expiresInHours": 1, "maxUses": 1, "count": 1}},
	}
	for _, qu := range questions {
		fStatus, fData := call(c.ctx, t, fakeHTTP, fake.URL(), qu.method, qu.fake, fake.Token, qu.fBody, nil)
		rStatus, rData := call(c.ctx, t, c.http, c.url, qu.method, qu.real, c.token, qu.rBody, nil)
		if fStatus != rStatus {
			t.Errorf("%s: eptest answers %d, EasyPatch %d: %s", qu.name, fStatus, rStatus, rData)
			continue
		}
		var f, r any
		if err := json.Unmarshal(fData, &f); err != nil {
			t.Errorf("%s: eptest: %v", qu.name, err)
			continue
		}
		if err := json.Unmarshal(rData, &r); err != nil {
			t.Errorf("%s: EasyPatch: %v", qu.name, err)
			continue
		}
		if qu.element {
			f, r = elementWithID(f, qu.fElem), elementWithID(r, qu.rElem)
			if f == nil || r == nil {
				t.Errorf("%s: the one asked about is missing (eptest %v, EasyPatch %v)", qu.name, f != nil, r != nil)
				continue
			}
		}
		if f == nil || r == nil {
			t.Errorf("%s: an empty answer", qu.name)
			continue
		}
		for _, p := range sameShape(qu.name, f, r, qu.dictionaryKeys) {
			t.Error(p)
		}
	}
}

func fakeTLS(t *testing.T, caPEM string) *tls.Config {
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM([]byte(caPEM)) {
		t.Fatal("eptest's CA is not PEM")
	}
	return &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}
}

func elementWithID(v any, id uuid.UUID) any {
	list, _ := v.([]any)
	for _, x := range list {
		if m, ok := x.(map[string]any); ok && m["id"] == id.String() {
			return m
		}
	}
	return nil
}

// sameShape lists the fields of fake that real lacks or has with another
// JSON type. A null on either side matches anything; a list's elements are
// compared with real's first. Objects named in dictionaries hold data in
// their keys, so only their values are compared, for the keys both have.
func sameShape(where string, fake, real any, dictionaries []string) []string {
	if fake == nil || real == nil {
		return nil
	}
	kind := func(v any) string {
		switch v.(type) {
		case map[string]any:
			return "an object"
		case []any:
			return "a list"
		case string:
			return "a string"
		case float64:
			return "a number"
		case bool:
			return "a boolean"
		}
		return fmt.Sprintf("%T", v)
	}
	if kind(fake) != kind(real) {
		return []string{fmt.Sprintf("%s: eptest sends %s, EasyPatch %s", where, kind(fake), kind(real))}
	}
	var problems []string
	switch f := fake.(type) {
	case map[string]any:
		r := real.(map[string]any)
		dictionary := slices.ContainsFunc(dictionaries, func(d string) bool { return strings.HasSuffix(where, "."+d) })
		keys := make([]string, 0, len(f))
		for k := range f {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			rv, ok := r[k]
			if !ok {
				if !dictionary {
					problems = append(problems, fmt.Sprintf("%s.%s: eptest sends it, EasyPatch does not", where, k))
				}
				continue
			}
			problems = append(problems, sameShape(where+"."+k, f[k], rv, dictionaries)...)
		}
	case []any:
		r := real.([]any)
		if len(r) > 0 {
			for i, fv := range f {
				problems = append(problems, sameShape(where+"["+strconv.Itoa(i)+"]", fv, r[0], dictionaries)...)
			}
		}
	}
	return problems
}
