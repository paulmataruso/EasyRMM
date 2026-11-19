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
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/easypatch/eptest"
	"github.com/paulmataruso/easyrmm/server/internal/httpapi"
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
	// engineURL and engineKey reach the same server as the patching engine
	// in EasyRMM's deployment does: plain HTTP on loopback, statements
	// signed with the gateway key (ADR-0038).
	engineURL string
	engineKey []byte
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
	c.engineURL = os.Getenv("EASYRMM_CONTRACT_ENGINE_URL")
	key, err := base64.StdEncoding.DecodeString(os.Getenv("EASYRMM_CONTRACT_ENGINE_KEY"))
	if c.url == "" || c.token == "" || c.readOnly == "" || caFile == "" || c.engineURL == "" || err != nil || len(key) < MinStatementKey {
		t.Fatal("the contract tests need a real EasyPatch server: run them with make test-contract")
	}
	c.engineKey = key
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
	// base is where it sends its requests, with header on each: EasyPatch's
	// own address unless it goes through EasyRMM's edge.
	base   string
	header http.Header
	// What its check-ins report.
	rebootPending bool
	capabilities  []string
}

func (c *contract) enroll(token, hostname string) *agent {
	c.t.Helper()
	return c.enrollVia(c.url, nil, token, hostname)
}

// enrollVia enrolls an agent that sends every request to base, with header.
func (c *contract) enrollVia(base string, header http.Header, token, hostname string) *agent {
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
	status, data := call(c.ctx, c.t, c.http, base, http.MethodPost, "/api/v1/agents/enroll", "", map[string]any{
		"enrollmentToken": token,
		"publicKey":       base64.StdEncoding.EncodeToString(spki),
		"agentVersion":    "1.10.0",
		"device": map[string]any{
			"hostname": hostname, "smbiosUuid": strings.ToUpper(uuid.NewString()), "serialNumber": "SN-" + hostname,
			"manufacturer": "QEMU", "model": "Standard PC (Q35 + ICH9, 2009)", "osCaption": "Debian GNU/Linux 13 (trixie)",
			"osBuild": "6.12.48+deb13-amd64", "architecture": "X64", "platform": "Linux", "osId": "debian", "osVersion": "13",
		},
	}, header)
	if status != http.StatusOK {
		c.t.Fatalf("enroll through %s answered %d: %s", base, status, data)
	}
	if err := json.Unmarshal(data, &r); err != nil {
		c.t.Fatal(err)
	}
	if r.State != "Active" || !strings.HasPrefix(r.CredentialID, "c_") || r.EndpointID == uuid.Nil || r.KeyFingerprint == "" {
		c.t.Fatalf("enrollment answered %+v", r)
	}
	return &agent{c: c, key: key, credential: r.CredentialID, endpoint: r.EndpointID, fingerprint: r.KeyFingerprint, base: base, header: header}
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
	header := a.header.Clone()
	if header == nil {
		header = http.Header{}
	}
	header.Set("X-EasyPatch-Credential", a.credential)
	header.Set("X-EasyPatch-Timestamp", timestamp)
	header.Set("X-EasyPatch-Nonce", nonce)
	header.Set("X-EasyPatch-Content-SHA256", contentHash)
	header.Set("X-EasyPatch-Signature", base64.StdEncoding.EncodeToString(signature))
	status, answer := call(a.c.ctx, t, a.c.http, a.base, http.MethodPost, route, "", json.RawMessage(data), header)
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
	// Restart is a restart job's settings.
	Restart map[string]any `json:"restart"`
}

type checkIn struct {
	Jobs         []deliveredJob `json:"jobs"`
	CancelJobIDs []uuid.UUID    `json:"cancelJobIds"`
}

func (a *agent) checkIn(active ...uuid.UUID) checkIn {
	a.c.t.Helper()
	var r checkIn
	if active == nil {
		active = []uuid.UUID{} // agents send lists, never null
	}
	reasons := []string{}
	if a.rebootPending {
		reasons = []string{"/var/run/reboot-required"}
	}
	a.post("/api/v1/agents/check-in", map[string]any{"agentVersion": "1.10.0", "activeJobIds": active, "currentActivity": "Idle",
		"agentArchitecture": "x64", "agentPackageFormat": "deb", "rebootPending": a.rebootPending, "rebootReasons": reasons,
		"capabilities": append([]string{}, a.capabilities...)}, &r)
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
	var restarted uuid.UUID // a restart job the agent completed
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
		if jobs, err := ep.Jobs(ctx, JobFilter{OrganizationID: org.ID, Active: true}, 1); err != nil || !slices.ContainsFunc(jobs.Items, func(j Job) bool { return j.ID == install.ID }) {
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

	run("retry a finished job", func(t *testing.T) {
		retry, err := ep.RetryJob(ctx, install.ID, "contract-retry@example.test")
		if err != nil {
			t.Fatal(err)
		}
		if retry.ID == install.ID || retry.Type != "InstallUpdates" || retry.Status != "Queued" || retry.EndpointID != a.endpoint {
			t.Errorf("retry %+v", retry)
		}
		var detail struct {
			RetryOfJobID uuid.UUID `json:"retryOfJobId"`
		}
		c.must(http.MethodGet, "/api/v1/jobs/"+retry.ID.String(), c.token, nil, http.StatusOK, &detail)
		if detail.RetryOfJobID != install.ID {
			t.Errorf("a retry of %v, want %v", detail.RetryOfJobID, install.ID)
		}
		// Only a finished job runs again, and not with a read-only token.
		var e *Error
		if _, err := ep.RetryJob(ctx, retry.ID, ""); !errors.As(err, &e) || e.Status != http.StatusConflict || e.Code != "invalid_state" {
			t.Errorf("retry of a queued job: %#v", err)
		}
		if _, err := ro.RetryJob(ctx, install.ID, ""); !IsStatus(err, http.StatusForbidden) {
			t.Errorf("read-only retry: %v", err)
		}
		if _, err := ep.CancelJob(ctx, retry.ID, ""); err != nil {
			t.Fatal(err)
		}
	})

	run("restart only where a restart is pending", func(t *testing.T) {
		a.capabilities = []string{"restart"}
		a.checkIn()
		if p, err := ep.RestartPending(ctx, org.ID); err != nil || p.Total != 0 || len(p.Endpoints) != 0 {
			t.Fatalf("nothing pending: %+v, %v", p, err)
		}
		a.rebootPending = true
		a.checkIn()
		p, err := ep.RestartPending(ctx, org.ID)
		if err != nil || p.Total != 1 || len(p.Endpoints) != 1 {
			t.Fatalf("pending: %+v, %v", p, err)
		}
		if e := p.Endpoints[0]; e.ID != a.endpoint || e.Platform != "Linux" || e.IsServer || !e.CanRestart || e.RebootPendingSince == nil {
			t.Errorf("pending endpoint %+v", e)
		}
		if _, err := ro.BulkRestart(ctx, []uuid.UUID{a.endpoint}, RestartOptions{Mode: "Countdown", Condition: "OnlyIfPending"}, ""); !IsStatus(err, http.StatusForbidden) {
			t.Errorf("read-only restart: %v", err)
		}

		// At a time: held until then.
		at := time.Now().Add(5 * time.Hour).UTC().Truncate(time.Second)
		later, err := ep.BulkRestart(ctx, []uuid.UUID{a.endpoint}, RestartOptions{Mode: "Countdown", Condition: "OnlyIfPending", ScheduledAt: &at}, "contract-restart@example.test")
		if err != nil || later.Succeeded != 1 || len(later.Results) != 1 || later.Results[0].JobID == nil {
			t.Fatalf("restart later %+v, %v", later, err)
		}
		job, err := ep.Job(ctx, *later.Results[0].JobID)
		if err != nil || job.Summary.Type != "Restart" || job.NotBefore == nil || !job.NotBefore.Equal(at) {
			t.Errorf("restart later %+v (not before %v), %v", job.Summary, job.NotBefore, err)
		}
		if _, err := ep.CancelJob(ctx, job.Summary.ID, ""); err != nil {
			t.Fatal(err)
		}

		// Now: the agent receives EasyRMM's preset at its next check-in.
		now, err := ep.BulkRestart(ctx, []uuid.UUID{a.endpoint}, RestartOptions{Mode: "Countdown", Condition: "OnlyIfPending"}, "")
		if err != nil || now.Succeeded != 1 || now.Results[0].JobID == nil {
			t.Fatalf("restart now %+v, %v", now, err)
		}
		id := *now.Results[0].JobID
		restarted = id
		in := a.checkIn()
		i := slices.IndexFunc(in.Jobs, func(j deliveredJob) bool { return j.JobID == id })
		if i < 0 {
			t.Fatalf("the restart was not delivered: %+v", in)
		}
		if r := in.Jobs[i].Restart; in.Jobs[i].Type != "Restart" || r["mode"] != "Countdown" || r["condition"] != "OnlyIfPending" ||
			r["countdownMinutes"] != 5.0 {
			t.Errorf("delivered restart %+v", in.Jobs[i])
		}
		a.post("/api/v1/agents/jobs/"+id.String()+"/ack", map[string]any{}, nil)
		a.report(id, "Completed")
		a.rebootPending = false
		a.checkIn()
		if job, err := ep.Job(ctx, id); err != nil || job.Summary.Status != "Completed" {
			t.Errorf("restart after the agent's report %+v, %v", job.Summary, err)
		}
		if p, err := ep.RestartPending(ctx, org.ID); err != nil || p.Total != 0 {
			t.Errorf("after the restart: %+v, %v", p, err)
		}

		// The options EasyRMM offers (one-product plan, C3): a prompt with a
		// deadline, whether or not a restart is pending, waiting an hour for
		// an offline computer. The endpoint says it can restart and whether
		// it is a server.
		if d, err := ep.Endpoint(ctx, a.endpoint); err != nil || !slices.Contains(d.AgentCapabilities, AgentCanRestart) ||
			d.OsProductType == "Server" || d.OsProductType == "DomainController" {
			t.Errorf("endpoint for a restart that need not be pending %+v, %v", d, err)
		}
		deadline, expiry := 120, 60
		prompt, err := ep.BulkRestart(ctx, []uuid.UUID{a.endpoint}, RestartOptions{Mode: "PromptWithDeadline", Condition: "Always",
			DeadlineMinutes: &deadline, ExpiresAfterMinutes: &expiry}, "contract-restart@example.test")
		if err != nil || prompt.Succeeded != 1 || prompt.Results[0].JobID == nil {
			t.Fatalf("restart with a prompt %+v, %v", prompt, err)
		}
		pid := *prompt.Results[0].JobID
		in = a.checkIn()
		i = slices.IndexFunc(in.Jobs, func(j deliveredJob) bool { return j.JobID == pid })
		if i < 0 {
			t.Fatalf("the prompted restart was not delivered: %+v", in)
		}
		if r := in.Jobs[i].Restart; r["mode"] != "PromptWithDeadline" || r["condition"] != "Always" || r["deadlineMinutes"] != 120.0 {
			t.Errorf("delivered prompted restart %+v", in.Jobs[i])
		}
		if job, err := ep.Job(ctx, pid); err != nil || job.Summary.CreatedAt.Add(time.Hour).Sub(job.Summary.ExpiresAt).Abs() > time.Minute {
			t.Errorf("prompted restart's expiry %+v, %v", job, err)
		}
		if _, err := ep.CancelJob(ctx, pid, ""); err != nil {
			t.Fatal(err)
		}
		// What EasyRMM refuses first, EasyPatch refuses too: per endpoint,
		// in a bulk request.
		short, long := 14, 10081
		for _, o := range []RestartOptions{{Mode: "Countdown", Condition: "Always", ExpiresAfterMinutes: &short},
			{Mode: "PromptWithDeadline", Condition: "Always", DeadlineMinutes: &long}} {
			if r, err := ep.BulkRestart(ctx, []uuid.UUID{a.endpoint}, o, ""); err != nil || r.Failed != 1 ||
				r.Results[0].ErrorCode != "validation_failed" {
				t.Errorf("restart %+v: %+v, %v", o, r, err)
			}
		}

		// Jobs filtered as the Jobs tab does: one endpoint's finished
		// restarts started by hand, and nothing from the future.
		done, err := ep.Jobs(ctx, JobFilter{OrganizationID: org.ID, EndpointID: &a.endpoint, Type: "Restart", Status: "Completed",
			Trigger: "Manual"}, 1)
		if err != nil || !slices.ContainsFunc(done.Items, func(j Job) bool { return j.ID == restarted }) {
			t.Errorf("finished restarts %+v, %v", done, err)
		}
		for _, j := range done.Items {
			if j.Type != "Restart" || j.Status != "Completed" || j.EndpointID != a.endpoint {
				t.Errorf("filtered job %+v", j)
			}
		}
		future := time.Now().Add(time.Hour)
		if none, err := ep.Jobs(ctx, JobFilter{OrganizationID: org.ID, From: &future}, 1); err != nil || none.TotalCount != 0 {
			t.Errorf("jobs from the future %+v, %v", none, err)
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

	run("the device's Patches tab", func(t *testing.T) {
		// What one-product plan C1 relies on: the endpoint's details, its
		// effective policy with where each value comes from, exclusions,
		// the install preview, messages and agent updates. The simulated
		// agent is a Linux one, which EasyPatch refuses messages and
		// removals for.
		detail, err := ep.Endpoint(ctx, a.endpoint)
		if err != nil || !slices.Contains(detail.AgentCapabilities, "restart") || detail.AgentUpdate == nil || detail.HasOwnPolicy {
			t.Fatalf("endpoint detail %+v, %v", detail, err)
		}
		policy, err := ep.EffectivePolicy(ctx, a.endpoint)
		if err != nil || len(policy.Sources) == 0 || !policy.AgentAutoUpdateEnabled || !policy.KnownExploitedSkipsDelay || policy.CheckInIntervalSeconds <= 0 {
			t.Fatalf("effective policy %+v, %v", policy, err)
		}
		for k, v := range policy.Sources {
			if !slices.Contains([]string{"Global", "Organization", "Site", "Endpoint", "Tag"}, v) || k == "" {
				t.Errorf("policy source %q: %q", k, v)
			}
		}

		if err := ep.Exclude(ctx, a.endpoint, tzdata, "contract", "contract-exclude@example.test"); err != nil {
			t.Fatal(err)
		}
		if err := ep.Exclude(ctx, a.endpoint, tzdata, "", ""); err != nil {
			t.Fatalf("excluding twice: %v", err)
		}
		find := func() Update {
			t.Helper()
			list, err := ep.Updates(ctx, a.endpoint, "")
			if err != nil {
				t.Fatal(err)
			}
			i := slices.IndexFunc(list, func(u Update) bool { return u.UpdateGUID == tzdata })
			if i < 0 {
				t.Fatalf("tzdata is not listed: %+v", list)
			}
			return list[i]
		}
		if u := find(); u.State != "Excluded" || !u.IsExcluded {
			t.Errorf("excluded update %+v", u)
		}
		p, err := ep.InstallPreview(ctx, a.endpoint, nil)
		if err != nil || p.Mode != "AllEligible" || !slices.ContainsFunc(p.Skipped, func(x PreviewSkip) bool { return x.UpdateGUID == tzdata && x.Reason == "Excluded" }) ||
			slices.ContainsFunc(p.Items, func(x PreviewItem) bool { return x.UpdateGUID == tzdata }) || p.Filter == nil {
			t.Errorf("preview with tzdata excluded %+v, %v", p, err)
		}
		p, err = ep.InstallPreview(ctx, a.endpoint, []uuid.UUID{openssl, tzdata})
		if err != nil || p.Mode != "Selected" || len(p.Items)+len(p.Skipped) != 2 {
			t.Errorf("preview of two updates %+v, %v", p, err)
		}
		if _, err := ro.InstallPreview(ctx, a.endpoint, nil); err != nil {
			t.Errorf("read-only preview: %v", err)
		}
		if err := ro.Exclude(ctx, a.endpoint, openssl, "", ""); !IsStatus(err, http.StatusForbidden) {
			t.Errorf("read-only exclusion: %v", err)
		}
		if err := ep.Include(ctx, a.endpoint, tzdata, "contract-include@example.test"); err != nil {
			t.Fatal(err)
		}
		if u := find(); u.State == "Excluded" || u.IsExcluded {
			t.Errorf("included update %+v", u)
		}
		if err := ep.Include(ctx, a.endpoint, tzdata, ""); err != nil {
			t.Errorf("including an update that is not excluded: %v", err)
		}

		// Removing an update: refused on Linux, with a reason to show.
		_, err = ep.RemoveUpdate(ctx, a.endpoint, libc, true, "contract", "")
		var e *Error
		if !errors.As(err, &e) || e.Status != http.StatusConflict || e.Code != "not_supported_on_linux" || !strings.Contains(e.Detail, "only available on Windows") {
			t.Errorf("removal on Linux: %#v", err)
		}

		presets, err := ep.MessagePresets(ctx)
		if err != nil || len(presets) != 6 || presets[5].Preset != "RestartScheduled" || !presets[5].NeedsRestartTime ||
			!strings.Contains(presets[5].Body, "{time}") || presets[0].Preset != "UpdatesInstalling" || presets[0].Title == "" {
			t.Errorf("message presets %+v, %v", presets, err)
		}
		if _, err := ro.MessagePresets(ctx); err != nil {
			t.Errorf("read-only presets: %v", err)
		}
		at := time.Now().Add(time.Hour).UTC()
		n, err := ep.BulkNotify(ctx, []uuid.UUID{a.endpoint}, Message{Preset: "RestartScheduled", RestartAt: &at}, "")
		if err != nil || n.Failed != 1 || n.Results[0].Success || n.Results[0].ErrorCode != "not_supported_on_linux" ||
			!strings.Contains(n.Results[0].Message, "Messages to users are only available on Windows") {
			t.Errorf("message on Linux %+v, %v", n, err)
		}
		if _, err := ro.BulkNotify(ctx, []uuid.UUID{a.endpoint}, Message{Preset: "SaveYourWork"}, ""); !IsStatus(err, http.StatusForbidden) {
			t.Errorf("read-only message: %v", err)
		}

		// An agent update is planned against what the agent reports: the
		// simulated one has no release key, so EasyPatch refuses with a
		// reason (agent_upgrade_required) that the console shows.
		u, err := ep.BulkAgentUpdate(ctx, []uuid.UUID{a.endpoint}, "contract-agent-update@example.test")
		if err != nil || len(u.Results) != 1 {
			t.Fatalf("agent update %+v, %v", u, err)
		}
		if r := u.Results[0]; (r.Success && r.JobID == nil) || (!r.Success && (r.ErrorCode == "" || r.Message == "")) {
			t.Errorf("agent update result %+v", r)
		} else {
			t.Logf("agent update: success %v, %s %s", r.Success, r.ErrorCode, r.Message)
			if r.JobID != nil {
				if _, err := ep.CancelJob(ctx, *r.JobID, ""); err != nil {
					t.Error(err)
				}
			}
		}
		if _, err := ro.BulkAgentUpdate(ctx, []uuid.UUID{a.endpoint}, ""); !IsStatus(err, http.StatusForbidden) {
			t.Errorf("read-only agent update: %v", err)
		}
	})

	run("the update catalog and holds", func(t *testing.T) {
		// What one-product plan C2 relies on: the catalog counted over an
		// organization or a site, one update with the endpoints that report
		// it, installing and removing it across endpoints, and holds.
		scope := FleetScope{OrganizationID: &org.ID}
		p, err := ep.Catalog(ctx, CatalogQuery{FleetScope: scope})
		if err != nil {
			t.Fatal(err)
		}
		i := slices.IndexFunc(p.Items, func(u FleetUpdate) bool { return u.UpdateGUID == tzdata })
		if i < 0 || p.Items[i].MissingCount != 1 || p.Items[i].Title != "tzdata 2026c-0+deb13u1" || p.Items[i].Category != "Other" ||
			p.Items[i].Package == nil || p.PageSize != CatalogPageSize || p.Items[i].OnHold {
			t.Fatalf("catalog %+v", p)
		}
		if slices.ContainsFunc(p.Items, func(u FleetUpdate) bool { return u.UpdateGUID == libc }) {
			t.Errorf("an update installed everywhere is listed: %+v", p.Items)
		}
		installed, err := ep.Catalog(ctx, CatalogQuery{FleetScope: scope, State: "Installed"})
		if i := slices.IndexFunc(installed.Items, func(u FleetUpdate) bool { return u.UpdateGUID == libc }); err != nil || i < 0 ||
			installed.Items[i].InstalledCount != 1 {
			t.Errorf("installed updates %+v, %v", installed, err)
		}
		for name, q := range map[string]CatalogQuery{
			"site":        {FleetScope: FleetScope{OrganizationID: &org.ID, SiteID: &site.ID}},
			"search":      {FleetScope: scope, Search: "TZDATA"},
			"category":    {FleetScope: scope, Category: "Other"},
			"most failed": {FleetScope: scope, Sort: "failed", Desc: true},
		} {
			if p, err := ep.Catalog(ctx, q); err != nil || !slices.ContainsFunc(p.Items, func(u FleetUpdate) bool { return u.UpdateGUID == tzdata }) {
				t.Errorf("%s: %+v, %v", name, p, err)
			}
		}
		other := uuid.New()
		if p, err := ep.Catalog(ctx, CatalogQuery{FleetScope: FleetScope{SiteID: &other}}); err != nil || len(p.Items) != 0 {
			t.Errorf("another site: %+v, %v", p, err)
		}
		exploited := true
		if p, err := ep.Catalog(ctx, CatalogQuery{FleetScope: scope, KnownExploited: &exploited}); err != nil ||
			slices.ContainsFunc(p.Items, func(u FleetUpdate) bool { return u.UpdateGUID == tzdata }) {
			t.Errorf("known exploited: %+v, %v", p, err)
		}

		d, err := ep.FleetUpdate(ctx, tzdata, scope)
		if err != nil || d.Summary.MissingCount != 1 || d.Summary.Title != "tzdata 2026c-0+deb13u1" || d.KbNumbers == nil || len(d.Holds) != 0 {
			t.Fatalf("update %+v, %v", d, err)
		}
		if _, err := ep.FleetUpdate(ctx, uuid.New(), scope); !IsStatus(err, http.StatusNotFound) {
			t.Errorf("unknown update: %v", err)
		}
		ends, err := ep.FleetUpdateEndpoints(ctx, tzdata, scope, "", 1)
		if err != nil || ends.TotalCount != 1 || ends.Items[0].EndpointID != a.endpoint || ends.Items[0].Hostname != "contract-"+suffix ||
			ends.Items[0].State != "Missing" || ends.Items[0].SiteName != "Head office" || ends.Items[0].IsExcluded {
			t.Errorf("update's endpoints %+v, %v", ends, err)
		}
		if ends, err := ep.FleetUpdateEndpoints(ctx, tzdata, scope, "Installed", 1); err != nil || len(ends.Items) != 0 {
			t.Errorf("endpoints where it is installed %+v, %v", ends, err)
		}

		// Installing on the endpoint: a job, or a reason (the scheduled
		// install of tzdata may still be queued).
		r, err := ep.FleetInstall(ctx, tzdata, []uuid.UUID{a.endpoint}, "contract-fleet@example.test")
		if err != nil || len(r.Results) != 1 || r.Results[0].EndpointID != a.endpoint {
			t.Fatalf("install on endpoints %+v, %v", r, err)
		}
		if x := r.Results[0]; (x.Success && x.JobID == nil) || (!x.Success && (x.ErrorCode == "" || x.Message == "")) {
			t.Errorf("install result %+v", x)
		} else if x.Success {
			if _, err := ep.CancelJob(ctx, *x.JobID, ""); err != nil {
				t.Error(err)
			}
		} else {
			t.Logf("install on endpoints: %s %s", x.ErrorCode, x.Message)
		}
		// Endpoints where it is not missing are left out, unanswered.
		if r, err := ep.FleetInstall(ctx, libc, []uuid.UUID{a.endpoint}, ""); err != nil || len(r.Results) != 0 {
			t.Errorf("install where it is installed %+v, %v", r, err)
		}
		if _, err := ro.FleetInstall(ctx, tzdata, []uuid.UUID{a.endpoint}, ""); !IsStatus(err, http.StatusForbidden) {
			t.Errorf("read-only install: %v", err)
		}
		// Removing: refused on Linux, per endpoint.
		r, err = ep.FleetRemove(ctx, libc, []uuid.UUID{a.endpoint}, true, "contract", "")
		if err != nil || len(r.Results) != 1 || r.Results[0].Success || r.Results[0].ErrorCode != "not_supported_on_linux" {
			t.Errorf("removal on Linux %+v, %v", r, err)
		}
		if r, err := ep.FleetRemove(ctx, tzdata, []uuid.UUID{a.endpoint}, false, "", ""); err != nil || len(r.Results) != 0 {
			t.Errorf("removal where it is not installed %+v, %v", r, err)
		}

		// Holds.
		h, err := ep.HoldUpdate(ctx, tzdata, &org.ID, "contract hold", "contract-hold@example.test")
		if err != nil || h.ID == uuid.Nil || h.OrganizationID == nil || *h.OrganizationID != org.ID || h.Source != "Manual" ||
			h.Reason != "contract hold" || !h.CanRelease || h.ReleasedAt != nil || h.Title != "tzdata 2026c-0+deb13u1" {
			t.Fatalf("hold %+v, %v", h, err)
		}
		_, err = ep.HoldUpdate(ctx, tzdata, &org.ID, "again", "")
		var e *Error
		if !errors.As(err, &e) || e.Status != http.StatusConflict || e.Code != "already_held" {
			t.Errorf("holding again: %#v", err)
		}
		if _, err := ep.HoldUpdate(ctx, uuid.New(), &org.ID, "unknown", ""); !IsStatus(err, http.StatusNotFound) {
			t.Errorf("holding an unknown update: %v", err)
		}
		if _, err := ro.HoldUpdate(ctx, tzdata, &org.ID, "read-only", ""); !IsStatus(err, http.StatusForbidden) {
			t.Errorf("read-only hold: %v", err)
		}
		if d, err := ep.FleetUpdate(ctx, tzdata, scope); err != nil || !d.Summary.OnHold || len(d.Holds) != 1 || d.Holds[0].ID != h.ID {
			t.Errorf("held update %+v, %v", d, err)
		}
		if p, err := ep.Catalog(ctx, CatalogQuery{FleetScope: scope, Search: "tzdata"}); err != nil || len(p.Items) != 1 || !p.Items[0].OnHold {
			t.Errorf("held in the catalog %+v, %v", p, err)
		}
		if list, err := ep.Holds(ctx, tzdata); err != nil || !slices.ContainsFunc(list, func(x Hold) bool { return x.ID == h.ID }) {
			t.Errorf("holds %+v, %v", list, err)
		}
		released, err := ep.ReleaseHold(ctx, h.ID, "contract-release@example.test")
		if err != nil || released.ReleasedAt == nil || released.CanRelease {
			t.Fatalf("release %+v, %v", released, err)
		}
		if _, err := ep.ReleaseHold(ctx, h.ID, ""); err != nil {
			t.Errorf("releasing again: %v", err)
		}
		if list, err := ep.Holds(ctx, tzdata); err != nil || slices.ContainsFunc(list, func(x Hold) bool { return x.ID == h.ID }) {
			t.Errorf("holds once released %+v, %v", list, err)
		}

		// Through the engine: statements bound the catalog, an
		// administrator holds in the organization, a super administrator
		// everywhere.
		signer, err := NewSigner(c.engineKey)
		if err != nil {
			t.Fatal(err)
		}
		engine, err := NewEngineClient(c.engineURL, signer, "contract")
		if err != nil {
			t.Fatal(err)
		}
		as := func(role string, orgs ...uuid.UUID) context.Context {
			return WithStatement(ctx, Statement{Subject: uuid.NewString(), Name: "contract-engine@example.test", Role: role, Organizations: orgs})
		}
		if p, err := engine.Catalog(as(RoleReadOnly, org.ID), CatalogQuery{}); err != nil ||
			!slices.ContainsFunc(p.Items, func(u FleetUpdate) bool { return u.UpdateGUID == tzdata }) {
			t.Errorf("catalog, the organization named: %+v, %v", p, err)
		}
		if p, err := engine.Catalog(as(RoleReadOnly, uuid.New()), CatalogQuery{Search: "tzdata 2026c"}); err != nil ||
			slices.ContainsFunc(p.Items, func(u FleetUpdate) bool { return u.UpdateGUID == tzdata }) {
			t.Errorf("catalog, another organization named: %+v, %v", p, err)
		}
		mine, err := engine.HoldUpdate(as(RoleAdmin, org.ID), tzdata, &org.ID, "engine hold", "")
		if err != nil || !mine.CanRelease || mine.CreatedBy != "easyrmm:contract-engine@example.test" {
			t.Fatalf("hold as an administrator of the organization: %+v, %v", mine, err)
		}
		if _, err := engine.HoldUpdate(as(RoleAdmin, org.ID), tzdata, nil, "everywhere", ""); !IsStatus(err, http.StatusForbidden) {
			t.Errorf("an administrator held an update everywhere: %v", err)
		}
		if _, err := engine.HoldUpdate(as(RoleAdmin, uuid.New()), tzdata, &org.ID, "elsewhere", ""); err == nil {
			t.Error("an administrator of another organization held an update in this one")
		}
		if _, err := engine.ReleaseHold(as(RoleAdmin, org.ID), mine.ID, ""); err != nil {
			t.Error(err)
		}
		super := WithStatement(ctx, Statement{Subject: uuid.NewString(), Name: "contract-engine@example.test", Role: RoleSuperAdmin, AllOrganizations: true})
		every, err := engine.HoldUpdate(super, tzdata, nil, "engine hold everywhere", "")
		if err != nil || every.OrganizationID != nil || !every.CanRelease {
			t.Fatalf("hold everywhere as a super administrator: %+v, %v", every, err)
		}
		if list, err := engine.Holds(as(RoleReadOnly, org.ID), tzdata); err != nil || len(list) != 1 || list[0].ID != every.ID || list[0].CanRelease {
			t.Errorf("a hold everywhere, as a reader: %+v, %v", list, err)
		}
		if _, err := engine.ReleaseHold(as(RoleAdmin, org.ID), every.ID, ""); !IsStatus(err, http.StatusForbidden) {
			t.Errorf("an administrator released a hold everywhere: %v", err)
		}
		if _, err := engine.ReleaseHold(super, every.ID, ""); err != nil {
			t.Error(err)
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

	// Whatever packages the image carries (ADR-0041) are of the engine's
	// own version, each with a valid release signature. CI's contract image
	// carries none; build one with scripts/build-test-agent-packages.sh to
	// check them.
	run("agent packages", func(t *testing.T) {
		list, err := ep.AgentPackages(ctx)
		if err != nil {
			t.Fatal(err)
		}
		info, err := ep.ServerInfo(ctx)
		if err != nil {
			t.Fatal(err)
		}
		for _, p := range list {
			if p.Version != info.Version || p.ReleaseKeyID == "" || p.SignatureProblem != "" || !p.IsLatest {
				t.Errorf("package %+v on a %s engine", p, info.Version)
			}
		}
		t.Logf("%d agent packages", len(list))
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
		for _, who := range []string{"contract-enroll@example.test", "contract-install@example.test", "contract-cancel@example.test",
			"contract-retry@example.test", "contract-restart@example.test"} {
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

	run("the patching engine: statements instead of a token", func(t *testing.T) {
		signer, err := NewSigner(c.engineKey)
		if err != nil {
			t.Fatal(err)
		}
		engine, err := NewEngineClient(c.engineURL, signer, "contract")
		if err != nil {
			t.Fatal(err)
		}
		// EasyRMM's own work: Admin in every organization, as the API token.
		if orgs, err := engine.Organizations(ctx); err != nil || !slices.ContainsFunc(orgs, func(o Organization) bool { return o.ID == org.ID }) {
			t.Fatalf("organizations as EasyRMM: %+v, %v", orgs, err)
		}
		// A person's call sees only the organizations it names.
		as := func(role string, orgs ...uuid.UUID) context.Context {
			return WithStatement(ctx, Statement{Subject: uuid.NewString(), Name: "contract-engine@example.test", Role: role, Organizations: orgs})
		}
		if _, err := engine.Endpoint(as(RoleReadOnly, org.ID), a.endpoint); err != nil {
			t.Errorf("endpoint, its organization named: %v", err)
		}
		// What is not any organization's needs none named.
		if p, err := engine.MessagePresets(as(RoleReadOnly)); err != nil || len(p) != 6 {
			t.Errorf("message presets, no organization named: %+v, %v", p, err)
		}
		if _, err := engine.Endpoint(as(RoleReadOnly, uuid.New()), a.endpoint); !IsStatus(err, http.StatusNotFound) {
			t.Errorf("endpoint, another organization named: %v", err)
		}
		if page, err := engine.Endpoints(as(RoleReadOnly), org.ID, 1); err == nil && len(page.Items) > 0 {
			t.Errorf("endpoints with no organization named: %+v", page)
		}
		// Read-only reads but never acts; the console shows the engine
		// refusing EasyRMM as the engine being unavailable, never as a 401
		// or 403 it would take for a lost session.
		_, err = engine.BulkScan(as(RoleReadOnly, org.ID), []uuid.UUID{a.endpoint}, "")
		if !IsStatus(err, http.StatusForbidden) {
			t.Fatalf("read-only scan: %v", err)
		}
		if ae, ok := apperr.As(epError(err)); !ok || ae.Kind != apperr.KindUnavailable || ae.Code != "patching_unavailable" {
			t.Errorf("read-only scan shows as %#v", epError(err))
		}
		// An administrator of the organization acts in it, and only in it.
		token, err := engine.CreateEnrollmentToken(as(RoleAdmin, org.ID), org.ID, &site.ID, "EasyRMM engine contract", "")
		if err != nil || token.ID == uuid.Nil {
			t.Fatalf("enrollment token as an administrator of the organization: %+v, %v", token, err)
		}
		if err := engine.RevokeEnrollmentToken(as(RoleAdmin, org.ID), token.ID, ""); err != nil {
			t.Error(err)
		}
		if _, err := engine.CreateEnrollmentToken(as(RoleAdmin, uuid.New()), org.ID, &site.ID, "elsewhere", ""); err == nil {
			t.Error("an administrator of another organization created an enrollment token in this one")
		}
		// A wrong key: refused, and shown the same way.
		other, _ := NewSigner(bytes.Repeat([]byte{1}, 32))
		wrong, err := NewEngineClient(c.engineURL, other, "contract")
		if err != nil {
			t.Fatal(err)
		}
		_, err = wrong.Organizations(ctx)
		if !IsStatus(err, http.StatusUnauthorized) {
			t.Fatalf("wrong key: %v", err)
		}
		if ae, ok := apperr.As(epError(err)); !ok || ae.Kind != apperr.KindUnavailable || ae.Code != "patching_unavailable" {
			t.Errorf("wrong key shows as %#v", epError(err))
		}
		// EasyPatch's field errors become EasyRMM's.
		err = engine.do(WithStatement(ctx, Statement{Subject: ServiceSubject, Name: "EasyRMM", Role: RoleSuperAdmin, AllOrganizations: true}),
			http.MethodPost, "/api/v1/notifications/channels", nil, map[string]any{"name": "", "type": "Email", "emailRecipients": []string{}}, "", nil)
		ae, ok := apperr.As(epError(err))
		if !ok || ae.Kind != apperr.KindInvalid || ae.Fields["name"] == "" || ae.Fields["emailRecipients"] == "" {
			t.Errorf("validation errors show as %#v (from %v)", epError(err), err)
		}
		// EasyPatch's audit log names EasyRMM's user.
		type entry struct {
			Username string `json:"username"`
			Action   string `json:"action"`
		}
		var page struct {
			Items []entry `json:"items"`
		}
		c.must(http.MethodGet, "/api/v1/audit-logs?pageSize=100", c.token, nil, http.StatusOK, &page)
		if !slices.ContainsFunc(page.Items, func(e entry) bool { return e.Username == "easyrmm:contract-engine@example.test" }) {
			t.Errorf("no audit entry names easyrmm:contract-engine@example.test: %+v", page.Items[:min(len(page.Items), 10)])
		}
	})

	run("eptest answers as EasyPatch does", func(t *testing.T) {
		a.rebootPending = true // so the restart-pending list is not empty
		a.checkIn()
		checkFake(t, c, org.ID, site.ID, a.endpoint, install.ID, restarted, suffix)
	})

	run("organizations, sites and endpoints for the reconciler", func(t *testing.T) {
		// What EasyRMM's reconciler relies on (one-product plan, B5), as the
		// engine in the deployment does it.
		signer, err := NewSigner(c.engineKey)
		if err != nil {
			t.Fatal(err)
		}
		engine, err := NewEngineClient(c.engineURL, signer, "contract")
		if err != nil {
			t.Fatal(err)
		}
		svc := WithStatement(ctx, Statement{Subject: ServiceSubject, Name: "EasyRMM", Role: RoleAdmin, AllOrganizations: true})
		scoped := WithStatement(ctx, Statement{Subject: ServiceSubject, Name: "EasyRMM", Role: RoleAdmin, Organizations: []uuid.UUID{org.ID}})

		// Organizations: only an all-organizations principal creates one;
		// names are unique case-sensitively, archived ones included.
		name := "Reconcile " + suffix
		if _, err := engine.CreateOrganization(scoped, name, "UTC"); !IsStatus(err, http.StatusForbidden) {
			t.Fatalf("create, scoped to one organization: %v", err)
		}
		o, err := engine.CreateOrganization(svc, name, "Europe/London")
		if err != nil || o.ID == uuid.Nil || o.Name != name || o.TimeZone != "Europe/London" || !o.IsActive {
			t.Fatalf("create: %+v, %v", o, err)
		}
		if _, err := engine.CreateOrganization(svc, name, "UTC"); !IsStatus(err, http.StatusConflict) {
			t.Fatalf("same name: %v", err)
		}
		other, err := engine.CreateOrganization(svc, strings.ToUpper(name), "UTC")
		if err != nil {
			t.Fatalf("a name differing only by case: %v", err)
		}
		if _, err := engine.CreateOrganization(svc, name, "Mars/Olympus"); err == nil {
			t.Fatal("an unknown time zone was accepted")
		} else if ae, ok := apperr.As(epError(err)); !ok || ae.Kind != apperr.KindInvalid || ae.Fields["timeZone"] == "" {
			t.Errorf("unknown time zone shows as %#v", epError(err))
		}
		// An update keeps what it is sent back, and replaces the rest.
		desc := "kept"
		o.Description = &desc
		o.TimeZone = "America/New_York"
		if o, err = engine.UpdateOrganization(svc, o); err != nil || o.TimeZone != "America/New_York" || o.Description == nil || *o.Description != desc {
			t.Fatalf("update: %+v, %v", o, err)
		}
		o.Name = name + " renamed"
		if o, err = engine.UpdateOrganization(svc, o); err != nil || o.Name != name+" renamed" || o.Description == nil {
			t.Fatalf("rename: %+v, %v", o, err)
		}
		o.Name = strings.ToUpper(name)
		if _, err := engine.UpdateOrganization(svc, o); !IsStatus(err, http.StatusConflict) {
			t.Fatalf("rename onto another's name: %v", err)
		}
		o.Name = name + " renamed"

		// Sites: unique per organization, archived ones included; a new
		// site takes its organization's time zone.
		site1, err := engine.CreateSite(svc, o.ID, "North", "")
		if err != nil || site1.TimeZone != "America/New_York" || site1.OrganizationID != o.ID {
			t.Fatalf("site: %+v, %v", site1, err)
		}
		site2, err := engine.CreateSite(svc, o.ID, "South", "Asia/Tokyo")
		if err != nil || site2.TimeZone != "Asia/Tokyo" {
			t.Fatalf("second site: %+v, %v", site2, err)
		}
		if _, err := engine.CreateSite(svc, o.ID, "North", ""); !IsStatus(err, http.StatusConflict) {
			t.Fatalf("same site name: %v", err)
		}
		if _, err := engine.CreateSite(svc, other.ID, "North", ""); err != nil {
			t.Fatalf("the same site name in another organization: %v", err)
		}
		addr := "1 Main St"
		site1.Address, site1.Name = &addr, "North office"
		if site1, err = engine.UpdateSite(svc, site1); err != nil || site1.Name != "North office" || site1.Address == nil {
			t.Fatalf("site update: %+v, %v", site1, err)
		}
		if got, err := engine.GetSite(svc, site1.ID); err != nil || got.Name != "North office" {
			t.Fatalf("site read: %+v, %v", got, err)
		}

		// Endpoints move between the sites of their organization only.
		tok, err := engine.CreateEnrollmentToken(svc, o.ID, &site1.ID, "reconcile contract", "")
		if err != nil {
			t.Fatal(err)
		}
		r := c.enroll(tok.Secret, "contract-reconcile-"+suffix)
		r.capabilities = []string{"uninstall"} // EasyPatch's agents since 1.6.0
		r.checkIn()
		e, err := engine.Endpoint(svc, r.endpoint)
		if err != nil || e.Summary.SiteID == nil || *e.Summary.SiteID != site1.ID || e.EsuOverride == "" {
			t.Fatalf("enrolled endpoint: %+v, %v", e.Summary, err)
		}
		if err := engine.MoveEndpoint(svc, r.endpoint, &site2.ID); err != nil {
			t.Fatal(err)
		}
		if e, err = engine.Endpoint(svc, r.endpoint); err != nil || e.Summary.SiteID == nil || *e.Summary.SiteID != site2.ID {
			t.Fatalf("moved: %+v, %v", e.Summary, err)
		}
		otherSites, err := engine.AllSites(svc, other.ID)
		if err != nil || len(otherSites) == 0 {
			t.Fatalf("other organization's sites: %+v, %v", otherSites, err)
		}
		if err := engine.MoveEndpoint(svc, r.endpoint, &otherSites[0].ID); !IsStatus(err, http.StatusBadRequest) {
			t.Fatalf("a move to another organization's site: %v", err)
		}

		// Uninstall first: revoking cancels open jobs, the uninstall's too.
		job, err := engine.UninstallAgent(svc, r.endpoint)
		if err != nil || job.ID == uuid.Nil {
			t.Fatalf("uninstall: %+v, %v", job, err)
		}
		if _, err := engine.UninstallAgent(svc, r.endpoint); !IsStatus(err, http.StatusConflict) {
			t.Fatalf("a second uninstall: %v", err)
		} else if e := (*Error)(nil); !errors.As(err, &e) || e.Code != "duplicate_job" {
			t.Errorf("a second uninstall: %v", err)
		}
		if err := engine.RevokeEndpoint(svc, r.endpoint, "EasyRMM contract"); err != nil {
			t.Fatal(err)
		}
		if d, err := engine.Job(svc, job.ID); err != nil || d.Summary.Status != "Cancelled" { //nolint:misspell // EasyPatch's enum value
			t.Fatalf("uninstall after revoking: %+v, %v", d.Summary.Status, err)
		}
		if _, err := engine.UninstallAgent(svc, r.endpoint); !IsStatus(err, http.StatusConflict) {
			t.Fatalf("uninstall of a revoked endpoint: %v", err)
		}

		// Archived: hidden from lists unless asked for, its name still
		// taken, and no new enrollments.
		if err := engine.ArchiveSite(svc, site2.ID); err != nil {
			t.Fatal(err)
		}
		if sites, err := engine.Sites(svc, o.ID); err != nil || slices.ContainsFunc(sites, func(x Site) bool { return x.ID == site2.ID }) {
			t.Fatalf("archived site listed: %+v, %v", sites, err)
		}
		if sites, err := engine.AllSites(svc, o.ID); err != nil || !slices.ContainsFunc(sites, func(x SiteDetail) bool { return x.ID == site2.ID && !x.IsActive }) {
			t.Fatalf("archived site not listed with the archived: %+v, %v", sites, err)
		}
		if _, err := engine.CreateSite(svc, o.ID, "South", ""); !IsStatus(err, http.StatusConflict) {
			t.Fatalf("an archived site's name: %v", err)
		}
		if err := engine.ArchiveOrganization(svc, o.ID); err != nil {
			t.Fatal(err)
		}
		if err := engine.ArchiveOrganization(svc, o.ID); err != nil {
			t.Fatalf("archiving twice: %v", err)
		}
		if list, err := engine.Organizations(svc); err != nil || slices.ContainsFunc(list, func(x Organization) bool { return x.ID == o.ID }) {
			t.Fatalf("archived organization listed: %v", err)
		}
		if list, err := engine.AllOrganizations(svc); err != nil || !slices.ContainsFunc(list, func(x Organization) bool { return x.ID == o.ID && !x.IsActive }) {
			t.Fatalf("archived organization not listed with the archived: %v", err)
		}
		if _, err := engine.CreateOrganization(svc, o.Name, "UTC"); !IsStatus(err, http.StatusConflict) {
			t.Fatalf("an archived organization's name: %v", err)
		}
		if _, err := engine.CreateEnrollmentToken(svc, o.ID, nil, "archived", ""); !IsStatus(err, http.StatusConflict) {
			t.Fatalf("a token in an archived organization: %v", err)
		}
		// Renamed, the archived organization frees its name.
		got, err := engine.GetOrganization(svc, o.ID)
		if err != nil || got.IsActive || got.ArchivedAt == nil {
			t.Fatalf("archived organization: %+v, %v", got, err)
		}
		freed := got.Name
		got.Name += " (deleted)"
		if _, err := engine.UpdateOrganization(svc, got); err != nil {
			t.Fatalf("renaming an archived organization: %v", err)
		}
		if _, err := engine.CreateOrganization(svc, freed, "UTC"); err != nil {
			t.Fatalf("a freed name: %v", err)
		}
	})

	run("agents through EasyRMM's edge", func(t *testing.T) {
		// In bundled mode the edge forwards the engine's agent paths (one-
		// product plan, B4). Agents sign the method, the request target and
		// the body: the engine accepting them proves all three arrive as
		// sent. The engine records the client address EasyRMM resolved,
		// and never sees a statement from outside.
		target, err := url.Parse(c.engineURL)
		if err != nil {
			t.Fatal(err)
		}
		fwd := NewAgentProxy(target, true, slog.New(slog.DiscardHandler))
		edge := httptest.NewServer(httpapi.Chain(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !AgentPath(r.URL.Path) {
				http.NotFound(w, r)
				return
			}
			fwd.ServeHTTP(w, httpapi.WithOrigin(r, httpapi.Origin{Console: "https://rmm.example.test"}))
		}), httpapi.RealIP([]netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")})))
		t.Cleanup(edge.Close)

		signer, err := NewSigner(c.engineKey)
		if err != nil {
			t.Fatal(err)
		}
		engine, err := NewEngineClient(c.engineURL, signer, "contract")
		if err != nil {
			t.Fatal(err)
		}
		admin := WithStatement(ctx, Statement{Subject: ServiceSubject, Name: "contract-edge@example.test", Role: RoleAdmin, Organizations: []uuid.UUID{org.ID}})
		token, err := engine.CreateEnrollmentToken(admin, org.ID, &site.ID, "EasyRMM edge contract", "")
		if err != nil {
			t.Fatal(err)
		}
		// As if through two of EasyRMM's own proxies on loopback, from a
		// device at 203.0.113.9 that claims another address and makes up a
		// statement. Passed on as sent, the engine (which reads the last
		// address) would see 127.0.0.5.
		via := http.Header{"X-Forwarded-For": {"198.51.100.1, 203.0.113.9, 127.0.0.5"}, StatementHeader: {"forged"}}
		b := c.enrollVia(edge.URL, via, token.Secret, "contract-edge-"+suffix)
		b.checkIn()

		// EasyPatch writes the address it saw at its next presence flush.
		deadline := time.Now().Add(45 * time.Second)
		for {
			var ep struct {
				Summary struct {
					LastSeenIP string `json:"lastSeenIp"`
				} `json:"summary"`
			}
			if err := engine.do(admin, http.MethodGet, "/api/v1/endpoints/"+b.endpoint.String(), nil, nil, "", &ep); err != nil {
				t.Fatal(err)
			}
			if ep.Summary.LastSeenIP == "203.0.113.9" {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("the engine saw the agent at %q, not at the address EasyRMM resolved", ep.Summary.LastSeenIP)
			}
			time.Sleep(time.Second)
		}

		// Downloads reach the engine too: its answer, sandboxed.
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, edge.URL+"/downloads/agent/EasyPatchAgent-0.0.0-x64.deb", nil)
		resp, err := c.http.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound || resp.Header.Get("Content-Security-Policy") != "default-src 'none'; frame-ancestors 'none'; sandbox" {
			t.Errorf("download of a missing package: %d %v", resp.StatusCode, resp.Header)
		}
	})
}

// checkFake asks eptest and the real server the same questions and checks
// that every field eptest answers with is in EasyPatch's answer, with a
// value of the same JSON type. EasyPatch may send more: the connector reads
// only what eptest sends.
// finished is a finished job of the endpoint with no identical job queued,
// which EasyPatch would refuse to retry (duplicate_job).
func checkFake(t *testing.T, c *contract, org, site, endpoint, job, finished uuid.UUID, suffix string) {
	fake := eptest.New(t)
	fOrg := fake.Org("Contract")
	fSite := fake.Site(fOrg, "Head office")
	fe := fake.AddEndpoint(fOrg, "contract", "SN-contract", "fingerprint")
	fEndpoint := fe.ID
	fake.Set(func() {
		fake.Version = "1.10.0"
		fake.Capabilities = []string{CapabilityScheduledInstalls, CapabilityOnBehalfOf}
		fe.RebootPending = true
	})
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
	fUpdate, rUpdate := pick(fake.URL(), fakeHTTP, fake.Token, fEndpoint), pick(c.url, c.http, c.token, endpoint)
	fakeInstall := map[string]any{"mode": "Selected", "updateGuids": []uuid.UUID{fUpdate}, "force": false, "scheduledAt": at}
	install["updateGuids"] = []uuid.UUID{rUpdate}

	// The fake's job comes from an install like the real one's.
	_, data := call(c.ctx, t, fakeHTTP, fake.URL(), http.MethodPost, "/api/v1/endpoints/"+fEndpoint.String()+"/install-updates", fake.Token,
		fakeInstall, nil)
	var fJob struct {
		ID uuid.UUID `json:"id"`
	}
	if err := json.Unmarshal(data, &fJob); err != nil {
		t.Fatalf("fake install: %v: %s", err, data)
	}
	fake.SetJobStatus(fJob.ID, "Failed") // finished, like the real one, so both can be retried

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
			real: "/api/v1/endpoints/" + endpoint.String() + "/effective-policy", dictionaryKeys: []string{"sources", "sourceTags"}},
		q("not found", "GET", "/api/v1/endpoints/"+uuid.NewString(), "/api/v1/endpoints/"+uuid.NewString()),
		{name: "install", method: "POST", fake: "/api/v1/endpoints/" + fEndpoint.String() + "/install-updates",
			real: "/api/v1/endpoints/" + endpoint.String() + "/install-updates", fBody: fakeInstall, rBody: install},
		{name: "bulk scan", method: "POST", fake: "/api/v1/endpoints/bulk/scan", real: "/api/v1/endpoints/bulk/scan",
			fBody: map[string]any{"endpointIds": []uuid.UUID{fEndpoint, uuid.New()}, "force": false},
			rBody: map[string]any{"endpointIds": []uuid.UUID{endpoint, uuid.New()}, "force": false}},
		q("restart pending", "GET", "/api/v1/organizations/"+fOrg.String()+"/restart-pending",
			"/api/v1/organizations/"+org.String()+"/restart-pending"),
		q("retry", "POST", "/api/v1/jobs/"+fJob.ID.String()+"/retry", "/api/v1/jobs/"+finished.String()+"/retry"),
		{name: "bulk restart", method: "POST", fake: "/api/v1/endpoints/bulk/restart", real: "/api/v1/endpoints/bulk/restart",
			fBody: map[string]any{"endpointIds": []uuid.UUID{fEndpoint}, "restart": RestartOptions{Mode: "Countdown", Condition: "OnlyIfPending", ScheduledAt: &at}},
			rBody: map[string]any{"endpointIds": []uuid.UUID{endpoint}, "restart": RestartOptions{Mode: "Countdown", Condition: "OnlyIfPending", ScheduledAt: &at}}},
		q("organization", "GET", "/api/v1/organizations/"+fOrg.String(), "/api/v1/organizations/"+org.String()),
		{name: "organizations, archived ones too", method: "GET", fake: "/api/v1/organizations?includeArchived=true",
			real: "/api/v1/organizations?includeArchived=true", element: true, fElem: fOrg, rElem: org},
		{name: "sites, archived ones too", method: "GET", fake: "/api/v1/organizations/" + fOrg.String() + "/sites?includeArchived=true",
			real: "/api/v1/organizations/" + org.String() + "/sites?includeArchived=true", element: true, fElem: fSite, rElem: site},
		q("site", "GET", "/api/v1/sites/"+fSite.String(), "/api/v1/sites/"+site.String()),
		{name: "create organization", method: "POST", fake: "/api/v1/organizations", real: "/api/v1/organizations",
			fBody: map[string]any{"name": "Shape " + uuid.NewString(), "timeZone": "Europe/Paris"},
			rBody: map[string]any{"name": "Shape " + uuid.NewString(), "timeZone": "Europe/Paris"}},
		{name: "create site", method: "POST", fake: "/api/v1/organizations/" + fOrg.String() + "/sites", real: "/api/v1/organizations/" + org.String() + "/sites",
			fBody: map[string]any{"name": "Shape " + uuid.NewString(), "timeZone": nil},
			rBody: map[string]any{"name": "Shape " + uuid.NewString(), "timeZone": nil}},
		{name: "duplicate organization", method: "POST", fake: "/api/v1/organizations", real: "/api/v1/organizations",
			fBody: map[string]any{"name": "Contract"}, rBody: map[string]any{"name": "Contract " + suffix}},
		{name: "invalid time zone", method: "POST", fake: "/api/v1/organizations", real: "/api/v1/organizations",
			fBody: map[string]any{"name": "Zone", "timeZone": ""}, rBody: map[string]any{"name": "Zone " + suffix, "timeZone": ""}},
		q("install preview", "GET", "/api/v1/endpoints/"+fEndpoint.String()+"/install-preview?mode=all",
			"/api/v1/endpoints/"+endpoint.String()+"/install-preview?mode=all"),
		q("message presets", "GET", "/api/v1/user-messages", "/api/v1/user-messages"),
		{name: "message on Linux", method: "POST", fake: "/api/v1/endpoints/bulk/notify", real: "/api/v1/endpoints/bulk/notify",
			fBody: map[string]any{"endpointIds": []uuid.UUID{fEndpoint}, "message": map[string]any{"preset": "SaveYourWork", "restartAt": nil}},
			rBody: map[string]any{"endpointIds": []uuid.UUID{endpoint}, "message": map[string]any{"preset": "SaveYourWork", "restartAt": nil}}},
		{name: "removal on Linux", method: "POST", fake: "/api/v1/endpoints/" + fEndpoint.String() + "/updates/" + uuid.NewString() + "/uninstall",
			real:  "/api/v1/endpoints/" + endpoint.String() + "/updates/" + uuid.NewString() + "/uninstall",
			fBody: map[string]any{"block": false, "reason": nil}, rBody: map[string]any{"block": false, "reason": nil}},
		{name: "agent update", method: "POST", fake: "/api/v1/endpoints/bulk/agent-update", real: "/api/v1/endpoints/bulk/agent-update",
			fBody: map[string]any{"endpointIds": []uuid.UUID{fEndpoint}, "version": nil},
			rBody: map[string]any{"endpointIds": []uuid.UUID{endpoint}, "version": nil}},
		{name: "enrollment token", method: "POST", fake: "/api/v1/enrollment-tokens", real: "/api/v1/enrollment-tokens",
			fBody: map[string]any{"organizationId": fOrg, "siteId": fSite, "description": "shape", "expiresInHours": 1, "maxUses": 1, "count": 1},
			rBody: map[string]any{"organizationId": org, "siteId": site, "description": "shape", "expiresInHours": 1, "maxUses": 1, "count": 1}},
		// The update catalog (one-product plan, C2).
		q("catalog", "GET", "/api/v1/updates?organizationId="+fOrg.String(), "/api/v1/updates?organizationId="+org.String()),
		q("catalog of a site", "GET", "/api/v1/updates?organizationId="+fOrg.String()+"&siteId="+fSite.String()+"&sort=missing&dir=desc",
			"/api/v1/updates?organizationId="+org.String()+"&siteId="+site.String()+"&sort=missing&dir=desc"),
		q("fleet update", "GET", "/api/v1/updates/"+fUpdate.String()+"?organizationId="+fOrg.String(),
			"/api/v1/updates/"+rUpdate.String()+"?organizationId="+org.String()),
		q("unknown fleet update", "GET", "/api/v1/updates/"+uuid.NewString(), "/api/v1/updates/"+uuid.NewString()),
		q("fleet update's endpoints", "GET", "/api/v1/updates/"+fUpdate.String()+"/endpoints?organizationId="+fOrg.String(),
			"/api/v1/updates/"+rUpdate.String()+"/endpoints?organizationId="+org.String()),
		{name: "fleet install", method: "POST", fake: "/api/v1/updates/" + fUpdate.String() + "/install",
			real:  "/api/v1/updates/" + rUpdate.String() + "/install",
			fBody: map[string]any{"endpointIds": []uuid.UUID{fEndpoint}}, rBody: map[string]any{"endpointIds": []uuid.UUID{endpoint}}},
	}
	ask := func(qu question) (f, r any) {
		fStatus, fData := call(c.ctx, t, fakeHTTP, fake.URL(), qu.method, qu.fake, fake.Token, qu.fBody, nil)
		rStatus, rData := call(c.ctx, t, c.http, c.url, qu.method, qu.real, c.token, qu.rBody, nil)
		if fStatus != rStatus {
			t.Errorf("%s: eptest answers %d, EasyPatch %d: %s", qu.name, fStatus, rStatus, rData)
			return nil, nil
		}
		if err := json.Unmarshal(fData, &f); err != nil {
			t.Errorf("%s: eptest: %v", qu.name, err)
			return nil, nil
		}
		if err := json.Unmarshal(rData, &r); err != nil {
			t.Errorf("%s: EasyPatch: %v", qu.name, err)
			return nil, nil
		}
		if qu.element {
			f, r = elementWithID(f, qu.fElem), elementWithID(r, qu.rElem)
			if f == nil || r == nil {
				t.Errorf("%s: the one asked about is missing (eptest %v, EasyPatch %v)", qu.name, f != nil, r != nil)
				return nil, nil
			}
		}
		if f == nil || r == nil {
			t.Errorf("%s: an empty answer", qu.name)
			return nil, nil
		}
		for _, p := range sameShape(qu.name, f, r, qu.dictionaryKeys) {
			t.Error(p)
		}
		return f, r
	}
	for _, qu := range questions {
		ask(qu)
	}

	// A hold, placed, listed, refused again and released on both.
	placeHold := question{name: "hold", method: "POST", fake: "/api/v1/updates/" + fUpdate.String() + "/holds",
		real: "/api/v1/updates/" + rUpdate.String() + "/holds", fBody: map[string]any{"organizationId": fOrg, "reason": "shape"},
		rBody: map[string]any{"organizationId": org, "reason": "shape"}}
	fHold, rHold := ask(placeHold)
	if fHold == nil || rHold == nil {
		return
	}
	placeHold.name = "hold again"
	ask(placeHold)
	ask(q("holds", "GET", "/api/v1/update-holds?updateGuid="+fUpdate.String(), "/api/v1/update-holds?updateGuid="+rUpdate.String()))
	fID, rID := fHold.(map[string]any)["id"].(string), rHold.(map[string]any)["id"].(string)
	ask(q("release", "POST", "/api/v1/update-holds/"+fID+"/release", "/api/v1/update-holds/"+rID+"/release"))
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
