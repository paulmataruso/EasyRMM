//go:build contract

// The contract tests run EasyRMM's client of the patching engine against a
// real EasyPatch server built from the same commit's easypatch/ directory.
// scripts/contract/easypatch.sh starts one and runs them (make
// test-contract; CI's "EasyPatch contract" job). EasyRMM calls it as it
// does in its deployment: plain HTTP on loopback, each request with a
// statement signed with the gateway key (ADR-0038). Simulated agents reach
// it at its public address, over HTTPS. The fast tests use eptest's
// recorded answers; these check the client against the real engine, and
// eptest's answers against its answers, so neither drifts from EasyPatch
// unnoticed.
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
	t   *testing.T
	ctx context.Context
	// url is the engine's public address, where agents enroll and check
	// in: HTTPS with a certificate made for the run, which http trusts.
	url     string
	http    *http.Client
	version string
	// engineURL and engineKey reach the same server as the patching engine
	// in EasyRMM's deployment does: plain HTTP on loopback, statements
	// signed with the gateway key (ADR-0038). engine is EasyRMM's client
	// of it, and signer its signer.
	engineURL string
	engineKey []byte
	signer    *Signer
	engine    *Client
}

func newContract(t *testing.T) *contract {
	t.Helper()
	c := &contract{
		t:         t,
		url:       os.Getenv("EASYRMM_CONTRACT_EASYPATCH_URL"),
		version:   os.Getenv("EASYRMM_CONTRACT_EASYPATCH_VERSION"),
		engineURL: os.Getenv("EASYRMM_CONTRACT_ENGINE_URL"),
	}
	caFile := os.Getenv("EASYRMM_CONTRACT_EASYPATCH_CA")
	key, err := base64.StdEncoding.DecodeString(os.Getenv("EASYRMM_CONTRACT_ENGINE_KEY"))
	if c.url == "" || c.version == "" || caFile == "" || c.engineURL == "" || err != nil || len(key) < MinStatementKey {
		t.Fatal("the contract tests need a real EasyPatch server: run them with make test-contract")
	}
	c.engineKey = key
	if c.signer, err = NewSigner(key); err != nil {
		t.Fatal(err)
	}
	if c.engine, err = NewEngineClient(c.engineURL, c.signer, "contract"); err != nil {
		t.Fatal(err)
	}
	ca, err := os.ReadFile(caFile)
	if err != nil {
		t.Fatal(err)
	}
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

// as is a call through EasyRMM for name: role in the organizations named,
// and in none when none are.
func (c *contract) as(name, role string, orgs ...uuid.UUID) context.Context {
	return WithStatement(c.ctx, Statement{Subject: uuid.NewString(), Name: name, Role: role, Organizations: orgs})
}

// everywhere is a call through EasyRMM for name, with role in every
// organization.
func (c *contract) everywhere(name, role string) context.Context {
	return WithStatement(c.ctx, Statement{Subject: uuid.NewString(), Name: name, Role: role, AllOrganizations: true})
}

// signed is a header with s, signed for one request: method and path (with
// its query) as sent, to whichever server it goes.
func signed(t *testing.T, signer *Signer, s Statement, method, path string) http.Header {
	t.Helper()
	u, err := url.Parse(path)
	if err != nil {
		t.Fatal(err)
	}
	st, err := signer.Sign(s, method, u.RequestURI())
	if err != nil {
		t.Fatal(err)
	}
	return http.Header{StatementHeader: {st}}
}

// call sends a request to base with header and returns the status and the
// body.
func call(ctx context.Context, t *testing.T, hc *http.Client, base, method, path string, body any, header http.Header) (int, []byte) {
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

// must sends a request to the engine as EasyRMM's own work (the statement
// of a call without one in its context: Admin in every organization) that
// must answer want, and decodes the answer into out (nil for none).
func (c *contract) must(method, path string, body any, want int, out any) {
	c.t.Helper()
	status, data := call(c.ctx, c.t, c.http, c.engineURL, method, path, body, signed(c.t, c.signer, statementFor(c.ctx, ""), method, path))
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
	status, data := call(c.ctx, c.t, c.http, base, http.MethodPost, "/api/v1/agents/enroll", map[string]any{
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
	status, answer := call(a.c.ctx, t, a.c.http, a.base, http.MethodPost, route, json.RawMessage(data), header)
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

// AlertRuleTypes lists EasyPatch's types of rule, which RuleTypes mirrors.
func (c *Client) AlertRuleTypes(ctx context.Context) ([]AlertRuleType, error) {
	var out []AlertRuleType
	err := c.do(ctx, http.MethodGet, alertRulesPath+"/types", nil, nil, "", &out)
	return out, err
}

func TestContract(t *testing.T) {
	c := newContract(t)
	// A call made with ctx carries EasyRMM's own statement: Admin in every
	// organization, named after whom it is for, if anyone. reader is a
	// person who may only read, in every organization.
	engine, ctx := c.engine, c.ctx
	reader := c.everywhere("contract-reader@example.test", RoleReadOnly)
	run := func(name string, fn func(t *testing.T)) {
		if !t.Run(name, fn) {
			t.FailNow() // each step needs the ones before it
		}
	}

	run("server info", func(t *testing.T) {
		info, err := engine.ServerInfo(ctx)
		if err != nil {
			t.Fatal(err)
		}
		// The engine built from this commit, or a release's (ADR-0052:
		// edge builds run the last release's). That the fake reports the
		// version of the one built from this commit is TestEngineVersion's.
		if info.Version != c.version {
			t.Errorf("version %q, want %q", info.Version, c.version)
		}
		if d := time.Since(info.ServerTime); d > time.Minute || d < -time.Minute {
			t.Errorf("server time %v", info.ServerTime)
		}
		if !SameServer(info.PublicURL, c.url) {
			t.Errorf("public URL %q, want %q", info.PublicURL, c.url)
		}
	})

	run("EasyRMM's own statement and a read-only one", func(t *testing.T) {
		if ok, err := engine.CanOperate(ctx); !ok || err != nil {
			t.Errorf("EasyRMM: CanOperate %v, %v", ok, err)
		}
		if ok, err := engine.CanOperate(reader); ok || err != nil {
			t.Errorf("read-only: CanOperate %v, %v", ok, err)
		}
	})

	// An organization and a site to work in, made with the engine's API (the
	// reconciler's calls are checked later on).
	suffix := uuid.NewString()[:8]
	var org struct {
		ID uuid.UUID `json:"id"`
	}
	c.must(http.MethodPost, "/api/v1/organizations", map[string]any{"name": "Contract " + suffix, "timeZone": "UTC"},
		http.StatusCreated, &org)
	var site struct {
		ID uuid.UUID `json:"id"`
	}
	c.must(http.MethodPost, "/api/v1/organizations/"+org.ID.String()+"/sites", map[string]any{"name": "Head office", "timeZone": "UTC"},
		http.StatusCreated, &site)

	run("organizations and sites", func(t *testing.T) {
		orgs, err := engine.Organizations(ctx)
		if err != nil {
			t.Fatal(err)
		}
		i := slices.IndexFunc(orgs, func(o Organization) bool { return o.ID == org.ID })
		if i < 0 || orgs[i].Name != "Contract "+suffix || !orgs[i].IsActive {
			t.Fatalf("organizations %+v lack the new one", orgs)
		}
		sites, err := engine.Sites(ctx, org.ID)
		if err != nil || !slices.ContainsFunc(sites, func(s Site) bool { return s.ID == site.ID && s.Name == "Head office" }) {
			t.Fatalf("sites %+v, %v", sites, err)
		}
		if _, err := engine.Organizations(reader); err != nil {
			t.Errorf("read-only: %v", err)
		}
	})

	var a *agent
	run("enrollment tokens and an agent", func(t *testing.T) {
		token, err := engine.CreateEnrollmentToken(ctx, org.ID, &site.ID, "EasyRMM contract", "contract-enroll@example.test")
		if err != nil {
			t.Fatal(err)
		}
		if token.ID == uuid.Nil || token.Secret == "" {
			t.Fatalf("token %+v", token)
		}
		a = c.enroll(token.Secret, "contract-"+suffix)
		for range 2 { // revoking twice is harmless
			if err := engine.RevokeEnrollmentToken(ctx, token.ID, "contract-enroll@example.test"); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := engine.CreateEnrollmentToken(reader, org.ID, nil, "read-only", ""); !IsStatus(err, http.StatusForbidden) {
			t.Errorf("a reader created an enrollment token: %v", err)
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
		page, err := engine.Endpoints(ctx, org.ID, 1)
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
		detail, err := engine.Endpoint(ctx, a.endpoint)
		if err != nil {
			t.Fatal(err)
		}
		if detail.Summary.ID != a.endpoint || detail.SerialNumber != "SN-contract-"+suffix || len(detail.Credentials) != 1 ||
			detail.Credentials[0].CredentialID != a.credential || detail.Credentials[0].KeyFingerprint != a.fingerprint ||
			detail.Credentials[0].RevokedAt != nil {
			t.Errorf("endpoint detail %+v", detail)
		}
		updates, err := engine.Updates(ctx, a.endpoint, "")
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
		if missing, err := engine.Updates(ctx, a.endpoint, "Missing"); err != nil || len(missing) != 2 {
			t.Errorf("missing updates %+v, %v", missing, err)
		}
		if installed, err := engine.InstalledUpdates(ctx, a.endpoint); err != nil ||
			!slices.ContainsFunc(installed, func(u Update) bool { return u.UpdateGUID == libc }) {
			t.Errorf("installed updates %+v, %v", installed, err)
		}
		history, err := engine.History(ctx, a.endpoint, 1)
		if err != nil || len(history.Items) != 1 || history.Items[0].Title != "libc6 2.41-12+deb13u1" || history.Items[0].Operation != "Installation" {
			t.Errorf("history %+v, %v", history, err)
		}
		policy, err := engine.EffectivePolicy(ctx, a.endpoint)
		if err != nil || policy.ScanIntervalMinutes <= 0 || policy.TimeZone == "" {
			t.Errorf("effective policy %+v, %v", policy, err)
		}
		if _, err := engine.Endpoint(reader, a.endpoint); err != nil {
			t.Errorf("read-only: %v", err)
		}
	})

	var install Job
	var restarted uuid.UUID // a restart job the agent completed
	run("install, follow and cancel a job", func(t *testing.T) {
		var err error
		install, err = engine.Install(ctx, a.endpoint, []uuid.UUID{openssl}, nil, "contract-install@example.test")
		if err != nil {
			t.Fatal(err)
		}
		if install.ID == uuid.Nil || install.EndpointID != a.endpoint || install.OrganizationID != org.ID || install.Type != "InstallUpdates" ||
			install.Status != "Queued" {
			t.Fatalf("install job %+v", install)
		}
		job, err := engine.Job(ctx, install.ID)
		if err != nil {
			t.Fatal(err)
		}
		if job.InstallMode != "Selected" || len(job.Items) != 1 || job.Items[0].UpdateGUID != openssl || job.Items[0].Status != "Pending" {
			t.Errorf("job detail %+v", job)
		}
		if jobs, err := engine.EndpointJobs(ctx, a.endpoint, 1); err != nil || !slices.ContainsFunc(jobs.Items, func(j Job) bool { return j.ID == install.ID }) {
			t.Errorf("endpoint jobs %+v, %v", jobs, err)
		}
		if jobs, err := engine.Jobs(ctx, JobFilter{OrganizationID: org.ID, Active: true}, 1); err != nil || !slices.ContainsFunc(jobs.Items, func(j Job) bool { return j.ID == install.ID }) {
			t.Errorf("active jobs %+v, %v", jobs, err)
		}
		if _, err := engine.Install(reader, a.endpoint, []uuid.UUID{openssl}, nil, ""); !IsStatus(err, http.StatusForbidden) {
			t.Errorf("read-only statement installed updates: %v", err)
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
		job, err = engine.Job(ctx, install.ID)
		if err != nil {
			t.Fatal(err)
		}
		if job.Summary.Status != "Running" || job.Summary.StartedAt == nil || len(job.Items) != 1 || job.Items[0].Status != "Installing" ||
			job.Items[0].InstallPercent == nil || *job.Items[0].InstallPercent != 40 {
			t.Errorf("running job %+v", job)
		}
		updates, err := engine.Updates(ctx, a.endpoint, "")
		if err != nil {
			t.Fatal(err)
		}
		if i := slices.IndexFunc(updates, func(u Update) bool { return u.UpdateGUID == openssl }); i < 0 ||
			updates[i].ActiveJob == nil || updates[i].ActiveJob.JobID != install.ID {
			t.Errorf("updates while installing %+v", updates)
		}

		// Canceling asks the agent to stop; the job ends when it says so.
		job, err = engine.CancelJob(ctx, install.ID, "contract-cancel@example.test")
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
		job, err = engine.Job(ctx, install.ID)
		if err != nil || job.Summary.Status != eptest.StatusCanceled || job.Summary.CompletedAt == nil {
			t.Errorf("job after the agent stopped %+v, %v", job, err)
		}
	})

	run("scheduled installs", func(t *testing.T) {
		at := time.Now().Add(2 * time.Hour).UTC().Truncate(time.Second)
		job, err := engine.Install(ctx, a.endpoint, []uuid.UUID{tzdata}, &at, "")
		if err != nil {
			t.Fatal(err)
		}
		detail, err := engine.Job(ctx, job.ID)
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
		detail, err = engine.CancelJob(ctx, job.ID, "")
		if err != nil || detail.Summary.Status != eptest.StatusCanceled {
			t.Errorf("canceled scheduled job %+v, %v", detail.Summary, err)
		}
	})

	run("retry a finished job", func(t *testing.T) {
		retry, err := engine.RetryJob(ctx, install.ID, "contract-retry@example.test")
		if err != nil {
			t.Fatal(err)
		}
		if retry.ID == install.ID || retry.Type != "InstallUpdates" || retry.Status != "Queued" || retry.EndpointID != a.endpoint {
			t.Errorf("retry %+v", retry)
		}
		var detail struct {
			RetryOfJobID uuid.UUID `json:"retryOfJobId"`
		}
		c.must(http.MethodGet, "/api/v1/jobs/"+retry.ID.String(), nil, http.StatusOK, &detail)
		if detail.RetryOfJobID != install.ID {
			t.Errorf("a retry of %v, want %v", detail.RetryOfJobID, install.ID)
		}
		// Only a finished job runs again, and not for a reader.
		var e *Error
		if _, err := engine.RetryJob(ctx, retry.ID, ""); !errors.As(err, &e) || e.Status != http.StatusConflict || e.Code != "invalid_state" {
			t.Errorf("retry of a queued job: %#v", err)
		}
		if _, err := engine.RetryJob(reader, install.ID, ""); !IsStatus(err, http.StatusForbidden) {
			t.Errorf("read-only retry: %v", err)
		}
		if _, err := engine.CancelJob(ctx, retry.ID, ""); err != nil {
			t.Fatal(err)
		}
	})

	run("restart only where a restart is pending", func(t *testing.T) {
		a.capabilities = []string{"restart"}
		a.checkIn()
		if p, err := engine.RestartPending(ctx, org.ID); err != nil || p.Total != 0 || len(p.Endpoints) != 0 {
			t.Fatalf("nothing pending: %+v, %v", p, err)
		}
		a.rebootPending = true
		a.checkIn()
		p, err := engine.RestartPending(ctx, org.ID)
		if err != nil || p.Total != 1 || len(p.Endpoints) != 1 {
			t.Fatalf("pending: %+v, %v", p, err)
		}
		if e := p.Endpoints[0]; e.ID != a.endpoint || e.Platform != "Linux" || e.IsServer || !e.CanRestart || e.RebootPendingSince == nil {
			t.Errorf("pending endpoint %+v", e)
		}
		if _, err := engine.BulkRestart(reader, []uuid.UUID{a.endpoint}, RestartOptions{Mode: "Countdown", Condition: "OnlyIfPending"}, ""); !IsStatus(err, http.StatusForbidden) {
			t.Errorf("read-only restart: %v", err)
		}

		// At a time: held until then.
		at := time.Now().Add(5 * time.Hour).UTC().Truncate(time.Second)
		later, err := engine.BulkRestart(ctx, []uuid.UUID{a.endpoint}, RestartOptions{Mode: "Countdown", Condition: "OnlyIfPending", ScheduledAt: &at}, "contract-restart@example.test")
		if err != nil || later.Succeeded != 1 || len(later.Results) != 1 || later.Results[0].JobID == nil {
			t.Fatalf("restart later %+v, %v", later, err)
		}
		job, err := engine.Job(ctx, *later.Results[0].JobID)
		if err != nil || job.Summary.Type != "Restart" || job.NotBefore == nil || !job.NotBefore.Equal(at) {
			t.Errorf("restart later %+v (not before %v), %v", job.Summary, job.NotBefore, err)
		}
		if _, err := engine.CancelJob(ctx, job.Summary.ID, ""); err != nil {
			t.Fatal(err)
		}

		// Now: the agent receives EasyRMM's preset at its next check-in.
		now, err := engine.BulkRestart(ctx, []uuid.UUID{a.endpoint}, RestartOptions{Mode: "Countdown", Condition: "OnlyIfPending"}, "")
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
		if job, err := engine.Job(ctx, id); err != nil || job.Summary.Status != "Completed" {
			t.Errorf("restart after the agent's report %+v, %v", job.Summary, err)
		}
		if p, err := engine.RestartPending(ctx, org.ID); err != nil || p.Total != 0 {
			t.Errorf("after the restart: %+v, %v", p, err)
		}

		// The options EasyRMM offers: a prompt with a deadline, whether or
		// not a restart is pending, waiting an hour for an offline computer.
		// The endpoint says it can restart and whether it is a server.
		if d, err := engine.Endpoint(ctx, a.endpoint); err != nil || !slices.Contains(d.AgentCapabilities, AgentCanRestart) ||
			d.OsProductType == "Server" || d.OsProductType == "DomainController" {
			t.Errorf("endpoint for a restart that need not be pending %+v, %v", d, err)
		}
		deadline, expiry := 120, 60
		prompt, err := engine.BulkRestart(ctx, []uuid.UUID{a.endpoint}, RestartOptions{Mode: "PromptWithDeadline", Condition: "Always",
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
		if job, err := engine.Job(ctx, pid); err != nil || job.Summary.CreatedAt.Add(time.Hour).Sub(job.Summary.ExpiresAt).Abs() > time.Minute {
			t.Errorf("prompted restart's expiry %+v, %v", job, err)
		}
		if _, err := engine.CancelJob(ctx, pid, ""); err != nil {
			t.Fatal(err)
		}
		// What EasyRMM refuses first, EasyPatch refuses too: per endpoint,
		// in a bulk request.
		short, long := 14, 10081
		for _, o := range []RestartOptions{{Mode: "Countdown", Condition: "Always", ExpiresAfterMinutes: &short},
			{Mode: "PromptWithDeadline", Condition: "Always", DeadlineMinutes: &long}} {
			if r, err := engine.BulkRestart(ctx, []uuid.UUID{a.endpoint}, o, ""); err != nil || r.Failed != 1 ||
				r.Results[0].ErrorCode != "validation_failed" {
				t.Errorf("restart %+v: %+v, %v", o, r, err)
			}
		}

		// Jobs filtered as the Jobs tab does: one endpoint's finished
		// restarts started by hand, and nothing from the future.
		done, err := engine.Jobs(ctx, JobFilter{OrganizationID: org.ID, EndpointID: &a.endpoint, Type: "Restart", Status: "Completed",
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
		if none, err := engine.Jobs(ctx, JobFilter{OrganizationID: org.ID, From: &future}, 1); err != nil || none.TotalCount != 0 {
			t.Errorf("jobs from the future %+v, %v", none, err)
		}
	})

	run("bulk actions", func(t *testing.T) {
		unknown := uuid.New()
		scan, err := engine.BulkScan(ctx, []uuid.UUID{a.endpoint, unknown}, "")
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
		bulk, err := engine.BulkInstall(ctx, []uuid.UUID{a.endpoint}, &at, "")
		if err != nil || bulk.Succeeded != 1 || len(bulk.Results) != 1 || bulk.Results[0].JobID == nil {
			t.Fatalf("bulk install %+v, %v", bulk, err)
		}
		if job, err := engine.Job(ctx, *bulk.Results[0].JobID); err != nil || job.NotBefore == nil || !job.NotBefore.Equal(at) {
			t.Errorf("bulk-scheduled job %+v, %v", job, err)
		}
		if _, err := engine.BulkScan(reader, []uuid.UUID{a.endpoint}, ""); !IsStatus(err, http.StatusForbidden) {
			t.Errorf("read-only statement scanned: %v", err)
		}
	})

	run("the device's Patches tab", func(t *testing.T) {
		// What the device's Patches tab relies on: the endpoint's details,
		// its effective policy with where each value comes from, exclusions,
		// the install preview, messages and agent updates. The simulated
		// agent is a Linux one, which EasyPatch refuses messages and removals
		// for.
		detail, err := engine.Endpoint(ctx, a.endpoint)
		if err != nil || !slices.Contains(detail.AgentCapabilities, "restart") || detail.AgentUpdate == nil || detail.HasOwnPolicy {
			t.Fatalf("endpoint detail %+v, %v", detail, err)
		}
		policy, err := engine.EffectivePolicy(ctx, a.endpoint)
		if err != nil || len(policy.Sources) == 0 || !policy.AgentAutoUpdateEnabled || !policy.KnownExploitedSkipsDelay || policy.CheckInIntervalSeconds <= 0 {
			t.Fatalf("effective policy %+v, %v", policy, err)
		}
		for k, v := range policy.Sources {
			if !slices.Contains([]string{"Global", "Organization", "Site", "Endpoint", "Tag"}, v) || k == "" {
				t.Errorf("policy source %q: %q", k, v)
			}
		}

		if err := engine.Exclude(ctx, a.endpoint, tzdata, "contract", "contract-exclude@example.test"); err != nil {
			t.Fatal(err)
		}
		if err := engine.Exclude(ctx, a.endpoint, tzdata, "", ""); err != nil {
			t.Fatalf("excluding twice: %v", err)
		}
		find := func() Update {
			t.Helper()
			list, err := engine.Updates(ctx, a.endpoint, "")
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
		p, err := engine.InstallPreview(ctx, a.endpoint, nil)
		if err != nil || p.Mode != "AllEligible" || !slices.ContainsFunc(p.Skipped, func(x PreviewSkip) bool { return x.UpdateGUID == tzdata && x.Reason == "Excluded" }) ||
			slices.ContainsFunc(p.Items, func(x PreviewItem) bool { return x.UpdateGUID == tzdata }) || p.Filter == nil {
			t.Errorf("preview with tzdata excluded %+v, %v", p, err)
		}
		p, err = engine.InstallPreview(ctx, a.endpoint, []uuid.UUID{openssl, tzdata})
		if err != nil || p.Mode != "Selected" || len(p.Items)+len(p.Skipped) != 2 {
			t.Errorf("preview of two updates %+v, %v", p, err)
		}
		if _, err := engine.InstallPreview(reader, a.endpoint, nil); err != nil {
			t.Errorf("read-only preview: %v", err)
		}
		if err := engine.Exclude(reader, a.endpoint, openssl, "", ""); !IsStatus(err, http.StatusForbidden) {
			t.Errorf("read-only exclusion: %v", err)
		}
		if err := engine.Include(ctx, a.endpoint, tzdata, "contract-include@example.test"); err != nil {
			t.Fatal(err)
		}
		if u := find(); u.State == "Excluded" || u.IsExcluded {
			t.Errorf("included update %+v", u)
		}
		if err := engine.Include(ctx, a.endpoint, tzdata, ""); err != nil {
			t.Errorf("including an update that is not excluded: %v", err)
		}

		// Removing an update: refused on Linux, with a reason to show.
		_, err = engine.RemoveUpdate(ctx, a.endpoint, libc, true, "contract", "")
		var e *Error
		if !errors.As(err, &e) || e.Status != http.StatusConflict || e.Code != "not_supported_on_linux" || !strings.Contains(e.Detail, "only available on Windows") {
			t.Errorf("removal on Linux: %#v", err)
		}

		presets, err := engine.MessagePresets(ctx)
		if err != nil || len(presets) != 6 || presets[5].Preset != "RestartScheduled" || !presets[5].NeedsRestartTime ||
			!strings.Contains(presets[5].Body, "{time}") || presets[0].Preset != "UpdatesInstalling" || presets[0].Title == "" {
			t.Errorf("message presets %+v, %v", presets, err)
		}
		if _, err := engine.MessagePresets(reader); err != nil {
			t.Errorf("read-only presets: %v", err)
		}
		at := time.Now().Add(time.Hour).UTC()
		n, err := engine.BulkNotify(ctx, []uuid.UUID{a.endpoint}, Message{Preset: "RestartScheduled", RestartAt: &at}, "")
		if err != nil || n.Failed != 1 || n.Results[0].Success || n.Results[0].ErrorCode != "not_supported_on_linux" ||
			!strings.Contains(n.Results[0].Message, "Messages to users are only available on Windows") {
			t.Errorf("message on Linux %+v, %v", n, err)
		}
		if _, err := engine.BulkNotify(reader, []uuid.UUID{a.endpoint}, Message{Preset: "SaveYourWork"}, ""); !IsStatus(err, http.StatusForbidden) {
			t.Errorf("read-only message: %v", err)
		}

		// An agent update is planned against what the agent reports: the
		// simulated one has no release key, so EasyPatch refuses with a
		// reason (agent_upgrade_required) that the console shows.
		u, err := engine.BulkAgentUpdate(ctx, []uuid.UUID{a.endpoint}, "contract-agent-update@example.test")
		if err != nil || len(u.Results) != 1 {
			t.Fatalf("agent update %+v, %v", u, err)
		}
		if r := u.Results[0]; (r.Success && r.JobID == nil) || (!r.Success && (r.ErrorCode == "" || r.Message == "")) {
			t.Errorf("agent update result %+v", r)
		} else {
			t.Logf("agent update: success %v, %s %s", r.Success, r.ErrorCode, r.Message)
			if r.JobID != nil {
				if _, err := engine.CancelJob(ctx, *r.JobID, ""); err != nil {
					t.Error(err)
				}
			}
		}
		if _, err := engine.BulkAgentUpdate(reader, []uuid.UUID{a.endpoint}, ""); !IsStatus(err, http.StatusForbidden) {
			t.Errorf("read-only agent update: %v", err)
		}
	})

	run("the update catalog and holds", func(t *testing.T) {
		// What Patching → Updates relies on: the catalog counted over an
		// organization or a site, one update with the endpoints that report
		// it, installing and removing it across endpoints, and holds.
		scope := FleetScope{OrganizationID: &org.ID}
		p, err := engine.Catalog(ctx, CatalogQuery{FleetScope: scope})
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
		installed, err := engine.Catalog(ctx, CatalogQuery{FleetScope: scope, State: "Installed"})
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
			if p, err := engine.Catalog(ctx, q); err != nil || !slices.ContainsFunc(p.Items, func(u FleetUpdate) bool { return u.UpdateGUID == tzdata }) {
				t.Errorf("%s: %+v, %v", name, p, err)
			}
		}
		other := uuid.New()
		if p, err := engine.Catalog(ctx, CatalogQuery{FleetScope: FleetScope{SiteID: &other}}); err != nil || len(p.Items) != 0 {
			t.Errorf("another site: %+v, %v", p, err)
		}
		exploited := true
		if p, err := engine.Catalog(ctx, CatalogQuery{FleetScope: scope, KnownExploited: &exploited}); err != nil ||
			slices.ContainsFunc(p.Items, func(u FleetUpdate) bool { return u.UpdateGUID == tzdata }) {
			t.Errorf("known exploited: %+v, %v", p, err)
		}

		d, err := engine.FleetUpdate(ctx, tzdata, scope)
		if err != nil || d.Summary.MissingCount != 1 || d.Summary.Title != "tzdata 2026c-0+deb13u1" || d.KbNumbers == nil || len(d.Holds) != 0 {
			t.Fatalf("update %+v, %v", d, err)
		}
		if _, err := engine.FleetUpdate(ctx, uuid.New(), scope); !IsStatus(err, http.StatusNotFound) {
			t.Errorf("unknown update: %v", err)
		}
		ends, err := engine.FleetUpdateEndpoints(ctx, tzdata, scope, "", 1)
		if err != nil || ends.TotalCount != 1 || ends.Items[0].EndpointID != a.endpoint || ends.Items[0].Hostname != "contract-"+suffix ||
			ends.Items[0].State != "Missing" || ends.Items[0].SiteName != "Head office" || ends.Items[0].IsExcluded {
			t.Errorf("update's endpoints %+v, %v", ends, err)
		}
		if ends, err := engine.FleetUpdateEndpoints(ctx, tzdata, scope, "Installed", 1); err != nil || len(ends.Items) != 0 {
			t.Errorf("endpoints where it is installed %+v, %v", ends, err)
		}

		// Installing on the endpoint: a job, or a reason (the scheduled
		// install of tzdata may still be queued).
		r, err := engine.FleetInstall(ctx, tzdata, []uuid.UUID{a.endpoint}, "contract-fleet@example.test")
		if err != nil || len(r.Results) != 1 || r.Results[0].EndpointID != a.endpoint {
			t.Fatalf("install on endpoints %+v, %v", r, err)
		}
		if x := r.Results[0]; (x.Success && x.JobID == nil) || (!x.Success && (x.ErrorCode == "" || x.Message == "")) {
			t.Errorf("install result %+v", x)
		} else if x.Success {
			if _, err := engine.CancelJob(ctx, *x.JobID, ""); err != nil {
				t.Error(err)
			}
		} else {
			t.Logf("install on endpoints: %s %s", x.ErrorCode, x.Message)
		}
		// Endpoints where it is not missing are left out, unanswered.
		if r, err := engine.FleetInstall(ctx, libc, []uuid.UUID{a.endpoint}, ""); err != nil || len(r.Results) != 0 {
			t.Errorf("install where it is installed %+v, %v", r, err)
		}
		if _, err := engine.FleetInstall(reader, tzdata, []uuid.UUID{a.endpoint}, ""); !IsStatus(err, http.StatusForbidden) {
			t.Errorf("read-only install: %v", err)
		}
		// Removing: refused on Linux, per endpoint.
		r, err = engine.FleetRemove(ctx, libc, []uuid.UUID{a.endpoint}, true, "contract", "")
		if err != nil || len(r.Results) != 1 || r.Results[0].Success || r.Results[0].ErrorCode != "not_supported_on_linux" {
			t.Errorf("removal on Linux %+v, %v", r, err)
		}
		if r, err := engine.FleetRemove(ctx, tzdata, []uuid.UUID{a.endpoint}, false, "", ""); err != nil || len(r.Results) != 0 {
			t.Errorf("removal where it is not installed %+v, %v", r, err)
		}

		// Holds.
		h, err := engine.HoldUpdate(ctx, tzdata, &org.ID, "contract hold", "contract-hold@example.test")
		if err != nil || h.ID == uuid.Nil || h.OrganizationID == nil || *h.OrganizationID != org.ID || h.Source != "Manual" ||
			h.Reason != "contract hold" || !h.CanRelease || h.ReleasedAt != nil || h.Title != "tzdata 2026c-0+deb13u1" {
			t.Fatalf("hold %+v, %v", h, err)
		}
		_, err = engine.HoldUpdate(ctx, tzdata, &org.ID, "again", "")
		var e *Error
		if !errors.As(err, &e) || e.Status != http.StatusConflict || e.Code != "already_held" {
			t.Errorf("holding again: %#v", err)
		}
		if _, err := engine.HoldUpdate(ctx, uuid.New(), &org.ID, "unknown", ""); !IsStatus(err, http.StatusNotFound) {
			t.Errorf("holding an unknown update: %v", err)
		}
		if _, err := engine.HoldUpdate(reader, tzdata, &org.ID, "read-only", ""); !IsStatus(err, http.StatusForbidden) {
			t.Errorf("read-only hold: %v", err)
		}
		if d, err := engine.FleetUpdate(ctx, tzdata, scope); err != nil || !d.Summary.OnHold || len(d.Holds) != 1 || d.Holds[0].ID != h.ID {
			t.Errorf("held update %+v, %v", d, err)
		}
		if p, err := engine.Catalog(ctx, CatalogQuery{FleetScope: scope, Search: "tzdata"}); err != nil || len(p.Items) != 1 || !p.Items[0].OnHold {
			t.Errorf("held in the catalog %+v, %v", p, err)
		}
		if list, err := engine.Holds(ctx, tzdata); err != nil || !slices.ContainsFunc(list, func(x Hold) bool { return x.ID == h.ID }) {
			t.Errorf("holds %+v, %v", list, err)
		}
		released, err := engine.ReleaseHold(ctx, h.ID, "contract-release@example.test")
		if err != nil || released.ReleasedAt == nil || released.CanRelease {
			t.Fatalf("release %+v, %v", released, err)
		}
		if _, err := engine.ReleaseHold(ctx, h.ID, ""); err != nil {
			t.Errorf("releasing again: %v", err)
		}
		if list, err := engine.Holds(ctx, tzdata); err != nil || slices.ContainsFunc(list, func(x Hold) bool { return x.ID == h.ID }) {
			t.Errorf("holds once released %+v, %v", list, err)
		}

		// People's statements bound the catalog, an administrator holds in
		// the organization, a super administrator everywhere.
		as := func(role string, orgs ...uuid.UUID) context.Context {
			return c.as("contract-engine@example.test", role, orgs...)
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
		super := c.everywhere("contract-engine@example.test", RoleSuperAdmin)
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

	// Policies at every level, and tags: what EasyRMM sends round-trips,
	// EasyPatch refuses what EasyRMM refuses, and EasyRMM's resolution of the
	// layers is EasyPatch's.
	run("policies at every level, and tags", func(t *testing.T) {
		const who = "contract-policy@example.test"
		reader, admin := c.as(who, RoleReadOnly, org.ID), c.as(who, RoleAdmin, org.ID)
		super, everyOrg := c.everywhere(who, RoleSuperAdmin), c.everywhere(who, RoleAdmin)

		// The global policy is always whole; saving it fills in what is left
		// out. Only a super administrator saves it.
		global, err := engine.LevelPolicy(reader, globalPolicyPath)
		if err != nil || global.ID == nil || global.ScanIntervalMinutes == nil || global.AllowedCategories == nil || global.MaintenanceStart == nil {
			t.Fatalf("global: %+v, %v", global, err)
		}
		t.Cleanup(func() {
			if _, err := engine.SetLevelPolicy(super, globalPolicyPath, global.PolicyLayer, ""); err != nil {
				t.Errorf("restore the global policy: %v", err)
			}
		})
		if g, err := engine.SetLevelPolicy(super, globalPolicyPath, PolicyLayer{ScanIntervalMinutes: ptr(240)}, ""); err != nil ||
			*g.ScanIntervalMinutes != 240 || g.JitterPercent == nil || *g.JitterPercent != *global.JitterPercent {
			t.Fatalf("save global: %+v, %v", g, err)
		}
		if _, err := engine.SetLevelPolicy(admin, globalPolicyPath, PolicyLayer{}, ""); !IsStatus(err, http.StatusForbidden) {
			t.Errorf("an administrator saved the global policy: %v", err)
		}

		// A level with no policy answers with every value null.
		op, sp, endp := organizationPolicyPath(org.ID), sitePolicyPath(site.ID), endpointPolicyPath(a.endpoint)
		if none, err := engine.LevelPolicy(reader, op); err != nil || none.ID != nil || none.ScanIntervalMinutes != nil || none.ExcludedKbs == nil {
			t.Fatalf("no organization policy: %+v, %v", none, err)
		}
		// Everything the editor sends, as normalizePolicy leaves it.
		layer := PolicyLayer{InstallDelayDays: ptr(3), ExcludedKbs: []string{"KB5044284"}, AllowedCategories: []string{"Security", "Critical"},
			MaintenanceDays: []int{1, 3}, MaintenanceStart: ptr("22:30"), MaintenanceDurationMinutes: ptr(120), AutoInstallEnabled: ptr(true),
			RestartSchedule: &RestartSchedule{Enabled: true, Days: []int{0}, Time: "04:00", Condition: "OnlyIfPending", Mode: "PromptWithDeadline",
				CountdownMinutes: 5, DeadlineMinutes: 240, ExpiryMinutes: 120},
			WindowsUpdate: &LayerWindowsUpdate{QualityUpdates: &GroupSetting[QualityUpdates]{Managed: true, Value: &QualityUpdates{DeferDays: ptr(7)}},
				FeatureUpdates: &GroupSetting[FeatureUpdates]{Managed: false},
				AutomaticUpdates: &GroupSetting[AutomaticUpdates]{Managed: true, Value: &AutomaticUpdates{Mode: "AutoDownloadScheduleInstall",
					ScheduledInstallDay: 0, ScheduledInstallHour: 3}},
				RestartBehavior: &GroupSetting[RestartBehavior]{Managed: true, Value: &RestartBehavior{NoAutoRestartWithSignedInUsers: true,
					ActiveHoursStart: ptr(8), ActiveHoursEnd: ptr(18)}}},
			ApplicationUpdates: &ApplicationUpdates{Enabled: true, ApprovedApps: []string{"Mozilla.Firefox"}}}
		inherited, _ := resolvePolicy(nil)
		if err := normalizePolicy(&layer, LevelOrganization, inherited); err != nil {
			t.Fatal(err)
		}
		if _, err := engine.SetLevelPolicy(reader, op, layer, ""); !IsStatus(err, http.StatusForbidden) {
			t.Errorf("a reader saved a policy: %v", err)
		}
		if _, err := engine.SetLevelPolicy(admin, op, layer, "contract-policy@example.test"); err != nil {
			t.Fatal(err)
		}
		saved, err := engine.LevelPolicy(reader, op)
		if err != nil {
			t.Fatal(err)
		}
		saved.ExcludedKbs = orEmpty(saved.ExcludedKbs)
		if diff := changedPolicyFields(layer, saved.PolicyLayer); saved.ID == nil || len(diff) > 0 {
			t.Fatalf("round trip changed %v: %+v", diff, saved.PolicyLayer)
		}
		// What EasyRMM refuses, EasyPatch refuses too.
		for name, bad := range map[string]PolicyLayer{
			"scan interval":       {ScanIntervalMinutes: ptr(5)},
			"group with nothing":  {WindowsUpdate: &LayerWindowsUpdate{QualityUpdates: &GroupSetting[QualityUpdates]{Managed: true}}},
			"active hours span":   {WindowsUpdate: &LayerWindowsUpdate{RestartBehavior: &GroupSetting[RestartBehavior]{Managed: true, Value: &RestartBehavior{ActiveHoursStart: ptr(6), ActiveHoursEnd: ptr(1)}}}},
			"restart with no day": {RestartSchedule: &RestartSchedule{Enabled: true, Days: []int{}, Time: "03:00", Condition: "Always", Mode: "Immediate", ExpiryMinutes: 120}},
			"winget id":           {ApplicationUpdates: &ApplicationUpdates{Enabled: true, ApprovedApps: []string{"firefox"}}},
			"KB":                  {ExcludedKbs: []string{"KB12a"}},
		} {
			// Sent first: normalizing drops what it refuses.
			if _, err := engine.SetLevelPolicy(admin, sp, bad, ""); !IsStatus(err, http.StatusBadRequest) {
				t.Errorf("%s: EasyPatch accepts it: %v", name, err)
			}
			if err := normalizePolicy(&bad, LevelOrganization, inherited); err == nil {
				t.Errorf("%s: EasyRMM accepts it", name)
			}
		}
		if _, err := engine.SetLevelPolicy(admin, endp, PolicyLayer{MaxConcurrentInstallsPerSite: ptr(2)}, ""); !IsStatus(err, http.StatusBadRequest) {
			t.Errorf("an endpoint set its site's limit: %v", err)
		}

		// Tags: managed by super administrators, assigned by administrators
		// of every organization.
		name := "Contract " + suffix
		tag, err := engine.CreateTag(super, TagInput{Name: name, Color: "teal", Priority: 5}, "")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = engine.DeleteTag(super, tag.ID, "") })
		if _, err := engine.CreateTag(super, TagInput{Name: strings.ToUpper(name), Color: "red"}, ""); !IsStatus(err, http.StatusConflict) {
			t.Errorf("a duplicate name: %v", err)
		}
		if _, err := engine.CreateTag(admin, TagInput{Name: "Not mine " + suffix, Color: "red"}, ""); !IsStatus(err, http.StatusForbidden) {
			t.Errorf("an administrator added a tag: %v", err)
		}
		if _, err := engine.SetLevelPolicy(super, tagPolicyPath(tag.ID), PolicyLayer{InstallDelayDays: ptr(9)}, ""); err != nil {
			t.Fatal(err)
		}
		if _, err := engine.SetLevelPolicy(super, tagPolicyPath(tag.ID), PolicyLayer{MaxConcurrentInstallsPerSite: ptr(2)}, ""); !IsStatus(err, http.StatusBadRequest) {
			t.Errorf("a tag set a site's limit: %v", err)
		}
		if err := engine.SetTags(admin, "sites", site.ID, []uuid.UUID{tag.ID}, ""); !IsStatus(err, http.StatusForbidden) {
			t.Errorf("an administrator of one organization assigned a tag: %v", err)
		}
		if err := engine.SetTags(everyOrg, "sites", site.ID, []uuid.UUID{tag.ID}, ""); err != nil {
			t.Fatal(err)
		}
		if err := engine.SetTags(everyOrg, "organizations", org.ID, []uuid.UUID{uuid.New()}, ""); !IsStatus(err, http.StatusNotFound) {
			t.Errorf("an unknown tag: %v", err)
		}

		// A tag's own policy is read by a super administrator only; an
		// administrator of every organization assigns tags, and removes them
		// with an empty list.
		if _, err := engine.LevelPolicy(everyOrg, tagPolicyPath(tag.ID)); !IsStatus(err, http.StatusForbidden) {
			t.Errorf("an administrator read a tag's policy: %v", err)
		}
		if p, err := engine.LevelPolicy(super, tagPolicyPath(tag.ID)); err != nil || p.InstallDelayDays == nil || *p.InstallDelayDays != 9 {
			t.Errorf("a tag's policy for a super administrator: %+v, %v", p, err)
		}
		if err := engine.SetTags(everyOrg, "organizations", org.ID, []uuid.UUID{tag.ID}, ""); err != nil {
			t.Errorf("assigned to the organization: %v", err)
		}
		if err := engine.SetTags(everyOrg, "organizations", org.ID, []uuid.UUID{}, ""); err != nil {
			t.Errorf("removed from the organization: %v", err)
		}
		if st, err := engine.GetSite(reader, site.ID); err != nil || len(st.Tags) != 1 || st.Tags[0].ID != tag.ID || st.Tags[0].InheritedFrom != "" {
			t.Errorf("site's tags: %+v, %v", st.Tags, err)
		}
		if e, err := engine.Endpoint(reader, a.endpoint); err != nil || len(e.Summary.Tags) != 1 || e.Summary.Tags[0].InheritedFrom != "Site" {
			t.Errorf("endpoint's tags: %+v, %v", e.Summary.Tags, err)
		}
		list, err := engine.Tags(super)
		if i := slices.IndexFunc(list, func(x Tag) bool { return x.ID == tag.ID }); err != nil || i < 0 || list[i].SiteCount != 1 ||
			list[i].EndpointCount != 1 || !list[i].HasPolicy {
			t.Errorf("tags for a super administrator: %+v, %v", list, err)
		}
		list, err = engine.Tags(reader)
		if i := slices.IndexFunc(list, func(x Tag) bool { return x.ID == tag.ID }); err != nil || i < 0 || list[i].EndpointCount != 0 {
			t.Errorf("tags for a reader: %+v, %v", list, err)
		}
		if _, err := engine.SetLevelPolicy(admin, sp, PolicyLayer{TrayIconEnabled: ptr(false)}, ""); err != nil {
			t.Fatal(err)
		}
		if _, err := engine.SetLevelPolicy(admin, endp, PolicyLayer{AgentAutoUpdateEnabled: ptr(false), ExcludedKbs: []string{"KB5000001"}}, ""); err != nil {
			t.Fatal(err)
		}

		// EasyRMM resolves the layers as EasyPatch does.
		var layers []namedLayer
		for _, l := range []namedPath{{"Global", globalPolicyPath}, {"Organization", op}, {"Site", sp}} {
			p, err := engine.LevelPolicy(reader, l.path)
			if err != nil {
				t.Fatal(err)
			}
			layers = append(layers, namedLayer{l.name, p.PolicyLayer})
		}
		// A reader, who cannot read a tag's policy, reads what the device's
		// tags set.
		tags, err := engine.TagPolicies(reader, a.endpoint)
		if err != nil || len(tags) != 1 || tags[0].Tag.Name != name || *tags[0].Policy.InstallDelayDays != 9 {
			t.Fatalf("tag policies: %+v, %v", tags, err)
		}
		layers = append(layers, namedLayer{"Tag", tags[0].Policy.PolicyLayer})
		own, err := engine.LevelPolicy(reader, endp)
		if err != nil {
			t.Fatal(err)
		}
		mine, from := resolvePolicy(append(layers, namedLayer{"Endpoint", own.PolicyLayer}))
		eff, err := engine.EffectivePolicy(reader, a.endpoint)
		if err != nil {
			t.Fatal(err)
		}
		if *mine.InstallDelayDays != eff.InstallDelayDays || *mine.ScanIntervalMinutes != eff.ScanIntervalMinutes ||
			*mine.TrayIconEnabled != eff.TrayIconEnabled || *mine.AgentAutoUpdateEnabled != eff.AgentAutoUpdateEnabled ||
			*mine.AutoInstallEnabled != eff.AutoInstallEnabled || !slices.Equal(mine.MaintenanceDays, eff.MaintenanceDays) ||
			*mine.MaintenanceStart != eff.MaintenanceStart || !slices.Equal(mine.AllowedCategories, eff.AllowedCategories) ||
			!slices.Equal(mine.ExcludedKbs, eff.ExcludedKbs) || mine.RestartSchedule.Time != eff.RestartSchedule.Time ||
			*mine.WindowsUpdate.QualityUpdates.Value.DeferDays != *eff.WindowsUpdate.QualityUpdates.DeferDays || eff.WindowsUpdate.FeatureUpdates != nil {
			t.Errorf("resolved:\n EasyRMM   %+v\n EasyPatch %+v", mine, eff)
		}
		for mineKey, theirs := range map[string]string{"installDelayDays": "InstallDelayDays", "scanIntervalMinutes": "ScanIntervalMinutes",
			"trayIconEnabled": "TrayIconEnabled", "agentAutoUpdateEnabled": "AgentAutoUpdateEnabled", "maintenanceDays": "MaintenanceWindow",
			"windowsUpdate.qualityUpdates": "WindowsUpdate.QualityUpdates", "jitterPercent": "JitterPercent"} {
			if from[mineKey] != eff.Sources[theirs] {
				t.Errorf("%s comes from %q for EasyRMM, %q for EasyPatch", mineKey, from[mineKey], eff.Sources[theirs])
			}
		}
		if eff.SourceTags["InstallDelayDays"] != name {
			t.Errorf("source tags: %v", eff.SourceTags)
		}

		// Renaming, deleting, and resetting each level.
		if renamed, err := engine.UpdateTag(super, tag.ID, TagInput{Name: name + " renamed", Color: "pink", Priority: 6}, ""); err != nil ||
			renamed.Name != name+" renamed" || renamed.Priority != 6 {
			t.Errorf("rename: %+v, %v", renamed, err)
		}
		if err := engine.DeleteTag(super, tag.ID, ""); err != nil {
			t.Fatal(err)
		}
		if tags, err := engine.TagPolicies(reader, a.endpoint); err != nil || len(tags) != 0 {
			t.Errorf("tag policies once it is deleted: %+v, %v", tags, err)
		}
		for _, p := range []string{endp, sp, op} {
			if err := engine.DeleteLevelPolicy(admin, p, ""); err != nil {
				t.Fatal(err)
			}
			if lp, err := engine.LevelPolicy(reader, p); err != nil || lp.ID != nil {
				t.Errorf("%s after reset: %+v, %v", p, lp, err)
			}
		}
	})

	// Reports: the trend, installations, schedules and monthly PDFs as
	// EasyRMM reads them, and the mail settings the bundled engine is given.
	run("reports", func(t *testing.T) {
		now := time.Now().UTC()
		points, err := engine.ComplianceTrend(ctx, org.ID, now.AddDate(0, 0, -29).Format(time.DateOnly), now.Format(time.DateOnly))
		if err != nil {
			t.Fatal(err)
		}
		for _, p := range points {
			if len(p.Date) != len("2006-01-02") || p.Compliant > p.TotalEndpoints || p.CompliancePercent < 0 || p.CompliancePercent > 100 {
				t.Errorf("trend point %+v", p)
			}
		}

		// The install canceled earlier finished with openssl.
		window := InstallationFilter{OrganizationID: org.ID, From: now.Add(-24 * time.Hour), To: now.Add(time.Minute)}
		rows, err := engine.Installations(ctx, window, 1)
		if err != nil {
			t.Fatal(err)
		}
		i := slices.IndexFunc(rows.Items, func(r InstallationRow) bool { return r.JobID == install.ID })
		if i < 0 {
			t.Fatalf("installations %+v", rows)
		}
		if r := rows.Items[i]; r.EndpointID != a.endpoint || r.UpdateGUID != openssl || r.Status != statusCanceled || r.Category != "Security" ||
			r.CompletedAt == nil || r.Hostname == "" || r.OrganizationName == "" || r.RequestedBy == "" {
			t.Errorf("installation %+v", r)
		}
		for name, f := range map[string]InstallationFilter{
			"another result":   {OrganizationID: org.ID, From: window.From, To: window.To, Result: "Failed"},
			"another category": {OrganizationID: org.ID, From: window.From, To: window.To, Category: "Driver"},
			"before it":        {OrganizationID: org.ID, From: window.From, To: window.From.Add(time.Minute)},
		} {
			if p, err := engine.Installations(ctx, f, 1); err != nil || slices.ContainsFunc(p.Items, func(r InstallationRow) bool { return r.JobID == install.ID }) {
				t.Errorf("%s: %+v, %v", name, p, err)
			}
		}
		if p, err := engine.Installations(ctx, InstallationFilter{OrganizationID: org.ID, From: window.From, To: window.To, Result: statusCanceled,
			Category: "Security"}, 1); err != nil || !slices.ContainsFunc(p.Items, func(r InstallationRow) bool { return r.JobID == install.ID }) {
			t.Errorf("its result and category: %+v, %v", p, err)
		}

		// A schedule: saved with an Admin statement, refused to a reader.
		sc, err := engine.ReportSchedule(ctx, org.ID)
		if err != nil || sc.OrganizationID != org.ID || sc.DayOfMonth < 1 || sc.TimeZone == "" {
			t.Fatalf("schedule: %+v, %v", sc, err)
		}
		in := ReportScheduleInput{Enabled: true, Recipients: []string{"cfo@example.com"}, DayOfMonth: 5}
		if _, err := engine.SetReportSchedule(reader, org.ID, in, ""); !IsStatus(err, http.StatusForbidden) {
			t.Errorf("read-only schedule: %v", err)
		}
		for name, bad := range map[string]ReportScheduleInput{"day 29": {DayOfMonth: 29}, "no recipients": {Enabled: true, DayOfMonth: 5},
			"bad address": {DayOfMonth: 5, Recipients: []string{"cfo@"}}} {
			var e *Error
			if _, err := engine.SetReportSchedule(ctx, org.ID, bad, ""); !errors.As(err, &e) || e.Status != http.StatusBadRequest || len(e.Fields) == 0 {
				t.Errorf("%s: %#v", name, err)
			}
		}
		sc, err = engine.SetReportSchedule(ctx, org.ID, in, "contract-report@example.test")
		if err != nil || !sc.Enabled || sc.DayOfMonth != 5 || !slices.Equal(sc.Recipients, in.Recipients) || sc.IncludeEndpointList ||
			sc.NextReportDate == nil || sc.NextReportPeriod == nil || sc.EnabledAt == nil || sc.UpdatedAt == nil {
			t.Fatalf("saved schedule: %+v, %v", sc, err)
		}

		// A report of last month, its PDF, and emailing it.
		last := now.AddDate(0, -1, 0)
		if _, err := engine.GenerateMonthlyReport(ctx, org.ID, now.Year()+1, 1, true, ""); !isEngineCode(err, "invalid_period") {
			t.Errorf("next year: %v", err)
		}
		if _, err := engine.GenerateMonthlyReport(reader, org.ID, last.Year(), int(last.Month()), true, ""); !IsStatus(err, http.StatusForbidden) {
			t.Errorf("read-only generate: %v", err)
		}
		rep, err := engine.GenerateMonthlyReport(ctx, org.ID, last.Year(), int(last.Month()), true, "contract-report@example.test")
		if err != nil {
			t.Fatal(err)
		}
		if rep.OrganizationID != org.ID || rep.PeriodStart != last.Format("2006-01")+"-01" || rep.MonthToDate || rep.Scheduled ||
			!strings.HasSuffix(rep.FileName, ".pdf") || rep.SizeBytes == 0 || len(rep.Sha256) != 64 || rep.DeliveryStatus != "" {
			t.Errorf("report %+v", rep)
		}
		if p, err := engine.MonthlyReports(reader, org.ID, 1); err != nil || !slices.ContainsFunc(p.Items, func(m MonthlyReport) bool { return m.ID == rep.ID }) {
			t.Errorf("list: %+v, %v", p, err)
		}
		if m, err := engine.MonthlyReport(reader, rep.ID); err != nil || m.FileName != rep.FileName {
			t.Errorf("one: %+v, %v", m, err)
		}
		pdf, err := engine.MonthlyReportPDF(reader, rep.ID)
		if err != nil || !bytes.HasPrefix(pdf, []byte("%PDF-")) || int64(len(pdf)) != rep.SizeBytes {
			t.Errorf("PDF: %d bytes, %v", len(pdf), err)
		}
		if _, err := engine.MonthlyReport(ctx, uuid.New()); !IsStatus(err, http.StatusNotFound) {
			t.Errorf("no such report: %v", err)
		}
		// The mail settings need a super administrator, as EasyRMM gives the
		// engine its mail server (syncMail): an Admin statement is refused.
		if _, err := engine.MailSettings(ctx); !IsStatus(err, http.StatusForbidden) {
			t.Errorf("an Admin statement reads the mail settings: %v", err)
		}
		super := WithStatement(ctx, Statement{Subject: ServiceSubject, Name: "EasyRMM", Role: RoleSuperAdmin, AllOrganizations: true})
		mail, err := engine.MailSettings(super)
		if err != nil {
			t.Fatal(err)
		}
		if mail.SMTPHost == "" {
			if _, err := engine.SendMonthlyReport(ctx, rep.ID, []string{"cfo@example.com"}, ""); !isEngineCode(err, "smtp_not_configured") {
				t.Errorf("no mail server: %v", err)
			}
		}
		t.Cleanup(func() {
			restore := MailSettingsInput{SMTPHost: mail.SMTPHost, SMTPPort: mail.SMTPPort, SMTPSecurity: mail.SMTPSecurity, SMTPUsername: mail.SMTPUsername,
				FromAddress: mail.FromAddress, FromName: mail.FromName, AllowPrivateNetworkWebhooks: mail.AllowPrivateNetworkWebhooks,
				SMTPSkipCertificateCheck: mail.SMTPSkipCertificateCheck}
			if !mail.SMTPPasswordConfigured {
				restore.SMTPPassword = ptr("")
			}
			if err := engine.SetMailSettings(super, restore); err != nil {
				t.Errorf("restore the mail settings: %v", err)
			}
		})
		plain := MailConfig{Host: "mail.example.test", Port: 25, From: "Reports <reports@example.test>", TLS: "none"}
		if err := engine.SetMailSettings(super, plain.mailSettings(mail)); err != nil {
			t.Fatal(err)
		}
		if _, err := engine.SendMonthlyReport(ctx, rep.ID, []string{"cfo@example.com"}, ""); !isEngineCode(err, "smtp_not_encrypted") {
			t.Errorf("a plain mail server: %v", err)
		}
		tls := MailConfig{Host: "mail.example.test", Port: 465, Username: "reports", Password: "contract-only", From: "Reports <reports@example.test>",
			TLS: "implicit"}
		if err := engine.SetMailSettings(super, tls.mailSettings(mail)); err != nil {
			t.Fatal(err)
		}
		got, err := engine.MailSettings(super)
		if err != nil || got.SMTPHost != "mail.example.test" || got.SMTPPort != 465 || got.SMTPSecurity != "SslOnConnect" || got.SMTPUsername != "reports" ||
			!got.SMTPPasswordConfigured || got.FromAddress != "reports@example.test" || got.FromName != "Reports" ||
			got.AllowPrivateNetworkWebhooks != mail.AllowPrivateNetworkWebhooks {
			t.Errorf("mail settings: %+v, %v", got, err)
		}
		if _, err := engine.SendMonthlyReport(ctx, rep.ID, []string{"cfo@"}, ""); !IsStatus(err, http.StatusBadRequest) {
			t.Errorf("a bad address: %v", err)
		}
		// No recipients takes the schedule's.
		sent, err := engine.SendMonthlyReport(ctx, rep.ID, nil, "contract-report@example.test")
		if err != nil || sent.DeliveryStatus == "" || !slices.Equal(sent.Recipients, in.Recipients) || sent.QueuedAt == nil {
			t.Errorf("sent: %+v, %v", sent, err)
		}
		if _, err := engine.SetReportSchedule(ctx, org.ID, ReportScheduleInput{DayOfMonth: 1}, ""); err != nil {
			t.Fatal(err)
		}
		if _, err := engine.SendMonthlyReport(ctx, rep.ID, nil, ""); !isEngineCode(err, "no_recipients") {
			t.Errorf("no recipients anywhere: %v", err)
		}
		// A report of the month so far, made with a statement.
		admin := WithStatement(ctx, Statement{Subject: uuid.NewString(), Name: "contract-report@example.test", Role: RoleAdmin,
			Organizations: []uuid.UUID{org.ID}})
		soFar, err := engine.GenerateMonthlyReport(admin, org.ID, now.Year(), int(now.Month()), false, "")
		if err != nil || !soFar.MonthToDate || soFar.GeneratedBy == "" {
			t.Errorf("month so far: %+v, %v", soFar, err)
		}
		other := WithStatement(ctx, Statement{Subject: uuid.NewString(), Name: "contract-report@example.test", Role: RoleReadOnly,
			Organizations: []uuid.UUID{uuid.New()}})
		if _, err := engine.MonthlyReport(other, rep.ID); !IsStatus(err, http.StatusForbidden) && !IsStatus(err, http.StatusNotFound) {
			t.Errorf("another organization's statement: %v", err)
		}

		if err := engine.DeleteMonthlyReport(reader, rep.ID, ""); !IsStatus(err, http.StatusForbidden) {
			t.Errorf("read-only delete: %v", err)
		}
		for _, id := range []uuid.UUID{rep.ID, soFar.ID} {
			if err := engine.DeleteMonthlyReport(ctx, id, "contract-report@example.test"); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := engine.MonthlyReport(ctx, rep.ID); !IsStatus(err, http.StatusNotFound) {
			t.Errorf("deleted: %v", err)
		}
	})

	// Settings → Patching's server-wide views.
	run("server settings, OS lifecycle and the audit log", func(t *testing.T) {
		const who = "contract-settings@example.test"
		super := c.everywhere(who, RoleSuperAdmin)

		// EasyRMM shows every one of EasyPatch's settings, and no other: it
		// saves them all with one PUT.
		var raw map[string]json.RawMessage
		c.must(http.MethodGet, "/api/v1/settings", nil, http.StatusOK, &raw)
		b, _ := json.Marshal(ServerSettings{})
		var shown map[string]any
		_ = json.Unmarshal(b, &shown)
		for k := range shown {
			if _, ok := raw[k]; !ok {
				t.Errorf("EasyPatch has no setting %q", k)
			}
		}
		for k := range raw {
			if _, ok := shown[k]; !ok {
				t.Errorf("EasyRMM does not show EasyPatch's setting %q", k)
			}
		}
		before, err := engine.ServerSettings(ctx)
		if err != nil || before.GlobalMaxConcurrentInstalls == 0 || before.RetentionAuditDays == 0 {
			t.Fatalf("settings: %+v, %v", before, err)
		}
		// Only a super administrator changes them.
		if _, err := engine.SetServerSettings(ctx, before); !IsStatus(err, http.StatusForbidden) {
			t.Errorf("an Admin statement changes the settings: %v", err)
		}
		t.Cleanup(func() {
			if _, err := engine.SetServerSettings(super, before); err != nil {
				t.Errorf("restore the settings: %v", err)
			}
		})
		in := before
		brand := "Contract IT"
		in.ReportBrandName, in.RolloutGuardFailurePercent = &brand, before.RolloutGuardFailurePercent%100+1
		got, err := engine.SetServerSettings(super, in)
		if err != nil || got.ReportBrandName == nil || *got.ReportBrandName != brand || got.RolloutGuardFailurePercent != in.RolloutGuardFailurePercent {
			t.Errorf("changed: %+v, %v", got, err)
		}
		bad := before
		bad.GlobalMaxConcurrentInstalls = 0
		if _, err := engine.SetServerSettings(super, bad); !IsStatus(err, http.StatusBadRequest) {
			t.Errorf("no installs at once: %v", err)
		}
		if _, err := engine.VulnerabilityFeeds(ctx); err != nil {
			t.Errorf("feeds: %v", err)
		}

		// Lifecycle entries: read by a reader, changed with a SuperAdmin
		// statement only; EasyRMM's 64 characters of a product fit.
		list, err := engine.Lifecycle(reader)
		if err != nil || len(list) == 0 || list[0].Product == "" || list[0].EndOfServicing == "" {
			t.Fatalf("lifecycle: %+v, %v", list, err)
		}
		entry := LifecycleInput{Product: "Contract OS " + strings.Repeat("x", 52), EditionGroup: "Contract", BuildNumber: 900_000 + int(time.Now().UnixNano()%99_999),
			VersionLabel: "1.0", EndOfServicing: "2030-01-31"}
		if _, err := engine.CreateLifecycle(ctx, entry); !IsStatus(err, http.StatusForbidden) {
			t.Errorf("an Admin statement adds an entry: %v", err)
		}
		e, err := engine.CreateLifecycle(super, entry)
		if err != nil || e.ID == uuid.Nil || e.Product != entry.Product || e.EndOfServicing != "2030-01-31" || e.EsuEndDate != nil {
			t.Fatalf("created: %+v, %v", e, err)
		}
		if _, err := engine.CreateLifecycle(super, entry); !IsStatus(err, http.StatusConflict) {
			t.Errorf("the same build again: %v", err)
		}
		esu := "2033-01-31"
		entry.EsuEndDate = &esu
		if u, err := engine.UpdateLifecycle(super, e.ID, entry); err != nil || u.EsuEndDate == nil || *u.EsuEndDate != esu {
			t.Errorf("updated: %+v, %v", u, err)
		}
		early := "2029-01-01"
		entry.EsuEndDate = &early
		if _, err := engine.UpdateLifecycle(super, e.ID, entry); !IsStatus(err, http.StatusBadRequest) {
			t.Errorf("extended support ending first: %v", err)
		}
		if err := engine.DeleteLifecycle(super, e.ID); err != nil {
			t.Fatal(err)
		}
		if err := engine.DeleteLifecycle(super, e.ID); !IsStatus(err, http.StatusNotFound) {
			t.Errorf("deleted twice: %v", err)
		}

		// The audit log names the EasyRMM user; an Admin statement for one
		// organization sees its entries only, and a reader none.
		all := c.everywhere(who, RoleAdmin)
		p, err := engine.AuditLogs(all, AuditFilter{Action: "lifecycle."}, 1, 50)
		if err != nil || !slices.ContainsFunc(p.Items, func(a AuditLog) bool {
			return a.Action == "lifecycle.create" && a.Username == "easyrmm:"+who && a.TargetID == e.ID.String() && a.OrganizationID == nil
		}) || slices.ContainsFunc(p.Items, func(a AuditLog) bool { return !strings.HasPrefix(a.Action, "lifecycle.") }) {
			t.Errorf("lifecycle entries: %+v, %v", p.Items[:min(len(p.Items), 5)], err)
		}
		if p, err := engine.AuditLogs(all, AuditFilter{Action: "settings."}, 1, 5); err != nil || len(p.Items) == 0 || p.Items[0].Username != "easyrmm:"+who {
			t.Errorf("settings entries: %+v, %v", p, err)
		}
		one := c.as(who, RoleAdmin, org.ID)
		p, err = engine.AuditLogs(one, AuditFilter{}, 1, 200)
		if err != nil || len(p.Items) == 0 || slices.ContainsFunc(p.Items, func(a AuditLog) bool { return a.OrganizationID == nil || *a.OrganizationID != org.ID }) {
			t.Errorf("one organization's entries: %d, %v", len(p.Items), err)
		}
		future := time.Now().Add(time.Hour)
		if p, err := engine.AuditLogs(all, AuditFilter{From: &future}, 1, 5); err != nil || len(p.Items) != 0 {
			t.Errorf("from an hour ahead: %+v, %v", p, err)
		}
		if _, err := engine.AuditLogs(reader, AuditFilter{}, 1, 5); !IsStatus(err, http.StatusForbidden) {
			t.Errorf("a reader reads the audit log: %v", err)
		}
	})

	// Alerts, alert rules and notification channels.
	run("alerts, alert rules and notification channels", func(t *testing.T) {
		const who = "contract-alerts@example.test"
		super, admin, reader := c.everywhere(who, RoleSuperAdmin), c.as(who, RoleAdmin, org.ID), c.as(who, RoleReadOnly, org.ID)

		// EasyRMM's table of rule types is EasyPatch's. Rules, channels and
		// deliveries are a super administrator's: an Admin statement is
		// refused.
		types, err := engine.AlertRuleTypes(super)
		want, _ := json.Marshal(RuleTypes())
		got, _ := json.Marshal(types)
		if err != nil || string(got) != string(want) {
			t.Errorf("rule types: EasyPatch %s, EasyRMM %s, %v", got, want, err)
		}
		if _, err := engine.AlertRuleTypes(ctx); !IsStatus(err, http.StatusForbidden) {
			t.Errorf("an Admin statement reads the rule types: %v", err)
		}
		rules, err := engine.AlertRules(super)
		if err != nil || len(rules) < 8 {
			t.Fatalf("rules: %+v, %v", rules, err)
		}
		for _, r := range rules {
			if !slices.Contains(AlertRuleKinds, r.Type) || !slices.Contains(AlertSeverities, r.Severity) {
				t.Errorf("rule %q: %s, %s", r.Name, r.Type, r.Severity)
			}
		}

		// Every filter EasyRMM sends is taken; acknowledging needs Admin.
		filters := []AlertFilter{{Status: "unresolved", Search: "contract", OrganizationID: org.ID}, {Status: "open"}, {Status: "acknowledged"},
			{Status: "resolved"}, {Status: "all", EndpointID: uuid.New()}}
		for _, s := range AlertSeverities {
			filters = append(filters, AlertFilter{Severity: s})
		}
		for _, k := range AlertRuleKinds {
			filters = append(filters, AlertFilter{RuleType: k})
		}
		for _, f := range filters {
			if _, err := engine.Alerts(reader, f, 1, PageSize); err != nil {
				t.Errorf("alerts %+v: %v", f, err)
			}
		}
		if _, err := engine.Alerts(ctx, AlertFilter{}, 1, 5); err != nil {
			t.Errorf("alerts with EasyRMM's own statement: %v", err)
		}
		if _, err := engine.AlertSummary(reader); err != nil {
			t.Errorf("summary: %v", err)
		}
		if n, err := engine.AcknowledgeAlerts(admin, []uuid.UUID{uuid.New()}); err != nil || n != 0 {
			t.Errorf("acknowledge an unknown alert: %d, %v", n, err)
		}
		if _, err := engine.AcknowledgeAlerts(reader, []uuid.UUID{uuid.New()}); !IsStatus(err, http.StatusForbidden) {
			t.Errorf("a ReadOnly statement acknowledges: %v", err)
		}
		if _, err := engine.AcknowledgeAlerts(admin, nil); !IsStatus(err, http.StatusBadRequest) {
			t.Errorf("acknowledge none: %v", err)
		}

		// Channels: field errors carry the names EasyRMM gives its own.
		mail, err := engine.CreateChannel(super, ChannelInput{Name: "Contract mail", Type: "Email", Enabled: true,
			EmailRecipients: []string{"ops@example.test", "OPS@example.test"}})
		if err != nil || len(mail.Channel.EmailRecipients) != 1 || mail.SigningSecret != "" || mail.Channel.LastDelivery != nil {
			t.Fatalf("email channel: %+v, %v", mail, err)
		}
		t.Cleanup(func() { _ = engine.DeleteChannel(super, mail.Channel.ID) })
		generic, slack := "Generic", "Slack"
		address := "https://hooks.example.test/contract?token=secret"
		hook, err := engine.CreateChannel(super, ChannelInput{Name: "Contract hook", Type: "Webhook", Enabled: true, WebhookFormat: &generic,
			WebhookURL: &address})
		if err != nil || hook.SigningSecret == "" || !hook.Channel.HasSigningSecret || hook.Channel.WebhookHost != "hooks.example.test" ||
			len(hook.Channel.EmailRecipients) != 0 {
			t.Fatalf("webhook: %+v, %v", hook, err)
		}
		t.Cleanup(func() { _ = engine.DeleteChannel(super, hook.Channel.ID) })
		if _, err := engine.CreateChannel(ctx, ChannelInput{Name: "Token", Type: "Email", EmailRecipients: []string{"ops@example.test"}}); !IsStatus(err,
			http.StatusForbidden) {
			t.Errorf("an Admin statement adds a channel: %v", err)
		}
		plain := "http://hooks.example.test/x"
		for field, in := range map[string]ChannelInput{
			"name":            {Name: " ", Type: "Email", EmailRecipients: []string{"ops@example.test"}},
			"emailRecipients": {Name: "Mail", Type: "Email", EmailRecipients: []string{"not an address"}},
			"webhookFormat":   {Name: "Hook", Type: "Webhook", WebhookURL: &address},
			"webhookUrl":      {Name: "Hook", Type: "Webhook", WebhookFormat: &slack, WebhookURL: &plain},
		} {
			_, err := engine.CreateChannel(super, in)
			var e *Error
			if !errors.As(err, &e) || e.Status != http.StatusBadRequest || e.Fields[field] == "" {
				t.Errorf("%s: %#v", field, err)
			}
		}
		u, err := engine.UpdateChannel(super, hook.Channel.ID, ChannelInput{Name: "Contract hook", Type: "Webhook", Enabled: true, WebhookFormat: &slack})
		if err != nil || u.Channel.WebhookHost != "hooks.example.test" || u.Channel.HasSigningSecret || u.SigningSecret != "" {
			t.Errorf("to Slack, keeping the address: %+v, %v", u, err)
		}
		var e *Error
		if _, err := engine.UpdateChannel(super, hook.Channel.ID, ChannelInput{Name: "Hook", Type: "Email",
			EmailRecipients: []string{"ops@example.test"}}); !errors.As(err, &e) || e.Fields["type"] == "" {
			t.Errorf("type changed: %#v", err)
		}
		if _, err := engine.RotateChannelSecret(super, hook.Channel.ID); !IsStatus(err, http.StatusBadRequest) {
			t.Errorf("a Slack webhook's secret: %v", err)
		}
		u, err = engine.UpdateChannel(super, hook.Channel.ID, ChannelInput{Name: "Contract hook", Type: "Webhook", Enabled: true, WebhookFormat: &generic})
		if err != nil || u.SigningSecret == "" {
			t.Errorf("generic again: %+v, %v", u, err)
		}
		if r, err := engine.RotateChannelSecret(super, hook.Channel.ID); err != nil || r.SigningSecret == "" || r.SigningSecret == u.SigningSecret {
			t.Errorf("rotated: %+v, %v", r, err)
		}
		d, err := engine.TestChannel(super, mail.Channel.ID)
		if err != nil || d.Kind != "Test" || d.Status != "Pending" || d.ChannelName != "Contract mail" {
			t.Errorf("test: %+v, %v", d, err)
		}
		if _, err := engine.TestChannel(super, mail.Channel.ID); !IsStatus(err, http.StatusTooManyRequests) {
			t.Errorf("a second test at once: %v", err)
		}
		p, err := engine.Deliveries(super, mail.Channel.ID, "", 1, 50)
		if err != nil || !slices.ContainsFunc(p.Items, func(x Delivery) bool { return x.ID == d.ID }) {
			t.Errorf("deliveries: %+v, %v", p, err)
		}
		for _, status := range DeliveryStatuses {
			if _, err := engine.Deliveries(super, uuid.Nil, status, 1, 5); err != nil {
				t.Errorf("deliveries %s: %v", status, err)
			}
		}
		if _, err := engine.Deliveries(ctx, uuid.Nil, "", 1, 5); !IsStatus(err, http.StatusForbidden) {
			t.Errorf("an Admin statement reads the deliveries: %v", err)
		}

		// The webhook switch changes alone; blank text is kept as none.
		m, err := engine.MailSettings(super)
		if err != nil {
			t.Fatal(err)
		}
		keep := func(m MailSettings, private bool) MailSettingsInput {
			return MailSettingsInput{SMTPHost: m.SMTPHost, SMTPPort: m.SMTPPort, SMTPSecurity: m.SMTPSecurity, SMTPUsername: m.SMTPUsername,
				FromAddress: m.FromAddress, FromName: m.FromName, SMTPSkipCertificateCheck: m.SMTPSkipCertificateCheck, AllowPrivateNetworkWebhooks: private}
		}
		t.Cleanup(func() {
			if err := engine.SetMailSettings(super, keep(m, m.AllowPrivateNetworkWebhooks)); err != nil {
				t.Errorf("restore the mail settings: %v", err)
			}
		})
		if err := engine.SetMailSettings(super, keep(m, !m.AllowPrivateNetworkWebhooks)); err != nil {
			t.Fatal(err)
		}
		if m2, err := engine.MailSettings(super); err != nil || m2.AllowPrivateNetworkWebhooks == m.AllowPrivateNetworkWebhooks ||
			m2.SMTPHost != m.SMTPHost || m2.FromAddress != m.FromAddress || m2.SMTPPasswordConfigured != m.SMTPPasswordConfigured {
			t.Errorf("the webhook switch: %+v, then %+v, %v", m, m2, err)
		}
		var raw map[string]any
		if err := engine.SetMailSettings(super, MailSettingsInput{SMTPPort: 587, SMTPSecurity: "StartTls", SMTPUsername: " "}); err != nil {
			t.Fatal(err)
		}
		if err := engine.do(super, http.MethodGet, mailSettingsPath, nil, nil, "", &raw); err != nil || raw["smtpHost"] != nil || raw["smtpUsername"] != nil {
			t.Errorf("blank text: %+v, %v", raw, err)
		}

		// Rules name EasyPatch's organization, a tag and channels.
		tag, err := engine.CreateTag(super, TagInput{Name: "Contract alerts " + uuid.NewString()[:8], Color: "blue"}, "")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = engine.DeleteTag(super, tag.ID, "") })
		two := 2
		in := AlertRuleInput{Name: "Contract offline", Type: "EndpointOffline", Enabled: true, Severity: "Critical", Threshold: &two,
			OrganizationID: &org.ID, TagID: &tag.ID, ChannelIDs: []uuid.UUID{mail.Channel.ID, hook.Channel.ID}, NotifyOnResolve: true, RenotifyHours: 24}
		r, err := engine.CreateAlertRule(super, in)
		if err != nil || r.ThresholdUnit != "hours" || r.OrganizationID == nil || *r.OrganizationID != org.ID || r.TagID == nil || len(r.ChannelIDs) != 2 ||
			r.UnresolvedAlerts != 0 || !r.NotifyOnResolve || r.RenotifyHours != 24 {
			t.Fatalf("rule: %+v, %v", r, err)
		}
		t.Cleanup(func() { _ = engine.DeleteAlertRule(super, r.ID) })
		if _, err := engine.CreateAlertRule(ctx, in); !IsStatus(err, http.StatusForbidden) {
			t.Errorf("an Admin statement adds a rule: %v", err)
		}
		zero := 0
		for name, change := range map[string]func(*AlertRuleInput){
			"threshold":       func(x *AlertRuleInput) { x.Threshold = &zero },
			"tag on held":     func(x *AlertRuleInput) { x.Type, x.Threshold = "UpdateHeld", nil },
			"unknown channel": func(x *AlertRuleInput) { x.ChannelIDs = []uuid.UUID{uuid.New()} },
			"reminders":       func(x *AlertRuleInput) { x.RenotifyHours = 721 },
		} {
			bad := in
			change(&bad)
			if _, err := engine.CreateAlertRule(super, bad); !IsStatus(err, http.StatusBadRequest) {
				t.Errorf("%s: %v", name, err)
			}
		}
		in.Severity, in.TagID = "Warning", nil
		if u, err := engine.UpdateAlertRule(super, r.ID, in); err != nil || u.Severity != "Warning" || u.TagID != nil {
			t.Errorf("updated: %+v, %v", u, err)
		}
		// A channel deleted leaves the rules that send to it.
		if err := engine.DeleteChannel(super, hook.Channel.ID); err != nil {
			t.Fatal(err)
		}
		rules, _ = engine.AlertRules(super)
		if i := slices.IndexFunc(rules, func(x AlertRule) bool { return x.ID == r.ID }); i < 0 || len(rules[i].ChannelIDs) != 1 {
			t.Errorf("after the channel went: %+v", rules)
		}
		if err := engine.DeleteAlertRule(super, r.ID); err != nil {
			t.Fatal(err)
		}
		if err := engine.DeleteAlertRule(super, r.ID); !IsStatus(err, http.StatusNotFound) {
			t.Errorf("deleted twice: %v", err)
		}
		if p, err := engine.AuditLogs(super, AuditFilter{Action: "alert_rule."}, 1, 10); err != nil || len(p.Items) == 0 || p.Items[0].Username != "easyrmm:"+who {
			t.Errorf("audit: %+v, %v", p, err)
		}

		// The fake answers in the same shapes.
		fake := eptest.NewEngine(t, c.engineKey)
		fakeClient, err := NewEngineClient(fake.URL(), c.signer, "contract")
		if err != nil {
			t.Fatal(err)
		}
		fOrg := fake.Org("Contract")
		fMail, err := fakeClient.CreateChannel(super, ChannelInput{Name: "Contract mail", Type: "Email", Enabled: true, EmailRecipients: []string{"ops@example.test"}})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := fakeClient.TestChannel(super, fMail.Channel.ID); err != nil {
			t.Fatal(err)
		}
		mail2, err := engine.CreateChannel(super, ChannelInput{Name: "Contract mail 2", Type: "Email", Enabled: true, EmailRecipients: []string{"ops@example.test"}})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = engine.DeleteChannel(super, mail2.Channel.ID) })
		if _, err := engine.TestChannel(super, mail2.Channel.ID); err != nil {
			t.Fatal(err)
		}
		fake.AddAlert(eptest.AlertInfo{RuleType: "UpdateHeld", Severity: "Warning", Title: "Contract: 1 update on hold", Org: fOrg})
		five := url.Values{"pageSize": {"5"}}
		for path, q := range map[string]url.Values{"/api/v1/alert-rules": nil, "/api/v1/alert-rules/types": nil, channelsPath: nil,
			"/api/v1/notifications/deliveries": five, "/api/v1/alerts": five, "/api/v1/alerts/summary": nil, mailSettingsPath: nil} {
			var f, r any
			if err := fakeClient.do(super, http.MethodGet, path, q, nil, "", &f); err != nil {
				t.Errorf("eptest %s: %v", path, err)
				continue
			}
			if err := engine.do(super, http.MethodGet, path, q, nil, "", &r); err != nil {
				t.Errorf("EasyPatch %s: %v", path, err)
				continue
			}
			for _, p := range sameShape(path, f, r, nil) {
				t.Error(p)
			}
		}
	})

	run("errors", func(t *testing.T) {
		_, err := engine.Endpoint(ctx, uuid.New())
		var e *Error
		if !IsStatus(err, http.StatusNotFound) || !errors.As(err, &e) || e.Code == "" || e.Detail == "" {
			t.Errorf("unknown endpoint: %#v", err)
		}
		if _, err := engine.Job(ctx, uuid.New()); !IsStatus(err, http.StatusNotFound) {
			t.Errorf("unknown job: %v", err)
		}
		// Without a statement, nothing but server-info answers.
		if status, data := call(ctx, t, c.http, c.engineURL, http.MethodGet, "/api/v1/organizations", nil, nil); status != http.StatusUnauthorized {
			t.Errorf("no statement: %d %s", status, data)
		}
	})

	// Whatever packages the image carries (ADR-0041) are of the engine's
	// own version, each with a valid release signature. CI's contract image
	// carries none; build one with scripts/build-test-agent-packages.sh to
	// check them.
	run("agent packages", func(t *testing.T) {
		list, err := engine.AgentPackages(ctx)
		if err != nil {
			t.Fatal(err)
		}
		info, err := engine.ServerInfo(ctx)
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
		// A call without a statement in its context is named after whom it
		// is for (statementFor), and EasyPatch records easyrmm:<name>.
		type entry struct {
			Action   string `json:"action"`
			Username string `json:"username"`
		}
		var page struct {
			Items []entry `json:"items"`
		}
		c.must(http.MethodGet, "/api/v1/audit-logs?pageSize=200&organizationId="+org.ID.String(), nil, http.StatusOK, &page)
		for _, who := range []string{"contract-enroll@example.test", "contract-install@example.test", "contract-cancel@example.test",
			"contract-retry@example.test", "contract-restart@example.test"} {
			if !slices.ContainsFunc(page.Items, func(e entry) bool { return e.Username == "easyrmm:"+who }) {
				t.Errorf("no audit entry names %s", who)
			}
		}
		if t.Failed() {
			for _, e := range page.Items[:min(len(page.Items), 15)] {
				t.Logf("audit: %s %s", e.Action, e.Username)
			}
		}
	})

	run("the patching engine: statements", func(t *testing.T) {
		// EasyRMM's own work: Admin in every organization.
		if orgs, err := engine.Organizations(ctx); err != nil || !slices.ContainsFunc(orgs, func(o Organization) bool { return o.ID == org.ID }) {
			t.Fatalf("organizations as EasyRMM: %+v, %v", orgs, err)
		}
		// A person's call sees only the organizations it names.
		as := func(role string, orgs ...uuid.UUID) context.Context {
			return c.as("contract-engine@example.test", role, orgs...)
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
		_, err := engine.BulkScan(as(RoleReadOnly, org.ID), []uuid.UUID{a.endpoint}, "")
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
		c.must(http.MethodGet, "/api/v1/audit-logs?pageSize=100", nil, http.StatusOK, &page)
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
		// What EasyRMM's reconciler relies on (ADR-0040), as the engine in
		// the deployment does it.
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
		// In bundled mode the edge forwards the engine's agent paths
		// (ADR-0039). Agents sign the method, the request target and the
		// body: the engine accepting them proves all three arrive as sent.
		// The engine records the client address EasyRMM resolved, and never
		// sees a statement from outside.
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
			var seen struct {
				Summary struct {
					LastSeenIP string `json:"lastSeenIp"`
				} `json:"summary"`
			}
			if err := engine.do(admin, http.MethodGet, "/api/v1/endpoints/"+b.endpoint.String(), nil, nil, "", &seen); err != nil {
				t.Fatal(err)
			}
			if seen.Summary.LastSeenIP == "203.0.113.9" {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("the engine saw the agent at %q, not at the address EasyRMM resolved", seen.Summary.LastSeenIP)
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

// checkFake asks eptest and the real engine the same questions, each with
// EasyRMM's own statement, and checks that every field eptest answers with
// is in EasyPatch's answer, with a value of the same JSON type. EasyPatch
// may send more: EasyRMM reads only what eptest sends. finished is a
// finished job of the endpoint with no identical job queued, which EasyPatch
// would refuse to retry (duplicate_job).
func checkFake(t *testing.T, c *contract, org, site, endpoint, job, finished uuid.UUID, suffix string) {
	fake := eptest.NewEngine(t, c.engineKey)
	fOrg := fake.Org("Contract")
	fSite := fake.Site(fOrg, "Head office")
	fe := fake.AddEndpoint(fOrg, "contract", "SN-contract", "fingerprint")
	fEndpoint := fe.ID
	fake.Set(func() { fe.RebootPending = true })
	fake.AddAudit(eptest.AuditInfo{Username: "easyrmm:EasyRMM", Org: &fOrg, Endpoint: &fEndpoint, Action: "endpoint.update", TargetType: "Endpoint",
		TargetID: fEndpoint.String(), Details: "{}", IPAddress: "192.0.2.1"})
	// send asks base with the statement of a call made without one.
	send := func(base, method, path string, body any) (int, []byte) {
		return call(c.ctx, t, c.http, base, method, path, body, signed(t, c.signer, statementFor(c.ctx, ""), method, path))
	}
	at := time.Now().Add(4 * time.Hour).UTC().Truncate(time.Second)
	install := map[string]any{"mode": "Selected", "updateGuids": []uuid.UUID{}, "force": false, "scheduledAt": at}
	// The fake's endpoint has its own update GUIDs; ask each for one of its own.
	pick := func(base string, e uuid.UUID) uuid.UUID {
		_, data := send(base, http.MethodGet, "/api/v1/endpoints/"+e.String()+"/updates", nil)
		var list []struct {
			UpdateGUID uuid.UUID `json:"updateGuid"`
		}
		if err := json.Unmarshal(data, &list); err != nil || len(list) == 0 {
			t.Fatalf("updates: %v: %s", err, data)
		}
		return list[0].UpdateGUID
	}
	fUpdate, rUpdate := pick(fake.URL(), fEndpoint), pick(c.engineURL, endpoint)
	fakeInstall := map[string]any{"mode": "Selected", "updateGuids": []uuid.UUID{fUpdate}, "force": false, "scheduledAt": at}
	install["updateGuids"] = []uuid.UUID{rUpdate}

	// The fake's job comes from an install like the real one's.
	_, data := send(fake.URL(), http.MethodPost, "/api/v1/endpoints/"+fEndpoint.String()+"/install-updates", fakeInstall)
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
		// Server-wide settings.
		q("server settings", "GET", "/api/v1/settings", "/api/v1/settings"),
		q("vulnerability feeds", "GET", "/api/v1/vulnerability-feeds", "/api/v1/vulnerability-feeds"),
		q("lifecycle", "GET", "/api/v1/lifecycle", "/api/v1/lifecycle"),
		q("audit log", "GET", "/api/v1/audit-logs?pageSize=5", "/api/v1/audit-logs?pageSize=5"),
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
		// The update catalog.
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
		// Policies and tags.
		q("global policy", "GET", "/api/v1/policies/global", "/api/v1/policies/global"),
		q("no organization policy", "GET", "/api/v1/organizations/"+fOrg.String()+"/policy", "/api/v1/organizations/"+org.String()+"/policy"),
		q("no endpoint policy", "GET", "/api/v1/endpoints/"+fEndpoint.String()+"/policy", "/api/v1/endpoints/"+endpoint.String()+"/policy"),
		{name: "save a site policy", method: "PUT", fake: "/api/v1/sites/" + fSite.String() + "/policy", real: "/api/v1/sites/" + site.String() + "/policy",
			fBody: shapePolicy, rBody: shapePolicy},
		q("tag policies", "GET", "/api/v1/endpoints/"+fEndpoint.String()+"/tag-policies", "/api/v1/endpoints/"+endpoint.String()+"/tag-policies"),
		q("tags", "GET", "/api/v1/tags", "/api/v1/tags"),
	}
	ask := func(qu question) (f, r any) {
		fStatus, fData := send(fake.URL(), qu.method, qu.fake, qu.fBody)
		rStatus, rData := send(c.engineURL, qu.method, qu.real, qu.rBody)
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

// shapePolicy is a site policy with every kind of value, for comparing the
// shape of EasyPatch's answer with eptest's.
var shapePolicy = PolicyLayer{ScanStaleAfterHours: ptr(72), ExcludedKbs: []string{"KB5044284"}, AllowedCategories: []string{"Security"},
	MaintenanceDays: []int{2}, MaintenanceStart: ptr("01:00"), MaintenanceDurationMinutes: ptr(60),
	RestartSchedule: &RestartSchedule{Enabled: false, Days: []int{}, Time: "03:00", Condition: "OnlyIfPending", Mode: "PromptWithDeadline",
		CountdownMinutes: 5, DeadlineMinutes: 240, ExpiryMinutes: 120},
	WindowsUpdate: &LayerWindowsUpdate{QualityUpdates: &GroupSetting[QualityUpdates]{Managed: true, Value: &QualityUpdates{DeferDays: ptr(3)}},
		FeatureUpdates: &GroupSetting[FeatureUpdates]{Managed: false}},
	ApplicationUpdates: &ApplicationUpdates{Enabled: true, ApprovedApps: []string{"Mozilla.Firefox"}}}

// isEngineCode says err is EasyPatch's problem with code.
func isEngineCode(err error, code string) bool {
	var e *Error
	return errors.As(err, &e) && e.Code == code
}
