//go:build integration

package remote

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/server/internal/access"
	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/auth"
	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/devices"
	"github.com/paulmataruso/easyrmm/server/internal/meshcentral"
	"github.com/paulmataruso/easyrmm/server/internal/meshcentral/meshtest"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
	"github.com/paulmataruso/easyrmm/server/internal/secrets"
	"github.com/paulmataruso/easyrmm/server/internal/tenancy"
	"github.com/paulmataruso/easyrmm/server/internal/testdb"
)

// rig is an EasyRMM database, the test MeshCentral and the remote-access
// service between them.
type rig struct {
	t     *testing.T
	ctx   context.Context
	db    *database.DB
	audit *audit.Logger
	ten   *tenancy.Service
	mesh  *meshcentral.Client
	svc   *Service
	dev   *devices.Service
	env   meshtest.Env
	sys   access.Caller
	log   *slog.Logger
}

func newRig(t *testing.T) *rig {
	t.Helper()
	inst := testdb.New(t)
	env := meshtest.Get(t)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	// Background goroutines may log after the test ends, so not via t.Log.
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	r := &rig{t: t, ctx: ctx, db: inst.DB, env: env, sys: access.System("test"), log: log}
	r.audit = audit.New(inst.DB, nil)
	r.ten = tenancy.New(inst.DB, r.audit)
	var err error
	r.mesh, err = meshcentral.NewClient(meshcentral.ClientOptions{
		BaseURL: env.URL, Key: env.Key, Log: log,
		OnEvent: func(ev meshcentral.Event) { r.svc.HandleEvent(ev) },
	})
	if err != nil {
		t.Fatal(err)
	}
	meshURL, _ := url.Parse(fmt.Sprintf("https://%s:%d", env.Hostname, env.PublicPort))
	r.svc = New(inst.DB, r.audit, r.mesh, Config{MeshURL: meshURL, LoginKey: env.Key}, log)
	r.dev = devices.New(inst.DB, true)
	go r.mesh.Run(ctx)
	r.waitFor(20*time.Second, "the MeshCentral control connection", r.mesh.Connected)
	t.Cleanup(r.cleanup)
	return r
}

// cleanup removes this test's groups and accounts from the shared
// MeshCentral: with no sites and no users left, a reconciliation deletes
// everything EasyRMM created.
func (r *rig) cleanup() {
	ctx := context.Background()
	r.exec(`DELETE FROM devices`)
	r.exec(`DELETE FROM sites`)
	r.exec(`DELETE FROM users`)
	if err := r.svc.Reconcile(ctx); err != nil {
		r.t.Logf("cleanup reconciliation: %v", err)
	}
}

func (r *rig) waitFor(d time.Duration, what string, ok func() bool) {
	r.t.Helper()
	deadline := time.Now().Add(d)
	for !ok() {
		if time.Now().After(deadline) {
			r.t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func (r *rig) exec(sql string, args ...any) {
	r.t.Helper()
	err := r.db.InTx(r.ctx, database.System, func(tx pgx.Tx) error {
		_, err := tx.Exec(r.ctx, sql, args...)
		return err
	})
	if err != nil {
		r.t.Fatalf("%s: %v", sql, err)
	}
}

func (r *rig) count(sql string, args ...any) int {
	r.t.Helper()
	var n int
	err := r.db.ReadTx(r.ctx, database.System, func(tx pgx.Tx) error {
		return tx.QueryRow(r.ctx, sql, args...).Scan(&n)
	})
	if err != nil {
		r.t.Fatalf("%s: %v", sql, err)
	}
	return n
}

func (r *rig) org(name string) *tenancy.Organization {
	r.t.Helper()
	o, err := r.ten.CreateOrganization(r.ctx, r.sys, tenancy.OrganizationInput{Name: name})
	if err != nil {
		r.t.Fatal(err)
	}
	return o
}

func (r *rig) site(org uuid.UUID, name string) *tenancy.Site {
	r.t.Helper()
	s, err := r.ten.CreateSite(r.ctx, r.sys, org, tenancy.SiteInput{Name: name})
	if err != nil {
		r.t.Fatal(err)
	}
	return s
}

// user creates an active user with the given roles and returns a caller
// acting as them.
func (r *rig) user(name string, as ...rbac.Assignment) (uuid.UUID, access.Caller) {
	r.t.Helper()
	var id uuid.UUID
	email := strings.ToLower(strings.ReplaceAll(name, " ", ".")) + "@example.com"
	err := r.db.InTx(r.ctx, database.System, func(tx pgx.Tx) error {
		if err := tx.QueryRow(r.ctx, `INSERT INTO users (email, display_name) VALUES ($1, $2) RETURNING id`, email, name).Scan(&id); err != nil {
			return err
		}
		for _, a := range as {
			var org, site *uuid.UUID
			if a.OrganizationID != uuid.Nil {
				org = &a.OrganizationID
			}
			if a.SiteID != uuid.Nil {
				site = &a.SiteID
			}
			if _, err := tx.Exec(r.ctx, `INSERT INTO role_assignments (user_id, role, organization_id, site_id) VALUES ($1, $2, $3, $4)`,
				id, string(a.Role), org, site); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		r.t.Fatal(err)
	}
	p, err := rbac.NewPrincipal(id, as)
	if err != nil {
		r.t.Fatal(err)
	}
	return id, access.User(p, auth.DataScope(p), audit.Actor{Type: audit.ActorUser, ID: id, Label: email})
}

// session creates a signed-in session for a user.
func (r *rig) session(userID uuid.UUID) uuid.UUID {
	r.t.Helper()
	var id uuid.UUID
	h := make([]byte, 32)
	_, _ = rand.Read(h)
	err := r.db.InTx(r.ctx, database.System, func(tx pgx.Tx) error {
		return tx.QueryRow(r.ctx, `INSERT INTO sessions (token_hash, user_id, state, idle_expires_at, expires_at)
			VALUES ($1, $2, 'active', now() + interval '1 hour', now() + interval '2 hours') RETURNING id`, h, userID).Scan(&id)
	})
	if err != nil {
		r.t.Fatal(err)
	}
	return id
}

func (r *rig) revoke(session uuid.UUID) {
	r.exec(`UPDATE sessions SET revoked_at = now(), revoked_reason = 'test' WHERE id = $1`, session)
}

// device records a device directly, as if discovered from MeshCentral.
func (r *rig) device(s *tenancy.Site, name, nodeID string, online bool) uuid.UUID {
	r.t.Helper()
	var node *string
	if nodeID != "" {
		node = &nodeID
	}
	var id uuid.UUID
	err := r.db.InTx(r.ctx, database.System, func(tx pgx.Tx) error {
		return tx.QueryRow(r.ctx, `INSERT INTO devices (organization_id, site_id, name, hostname, platform, mesh_node_id, remote_online)
			VALUES ($1, $2, $3, $3, 'linux', $4, $5) RETURNING id`, s.OrganizationID, s.ID, name, node, online).Scan(&id)
	})
	if err != nil {
		r.t.Fatal(err)
	}
	return id
}

func (r *rig) meshOfSite(site uuid.UUID) string {
	r.t.Helper()
	id, err := r.svc.meshOf(r.ctx, site)
	if err != nil || id == "" {
		r.t.Fatalf("no group recorded for site %s (%v)", site, err)
	}
	return id
}

func (r *rig) meshes() map[string]meshcentral.Mesh {
	r.t.Helper()
	ms, err := r.mesh.Meshes(r.ctx)
	if err != nil {
		r.t.Fatal(err)
	}
	out := map[string]meshcentral.Mesh{}
	for _, m := range ms {
		out[m.ID] = m
	}
	return out
}

func (r *rig) accounts() map[string]meshcentral.User {
	r.t.Helper()
	us, err := r.mesh.Users(r.ctx)
	if err != nil {
		r.t.Fatal(err)
	}
	out := map[string]meshcentral.User{}
	for _, u := range us {
		out[u.ID] = u
	}
	return out
}

func (r *rig) reconcile() {
	r.t.Helper()
	if err := r.svc.Reconcile(r.ctx); err != nil {
		r.t.Fatalf("reconcile: %v", err)
	}
}

var fullAccess = meshcentral.Access{Desktop: true, Terminal: true, Files: true}

func TestReconcileMirrorsTenancy(t *testing.T) {
	r := newRig(t)
	acme, globex := r.org("Acme"), r.org("Globex")
	hq, branch, lab := r.site(acme.ID, "HQ"), r.site(acme.ID, "Branch"), r.site(globex.ID, "Lab")

	tech, _ := r.user("Tess Tech", rbac.Assignment{Role: rbac.RoleTechnician, OrganizationID: acme.ID, SiteID: hq.ID})
	admin, _ := r.user("Ora Admin", rbac.Assignment{Role: rbac.RoleOrgAdmin, OrganizationID: acme.ID})
	viewer, _ := r.user("Vic Viewer", rbac.Assignment{Role: rbac.RoleReadOnly, OrganizationID: globex.ID})
	super, _ := r.user("Sue Super", rbac.Assignment{Role: rbac.RoleSuperAdmin})
	disabled, _ := r.user("Dan Disabled", rbac.Assignment{Role: rbac.RoleTechnician, OrganizationID: globex.ID})
	r.exec(`UPDATE users SET status = 'disabled' WHERE id = $1`, disabled)

	r.reconcile()

	meshes := r.meshes()
	for _, s := range []*tenancy.Site{hq, branch, lab} {
		m, ok := meshes[r.meshOfSite(s.ID)]
		if !ok {
			t.Fatalf("site %s: group missing", s.Name)
		}
		if want := s.OrganizationName + " / " + s.Name; m.Name != want {
			t.Errorf("group name = %q, want %q", m.Name, want)
		}
		if got, ok := markedSite(m); !ok || got != s.ID {
			t.Errorf("group %q is not marked with its site", m.Name)
		}
	}
	accounts := r.accounts()
	for _, u := range []uuid.UUID{tech, admin, super} {
		a, ok := accounts[accountID(u)]
		if !ok {
			t.Fatalf("no MeshCentral account for user %s", u)
		}
		if a.SiteAdmin != meshcentral.TechnicianSiteRights {
			t.Errorf("account %s site rights = %d", a.Name, a.SiteAdmin)
		}
	}
	if a := accounts[accountID(tech)]; a.RealName != "Tess Tech" {
		t.Errorf("real name = %q", a.RealName)
	}
	for _, u := range []uuid.UUID{viewer, disabled} {
		if _, ok := accounts[accountID(u)]; ok {
			t.Errorf("user %s without remote access has an account", u)
		}
	}
	wantRights := map[*tenancy.Site]map[uuid.UUID]uint32{
		hq:     {tech: fullAccess.Rights(), admin: fullAccess.Rights(), super: fullAccess.Rights()},
		branch: {admin: fullAccess.Rights(), super: fullAccess.Rights()},
		lab:    {super: fullAccess.Rights()},
	}
	for s, want := range wantRights {
		m := meshes[r.meshOfSite(s.ID)]
		got := map[uuid.UUID]uint32{}
		for uid, l := range m.Links {
			if id, ok := userOfAccount(uid); ok {
				got[id] = l.Rights
			}
		}
		if fmt.Sprint(got) != fmt.Sprint(want) {
			t.Errorf("site %s links = %v, want %v", s.Name, got, want)
		}
	}

	// A second pass changes nothing.
	before := r.meshes()
	r.reconcile()
	after := r.meshes()
	if len(before) != len(after) {
		t.Errorf("second pass changed the groups: %d → %d", len(before), len(after))
	}

	// Renaming the organization renames its groups.
	if _, err := r.ten.UpdateOrganization(r.ctx, r.sys, acme.ID, tenancy.OrganizationInput{Name: "Acme Corp"}); err != nil {
		t.Fatal(err)
	}
	r.reconcile()
	if m := r.meshes()[r.meshOfSite(hq.ID)]; m.Name != "Acme Corp / HQ" {
		t.Errorf("renamed group = %q", m.Name)
	}

	// Losing the role removes the account.
	r.exec(`DELETE FROM role_assignments WHERE user_id = $1`, tech)
	r.reconcile()
	if _, ok := r.accounts()[accountID(tech)]; ok {
		t.Error("account kept after the user lost remote access")
	}

	// A lost mapping row is recovered by adopting the marked group, not by
	// creating a second one.
	hqMesh := r.meshOfSite(hq.ID)
	r.exec(`DELETE FROM mesh_sites WHERE site_id = $1`, hq.ID)
	r.reconcile()
	if got := r.meshOfSite(hq.ID); got != hqMesh {
		t.Errorf("site group after a lost mapping = %s, want the adopted %s", got, hqMesh)
	}
	n := 0
	for _, m := range r.meshes() {
		if s, ok := markedSite(m); ok && s == hq.ID {
			n++
		}
	}
	if n != 1 {
		t.Errorf("%d groups for one site", n)
	}

	// Deleting a site deletes its group.
	branchMesh := r.meshOfSite(branch.ID)
	if err := r.ten.DeleteSite(r.ctx, r.sys, branch.ID); err != nil {
		t.Fatal(err)
	}
	r.reconcile()
	if _, ok := r.meshes()[branchMesh]; ok {
		t.Error("group of a deleted site still exists")
	}

	st := r.svc.Status(r.ctx)
	if !st.Connected || st.LastSyncAt == nil || st.LastError != "" {
		t.Errorf("status = %+v", st)
	}
}

func TestReconcileReportsUnavailable(t *testing.T) {
	r := newRig(t)
	r.org("Acme")
	// A client that cannot reach MeshCentral.
	dead, err := meshcentral.NewClient(meshcentral.ClientOptions{BaseURL: "http://127.0.0.1:1", Key: r.env.Key})
	if err != nil {
		t.Fatal(err)
	}
	svc := New(r.db, r.audit, dead, r.svc.cfg, r.log)
	ctx, cancel := context.WithTimeout(r.ctx, 2*time.Second) // calls wait for a reconnection until then
	defer cancel()
	if err := svc.Reconcile(ctx); !errors.Is(err, meshcentral.ErrUnavailable) {
		t.Fatalf("reconcile without MeshCentral = %v", err)
	}
	if st := svc.Status(r.ctx); st.Connected || st.LastError == "" || st.LastErrorAt == nil {
		t.Errorf("status = %+v", st)
	}
}

// serveGateway serves the gateway with TLS where the test MeshCentral tells
// agents to connect, and returns a browser-like client for it.
func (r *rig) serveGateway(g *Gateway) {
	r.t.Helper()
	cert, err := tls.LoadX509KeyPair(r.env.CertFile, r.env.KeyFile)
	if err != nil {
		r.t.Fatal(err)
	}
	ln, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(r.env.PublicPort)))
	if err != nil {
		r.t.Fatal(err)
	}
	srv := &http.Server{Handler: g, ReadHeaderTimeout: 10 * time.Second,
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}}
	go func() { _ = srv.ServeTLS(ln, "", "") }()
	r.t.Cleanup(func() { _ = srv.Close() })
}

func (r *rig) browser() *http.Client {
	r.t.Helper()
	pem, err := os.ReadFile(r.env.CertFile)
	if err != nil {
		r.t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(pem)
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(r.env.PublicPort))
	d := &net.Dialer{Timeout: 5 * time.Second}
	jar, _ := cookiejar.New(nil)
	return &http.Client{
		Jar: jar,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return d.DialContext(ctx, network, addr)
			},
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

func (r *rig) origin() string { return fmt.Sprintf("https://%s:%d", r.env.Hostname, r.env.PublicPort) }

// fetched is a response whose body has been read and closed.
type fetched struct {
	StatusCode int
	Header     http.Header
	cookies    []*http.Cookie
}

func (f fetched) Cookies() []*http.Cookie { return f.cookies }

func (r *rig) get(c *http.Client, target string) (fetched, string) {
	r.t.Helper()
	if strings.HasPrefix(target, "/") {
		target = r.origin() + target
	}
	ctx, cancel := context.WithTimeout(r.ctx, 30*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	resp, err := c.Do(req)
	if err != nil {
		r.t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	return fetched{StatusCode: resp.StatusCode, Header: resp.Header, cookies: resp.Cookies()}, string(body)
}

// open signs a browser in through a launch link, as the console's iframe
// does, and returns the page it lands on, on the link's origin.
func (r *rig) open(c *http.Client, l *Launch) string {
	r.t.Helper()
	link, err := url.Parse(l.URL)
	if err != nil {
		r.t.Fatal(err)
	}
	resp, body := r.get(c, l.URL)
	if resp.StatusCode != http.StatusSeeOther {
		r.t.Fatalf("launch: %d %s", resp.StatusCode, body)
	}
	loc := resp.Header.Get("Location")
	// MeshCentral's page must be able to read the device and view from it.
	if args := parseUriArgs(loc); !strings.HasPrefix(loc, "/?") || !strings.Contains(loc, "&login=") ||
		args["gotonode"] == "" || args["viewmode"] == "" || args["hide"] != "63" {
		r.t.Fatalf("launch redirect = %q", loc)
	}
	var grant *http.Cookie
	for _, ck := range resp.Cookies() {
		if ck.Name == "__Host-easyrmm_remote" {
			grant = ck
		}
	}
	if grant == nil || !grant.HttpOnly || !grant.Secure || grant.SameSite != http.SameSiteStrictMode || grant.Path != "/" {
		r.t.Fatalf("grant cookie = %+v", grant)
	}
	resp, body = r.get(c, link.Scheme+"://"+link.Host+loc)
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, "var userinfo") {
		r.t.Fatalf("MeshCentral page after launch: %d %.300s", resp.StatusCode, body)
	}
	return body
}

// dial opens a WebSocket through the gateway as the browser, from a page on
// the public MeshCentral origin.
func (r *rig) dial(c *http.Client, path string) (*websocket.Conn, error) {
	return r.dialOn(c, r.origin(), r.origin(), path)
}

// dialOn opens a WebSocket through the gateway on a MeshCentral origin, as
// a page on origin.
func (r *rig) dialOn(c *http.Client, meshOrigin, origin, path string) (*websocket.Conn, error) {
	ctx, cancel := context.WithTimeout(r.ctx, 15*time.Second)
	defer cancel()
	//nolint:bodyclose // coder/websocket owns the handshake response body
	ws, _, err := websocket.Dial(ctx, "wss://"+strings.TrimPrefix(meshOrigin, "https://")+path, &websocket.DialOptions{
		HTTPClient: c,
		HTTPHeader: http.Header{"Origin": {origin}},
	})
	if err == nil {
		ws.SetReadLimit(16 << 20)
	}
	return ws, err
}

// readUntil reads JSON messages until one has the given action.
func readUntil(t *testing.T, ws *websocket.Conn, action string, d time.Duration) map[string]json.RawMessage {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()
	for {
		typ, data, err := ws.Read(ctx)
		if err != nil {
			t.Fatalf("waiting for %q: %v", action, err)
		}
		if typ != websocket.MessageText {
			continue
		}
		var m map[string]json.RawMessage
		if json.Unmarshal(data, &m) != nil {
			continue
		}
		var a string
		_ = json.Unmarshal(m["action"], &a)
		if a == action {
			return m
		}
	}
}

func send(t *testing.T, ws *websocket.Conn, v any) {
	t.Helper()
	b, _ := json.Marshal(v)
	if err := ws.Write(context.Background(), websocket.MessageText, b); err != nil {
		t.Fatal(err)
	}
}

func wantAppErr(t *testing.T, err error, kind apperr.Kind, what string) {
	t.Helper()
	ae, ok := apperr.As(err)
	if !ok || ae.Kind != kind {
		t.Fatalf("%s: got %v, want kind %d", what, err, kind)
	}
}

func TestRemoteSessionLaunch(t *testing.T) {
	r := newRig(t)
	acme := r.org("Acme")
	hq := r.site(acme.ID, "HQ")
	techID, tech := r.user("Tess Tech", rbac.Assignment{Role: rbac.RoleTechnician, OrganizationID: acme.ID, SiteID: hq.ID})
	viewerID, viewer := r.user("Vic Viewer", rbac.Assignment{Role: rbac.RoleReadOnly, OrganizationID: acme.ID})
	_, stranger := r.user("Sam Stranger", rbac.Assignment{Role: rbac.RoleTechnician, OrganizationID: r.org("Elsewhere").ID})
	r.reconcile()

	online := r.device(hq, "web-01", "node//easyrmmtest"+hex.EncodeToString([]byte(uuid.NewString()[:8])), true)
	offline := r.device(hq, "db-01", "node//easyrmmtestoffline", false)
	noAgent := r.device(hq, "printer", "", false)
	sess := r.session(techID)

	// Listing and status.
	list, err := r.dev.List(r.ctx, tech, devices.Query{})
	if err != nil || len(list) != 3 {
		t.Fatalf("tech devices = %d, %v", len(list), err)
	}
	if list[2].Name != "web-01" || !list[2].CanDesktop || !list[2].RemoteAgent || list[1].RemoteAgent {
		t.Errorf("devices = %+v %+v", list[1], list[2])
	}
	if l, _ := r.dev.List(r.ctx, tech, devices.Query{Status: "online"}); len(l) != 1 {
		t.Errorf("online devices = %d", len(l))
	}
	if l, _ := r.dev.List(r.ctx, tech, devices.Query{Search: "DB", SiteID: hq.ID, OrganizationID: acme.ID}); len(l) != 1 || l[0].ID != offline {
		t.Errorf("search = %+v", l)
	}
	if _, err := r.dev.List(r.ctx, tech, devices.Query{Status: "asleep"}); err == nil {
		t.Error("bad status filter accepted")
	}
	if l, _ := r.dev.List(r.ctx, stranger, devices.Query{}); len(l) != 0 {
		t.Errorf("stranger sees %d devices", len(l))
	}
	if d, err := r.dev.Get(r.ctx, viewer, online); err != nil || d.CanDesktop || d.CanTerminal || d.CanFiles {
		t.Errorf("viewer device = %+v, %v", d, err)
	}
	if _, err := r.dev.Get(r.ctx, stranger, online); !errors.Is(err, apperr.ErrNotFound) {
		t.Errorf("stranger GetDevice = %v", err)
	}
	if st := r.svc.Status(r.ctx); st.Devices != 2 || st.DevicesOnline != 1 {
		t.Errorf("status counts = %+v", st)
	}

	// Refusals.
	_, err = r.svc.StartSession(r.ctx, viewer, r.session(viewerID), online, KindDesktop)
	wantAppErr(t, err, apperr.KindForbidden, "read-only user")
	entries, err := r.audit.List(r.ctx, database.System, audit.Query{ActionPrefix: "device.remote_session"})
	if err != nil || len(entries) != 1 || entries[0].Outcome != audit.Denied || entries[0].DeviceID == nil {
		t.Errorf("denied audit = %+v, %v", entries, err)
	}
	_, err = r.svc.StartSession(r.ctx, tech, sess, online, "console")
	wantAppErr(t, err, apperr.KindInvalid, "unknown kind")
	_, err = r.svc.StartSession(r.ctx, tech, sess, noAgent, KindDesktop)
	wantAppErr(t, err, apperr.KindConflict, "no agent")
	_, err = r.svc.StartSession(r.ctx, tech, sess, offline, KindDesktop)
	wantAppErr(t, err, apperr.KindConflict, "offline")
	_, err = r.svc.StartSession(r.ctx, stranger, sess, online, KindDesktop)
	wantAppErr(t, err, apperr.KindNotFound, "device outside the caller's scope")

	// The account is created and granted on demand.
	// (A reconciliation here would drop these devices: their nodes do not
	// exist in MeshCentral.)
	if err := r.mesh.DeleteUser(r.ctx, accountID(techID)); err != nil {
		t.Fatal(err)
	}
	l, err := r.svc.StartSession(r.ctx, tech, sess, online, KindTerminal)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(l.URL, r.origin()+LaunchPath+"?t=") || l.Kind != KindTerminal || time.Until(l.ExpiresAt) > LaunchTTL {
		t.Errorf("launch = %+v", l)
	}
	if m := r.meshes()[r.meshOfSite(hq.ID)]; m.Links[accountID(techID)].Rights != fullAccess.Rights() {
		t.Errorf("rights after launch = %+v", m.Links)
	}
	entries, _ = r.audit.List(r.ctx, database.System, audit.Query{ActionPrefix: "device.remote_session"})
	if len(entries) != 2 || entries[0].Outcome != audit.Success || entries[0].Details["kind"] != "terminal" {
		t.Errorf("success audit = %+v", entries[0])
	}

	// The browser side, through the gateway.
	upstream, _ := url.Parse(r.env.URL)
	g, err := NewGateway(r.svc, GatewayConfig{Upstream: upstream, Secure: true, CacheTTL: 200 * time.Millisecond}, r.log)
	if err != nil {
		t.Fatal(err)
	}
	r.serveGateway(g)
	b := r.browser()
	page := r.open(b, l)
	if !strings.Contains(page, accountName(techID)) {
		t.Error("MeshCentral page is not signed in as the technician's account")
	}
	if resp, body := r.get(r.browser(), l.URL); resp.StatusCode != http.StatusForbidden || !strings.Contains(body, "expired") {
		t.Errorf("second use of a launch link: %d", resp.StatusCode)
	}
	if resp, _ := r.get(r.browser(), "/"); resp.StatusCode != http.StatusForbidden {
		t.Errorf("browser without a grant: %d", resp.StatusCode)
	}
	if resp, _ := r.get(b, "/meshsettings?id=x"); resp.StatusCode != http.StatusForbidden {
		t.Errorf("blocked feature with a grant: %d", resp.StatusCode)
	}
	// MeshCentral's device page embeds MeshCommander and calls into it to
	// open a device; without it the page shows no device at all.
	if resp, body := r.get(b, "/commander.ashx"); resp.StatusCode != http.StatusOK || !strings.Contains(body, "getCurrentMeshNode") {
		t.Errorf("MeshCommander frame with a grant: %d", resp.StatusCode)
	}

	// The browser's MeshCentral control channel is the technician's.
	ws, err := r.dial(b, "/control.ashx")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ws.CloseNow() }()
	ui := readUntil(t, ws, "userinfo", 15*time.Second)
	var info struct {
		UserInfo struct {
			ID        string `json:"_id"`
			SiteAdmin uint32 `json:"siteadmin"`
		} `json:"userinfo"`
	}
	b2, _ := json.Marshal(ui)
	_ = json.Unmarshal(b2, &info)
	if info.UserInfo.ID != accountID(techID) || info.UserInfo.SiteAdmin != meshcentral.TechnicianSiteRights {
		t.Errorf("browser signed in as %+v", info.UserInfo)
	}
	if g.OpenConnections() != 1 {
		t.Errorf("tracked connections = %d", g.OpenConnections())
	}

	// Signing out of EasyRMM ends the remote session.
	r.revoke(sess)
	g.sweep(r.ctx)
	rctx, cancel := context.WithTimeout(r.ctx, 5*time.Second)
	defer cancel()
	for {
		if _, _, err := ws.Read(rctx); err != nil {
			if rctx.Err() != nil {
				t.Fatal("WebSocket still open after its session was revoked")
			}
			break
		}
	}
	if g.OpenConnections() != 0 {
		t.Errorf("tracked connections after sweep = %d", g.OpenConnections())
	}
	if resp, _ := r.get(b, "/"); resp.StatusCode != http.StatusForbidden {
		t.Errorf("grant still accepted after sign-out: %d", resp.StatusCode)
	}

	// Launch links expire, and die with their session.
	sess2 := r.session(techID)
	l2, err := r.svc.StartSession(r.ctx, tech, sess2, online, KindDesktop)
	if err != nil {
		t.Fatal(err)
	}
	r.svc.now = func() time.Time { return time.Now().Add(2 * LaunchTTL) }
	if resp, _ := r.get(r.browser(), l2.URL); resp.StatusCode != http.StatusForbidden {
		t.Errorf("expired launch link: %d", resp.StatusCode)
	}
	r.svc.now = time.Now
	l3, err := r.svc.StartSession(r.ctx, tech, sess2, online, KindFiles)
	if err != nil {
		t.Fatal(err)
	}
	r.revoke(sess2)
	if resp, _ := r.get(r.browser(), l3.URL); resp.StatusCode != http.StatusForbidden {
		t.Errorf("launch link of a revoked session: %d", resp.StatusCode)
	}
	if valid, err := r.svc.SessionsValid(r.ctx, []uuid.UUID{sess, sess2, r.session(techID)}); err != nil || len(valid) != 1 {
		t.Errorf("SessionsValid = %v, %v", valid, err)
	}

	// Old grants are cleaned up.
	if r.count(`SELECT count(*) FROM remote_grants`) != 3 {
		t.Fatalf("grants = %d", r.count(`SELECT count(*) FROM remote_grants`))
	}
	r.exec(`UPDATE remote_grants SET created_at = now() - interval '2 days'`)
	if err := r.svc.CleanupGrants(r.ctx); err != nil {
		t.Fatal(err)
	}
	if n := r.count(`SELECT count(*) FROM remote_grants`); n != 0 {
		t.Errorf("grants after cleanup = %d", n)
	}
}

// controlAnswer reads a control connection's first answer that is either
// the user's details or MeshCentral closing it, and returns its action
// and cause.
func controlAnswer(t *testing.T, ws *websocket.Conn) (action, cause string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	for {
		typ, data, err := ws.Read(ctx)
		if err != nil {
			t.Fatalf("waiting for MeshCentral's answer: %v", err)
		}
		var m struct {
			Action string `json:"action"`
			Cause  string `json:"cause"`
		}
		if typ == websocket.MessageText && json.Unmarshal(data, &m) == nil && (m.Action == "userinfo" || m.Action == "close") {
			return m.Action, m.Cause
		}
	}
}

// A session launched from a console reached by IP address runs on that
// address's MeshCentral origin (ADR-0016), so MeshCentral sees that origin
// on the session's control connection. It accepts every MeshCentral origin
// EasyRMM serves (allowedOrigin), IPv4 and IPv6, and still refuses others.
// Until 2026-11-21 it accepted only its own hostname (`cert`) and closed
// every session from an IP origin with "invalidorigin".
func TestRemoteSessionFromIPOrigin(t *testing.T) {
	r := newRig(t)
	acme := r.org("Acme")
	hq := r.site(acme.ID, "HQ")
	techID, tech := r.user("Tess Tech", rbac.Assignment{Role: rbac.RoleTechnician, OrganizationID: acme.ID, SiteID: hq.ID})
	r.reconcile()
	online := r.device(hq, "web-01", "node//easyrmmtest"+hex.EncodeToString([]byte(uuid.NewString()[:8])), true)

	upstream, _ := url.Parse(r.env.URL)
	g, err := NewGateway(r.svc, GatewayConfig{Upstream: upstream, Secure: true}, r.log)
	if err != nil {
		t.Fatal(err)
	}
	r.serveGateway(g)
	cert, err := tls.LoadX509KeyPair(r.env.CertFile, r.env.KeyFile)
	if err != nil {
		t.Fatal(err)
	}
	for _, origin := range meshtest.IPOrigins {
		t.Run(origin, func(t *testing.T) {
			o, _ := url.Parse(origin)
			if err := cert.Leaf.VerifyHostname(o.Hostname()); err != nil {
				t.Fatalf("the test MeshCentral predates its IP origins; set it up again with `make test-mesh`: %v", err)
			}
			l, err := r.svc.StartSession(r.ctx, tech, r.session(techID), online, KindTerminal)
			if err != nil {
				t.Fatal(err)
			}
			// As the console's API moves a launch to the MeshCentral
			// origin of the console origin it was asked on.
			link, _ := url.Parse(l.URL)
			link.Host = o.Host
			l.URL = link.String()
			b := r.browser()
			r.open(b, l)

			ws, err := r.dialOn(b, origin, origin, "/control.ashx")
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = ws.CloseNow() }()
			if action, cause := controlAnswer(t, ws); action != "userinfo" {
				t.Fatalf("MeshCentral answered a session from %s with %s (%s)", origin, action, cause)
			}

			// A page on a host EasyRMM does not serve is refused.
			other, err := r.dialOn(b, origin, "https://198.51.100.7:4443", "/control.ashx")
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = other.CloseNow() }()
			if action, cause := controlAnswer(t, other); action != "close" || cause != "invalidorigin" {
				t.Fatalf("a foreign origin got %s (%s)", action, cause)
			}
		})
	}
}

// agentFiles downloads the Linux x86-64 MeshAgent and its settings for a
// device group, signed in as the service account (anonymous downloads are
// locked), into a directory the agent can write its database to.
func (r *rig) agentFiles(meshID string) string {
	r.t.Helper()
	token, err := meshcentral.LoginToken(r.env.Key, meshcentral.UserID(meshcentral.ServiceAccount), time.Now())
	if err != nil {
		r.t.Fatal(err)
	}
	fetch := func(path string, cookies []*http.Cookie) (fetched, []byte) {
		req, _ := http.NewRequestWithContext(r.ctx, http.MethodGet, r.env.URL+path, nil)
		req.Header.Set("X-Forwarded-Proto", "https")
		// MeshCentral marks its session cookie Secure; send it back by hand
		// over the loopback HTTP connection.
		for _, c := range cookies {
			req.AddCookie(&http.Cookie{Name: c.Name, Value: c.Value})
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			r.t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		body, _ := io.ReadAll(resp.Body)
		return fetched{StatusCode: resp.StatusCode, Header: resp.Header, cookies: resp.Cookies()}, body
	}
	resp, _ := fetch("/?login="+url.QueryEscape(token), nil)
	session := resp.Cookies()
	if len(session) == 0 {
		r.t.Fatal("signing in as the service account set no session cookie")
	}
	if resp, _ := fetch("/meshagents?id=6", nil); resp.StatusCode == http.StatusOK {
		r.t.Error("anonymous agent download allowed")
	}
	resp, bin := fetch("/meshagents?id=6", session)
	if resp.StatusCode != http.StatusOK || len(bin) < 1<<20 {
		r.t.Fatalf("agent download: %d, %d bytes", resp.StatusCode, len(bin))
	}
	resp, msh := fetch("/meshsettings?id="+url.QueryEscape(strings.TrimPrefix(meshID, "mesh//")), session)
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(msh), "MeshServer=wss://"+r.env.Hostname+":"+strconv.Itoa(r.env.PublicPort)+"/agent.ashx") {
		r.t.Fatalf("agent settings: %d %q", resp.StatusCode, msh)
	}
	dir := r.t.TempDir()
	if err := os.Chmod(dir, 0o777); err != nil { //nolint:gosec // the agent runs as another user and keeps its database here
		r.t.Fatal(err)
	}
	if err := os.WriteFile(dir+"/meshagent", bin, 0o755); err != nil { //nolint:gosec // an executable
		r.t.Fatal(err)
	}
	if err := os.WriteFile(dir+"/meshagent.msh", msh, 0o644); err != nil { //nolint:gosec // read by the agent's user
		r.t.Fatal(err)
	}
	return dir
}

// docker runs a docker command.
func docker(t *testing.T, args ...string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	out, err := exec.CommandContext(ctx, "docker", args...).CombinedOutput()
	if err != nil {
		t.Fatalf("docker %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return string(out)
}

// TestAgentEndToEnd runs a real MeshAgent against the test MeshCentral
// through the gateway, and drives a terminal session on it the way the
// embedded MeshCentral page does.
func TestAgentEndToEnd(t *testing.T) {
	image := os.Getenv("EASYRMM_TEST_AGENT_IMAGE")
	if image == "" {
		t.Fatal("EASYRMM_TEST_AGENT_IMAGE is not set (a glibc Linux image for the test agent; see the Makefile)")
	}
	r := newRig(t)
	acme := r.org("Acme")
	hq := r.site(acme.ID, "HQ")
	techID, tech := r.user("Tess Tech", rbac.Assignment{Role: rbac.RoleTechnician, OrganizationID: acme.ID, SiteID: hq.ID})
	r.reconcile()

	upstream, _ := url.Parse(r.env.URL)
	g, err := NewGateway(r.svc, GatewayConfig{Upstream: upstream, Secure: true, CacheTTL: 200 * time.Millisecond}, r.log)
	if err != nil {
		t.Fatal(err)
	}
	r.serveGateway(g)
	go r.svc.Run(r.ctx) // device events from MeshCentral refresh devices

	dir := r.agentFiles(r.meshOfSite(hq.ID))
	name := "easyrmm-testagent-" + uuid.NewString()[:8]
	docker(t, "run", "-d", "--name", name, "--network", "host",
		"--add-host", r.env.Hostname+":127.0.0.1",
		"--user", "65534:65534", "--read-only", "--tmpfs", "/tmp", "--cap-drop", "ALL",
		"--security-opt", "no-new-privileges", "-v", dir+":/agent", "-w", "/agent",
		image, "./meshagent", "connect")
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("agent output:\n%s", docker(t, "logs", "--tail", "50", name))
		}
		_, _ = exec.Command("docker", "rm", "-f", name).CombinedOutput()
	})

	// The agent connects through the gateway and its device appears.
	var dev *devices.Device
	r.waitFor(2*time.Minute, "the agent's device to come online", func() bool {
		list, err := r.dev.List(r.ctx, tech, devices.Query{Status: "online"})
		if err == nil && len(list) == 1 {
			dev = list[0]
		}
		return dev != nil
	})
	if dev.Platform != "linux" || !dev.RemoteAgent || !dev.CanTerminal || dev.Hostname == "" || dev.SiteID != hq.ID || dev.LastSeenAt == nil {
		t.Errorf("device = %+v", dev)
	}
	// What `meshagent -nodeid` prints is MeshCentral's node id once encoded
	// the way MeshCentral does; the EasyRMM agent reports it (ADR-0015).
	printed := docker(t, "exec", name, "./meshagent", "-nodeid")
	if key, err := agentproto.MeshNodeKey(printed); err != nil || key != dev.MeshNodeID {
		t.Errorf("meshagent -nodeid = %q, encoded %q (%v); MeshCentral's node id is %q", printed, key, err, dev.MeshNodeID)
	}

	// Open a terminal like MeshCentral's page does: an authenticated relay
	// connection, and a tunnel request over the control channel.
	sess := r.session(techID)
	l, err := r.svc.StartSession(r.ctx, tech, sess, dev.ID, KindTerminal)
	if err != nil {
		t.Fatal(err)
	}
	b := r.browser()
	r.open(b, l)
	ctl, err := r.dial(b, "/control.ashx")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ctl.CloseNow() }()
	readUntil(t, ctl, "userinfo", 15*time.Second)
	send(t, ctl, map[string]any{"action": "authcookie"})
	var ac struct{ Cookie, Rcookie string }
	raw, _ := json.Marshal(readUntil(t, ctl, "authcookie", 15*time.Second))
	_ = json.Unmarshal(raw, &ac)
	tunnel := hex.EncodeToString([]byte(uuid.NewString()[:8]))
	relay, err := r.dial(b, "/meshrelay.ashx?browser=1&p=1&nodeid="+dev.MeshNodeID+"&id="+tunnel+"&auth="+ac.Cookie)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = relay.CloseNow() }()
	send(t, ctl, map[string]any{
		"action": "msg", "type": "tunnel", "nodeid": dev.MeshNodeID, "usage": 1,
		"value": "*/meshrelay.ashx?p=1&nodeid=" + dev.MeshNodeID + "&id=" + tunnel + "&rauth=" + ac.Rcookie,
	})
	ctx, cancel := context.WithTimeout(r.ctx, 60*time.Second)
	defer cancel()
	for {
		typ, data, err := relay.Read(ctx)
		if err != nil {
			t.Fatalf("waiting for the agent to join the relay: %v", err)
		}
		if typ == websocket.MessageText && (string(data) == "c" || string(data) == "cr") {
			break
		}
	}
	_ = relay.Write(ctx, websocket.MessageText, []byte(`{"protocol":1,"cols":80,"rows":25,"xterm":true,"type":"options"}`))
	_ = relay.Write(ctx, websocket.MessageText, []byte("1"))
	var out strings.Builder
	sent := false
	for !strings.Contains(out.String(), "easyrmm-42") {
		typ, data, err := relay.Read(ctx)
		if err != nil {
			t.Fatalf("terminal output so far %q: %v", out.String(), err)
		}
		if typ != websocket.MessageBinary {
			continue
		}
		out.Write(data)
		if !sent {
			// The shell is up; the arithmetic proves it ran the command.
			if err := relay.Write(ctx, websocket.MessageBinary, []byte("echo easyrmm-$((6*7))\r")); err != nil {
				t.Fatal(err)
			}
			sent = true
		}
	}

	// Only EasyRMM's session types reach the agent: no TCP or UDP tunnels
	// to the device or its network, however they are asked for (ADR-0022).
	refusedDial := func(what string, c *http.Client, path string, origin bool) {
		t.Helper()
		opts := &websocket.DialOptions{HTTPClient: c}
		if origin {
			opts.HTTPHeader = http.Header{"Origin": {r.origin()}}
		}
		dctx, dcancel := context.WithTimeout(r.ctx, 15*time.Second)
		defer dcancel()
		ws, resp, err := websocket.Dial(dctx, "wss://"+r.env.Hostname+":"+strconv.Itoa(r.env.PublicPort)+path, opts)
		if resp != nil && resp.Body != nil {
			_ = resp.Body.Close()
		}
		if err == nil {
			_ = ws.CloseNow()
			t.Errorf("%s: connected", what)
		} else if resp == nil || resp.StatusCode != http.StatusForbidden {
			t.Errorf("%s: %v", what, err)
		}
	}
	refusedDial("relay with a TCP port", b, "/meshrelay.ashx?browser=1&p=1&nodeid="+dev.MeshNodeID+"&id=x1&tcpport=22&auth="+ac.Cookie, true)
	refusedDial("relay with a remote address", b, "/meshrelay.ashx?browser=1&p=1&nodeid="+dev.MeshNodeID+"&id=x2&tcpaddr=192.0.2.1&tcpport=445", true)
	refusedDial("relay for a device without a grant", b, "/meshrelay.ashx?browser=1&p=1&nodeid=node//easyrmmtestnogrant&id=x3&auth="+ac.Cookie, true)
	refusedDial("relay outside EasyRMM's session types", b, "/meshrelay.ashx?browser=1&p=10&nodeid="+dev.MeshNodeID+"&id=x4", true)
	refusedDial("desktop relay on a terminal grant", b, "/meshrelay.ashx?browser=1&p=2&nodeid="+dev.MeshNodeID+"&id=x7&auth="+ac.Cookie, true)
	refusedDial("files relay on a terminal grant", b, "/meshrelay.ashx?browser=1&p=5&nodeid="+dev.MeshNodeID+"&id=x8&auth="+ac.Cookie, true)
	// MeshCentral's query parser (qs) reads tcpport[] as tcpport.
	refusedDial("relay with a TCP port spelled as an array", b, "/meshrelay.ashx?browser=1&p=1&nodeid="+dev.MeshNodeID+"&id=x12&tcpport[]=22&auth="+ac.Cookie, true)
	// Without the browser's headers a request takes the agent path, where a
	// MeshCentral user cookie would have skipped the checks above.
	refusedDial("agent-path relay signed in as the user", r.browser(), "/meshrelay.ashx?p=1&nodeid="+dev.MeshNodeID+"&id=x5&tcpport=22&auth="+ac.Cookie, false)
	// The control channel closes on a request for a tunnel or a cookie that
	// encodes one, and on a tunnel request the session holds no grant for
	// or that names no device; the agent never hears of it.
	for _, cmd := range []map[string]any{
		{"action": "msg", "type": "tunnel", "nodeid": dev.MeshNodeID, "value": "*/meshrelay.ashx?id=x6&rauth=" + ac.Rcookie, "tcpport": 22},
		{"action": "getcookie", "nodeid": dev.MeshNodeID, "tcpport": 22, "tcpaddr": "127.0.0.1"},
		{"action": "msg", "type": "tunnel", "nodeid": dev.MeshNodeID, "usage": 2, "value": "*/meshrelay.ashx?p=2&nodeid=" + dev.MeshNodeID + "&id=x9&rauth=" + ac.Rcookie},
		{"action": "msg", "type": "tunnel", "nodeid": dev.MeshNodeID, "usage": 1, "value": "*/meshrelay.ashx?p=1&id=x10&rauth=" + ac.Rcookie},
		{"action": "msg", "type": "tunnel", "nodeid": dev.MeshNodeID, "usage": 1, "value": "*/meshrelay.ashx?p=1&nodeid=" + dev.MeshNodeID + "&id=" + tunnel + "x&tcpport[]=22&rauth=" + ac.Rcookie},
	} {
		c2, err := r.dial(b, "/control.ashx")
		if err != nil {
			t.Fatal(err)
		}
		readUntil(t, c2, "userinfo", 15*time.Second)
		send(t, c2, cmd)
		rctx, rcancel := context.WithTimeout(r.ctx, 10*time.Second)
		for {
			typ, data, err := c2.Read(rctx)
			if err != nil {
				if rctx.Err() != nil {
					t.Errorf("control channel still open after %v", cmd)
				}
				break
			}
			if typ == websocket.MessageText && strings.Contains(string(data), `"getcookie"`) {
				t.Errorf("MeshCentral answered a tunnel cookie request: %s", data)
			}
		}
		rcancel()
		_ = c2.CloseNow()
	}
	// MeshCentral routes any device message to the agent for a user with
	// remote control rights, and MeshAgent answers process lists, kills
	// processes and stops services without checking the session types. The
	// gateway drops them, and the channel stays open. (cpuinfo and
	// userSessions are answered on any Linux machine; ps needs procps, which
	// the test image lacks.)
	c3, err := r.dial(b, "/control.ashx")
	if err != nil {
		t.Fatal(err)
	}
	readUntil(t, c3, "userinfo", 15*time.Second)
	send(t, c3, map[string]any{"action": "msg", "type": "ps", "nodeid": dev.MeshNodeID})
	send(t, c3, map[string]any{"action": "msg", "type": "cpuinfo", "nodeid": dev.MeshNodeID})
	send(t, c3, map[string]any{"action": "msg", "type": "userSessions", "nodeid": dev.MeshNodeID})
	send(t, c3, map[string]any{"action": "msg", "type": "getclip", "nodeid": dev.MeshNodeID})
	time.Sleep(10 * time.Second) // the agent answers a process list in well under a second
	send(t, c3, map[string]any{"action": "authcookie"})
	actx, acancel := context.WithTimeout(r.ctx, 15*time.Second)
	for {
		typ, data, err := c3.Read(actx)
		if err != nil {
			t.Fatalf("control channel after dropped messages: %v", err)
		}
		if typ != websocket.MessageText {
			continue
		}
		if m := string(data); strings.Contains(m, `"action":"msg"`) && strings.Contains(m, `"type":"`) {
			t.Errorf("the agent answered a dropped message: %.200s", data)
		}
		if strings.Contains(string(data), `"action":"authcookie"`) {
			break
		}
	}
	acancel()
	_ = c3.CloseNow()

	// MeshAgent takes the session type from the browser's first relay
	// message: a terminal relay whose first message asks for a desktop is
	// closed before the agent reads it.
	sw := hex.EncodeToString([]byte(uuid.NewString()[:8]))
	swRelay, err := r.dial(b, "/meshrelay.ashx?browser=1&p=1&nodeid="+dev.MeshNodeID+"&id="+sw+"&auth="+ac.Cookie)
	if err != nil {
		t.Fatal(err)
	}
	send(t, ctl, map[string]any{
		"action": "msg", "type": "tunnel", "nodeid": dev.MeshNodeID, "usage": 1,
		"value": "*/meshrelay.ashx?p=1&nodeid=" + dev.MeshNodeID + "&id=" + sw + "&rauth=" + ac.Rcookie,
	})
	sctx, scancel := context.WithTimeout(r.ctx, 60*time.Second)
	for {
		typ, data, err := swRelay.Read(sctx)
		if err != nil {
			t.Fatalf("waiting for the agent to join the second relay: %v", err)
		}
		if typ == websocket.MessageText && (string(data) == "c" || string(data) == "cr") {
			break
		}
	}
	_ = swRelay.Write(sctx, websocket.MessageText, []byte("2"))
	for {
		typ, data, err := swRelay.Read(sctx)
		if err != nil {
			if sctx.Err() != nil {
				t.Error("terminal relay still open after asking for a desktop")
			}
			break
		}
		if typ == websocket.MessageBinary {
			t.Errorf("the agent sent %d bytes on a terminal relay that asked for a desktop", len(data))
			break
		}
	}
	scancel()
	_ = swRelay.CloseNow()

	// MeshCentral's web RDP relay (ADR-0026). The agent tunnels RDP to the
	// device's own port 3389; the test runs on the agent's network, so it
	// plays the device's RDP server and sees what arrives.
	rdpServer, err := net.Listen("tcp4", "127.0.0.1:3389")
	if err != nil {
		t.Fatalf("the RDP check plays an RDP server on 127.0.0.1:3389: %v", err)
	}
	defer func() { _ = rdpServer.Close() }()
	rdpArrived := make(chan []byte, 4)
	go func() {
		for {
			c, err := rdpServer.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = c.Close() }()
				_ = c.SetReadDeadline(time.Now().Add(30 * time.Second))
				head := make([]byte, 4)
				if _, err := io.ReadFull(c, head); err == nil {
					rdpArrived <- head
				}
			}()
		}
	}()
	// rdp opens the relay as MeshCentral's RDP client does and keeps it open
	// for wait: whether MeshCentral answered, and the first bytes that
	// reached the device's RDP port.
	rdp := func(wait time.Duration) (closed bool, head []byte) {
		t.Helper()
		ws, err := r.dial(b, "/mstscrelay.ashx")
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = ws.CloseNow() }()
		infos := `["infos",{"ip":"` + dev.MeshNodeID + `","port":3389,"screen":{"width":1024,"height":768},` +
			`"domain":"","username":"easyrmm","password":"test-only","options":{},"locale":"en-US"}]`
		wctx, wcancel := context.WithTimeout(r.ctx, wait)
		defer wcancel()
		if err := ws.Write(wctx, websocket.MessageText, []byte(infos)); err != nil {
			t.Fatal(err)
		}
		readErr := make(chan error, 1)
		go func() {
			for {
				if _, _, err := ws.Read(wctx); err != nil {
					readErr <- err
					return
				}
			}
		}()
		select {
		case head = <-rdpArrived:
		case err := <-readErr:
			closed = err != nil && wctx.Err() == nil
		case <-wctx.Done():
		}
		return closed, head
	}
	// The session holds a terminal grant only: the gateway closes the relay
	// and nothing reaches the device.
	if closed, head := rdp(10 * time.Second); !closed || head != nil {
		t.Errorf("RDP relay on a terminal grant: closed %v, device got %x", closed, head)
	}
	lr, err := r.svc.StartSession(r.ctx, tech, sess, dev.ID, KindRDP)
	if err != nil {
		t.Fatal(err)
	}
	r.open(b, lr)
	// With an RDP grant the RDP client's connection request (a TPKT header)
	// reaches the device's RDP port through MeshCentral and the agent.
	if _, head := rdp(45 * time.Second); len(head) != 4 || head[0] != 3 || head[1] != 0 {
		t.Errorf("RDP relay on an RDP grant: the device's RDP port got %x", head)
	}

	// A file download from the device (devicefile.ashx, as MeshCentral's
	// files view links it) needs a files session on the device. MeshCentral's
	// main port answers a plain GET with the user's MeshCentral cookie, so
	// without browser headers (the agent path) it is refused too.
	download := func(c *http.Client, browser bool) (int, string) {
		t.Helper()
		u := r.origin() + "/devicefile.ashx?c=" + url.QueryEscape(ac.Cookie) + "&m=x&n=" +
			strings.TrimPrefix(dev.MeshNodeID, "node//") + "&f=" + url.QueryEscape("/etc/hostname")
		req, _ := http.NewRequestWithContext(r.ctx, http.MethodGet, u, nil)
		if browser {
			req.Header.Set("Sec-Fetch-Mode", "cors")
			req.Header.Set("Sec-Fetch-Site", "same-origin")
		}
		resp, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		return resp.StatusCode, string(body)
	}
	hostname := strings.TrimSpace(docker(t, "exec", name, "cat", "/etc/hostname"))
	if code, body := download(r.browser(), false); code != http.StatusForbidden || strings.Contains(body, hostname) {
		t.Errorf("download on the agent path with a user's cookie: %d %.100q", code, body)
	}
	if code, body := download(b, true); code != http.StatusForbidden || strings.Contains(body, hostname) {
		t.Errorf("download on a terminal grant: %d %.100q", code, body)
	}
	lf, err := r.svc.StartSession(r.ctx, tech, sess, dev.ID, KindFiles)
	if err != nil {
		t.Fatal(err)
	}
	r.open(b, lf)
	// With a files grant the download works: MeshCentral asks the agent,
	// which sends the file over its own devicefile.ashx connection.
	if code, body := download(b, true); code != http.StatusOK || strings.TrimSpace(body) != hostname {
		t.Errorf("download on a files grant: %d %.100q, want %q", code, body, hostname)
	}

	// The terminal itself is unaffected.
	if err := relay.Write(ctx, websocket.MessageBinary, []byte("echo still-$((2*21))\r")); err != nil {
		t.Fatal(err)
	}
	for !strings.Contains(out.String(), "still-42") {
		typ, data, err := relay.Read(ctx)
		if err != nil {
			t.Fatalf("terminal after the refusals %q: %v", out.String(), err)
		}
		if typ == websocket.MessageBinary {
			out.Write(data)
		}
	}

	// Signing out of EasyRMM closes the terminal.
	r.revoke(sess)
	g.sweep(r.ctx)
	for {
		if _, _, err := relay.Read(ctx); err != nil {
			if ctx.Err() != nil {
				t.Fatal("terminal still open after its session was revoked")
			}
			break
		}
	}

	// Losing remote access removes the MeshCentral account.
	r.exec(`DELETE FROM role_assignments WHERE user_id = $1`, techID)
	r.reconcile()
	if _, ok := r.accounts()[accountID(techID)]; ok {
		t.Error("account kept after the user lost remote access")
	}

	// "meshagent connect" runs a temporary agent, which MeshCentral forgets
	// when it disconnects; the device leaves EasyRMM with it.
	docker(t, "stop", "-t", "2", name)
	deadline := time.Now().Add(time.Minute)
	for {
		_, err := r.dev.Get(r.ctx, r.sys, dev.ID)
		if errors.Is(err, apperr.ErrNotFound) {
			break
		}
		if time.Now().After(deadline) {
			nodes, nerr := r.mesh.Nodes(r.ctx)
			t.Fatalf("device kept a minute after its temporary agent stopped: %v; MeshCentral nodes %+v %v", err, nodes, nerr)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

func TestSecretsPersistAndReseal(t *testing.T) {
	inst := testdb.New(t)
	ctx := context.Background()
	key := func(id string) secrets.Key {
		raw := make([]byte, 32)
		_, _ = rand.Read(raw)
		return secrets.Key{ID: id, Raw: raw}
	}
	k1, k2 := key("k1"), key("k2")
	s1, _ := secrets.NewSealer(k1)
	first, err := LoadSecrets(ctx, inst.DB, s1)
	if err != nil {
		t.Fatal(err)
	}
	if len(first.LoginKey) != meshcentral.KeySize || len(first.SessionKey) < 32 {
		t.Fatalf("secrets = %d-byte key, %d-char session key", len(first.LoginKey), len(first.SessionKey))
	}
	var stored string
	read := func() {
		t.Helper()
		if err := inst.DB.ReadTx(ctx, database.System, func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT value::text FROM settings WHERE key = 'meshcentral.secrets'`).Scan(&stored)
		}); err != nil {
			t.Fatal(err)
		}
	}
	read()
	if strings.Contains(stored, meshcentral.KeyHex(first.LoginKey)) || strings.Contains(stored, first.SessionKey) {
		t.Fatal("secrets stored in the clear")
	}
	again, err := LoadSecrets(ctx, inst.DB, s1)
	if err != nil || !bytes.Equal(again.LoginKey, first.LoginKey) || again.SessionKey != first.SessionKey {
		t.Fatalf("second load returned different secrets (%v)", err)
	}

	// Rotating the server key reseals them with the new key.
	rotated, _ := secrets.NewSealer(k2, k1)
	if got, err := LoadSecrets(ctx, inst.DB, rotated); err != nil || !bytes.Equal(got.LoginKey, first.LoginKey) {
		t.Fatalf("load after rotation: %v", err)
	}
	onlyNew, _ := secrets.NewSealer(k2)
	if _, err := LoadSecrets(ctx, inst.DB, onlyNew); err != nil {
		t.Fatalf("resealed secrets do not open with the new key alone: %v", err)
	}
	if _, err := LoadSecrets(ctx, inst.DB, s1); err == nil || !strings.Contains(err.Error(), "EASYRMM_SECRET_KEYS_PREVIOUS") {
		t.Fatalf("load with a forgotten key = %v", err)
	}
}

func TestReconcileRecreatesDeletedGroup(t *testing.T) {
	r := newRig(t)
	hq := r.site(r.org("Acme").ID, "HQ")
	r.reconcile()
	old := r.meshOfSite(hq.ID)
	// Someone deletes the group in MeshCentral directly.
	if err := r.mesh.DeleteMesh(r.ctx, old); err != nil {
		t.Fatal(err)
	}
	r.reconcile()
	if now := r.meshOfSite(hq.ID); now == old {
		t.Fatal("site still mapped to the deleted group")
	} else if _, ok := r.meshes()[now]; !ok {
		t.Fatal("replacement group missing")
	}
}

func tenancyName(name string) tenancy.OrganizationInput { return tenancy.OrganizationInput{Name: name} }
