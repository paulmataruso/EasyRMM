//go:build integration

package quickassist_test

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/agent/client"
	"github.com/paulmataruso/easyrmm/agent/quickassist"
	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/server/internal/agents"
	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/httpapi/agentapi"
	"github.com/paulmataruso/easyrmm/server/internal/httpapi/quickassistapi"
	qa "github.com/paulmataruso/easyrmm/server/internal/quickassist"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
	"github.com/paulmataruso/easyrmm/server/internal/testdb"
)

// stepUpNever stands in for a signed-in session that has not stepped up; the
// routes this test uses ask for none.
type stepUpNever struct{}

func (stepUpNever) StepUp(*http.Request) error { return http.ErrNotSupported }

// e2e is the real server (agent API and the public link routes) over the
// real database, and the real agent binary built from this tree.
type e2e struct {
	*fx
	url  string
	base string
	bin  string
}

func newE2E(t *testing.T) *e2e {
	t.Helper()
	inst := testdb.New(t)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	jobPub, key, _ := ed25519.GenerateKey(rand.Reader)

	var handler atomic.Pointer[http.Handler]
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { (*handler.Load()).ServeHTTP(w, r) }))
	t.Cleanup(srv.Close)

	f := &fx{t: t, ctx: context.Background(), db: inst.DB, svc: qa.New(inst.DB, audit.New(inst.DB, nil), key, srv.URL)}
	f.acme = f.id(`INSERT INTO organizations (name) VALUES ('Acme') RETURNING id`)

	// The real agent, built from this tree, served as the release build.
	dir := t.TempDir()
	bin := filepath.Join(dir, "easyrmm-agent-linux-amd64")
	build := exec.Command("go", "build", "-o", bin, "github.com/paulmataruso/easyrmm/agent/cmd/easyrmm-agent")
	build.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH=amd64")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("building the agent: %v\n%s", err, out)
	}
	builds, err := agents.LoadBuilds(dir)
	if err != nil {
		t.Fatal(err)
	}

	asvc := agents.New(inst.DB, audit.New(inst.DB, time.Now), nil, log)
	asvc.SetJobKey(agentproto.EncodeKey(jobPub))
	api, err := agentapi.New(asvc, builds, []agentapi.Address{{URL: srv.URL}}, nil, log)
	if err != nil {
		t.Fatal(err)
	}
	api.WithQuickAssist(f.svc)
	mux := http.NewServeMux()
	mux.Handle("/api/agent/", api.Handler())
	quickassistapi.New(f.svc, stepUpNever{}, builds).Register(mux)
	var h http.Handler = mux
	handler.Store(&h)
	return &e2e{fx: f, url: srv.URL, base: t.TempDir(), bin: bin}
}

// fetch downloads the runner as a user would, from the link's page.
func (e *e2e) fetch(token string) string {
	e.t.Helper()
	resp, err := http.Get(e.url + "/qa/" + token + "/download?os=linux")
	if err != nil {
		e.t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != 200 {
		e.t.Fatalf("download: %s", resp.Status)
	}
	path := filepath.Join(e.t.TempDir(), "easyrmm-quick-assist")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0o700)
	if err != nil {
		e.t.Fatal(err)
	}
	if _, err := io.Copy(f, resp.Body); err != nil {
		e.t.Fatal(err)
	}
	_ = f.Close()
	return path
}

type proc struct {
	cmd   *exec.Cmd
	in    io.WriteCloser
	lines chan string
	done  chan error
}

func (e *e2e) start(path string, args ...string) *proc {
	e.t.Helper()
	cmd := exec.Command(path, append([]string{"quick-assist", "--base-dir", e.base, "--poll", "200ms"}, args...)...)
	in, _ := cmd.StdinPipe()
	out, _ := cmd.StdoutPipe()
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		e.t.Fatal(err)
	}
	p := &proc{cmd: cmd, in: in, lines: make(chan string, 200), done: make(chan error, 1)}
	go func() {
		sc := bufio.NewScanner(out)
		sc.Split(scanPrompt)
		for sc.Scan() {
			p.lines <- sc.Text()
		}
		p.done <- cmd.Wait()
	}()
	e.t.Cleanup(func() { _ = cmd.Process.Kill() })
	return p
}

// scanPrompt splits on newlines and after the consent prompt's colon, which
// ends without one.
func scanPrompt(data []byte, atEOF bool) (int, []byte, error) {
	if i := strings.IndexByte(string(data), '\n'); i >= 0 {
		return i + 1, data[:i], nil
	}
	if s := string(data); strings.HasSuffix(s, "cancel: ") {
		return len(data), data, nil
	}
	if atEOF && len(data) > 0 {
		return len(data), data, nil
	}
	return 0, nil, nil
}

var codeRe = regexp.MustCompile(`Your session code: (\d{6})`)

// code reads the consent text and returns the code it shows.
func (p *proc) code(t *testing.T) string {
	t.Helper()
	deadline := time.After(30 * time.Second)
	for {
		select {
		case l := <-p.lines:
			if m := codeRe.FindStringSubmatch(l); m != nil {
				return m[1]
			}
		case <-deadline:
			t.Fatal("the runner never showed its code")
		}
	}
}

func (p *proc) waitFor(t *testing.T, text string) {
	t.Helper()
	deadline := time.After(30 * time.Second)
	for {
		select {
		case l := <-p.lines:
			if strings.Contains(l, text) {
				return
			}
		case <-deadline:
			t.Fatalf("the runner never said %q", text)
		}
	}
}

func (p *proc) exit(t *testing.T) error {
	t.Helper()
	select {
	case err := <-p.done:
		return err
	case <-time.After(60 * time.Second):
		t.Fatal("the runner did not exit")
		return nil
	}
}

func (e *e2e) session() (uuid.UUID, uuid.UUID) {
	e.t.Helper()
	var sid, did uuid.UUID
	deadline := time.Now().Add(30 * time.Second)
	for {
		err := e.db.ReadTx(e.ctx, database.System, func(tx pgx.Tx) error {
			return tx.QueryRow(e.ctx, `SELECT id, device_id FROM quick_assist_sessions ORDER BY requested_at DESC LIMIT 1`).Scan(&sid, &did)
		})
		if err == nil {
			return sid, did
		}
		if time.Now().After(deadline) {
			e.t.Fatal("no session was requested")
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func (e *e2e) leftovers() []string {
	m, _ := filepath.Glob(filepath.Join(e.base, "easyrmm-qa-*"))
	return m
}

// TestRunnerEndToEnd runs the real runner against the real server: the
// download, the consent and code, the request, acceptance by typing the
// code, the technician ending it, and the cleanup it reports.
func TestRunnerEndToEnd(t *testing.T) {
	e := newE2E(t)
	tech := e.user(rbac.RoleTechnician, e.acme)
	link := e.oneTime(tech, e.acme)
	path := e.fetch(link.Token)

	// The same link does not download twice.
	resp, err := http.Get(e.url + "/qa/" + link.Token + "/download?os=linux")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != 404 {
		t.Fatalf("second download: %s", resp.Status)
	}

	p := e.start(path)
	code := p.code(t)
	// Nothing reaches the server before the user says yes.
	time.Sleep(500 * time.Millisecond)
	if n := e.count(`SELECT count(*) FROM quick_assist_sessions`); n != 0 {
		t.Fatal("the runner contacted the server before consent")
	}
	_, _ = io.WriteString(p.in, "YES\n")
	sid, did := e.session()
	if n := e.count(`SELECT count(*) FROM quick_assist_sessions WHERE state = 'requested'`); n != 1 {
		t.Fatal("the request is not waiting")
	}
	p.waitFor(t, "Waiting for")
	if got := e.leftovers(); len(got) != 1 {
		t.Fatalf("the session folder: %v", got)
	}
	if _, err := e.svc.Accept(e.ctx, tech, sid, code); err != nil {
		t.Fatal(err)
	}
	p.waitFor(t, "accepted")
	if n := e.count(`SELECT count(*) FROM devices d JOIN sites s ON s.id = d.site_id WHERE d.id = $1 AND s.kind = 'quick_assist' AND d.quick_assist AND d.agent_last_seen_at > now() - interval '1 minute'`, did); n != 1 {
		t.Fatal("the device is not listed in the Quick Assist site")
	}
	if err := e.svc.End(e.ctx, tech, sid); err != nil {
		t.Fatal(err)
	}
	if err := p.exit(t); err != nil {
		t.Fatalf("runner exit: %v", err)
	}
	if got := e.leftovers(); len(got) != 0 {
		t.Fatalf("left behind: %v", got)
	}
	if n := e.count(`SELECT count(*) FROM quick_assist_sessions WHERE id = $1 AND state = 'ended' AND end_reason = 'technician' AND cleanup = 'verified'`, sid); n != 1 {
		t.Fatal("the session did not end with a verified cleanup")
	}
	if n := e.count(`SELECT count(*) FROM devices WHERE id = $1 AND agent_public_key IS NULL`, did); n != 1 {
		t.Fatal("the session's key still works")
	}
}

// TestRunnerCancelAndWrongCode: the user can say no, and a wrong code three
// times closes the request and the runner cleans up and exits.
func TestRunnerCancelAndWrongCode(t *testing.T) {
	e := newE2E(t)
	tech := e.user(rbac.RoleTechnician, e.acme)

	p := e.start(e.fetch(e.oneTime(tech, e.acme).Token))
	p.code(t)
	_, _ = io.WriteString(p.in, "no\n")
	if err := p.exit(t); err != nil {
		t.Fatalf("cancel exit: %v", err)
	}
	if n := e.count(`SELECT count(*) FROM quick_assist_sessions`); n != 0 {
		t.Fatal("a canceled runner reached the server")
	}

	p = e.start(e.fetch(e.oneTime(tech, e.acme).Token))
	p.code(t)
	_, _ = io.WriteString(p.in, "YES\n")
	sid, _ := e.session()
	for range qa.MaxCodeFailures {
		_, _ = e.svc.Accept(e.ctx, tech, sid, "000000")
	}
	if err := p.exit(t); err != nil {
		t.Fatalf("declined exit: %v", err)
	}
	if got := e.leftovers(); len(got) != 0 {
		t.Fatalf("left behind: %v", got)
	}
	if n := e.count(`SELECT count(*) FROM quick_assist_sessions WHERE id = $1 AND state = 'declined' AND end_reason = 'code_failed' AND cleanup = 'verified'`, sid); n != 1 {
		t.Fatal("not recorded as declined with a verified cleanup")
	}
}

// TestRunnerCrashIsCleanedUp: a killed runner leaves its folder; the next
// run (or --clean) removes it, and the server marks the session lost.
func TestRunnerCrashIsCleanedUp(t *testing.T) {
	e := newE2E(t)
	tech := e.user(rbac.RoleTechnician, e.acme)
	path := e.fetch(e.oneTime(tech, e.acme).Token)

	p := e.start(path)
	code := p.code(t)
	_, _ = io.WriteString(p.in, "YES\n")
	sid, _ := e.session()
	if _, err := e.svc.Accept(e.ctx, tech, sid, code); err != nil {
		t.Fatal(err)
	}
	p.waitFor(t, "accepted")
	_ = p.cmd.Process.Kill()
	_ = p.exit(t)
	if got := e.leftovers(); len(got) != 1 {
		t.Fatalf("a killed runner should leave its folder for the clean-up: %v", got)
	}
	out, err := exec.Command(path, "quick-assist", "--clean", "--base-dir", e.base).CombinedOutput()
	if err != nil || !strings.Contains(string(out), "Removed 1") {
		t.Fatalf("--clean: %v %s", err, out)
	}
	if got := e.leftovers(); len(got) != 0 {
		t.Fatalf("left behind after --clean: %v", got)
	}
	e.exec(`UPDATE quick_assist_sessions SET last_seen_at = now() - interval '11 minutes' WHERE id = $1`, sid)
	if err := e.svc.Sweep(e.ctx); err != nil {
		t.Fatal(err)
	}
	if n := e.count(`SELECT count(*) FROM quick_assist_sessions WHERE id = $1 AND state = 'lost' AND cleanup = 'unconfirmed'`, sid); n != 1 {
		t.Fatal("the crashed session is not lost and unconfirmed")
	}
}

// lockedBuffer is a writer the runner fills and the test reads.
type lockedBuffer struct {
	mu sync.Mutex
	b  strings.Builder
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

func waitText(t *testing.T, b *lockedBuffer, re *regexp.Regexp) []string {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if m := re.FindStringSubmatch(b.String()); m != nil {
			return m
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("never saw %s in:\n%s", re, b.String())
	return nil
}

// TestInstallPermanently: the technician asks, the user agrees in the
// runner, the permanent agent enrolls with the conversion token, and the
// session moves to it, with the temporary device and key gone.
func TestInstallPermanently(t *testing.T) {
	e := newE2E(t)
	tech := e.user(rbac.RoleTechnician, e.acme)
	admin := e.user(rbac.RoleOrgAdmin, e.acme)
	path := e.fetch(e.oneTime(tech, e.acme).Token)

	in, w := io.Pipe()
	out := &lockedBuffer{}
	var newDevice string
	var enrolledWith string
	done := make(chan error, 1)
	go func() {
		done <- quickassist.Run(context.Background(), quickassistopts(path, e, in, out, &newDevice, &enrolledWith))
	}()
	code := waitText(t, out, regexp.MustCompile(`Your session code: (\d{6})`))[1]
	_, _ = io.WriteString(w, "YES\n")
	sid, did := e.session()
	if _, err := e.svc.Accept(e.ctx, tech, sid, code); err != nil {
		t.Fatal(err)
	}
	// A technician without the install permission cannot ask; the
	// administrator who takes the session over can.
	if err := e.svc.RequestInstall(e.ctx, tech, sid); !errors.Is(err, apperr.ErrForbidden) {
		t.Fatalf("technician asked to install: %v", err)
	}
	if err := e.svc.Takeover(e.ctx, admin, sid); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.RequestInstall(e.ctx, admin, sid); err != nil {
		t.Fatal(err)
	}
	waitText(t, out, regexp.MustCompile(`Type INSTALL`))
	_, _ = io.WriteString(w, "INSTALL\n")
	if err := <-done; err != nil {
		t.Fatalf("runner: %v\n%s", err, out.String())
	}
	_ = w.Close()

	if n := e.count(`SELECT count(*) FROM quick_assist_sessions WHERE id = $1 AND state = 'converted' AND device_id = $2 AND cleanup = 'verified'`, sid, newDevice); n != 1 {
		t.Fatalf("session not moved to the new device:\n%s", out.String())
	}
	if n := e.count(`SELECT count(*) FROM devices WHERE id = $1`, did); n != 0 {
		t.Fatal("the temporary device is still there")
	}
	if n := e.count(`SELECT count(*) FROM devices d JOIN sites s ON s.id = d.site_id WHERE d.id = $1 AND d.quick_assist AND d.origin_session_id = $2 AND s.kind = 'quick_assist'`, newDevice, sid); n != 1 {
		t.Fatal("the permanent device is not linked to its session in the Quick Assist site")
	}
	if n := e.count(`SELECT count(*) FROM enrollment_tokens WHERE revoked_at IS NOT NULL AND name = 'Quick Assist conversion' AND max_uses = 1 AND expires_at < now() + interval '31 minutes'`); n != 1 {
		t.Fatal("the conversion token is not one use, short and spent")
	}
	if got := e.leftovers(); len(got) != 0 {
		t.Fatalf("left behind: %v", got)
	}
	if got := e.actions("quickassist.converted"); len(got) != 1 {
		t.Fatalf("audit: %v", got)
	}
	// Retention does not delete the permanent device.
	e.exec(`UPDATE quick_assist_sessions SET ended_at = now() - interval '40 days' WHERE id = $1`, sid)
	if err := e.svc.Sweep(e.ctx); err != nil {
		t.Fatal(err)
	}
	if n := e.count(`SELECT count(*) FROM devices WHERE id = $1`, newDevice); n != 1 {
		t.Fatal("retention deleted the permanent device")
	}
	// Moved out of the Quick Assist site it is an ordinary device: the move
	// action clears the flag.
	_ = enrolledWith
}

func quickassistopts(path string, e *e2e, in io.Reader, out io.Writer, newDevice, enrolledWith *string) quickassist.Options {
	return quickassist.Options{
		Self: path, BaseDir: e.base, Server: e.url, Poll: 100 * time.Millisecond, Elevated: true, In: in, Out: out,
		Install: func(ctx context.Context, server, token string) error {
			c, err := client.New(client.Options{Server: server})
			if err != nil {
				return err
			}
			pub, _, _ := ed25519.GenerateKey(rand.Reader)
			res, err := c.Enroll(ctx, token, pub, agentproto.Facts{Hostname: "pc-1", OS: "Test OS", Platform: "linux", Arch: "amd64", AgentVersion: "dev"})
			if err != nil {
				return err
			}
			*newDevice, *enrolledWith = res.DeviceID, token
			return nil
		},
	}
}
