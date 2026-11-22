//go:build integration

package easypatch

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/database"
)

// logBuffer is a log that tests read while services write it.
type logBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *logBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *logBuffer) count(s string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return strings.Count(l.b.String(), s)
}

// One of EasyRMM's servers gives the engine its mail server; the others,
// whose mail servers differ, do not give it theirs in turn, but say so,
// once per change, in the log and on Settings → Patching, comparing a
// digest in the database, never the mail server. When the server that
// gives it stops, another takes over at its next pass.
func TestOneServerGivesTheEngineItsMailServer(t *testing.T) {
	f := newFleetFixture(t)
	ctx := f.ctx
	a := MailConfig{Host: "smtp-a.example.com", Port: 587, Username: "rmm", Password: "pw-a", FromAddress: "rmm@example.com", Security: "starttls"}
	b := a
	b.Password = "pw-b" // only the password differs
	c := MailConfig{Host: "smtp-c.example.com", Port: 465, Username: "rmm", Password: "pw-c", FromAddress: "rmm@example.com", Security: "tls"}
	var mu sync.Mutex
	inForce := map[string]MailConfig{"one": a, "two": b}
	set := func(server string, cfg MailConfig) {
		mu.Lock()
		inForce[server] = cfg
		mu.Unlock()
	}
	source := func(server string) EngineOption {
		return Mail(func(context.Context) (MailConfig, error) {
			mu.Lock()
			defer mu.Unlock()
			return inForce[server], nil
		}, mailKey)
	}
	var logOne, logTwo logBuffer
	one := f.engineServiceLog(f.engine, slog.New(slog.NewTextHandler(&logOne, nil)), source("one"))
	two := f.engineServiceLog(f.engine, slog.New(slog.NewTextHandler(&logTwo, nil)), source("two"))
	t.Cleanup(one.stopLeadingMail)
	t.Cleanup(two.stopLeadingMail)
	pass := func(s *Service) {
		t.Helper()
		var res ReconcileResult
		s.syncMail(ctx, s.engine.client, &res)
		if len(res.Problems) > 0 {
			t.Fatal(res.Problems)
		}
	}
	holds := func(step string, cfg MailConfig) {
		t.Helper()
		if m := f.engine.Mail(); m["smtpHost"] != cfg.Host || m["smtpPassword"] != cfg.Password {
			t.Fatalf("%s: the engine holds %v, want %s", step, m, cfg.Host)
		}
	}
	problem := func(s *Service) string {
		t.Helper()
		v, err := s.Notifications(ctx, f.admin)
		if err != nil {
			t.Fatal(err)
		}
		return v.Mail.Problem
	}
	puts := func() int { return len(f.engine.RequestsTo("PUT", mailSettingsPath)) }
	const differs = "level=ERROR msg=\"patching: This server's mail server"

	pass(one)
	holds("the first server's pass", a)
	before := puts()
	for range 3 {
		pass(two)
		pass(one)
	}
	if n := puts() - before; n != 0 {
		t.Fatalf("the servers gave the engine their mail servers %d times in turn", n)
	}
	holds("after both servers' passes", a)
	if logTwo.count(differs) != 1 || problem(two) != mailDiffers || problem(one) != "" || logOne.count("level=ERROR") != 0 {
		t.Fatalf("the second server: %q, logged %d times", problem(two), logTwo.count(differs))
	}

	// The webhook switch changed on the second server keeps the engine's
	// mail server, its password included, and the first finds nothing to
	// repair.
	if v, err := two.SetNotificationSettings(ctx, f.admin, NotificationSettings{AllowPrivateNetworkWebhooks: true}); err != nil || !v.AllowPrivateNetworkWebhooks {
		t.Fatalf("the switch on the second server: %+v, %v", v, err)
	}
	holds("the switch on the second server", a)
	if r := f.engine.RequestsTo("PUT", mailSettingsPath); len(r) != before+1 {
		t.Fatalf("%d pushes for the switch", len(r)-before)
	} else if r[len(r)-1].Body["smtpPassword"] != nil {
		t.Fatal("the second server's switch sent a password")
	}
	pass(one)
	if puts() != before+1 {
		t.Fatal("the first server gave the engine its mail server again after the switch")
	}
	if m := f.engine.Mail(); m["allowPrivateNetworkWebhooks"] != true {
		t.Fatalf("the switch is lost: %v", m)
	}

	// The database holds a keyed digest, never the mail server: without the
	// key, the password cannot be guessed from it.
	var digest []byte
	if err := f.db.ReadTx(ctx, database.System, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT digest FROM mail_engine_given`).Scan(&digest)
	}); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(mailDigest(a, mailKey), digest) || bytes.Equal(mailDigest(b, mailKey), digest) ||
		bytes.Equal(mailDigest(a, bytes.Repeat([]byte{8}, 32)), digest) || bytes.Contains(digest, []byte("pw-a")) {
		t.Fatal("the record is not a keyed digest of the mail server given")
	}

	// The second server's put right: it says so, once.
	set("two", a)
	pass(two)
	pass(two)
	if problem(two) != "" || logTwo.count("is the one the patching engine was given again") != 1 {
		t.Fatalf("put right: %q", problem(two))
	}

	// The first server's changes: the second, with the old one, says so.
	set("one", c)
	pass(one)
	holds("a change on the first server", c)
	pass(two)
	pass(two)
	if logTwo.count(differs) != 2 || problem(two) != mailDiffers {
		t.Fatalf("after a change on the first server: logged %d times", logTwo.count(differs))
	}

	// The first server stops: the second takes over at its next pass and
	// gives the engine its own.
	one.stopLeadingMail()
	set("two", b)
	pass(two)
	holds("taken over", b)
	if problem(two) != "" {
		t.Fatalf("the server that gives it: %q", problem(two))
	}
	// Back, the first follows, and says its own differs.
	before = puts()
	pass(one)
	pass(one)
	if puts() != before || problem(one) != mailDiffers || logOne.count(differs) != 1 {
		t.Fatalf("the first server back: %d pushes, %q", puts()-before, problem(one))
	}
	holds("the first server back", b)
}

// The lock on the engine's mail settings is taken with the request's
// context: a request does not wait for it past its end.
func TestMailLockFollowsTheRequest(t *testing.T) {
	f := newFleetFixture(t)
	cfg := MailConfig{Host: "smtp.example.com", Port: 587, Username: "rmm", Password: "pw", FromAddress: "rmm@example.com", Security: "starttls"}
	f.svc = f.engineService(f.engine, Mail(func(context.Context) (MailConfig, error) { return cfg, nil }, mailKey))
	f.reconcile()
	e := f.svc.engine
	if err := e.lockMail(f.ctx); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(f.ctx, 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := f.svc.SetNotificationSettings(ctx, f.admin, NotificationSettings{AllowPrivateNetworkWebhooks: true}); !errors.Is(err, context.DeadlineExceeded) ||
		time.Since(start) > 5*time.Second {
		t.Fatalf("the switch, the lock held: %v after %s", err, time.Since(start))
	}
	var res ReconcileResult
	f.svc.syncMail(ctx, e.client, &res)
	if len(res.Problems) != 1 {
		t.Fatalf("a pass, the lock held: %v", res.Problems)
	}
	e.unlockMail()
	if v, err := f.svc.SetNotificationSettings(f.ctx, f.admin, NotificationSettings{AllowPrivateNetworkWebhooks: true}); err != nil || !v.AllowPrivateNetworkWebhooks {
		t.Fatalf("the switch, the lock free: %+v, %v", v, err)
	}
}

// An engine that does not answer holds the lock on its mail settings for
// mailTimeout a call, not as long as the client would wait.
func TestHungEngineReleasesTheMailLock(t *testing.T) {
	f := newFleetFixture(t)
	cfg := MailConfig{Host: "smtp.example.com", Port: 587, Username: "rmm", Password: "pw", FromAddress: "rmm@example.com", Security: "starttls"}
	f.svc = f.engineService(f.engine, Mail(func(context.Context) (MailConfig, error) { return cfg, nil }, mailKey))
	f.reconcile()
	e := f.svc.engine
	if e.mailTimeout != 10*time.Second {
		t.Fatalf("each call is bounded at %s, want 10s", e.mailTimeout)
	}
	e.mailTimeout = 300 * time.Millisecond
	hang := func(method string) {
		f.engine.Set(func() {
			f.engine.Hang = func(m, path string) bool { return path == mailSettingsPath && (method == "" || m == method) }
		})
	}
	quick := func(step string, call func() error) {
		t.Helper()
		start := time.Now()
		if err := call(); err == nil || time.Since(start) > 5*time.Second {
			t.Fatalf("%s: %v after %s", step, err, time.Since(start))
		}
	}
	toggle := func() error {
		_, err := f.svc.SetNotificationSettings(f.ctx, f.admin, NotificationSettings{AllowPrivateNetworkWebhooks: true})
		return err
	}
	pass := func() error {
		var res ReconcileResult
		f.svc.syncMail(f.ctx, e.client, &res)
		if len(res.Problems) == 0 {
			return nil
		}
		return errors.New(res.Problems[0])
	}
	hang("GET")
	quick("the switch, reading hangs", toggle)
	quick("a pass, reading hangs", pass)
	hang("PUT")
	quick("the switch, writing hangs", toggle)
	f.engine.Set(func() { f.engine.Hang = nil })
	if err := toggle(); err != nil {
		t.Fatal(err)
	}
	if m := f.engine.Mail(); m["allowPrivateNetworkWebhooks"] != true || m["smtpHost"] != cfg.Host {
		t.Fatalf("answering again: %v", m)
	}
}

// The webhook switch goes ahead when EasyRMM's mail server cannot be read
// (a password sealed with another key, or the database for a moment): it
// leaves the engine's mail server as it is, never removes it, and
// Settings → Patching says why; the first pass that can read it gives it
// again.
func TestWebhookSwitchWithAnUnreadableMailServer(t *testing.T) {
	f := newFleetFixture(t)
	cfg := MailConfig{Host: "smtp.example.com", Port: 587, Username: "rmm", Password: "pw", FromAddress: "rmm@example.com", Security: "starttls"}
	var readErr error
	f.svc = f.engineService(f.engine, Mail(func(context.Context) (MailConfig, error) { return cfg, readErr }, mailKey))
	f.reconcile()
	readErr = errors.New("the stored password cannot be opened")
	v, err := f.svc.SetNotificationSettings(f.ctx, f.admin, NotificationSettings{AllowPrivateNetworkWebhooks: true})
	if err != nil || !v.AllowPrivateNetworkWebhooks || v.Mail.Host != cfg.Host || !strings.Contains(v.Mail.Problem, "the stored password cannot be opened") {
		t.Fatalf("the switch: %+v, %v", v, err)
	}
	if m := f.engine.Mail(); m["allowPrivateNetworkWebhooks"] != true || m["smtpHost"] != cfg.Host || m["smtpPassword"] != cfg.Password {
		t.Fatalf("the engine: %v", m)
	}
	if r := f.engine.RequestsTo("PUT", mailSettingsPath); r[len(r)-1].Body["smtpPassword"] != nil {
		t.Fatal("the switch sent a password it could not read")
	}
	if a := f.audits("patch.notifications_update"); len(a) != 1 {
		t.Fatalf("audit: %+v", a)
	}
	readErr = nil
	f.reconcile()
	if m := f.engine.Mail(); m["allowPrivateNetworkWebhooks"] != true || m["smtpHost"] != cfg.Host || m["smtpPassword"] != cfg.Password {
		t.Fatalf("given again: %v", m)
	}
	if v, err := f.svc.Notifications(f.ctx, f.admin); err != nil || v.Mail.Problem != "" {
		t.Fatalf("the problem stays: %+v, %v", v.Mail, err)
	}
}

// When the connection that holds the lead drops, its server stops giving
// the engine its mail server, and another takes over at its next pass.
func TestAnotherServerTakesOverTheEngineMail(t *testing.T) {
	f := newFleetFixture(t)
	ctx := f.ctx
	a := MailConfig{Host: "smtp-a.example.com", Port: 587, Username: "rmm", Password: "pw-a", FromAddress: "rmm@example.com", Security: "starttls"}
	b := a
	b.Host = "smtp-b.example.com"
	one := f.engineService(f.engine, Mail(func(context.Context) (MailConfig, error) { return a, nil }, mailKey))
	two := f.engineService(f.engine, Mail(func(context.Context) (MailConfig, error) { return b, nil }, mailKey))
	t.Cleanup(one.stopLeadingMail)
	t.Cleanup(two.stopLeadingMail)
	pass := func(s *Service) {
		t.Helper()
		var res ReconcileResult
		s.syncMail(ctx, s.engine.client, &res)
		if len(res.Problems) > 0 {
			t.Fatal(res.Problems)
		}
	}
	pass(one)
	pass(two)
	if m := f.engine.Mail(); m["smtpHost"] != a.Host {
		t.Fatalf("the first server's: %v", m)
	}
	super, err := pgx.Connect(ctx, f.superDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer super.Close(ctx)
	var ended bool
	if err := super.QueryRow(ctx, `SELECT pg_terminate_backend(pid) FROM pg_locks
		WHERE locktype = 'advisory' AND granted AND (classid::bigint << 32 | objid::bigint) = $1`, int64(lockEngineMail)).Scan(&ended); err != nil || !ended {
		t.Fatalf("ending the leader's connection: %v %v", ended, err)
	}
	start := time.Now()
	for f.engine.Mail()["smtpHost"] != b.Host {
		if time.Since(start) > 10*time.Second {
			t.Fatal("the second server did not take over")
		}
		pass(two)
		time.Sleep(50 * time.Millisecond)
	}
	// The first, its connection gone, follows, and says its own differs.
	pass(one)
	if m := f.engine.Mail(); m["smtpHost"] != b.Host {
		t.Fatalf("the first server took it back: %v", m)
	}
	if v, err := one.Notifications(ctx, f.admin); err != nil || v.Mail.Problem != mailDiffers {
		t.Fatalf("the first server: %+v, %v", v.Mail, err)
	}
}

// Each server reads and changes the engine's mail settings holding one
// lock across servers, so that one's change never falls between another's
// read and write.
func TestEngineMailChangesTakeTurns(t *testing.T) {
	f := newFleetFixture(t)
	cfg := MailConfig{Host: "smtp.example.com", Port: 587, Username: "rmm", Password: "pw", FromAddress: "rmm@example.com", Security: "starttls"}
	f.svc = f.engineService(f.engine, Mail(func(context.Context) (MailConfig, error) { return cfg, nil }, mailKey))
	f.reconcile()
	held, err := pgx.Connect(f.ctx, f.superDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close(f.ctx)
	tx, err := held.Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(f.ctx, `SELECT pg_advisory_xact_lock($1)`, int64(lockEngineMailChange)); err != nil {
		t.Fatal(err)
	}
	puts := len(f.engine.RequestsTo("PUT", mailSettingsPath))
	gets := len(f.engine.RequestsTo("GET", mailSettingsPath))
	waits := func(step string, call func(context.Context) error) {
		t.Helper()
		ctx, cancel := context.WithTimeout(f.ctx, 500*time.Millisecond)
		defer cancel()
		start := time.Now()
		if err := call(ctx); err == nil || time.Since(start) < 400*time.Millisecond {
			t.Fatalf("%s while another server held the lock: %v after %s", step, err, time.Since(start))
		}
	}
	waits("the switch", func(ctx context.Context) error {
		_, err := f.svc.SetNotificationSettings(ctx, f.admin, NotificationSettings{AllowPrivateNetworkWebhooks: true})
		return err
	})
	waits("a pass", func(ctx context.Context) error {
		var res ReconcileResult
		f.svc.syncMail(ctx, f.svc.engine.client, &res)
		if len(res.Problems) == 0 {
			return nil
		}
		return errors.New(res.Problems[0])
	})
	// Neither read the engine's mail settings, nor changed them.
	if len(f.engine.RequestsTo("PUT", mailSettingsPath)) != puts || len(f.engine.RequestsTo("GET", mailSettingsPath)) != gets {
		t.Fatal("the engine's mail settings were reached without the lock")
	}
	if err := tx.Commit(f.ctx); err != nil {
		t.Fatal(err)
	}
	if v, err := f.svc.SetNotificationSettings(f.ctx, f.admin, NotificationSettings{AllowPrivateNetworkWebhooks: true}); err != nil || !v.AllowPrivateNetworkWebhooks {
		t.Fatalf("the switch, the lock free: %+v, %v", v, err)
	}
	if m := f.engine.Mail(); m["smtpHost"] != cfg.Host || m["smtpPassword"] != cfg.Password {
		t.Fatalf("the engine: %v", m)
	}
}

// A service that gives the engine its mail server needs the digest key
// every server shares.
func TestEngineMailNeedsTheDigestKey(t *testing.T) {
	f := newFleetFixture(t)
	signer, err := NewSigner(reconcileKey)
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewEngineClient(f.engine.URL(), signer, "1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	svc := New(f.db, audit.New(f.db, nil), "1.0.0", slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err := svc.UseEngine(client, Mail(func(context.Context) (MailConfig, error) { return MailConfig{}, nil }, mailKey[:16])); err == nil {
		t.Fatal("a short key was taken")
	}
}
