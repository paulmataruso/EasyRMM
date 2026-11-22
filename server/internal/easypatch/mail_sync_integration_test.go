//go:build integration

package easypatch

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

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
		})
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

	// The database holds a salted digest, never the mail server.
	var salt, digest []byte
	if err := f.db.ReadTx(ctx, database.System, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT salt, digest FROM mail_engine_given`).Scan(&salt, &digest)
	}); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(mailDigest(a, salt), digest) || bytes.Equal(mailDigest(b, salt), digest) || bytes.Contains(digest, []byte("pw-a")) {
		t.Fatal("the record is not a digest of the mail server given")
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
	f.svc = f.engineService(f.engine, Mail(func(context.Context) (MailConfig, error) { return cfg, nil }))
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
	f.svc = f.engineService(f.engine, Mail(func(context.Context) (MailConfig, error) { return cfg, nil }))
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
// (a password sealed with another key): no mail server goes with it, as
// when passes cannot give one, and Settings → Patching says why; the first
// pass that can read it gives it again.
func TestWebhookSwitchWithAnUnreadableMailServer(t *testing.T) {
	f := newFleetFixture(t)
	cfg := MailConfig{Host: "smtp.example.com", Port: 587, Username: "rmm", Password: "pw", FromAddress: "rmm@example.com", Security: "starttls"}
	var readErr error
	f.svc = f.engineService(f.engine, Mail(func(context.Context) (MailConfig, error) { return cfg, readErr }))
	f.reconcile()
	readErr = errors.New("the stored password cannot be opened")
	v, err := f.svc.SetNotificationSettings(f.ctx, f.admin, NotificationSettings{AllowPrivateNetworkWebhooks: true})
	if err != nil || !v.AllowPrivateNetworkWebhooks || v.Mail.Host != "" || !strings.Contains(v.Mail.Problem, "the stored password cannot be opened") {
		t.Fatalf("the switch: %+v, %v", v, err)
	}
	if m := f.engine.Mail(); m["allowPrivateNetworkWebhooks"] != true || m["smtpHost"] != nil || m["smtpPassword"] != "" {
		t.Fatalf("the engine: %v", m)
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
