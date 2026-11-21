//go:build integration

package mailserver

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/mailer"
	"github.com/paulmataruso/easyrmm/server/internal/secrets"
	"github.com/paulmataruso/easyrmm/server/internal/testdb"
	"github.com/paulmataruso/easyrmm/server/internal/testmail"
)

type fixture struct {
	t       *testing.T
	ctx     context.Context
	db      *database.DB
	audit   *audit.Logger
	sealer  *secrets.Sealer
	svc     *Service
	mp      *testmail.Mailpit
	admin   audit.Actor
	changes int
}

func newSealer(t *testing.T) *secrets.Sealer {
	t.Helper()
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	s, err := secrets.NewSealer(secrets.Key{ID: "k1", Raw: raw})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func newFixture(t *testing.T, env *mailer.Config) *fixture {
	t.Helper()
	inst := testdb.New(t)
	f := &fixture{t: t, ctx: context.Background(), db: inst.DB, audit: audit.New(inst.DB, nil), sealer: newSealer(t), mp: testmail.New(t)}
	svc, err := New(inst.DB, f.audit, f.sealer, env, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	f.svc = svc
	svc.OnChange(func() { f.changes++ })
	var id uuid.UUID
	if err := inst.DB.InTx(f.ctx, database.System, func(tx pgx.Tx) error {
		return tx.QueryRow(f.ctx, `INSERT INTO users (email, display_name) VALUES ('admin@msp.example', 'Admin') RETURNING id`).Scan(&id)
	}); err != nil {
		t.Fatal(err)
	}
	f.admin = audit.Actor{Type: audit.ActorUser, ID: id, Label: "admin@msp.example"}
	return f
}

func (f *fixture) exec(sql string, args ...any) {
	f.t.Helper()
	if err := f.db.InTx(f.ctx, database.System, func(tx pgx.Tx) error {
		_, err := tx.Exec(f.ctx, sql, args...)
		return err
	}); err != nil {
		f.t.Fatalf("%s: %v", sql, err)
	}
}

func (f *fixture) str(sql string, args ...any) string {
	f.t.Helper()
	var s string
	if err := f.db.ReadTx(f.ctx, database.System, func(tx pgx.Tx) error {
		return tx.QueryRow(f.ctx, sql, args...).Scan(&s)
	}); err != nil {
		f.t.Fatalf("%s: %v", sql, err)
	}
	return s
}

// input is Mailpit's plain server as the console's form fills it in.
func (f *fixture) input() Input {
	return Input{Host: f.mp.Host, Port: f.mp.Port, Security: mailer.None, SignIn: SignInPassword, Username: f.mp.Username,
		Password: f.mp.Password, FromAddress: f.mp.From, FromName: "EasyRMM"}
}

func (f *fixture) get() View {
	f.t.Helper()
	v, err := f.svc.Get(f.ctx)
	if err != nil {
		f.t.Fatal(err)
	}
	return v
}

func fieldErr(t *testing.T, err error, field string) {
	t.Helper()
	var ae *apperr.Error
	if !errors.As(err, &ae) || ae.Kind != apperr.KindInvalid || ae.Fields[field] == "" {
		t.Fatalf("error %v, want a problem with %s", err, field)
	}
}

func TestNoMailServerAtFirst(t *testing.T) {
	f := newFixture(t, nil)
	v := f.get()
	if v.InForce != FromNowhere || v.Env != nil || v.Console != nil {
		t.Fatalf("view %+v", v)
	}
	if v.Limits.PerMinute != 30 || v.Limits.PerDay != 9000 || v.Usage != (Usage{OtherDayLimit: 8100}) {
		t.Fatalf("limits %+v, usage %+v", v.Limits, v.Usage)
	}
	if f.svc.Available(f.ctx) {
		t.Fatal("available without a mail server")
	}
	if cfg, err := f.svc.InForce(f.ctx); cfg != nil || err != nil {
		t.Fatalf("in force %+v %v", cfg, err)
	}
	if err := f.svc.SendAccountMail(f.ctx, f.mp.Address("a"), mailer.Message{Subject: "s", Text: "t"}); !errors.Is(err, ErrNoMailServer) {
		t.Fatalf("account mail: %v", err)
	}
	if _, err := f.svc.Test(f.ctx, f.admin, TestInput{To: f.mp.Address("a")}); !errors.Is(err, ErrNoMailServer) {
		t.Fatalf("test: %v", err)
	}
	if _, err := f.svc.Delete(f.ctx, f.admin); !errors.Is(err, apperr.ErrNotFound) {
		t.Fatalf("delete: %v", err)
	}
}

func TestUpdateValidates(t *testing.T) {
	f := newFixture(t, nil)
	for field, mutate := range map[string]func(*Input){
		"host":        func(in *Input) { in.Host = "" },
		"port":        func(in *Input) { in.Port = 0 },
		"security":    func(in *Input) { in.Host, in.Security = "smtp.example.com", mailer.None },
		"signIn":      func(in *Input) { in.SignIn = "oauth" },
		"username":    func(in *Input) { in.Username = "" },
		"password":    func(in *Input) { in.Password = "a\nb" },
		"fromAddress": func(in *Input) { in.FromAddress = "EasyRMM <rmm@example.com>" },
		"fromName":    func(in *Input) { in.FromName = "Easy\nRMM" },
	} {
		in := f.input()
		mutate(&in)
		_, err := f.svc.Update(f.ctx, f.admin, in)
		fieldErr(t, err, field)
	}
	for _, host := range []string{"smtp.example.com/x", "https://smtp.example.com", "smtp.example.com:587", "-bad.example.com"} {
		in := f.input()
		in.Host = host
		_, err := f.svc.Update(f.ctx, f.admin, in)
		fieldErr(t, err, "host")
	}
	in := f.input()
	in.SignIn, in.Password = SignInNone, ""
	_, err := f.svc.Update(f.ctx, f.admin, in)
	fieldErr(t, err, "username")
	in.Username = ""
	in.Host, in.Security = "[::1]", mailer.None
	if _, err := f.svc.Update(f.ctx, f.admin, in); err != nil {
		t.Fatalf("loopback by IPv6 address: %v", err)
	}
	if v := f.get(); v.Console.Host != "::1" {
		t.Fatalf("host %q", v.Console.Host)
	}
}

// The console's mail server is in force at once; its password is sealed,
// never shown, and kept only while the host and user name stay the same.
func TestUpdateKeepsThePasswordSealed(t *testing.T) {
	f := newFixture(t, nil)
	v, err := f.svc.Update(f.ctx, f.admin, f.input())
	if err != nil {
		t.Fatal(err)
	}
	if v.InForce != FromConsole || v.Console == nil || !v.Console.PasswordSet || v.Console.UpdatedBy != "admin@msp.example" || f.changes != 1 {
		t.Fatalf("view %+v, %d changes", v, f.changes)
	}
	body, _ := json.Marshal(v)
	if strings.Contains(string(body), f.mp.Password) {
		t.Fatal("the view carries the password")
	}
	if sealed := f.str(`SELECT password_sealed FROM mail_server`); sealed == "" || strings.Contains(sealed, f.mp.Password) {
		t.Fatalf("sealed %q", sealed)
	}
	details := f.str(`SELECT details::text FROM audit_log WHERE action = 'mail_server.update'`)
	if strings.Contains(details, f.mp.Password) || !strings.Contains(details, `"passwordChanged": true`) {
		t.Fatalf("audit details %s", details)
	}
	if !f.svc.Available(f.ctx) {
		t.Fatal("not available")
	}
	cfg, err := f.svc.InForce(f.ctx)
	if err != nil || cfg.Password != f.mp.Password || cfg.Username != f.mp.Username || cfg.Host != f.mp.Host {
		t.Fatalf("in force %+v %v", cfg, err)
	}

	// Blank: kept, for the same host and user name.
	in := f.input()
	in.Password, in.FromName = "", "RMM"
	if _, err := f.svc.Update(f.ctx, f.admin, in); err != nil {
		t.Fatal(err)
	}
	if cfg, _ := f.svc.InForce(f.ctx); cfg.Password != f.mp.Password || cfg.FromName != "RMM" {
		t.Fatalf("in force %+v", cfg)
	}
	if n := f.str(`SELECT count(*)::text FROM audit_log WHERE action = 'mail_server.update' AND details->>'passwordChanged' = 'false'`); n != "1" {
		t.Fatalf("%s updates without a password change", n)
	}
	// Never sent to another server, or for another user.
	in.Host = "localhost"
	_, err = f.svc.Update(f.ctx, f.admin, in)
	fieldErr(t, err, "password")
	in.Host, in.Username = f.mp.Host, "someone-else"
	_, err = f.svc.Update(f.ctx, f.admin, in)
	fieldErr(t, err, "password")

	// A password sealed with another key is reported, not used.
	other, err := New(f.db, f.audit, newSealer(t), nil, f.svc.log)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := other.InForce(f.ctx); err == nil || !strings.Contains(err.Error(), "cannot be opened") {
		t.Fatalf("in force with another key: %v", err)
	}
	in = f.input()
	in.Password = ""
	_, err = other.Update(f.ctx, f.admin, in)
	fieldErr(t, err, "password")

	// Removed: none in force; the limits stay.
	if _, err := f.svc.SetLimits(f.ctx, f.admin, LimitsInput{PerMinute: 5, PerDay: 50}); err != nil {
		t.Fatal(err)
	}
	v, err = f.svc.Delete(f.ctx, f.admin)
	if err != nil {
		t.Fatal(err)
	}
	if v.InForce != FromNowhere || v.Console != nil || v.Limits.PerMinute != 5 || f.changes != 3 || f.svc.Available(f.ctx) {
		t.Fatalf("after removal %+v, %d changes", v, f.changes)
	}
	if f.str(`SELECT password_sealed FROM mail_server`) != "" {
		t.Fatal("the sealed password stays")
	}
	if n := f.str(`SELECT count(*)::text FROM audit_log WHERE action = 'mail_server.delete' AND target_id = $1`, f.mp.Host+":"+strconv.Itoa(f.mp.Port)); n != "1" {
		t.Fatalf("%s removals audited", n)
	}
}

// .env's mail server wins: the console's cannot be changed, its limits can.
func TestEnvWins(t *testing.T) {
	mp := testmail.New(t)
	env := &mailer.Config{Host: mp.Host, Port: mp.Port, Security: mailer.None, Username: mp.Username, Password: mp.Password, FromAddress: mp.From}
	f := newFixture(t, env)
	f.mp = mp
	v := f.get()
	if v.InForce != FromEnv || v.Env == nil || v.Env.Host != mp.Host || !v.Env.PasswordSet || v.Env.SignIn != SignInPassword {
		t.Fatalf("view %+v", v)
	}
	body, _ := json.Marshal(v)
	if strings.Contains(string(body), mp.Password) {
		t.Fatal("the view carries .env's password")
	}
	if _, err := f.svc.Update(f.ctx, f.admin, f.input()); !errors.Is(err, ErrFromEnv) {
		t.Fatalf("update: %v", err)
	}
	if _, err := f.svc.Delete(f.ctx, f.admin); !errors.Is(err, ErrFromEnv) {
		t.Fatalf("delete: %v", err)
	}
	in := f.input()
	if _, err := f.svc.Test(f.ctx, f.admin, TestInput{To: mp.Address("a"), Server: &in}); !errors.Is(err, ErrFromEnv) {
		t.Fatalf("test of the form: %v", err)
	}
	if _, err := f.svc.SetLimits(f.ctx, f.admin, LimitsInput{PerMinute: 10, PerDay: 100}); err != nil {
		t.Fatal(err)
	}
	if !f.svc.Available(f.ctx) || f.changes != 0 {
		t.Fatal("not available")
	}
	to := mp.Address("a")
	res, err := f.svc.Test(f.ctx, f.admin, TestInput{To: to})
	if err != nil || !res.OK {
		t.Fatalf("test %+v %v", res, err)
	}
	if got := mp.Wait(to, 1); got[0].Subject != "EasyRMM test message" {
		t.Fatalf("subject %q", got[0].Subject)
	}
	if src := f.str(`SELECT details->>'source' FROM audit_log WHERE action = 'mail_server.test'`); src != FromEnv {
		t.Fatalf("source %q", src)
	}

	// .env's mail server is checked at start.
	if _, err := New(f.db, f.audit, f.sealer, &mailer.Config{Host: "smtp.example.com", Port: 25, Security: mailer.None, FromAddress: "a@example.com"}, f.svc.log); err == nil ||
		!strings.Contains(err.Error(), "EASYRMM_SMTP_") {
		t.Fatalf("plain SMTP to a remote server from .env: %v", err)
	}
}

func TestLimitsValidateAndAudit(t *testing.T) {
	f := newFixture(t, nil)
	for _, tc := range []struct {
		in    LimitsInput
		field string
	}{
		{LimitsInput{PerMinute: 0, PerDay: 10}, "perMinute"},
		{LimitsInput{PerMinute: 10_001, PerDay: 20_000}, "perMinute"},
		{LimitsInput{PerMinute: 10, PerDay: 1_000_001}, "perDay"},
		{LimitsInput{PerMinute: 10, PerDay: 5}, "perDay"},
	} {
		_, err := f.svc.SetLimits(f.ctx, f.admin, tc.in)
		fieldErr(t, err, tc.field)
	}
	v, err := f.svc.SetLimits(f.ctx, f.admin, LimitsInput{PerMinute: 60, PerDay: 2000})
	if err != nil {
		t.Fatal(err)
	}
	if v.Limits.PerMinute != 60 || v.Limits.PerDay != 2000 || v.Limits.UpdatedBy != "admin@msp.example" || v.Usage.OtherDayLimit != 1800 {
		t.Fatalf("limits %+v %+v", v.Limits, v.Usage)
	}
	details := f.str(`SELECT details::text FROM audit_log WHERE action = 'mail_server.limits_update'`)
	if !strings.Contains(details, `"perDay": {"to": 2000, "from": 9000}`) || !strings.Contains(details, `"perMinute": {"to": 60, "from": 30}`) {
		t.Fatalf("details %s", details)
	}
}

// The test message: the form's settings, before they are saved; one every
// 30 seconds; recorded with the mail server's answer.
func TestTestMessage(t *testing.T) {
	f := newFixture(t, nil)
	in := f.input()
	to := f.mp.Address("tester")
	_, err := f.svc.Test(f.ctx, f.admin, TestInput{To: "not an address", Server: &in})
	fieldErr(t, err, "to")
	bad := in
	bad.Port = 0
	_, err = f.svc.Test(f.ctx, f.admin, TestInput{To: to, Server: &bad})
	fieldErr(t, err, "port")

	res, err := f.svc.Test(f.ctx, f.admin, TestInput{To: to, Server: &in})
	if err != nil || !res.OK || !strings.Contains(res.Message, "took the message for "+to+" and answered: 250 ") {
		t.Fatalf("test %+v %v", res, err)
	}
	got := f.mp.Wait(to, 1)[0]
	if got.Subject != "EasyRMM test message" || !strings.Contains(got.Text, "This is a test message from EasyRMM.") ||
		!strings.Contains(got.HTML, "This is a test message from EasyRMM.") || got.From.Name != "EasyRMM" {
		t.Fatalf("message %+v", got)
	}
	if f.get().Console != nil {
		t.Fatal("testing saved the form")
	}
	details := f.str(`SELECT details::text FROM audit_log WHERE action = 'mail_server.test' AND outcome = 'success'`)
	if !strings.Contains(details, to) || strings.Contains(details, f.mp.Password) || !strings.Contains(details, `"source": "console"`) {
		t.Fatalf("details %s", details)
	}
	if v := f.get(); v.Usage.LastMinute != 1 || v.Usage.LastDay != 1 || v.Usage.AccountLastDay != 0 {
		t.Fatalf("usage %+v", v.Usage)
	}

	// Too soon.
	_, err = f.svc.Test(f.ctx, f.admin, TestInput{To: to, Server: &in})
	var soon *TooSoonError
	if !errors.As(err, &soon) || soon.RetryAfter <= 0 || soon.RetryAfter > TestInterval || soon.Seconds() < 1 || !strings.Contains(soon.Error(), "Try again in") {
		t.Fatalf("second test: %v", err)
	}

	// Refused: reported and recorded, and it does not count.
	f.exec(`UPDATE mail_server SET last_test_at = NULL`)
	res, err = f.svc.Test(f.ctx, f.admin, TestInput{To: testmail.Refused, Server: &in})
	if err != nil || res.OK || !strings.Contains(res.Message, "refused the recipient: 550") {
		t.Fatalf("refused test %+v %v", res, err)
	}
	if e := f.str(`SELECT details->>'error' FROM audit_log WHERE action = 'mail_server.test' AND outcome = 'failure'`); !strings.Contains(e, "550") {
		t.Fatalf("recorded error %q", e)
	}
	if v := f.get(); v.Usage.LastDay != 1 {
		t.Fatalf("usage %+v", v.Usage)
	}

	// Saved, the mail server in force is tested; a blank password in the
	// form is the stored one.
	if _, err := f.svc.Update(f.ctx, f.admin, in); err != nil {
		t.Fatal(err)
	}
	f.exec(`UPDATE mail_server SET last_test_at = NULL`)
	if res, err := f.svc.Test(f.ctx, f.admin, TestInput{To: to}); err != nil || !res.OK {
		t.Fatalf("test %+v %v", res, err)
	}
	f.exec(`UPDATE mail_server SET last_test_at = NULL`)
	blank := in
	blank.Password = ""
	if res, err := f.svc.Test(f.ctx, f.admin, TestInput{To: to, Server: &blank}); err != nil || !res.OK {
		t.Fatalf("test with the stored password %+v %v", res, err)
	}
	f.mp.Wait(to, 3)
}

func TestAccountMail(t *testing.T) {
	f := newFixture(t, nil)
	if _, err := f.svc.Update(f.ctx, f.admin, f.input()); err != nil {
		t.Fatal(err)
	}
	to := f.mp.Address("new-user")
	msg, _ := mailer.Letter{Subject: "You have been invited to EasyRMM", Before: []string{"Welcome."},
		Link: &mailer.Link{Label: "Set up", URL: "https://rmm.example.com/invite#t"}}.Message()
	if err := f.svc.SendAccountMail(f.ctx, to, msg); err != nil {
		t.Fatal(err)
	}
	if got := f.mp.Wait(to, 1)[0]; got.Subject != msg.Subject || !strings.Contains(got.HTML, "https://rmm.example.com/invite#t") {
		t.Fatalf("message %+v", got)
	}
	var re *mailer.ReplyError
	if err := f.svc.SendAccountMail(f.ctx, testmail.Refused, msg); !errors.As(err, &re) || re.Code != 550 {
		t.Fatalf("refused: %v", err)
	}
	if v := f.get(); v.Usage.LastDay != 1 || v.Usage.AccountLastDay != 1 {
		t.Fatalf("usage %+v", v.Usage)
	}
}

// sends records n messages sent ago.
func (f *fixture) sends(n int, ago time.Duration, account bool) {
	f.t.Helper()
	f.exec(`INSERT INTO mail_sends (sent_at, account) SELECT clock_timestamp() - make_interval(secs => $1), $2 FROM generate_series(1, $3)`,
		ago.Seconds(), account, n)
}

// Account mail first: other mail stops at 90% of the day's limit, never
// waits, and stands back while account mail waits; account mail may use
// the whole day's limit and waits for room under the minute's.
func TestLimits(t *testing.T) {
	f := newFixture(t, nil)
	if _, err := f.svc.SetLimits(f.ctx, f.admin, LimitsInput{PerMinute: 2, PerDay: 10}); err != nil {
		t.Fatal(err)
	}
	var le *LimitError

	// The minute's limit.
	if _, err := f.svc.take(f.ctx, false); err != nil {
		t.Fatal(err)
	}
	id, err := f.svc.take(f.ctx, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.take(f.ctx, false); !errors.As(err, &le) || le.Day || le.RetryAfter <= 0 || le.RetryAfter > time.Minute ||
		!strings.Contains(le.Error(), "limit of 2 messages a minute") {
		t.Fatalf("third in a minute: %v", err)
	}
	// A message not taken is not counted.
	f.svc.untake(id)
	if _, err := f.svc.take(f.ctx, false); err != nil {
		t.Fatal(err)
	}

	// Account mail waits for the oldest to be a minute old.
	f.exec(`DELETE FROM mail_sends`)
	f.sends(2, 59*time.Second, false)
	start := time.Now()
	if _, err := f.svc.take(f.ctx, true); err != nil {
		t.Fatal(err)
	}
	if waited := time.Since(start); waited < 500*time.Millisecond || waited > 10*time.Second {
		t.Fatalf("account mail waited %s", waited)
	}
	// ...but not past its context.
	f.sends(2, time.Second, false)
	ctx, cancel := context.WithTimeout(f.ctx, 200*time.Millisecond)
	defer cancel()
	if _, err := f.svc.take(ctx, true); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("account mail past its context: %v", err)
	}

	// Nor longer than accountWait.
	f.exec(`DELETE FROM mail_sends`)
	f.sends(2, -10*time.Second, false)
	if _, err := f.svc.take(f.ctx, true); !errors.As(err, &le) || le.Day || !le.Account {
		t.Fatalf("account mail with no room for over a minute: %v", err)
	}

	// Other mail stands back while account mail waits.
	f.exec(`DELETE FROM mail_sends`)
	f.svc.accountWaiting.Add(1)
	_, err = f.svc.take(f.ctx, false)
	f.svc.accountWaiting.Add(-1)
	if !errors.As(err, &le) || !le.AccountWaiting || !strings.Contains(le.Error(), "go first") {
		t.Fatalf("other mail while account mail waits: %v", err)
	}

	// The day: other mail stops at 9 of 10, account mail at 10.
	f.sends(9, time.Hour, false)
	if _, err := f.svc.take(f.ctx, false); !errors.As(err, &le) || !le.Day || le.Account || !strings.Contains(le.Error(), "reach 9, 90% of the limit of 10 a day") {
		t.Fatalf("other mail at 90%%: %v", err)
	}
	if _, err := f.svc.take(f.ctx, true); err != nil {
		t.Fatalf("account mail at 90%%: %v", err)
	}
	if _, err := f.svc.take(f.ctx, true); !errors.As(err, &le) || !le.Day || !le.Account || !strings.Contains(le.Error(), "limit of 10 messages a day is reached") {
		t.Fatalf("account mail at 100%%: %v", err)
	}

	// Messages older than a day no longer count, and go.
	f.exec(`DELETE FROM mail_sends`)
	f.sends(10, 25*time.Hour, true)
	if _, err := f.svc.take(f.ctx, false); err != nil {
		t.Fatal(err)
	}
	if n := f.str(`SELECT count(*)::text FROM mail_sends`); n != "1" {
		t.Fatalf("%s sends kept", n)
	}

	// Through the mail server: the test message is other mail.
	f.exec(`DELETE FROM mail_sends`)
	f.sends(9, time.Hour, true)
	in := f.input()
	res, err := f.svc.Test(f.ctx, f.admin, TestInput{To: f.mp.Address("a"), Server: &in})
	if err != nil || res.OK || !strings.Contains(res.Message, "90% of the limit") {
		t.Fatalf("test at 90%%: %+v %v", res, err)
	}
	if _, err := f.svc.Update(f.ctx, f.admin, in); err != nil {
		t.Fatal(err)
	}
	to := f.mp.Address("b")
	if err := f.svc.SendAccountMail(f.ctx, to, mailer.Message{Subject: "s", Text: "t"}); err != nil {
		t.Fatalf("account mail at 90%%: %v", err)
	}
	f.mp.Wait(to, 1)
}

func TestLimitErrorWords(t *testing.T) {
	if got := thousands(1234567); got != "1,234,567" {
		t.Fatal(got)
	}
	if got := thousands(999); got != "999" {
		t.Fatal(got)
	}
	e := &LimitError{PerMinute: 30, PerDay: 9000, RetryAfter: 1500 * time.Millisecond}
	if got := e.Error(); got != "Not sent: the limit of 30 messages a minute is reached. Try again in 2 seconds." {
		t.Fatal(got)
	}
}
