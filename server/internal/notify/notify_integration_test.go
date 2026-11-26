//go:build integration

package notify

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/server/internal/access"
	"github.com/paulmataruso/easyrmm/server/internal/addrpolicy"
	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/devscope"
	"github.com/paulmataruso/easyrmm/server/internal/mailer"
	"github.com/paulmataruso/easyrmm/server/internal/mailserver"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
	"github.com/paulmataruso/easyrmm/server/internal/secrets"
	"github.com/paulmataruso/easyrmm/server/internal/testdb"
	"github.com/paulmataruso/easyrmm/server/internal/testmail"
)

// logBuffer is a log tests read while the service writes it.
type logBuffer struct {
	mu sync.Mutex
	b  strings.Builder
}

func (l *logBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *logBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

type fx struct {
	t      *testing.T
	ctx    context.Context
	db     *database.DB
	svc    *Service
	mail   *mailserver.Service
	mp     *testmail.Mailpit
	log    *logBuffer
	orgA   uuid.UUID
	orgB   uuid.UUID
	clock  time.Time
	clockM sync.Mutex
	dsn    string
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

func newFx(t *testing.T) *fx {
	t.Helper()
	inst := testdb.New(t)
	f := &fx{t: t, ctx: context.Background(), db: inst.DB, dsn: inst.SuperDSN, log: &logBuffer{}, mp: testmail.New(t), clock: time.Now().UTC()}
	log := slog.New(slog.NewTextHandler(f.log, &slog.HandlerOptions{Level: slog.LevelDebug}))
	auditLog := audit.New(inst.DB, nil)
	sealer := newSealer(t)
	ms, err := mailserver.New(inst.DB, auditLog, sealer, nil, log)
	if err != nil {
		t.Fatal(err)
	}
	f.mail = ms
	if _, err := ms.Update(f.ctx, audit.SystemActor("test"), mailserver.Input{Host: f.mp.Host, Port: f.mp.Port, Security: mailer.None, SignIn: mailserver.SignInPassword,
		Username: f.mp.Username, Password: f.mp.Password, FromAddress: f.mp.From, FromName: "EasyRMM"}); err != nil {
		t.Fatal(err)
	}
	f.svc = New(inst.DB, auditLog, sealer, addrpolicy.NewEnvironment(nil, nil), ms, log)
	f.svc.now = func() time.Time {
		f.clockM.Lock()
		defer f.clockM.Unlock()
		return f.clock
	}
	f.svc.testWait = 0
	f.svc.SetConsoleURL("https://rmm.example.com")
	f.orgA = f.id(`INSERT INTO organizations (name) VALUES ('Acme') RETURNING id`)
	f.orgB = f.id(`INSERT INTO organizations (name) VALUES ('Globex') RETURNING id`)
	return f
}

func (f *fx) advance(d time.Duration) {
	f.clockM.Lock()
	defer f.clockM.Unlock()
	f.clock = f.clock.Add(d)
}

func (f *fx) id(q string, args ...any) uuid.UUID {
	f.t.Helper()
	var id uuid.UUID
	if err := f.db.InTx(f.ctx, database.System, func(tx pgx.Tx) error { return tx.QueryRow(f.ctx, q, args...).Scan(&id) }); err != nil {
		f.t.Fatal(err)
	}
	return id
}

func (f *fx) exec(q string, args ...any) {
	f.t.Helper()
	if err := f.db.InTx(f.ctx, database.System, func(tx pgx.Tx) error {
		_, err := tx.Exec(f.ctx, q, args...)
		return err
	}); err != nil {
		f.t.Fatalf("%s: %v", q, err)
	}
}

func (f *fx) str(q string, args ...any) string {
	f.t.Helper()
	var s *string
	if err := f.db.ReadTx(f.ctx, database.System, func(tx pgx.Tx) error { return tx.QueryRow(f.ctx, q, args...).Scan(&s) }); err != nil {
		f.t.Fatalf("%s: %v", q, err)
	}
	if s == nil {
		return ""
	}
	return *s
}

func (f *fx) n(q string, args ...any) int {
	f.t.Helper()
	var n int
	if err := f.db.ReadTx(f.ctx, database.System, func(tx pgx.Tx) error { return tx.QueryRow(f.ctx, q, args...).Scan(&n) }); err != nil {
		f.t.Fatalf("%s: %v", q, err)
	}
	return n
}

func (f *fx) super() access.Caller { return access.System("test") }

func (f *fx) caller(role rbac.Role, org uuid.UUID) access.Caller {
	p, err := rbac.NewPrincipal(uuid.New(), []rbac.Assignment{{Role: role, OrganizationID: org}})
	if err != nil {
		f.t.Fatal(err)
	}
	return access.User(p, database.Scope{Orgs: []uuid.UUID{org}}, audit.Actor{Type: audit.ActorUser, ID: uuid.New(), Label: "admin@example.com"})
}

func (f *fx) orgAdmin(org uuid.UUID) access.Caller { return f.caller(rbac.RoleOrgAdmin, org) }

// receiver is a TLS webhook receiver: it records what it is sent and answers
// with the status the test sets.
type receiver struct {
	*httptest.Server
	mu       sync.Mutex
	status   int
	retry    string
	requests []recvReq
}

type recvReq struct {
	path   string
	header http.Header
	body   []byte
}

func newReceiver(t *testing.T) *receiver {
	t.Helper()
	r := &receiver{status: 204}
	r.Server = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		b, _ := io.ReadAll(req.Body)
		r.mu.Lock()
		r.requests = append(r.requests, recvReq{path: req.URL.RequestURI(), header: req.Header.Clone(), body: b})
		status, retry := r.status, r.retry
		r.mu.Unlock()
		if retry != "" {
			w.Header().Set("Retry-After", retry)
		}
		if status == 302 {
			w.Header().Set("Location", "/elsewhere")
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte("response body that must never reach a log"))
	}))
	r.StartTLS()
	t.Cleanup(r.Close)
	return r
}

func (r *receiver) set(status int, retry string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.status, r.retry = status, retry
}

func (r *receiver) got() []recvReq {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]recvReq(nil), r.requests...)
}

// url is the receiver's address with a path and a query that are secrets in
// themselves (Slack's and Teams' work so).
func (r *receiver) url() string { return r.URL + "/services/T00/B00/sekrit-path?token=sekrit-query" }

func (r *receiver) authority() string {
	var out []byte
	for _, c := range r.TLS.Certificates {
		out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Certificate[0]})...)
	}
	return string(out)
}

func ptr[T any](v T) *T { return &v }

// platformHook makes a platform webhook to the receiver, trusting its certificate.
func (f *fx) platformHook(r *receiver, name string) Channel {
	f.t.Helper()
	ch, err := f.svc.Create(f.ctx, f.super(), ChannelInput{Kind: KindWebhook, Name: ptr(name), URL: ptr(r.url()), TrustedAuthority: ptr(r.authority())})
	if err != nil {
		f.t.Fatal(err)
	}
	return ch
}

// queue puts an event delivery in the outbox, as the planner will (slice 4).
func (f *fx) queue(ch Channel, charged uuid.UUID, subjects []string, queuedAt time.Time) uuid.UUID {
	f.t.Helper()
	owner := uuid.Nil
	if ch.OrganizationID != nil {
		owner = *ch.OrganizationID
	}
	if subjects == nil {
		subjects = []string{}
	}
	about := []uuid.UUID{}
	if charged != uuid.Nil {
		about = append(about, charged)
	}
	msg, _ := json.Marshal(Message{Subject: "Notice opened", Summary: "something happened", Notice: &NoticeBody{ID: uuid.New(), Kind: "x", Title: "t", OpenedAt: queuedAt}})
	id := f.id(`INSERT INTO notification_deliveries (owner, charged_org, channel_id, kind, event, subjects, about, message, queued_at, next_attempt_at)
		VALUES ($1, $2, $3, 'event', 'notices.opened', $4, $5, $6, $7, $7) RETURNING id`, owner, charged, ch.ID, subjects, about, msg, queuedAt)
	rs := ch.Recipients
	if ch.Kind == KindWebhook {
		rs = []string{webhookRecipient}
	}
	for _, r := range rs {
		f.exec(`INSERT INTO notification_delivery_recipients (delivery_id, recipient) VALUES ($1, $2)`, id, r)
	}
	return id
}

func (f *fx) status(id uuid.UUID) string {
	return f.str(`SELECT status FROM notification_deliveries WHERE id = $1`, id)
}

func TestWebhookTestIsSignedAndReceived(t *testing.T) {
	f := newFx(t)
	r := newReceiver(t)
	ch := f.platformHook(r, "ops webhook")
	if ch.Host != "127.0.0.1" || ch.State != StateSending {
		t.Fatalf("%+v", ch)
	}
	res, err := f.svc.Test(f.ctx, f.super(), ch.ID)
	if err != nil || res.Status != StatusPending {
		t.Fatalf("test queued: %+v %v", res, err)
	}
	f.svc.SendDue(f.ctx)
	res = f.svc.awaitTest(f.ctx, uuid.Nil, res.DeliveryID)
	if res.Status != StatusSent {
		t.Fatalf("test: %+v", res)
	}
	reqs := r.got()
	if len(reqs) != 1 {
		t.Fatalf("%d requests", len(reqs))
	}
	req := reqs[0]
	sec, err := f.svc.Reveal(f.ctx, f.super(), ch.ID)
	if err != nil || sec.URL != r.url() || len(sec.Secret) != 43 {
		t.Fatalf("reveal: %+v %v", sec, err)
	}
	// The signature: t=<unix>,v1=<hex HMAC-SHA256(secret, t + "." + body)>.
	sig := req.header.Get("X-EasyRMM-Signature")
	parts := strings.Split(sig, ",")
	if len(parts) != 2 || !strings.HasPrefix(parts[0], "t=") || !strings.HasPrefix(parts[1], "v1=") {
		t.Fatalf("signature %q", sig)
	}
	mac := hmac.New(sha256.New, []byte(sec.Secret))
	mac.Write([]byte(strings.TrimPrefix(parts[0], "t=") + "."))
	mac.Write(req.body)
	if hex.EncodeToString(mac.Sum(nil)) != strings.TrimPrefix(parts[1], "v1=") {
		t.Fatal("the signature does not verify")
	}
	if ts, _ := strconv.ParseInt(strings.TrimPrefix(parts[0], "t="), 10, 64); time.Since(time.Unix(ts, 0)) > 5*time.Minute {
		t.Fatal("stale timestamp")
	}
	if req.header.Get("X-EasyRMM-Event") != "test" || req.header.Get("Content-Type") != "application/json" || req.header.Get("X-EasyRMM-Delivery") != res.DeliveryID.String() {
		t.Fatalf("headers %v", req.header)
	}
	if req.header.Get("X-EasyPatch-Signature") != "" {
		t.Fatal("a new channel sends the engine's headers")
	}
	if req.path != "/services/T00/B00/sekrit-path?token=sekrit-query" {
		t.Fatalf("the request went to %s", req.path)
	}
	var body map[string]any
	if err := json.Unmarshal(req.body, &body); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"event", "deliveryId", "sentAt", "subject", "summary", "alerts", "moreCount", "consoleUrl", "source"} {
		if _, ok := body[k]; !ok {
			t.Errorf("body lacks %s: %s", k, req.body)
		}
	}
	if body["source"] != "easyrmm" || body["event"] != "test" || body["consoleUrl"] != "https://rmm.example.com" || strings.Contains(string(req.body), ch.Name) {
		t.Fatalf("body %s", req.body)
	}
	// Sealed at rest: neither the address nor the secret is in the database or the log.
	for _, col := range []string{"sealed_url", "sealed_secret"} {
		v := f.str(`SELECT `+col+` FROM notification_channel_details WHERE channel_id = $1`, ch.ID)
		if v == "" || strings.Contains(v, "sekrit") || strings.Contains(v, sec.Secret) {
			t.Fatalf("%s is not sealed: %q", col, v)
		}
	}
	// Rotating replaces the secret at once.
	if err := f.svc.RotateSecret(f.ctx, f.super(), ch.ID); err != nil {
		t.Fatal(err)
	}
	sec2, _ := f.svc.Reveal(f.ctx, f.super(), ch.ID)
	if sec2.Secret == sec.Secret {
		t.Fatal("the secret was not rotated")
	}
	// The audit log records that it was shown, never what.
	if n := f.n(`SELECT count(*) FROM audit_log WHERE action = 'notification_channel.reveal'`); n != 2 {
		t.Fatalf("%d reveal records", n)
	}
	for _, leak := range []string{"sekrit", sec.Secret, sec2.Secret} {
		if n := f.n(`SELECT count(*) FROM audit_log WHERE details::text LIKE '%' || $1 || '%'`, leak); n != 0 {
			t.Fatalf("the audit log holds %q", leak)
		}
		if strings.Contains(f.log.String(), leak) {
			t.Fatalf("the log holds %q", leak)
		}
	}
	// A second test within 30 seconds is refused as the engine refuses it.
	_, err = f.svc.Test(f.ctx, f.super(), ch.ID)
	var ae *apperr.Error
	if !asApp(err, &ae) || ae.Kind != apperr.KindTooMany || ae.Code != "test_rate_limited" {
		t.Fatalf("second test: %v", err)
	}
	f.advance(31 * time.Second)
	if _, err := f.svc.Test(f.ctx, f.super(), ch.ID); err != nil {
		t.Fatalf("test after 30 seconds: %v", err)
	}
}

func asApp(err error, target **apperr.Error) bool {
	ae, ok := apperr.As(err)
	if ok {
		*target = ae
	}
	return ok
}

func TestAnOrganizationsWebhookIsRefusedLoopbackEvenWhenApproved(t *testing.T) {
	f := newFx(t)
	r := newReceiver(t)
	admin := f.orgAdmin(f.orgA)
	ch, err := f.svc.Create(f.ctx, admin, ChannelInput{OrganizationID: &f.orgA, Kind: KindWebhook, Name: ptr("mine"), URL: ptr(r.url()), TrustedAuthority: ptr(r.authority())})
	if err != nil {
		t.Fatal(err)
	}
	res, _ := f.svc.Test(f.ctx, admin, ch.ID)
	f.svc.SendDue(f.ctx)
	res = f.svc.awaitTest(f.ctx, f.orgA, res.DeliveryID)
	if res.Status == StatusSent || len(r.got()) != 0 {
		t.Fatalf("a loopback destination was reached: %+v", res)
	}
	if !strings.Contains(res.Message, "127.0.0.1") || strings.Contains(res.Message, "sekrit") {
		t.Fatalf("message %q", res.Message)
	}
	// Loopback needs no approval, and is not curable by one: it was refused for good, not asked about.
	if ap, _ := f.svc.get(f.ctx, admin, ch.ID); ap.Approval != nil {
		t.Fatalf("an approval was asked for loopback: %+v", ap.Approval)
	}
}

func TestWebhookAnswersAreClassifiedAndErrorsHoldNoSecret(t *testing.T) {
	f := newFx(t)
	r := newReceiver(t)
	ch := f.platformHook(r, "hook")
	send := func(status int, retry string) (string, Channel) {
		t.Helper()
		r.set(status, retry)
		id := f.queue(ch, uuid.Nil, nil, f.clock)
		f.svc.SendDue(f.ctx)
		got, err := f.svc.Get(f.ctx, f.super(), ch.ID)
		if err != nil {
			t.Fatal(err)
		}
		return id.String(), got
	}
	// 500: transient: stays pending, backs off a minute.
	id, got := send(500, "")
	if st := f.str(`SELECT status FROM notification_deliveries WHERE id = $1`, id); st != StatusPending {
		t.Fatalf("500: %s", st)
	}
	if d := f.str(`SELECT extract(epoch FROM next_attempt_at - $2)::int::text FROM notification_deliveries WHERE id = $1`, id, f.clock); d != "60" {
		t.Fatalf("500: next attempt in %ss, want 60", d)
	}
	if got.LastError != "The receiver at 127.0.0.1 answered 500." {
		t.Fatalf("last error %q", got.LastError)
	}
	f.exec(`DELETE FROM notification_deliveries`)
	// 429 with Retry-After is honored.
	id, _ = send(429, "300")
	if d := f.str(`SELECT extract(epoch FROM next_attempt_at - $2)::int::text FROM notification_deliveries WHERE id = $1`, id, f.clock); d != "300" {
		t.Fatalf("429: next attempt in %ss, want 300", d)
	}
	f.exec(`DELETE FROM notification_deliveries`)
	// A redirect is a failure, and is not followed.
	before := len(r.got())
	id, _ = send(302, "")
	if st := f.str(`SELECT status FROM notification_deliveries WHERE id = $1`, id); st != StatusFailed {
		t.Fatalf("302: %s", st)
	}
	if len(r.got()) != before+1 {
		t.Fatal("the redirect was followed")
	}
	f.exec(`DELETE FROM notification_deliveries`)
	// 422 is permanent but does not mark the channel failing at once (three in a row do).
	send(204, "")
	f.exec(`DELETE FROM notification_deliveries`)
	for i, want := range []bool{false, false, true} {
		_, got = send(422, "")
		if (got.State == StateFailing) != want {
			t.Fatalf("after %d permanent answers: state %s", i+1, got.State)
		}
		f.exec(`DELETE FROM notification_deliveries`)
	}
	// A success recovers it, and resolves its notice.
	_, got = send(204, "")
	if got.State != StateSending || f.n(`SELECT count(*) FROM notices WHERE kind = 'channel_failing' AND resolved_at IS NULL`) != 0 {
		t.Fatalf("not recovered: %s", got.State)
	}
	f.exec(`DELETE FROM notification_deliveries`)
	// 410 marks it failing at once, with a notice naming the channel.
	_, got = send(410, "")
	if got.State != StateFailing {
		t.Fatalf("410: %s", got.State)
	}
	if f.n(`SELECT count(*) FROM notices WHERE kind = 'channel_failing' AND resolved_at IS NULL AND organization_id IS NULL`) != 1 {
		t.Fatal("no notice for the failing channel")
	}
	// Nothing sensitive in errors, notices, the log or audit: not the path, the query, the secret or the response body.
	sec, _ := f.svc.Reveal(f.ctx, f.super(), ch.ID)
	for _, q := range []string{
		`SELECT coalesce(string_agg(last_error, ' '), '') FROM notification_deliveries`,
		`SELECT coalesce(string_agg(last_error, ' '), '') FROM notification_channel_details`,
		`SELECT coalesce(string_agg(title || ' ' || detail, ' '), '') FROM notices`,
		`SELECT coalesce(string_agg(details::text, ' '), '') FROM audit_log`,
	} {
		text := f.str(q) + f.log.String()
		for _, leak := range []string{"sekrit", "response body that must never", sec.Secret, "/services/"} {
			if strings.Contains(text, leak) {
				t.Fatalf("%q leaked through %s", leak, q)
			}
		}
	}
}

func TestErrorsNeverCarryTheURL(t *testing.T) {
	f := newFx(t)
	// A platform webhook to a closed port on loopback, then to a name that does not resolve, then a bad certificate.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()
	hooks := map[string]string{
		"closed":   "https://127.0.0.1:" + strconv.Itoa(port) + "/services/T0/sekrit-path?token=sekrit-query",
		"nodns":    "https://no-such-host.invalid/services/T0/sekrit-path?token=sekrit-query",
		"badcerts": "",
	}
	r := newReceiver(t)
	hooks["badcerts"] = r.url()
	for name, u := range hooks {
		in := ChannelInput{Kind: KindWebhook, Name: ptr(name), URL: ptr(u)}
		ch, err := f.svc.Create(f.ctx, f.super(), in)
		if err != nil {
			t.Fatal(err)
		}
		id := f.queue(ch, uuid.Nil, nil, f.clock)
		f.svc.SendDue(f.ctx)
		msg := f.str(`SELECT last_error FROM notification_deliveries WHERE id = $1`, id)
		if msg == "" || strings.Contains(msg, "sekrit") || strings.Contains(msg, "services") {
			t.Fatalf("%s: error %q", name, msg)
		}
		t.Logf("%s: %s", name, msg)
	}
	if strings.Contains(f.log.String(), "sekrit") {
		t.Fatal("the log holds a URL's secret")
	}
}

func TestAChannelsDeliveriesGoInOrderUntilAnHour(t *testing.T) {
	f := newFx(t)
	r := newReceiver(t)
	ch := f.platformHook(r, "ordered")
	r.set(503, "")
	t0 := f.clock
	first := f.queue(ch, uuid.Nil, []string{"notice:1"}, t0)
	f.advance(time.Second)
	sameSubject := f.queue(ch, uuid.Nil, []string{"notice:1"}, f.clock)
	other := f.queue(ch, uuid.Nil, []string{"notice:2"}, f.clock)
	f.svc.SendDue(f.ctx)
	if len(r.got()) != 1 {
		t.Fatalf("%d requests: the later ones went before the earliest was done", len(r.got()))
	}
	// The earliest waits a long time; what is queued behind it waits with it.
	f.exec(`UPDATE notification_deliveries SET next_attempt_at = $2 WHERE id = $1`, first, f.clock.Add(4*time.Hour))
	// Within the hour nothing goes before the earliest unsent one, though it waits.
	f.advance(30 * time.Minute)
	f.exec(`UPDATE notification_deliveries SET next_attempt_at = $1 WHERE id <> $2`, f.clock, first)
	f.svc.SendDue(f.ctx)
	if len(r.got()) != 1 {
		t.Fatalf("%d requests after 30 minutes: order was not kept", len(r.got()))
	}
	// After an hour, one that carries no subject an earlier unsent one carries may go; the one that shares does not.
	f.advance(31 * time.Minute)
	r.set(204, "")
	f.svc.SendDue(f.ctx)
	if st := f.status(other); st != StatusSent {
		t.Fatalf("the unrelated delivery is %s", st)
	}
	if st := f.status(sameSubject); st != StatusPending {
		t.Fatalf("the delivery sharing a subject with an earlier unsent one is %s, want it held", st)
	}
	if st := f.status(first); st != StatusPending {
		t.Fatalf("the earliest is %s: it was backing off", st)
	}
	// Once the earliest is due again, all go in order.
	f.exec(`UPDATE notification_deliveries SET next_attempt_at = $1 WHERE status = 'pending'`, f.clock)
	for range 3 {
		f.svc.SendDue(f.ctx)
	}
	if f.status(first) != StatusSent || f.status(sameSubject) != StatusSent {
		t.Fatal("the rest were not sent in the end")
	}
	order := []string{}
	for _, q := range r.got() {
		var b struct{ DeliveryID string }
		_ = json.Unmarshal(q.body, &b)
		order = append(order, b.DeliveryID)
	}
	if got := order[len(order)-2:]; got[0] != first.String() || got[1] != sameSubject.String() {
		t.Fatalf("order %v", order)
	}
}

func TestAGivenUpDeliveryRaisesANotice(t *testing.T) {
	f := newFx(t)
	r := newReceiver(t)
	ch := f.platformHook(r, "dead")
	r.set(500, "")
	id := f.queue(ch, uuid.Nil, nil, f.clock.Add(-25*time.Hour))
	f.svc.SendDue(f.ctx)
	if st := f.status(id); st != StatusFailed {
		t.Fatalf("a delivery 25 hours old, after a failure: %s", st)
	}
	got, _ := f.svc.Get(f.ctx, f.super(), ch.ID)
	if got.State != StateFailing {
		t.Fatalf("a given-up delivery leaves the channel %s", got.State)
	}
	var detail string
	if err := f.db.ReadTx(f.ctx, database.System, func(tx pgx.Tx) error {
		return tx.QueryRow(f.ctx, `SELECT detail FROM notices WHERE kind = 'messages_not_sent'`).Scan(&detail)
	}); err != nil || detail != `1 message to channel "dead" were not sent.` {
		t.Fatalf("notice %q %v", detail, err)
	}
}

func TestQuotaHoldsMessagesBackAndTellsTheOrganization(t *testing.T) {
	f := newFx(t)
	r := newReceiver(t)
	ch := f.platformHook(r, "shared")
	if _, err := f.svc.SetQuota(f.ctx, f.super(), f.orgA, Quota{Channels: 20, Rules: 50, TestsPerHour: 20, MessagesPerHour: 2}); err != nil {
		t.Fatal(err)
	}
	var ids []uuid.UUID
	for range 3 {
		ids = append(ids, f.queue(ch, f.orgA, nil, f.clock))
		f.advance(time.Second)
	}
	for range 4 {
		f.svc.SendDue(f.ctx)
	}
	if len(r.got()) != 2 {
		t.Fatalf("%d messages sent, want the quota's 2", len(r.got()))
	}
	if st := f.status(ids[2]); st != StatusPending {
		t.Fatalf("the third is %s, want waiting for room", st)
	}
	if f.n(`SELECT count(*) FROM notices WHERE kind = 'quota_reached' AND organization_id = $1 AND resolved_at IS NULL`, f.orgA) != 1 {
		t.Fatal("the organization was not told")
	}
	// Another organization's messages through the same channel are not held back.
	f.queue(ch, f.orgB, nil, f.clock)
	f.svc.SendDue(f.ctx)
	if len(r.got()) != 3 {
		t.Fatalf("another organization's message was held: %d", len(r.got()))
	}
	// An hour on, there is room, and the notice resolves.
	f.advance(61 * time.Minute)
	f.exec(`UPDATE notification_deliveries SET next_attempt_at = $1 WHERE status = 'pending'`, f.clock)
	f.svc.SendDue(f.ctx)
	if f.status(ids[2]) != StatusSent || f.n(`SELECT count(*) FROM notices WHERE kind = 'quota_reached' AND resolved_at IS NULL`) != 0 {
		t.Fatal("the held message was not sent when there was room")
	}
	// Reading quotas: an organization's administrator sees theirs but cannot change it.
	q, err := f.svc.GetQuota(f.ctx, f.orgAdmin(f.orgA), f.orgA)
	if err != nil || q.MessagesPerHour != 2 {
		t.Fatalf("%+v %v", q, err)
	}
	if _, err := f.svc.SetQuota(f.ctx, f.orgAdmin(f.orgA), f.orgA, Quota{Channels: 999}); err == nil {
		t.Fatal("an organization raised its own quota")
	}
	// Tests have a quota of their own.
	if _, err := f.svc.SetQuota(f.ctx, f.super(), f.orgA, Quota{Channels: 20, Rules: 50, TestsPerHour: 1, MessagesPerHour: 600}); err != nil {
		t.Fatal(err)
	}
	own, err := f.svc.Create(f.ctx, f.orgAdmin(f.orgA), ChannelInput{OrganizationID: &f.orgA, Kind: KindEmail, Name: ptr("mail"), Recipients: []string{"a@example.com"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.Test(f.ctx, f.orgAdmin(f.orgA), own.ID); err != nil {
		t.Fatal(err)
	}
	f.advance(time.Minute)
	if _, err := f.svc.Test(f.ctx, f.orgAdmin(f.orgA), own.ID); err == nil || !strings.Contains(err.Error(), "test_quota") {
		t.Fatalf("a second test in the hour: %v", err)
	}
}

func TestChannelQuota(t *testing.T) {
	f := newFx(t)
	if _, err := f.svc.SetQuota(f.ctx, f.super(), f.orgA, Quota{Channels: 1, Rules: 50, TestsPerHour: 20, MessagesPerHour: 600}); err != nil {
		t.Fatal(err)
	}
	admin := f.orgAdmin(f.orgA)
	in := ChannelInput{OrganizationID: &f.orgA, Kind: KindEmail, Name: ptr("one"), Recipients: []string{"a@example.com"}}
	if _, err := f.svc.Create(f.ctx, admin, in); err != nil {
		t.Fatal(err)
	}
	in.Name = ptr("two")
	if _, err := f.svc.Create(f.ctx, admin, in); !errors.Is(err, ErrChannelQuota) {
		t.Fatalf("over the quota: %v", err)
	}
}

func TestTheDevScopeStopsAutomaticSends(t *testing.T) {
	f := newFx(t)
	r := newReceiver(t)
	ch := f.platformHook(r, "scoped")
	restore := devscope.Set(f.orgB)
	defer restore()
	out := f.queue(ch, f.orgA, nil, f.clock)
	in := f.queue(ch, f.orgB, nil, f.clock.Add(time.Second))
	f.advance(2 * time.Second)
	for range 3 {
		f.svc.SendDue(f.ctx)
	}
	if st := f.status(out); st != StatusDropped {
		t.Fatalf("a delivery about an organization outside the dev scope is %s", st)
	}
	if st := f.status(in); st != StatusSent {
		t.Fatalf("a delivery about the organization in scope is %s", st)
	}
	if len(r.got()) != 1 {
		t.Fatalf("%d sent, want only the one in scope", len(r.got()))
	}
	// A notice about an organization outside the scope is never raised.
	if err := f.db.InTx(f.ctx, database.System, func(tx pgx.Tx) error {
		return openNotice(f.ctx, tx, &f.orgA, "channel_failing", "x", "t", "d")
	}); err != nil {
		t.Fatal(err)
	}
	if f.n(`SELECT count(*) FROM notices WHERE organization_id = $1`, f.orgA) != 0 {
		t.Fatal("a notice was raised for an organization outside the dev scope")
	}
	// A person's own test still goes: it is not automatic.
	pch, err := f.svc.Create(f.ctx, f.super(), ChannelInput{Kind: KindWebhook, Name: ptr("t"), URL: ptr(r.url()), TrustedAuthority: ptr(r.authority())})
	if err != nil {
		t.Fatal(err)
	}
	res, _ := f.svc.Test(f.ctx, f.super(), pch.ID)
	f.svc.SendDue(f.ctx)
	if res = f.svc.awaitTest(f.ctx, uuid.Nil, res.DeliveryID); res.Status != StatusSent {
		t.Fatalf("test: %+v", res)
	}
}

// An organization with no channels lists an empty array, never null: the
// console reads the list's length (CI run 14's Settings → Notifications).
func TestAnEmptyChannelListIsAnArray(t *testing.T) {
	f := newFx(t)
	list, err := f.svc.List(f.ctx, f.orgAdmin(f.orgA), &f.orgA)
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := json.Marshal(map[string]any{"channels": list}); string(b) != `{"channels":[]}` {
		t.Fatalf("an empty list encodes as %s", b)
	}
}

func TestPermissionsAndSharing(t *testing.T) {
	f := newFx(t)
	r := newReceiver(t)
	plat := f.platformHook(r, "platform hook")
	adminA, adminB := f.orgAdmin(f.orgA), f.orgAdmin(f.orgB)
	mine, err := f.svc.Create(f.ctx, adminA, ChannelInput{OrganizationID: &f.orgA, Kind: KindEmail, Name: ptr("a mail"), Recipients: []string{"a@example.com", "A@example.com", "b@example.com"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(mine.Recipients) != 2 {
		t.Fatalf("recipients %v: duplicates ignoring case", mine.Recipients)
	}
	isNotFound := func(err error) bool { return err != nil && errors.Is(err, apperr.NotFound()) }
	// Another organization's administrator, a technician and a site role cannot touch it.
	if _, err := f.svc.Get(f.ctx, adminB, mine.ID); !isNotFound(err) {
		t.Fatalf("another organization reads the channel: %v", err)
	}
	if _, err := f.svc.Test(f.ctx, adminB, mine.ID); !isNotFound(err) {
		t.Fatalf("another organization tests the channel: %v", err)
	}
	if err := f.svc.Delete(f.ctx, f.caller(rbac.RoleTechnician, f.orgA), mine.ID); !isNotFound(err) {
		t.Fatalf("a technician deletes the channel: %v", err)
	}
	if _, err := f.svc.List(f.ctx, adminA, nil); !isNotFound(err) {
		t.Fatalf("an organization lists every owner's channels: %v", err)
	}
	// Nothing is shared by default: the platform channel is not in the list.
	list, err := f.svc.List(f.ctx, adminA, &f.orgA)
	if err != nil || len(list) != 1 {
		t.Fatalf("%d channels %v", len(list), err)
	}
	if err := f.svc.Share(f.ctx, adminA, plat.ID, f.orgA); !isNotFound(err) {
		t.Fatalf("an organization shared a platform channel: %v", err)
	}
	if err := f.svc.Share(f.ctx, f.super(), mine.ID, f.orgB); err == nil {
		t.Fatal("an organization's own channel was shared")
	}
	if err := f.svc.Share(f.ctx, f.super(), plat.ID, f.orgA); err != nil {
		t.Fatal(err)
	}
	list, _ = f.svc.List(f.ctx, adminA, &f.orgA)
	var shared *Channel
	for i := range list {
		if list[i].ID == plat.ID {
			shared = &list[i]
		}
	}
	if shared == nil || !shared.Shared || !shared.Platform || shared.Name != "platform hook" || shared.Kind != KindWebhook {
		t.Fatalf("the shared channel as the organization sees it: %+v", shared)
	}
	if shared.Host != "" || shared.Recipients != nil || shared.LastError != "" || shared.Approval != nil || shared.SharedWith != nil || shared.State != "" {
		t.Fatalf("a shared channel shows more than its name and kind: %+v", *shared)
	}
	// It is never revealed, tested or changed by the organization.
	if _, err := f.svc.Reveal(f.ctx, adminA, plat.ID); !isNotFound(err) {
		t.Fatalf("an organization revealed a platform secret: %v", err)
	}
	if _, err := f.svc.Update(f.ctx, adminA, plat.ID, ChannelInput{Name: ptr("x")}); !isNotFound(err) {
		t.Fatalf("an organization renamed a platform channel: %v", err)
	}
	// Super administrators see who it is shared with. Unsharing drops what was pending for that organization only.
	d1 := f.queue(plat, f.orgA, nil, f.clock)
	d2 := f.queue(plat, f.orgB, nil, f.clock)
	all, _ := f.svc.List(f.ctx, f.super(), nil)
	for _, c := range all {
		if c.ID == plat.ID && (len(c.SharedWith) != 1 || c.SharedWith[0].OrganizationID != f.orgA || c.Pending != 2) {
			t.Fatalf("%+v", c)
		}
	}
	if err := f.svc.Unshare(f.ctx, f.super(), plat.ID, f.orgA); err != nil {
		t.Fatal(err)
	}
	if f.status(d1) != StatusDropped || f.status(d2) != StatusPending {
		t.Fatalf("after unsharing: %s %s", f.status(d1), f.status(d2))
	}
	list, _ = f.svc.List(f.ctx, adminA, &f.orgA)
	if len(list) != 1 {
		t.Fatal("the unshared channel is still listed")
	}
	if n := f.n(`SELECT count(*) FROM audit_log WHERE action IN ('notification_channel.share', 'notification_channel.unshare')`); n != 2 {
		t.Fatalf("%d share records", n)
	}
	// Turning a channel off, then deleting it, drops what was pending.
	if _, err := f.svc.Update(f.ctx, f.super(), plat.ID, ChannelInput{Enabled: ptr(false)}); err != nil {
		t.Fatal(err)
	}
	if f.status(d2) != StatusDropped {
		t.Fatalf("turned off: %s", f.status(d2))
	}
	if res, err := f.svc.Test(f.ctx, f.super(), plat.ID); err == nil {
		t.Fatalf("a channel that is off was tested: %+v", res)
	}
	d3 := f.queue(mine, f.orgA, nil, f.clock)
	if err := f.svc.Delete(f.ctx, adminA, mine.ID); err != nil {
		t.Fatal(err)
	}
	if f.n(`SELECT count(*) FROM notification_deliveries WHERE id = $1`, d3) != 0 {
		t.Fatal("a pending delivery outlived its channel")
	}
	if f.n(`SELECT count(*) FROM notification_channels WHERE id = $1`, mine.ID) != 0 {
		t.Fatal("not deleted")
	}
	// Validation.
	for _, in := range []ChannelInput{
		{OrganizationID: &f.orgA, Kind: KindEmail, Name: ptr(""), Recipients: []string{"a@example.com"}},
		{OrganizationID: &f.orgA, Kind: KindEmail, Name: ptr(strings.Repeat("n", 101)), Recipients: []string{"a@example.com"}},
		{OrganizationID: &f.orgA, Kind: KindEmail, Name: ptr("n"), Recipients: nil},
		{OrganizationID: &f.orgA, Kind: KindEmail, Name: ptr("n"), Recipients: []string{"not an address"}},
		{OrganizationID: &f.orgA, Kind: "slack", Name: ptr("n"), URL: ptr("https://hooks.slack.com/x")},
		{OrganizationID: &f.orgA, Kind: KindWebhook, Name: ptr("n"), URL: ptr("http://hooks.example.com/x")},
		{OrganizationID: &f.orgA, Kind: KindWebhook, Name: ptr("n"), URL: ptr("https://u:p@hooks.example.com/x")},
		{OrganizationID: &f.orgA, Kind: KindWebhook, Name: ptr("n"), URL: ptr("https://hooks.example.com/x"), TrustedAuthority: ptr(pemBlock("PRIV" + "ATE KEY"))},
	} {
		if _, err := f.svc.Create(f.ctx, adminA, in); err == nil {
			t.Errorf("accepted %+v", in)
		}
	}
	many := make([]string, 21)
	for i := range many {
		many[i] = "u" + strconv.Itoa(i) + "@example.com"
	}
	if _, err := f.svc.Create(f.ctx, adminA, ChannelInput{OrganizationID: &f.orgA, Kind: KindEmail, Name: ptr("many"), Recipients: many}); err == nil {
		t.Error("21 recipients accepted")
	}
	if _, err := f.svc.Create(f.ctx, adminA, ChannelInput{OrganizationID: &f.orgA, Kind: KindEmail, Name: ptr("dup"), Recipients: []string{"a@example.com"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.Create(f.ctx, adminA, ChannelInput{OrganizationID: &f.orgA, Kind: KindEmail, Name: ptr("DUP"), Recipients: []string{"a@example.com"}}); !errors.Is(err, ErrNameTaken) {
		t.Fatalf("duplicate name: %v", err)
	}
}

func TestAnEmailChannelsTestArrivesInMailpit(t *testing.T) {
	f := newFx(t)
	admin := f.orgAdmin(f.orgA)
	to := f.mp.Address("notify")
	second := f.mp.Address("second")
	ch, err := f.svc.Create(f.ctx, admin, ChannelInput{OrganizationID: &f.orgA, Kind: KindEmail, Name: ptr("people"), Recipients: []string{to, second, testmail.Refused}})
	if err != nil {
		t.Fatal(err)
	}
	res, err := f.svc.Test(f.ctx, admin, ch.ID)
	if err != nil {
		t.Fatal(err)
	}
	f.svc.SendDue(f.ctx)
	res = f.svc.awaitTest(f.ctx, f.orgA, res.DeliveryID)
	// One recipient's refusal is permanent for that recipient only; the others got theirs.
	if res.Status != StatusSent {
		t.Fatalf("test: %+v", res)
	}
	for _, addr := range []string{to, second} {
		msgs := f.mp.Wait(addr, 1)
		if len(msgs) != 1 || msgs[0].Subject != "EasyRMM test notification" {
			t.Fatalf("%s: %+v", addr, msgs)
		}
		raw := f.mp.Raw(msgs[0].ID)
		if !strings.Contains(raw, "This is a test notification from EasyRMM") || strings.Contains(raw, "people") {
			t.Fatalf("message text:\n%s", raw)
		}
		wantID := "<" + messageKey(res.DeliveryID, addr) + "@"
		if !strings.Contains(raw, "Message-ID: "+wantID) {
			t.Fatalf("Message-ID is not made from the delivery and the recipient:\n%s", raw)
		}
	}
	log, err := f.svc.Deliveries(f.ctx, admin, nil, &ch.ID, "", 10)
	if err != nil || len(log) != 1 {
		t.Fatalf("%v %v", log, err)
	}
	st := map[string]string{}
	for _, r := range log[0].Recipients {
		st[r.Recipient] = r.Status
	}
	if st[to] != StatusSent || st[second] != StatusSent || st[testmail.Refused] != StatusFailed {
		t.Fatalf("recipient outcomes %v", st)
	}
	// The mail server's own reply is for super administrators only.
	if log[0].MailReply != "" {
		t.Fatalf("an organization sees the mail server's reply: %q", log[0].MailReply)
	}
	sup, _ := f.svc.Deliveries(f.ctx, f.super(), nil, &ch.ID, "", 10)
	if len(sup) != 1 || sup[0].MailReply == "" {
		t.Fatalf("super administrators do not see the reply: %+v", sup)
	}
}

func TestAnEmailRetryGoesToTheRecipientsNotYetAccepted(t *testing.T) {
	f := newFx(t)
	to, later := f.mp.Address("kept"), f.mp.Address("later")
	ch, err := f.svc.Create(f.ctx, f.super(), ChannelInput{Kind: KindEmail, Name: ptr("mail"), Recipients: []string{to, later}})
	if err != nil {
		t.Fatal(err)
	}
	id := f.queue(ch, uuid.Nil, nil, f.clock)
	// One recipient is already accepted: a retry never sends to it again.
	f.exec(`UPDATE notification_delivery_recipients SET status = 'sent', sent_at = now() WHERE delivery_id = $1 AND recipient = $2`, id, to)
	f.svc.SendDue(f.ctx)
	if got := f.mp.Received(to); len(got) != 0 {
		t.Fatalf("an accepted recipient got it again: %d", len(got))
	}
	if got := f.mp.Wait(later, 1); len(got) != 1 {
		t.Fatal("the pending recipient got nothing")
	}
	if f.status(id) != StatusSent {
		t.Fatalf("status %s", f.status(id))
	}
}

func TestEmailWithoutAMailServerWaits(t *testing.T) {
	f := newFx(t)
	if _, err := f.mail.Delete(f.ctx, audit.SystemActor("test")); err != nil {
		t.Fatal(err)
	}
	ch, err := f.svc.Create(f.ctx, f.super(), ChannelInput{Kind: KindEmail, Name: ptr("mail"), Recipients: []string{"a@example.com"}})
	if err != nil {
		t.Fatal(err)
	}
	id := f.queue(ch, uuid.Nil, nil, f.clock)
	f.svc.SendDue(f.ctx)
	if f.status(id) != StatusPending {
		t.Fatalf("status %s", f.status(id))
	}
	if e := f.str(`SELECT last_error FROM notification_deliveries WHERE id = $1`, id); !strings.Contains(e, "mail server") {
		t.Fatalf("error %q", e)
	}
}

func TestMailCircuitPausesEmailAndNotWebhooks(t *testing.T) {
	f := newFx(t)
	for i := range 5 {
		f.svc.circuitRecord(true, false)
		if f.svc.mailPaused() != (i == 4) {
			t.Fatalf("after %d failures: paused %v", i+1, f.svc.mailPaused())
		}
	}
	f.advance(61 * time.Second)
	if f.svc.mailPaused() {
		t.Fatal("still paused after a minute")
	}
	f.svc.circuitRecord(true, false)
	if f.svc.circuit.pause != 2*time.Minute {
		t.Fatalf("pause %v, want doubled", f.svc.circuit.pause)
	}
	f.svc.circuitRecord(false, true)
	if f.svc.circuit.fails != 0 || f.svc.circuit.pause != 0 {
		t.Fatal("a success did not close the circuit")
	}
	for range 10 {
		f.svc.circuitRecord(true, false)
	}
	if f.svc.circuit.pause != 15*time.Minute {
		t.Fatalf("pause %v, want the 15 minute cap", f.svc.circuit.pause)
	}
	// Paused, email is not picked; webhooks go on.
	f.svc.circuitRecord(true, false)
	picked := f.svc.pick([]candidate{{channel: uuid.New(), class: classEmail}, {channel: uuid.New(), class: classWebhook}})
	if len(picked) != 1 || picked[0].class != classWebhook {
		t.Fatalf("picked %+v", picked)
	}
}

func TestFairShare(t *testing.T) {
	f := newFx(t)
	var cands []candidate
	orgs := []uuid.UUID{uuid.New(), uuid.New(), uuid.New(), uuid.Nil}
	for _, o := range orgs {
		for range 5 {
			cands = append(cands, candidate{channel: uuid.New(), charged: o, class: classWebhook})
		}
	}
	got := f.svc.pick(cands)
	per := map[uuid.UUID]int{}
	for _, c := range got {
		per[c.charged]++
	}
	// 2 per organization, 4 for the platform, 8 webhooks in all.
	if len(got) != 8 || per[orgs[0]] != 2 || per[orgs[1]] != 2 || per[orgs[2]] != 2 || per[uuid.Nil] != 2 {
		t.Fatalf("picked %d: %v", len(got), per)
	}
	// One per channel: the same channel twice is picked once.
	f2 := newFx(t)
	ch := uuid.New()
	if got := f2.svc.pick([]candidate{{channel: ch, class: classEmail}, {channel: ch, class: classEmail}}); len(got) != 1 {
		t.Fatalf("one channel picked %d times", len(got))
	}
	// Email is its own class: 4 sessions however many webhooks are in flight.
	var mixed []candidate
	for range 10 {
		mixed = append(mixed, candidate{channel: uuid.New(), charged: uuid.New(), class: classWebhook}, candidate{channel: uuid.New(), charged: uuid.New(), class: classEmail})
	}
	n := map[string]int{}
	for _, c := range f.svc.pick(mixed) {
		n[c.class]++
	}
	// The first pick already holds 8 webhooks and 0 email: the others are 4 email.
	if n[classEmail] != 4 {
		t.Fatalf("email picked %v", n)
	}
}

func TestApprovalLifecycleAndTransportGenerations(t *testing.T) {
	f := newFx(t)
	f.svc.resolve = func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("10.20.30.40")}, nil
	}
	admin := f.orgAdmin(f.orgA)
	ch, err := f.svc.Create(f.ctx, admin, ChannelInput{OrganizationID: &f.orgA, Kind: KindWebhook, Name: ptr("lan"), URL: ptr("https://hooks.lan.example/x?k=sekrit-query")})
	if err != nil {
		t.Fatal(err)
	}
	// The organization may ask; the request proposes the addresses the host resolves to.
	ap, err := f.svc.RequestApproval(f.ctx, admin, ch.ID)
	if err != nil || ap.State != "requested" || len(ap.Proposed) != 1 || ap.Proposed[0] != "10.20.30.40" || ap.Host != "hooks.lan.example" || ap.Port != 443 {
		t.Fatalf("%+v %v", ap, err)
	}
	// The organization cannot approve, and a prefix must hold an address the host resolves to.
	if _, err := f.svc.Approve(f.ctx, admin, ch.ID, []string{"10.20.30.40"}); err == nil {
		t.Fatal("an organization approved its own destination")
	}
	if _, err := f.svc.Approve(f.ctx, f.super(), ch.ID, []string{"10.99.0.0/16"}); err == nil {
		t.Fatal("approved a network that holds no proposed address")
	}
	if _, err := f.svc.Approve(f.ctx, f.super(), ch.ID, []string{"0.0.0.0/0"}); err == nil {
		t.Fatal("approved everything")
	}
	reqs, _ := f.svc.Requests(f.ctx, f.super())
	if len(reqs) != 1 || reqs[0].ChannelID != ch.ID || reqs[0].Name != "lan" {
		t.Fatalf("requests %+v", reqs)
	}
	if _, err := f.svc.Requests(f.ctx, admin); err == nil {
		t.Fatal("an organization lists the requests")
	}
	// The sender's own refusal asks too, and says it is waiting: a delivery fails with "waiting for approval", a notice says so.
	f2 := f
	d := f2.queueOrg(ch)
	f.svc.SendDue(f.ctx)
	if e := f.str(`SELECT last_error FROM notification_deliveries WHERE id = $1`, d); !strings.Contains(e, "Waiting for approval") {
		t.Fatalf("error %q", e)
	}
	if f.n(`SELECT count(*) FROM notices WHERE kind = 'channel_waiting_approval' AND organization_id = $1 AND resolved_at IS NULL`, f.orgA) != 1 {
		t.Fatal("no notice about waiting for approval")
	}
	got, _ := f.svc.Get(f.ctx, admin, ch.ID)
	if got.State != StateWaiting {
		t.Fatalf("state %s", got.State)
	}
	// Approving raises the generation, resolves the notice, and is audited.
	gen := f.n(`SELECT generation FROM notification_channel_details WHERE channel_id = $1`, ch.ID)
	if _, err := f.svc.Approve(f.ctx, f.super(), ch.ID, []string{"10.20.30.0/24"}); err != nil {
		t.Fatal(err)
	}
	if f.n(`SELECT generation FROM notification_channel_details WHERE channel_id = $1`, ch.ID) != gen+1 {
		t.Fatal("approval did not raise the generation")
	}
	if f.n(`SELECT count(*) FROM notices WHERE kind = 'channel_waiting_approval' AND resolved_at IS NULL`) != 0 {
		t.Fatal("the notice stayed open after approval")
	}
	// Changing the host clears the approval; the same host does not.
	if _, err := f.svc.Update(f.ctx, admin, ch.ID, ChannelInput{URL: ptr("https://hooks.lan.example/other")}); err != nil {
		t.Fatal(err)
	}
	if f.n(`SELECT count(*) FROM notification_channel_approvals WHERE channel_id = $1`, ch.ID) != 1 {
		t.Fatal("a new path cleared the approval")
	}
	if _, err := f.svc.Update(f.ctx, admin, ch.ID, ChannelInput{URL: ptr("https://other.lan.example:8443/x")}); err != nil {
		t.Fatal(err)
	}
	if f.n(`SELECT count(*) FROM notification_channel_approvals WHERE channel_id = $1`, ch.ID) != 0 {
		t.Fatal("a new host kept the approval")
	}
	// Withdrawal raises the generation and closes the transport at once.
	if _, err := f.svc.RequestApproval(f.ctx, admin, ch.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.Approve(f.ctx, f.super(), ch.ID, []string{"10.20.30.40"}); err != nil {
		t.Fatal(err)
	}
	f.svc.clientFor(ch.ID, 99, addrpolicy.Policy{Mode: addrpolicy.Organization}, nil) //nolint:errcheck // made to be dropped
	if f.svc.transportCount() != 1 {
		t.Fatal("no transport")
	}
	if err := f.svc.Withdraw(f.ctx, f.super(), ch.ID); err != nil {
		t.Fatal(err)
	}
	if f.svc.transportCount() != 0 {
		t.Fatal("withdrawal left the transport open")
	}
	if n := f.n(`SELECT count(*) FROM audit_log WHERE action LIKE 'notification_channel.approv%'`); n != 5 {
		t.Fatalf("%d approval records, want request, approve, request, approve and withdraw to be audited", n)
	}
	if strings.Contains(f.log.String(), "sekrit-query") {
		t.Fatal("the log holds a URL's query")
	}
}

func (f *fx) queueOrg(ch Channel) uuid.UUID { return f.queue(ch, *ch.OrganizationID, nil, f.clock) }

func TestTransportsAreKeyedByGenerationAndEnvironment(t *testing.T) {
	f := newFx(t)
	id := uuid.New()
	pol := addrpolicy.Policy{Mode: addrpolicy.Organization}
	c1, err := f.svc.clientFor(id, 1, pol, nil)
	if err != nil {
		t.Fatal(err)
	}
	if c2, _ := f.svc.clientFor(id, 1, pol, nil); c2 != c1 {
		t.Fatal("the same generation made a new transport")
	}
	if c3, _ := f.svc.clientFor(id, 2, pol, nil); c3 == c1 {
		t.Fatal("a new generation reused the transport")
	}
	other := uuid.New()
	if co, _ := f.svc.clientFor(other, 1, pol, nil); co == c1 {
		t.Fatal("two channels share a transport")
	}
	f.advance(11 * time.Minute)
	f.svc.sweepTransports()
	if f.svc.transportCount() != 0 {
		t.Fatalf("%d transports after ten idle minutes", f.svc.transportCount())
	}
}

func TestNoticesAreJournaledPlannedAndAcknowledged(t *testing.T) {
	f := newFx(t)
	if err := f.db.InTx(f.ctx, database.System, func(tx pgx.Tx) error {
		return openNotice(f.ctx, tx, &f.orgA, NoticeChannelFailing, "c1", "Channel failing", "why")
	}); err != nil {
		t.Fatal(err)
	}
	if f.n(`SELECT count(*) FROM notification_events WHERE status = 'new'`) != 1 {
		t.Fatal("no journal row")
	}
	// Opening the same notice again only updates it; no second row, no second notice.
	if err := f.db.InTx(f.ctx, database.System, func(tx pgx.Tx) error {
		return openNotice(f.ctx, tx, &f.orgA, NoticeChannelFailing, "c1", "Channel failing", "why again")
	}); err != nil {
		t.Fatal(err)
	}
	if f.n(`SELECT count(*) FROM notices`) != 1 || f.n(`SELECT count(*) FROM notification_events`) != 1 {
		t.Fatal("the same notice was opened twice")
	}
	adminA, adminB := f.orgAdmin(f.orgA), f.orgAdmin(f.orgB)
	ns, err := f.svc.Notices(f.ctx, adminA, &f.orgA, false)
	if err != nil || len(ns) != 1 || ns[0].Detail != "why again" {
		t.Fatalf("%+v %v", ns, err)
	}
	if _, err := f.svc.Notices(f.ctx, adminB, &f.orgA, false); err == nil {
		t.Fatal("another organization reads the notices")
	}
	if err := f.svc.Acknowledge(f.ctx, adminB, ns[0].ID); err == nil {
		t.Fatal("another organization acknowledged the notice")
	}
	if err := f.svc.Acknowledge(f.ctx, adminA, ns[0].ID); err != nil {
		t.Fatal(err)
	}
	if err := f.svc.Acknowledge(f.ctx, adminA, ns[0].ID); err == nil {
		t.Fatal("acknowledged twice")
	}
	if err := f.db.InTx(f.ctx, database.System, func(tx pgx.Tx) error {
		return resolveNotice(f.ctx, tx, &f.orgA, NoticeChannelFailing, "c1")
	}); err != nil {
		t.Fatal(err)
	}
	if got := f.str(`SELECT string_agg(event, ',' ORDER BY id) FROM notification_events`); got != "opened,acknowledged,resolved" {
		t.Fatalf("journal %q", got)
	}
	open, _ := f.svc.Notices(f.ctx, f.super(), nil, false)
	if len(open) != 0 {
		t.Fatalf("%d open notices", len(open))
	}
	all, _ := f.svc.Notices(f.ctx, f.super(), nil, true)
	if len(all) != 1 || all[0].ResolvedAt == nil {
		t.Fatalf("%+v", all)
	}
	// The planner plans each row once; retention removes it after a week.
	if err := f.svc.Plan(f.ctx); err != nil {
		t.Fatal(err)
	}
	if f.n(`SELECT count(*) FROM notification_events WHERE status = 'planned'`) != 3 {
		t.Fatal("rows were not planned")
	}
	f.advance(8 * 24 * time.Hour)
	if err := f.svc.Purge(f.ctx); err != nil {
		t.Fatal(err)
	}
	if f.n(`SELECT count(*) FROM notification_events`) != 0 {
		t.Fatal("planned rows were not purged")
	}
	// Ended deliveries are kept 30 days.
	r := newReceiver(t)
	ch := f.platformHook(r, "keep")
	id := f.queue(ch, uuid.Nil, nil, f.clock)
	f.svc.SendDue(f.ctx)
	f.advance(29 * 24 * time.Hour)
	_ = f.svc.Purge(f.ctx)
	if f.n(`SELECT count(*) FROM notification_deliveries WHERE id = $1`, id) != 1 {
		t.Fatal("purged early")
	}
	f.advance(2 * 24 * time.Hour)
	_ = f.svc.Purge(f.ctx)
	if f.n(`SELECT count(*) FROM notification_deliveries WHERE id = $1`, id) != 0 {
		t.Fatal("not purged after 30 days")
	}
}

func TestHeldServerSendsNothing(t *testing.T) {
	f := newFx(t)
	r := newReceiver(t)
	ch := f.platformHook(r, "held")
	f.queue(ch, uuid.Nil, nil, f.clock)
	f.svc.SetHeld(func() bool { return true })
	ctx, cancel := context.WithTimeout(f.ctx, 3*time.Second)
	defer cancel()
	f.svc.Run(ctx)
	if len(r.got()) != 0 {
		t.Fatal("a held server sent")
	}
	// Released, the worker sends on its own: it takes the lock, and sends.
	f.svc.SetHeld(func() bool { return false })
	ctx2, cancel2 := context.WithTimeout(f.ctx, 8*time.Second)
	defer cancel2()
	go func() {
		for ctx2.Err() == nil && len(r.got()) == 0 {
			time.Sleep(100 * time.Millisecond)
		}
		cancel2()
	}()
	f.svc.Run(ctx2)
	if len(r.got()) != 1 {
		t.Fatalf("the worker sent %d messages", len(r.got()))
	}
}

func TestLegacyHeadersCanOnlyBeTurnedOff(t *testing.T) {
	f := newFx(t)
	r := newReceiver(t)
	ch := f.platformHook(r, "moved")
	f.exec(`UPDATE notification_channel_details SET legacy_headers = true WHERE channel_id = $1`, ch.ID)
	id := f.queue(ch, uuid.Nil, nil, f.clock)
	f.svc.SendDue(f.ctx)
	q := r.got()[0]
	if q.header.Get("X-EasyPatch-Signature") != q.header.Get("X-EasyRMM-Signature") || q.header.Get("X-EasyPatch-Event") != "notices.opened" {
		t.Fatalf("headers %v", q.header)
	}
	_ = id
	if _, err := f.svc.Update(f.ctx, f.super(), ch.ID, ChannelInput{LegacyHeaders: ptr(true)}); err == nil {
		t.Fatal("legacy headers turned on")
	}
	if _, err := f.svc.Update(f.ctx, f.super(), ch.ID, ChannelInput{LegacyHeaders: ptr(false)}); err != nil {
		t.Fatal(err)
	}
	f.queue(ch, uuid.Nil, nil, f.clock)
	f.svc.SendDue(f.ctx)
	if r.got()[1].header.Get("X-EasyPatch-Signature") != "" {
		t.Fatal("still sending the engine's headers")
	}
}

func TestSignMatchesTheEnginesScheme(t *testing.T) {
	at := time.Unix(1_700_000_000, 0)
	got := Sign("secret", at, []byte(`{"a":1}`))
	mac := hmac.New(sha256.New, []byte("secret"))
	mac.Write([]byte("1700000000." + `{"a":1}`))
	if want := "t=1700000000,v1=" + hex.EncodeToString(mac.Sum(nil)); got != want {
		t.Fatalf("%s want %s", got, want)
	}
}

func TestDescribeNeverEchoesAURL(t *testing.T) {
	for _, err := range []error{
		&tlsErr{}, context.DeadlineExceeded, io.EOF, bytes.ErrTooLarge,
	} {
		if got := describe(err, "hooks.example.com"); strings.Contains(got, "http") || got == "" {
			t.Errorf("%v -> %q", err, got)
		}
	}
	_ = tls.VersionTLS12
}

type tlsErr struct{}

func (*tlsErr) Error() string {
	return "tls: failed to verify certificate for https://x/secret?token=1"
}

var _ pgx.Tx

// pemBlock is a PEM block of the given type with a few bytes in it, not a real key.
func pemBlock(kind string) string {
	return "-----BEGIN " + kind + "-----\nMA==\n-----END " + kind + "-----"
}
