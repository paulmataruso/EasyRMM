//go:build integration

package mailserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/paulmataruso/easyrmm/server/internal/m365"
	"github.com/paulmataruso/easyrmm/server/internal/m365/m365test"
	"github.com/paulmataruso/easyrmm/server/internal/mailer"
	"github.com/paulmataruso/easyrmm/server/internal/testmail"
)

// Signing in with a Microsoft 365 application (ADR-0053, slice 2), against
// stand-ins for Microsoft's token endpoint and Exchange Online (m365test);
// the rest goes through Mailpit.

func TestMain(m *testing.M) {
	// The mailer trusts the system's roots only: the stand-ins' authority
	// and Mailpit's are trusted as theirs.
	if err := m365test.Trust(testmail.CA()); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	os.Exit(m.Run())
}

// microsoft is a stand-in token endpoint, for an application with a secret
// and a certificate, and a stand-in Exchange Online taking its tokens.
type microsoft struct {
	ep              *m365test.TokenEndpoint
	smtp            *m365test.SMTPServer
	certPEM, keyPEM string
}

func newMicrosoft(t *testing.T) *microsoft {
	t.Helper()
	now := time.Now()
	certPEM, keyPEM := m365test.AppCertificate(t, now.Add(-time.Hour), now.Add(365*24*time.Hour))
	ep := m365test.NewTokenEndpoint(t, m365test.ParsePEMCertificate(t, certPEM))
	return &microsoft{ep: ep, smtp: m365test.NewSMTPServer(t, ep.Valid, false), certPEM: certPEM, keyPEM: keyPEM}
}

// appInput is the console's form for the stand-in with the secret.
func (ms *microsoft) appInput() Input {
	return Input{Host: ms.smtp.Host, Port: ms.smtp.Port, Security: mailer.StartTLS, SignIn: SignInMicrosoft365, FromAddress: m365test.Mailbox,
		FromName: "EasyRMM", TenantID: m365test.TenantID, ClientID: m365test.ClientID, Credential: m365.CredentialSecret, ClientSecret: m365test.Secret}
}

func (ms *microsoft) certInput() Input {
	in := ms.appInput()
	in.Credential, in.ClientSecret, in.Certificate, in.CertificateKey = m365.CredentialCertificate, "", ms.certPEM, ms.keyPEM
	return in
}

// The form is checked; what is saved signs in, and is shown, never the
// secret or the key, which are sealed, each to its column.
func TestApplicationSaved(t *testing.T) {
	ms := newMicrosoft(t)
	f := newFixture(t, nil, Authority(ms.ep.URL))
	for field, mutate := range map[string]func(*Input){
		"tenantId":       func(in *Input) { in.TenantID = "contoso" },
		"clientId":       func(in *Input) { in.ClientID = "contoso.onmicrosoft.com" },
		"credential":     func(in *Input) { in.Credential = "password" },
		"clientSecret":   func(in *Input) { in.ClientSecret = "two\nlines" },
		"security":       func(in *Input) { in.Host, in.Security = "localhost", mailer.None },
		"username":       func(in *Input) { in.Username = "rmm" },
		"certificate":    func(in *Input) { in.Certificate = ms.certPEM },
		"certificateKey": func(in *Input) { *in = ms.certInput(); in.CertificateKey = m365test.OtherKey() },
	} {
		in := ms.appInput()
		mutate(&in)
		_, err := f.svc.Update(f.ctx, f.admin, in)
		fieldErr(t, err, field)
	}
	in := ms.certInput()
	in.Certificate = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----"
	_, err := f.svc.Update(f.ctx, f.admin, in)
	fieldErr(t, err, "certificate")
	expiredPEM, _ := m365test.AppCertificate(t, time.Now().Add(-48*time.Hour), time.Now().Add(-24*time.Hour))
	in.Certificate = expiredPEM
	_, err = f.svc.Update(f.ctx, f.admin, in)
	fieldErr(t, err, "certificate")

	v, err := f.svc.Update(f.ctx, f.admin, ms.appInput())
	if err != nil {
		t.Fatal(err)
	}
	a := v.Console.Application
	if v.Console.SignIn != SignInMicrosoft365 || a == nil || a.TenantID != m365test.TenantID || a.ClientID != m365test.ClientID ||
		a.Credential != m365.CredentialSecret || !a.SecretSet || a.Certificate != nil || v.EngineWithheld != EngineWithheld || v.Console.Username != "" {
		t.Fatalf("view %+v %+v", v.Console, a)
	}
	b, _ := json.Marshal(v)
	if strings.Contains(string(b), m365test.Secret) || strings.Contains(f.str(`SELECT client_secret_sealed FROM mail_server`), m365test.Secret) {
		t.Fatal("the secret is shown or stored in the clear")
	}
	if f.str(`SELECT details::text FROM audit_log WHERE action = 'mail_server.update' ORDER BY id DESC LIMIT 1`) == "" ||
		strings.Contains(f.str(`SELECT string_agg(details::text, '') FROM audit_log`), m365test.Secret) {
		t.Fatal("the secret is in the audit log")
	}
	// The sealed secret is bound to its column.
	sealed := f.str(`SELECT client_secret_sealed FROM mail_server`)
	if _, err := f.sealer.Open(sealed, passwordAD); err == nil {
		t.Fatal("the secret opens as the password")
	}
	cfg, err := f.svc.InForce(f.ctx)
	if err != nil || cfg.OAuth == nil || cfg.Username != m365test.Mailbox || cfg.Password != "" || !WithholdsFromEngine(cfg) {
		t.Fatalf("in force: %+v, %v", cfg, err)
	}

	// Kept while the server, the security, the tenant and the application
	// stay the same; asked again otherwise.
	keep := ms.appInput()
	keep.ClientSecret, keep.FromName = "", "EasyRMM mail"
	if _, err := f.svc.Update(f.ctx, f.admin, keep); err != nil {
		t.Fatalf("kept: %v", err)
	}
	for name, mutate := range map[string]func(*Input){
		"another port":        func(in *Input) { in.Port++ },
		"another security":    func(in *Input) { in.Security = mailer.TLS },
		"another tenant":      func(in *Input) { in.TenantID = "m365.example.com" },
		"another application": func(in *Input) { in.ClientID = "00000000-0000-4000-8000-00000000c002" },
		"a certificate":       func(in *Input) { in.Credential, in.Certificate = m365.CredentialCertificate, ms.certPEM },
	} {
		in := keep
		mutate(&in)
		_, err := f.svc.Update(f.ctx, f.admin, in)
		var field string
		if name == "a certificate" {
			field = "certificateKey"
		} else {
			field = "clientSecret"
		}
		fieldErr(t, err, field)
	}

	// A certificate: its key sealed, its thumbprint and dates shown; a
	// renewed certificate on the same key needs no key again.
	v, err = f.svc.Update(f.ctx, f.admin, ms.certInput())
	if err != nil {
		t.Fatal(err)
	}
	a = v.Console.Application
	leaf := m365test.ParsePEMCertificate(t, ms.certPEM)
	if a.Credential != m365.CredentialCertificate || a.SecretSet || a.Certificate == nil || a.Certificate.Thumbprint != m365.CertificateInfo(leaf).Thumbprint ||
		a.CertificateWarning != "" || f.str(`SELECT client_secret_sealed FROM mail_server`) != "" {
		t.Fatalf("certificate: %+v", a)
	}
	if strings.Contains(f.str(`SELECT client_key_sealed FROM mail_server`), "PRIVATE KEY") {
		t.Fatal("the key is stored in the clear")
	}
	soonPEM, _ := m365test.AppCertificate(t, time.Now().Add(-time.Hour), time.Now().Add(10*24*time.Hour))
	renewed := ms.certInput()
	renewed.Certificate, renewed.CertificateKey = soonPEM, ""
	if v, err = f.svc.Update(f.ctx, f.admin, renewed); err != nil {
		t.Fatalf("renewed on the same key: %v", err)
	}
	if w := v.Console.Application.CertificateWarning; !strings.Contains(w, "expires on") || !strings.Contains(w, "in 9 days") {
		t.Fatalf("warning %q", w)
	}
	// Back to a password: the application's columns are emptied.
	if _, err := f.svc.Update(f.ctx, f.admin, f.input()); err != nil {
		t.Fatal(err)
	}
	if s := f.str(`SELECT tenant_id || client_id || client_credential || client_secret_sealed || client_certificate || client_key_sealed FROM mail_server`); s != "" {
		t.Fatalf("left: %q", s)
	}
}

// The test message and account mail sign in with the application's token,
// shared, and the audit log names the application, never its secret.
func TestApplicationSends(t *testing.T) {
	ms := newMicrosoft(t)
	f := newFixture(t, nil, Authority(ms.ep.URL))
	// A form tried before it is saved.
	res, err := f.svc.Test(f.ctx, f.admin, TestInput{To: "someone@example.org", Server: ptr(ms.certInput())})
	if err != nil || !res.OK || !strings.Contains(res.Message, "took the message") {
		t.Fatalf("test: %+v, %v", res, err)
	}
	details := f.str(`SELECT details::text FROM audit_log WHERE action = 'mail_server.test' ORDER BY id DESC LIMIT 1`)
	for _, want := range []string{`"signIn": "microsoft365"`, m365test.TenantID, `"credential": "certificate"`} {
		if !strings.Contains(details, want) {
			t.Fatalf("audit %s lacks %s", details, want)
		}
	}
	if _, err := f.svc.Update(f.ctx, f.admin, ms.appInput()); err != nil {
		t.Fatal(err)
	}
	f.exec(`UPDATE mail_server SET last_test_at = NULL`)
	if res, err := f.svc.Test(f.ctx, f.admin, TestInput{To: "someone@example.org"}); err != nil || !res.OK {
		t.Fatalf("test in force: %+v, %v", res, err)
	}
	msg, _ := mailer.Letter{Subject: "Welcome", Before: []string{"hi"}}.Message()
	if err := f.svc.SendAccountMail(f.ctx, "alice@example.org", msg, mailer.AccountMail{Self: true}); err != nil {
		t.Fatal(err)
	}
	// One token for the secret, kept for every sending since.
	secretRequests := 0
	for _, r := range ms.ep.Requests() {
		if r.Has("client_secret") {
			secretRequests++
		}
	}
	if secretRequests != 1 || len(ms.smtp.Messages()) != 3 {
		t.Fatalf("%d token requests with the secret, %d messages", secretRequests, len(ms.smtp.Messages()))
	}
	// Refused for the rate: account mail is tried again after the wait.
	f.svc.rateRetry = 50 * time.Millisecond
	ms.smtp.Set(func() { ms.smtp.DataReply, ms.smtp.DataReplyTimes = m365test.ThreadLimit, 1 })
	if err := f.svc.SendAccountMail(f.ctx, "bob@example.org", msg, mailer.AccountMail{Self: true}); err != nil {
		t.Fatalf("after a refusal for rate: %v", err)
	}
	// The test message is not: it shows the refusal, explained.
	ms.smtp.Set(func() { ms.smtp.DataReply, ms.smtp.DataReplyTimes = m365test.ThreadLimit, 1 })
	f.exec(`UPDATE mail_server SET last_test_at = NULL`)
	if res, err := f.svc.Test(f.ctx, f.admin, TestInput{To: "someone@example.org"}); err != nil || res.OK || !strings.Contains(res.Message, "at most 3 connections") {
		t.Fatalf("test refused for rate: %+v, %v", res, err)
	}
	// SMTP AUTH off for the mailbox: said so, with the setting.
	ms.smtp.Set(func() { ms.smtp.SignInReply = m365test.AuthOffMailbox })
	f.exec(`UPDATE mail_server SET last_test_at = NULL`)
	if res, err := f.svc.Test(f.ctx, f.admin, TestInput{To: "someone@example.org"}); err != nil || res.OK ||
		!strings.Contains(res.Message, "Set-CASMailbox -Identity <mailbox> -SmtpClientAuthenticationDisabled $false") {
		t.Fatalf("SMTP AUTH off: %+v, %v", res, err)
	}
	all := f.str(`SELECT string_agg(details::text, '') FROM audit_log`) + f.log.String()
	for _, secret := range append(ms.ep.Issued(), m365test.Secret, strings.Split(ms.keyPEM, "\n")[1]) {
		if strings.Contains(all, secret) {
			t.Fatal("a secret, key or token is in the audit log or the log")
		}
	}
}

func ptr[T any](v T) *T { return &v }

// The server checks the mail server in force at start and after a change:
// it signs in and sends nothing, logs the answer, and keeps it for the
// console; with an application, it warns that the patching engine has no
// mail server, and of a certificate near its end.
func TestApplicationChecked(t *testing.T) {
	ms := newMicrosoft(t)
	f := newFixture(t, nil, Authority(ms.ep.URL))
	ctx, cancel := context.WithCancel(f.ctx)
	t.Cleanup(cancel)
	go f.svc.Run(ctx)
	waitCheck := func(step string, ok bool) *CheckResult {
		t.Helper()
		deadline := time.Now().Add(15 * time.Second)
		for {
			if c := f.get().Check; c != nil && c.OK == ok {
				return c
			}
			if time.Now().After(deadline) {
				t.Fatalf("%s: no check: %+v", step, f.get().Check)
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
	if _, err := f.svc.Update(f.ctx, f.admin, ms.appInput()); err != nil {
		t.Fatal(err)
	}
	c := waitCheck("after the change", true)
	if !strings.Contains(c.Message, "signed in to "+m365test.Mailbox+" with a Microsoft 365 application's token") {
		t.Fatalf("check %+v", c)
	}
	for _, s := range ms.smtp.Sessions() {
		if len(s.Messages) != 0 {
			t.Fatal("the check sent a message")
		}
	}
	if !strings.Contains(f.log.String(), "the engine is given no mail server") || !strings.Contains(f.log.String(), "mail server: checked") {
		t.Fatalf("log: %s", f.log.String())
	}
	ms.smtp.Set(func() { ms.smtp.SignInReply = m365test.AuthOffTenant })
	if _, err := f.svc.Update(f.ctx, f.admin, func() Input { i := ms.appInput(); i.FromName = "x"; return i }()); err != nil {
		t.Fatal(err)
	}
	c = waitCheck("refused", false)
	if !strings.Contains(c.Message, "Set-TransportConfig") || !strings.Contains(f.log.String(), "level=ERROR") {
		t.Fatalf("refused: %+v", c)
	}
	// Check, as easyrmm-server mail check does.
	ms.smtp.Set(func() { ms.smtp.SignInReply = "" })
	if answer, err := f.svc.Check(f.ctx); err != nil || !strings.Contains(answer, "235") {
		t.Fatalf("Check: %q, %v", answer, err)
	}
	if _, err := f.svc.Delete(f.ctx, f.admin); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.Check(f.ctx); !errors.Is(err, ErrNoMailServer) {
		t.Fatalf("Check without one: %v", err)
	}
}

// .env's application wins over the console, shown read-only; it signs in
// as .env's sender's mailbox; the console's certificate warning shows for
// it too.
func TestEnvApplication(t *testing.T) {
	ms := newMicrosoft(t)
	soonPEM, keyPEM := m365test.AppCertificate(t, time.Now().Add(-time.Hour), time.Now().Add(20*24*time.Hour))
	cert, err := m365.ParseCertificate(soonPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	env := &mailer.Config{Host: ms.smtp.Host, Port: ms.smtp.Port, Security: mailer.StartTLS, FromAddress: m365test.Mailbox, FromName: "EasyRMM"}
	app := &m365.Credentials{TenantID: m365test.TenantID, ClientID: m365test.ClientID, Certificate: cert}
	ep := m365test.NewTokenEndpoint(t, cert.Leaf)
	ms.smtp.Set(func() { ms.smtp.Valid = ep.Valid })
	f := newFixture(t, env, EnvApplication(app), Authority(ep.URL))
	v := f.get()
	if v.InForce != FromEnv || v.Env.SignIn != SignInMicrosoft365 || v.Env.Application == nil || v.Env.Application.Credential != m365.CredentialCertificate ||
		!strings.Contains(v.Env.Application.CertificateWarning, "in 19 days") || v.EngineWithheld != EngineWithheld {
		t.Fatalf("view %+v", v.Env)
	}
	if _, err := f.svc.Update(f.ctx, f.admin, ms.appInput()); !errors.Is(err, ErrFromEnv) {
		t.Fatalf("update: %v", err)
	}
	if res, err := f.svc.Test(f.ctx, f.admin, TestInput{To: "someone@example.org"}); err != nil || !res.OK {
		t.Fatalf("test: %+v, %v", res, err)
	}
	f.svc.checkInForce(f.ctx, true)
	if c := f.get().Check; c == nil || !c.OK {
		t.Fatalf("check %+v", c)
	}
	if !strings.Contains(f.log.String(), "in 19 days") || !strings.Contains(f.log.String(), "the engine is given no mail server") {
		t.Fatalf("log %s", f.log.String())
	}
	// Half an application, or one without its host, does not start.
	if _, err := New(f.db, f.audit, f.sealer, env, f.svc.log, EnvApplication(&m365.Credentials{TenantID: "x", ClientID: m365test.ClientID, Secret: "s"})); err == nil {
		t.Fatal("a bad tenant started")
	}
	if _, err := New(f.db, f.audit, f.sealer, nil, f.svc.log, EnvApplication(app)); err == nil {
		t.Fatal("an application without a host started")
	}
	noTLS := *env
	noTLS.Host, noTLS.Security = "localhost", mailer.None
	if _, err := New(f.db, f.audit, f.sealer, &noTLS, f.svc.log, EnvApplication(app)); err == nil {
		t.Fatal("an application without TLS started")
	}
}
