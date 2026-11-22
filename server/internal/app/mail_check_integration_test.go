//go:build integration

package app

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/paulmataruso/easyrmm/server/internal/config"
	"github.com/paulmataruso/easyrmm/server/internal/m365/m365test"
	"github.com/paulmataruso/easyrmm/server/internal/testdb"
	"github.com/paulmataruso/easyrmm/server/internal/testmail"
)

// TestMain trusts Mailpit's certificate and the stand-ins for Microsoft's
// as system roots, as a public mail server's and Microsoft's would be.
func TestMain(m *testing.M) {
	if err := m365test.Trust(testmail.CA()); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	os.Exit(m.Run())
}

// easyrmm-server mail check with .env's Microsoft 365 application, against
// stand-ins for Microsoft's token endpoint and Exchange Online: it gets a
// token, signs in with it and quits, sending nothing; with the secret, then
// with the certificate; a refused secret says why.
func TestMailCheck(t *testing.T) {
	now := time.Now()
	certPEM, keyPEM := m365test.AppCertificate(t, now.Add(-time.Hour), now.Add(365*24*time.Hour))
	ep := m365test.NewTokenEndpoint(t, m365test.ParsePEMCertificate(t, certPEM))
	exchange := m365test.NewSMTPServer(t, ep.Valid, false)
	m365Authority = ep.URL
	t.Cleanup(func() { m365Authority = "" })

	inst := testdb.New(t)
	cfg := runConfig(t, inst)
	cfg.SMTP = config.SMTPConfig{Host: exchange.Host, Port: exchange.Port, From: "EasyRMM <" + m365test.Mailbox + ">", TLS: "starttls",
		Auth: config.SMTPAuthMicrosoft365, TenantID: m365test.TenantID, ClientID: m365test.ClientID,
		ClientSecret: m365test.Secret + "\n", ClientSecretFile: "/run/secrets/easyrmm/smtp-client-secret"}
	ctx := context.Background()
	var out bytes.Buffer
	if err := MailCheck(ctx, cfg, discard(), &out); err != nil {
		t.Fatal(err)
	}
	if want := "and signed in to " + m365test.Mailbox + " with a Microsoft 365 application's token: 235 "; !strings.Contains(out.String(), want) {
		t.Fatalf("check: %q", out.String())
	}
	sessions := exchange.Sessions()
	if len(sessions) != 1 || sessions[0].User != m365test.Mailbox || !slices.Equal(sessions[0].AuthOverTLS, []bool{true}) || len(sessions[0].Messages) != 0 ||
		!sessions[0].Quit || len(ep.Issued()) != 1 || sessions[0].Token != ep.Issued()[0] {
		t.Fatalf("sessions %+v, tokens %d", sessions, len(ep.Issued()))
	}

	// The certificate, its assertion signed with the key.
	cfg.SMTP.ClientSecret, cfg.SMTP.ClientSecretFile = "", ""
	cfg.SMTP.ClientCert, cfg.SMTP.ClientCertFile = certPEM, "/run/secrets/easyrmm/smtp-client.crt"
	cfg.SMTP.ClientKey, cfg.SMTP.ClientKeyFile = keyPEM, "/run/secrets/easyrmm/smtp-client.key"
	out.Reset()
	if err := MailCheck(ctx, cfg, discard(), &out); err != nil || !strings.Contains(out.String(), "with a Microsoft 365 application's token") {
		t.Fatalf("certificate: %q, %v", out.String(), err)
	}
	if reqs := ep.Requests(); len(reqs) != 2 || reqs[1].Get("client_assertion") == "" || reqs[1].Get("client_secret") != "" {
		t.Fatalf("token requests %v", reqs)
	}

	// A secret Entra refuses: no sign-in is tried, and the answer says what
	// to fix.
	cfg.SMTP.ClientCert, cfg.SMTP.ClientCertFile, cfg.SMTP.ClientKey, cfg.SMTP.ClientKeyFile = "", "", "", ""
	cfg.SMTP.ClientSecret, cfg.SMTP.ClientSecretFile = m365test.Secret, "/run/secrets/easyrmm/smtp-client-secret"
	ep.Set(func() { ep.Refuse = &m365test.BadSecret })
	err := MailCheck(ctx, cfg, discard(), &out)
	if err == nil || !strings.Contains(err.Error(), "AADSTS7000215") || !strings.Contains(err.Error(), "not its Secret ID") ||
		slices.ContainsFunc(exchange.Sessions()[2:], func(s m365test.Session) bool { return len(s.AuthOverTLS) > 0 }) {
		t.Fatalf("a refused secret: %v", err)
	}

	// An unusable application stops it before anything is reached.
	cfg.SMTP.ClientID = "not-a-guid"
	if err := MailCheck(ctx, cfg, discard(), &out); err == nil || !strings.Contains(err.Error(), "EASYRMM_SMTP_*") {
		t.Fatalf("a bad application: %v", err)
	}
	cfg.DatabaseURL = "postgres://%zz"
	if err := MailCheck(ctx, cfg, discard(), &out); err == nil {
		t.Fatal("a bad database URL accepted")
	}
}
