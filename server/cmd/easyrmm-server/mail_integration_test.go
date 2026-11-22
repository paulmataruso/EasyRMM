//go:build integration

package main

import (
	"bytes"
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/paulmataruso/easyrmm/server/internal/m365/m365test"
	"github.com/paulmataruso/easyrmm/server/internal/testmail"
)

// TestMain trusts Mailpit's certificate as a system root, as a public mail
// server's would be.
func TestMain(m *testing.M) {
	if err := m365test.Trust(testmail.CA()); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	os.Exit(m.Run())
}

// easyrmm-server mail check signs in to the mail server in force and sends
// nothing: .env's, over STARTTLS with a password, in Mailpit; a wrong
// password, or no mail server at all, exits 1 with why. (Its Microsoft 365
// application, against stand-ins for Microsoft, is app's TestMailCheck.)
func TestMailCheckCommand(t *testing.T) {
	setEnv(t)
	if got := run([]string{"migrate"}); got != 0 {
		t.Fatalf("migrate = %d", got)
	}
	var out, errs bytes.Buffer
	check := func() int {
		out.Reset()
		errs.Reset()
		return mailCommand([]string{"check"}, &out, &errs)
	}
	if got := check(); got != 1 || !strings.Contains(errs.String(), "EasyRMM has no mail server") {
		t.Fatalf("no mail server: %d %q", got, errs.String())
	}

	mp := testmail.Mode(t, testmail.StartTLS)
	t.Setenv("EASYRMM_SMTP_HOST", mp.Host)
	t.Setenv("EASYRMM_SMTP_PORT", strconv.Itoa(mp.Port))
	t.Setenv("EASYRMM_SMTP_USERNAME", mp.Username)
	t.Setenv("EASYRMM_SMTP_PASSWORD", mp.Password)
	t.Setenv("EASYRMM_SMTP_FROM", mp.From)
	t.Setenv("EASYRMM_SMTP_TLS", "starttls")
	if got := check(); got != 0 || !strings.Contains(out.String(), "(STARTTLS) and signed in as "+mp.Username+" with a password: 235 ") {
		t.Fatalf("check: %d %q %q", got, out.String(), errs.String())
	}

	t.Setenv("EASYRMM_SMTP_PASSWORD", "wrong")
	if got := check(); got != 1 || !strings.HasPrefix(errs.String(), "mail check: ") || !strings.Contains(errs.String(), "535") {
		t.Fatalf("a wrong password: %d %q", got, errs.String())
	}
	// A Microsoft 365 application without its secret's file stops at the
	// configuration.
	t.Setenv("EASYRMM_SMTP_USERNAME", "")
	t.Setenv("EASYRMM_SMTP_PASSWORD", "")
	t.Setenv("EASYRMM_SMTP_AUTH", "microsoft365")
	t.Setenv("EASYRMM_SMTP_TENANT_ID", m365test.TenantID)
	t.Setenv("EASYRMM_SMTP_CLIENT_ID", m365test.ClientID)
	if got := check(); got != 1 || !strings.Contains(errs.String(), "needs EASYRMM_SMTP_CLIENT_SECRET_FILE") {
		t.Fatalf("an application without a secret: %d %q", got, errs.String())
	}
}

func TestMailCommandArguments(t *testing.T) {
	var out, errs bytes.Buffer
	for _, args := range [][]string{nil, {"send"}, {"check", "now"}} {
		errs.Reset()
		if got := mailCommand(args, &out, &errs); got != 2 || !strings.Contains(errs.String(), "usage: easyrmm-server mail check") {
			t.Errorf("mail %v = %d %q", args, got, errs.String())
		}
	}
	if got := run([]string{"mail"}); got != 2 {
		t.Errorf("run mail = %d", got)
	}
}
