package mailserver

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/m365"
	"github.com/paulmataruso/easyrmm/server/internal/mailer"
)

// Signing in with a Microsoft 365 application (ADR-0053, slice 2): the
// tenant, the application (client) ID, and a client secret or a
// certificate with its private key. The mailbox it sends as is the
// sender's address. The secret and the key are sealed, each bound to its
// column, and never shown again.

// SignInMicrosoft365 signs in with a Microsoft 365 application's token
// (AUTH XOAUTH2).
const SignInMicrosoft365 = "microsoft365"

var (
	clientSecretAD = []byte("mail_server.client_secret")
	clientKeyAD    = []byte("mail_server.client_key")
)

// EngineWithheld is why the patching engine has no mail server while
// EasyRMM's signs in with an application: the engine signs in with a
// password only, until its email moves to EasyRMM's sender (ADR-0053,
// slice 6).
const EngineWithheld = "EasyRMM's mail server signs in with a Microsoft 365 application, which the patching engine cannot do: the engine is given no mail server, so patching sends no email and no monthly reports until a later release moves them to EasyRMM. For patching's email meanwhile, send through a relay, or sign in with a password."

// Application is a Microsoft 365 application as the console shows it,
// never its secret or key.
type Application struct {
	TenantID string `json:"tenantId"`
	ClientID string `json:"clientId"`
	// Credential is secret or certificate.
	Credential string `json:"credential"`
	// SecretSet says a client secret is stored.
	SecretSet   bool       `json:"secretSet"`
	Certificate *m365.Info `json:"certificate,omitempty"`
	// CertificateWarning says the certificate has expired, or does within
	// 30 days.
	CertificateWarning string `json:"certificateWarning,omitempty"`
}

// CheckResult is the last check of the mail server in force on this
// server: connecting and signing in, without sending (Run).
type CheckResult struct {
	At      time.Time `json:"at"`
	OK      bool      `json:"ok"`
	Message string    `json:"message"`
}

// Option configures New.
type Option func(*Service)

// EnvApplication is .env's Microsoft 365 application, which .env's mail
// server signs in with (EASYRMM_SMTP_AUTH=microsoft365).
func EnvApplication(c *m365.Credentials) Option {
	return func(s *Service) { s.envApp = c }
}

// Authority has applications ask for tokens at authority rather than at
// Microsoft's identity platform: tests give their stand-in's.
func Authority(authority string) Option {
	return func(s *Service) { s.authority = authority }
}

// application is r's application as the console shows it, nil when r does
// not sign in with one.
func (r *row) application() *Application {
	if r.signIn != SignInMicrosoft365 {
		return nil
	}
	a := &Application{TenantID: r.tenantID, ClientID: r.clientID, Credential: r.credential, SecretSet: r.secretSealed != ""}
	if leaf, err := m365.ParseCertificateOnly(r.certificate); err == nil {
		info := m365.CertificateInfo(leaf)
		a.Certificate, a.CertificateWarning = &info, m365.Warning(leaf, time.Now())
	}
	return a
}

// envApplication is .env's application as the console shows it.
func envApplication(c *m365.Credentials) *Application {
	a := &Application{TenantID: c.TenantID, ClientID: c.ClientID, Credential: c.Kind(), SecretSet: c.Secret != ""}
	if c.Certificate != nil {
		info := c.Certificate.Info()
		a.Certificate, a.CertificateWarning = &info, m365.Warning(c.Certificate.Leaf, time.Now())
	}
	return a
}

// credentials opens r's application's secret or key.
func (s *Service) credentials(r *row) (*m365.Credentials, error) {
	c := &m365.Credentials{TenantID: r.tenantID, ClientID: r.clientID, Authority: s.authority}
	switch r.credential {
	case m365.CredentialSecret:
		b, err := s.sealer.Open(r.secretSealed, clientSecretAD)
		if err != nil {
			return nil, errors.New("the mail server's stored client secret cannot be opened with this server's secret key; enter it again under Settings → Notifications → Mail server")
		}
		c.Secret = string(b)
	default:
		k, err := s.sealer.Open(r.keySealed, clientKeyAD)
		if err != nil {
			return nil, errors.New("the mail server's stored certificate key cannot be opened with this server's secret key; enter it again under Settings → Notifications → Mail server")
		}
		cert, err := m365.ParseCertificate(r.certificate, string(k))
		if err != nil {
			return nil, fmt.Errorf("the mail server's stored certificate: %w", err)
		}
		c.Certificate = cert
	}
	return c, nil
}

// signInWith has cfg sign in with app's token, as the sender's mailbox.
func (s *Service) signInWith(cfg *mailer.Config, app *m365.Credentials) {
	cfg.Username, cfg.Password, cfg.OAuth = cfg.FromAddress, "", s.tokens.Source(*app)
}

// keepsApplication reports whether in may keep stored's client secret, or
// certificate and key: it signs in to the same host, on the same port,
// with the same security, for the same tenant and application, with the
// same kind of credential.
func keepsApplication(in *Input, stored *row) bool {
	return stored != nil && stored.signIn == SignInMicrosoft365 && strings.EqualFold(stored.host, in.Host) && stored.port == in.Port &&
		stored.security == in.Security && strings.EqualFold(stored.tenantID, in.TenantID) && strings.EqualFold(stored.clientID, in.ClientID) &&
		stored.credential == in.Credential
}

// sentence is an error's message as a sentence.
func sentence(err error) string {
	m := err.Error()
	if m == "" {
		return m
	}
	r := []rune(m)
	r[0] = unicode.ToUpper(r[0])
	return string(r) + "."
}

// checkApplication validates in's application, cleaning it, using the
// stored secret, or certificate and key, when in gives none and
// keepsApplication allows. A certificate given without its key may take
// the stored key, when it is the key's: a renewed certificate.
func (s *Service) checkApplication(f apperr.Fields, in *Input, stored *row) (app *m365.Credentials, keyPEM string) {
	in.TenantID, in.ClientID = strings.TrimSpace(in.TenantID), strings.TrimSpace(in.ClientID)
	in.Certificate, in.CertificateKey = strings.TrimSpace(in.Certificate), strings.TrimSpace(in.CertificateKey)
	switch {
	case in.TenantID == "":
		f.Add("tenantId", "Enter the Directory (tenant) ID from the application's Overview page in Entra.")
	case !m365.ValidTenant(in.TenantID):
		f.Add("tenantId", "Enter the tenant's ID, a GUID, or one of its domain names, such as contoso.onmicrosoft.com.")
	}
	switch {
	case in.ClientID == "":
		f.Add("clientId", "Enter the Application (client) ID from the application's Overview page in Entra.")
	case !m365.ValidClientID(in.ClientID):
		f.Add("clientId", "Enter the Application (client) ID: a GUID, such as 00000000-0000-0000-0000-000000000000.")
	}
	f.Check(in.Security != mailer.None, "security",
		"A Microsoft 365 application signs in only over STARTTLS or TLS: Exchange Online's is smtp.office365.com, port 587, STARTTLS.")
	keep := keepsApplication(in, stored)
	app = &m365.Credentials{TenantID: in.TenantID, ClientID: in.ClientID, Authority: s.authority}
	switch in.Credential {
	case m365.CredentialSecret:
		f.Check(in.Certificate == "" && in.CertificateKey == "", "certificate", "Give a client secret or a certificate, not both.")
		switch {
		case in.ClientSecret != "":
			if err := m365.CheckSecret(in.ClientSecret); err != nil {
				f.Add("clientSecret", "Enter the secret's Value from Certificates & secrets: one line of at most 1,024 characters.")
			}
			app.Secret = in.ClientSecret
		case keep:
			b, err := s.sealer.Open(stored.secretSealed, clientSecretAD)
			if err != nil {
				f.Add("clientSecret", "The stored client secret cannot be opened with this server's secret key. Enter it again.")
			}
			app.Secret = string(b)
		default:
			f.Add("clientSecret", "Enter the client secret's Value. A stored secret is kept only while the server, the port, the security, the tenant and the application stay the same.")
		}
	case m365.CredentialCertificate:
		f.Check(in.ClientSecret == "", "clientSecret", "Give a client secret or a certificate, not both.")
		certPEM, keyPEM := in.Certificate, in.CertificateKey
		if certPEM == "" && keep {
			certPEM = stored.certificate
		}
		if keyPEM == "" && keep {
			k, err := s.sealer.Open(stored.keySealed, clientKeyAD)
			if err != nil {
				f.Add("certificateKey", "The stored private key cannot be opened with this server's secret key. Enter it again.")
				return nil, ""
			}
			keyPEM = string(k)
		}
		switch {
		case certPEM == "":
			f.Add("certificate", "Paste the certificate (PEM) uploaded to the application under Certificates & secrets.")
		case keyPEM == "":
			f.Add("certificateKey", "Paste the certificate's private key (PEM). A stored key is kept only while the server, the port, the security, the tenant and the application stay the same.")
		}
		if certPEM == "" || keyPEM == "" {
			return nil, ""
		}
		leaf, err := m365.ParseCertificateOnly(certPEM)
		if err != nil {
			f.Add("certificate", sentence(err))
			return nil, ""
		}
		cert, err := m365.ParseCertificate(certPEM, keyPEM)
		if err != nil {
			f.Add("certificateKey", sentence(err))
			return nil, ""
		}
		if why := m365.Expired(leaf, time.Now()); why != "" {
			f.Add("certificate", sentence(errors.New(why))+" Make a new one and upload it to the application in Entra.")
		}
		app.Certificate = cert
		return app, keyPEM
	default:
		f.Add("credential", "Choose a client secret or a certificate.")
	}
	return app, ""
}

// lastCheck is the last check's result, under its lock.
type lastCheck struct {
	mu     sync.Mutex
	result *CheckResult
}

func (l *lastCheck) get() *CheckResult {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.result == nil {
		return nil
	}
	r := *l.result
	return &r
}

func (l *lastCheck) set(r *CheckResult) {
	l.mu.Lock()
	l.result = r
	l.mu.Unlock()
}

// checkEvery is how often Run checks the mail server in force, besides at
// start and after a change on this server.
const checkEvery = 24 * time.Hour

// checkTimeout bounds one check.
const checkTimeout = 2 * time.Minute

// Run checks the mail server in force at start, after every change made on
// this server, and daily: it connects and signs in as a message would, and
// quits without sending (as easyrmm-server mail check does), logs the
// answer, and keeps it for the console. While an application signs in, it
// logs at start and after each change that the patching engine is given no
// mail server, and from 30 days before the certificate's end, that it
// ends. It returns when ctx ends.
func (s *Service) Run(ctx context.Context) {
	t := time.NewTicker(checkEvery)
	defer t.Stop()
	changed := true
	for {
		s.checkInForce(ctx, changed)
		select {
		case <-ctx.Done():
			return
		case <-s.kick:
			changed = true
		case <-t.C:
			changed = false
		}
	}
}

// checkInForce checks the mail server in force once; changed says it is
// the first check since the start or a change.
func (s *Service) checkInForce(ctx context.Context, changed bool) {
	ctx, cancel := context.WithTimeout(ctx, checkTimeout)
	defer cancel()
	cfg, app, err := s.inForce(ctx)
	if err == nil && cfg == nil {
		s.checked.set(nil)
		return
	}
	if err == nil {
		if app != nil && changed {
			s.log.Warn("mail server: " + EngineWithheld)
		}
		if app != nil && app.Certificate != nil {
			if w := m365.Warning(app.Certificate.Leaf, time.Now()); w != "" {
				s.log.Warn("mail server: " + w)
			}
		}
		var m *mailer.SMTP
		if m, err = mailer.New(*cfg); err == nil {
			var answer string
			if answer, err = m.Check(ctx); err == nil {
				s.checked.set(&CheckResult{At: time.Now(), OK: true, Message: answer})
				s.log.Info("mail server: checked: " + answer)
				return
			}
		}
	}
	if ctx.Err() != nil && errors.Is(err, context.Canceled) {
		return
	}
	msg := strings.TrimPrefix(err.Error(), "mailer: ")
	s.checked.set(&CheckResult{At: time.Now(), Message: msg})
	s.log.Error("mail server: the check of the mail server in force failed: connecting and signing in, sending nothing", "error", msg)
}

// Check checks the mail server in force once, as Run does, and returns its
// answer: easyrmm-server mail check.
func (s *Service) Check(ctx context.Context) (string, error) {
	cfg, _, err := s.inForce(ctx)
	if err != nil {
		return "", err
	}
	if cfg == nil {
		return "", ErrNoMailServer
	}
	m, err := mailer.New(*cfg)
	if err != nil {
		return "", err
	}
	return m.Check(ctx)
}
