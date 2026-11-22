package m365

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/paulmataruso/easyrmm/server/internal/m365/m365test"
)

func TestMain(m *testing.M) {
	// The stand-ins' authority, trusted as the system's roots are.
	if err := m365test.Trust(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	os.Exit(m.Run())
}

func TestValidIDs(t *testing.T) {
	for s, ok := range map[string]bool{
		m365test.TenantID:                       true,
		"00000000-0000-4000-8000-00000000A001":  true,
		"contoso.onmicrosoft.com":               true,
		"m365.example.com":                      true,
		"contoso":                               false,
		"contoso.com.":                          false,
		"contoso.c0m":                           false,
		"-contoso.com":                          false,
		"contoso..com":                          false,
		"contoso.com/../evil":                   false,
		"00000000-0000-4000-8000-00000000a00":   false,
		"":                                      false,
		strings.Repeat("a.", 127) + "com":       false,
		"https://login.microsoftonline.com/foo": false,
	} {
		if ValidTenant(s) != ok {
			t.Errorf("ValidTenant(%q) = %v", s, !ok)
		}
	}
	if !ValidClientID(m365test.ClientID) || ValidClientID("contoso.com") || ValidClientID("{"+m365test.ClientID+"}") {
		t.Error("ValidClientID")
	}
	for s, ok := range map[string]bool{
		m365test.Secret:                  true,
		"":                               false,
		"two\nlines":                     false,
		"tab\there":                      false,
		"nb sp":                          false,
		strings.Repeat("x", MaxSecret+1): false,
		strings.Repeat("x", MaxSecret):   true,
	} {
		if (CheckSecret(s) == nil) != ok {
			t.Errorf("CheckSecret(%q): %v", s, CheckSecret(s))
		}
	}
}

func TestParseCertificate(t *testing.T) {
	now := time.Now()
	certPEM, keyPEM := m365test.AppCertificate(t, now.Add(-time.Hour), now.Add(365*24*time.Hour))
	c, err := ParseCertificate(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	info := c.Info()
	if info.Subject != "CN=EasyRMM mail (stand-in)" || len(info.Thumbprint) != 40 || strings.ToUpper(info.Thumbprint) != info.Thumbprint ||
		!info.NotAfter.Equal(c.Leaf.NotAfter) {
		t.Fatalf("info: %+v", info)
	}
	if Expired(c.Leaf, now) != "" {
		t.Fatal(Expired(c.Leaf, now))
	}
	if !strings.Contains(Expired(c.Leaf, now.Add(366*24*time.Hour)), "expired on") ||
		!strings.Contains(Expired(c.Leaf, now.Add(-2*time.Hour)), "not valid before") {
		t.Fatal("Expired")
	}
	// PKCS #1 works as PKCS #8 does; a chain after the certificate is kept.
	b, _ := pem.Decode([]byte(keyPEM))
	k, _ := x509.ParsePKCS8PrivateKey(b.Bytes)
	pkcs1 := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k.(*rsa.PrivateKey))}))
	other, _ := m365test.AppCertificate(t, now.Add(-time.Hour), now.Add(time.Hour))
	if c, err := ParseCertificate(certPEM+other, "comment\n"+pkcs1); err != nil || c.PEM != certPEM+other {
		t.Fatalf("PKCS #1 with a chain: %v", err)
	}
	// What is kept is the CERTIFICATE blocks encoded anew: not the line
	// endings, the headers or the blank lines given.
	cb, _ := pem.Decode([]byte(certPEM))
	withHeaders := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Headers: map[string]string{"Note": "kept out"}, Bytes: cb.Bytes}))
	given := "\r\n" + strings.ReplaceAll(withHeaders, "\n", "\r\n") + "\n\n"
	if c, err := ParseCertificate(given, keyPEM); err != nil || c.PEM != certPEM {
		t.Fatalf("encoded anew: %v", err)
	}
	// Anything but CERTIFICATE blocks is refused, not stored.
	for name, tc := range map[string]struct{ cert, want string }{
		"OpenSSH key":       {certPEM + junkPEM("OPENSSH PRIVATE KEY", nil), "holds a private key"},
		"another block":     {certPEM + junkPEM("X509 CRL", nil), "block that is not a certificate"},
		"text before":       {"Bag Attributes\n    localKeyID: 01\n" + certPEM, "text outside its PEM blocks"},
		"text after":        {certPEM + "subject=CN = EasyRMM\n", "text outside its PEM blocks"},
		"between":           {certPEM + "issuer=CN = EasyRMM\n" + other, "text outside its PEM blocks"},
		"unreadable first":  {"-----BEGIN CERTIFICATE-----\n!!\n" + certPEM, "does not parse"},
		"a block, unclosed": {certPEM + "-----BEGIN CERTIFICATE-----\nAAAA\n", "does not parse"},
	} {
		if _, err := ParseCertificate(tc.cert, keyPEM); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v, want %q", name, err, tc.want)
		}
		if _, err := ParseCertificateOnly(tc.cert); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s, alone: %v, want %q", name, err, tc.want)
		}
	}
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ecb, _ := x509.MarshalECPrivateKey(ec)
	ec8, _ := x509.MarshalPKCS8PrivateKey(ec)
	small, _ := rsa.GenerateKey(rand.Reader, 1024)
	for name, tc := range map[string]struct{ cert, key, want string }{
		"another key":      {certPEM, m365test.OtherKey(), "not the certificate's"},
		"EC key":           {certPEM, string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: ecb})), "not RSA"},
		"EC key, PKCS #8":  {certPEM, string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: ec8})), "not RSA"},
		"encrypted":        {certPEM, junkPEM("ENCRYPTED PRIVATE KEY", nil), "encrypted"},
		"old encrypted":    {certPEM, junkPEM("RSA PRIVATE KEY", map[string]string{"Proc-Type": "4,ENCRYPTED", "DEK-Info": "AES-128-CBC,00"}), "encrypted"},
		"small key":        {certPEM, string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(small)})), "1024 bits"},
		"no key":           {certPEM, "nothing", "no PEM private key"},
		"bad key":          {certPEM, junkPEM("PRIVATE KEY", nil), "does not parse"},
		"no certificate":   {"nothing", keyPEM, "no PEM certificate"},
		"bad certificate":  {junkPEM("CERTIFICATE", nil), keyPEM, "does not parse"},
		"key in the cert":  {certPEM + keyPEM, keyPEM, "holds a private key"},
		"large cert":       {strings.Repeat("x", MaxCertificate+1), keyPEM, "larger than"},
		"large key":        {certPEM, strings.Repeat("x", MaxKey+1), "larger than"},
		"EC certificate":   {ecCertificate(t, ec), keyPEM, "not RSA"},
		"certificate only": {certPEM, "", "no PEM private key"},
	} {
		if _, err := ParseCertificate(tc.cert, tc.key); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v, want %q", name, err, tc.want)
		}
	}
}

// junkPEM is a PEM block of the type and headers given around three bytes
// that are no key or certificate.
func junkPEM(typ string, headers map[string]string) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: typ, Headers: headers, Bytes: []byte{0, 0, 0}}))
}

func ecCertificate(t *testing.T, key *ecdsa.PrivateKey) string {
	t.Helper()
	tmpl := &x509.Certificate{SerialNumber: bigOne(), NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func TestCredentialsCheck(t *testing.T) {
	now := time.Now()
	certPEM, keyPEM := m365test.AppCertificate(t, now.Add(-time.Hour), now.Add(time.Hour))
	cert, err := ParseCertificate(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	good := Credentials{TenantID: m365test.TenantID, ClientID: m365test.ClientID, Secret: m365test.Secret}
	if err := good.Check(); err != nil || good.Kind() != CredentialSecret {
		t.Fatal(err)
	}
	withCert := Credentials{TenantID: "m365.example.com", ClientID: m365test.ClientID, Certificate: cert}
	if err := withCert.Check(); err != nil || withCert.Kind() != CredentialCertificate {
		t.Fatal(err)
	}
	for name, c := range map[string]Credentials{
		"tenant": {TenantID: "nope", ClientID: m365test.ClientID, Secret: "s"},
		"client": {TenantID: m365test.TenantID, ClientID: "nope", Secret: "s"},
		"both":   {TenantID: m365test.TenantID, ClientID: m365test.ClientID, Secret: "s", Certificate: cert},
		"none":   {TenantID: m365test.TenantID, ClientID: m365test.ClientID},
	} {
		if c.Check() == nil {
			t.Errorf("%s: taken", name)
		}
	}
}

// logBuffer collects a test's log.
type logBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
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

func newSource(cred Credentials) (*Source, *logBuffer) {
	var lb logBuffer
	return NewSource(cred, slog.New(slog.NewTextHandler(&lb, nil))), &lb
}

// A secret gets a token for Exchange Online, which is kept until 5 minutes
// before its end and then renewed; one the mail server refused is dropped.
func TestTokenWithSecret(t *testing.T) {
	ep := m365test.NewTokenEndpoint(t, nil)
	s, lb := newSource(Credentials{TenantID: m365test.TenantID, ClientID: m365test.ClientID, Secret: m365test.Secret, Authority: ep.URL + "/"})
	clock := time.Now()
	s.now = func() time.Time { return clock }
	ctx := context.Background()
	tok, err := s.Token(ctx)
	if err != nil || !ep.Valid(tok) {
		t.Fatalf("token: %q, %v", tok, err)
	}
	f := ep.Requests()[0]
	if f.Get("grant_type") != "client_credentials" || f.Get("scope") != Scope || f.Get("client_id") != m365test.ClientID ||
		f.Get("client_secret") != m365test.Secret || f.Has("client_assertion") {
		t.Fatalf("request: %v", f)
	}
	clock = clock.Add(54*time.Minute + 59*time.Second)
	if again, err := s.Token(ctx); err != nil || again != tok || len(ep.Requests()) != 1 {
		t.Fatalf("within its time: %v, %d requests", err, len(ep.Requests()))
	}
	clock = clock.Add(time.Second)
	renewed, err := s.Token(ctx)
	if err != nil || renewed == tok || len(ep.Requests()) != 2 {
		t.Fatalf("5 minutes before its end: %v, %d requests", err, len(ep.Requests()))
	}
	// A token the mail server refused is dropped; another's is not.
	s.Refused("another")
	if again, _ := s.Token(ctx); again != renewed {
		t.Fatal("dropped for another token")
	}
	s.Refused(renewed)
	if third, err := s.Token(ctx); err != nil || third == renewed || len(ep.Requests()) != 3 {
		t.Fatalf("after a refusal: %v", err)
	}
	// expires_in as a string, as some endpoints answer.
	ep.Set(func() { ep.ExpiresAsString = true })
	s.Refused(ep.Issued()[2])
	if _, err := s.Token(ctx); err != nil {
		t.Fatal(err)
	}
	for _, tk := range ep.Issued() {
		if strings.Contains(lb.String(), tk) {
			t.Fatal("a token is in the log")
		}
	}
}

// Sendings at once wait for one token.
func TestTokenOnceForMany(t *testing.T) {
	ep := m365test.NewTokenEndpoint(t, nil)
	s, _ := newSource(Credentials{TenantID: m365test.TenantID, ClientID: m365test.ClientID, Secret: m365test.Secret, Authority: ep.URL})
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			if _, err := s.Token(context.Background()); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	if n := len(ep.Requests()); n != 1 {
		t.Fatalf("%d requests", n)
	}
}

// A certificate signs a client assertion that the stand-in checks as
// Entra does; each assertion is new.
func TestTokenWithCertificate(t *testing.T) {
	now := time.Now()
	certPEM, keyPEM := m365test.AppCertificate(t, now.Add(-time.Hour), now.Add(time.Hour))
	cert, err := ParseCertificate(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	ep := m365test.NewTokenEndpoint(t, cert.Leaf)
	s, _ := newSource(Credentials{TenantID: m365test.TenantID, ClientID: m365test.ClientID, Certificate: cert, Authority: ep.URL})
	tok, err := s.Token(context.Background())
	if err != nil || !ep.Valid(tok) {
		t.Fatalf("token: %v", err)
	}
	s.Refused(tok)
	if _, err := s.Token(context.Background()); err != nil {
		t.Fatalf("a second assertion: %v", err)
	}
	f := ep.Requests()[0]
	if f.Has("client_secret") || f.Get("client_assertion_type") != "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" {
		t.Fatalf("request: %v", f)
	}
	parts := strings.Split(f.Get("client_assertion"), ".")
	head, _ := base64.RawURLEncoding.DecodeString(parts[0])
	var h map[string]string
	if err := json.Unmarshal(head, &h); err != nil || h["alg"] != "PS256" || h["x5t#S256"] == "" || h["x5t"] != "" {
		t.Fatalf("header: %s", head)
	}
	// A certificate Entra does not have for the application is refused.
	otherPEM, _ := m365test.AppCertificate(t, now.Add(-time.Hour), now.Add(time.Hour))
	other, err := ParseCertificate(otherPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	s2, _ := newSource(Credentials{TenantID: m365test.TenantID, ClientID: m365test.ClientID, Certificate: other, Authority: ep.URL})
	_, err = s2.Token(context.Background())
	var te *TokenError
	if !errors.As(err, &te) || te.Code != "invalid_client" || !strings.Contains(err.Error(), "upload it to the application") {
		t.Fatalf("another certificate: %v", err)
	}
}

// The identity platform's refusals are shown with its error and
// description, on one line, with what to do; never the secret.
func TestTokenRefused(t *testing.T) {
	ep := m365test.NewTokenEndpoint(t, nil)
	for name, tc := range map[string]struct {
		cred Credentials
		want []string
	}{
		"bad secret": {Credentials{TenantID: m365test.TenantID, ClientID: m365test.ClientID, Secret: "wrong-secret-value"},
			[]string{"invalid_client: AADSTS7000215: Invalid client secret provided", "not its Secret ID"}},
		"no tenant": {Credentials{TenantID: "00000000-0000-4000-8000-0000000000ff", ClientID: m365test.ClientID, Secret: m365test.Secret},
			[]string{"invalid_request: AADSTS90002", "Directory (tenant) ID"}},
		"no application": {Credentials{TenantID: m365test.TenantID, ClientID: "00000000-0000-4000-8000-0000000000ff", Secret: m365test.Secret},
			[]string{"unauthorized_client: AADSTS700016", "check both IDs"}},
	} {
		tc.cred.Authority = ep.URL
		s, lb := newSource(tc.cred)
		_, err := s.Token(context.Background())
		var te *TokenError
		if !errors.As(err, &te) {
			t.Fatalf("%s: %v", name, err)
		}
		msg := err.Error()
		for _, w := range tc.want {
			if !strings.Contains(msg, w) {
				t.Errorf("%s: %q lacks %q", name, msg, w)
			}
		}
		if strings.ContainsAny(msg, "\r\n") || strings.Contains(msg, tc.cred.Secret) || strings.Contains(lb.String(), tc.cred.Secret) {
			t.Errorf("%s: %q", name, msg)
		}
		if !strings.Contains(lb.String(), "AADSTS") || !strings.Contains(lb.String(), "level=WARN") {
			t.Errorf("%s: not logged: %s", name, lb.String())
		}
		// One attribute, on one line: the description's line breaks (its
		// Trace ID and Timestamp) are spaces.
		if !strings.Contains(lb.String(), `answer="HTTP `+strconv.Itoa(te.Status)+", "+te.Code+": AADSTS") ||
			strings.Contains(lb.String(), `\r`) || strings.Contains(lb.String(), `\n`) || strings.Count(lb.String(), "\n") != 1 {
			t.Errorf("%s: logged as %q", name, lb.String())
		}
		if logText("a\r\nb\nc") != "a  b c" {
			t.Error("logText")
		}
	}
	ep.Set(func() { ep.Refuse = &m365test.BadSecret })
	s, _ := newSource(Credentials{TenantID: m365test.TenantID, ClientID: m365test.ClientID, Secret: m365test.Secret, Authority: ep.URL})
	if _, err := s.Token(context.Background()); err == nil {
		t.Fatal("refused, a token")
	}
}

// Answers that are not a token are refused, and nothing is followed.
func TestTokenBadAnswers(t *testing.T) {
	for name, tc := range map[string]struct {
		status int
		body   string
		header map[string]string
		want   string
	}{
		"not JSON":       {200, "<html>", nil, "not a token"},
		"no token":       {200, `{"token_type":"Bearer","expires_in":3599}`, nil, "without a usable token"},
		"not bearer":     {200, `{"token_type":"pop","expires_in":3599,"access_token":"x"}`, nil, `"pop" token`},
		"no lifetime":    {200, `{"token_type":"Bearer","access_token":"x"}`, nil, "without its lifetime"},
		"bad lifetime":   {200, `{"token_type":"Bearer","access_token":"x","expires_in":"soon"}`, nil, "without its lifetime"},
		"zero lifetime":  {200, `{"token_type":"Bearer","access_token":"x","expires_in":0}`, nil, "without its lifetime"},
		"error not JSON": {502, "Bad gateway", nil, "(HTTP 502)"},
		"a redirect":     {302, "", map[string]string{"Location": "https://evil.example/token"}, "(HTTP 302)"},
	} {
		srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			for k, v := range tc.header {
				w.Header().Set(k, v)
			}
			w.WriteHeader(tc.status)
			_, _ = w.Write([]byte(tc.body))
		}))
		srv.TLS = m365test.ServerTLS()
		srv.StartTLS()
		s, _ := newSource(Credentials{TenantID: m365test.TenantID, ClientID: m365test.ClientID, Secret: m365test.Secret, Authority: srv.URL})
		if _, err := s.Token(context.Background()); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v, want %q", name, err, tc.want)
		}
		srv.Close()
	}
	// A lifetime longer than a day is held to a day.
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"token_type":"bearer","access_token":"x","expires_in":"999999"}`))
	}))
	srv.TLS = m365test.ServerTLS()
	srv.StartTLS()
	defer srv.Close()
	s, _ := newSource(Credentials{TenantID: m365test.TenantID, ClientID: m365test.ClientID, Secret: m365test.Secret, Authority: srv.URL})
	clock := time.Now()
	s.now = func() time.Time { return clock }
	if _, err := s.Token(context.Background()); err != nil || !s.expires.Equal(clock.Add(24*time.Hour)) {
		t.Fatalf("%v, expires %s", err, s.expires.Sub(clock))
	}
}

// The token endpoint is dialed through netguard: never a link-local
// address, where clouds serve instance metadata; and an unreachable one
// names the host, not the address.
func TestTokenEndpointGuarded(t *testing.T) {
	s, _ := newSource(Credentials{TenantID: m365test.TenantID, ClientID: m365test.ClientID, Secret: m365test.Secret, Authority: "https://169.254.169.254"})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := s.Token(ctx); err == nil || !strings.Contains(err.Error(), "does not connect to 169.254.169.254") {
		t.Fatalf("metadata: %v", err)
	}
	srvClosed := httptest.NewUnstartedServer(http.NotFoundHandler())
	srvClosed.TLS = m365test.ServerTLS()
	srvClosed.StartTLS()
	closedURL := srvClosed.URL
	srvClosed.Close()
	s, _ = newSource(Credentials{TenantID: m365test.TenantID, ClientID: m365test.ClientID, Secret: m365test.Secret, Authority: closedURL})
	if _, err := s.Token(ctx); err == nil || !strings.Contains(err.Error(), "cannot reach 127.0.0.1:") || strings.Contains(err.Error(), "/oauth2/") {
		t.Fatalf("closed: %v", err)
	}
}

func TestCache(t *testing.T) {
	c := NewCache(slog.New(slog.DiscardHandler))
	cred := Credentials{TenantID: m365test.TenantID, ClientID: m365test.ClientID, Secret: m365test.Secret}
	a := c.Source(cred)
	upper := cred
	upper.TenantID, upper.ClientID = strings.ToUpper(cred.TenantID), strings.ToUpper(cred.ClientID)
	if c.Source(upper) != a {
		t.Fatal("the same application, in capitals, has another source")
	}
	other := cred
	other.Secret = "another secret"
	if c.Source(other) == a {
		t.Fatal("another secret shares the source")
	}
	for i := range cacheSize {
		x := cred
		x.Secret = fmt.Sprint("secret ", i)
		c.Source(x)
	}
	if c.Source(cred) == a {
		t.Fatal("kept past the cache's size")
	}
}

func bigOne() *big.Int { return big.NewInt(1) }
