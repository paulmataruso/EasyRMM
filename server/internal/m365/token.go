package m365

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/paulmataruso/easyrmm/server/internal/netguard"
)

// renewBefore is how long before a token's end a new one is asked for: a
// token is never sent with less left (ADR-0053).
const renewBefore = 5 * time.Minute

// maxLifetime caps the lifetime a token endpoint gives, so that a token is
// asked for again at least daily.
const maxLifetime = 24 * time.Hour

// requestTimeout bounds one token request, connecting included.
const requestTimeout = 30 * time.Second

// maxBody is the most of the token endpoint's answer read.
const maxBody = 1 << 20

// TokenError is the identity platform refusing a token request: its
// error and error_description, which say why, and the HTTP status.
type TokenError struct {
	Status      int
	Code        string
	Description string
	// Codes are the AADSTS codes in error_codes.
	Codes []int
}

func (e *TokenError) Error() string {
	msg := "Microsoft's identity platform refused the token request"
	if e.Code != "" {
		msg += ": " + e.Code
	} else {
		msg += fmt.Sprintf(" (HTTP %d)", e.Status)
	}
	if e.Description != "" {
		msg += ": " + oneLine(e.Description, 600)
	}
	if h := e.hint(); h != "" {
		msg += ". " + h
	}
	return msg
}

// hint says what to do about the AADSTS codes seen most, "" otherwise.
func (e *TokenError) hint() string {
	has := func(code int) bool {
		for _, c := range e.Codes {
			if c == code {
				return true
			}
		}
		return strings.Contains(e.Description, "AADSTS"+strconv.Itoa(code)+":")
	}
	switch {
	case has(7000215):
		return "The client secret is not the application's: enter the secret's Value from Certificates & secrets, not its Secret ID"
	case has(7000222):
		return "The client secret has expired: make a new one under Certificates & secrets and enter it here"
	case has(700016):
		return "No application with this application (client) ID is in the tenant: check both IDs on the application's Overview page"
	case has(90002), has(900023):
		return "The tenant is not found: enter the Directory (tenant) ID from the application's Overview page"
	case has(700027), has(700024):
		return "The certificate is not accepted: upload it to the application under Certificates & secrets, and check the server's clock"
	case has(7000112):
		return "The application is disabled in the tenant"
	}
	return ""
}

// logText is what the identity platform, or the way to it, said, for the
// log: its line breaks made spaces, so that an answer cannot add lines of
// its own to the log, whatever the log's handler escapes.
func logText(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, "\n", " "), "\r", " ")
}

// oneLine keeps s on one line and to at most n bytes, on a rune boundary.
func oneLine(s string, n int) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) <= n {
		return s
	}
	for n > 0 && s[n]&0xC0 == 0x80 {
		n--
	}
	return s[:n] + "…"
}

// Source gets an application's tokens for Exchange Online and keeps the
// last one, for every sending, until renewBefore its end.
type Source struct {
	cred   Credentials
	client *http.Client
	log    *slog.Logger
	now    func() time.Time

	// mu is held across a request, so that sendings at once wait for one
	// token rather than each ask for their own.
	mu      sync.Mutex
	token   string
	expires time.Time
}

// NewSource makes a source for cred, which Check must have passed. Failed
// requests are logged with Microsoft's error and description, never the
// secret or a token.
func NewSource(cred Credentials, log *slog.Logger) *Source {
	return &Source{cred: cred, client: httpClient(), log: log, now: time.Now}
}

// httpClient reaches the identity platform: through netguard, as the mail
// server is, with no proxy, no redirects and no cookies, TLS 1.2 or later
// against the system's certificate authorities.
func httpClient() *http.Client {
	d := &net.Dialer{Timeout: 10 * time.Second, Control: netguard.Control}
	return &http.Client{
		Timeout: requestTimeout,
		Transport: &http.Transport{
			Proxy:                 nil,
			DialContext:           d.DialContext,
			TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: 20 * time.Second,
			MaxIdleConns:          1,
			IdleConnTimeout:       90 * time.Second,
			ForceAttemptHTTP2:     true,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// Token is a token for Exchange Online: the one kept, or a new one when it
// has less than renewBefore left.
func (s *Source) Token(ctx context.Context) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.token != "" && s.now().Before(s.expires.Add(-renewBefore)) {
		return s.token, nil
	}
	s.token = ""
	token, lifetime, err := s.request(ctx)
	if err != nil {
		var te *TokenError
		if errors.As(err, &te) {
			s.log.Warn("mail server: Microsoft's identity platform refused the token request", "tenant", s.cred.TenantID,
				"client", s.cred.ClientID, "answer", logText(fmt.Sprintf("HTTP %d, %s: %s", te.Status, te.Code, oneLine(te.Description, 600))))
		} else {
			s.log.Warn("mail server: could not get a token from Microsoft's identity platform", "tenant", s.cred.TenantID, "error", logText(err.Error()))
		}
		return "", err
	}
	s.token, s.expires = token, s.now().Add(lifetime)
	return token, nil
}

// Refused drops token, which the mail server refused, so that the next
// Token asks for a new one.
func (s *Source) Refused(token string) {
	s.mu.Lock()
	if s.token == token {
		s.token = ""
	}
	s.mu.Unlock()
}

// tokenAnswer is the token endpoint's answer, a token or an error.
type tokenAnswer struct {
	TokenType   string          `json:"token_type"`
	AccessToken string          `json:"access_token"`
	ExpiresIn   json.RawMessage `json:"expires_in"`
	Error       string          `json:"error"`
	Description string          `json:"error_description"`
	Codes       []int           `json:"error_codes"`
}

// request asks for a token with the client credentials grant.
func (s *Source) request(ctx context.Context) (string, time.Duration, error) {
	form := url.Values{"grant_type": {"client_credentials"}, "client_id": {s.cred.ClientID}, "scope": {Scope}}
	if s.cred.Certificate != nil {
		a, err := s.cred.assertion(s.now(), uuid.NewString())
		if err != nil {
			return "", 0, err
		}
		form.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
		form.Set("client_assertion", a)
	} else {
		form.Set("client_secret", s.cred.Secret)
	}
	endpoint := s.cred.tokenURL()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", 0, errors.New("m365: the tenant makes no valid token address")
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	host := req.URL.Host
	resp, err := s.client.Do(req)
	if err != nil {
		// *url.Error names the URL and the method; only the cause is kept,
		// with the host.
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return "", 0, fmt.Errorf("cannot reach %s: %w", host, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return "", 0, fmt.Errorf("reading the answer of %s: %w", host, err)
	}
	var a tokenAnswer
	jsonErr := json.Unmarshal(body, &a)
	if resp.StatusCode != http.StatusOK {
		if jsonErr != nil {
			return "", 0, &TokenError{Status: resp.StatusCode}
		}
		return "", 0, &TokenError{Status: resp.StatusCode, Code: oneLine(a.Error, 100), Description: a.Description, Codes: a.Codes}
	}
	if jsonErr != nil {
		return "", 0, fmt.Errorf("%s answered with something that is not a token", host)
	}
	lifetime, ok := seconds(a.ExpiresIn)
	switch {
	case a.AccessToken == "" || strings.ContainsAny(a.AccessToken, " \t\r\n\x00\x01"):
		return "", 0, fmt.Errorf("%s answered without a usable token", host)
	case !strings.EqualFold(a.TokenType, "Bearer"):
		return "", 0, fmt.Errorf("%s answered a %q token, not a bearer token", host, oneLine(a.TokenType, 40))
	case !ok:
		return "", 0, fmt.Errorf("%s answered a token without its lifetime (expires_in)", host)
	}
	return a.AccessToken, lifetime, nil
}

// seconds reads expires_in, a number or a string of digits, as a positive
// duration of at most maxLifetime.
func seconds(raw json.RawMessage) (time.Duration, bool) {
	var n json.Number
	if err := json.Unmarshal(raw, &n); err != nil {
		var s string
		if json.Unmarshal(raw, &s) != nil {
			return 0, false
		}
		n = json.Number(s)
	}
	v, err := n.Int64()
	if err != nil || v <= 0 {
		return 0, false
	}
	return time.Duration(min(v, int64(maxLifetime/time.Second))) * time.Second, true
}

// Cache keeps a Source per application, so that every sending with the same
// credentials shares one token, and the mail server in force and a form
// being tried do not take each other's.
type Cache struct {
	log *slog.Logger
	mu  sync.Mutex
	// sources, the most recently used last.
	sources []*cached
}

type cached struct {
	key    cacheKey
	source *Source
}

// cacheKey tells credentials apart. The certificate stands for its key,
// which ParseCertificate checked is its own.
type cacheKey struct {
	authority, tenant, client, secret, certificate string
}

// cacheSize is how many applications' sources are kept.
const cacheSize = 4

// NewCache makes an empty cache.
func NewCache(log *slog.Logger) *Cache { return &Cache{log: log} }

// Source is the source for cred, made the first time.
func (c *Cache) Source(cred Credentials) *Source {
	k := cacheKey{authority: cred.authority(), tenant: strings.ToLower(cred.TenantID), client: strings.ToLower(cred.ClientID), secret: cred.Secret}
	if cred.Certificate != nil {
		k.certificate = string(cred.Certificate.Leaf.Raw)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for i, e := range c.sources {
		if e.key == k {
			c.sources = append(append(c.sources[:i:i], c.sources[i+1:]...), e)
			return e.source
		}
	}
	s := NewSource(cred, c.log)
	if len(c.sources) == cacheSize {
		c.sources = c.sources[1:]
	}
	c.sources = append(c.sources, &cached{key: k, source: s})
	return s
}
