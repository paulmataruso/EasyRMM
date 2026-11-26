package tlscert

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"path"
	"strings"
	"time"

	"github.com/caddyserver/certmagic"
	"github.com/mholt/acmez/v3/acme"
)

// The account EasyRMM registered or imported is named for every order
// (AccountKeyPEM), so that CertMagic never chooses one, never prompts and
// never reads standard input (ADR-0055). Its key is kept under a key of
// EasyRMM's own; the registration CertMagic keeps under its account keys
// (acme/<CA>/users/<address or "default">/) is the precondition for CertMagic's
// interactive calls, and is checked before any attempt.
func (s *Service) accountKeyName() string {
	return path.Join("easyrmm", "account", certmagic.StorageKeys.Safe(s.issuerKey())+".key")
}

func (s *Service) issuerKey() string { return (&certmagic.ACMEIssuer{CA: s.set.Directory}).IssuerKey() }

func (s *Service) usersPrefix() string {
	return path.Join("acme", certmagic.StorageKeys.Safe(s.issuerKey()), "users")
}

// loadAccountKey returns the account's key, generating one (kept in storage)
// when there is none and the autocert import did not bring one. It does no
// network.
func (s *Service) loadAccountKey(ctx context.Context) ([]byte, error) {
	k, err := s.store.Load(ctx, s.accountKeyName())
	if err == nil {
		return k, nil
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	// The lock keeps two servers starting together from keeping two keys.
	if err := s.store.Lock(ctx, "easyrmm-account-key"); err != nil {
		return nil, err
	}
	defer func() { _ = s.store.Unlock(context.Background(), "easyrmm-account-key") }()
	if k, err := s.store.Load(ctx, s.accountKeyName()); err == nil {
		return k, nil
	}
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	pem, err := certmagic.PEMEncodePrivateKey(priv)
	if err != nil {
		return nil, err
	}
	return pem, s.store.Store(ctx, s.accountKeyName(), pem)
}

func (s *Service) httpClient() *http.Client {
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: s.set.roots()}
	return &http.Client{Transport: t, Timeout: 60 * time.Second}
}

func (st Settings) roots() *x509.CertPool {
	if len(st.RootsPEM) == 0 {
		return nil // the system's roots
	}
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	pool.AppendCertsFromPEM(st.RootsPEM)
	return pool
}

// ensureAccount makes the account usable: it finds the account with the CA
// (an imported one is looked up, which orders and registers nothing; a new
// key is registered first), keeps its registration where CertMagic looks for
// it, and makes it the only account stored for the CA, so that
// mostRecentAccountEmail finds it and the prompt is never reached.
func (s *Service) ensureAccount(ctx context.Context) error {
	s.mu.Lock()
	ready := s.accountReady
	s.mu.Unlock()
	if ready {
		return nil
	}
	key := []byte(s.issuer.AccountKeyPEM)
	acct, err := s.issuer.GetAccount(ctx, key)
	if err != nil && strings.Contains(err.Error(), "accountDoesNotExist") {
		priv, perr := certmagic.PEMDecodePrivateKey(key)
		if perr != nil {
			return perr
		}
		reg := acme.Account{PrivateKey: priv, TermsOfServiceAgreed: true}
		if s.set.Email != "" {
			reg.Contact = []string{"mailto:" + s.set.Email}
		}
		client := &acme.Client{Directory: s.set.Directory, HTTPClient: s.httpClient(), UserAgent: "EasyRMM"}
		if _, rerr := client.NewAccount(ctx, reg); rerr != nil {
			return fmt.Errorf("registering the account: %w", rerr)
		}
		s.audit(ctx, "tls.account_register", "", map[string]any{"directory": s.set.Directory, "contact": s.set.Email != ""}, true)
		acct, err = s.issuer.GetAccount(ctx, key)
	}
	if err != nil {
		return fmt.Errorf("finding the account: %w", err)
	}
	if err := s.onlyAccount(ctx, key); err != nil {
		return err
	}
	s.mu.Lock()
	s.accountReady, s.acctURI = true, acct.Location
	s.mu.Unlock()
	return nil
}

// onlyAccount removes from storage the registrations of any other account for
// this CA (the keys CertMagic may have kept from before, under another
// address), leaving the named one, and checks the way CertMagic looks.
func (s *Service) onlyAccount(ctx context.Context, key []byte) error {
	folders, err := s.store.List(ctx, s.usersPrefix(), false)
	if err != nil {
		return fmt.Errorf("the account is not stored: %w", err)
	}
	keep := ""
	for _, f := range folders {
		files, err := s.store.List(ctx, f, true)
		if err != nil {
			continue
		}
		for _, file := range files {
			if strings.HasSuffix(file, ".key") {
				if k, err := s.store.Load(ctx, file); err == nil && strings.TrimSpace(string(k)) == strings.TrimSpace(string(key)) {
					keep = f
				}
			}
		}
	}
	if keep == "" {
		return errors.New("the account's registration is not stored")
	}
	for _, f := range folders {
		if f != keep {
			if err := s.store.Delete(ctx, f); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *Service) accountURI() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.acctURI
}
