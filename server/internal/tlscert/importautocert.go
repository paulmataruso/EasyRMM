package tlscert

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"

	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/caddyserver/certmagic"
)

const importMarker = "easyrmm/import/autocert"

// importAutocert moves what autocert kept in <data dir>/acme into storage,
// once, under the storage lock: the account's key (acme_account+key), and the
// ECDSA certificate of every managed name still valid (the entries named
// after the name alone; the +rsa and +token entries are skipped). It orders
// nothing and registers no account. The directory stays in place, so that a
// rollback (ADR-0052) still finds it. It returns the names imported.
func (s *Service) importAutocert(ctx context.Context) ([]string, error) {
	if s.store.Exists(ctx, importMarker) {
		return nil, nil
	}
	if err := s.store.Lock(ctx, "easyrmm-import"); err != nil {
		return nil, err
	}
	defer func() { _ = s.store.Unlock(context.Background(), "easyrmm-import") }()
	if s.store.Exists(ctx, importMarker) {
		return nil, nil
	}
	var imported []string
	if dir := s.set.AutocertDir; dir != "" {
		if _, err := os.Stat(dir); err == nil {
			if raw, err := os.ReadFile(filepath.Join(dir, "acme_account+key")); err == nil && !s.store.Exists(ctx, s.accountKeyName()) {
				// autocert wrote the account's key as PEM; CertMagic wants the
				// same encoding, decoded and encoded again to be sure of it.
				if priv, err := certmagic.PEMDecodePrivateKey(raw); err == nil {
					if p, err := certmagic.PEMEncodePrivateKey(priv); err == nil {
						if err := s.store.Store(ctx, s.accountKeyName(), p); err != nil {
							return nil, err
						}
					}
				}
			}
			for _, name := range s.set.Names {
				if strings.ContainsAny(name, `/\`) {
					continue
				}
				raw, err := os.ReadFile(filepath.Join(dir, name))
				if err != nil {
					continue
				}
				ok, err := s.importOne(ctx, name, raw)
				if err != nil {
					return imported, err
				}
				if ok {
					imported = append(imported, name)
				}
			}
		}
	}
	if err := s.store.Store(ctx, importMarker, []byte(time.Now().UTC().Format(time.RFC3339))); err != nil {
		return imported, err
	}
	return imported, nil
}

// importOne reads autocert's cache entry: the private key's PEM, then the
// certificate chain's. It imports only a valid ECDSA certificate for the
// name whose key matches, and only where storage has none.
func (s *Service) importOne(ctx context.Context, name string, raw []byte) (bool, error) {
	var keyPEM, chain []byte
	var leaf *x509.Certificate
	rest := raw
	for {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			break
		}
		switch {
		case strings.HasSuffix(b.Type, "PRIVATE KEY") && keyPEM == nil:
			keyPEM = pem.EncodeToMemory(b)
		case b.Type == "CERTIFICATE":
			chain = append(chain, pem.EncodeToMemory(b)...)
			if leaf == nil {
				c, err := x509.ParseCertificate(b.Bytes)
				if err != nil {
					return false, nil
				}
				leaf = c
			}
		}
	}
	if keyPEM == nil || leaf == nil {
		return false, nil
	}
	priv, err := certmagic.PEMDecodePrivateKey(keyPEM)
	if err != nil {
		return false, nil
	}
	ek, ok := priv.(*ecdsa.PrivateKey)
	if !ok || !ek.PublicKey.Equal(leaf.PublicKey) {
		return false, nil
	}
	if time.Now().After(leaf.NotAfter) || leaf.VerifyHostname(name) != nil {
		return false, nil
	}
	ik := s.issuerKey()
	if s.store.Exists(ctx, certmagic.StorageKeys.SiteCert(ik, name)) {
		return false, nil
	}
	pkPEM, err := certmagic.PEMEncodePrivateKey(priv)
	if err != nil {
		return false, err
	}
	meta, _ := json.Marshal(map[string]any{"sans": []string{name}})
	for _, kv := range []struct {
		k string
		v []byte
	}{
		{certmagic.StorageKeys.SitePrivateKey(ik, name), pkPEM},
		{certmagic.StorageKeys.SiteMeta(ik, name), meta},
		{certmagic.StorageKeys.SiteCert(ik, name), bytes.TrimSpace(chain)}, // the .crt last: it announces the name
	} {
		if err := s.store.Store(ctx, kv.k, kv.v); err != nil {
			return false, err
		}
	}
	return true, nil
}
