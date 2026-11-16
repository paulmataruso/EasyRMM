// Package pki is the server's own certificate authority (ADR-0016). It
// serves HTTPS where no publicly trusted certificate can exist: connections
// to an IP address, and servers run without DNS.
//
// The authority's certificate is stable for ten years, so browsers that
// trust it keep trusting the server. The server's key is stable too, so the
// public-key pin in an install command stays valid when the certificate is
// renewed or its addresses change.
package pki

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/secrets"
)

const (
	setting = "tls.internal_ca" //nolint:gosec // a settings key, not a credential
	aad     = "easyrmm:" + setting

	caLifetime   = 10 * 365 * 24 * time.Hour
	leafLifetime = 365 * 24 * time.Hour
	// renewBefore is how long before expiry the server certificate is renewed.
	renewBefore = 30 * 24 * time.Hour
)

// stored is the sealed settings value.
type stored struct {
	Sealed string `json:"sealed"`
}

// material is what is sealed: the authority and the server key.
type material struct {
	CACert    []byte `json:"caCert"` // DER
	CAKey     []byte `json:"caKey"`  // PKCS#8
	ServerKey []byte `json:"serverKey"`
}

// Authority issues the server's certificate.
type Authority struct {
	ca        *x509.Certificate
	caKey     *ecdsa.PrivateKey
	serverKey *ecdsa.PrivateKey
	now       func() time.Time

	mu    sync.Mutex
	leaf  *tls.Certificate
	names []string
	ips   []net.IP
}

// Load reads the authority from the settings table, creating it on first
// use. When two servers start at once, the first one stored wins.
func Load(ctx context.Context, db *database.DB, sealer *secrets.Sealer) (*Authority, error) {
	var m material
	err := db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		var raw []byte
		err := tx.QueryRow(ctx, `SELECT value FROM settings WHERE key = $1`, setting).Scan(&raw)
		if errors.Is(err, pgx.ErrNoRows) {
			fresh, err := generate(time.Now())
			if err != nil {
				return err
			}
			value, err := seal(sealer, fresh)
			if err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `INSERT INTO settings (key, value) VALUES ($1, $2) ON CONFLICT (key) DO NOTHING`, setting, value); err != nil {
				return err
			}
			err = tx.QueryRow(ctx, `SELECT value FROM settings WHERE key = $1`, setting).Scan(&raw)
			if err != nil {
				return err
			}
		} else if err != nil {
			return err
		}
		var s stored
		if err := json.Unmarshal(raw, &s); err != nil {
			return fmt.Errorf("pki: reading the stored authority: %w", err)
		}
		plain, err := sealer.Open(s.Sealed, []byte(aad))
		if err != nil {
			return fmt.Errorf("pki: opening the stored authority (was EASYRMM_SECRET_KEY changed without listing the old key in EASYRMM_SECRET_KEYS_PREVIOUS?): %w", err)
		}
		if err := json.Unmarshal(plain, &m); err != nil {
			return fmt.Errorf("pki: reading the stored authority: %w", err)
		}
		if !sealer.NeedsReseal(s.Sealed) {
			return nil
		}
		value, err := seal(sealer, m)
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `UPDATE settings SET value = $2, updated_at = now() WHERE key = $1`, setting, value)
		return err
	})
	if err != nil {
		return nil, err
	}
	return fromMaterial(m, time.Now)
}

// New creates an authority kept only in memory, for tests and tools;
// servers use Load so that the authority, and the trust placed in it, last.
func New() (*Authority, error) {
	m, err := generate(time.Now())
	if err != nil {
		return nil, err
	}
	return fromMaterial(m, time.Now)
}

// seal encrypts the material under the primary secret key.
func seal(sealer *secrets.Sealer, m material) ([]byte, error) {
	plain, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	sealed, err := sealer.Seal(plain, []byte(aad))
	if err != nil {
		return nil, err
	}
	return json.Marshal(stored{Sealed: sealed})
}

// generate creates a new authority and server key.
func generate(now time.Time) (material, error) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return material{}, err
	}
	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return material{}, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial(),
		Subject:               pkix.Name{CommonName: "EasyRMM server CA", Organization: []string{"EasyRMM"}},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(caLifetime),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &caKey.PublicKey, caKey)
	if err != nil {
		return material{}, err
	}
	caPKCS8, err := x509.MarshalPKCS8PrivateKey(caKey)
	if err != nil {
		return material{}, err
	}
	serverPKCS8, err := x509.MarshalPKCS8PrivateKey(serverKey)
	if err != nil {
		return material{}, err
	}
	return material{CACert: caDER, CAKey: caPKCS8, ServerKey: serverPKCS8}, nil
}

func fromMaterial(m material, now func() time.Time) (*Authority, error) {
	ca, err := x509.ParseCertificate(m.CACert)
	if err != nil {
		return nil, fmt.Errorf("pki: authority certificate: %w", err)
	}
	caKey, err := parseKey(m.CAKey)
	if err != nil {
		return nil, fmt.Errorf("pki: authority key: %w", err)
	}
	serverKey, err := parseKey(m.ServerKey)
	if err != nil {
		return nil, fmt.Errorf("pki: server key: %w", err)
	}
	return &Authority{ca: ca, caKey: caKey, serverKey: serverKey, now: now}, nil
}

func parseKey(der []byte) (*ecdsa.PrivateKey, error) {
	k, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, err
	}
	ec, ok := k.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("not an ECDSA key")
	}
	return ec, nil
}

func serial() *big.Int {
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		panic(err) // crypto/rand never fails on supported platforms
	}
	return n
}

// SetAddresses sets the names and IP addresses the server certificate
// covers. The certificate is reissued (with the same key) when they change.
func (a *Authority) SetAddresses(names []string, ips []net.IP) error {
	names = normalizeNames(names)
	ips = normalizeIPs(ips)
	a.mu.Lock()
	defer a.mu.Unlock()
	if slices.Equal(names, a.names) && slices.EqualFunc(ips, a.ips, net.IP.Equal) && a.leaf != nil {
		return nil
	}
	a.names, a.ips = names, ips
	return a.issueLocked()
}

func (a *Authority) issueLocked() error {
	now := a.now()
	notAfter := now.Add(leafLifetime)
	if notAfter.After(a.ca.NotAfter) {
		notAfter = a.ca.NotAfter
	}
	cn := "EasyRMM server"
	if len(a.names) > 0 {
		cn = a.names[0]
	} else if len(a.ips) > 0 {
		cn = a.ips[0].String()
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial(),
		Subject:      pkix.Name{CommonName: cn, Organization: []string{"EasyRMM"}},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     a.names,
		IPAddresses:  a.ips,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, a.ca, &a.serverKey.PublicKey, a.caKey)
	if err != nil {
		return fmt.Errorf("pki: issuing the server certificate: %w", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return err
	}
	a.leaf = &tls.Certificate{Certificate: [][]byte{der, a.ca.Raw}, PrivateKey: a.serverKey, Leaf: leaf}
	return nil
}

// Certificate returns the server certificate, renewing it when it is close
// to expiry.
func (a *Authority) Certificate() (*tls.Certificate, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.leaf == nil || a.now().After(a.leaf.Leaf.NotAfter.Add(-renewBefore)) {
		if err := a.issueLocked(); err != nil {
			return nil, err
		}
	}
	return a.leaf, nil
}

// GetCertificate serves the server certificate for every connection.
func (a *Authority) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return a.Certificate()
}

// CAPEM is the authority's certificate, for browsers and agents to trust.
func (a *Authority) CAPEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: a.ca.Raw})
}

// Fingerprint is the SHA-256 fingerprint of the authority's certificate,
// as browsers and operating systems show it (AB:CD:...).
func (a *Authority) Fingerprint() string {
	sum := sha256.Sum256(a.ca.Raw)
	h := strings.ToUpper(hex.EncodeToString(sum[:]))
	parts := make([]string, 0, len(sum))
	for i := 0; i < len(h); i += 2 {
		parts = append(parts, h[i:i+2])
	}
	return strings.Join(parts, ":")
}

// Pin is the server key's public-key pin in curl's format
// (sha256//<base64 of the SHA-256 of the SubjectPublicKeyInfo>). The key
// never changes, so neither does the pin.
func (a *Authority) Pin() string {
	spki, err := x509.MarshalPKIXPublicKey(&a.serverKey.PublicKey)
	if err != nil {
		panic(err) // an ECDSA P-256 key always marshals
	}
	return SPKIPin(spki)
}

// SPKIPin formats the pin of a DER SubjectPublicKeyInfo.
func SPKIPin(spki []byte) string {
	sum := sha256.Sum256(spki)
	return "sha256//" + base64.StdEncoding.EncodeToString(sum[:])
}

func normalizeNames(names []string) []string {
	out := []string{}
	for _, n := range names {
		n = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(n), "."))
		if n != "" && net.ParseIP(n) == nil && !slices.Contains(out, n) {
			out = append(out, n)
		}
	}
	return out
}

func normalizeIPs(ips []net.IP) []net.IP {
	out := []net.IP{}
	for _, ip := range ips {
		if ip == nil {
			continue
		}
		if v4 := ip.To4(); v4 != nil {
			ip = v4
		}
		if !slices.ContainsFunc(out, ip.Equal) {
			out = append(out, ip)
		}
	}
	return out
}
