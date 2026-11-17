// Package pki is the server's own certificate authority (ADR-0016). It
// serves HTTPS where no publicly trusted certificate can exist: connections
// to an IP address, and servers run without DNS.
//
// The authority's certificate is stable for ten years, so browsers that
// trust it keep trusting the server. The server's key is stable too, so the
// public-key pin in an install command stays valid when the certificate is
// renewed or its addresses change. The server certificate itself is stored
// and survives restarts: MeshAgent pins the exact certificate it sees.
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
	"encoding/asn1"
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
	// certSetting holds the server certificate (public, so not sealed).
	certSetting = "tls.internal_cert"

	caLifetime   = 10 * 365 * 24 * time.Hour
	leafLifetime = 365 * 24 * time.Hour
	// renewBefore is how long before expiry the server certificate is renewed.
	renewBefore = 30 * 24 * time.Hour
)

// stored is the sealed settings value.
type stored struct {
	Sealed string `json:"sealed"`
}

// storedCert is the server certificate's settings value.
type storedCert struct {
	Cert []byte `json:"cert"` // DER
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
	// db stores the server certificate; nil for an authority kept in memory.
	db *database.DB

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
	a, err := fromMaterial(m, time.Now)
	if err != nil {
		return nil, err
	}
	a.db = db
	return a, nil
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
// covers. It serves the certificate an earlier start stored while that one
// covers the same addresses and is not due for renewal; otherwise it issues
// one (with the same key) and stores it. A restart must not change the
// certificate: MeshAgent pins the exact certificate it sees, and MeshCentral
// re-reads it at most every two minutes, holding the connection of every
// agent that saw another until then.
func (a *Authority) SetAddresses(ctx context.Context, names []string, ips []net.IP) error {
	names = normalizeNames(names)
	ips = normalizeIPs(ips)
	a.mu.Lock()
	defer a.mu.Unlock()
	if slices.Equal(names, a.names) && slices.EqualFunc(ips, a.ips, net.IP.Equal) && a.leaf != nil {
		return nil
	}
	a.names, a.ips = names, ips
	if a.db == nil {
		return a.issueLocked()
	}
	return a.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		// FOR UPDATE: servers starting together agree on one certificate.
		c, err := loadCert(ctx, tx, true)
		if err != nil {
			return err
		}
		if c != nil && a.reusableLocked(c) {
			a.useLocked(c)
			return nil
		}
		if err := a.issueLocked(); err != nil {
			return err
		}
		if c != nil {
			return storeCert(ctx, tx, a.leaf.Leaf.Raw)
		}
		tag, err := tx.Exec(ctx, `INSERT INTO settings (key, value) VALUES ($1, $2) ON CONFLICT (key) DO NOTHING`,
			certSetting, storedCert{Cert: a.leaf.Leaf.Raw})
		if err != nil || tag.RowsAffected() == 1 {
			return err
		}
		// Another server stored one first: serve it if it fits.
		if c, err = loadCert(ctx, tx, true); err != nil {
			return err
		}
		if c != nil && a.reusableLocked(c) {
			a.useLocked(c)
			return nil
		}
		return storeCert(ctx, tx, a.leaf.Leaf.Raw)
	})
}

// loadCert reads the stored server certificate; nil when there is none or
// it cannot be read, as a certificate that cannot be read is replaced.
func loadCert(ctx context.Context, tx pgx.Tx, lock bool) (*x509.Certificate, error) {
	q := `SELECT value FROM settings WHERE key = $1`
	if lock {
		q += ` FOR UPDATE`
	}
	var v storedCert
	err := tx.QueryRow(ctx, q, certSetting).Scan(&v)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		var syntax *json.SyntaxError
		if errors.As(err, &syntax) {
			return nil, nil
		}
		return nil, err
	}
	c, err := x509.ParseCertificate(v.Cert)
	if err != nil {
		return nil, nil //nolint:nilerr // replaced, as above
	}
	return c, nil
}

func storeCert(ctx context.Context, tx pgx.Tx, der []byte) error {
	_, err := tx.Exec(ctx, `INSERT INTO settings (key, value) VALUES ($1, $2)
		ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()`, certSetting, storedCert{Cert: der})
	return err
}

// reusableLocked reports whether c is this authority's certificate for this
// key and the current addresses, and is not due for renewal.
func (a *Authority) reusableLocked(c *x509.Certificate) bool {
	pub, ok := c.PublicKey.(*ecdsa.PublicKey)
	now := a.now()
	return ok && pub.Equal(&a.serverKey.PublicKey) &&
		c.CheckSignatureFrom(a.ca) == nil &&
		now.After(c.NotBefore) && now.Before(c.NotAfter.Add(-renewBefore)) &&
		slices.Equal(normalizeNames(c.DNSNames), a.names) &&
		slices.EqualFunc(normalizeIPs(c.IPAddresses), a.ips, net.IP.Equal)
}

func (a *Authority) useLocked(c *x509.Certificate) {
	a.leaf = &tls.Certificate{Certificate: [][]byte{c.Raw, a.ca.Raw}, PrivateKey: a.serverKey, Leaf: c}
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
	a.useLocked(leaf)
	return nil
}

// Certificate returns the server certificate, renewing it when it is close
// to expiry.
func (a *Authority) Certificate() (*tls.Certificate, error) {
	a.mu.Lock()
	renewed := false
	if a.leaf == nil || a.now().After(a.leaf.Leaf.NotAfter.Add(-renewBefore)) {
		if err := a.issueLocked(); err != nil {
			a.mu.Unlock()
			return nil, err
		}
		renewed = true
	}
	leaf := a.leaf
	a.mu.Unlock()
	if renewed && a.db != nil {
		// Stored outside the lock, so that other connections are not held.
		// Should it fail, the next start finds the stored certificate due
		// for renewal and issues another.
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_ = a.db.InTx(ctx, database.System, func(tx pgx.Tx) error { return storeCert(ctx, tx, leaf.Leaf.Raw) })
		cancel()
	}
	return leaf, nil
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

// KeyPin is the server key's pin for the Windows installer: the hex SHA-256
// of the public key itself, the bytes .NET's X509Certificate.GetPublicKey
// returns. PowerShell computes it where it cannot compute curl's pin.
func (a *Authority) KeyPin() string {
	spki, err := x509.MarshalPKIXPublicKey(&a.serverKey.PublicKey)
	if err != nil {
		panic(err) // an ECDSA P-256 key always marshals
	}
	pin, err := SPKIKeyPin(spki)
	if err != nil {
		panic(err) // a SubjectPublicKeyInfo just marshaled parses
	}
	return pin
}

// SPKIKeyPin is the KeyPin of a DER SubjectPublicKeyInfo: the hex SHA-256
// (upper case, as .NET formats it) of its public key bit string.
func SPKIKeyPin(spki []byte) (string, error) {
	var info struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	rest, err := asn1.Unmarshal(spki, &info)
	if err != nil || len(rest) > 0 {
		return "", errors.New("pki: not a SubjectPublicKeyInfo")
	}
	sum := sha256.Sum256(info.PublicKey.Bytes)
	return strings.ToUpper(hex.EncodeToString(sum[:])), nil
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
