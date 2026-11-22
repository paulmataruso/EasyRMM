// Package m365 signs EasyRMM in to Microsoft 365 for mail (ADR-0053, slice
// 2): it asks the Microsoft identity platform for an Entra application's
// token with the client credentials grant, for Exchange Online
// (https://outlook.office365.com/.default), with the application's client
// secret or a client assertion signed with its certificate, and keeps the
// token until shortly before it expires. The mailer sends it with AUTH
// XOAUTH2.
//
// The token endpoint is dialed through netguard, as the mail server is,
// with no proxy and no redirects, trusting the system's certificate
// authorities only. Neither the secret, the key nor a token reaches a log
// or an error.
package m365

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // Entra shows a certificate's SHA-1 thumbprint; it is shown so, never used to sign or check
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
	"unicode"
)

// Scope is the scope of a token for Exchange Online's SMTP, POP and IMAP
// with an application's own credentials ("Authenticate an IMAP, POP or SMTP
// connection using OAuth", Microsoft Learn).
const Scope = "https://outlook.office365.com/.default"

// Authority is the Microsoft identity platform of Microsoft's global cloud.
const Authority = "https://login.microsoftonline.com"

// How the application proves who it is.
const (
	CredentialSecret      = "secret"
	CredentialCertificate = "certificate"
)

// The longest client secret, certificate and key taken: Entra's secrets are
// 40 characters; a certificate with its chain and a 4,096-bit key fit
// easily.
const (
	MaxSecret      = 1024
	MaxCertificate = 64 << 10
	MaxKey         = 16 << 10
)

// minKeyBits is the smallest RSA key taken.
const minKeyBits = 2048

var guid = regexp.MustCompile(`^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$`)

var domainLabel = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$`)

// ValidTenant reports whether s is a tenant as the token endpoint takes it:
// the tenant's ID, a GUID, or one of its domain names, such as
// contoso.onmicrosoft.com.
func ValidTenant(s string) bool {
	if guid.MatchString(s) {
		return true
	}
	if len(s) > 253 || !strings.Contains(s, ".") {
		return false
	}
	labels := strings.Split(s, ".")
	for _, l := range labels {
		if !domainLabel.MatchString(l) {
			return false
		}
	}
	// The last label is a top-level domain: letters only.
	return strings.IndexFunc(labels[len(labels)-1], func(r rune) bool { return !unicode.IsLetter(r) }) < 0
}

// ValidClientID reports whether s is an application (client) ID: a GUID.
func ValidClientID(s string) bool { return guid.MatchString(s) }

// CheckSecret checks a client secret: not empty, at most MaxSecret bytes, on
// one line, of printable characters.
func CheckSecret(s string) error {
	switch {
	case s == "":
		return errors.New("the client secret is empty")
	case len(s) > MaxSecret:
		return fmt.Errorf("the client secret is longer than %d characters", MaxSecret)
	case strings.ContainsFunc(s, func(r rune) bool { return !unicode.IsPrint(r) || r == ' ' }):
		return errors.New("the client secret is not one line of printable characters")
	}
	return nil
}

// Certificate is an application's certificate with its private key.
type Certificate struct {
	// Leaf is the application's certificate, the first in the PEM.
	Leaf *x509.Certificate
	key  *rsa.PrivateKey
	// PEM is the certificate as given, its chain included.
	PEM string
}

// Info is what the console shows of a certificate.
type Info struct {
	Subject string `json:"subject"`
	// Thumbprint is the SHA-1 thumbprint, in hexadecimal as Entra shows it
	// under Certificates & secrets.
	Thumbprint string    `json:"thumbprint"`
	NotBefore  time.Time `json:"notBefore"`
	NotAfter   time.Time `json:"notAfter"`
}

// Info describes the certificate.
func (c *Certificate) Info() Info { return CertificateInfo(c.Leaf) }

// CertificateInfo describes a certificate.
func CertificateInfo(leaf *x509.Certificate) Info {
	sum := sha1.Sum(leaf.Raw) //nolint:gosec // see the import
	return Info{Subject: leaf.Subject.String(), Thumbprint: strings.ToUpper(hex.EncodeToString(sum[:])), NotBefore: leaf.NotBefore,
		NotAfter: leaf.NotAfter}
}

// Warning says when a certificate cannot sign in, or will not within
// ExpiresSoon, with what to do; "" otherwise.
func Warning(leaf *x509.Certificate, now time.Time) string {
	if why := Expired(leaf, now); why != "" {
		return "The application's certificate cannot sign in: " + why + ". Make a new one, upload it to the application in Entra, and give it to EasyRMM."
	}
	if left := leaf.NotAfter.Sub(now); left < ExpiresSoon {
		days := int(left.Hours() / 24)
		when := fmt.Sprintf("in %d days", days)
		if days < 1 {
			when = "within a day"
		}
		return fmt.Sprintf("The application's certificate expires on %s, %s. Make a new one, upload it to the application in Entra, and give it to EasyRMM before then.",
			leaf.NotAfter.UTC().Format("2 January 2006"), when)
	}
	return ""
}

// x5tS256 is the certificate's SHA-256 thumbprint, base64url, as a client
// assertion's x5t#S256 header names it.
func (c *Certificate) x5tS256() string {
	sum := sha256.Sum256(c.Leaf.Raw)
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// ParseCertificateOnly reads the certificates in certPEM, the
// application's first.
func ParseCertificateOnly(certPEM string) (*x509.Certificate, error) {
	if len(certPEM) > MaxCertificate {
		return nil, fmt.Errorf("the certificate is larger than %d KiB", MaxCertificate>>10)
	}
	var leaf *x509.Certificate
	rest := []byte(certPEM)
	for {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			break
		}
		switch b.Type {
		case "CERTIFICATE":
			c, err := x509.ParseCertificate(b.Bytes)
			if err != nil {
				return nil, errors.New("the certificate does not parse")
			}
			if leaf == nil {
				leaf = c
			}
		case "PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY", "ENCRYPTED PRIVATE KEY":
			return nil, errors.New("the certificate's PEM holds a private key: give the key on its own")
		}
	}
	if leaf == nil {
		return nil, errors.New("no PEM certificate (-----BEGIN CERTIFICATE-----) found")
	}
	if _, ok := leaf.PublicKey.(*rsa.PublicKey); !ok {
		return nil, errors.New("the certificate's key is not RSA: Entra signs in applications with RSA certificates")
	}
	return leaf, nil
}

// ParseCertificate reads an application's certificate and its private key,
// both PEM: the key unencrypted, RSA of at least 2,048 bits, PKCS #1 or
// PKCS #8, and the certificate's. It does not check the dates: Expired
// does.
func ParseCertificate(certPEM, keyPEM string) (*Certificate, error) {
	leaf, err := ParseCertificateOnly(certPEM)
	if err != nil {
		return nil, err
	}
	key, err := parseKey(keyPEM)
	if err != nil {
		return nil, err
	}
	if !key.PublicKey.Equal(leaf.PublicKey) {
		return nil, errors.New("the private key is not the certificate's")
	}
	return &Certificate{Leaf: leaf, key: key, PEM: strings.TrimSpace(certPEM) + "\n"}, nil
}

func parseKey(keyPEM string) (*rsa.PrivateKey, error) {
	if len(keyPEM) > MaxKey {
		return nil, fmt.Errorf("the private key is larger than %d KiB", MaxKey>>10)
	}
	rest := []byte(keyPEM)
	for {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			return nil, errors.New("no PEM private key (-----BEGIN PRIVATE KEY----- or -----BEGIN RSA PRIVATE KEY-----) found")
		}
		if b.Headers["Proc-Type"] != "" || b.Type == "ENCRYPTED PRIVATE KEY" {
			return nil, errors.New("the private key is encrypted: give it without a passphrase (openssl pkey -in key.pem -out plain.pem)")
		}
		var key any
		var err error
		switch b.Type {
		case "RSA PRIVATE KEY":
			key, err = x509.ParsePKCS1PrivateKey(b.Bytes)
		case "PRIVATE KEY":
			key, err = x509.ParsePKCS8PrivateKey(b.Bytes)
		case "EC PRIVATE KEY":
			return nil, errors.New("the private key is not RSA: Entra signs in applications with RSA certificates")
		default:
			continue
		}
		if err != nil {
			return nil, errors.New("the private key does not parse")
		}
		rk, ok := key.(*rsa.PrivateKey)
		if !ok {
			return nil, errors.New("the private key is not RSA: Entra signs in applications with RSA certificates")
		}
		if rk.N.BitLen() < minKeyBits {
			return nil, fmt.Errorf("the private key has %d bits: give one of at least %d", rk.N.BitLen(), minKeyBits)
		}
		return rk, nil
	}
}

// Expired says why cert cannot sign in at now, "" when it can.
func Expired(cert *x509.Certificate, now time.Time) string {
	switch {
	case now.After(cert.NotAfter):
		return "the certificate expired on " + cert.NotAfter.UTC().Format("2 January 2006")
	case now.Before(cert.NotBefore):
		return "the certificate is not valid before " + cert.NotBefore.UTC().Format("2 January 2006 15:04 MST")
	}
	return ""
}

// ExpiresSoon is how long before a certificate's end EasyRMM warns.
const ExpiresSoon = 30 * 24 * time.Hour

// Credentials are an Entra application's: its tenant, its ID, and its
// client secret or certificate.
type Credentials struct {
	TenantID string
	ClientID string
	// Secret, or Certificate.
	Secret      string
	Certificate *Certificate
	// Authority is the identity platform's address; empty for Authority,
	// Microsoft's global cloud. Tests give their stand-in's.
	Authority string
}

// Kind is CredentialSecret or CredentialCertificate.
func (c *Credentials) Kind() string {
	if c.Certificate != nil {
		return CredentialCertificate
	}
	return CredentialSecret
}

// Check checks the IDs and that there is one credential.
func (c *Credentials) Check() error {
	switch {
	case !ValidTenant(c.TenantID):
		return errors.New("the tenant ID is neither a GUID nor a domain name")
	case !ValidClientID(c.ClientID):
		return errors.New("the application (client) ID is not a GUID")
	case c.Certificate != nil && c.Secret != "":
		return errors.New("give a client secret or a certificate, not both")
	case c.Certificate == nil:
		return CheckSecret(c.Secret)
	}
	return nil
}

func (c *Credentials) authority() string {
	if c.Authority != "" {
		return strings.TrimSuffix(c.Authority, "/")
	}
	return Authority
}

// tokenURL is the tenant's token endpoint.
func (c *Credentials) tokenURL() string {
	return c.authority() + "/" + strings.ToLower(c.TenantID) + "/oauth2/v2.0/token"
}

// assertion is a client assertion (RFC 7523) signed with the application's
// certificate, as Entra takes it: PS256, the certificate named by its
// SHA-256 thumbprint, for the token endpoint, valid for 10 minutes ("Microsoft
// identity platform certificate credentials", Microsoft Learn).
func (c *Credentials) assertion(now time.Time, jti string) (string, error) {
	enc := func(v any) (string, error) {
		b, err := json.Marshal(v)
		return base64.RawURLEncoding.EncodeToString(b), err
	}
	head, err := enc(map[string]string{"alg": "PS256", "typ": "JWT", "x5t#S256": c.Certificate.x5tS256()})
	if err != nil {
		return "", err
	}
	claims, err := enc(map[string]any{"aud": c.tokenURL(), "iss": c.ClientID, "sub": c.ClientID, "jti": jti,
		"nbf": now.Unix(), "iat": now.Unix(), "exp": now.Add(10 * time.Minute).Unix()})
	if err != nil {
		return "", err
	}
	signed := head + "." + claims
	sum := sha256.Sum256([]byte(signed))
	sig, err := rsa.SignPSS(rand.Reader, c.Certificate.key, crypto.SHA256, sum[:], &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
	if err != nil {
		return "", errors.New("m365: signing the client assertion failed")
	}
	return signed + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}
