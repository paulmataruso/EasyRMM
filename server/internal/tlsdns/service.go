// Package tlsdns manages DNS-01 challenge credentials (ADR-0055, slice 5b4):
// RFC 2136 dynamic update and Cloudflare API tokens, sealed and tested on
// save, and exposed to CertMagic as DNS-01 solvers.
package tlsdns

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/caddyserver/certmagic"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	cflib "github.com/libdns/cloudflare"
	"github.com/libdns/libdns"
	rfclib "github.com/libdns/rfc2136"

	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/secrets"
)

// Providers.
const (
	ProviderRFC2136   = "rfc2136"
	ProviderCloudflare = "cloudflare"
)

// Allowed TSIG algorithms (ADR: HMAC-SHA256 or stronger; HMAC-MD5 and
// HMAC-SHA1 are refused).
var allowedTSIGAlgorithms = map[string]bool{
	"hmac-sha256.": true,
	"hmac-sha384.": true,
	"hmac-sha512.": true,
}

// Errors.
var (
	ErrNotFound       = errors.New("tlsdns: credential not found")
	ErrDuplicateZone  = errors.New("tlsdns: a credential for this zone already exists")
	ErrBadProvider    = errors.New("tlsdns: unknown provider")
	ErrBadZone        = errors.New("tlsdns: not a valid DNS zone")
	ErrBadAlgorithm   = errors.New("tlsdns: TSIG algorithm not allowed; use hmac-sha256, hmac-sha384 or hmac-sha512")
	ErrBadServer      = errors.New("tlsdns: the server address is not reachable or not allowed")
	ErrCloudMetadata  = errors.New("tlsdns: cloud metadata addresses are not allowed")
	ErrTestFailed     = errors.New("tlsdns: the test record could not be created or removed")
	ErrMissingField   = errors.New("tlsdns: a required field is empty")
)

// TestReason maps library errors to fixed reasons the page shows.
type TestReason string

const (
	ReasonOK           TestReason = "ok"
	ReasonRefused      TestReason = "refused"
	ReasonTimedOut     TestReason = "timed_out"
	ReasonNotAuthorized TestReason = "not_authorized"
	ReasonZoneNotFound  TestReason = "zone_not_found"
	ReasonUnknown      TestReason = "unknown"
)

// RFC2136Input is what a super administrator provides for an RFC 2136 provider.
type RFC2136Input struct {
	Server    string `json:"server"`
	Zone      string `json:"zone"`
	KeyName   string `json:"keyName"`
	KeySecret string `json:"keySecret"`
	Algorithm string `json:"algorithm"`
}

// CloudflareInput is what a super administrator provides for Cloudflare.
type CloudflareInput struct {
	Zone     string `json:"zone"`
	APIToken string `json:"apiToken"`
}

// SaveInput is a provider-agnostic save request.
type SaveInput struct {
	Provider        string `json:"provider"`
	OverrideDomain  string `json:"overrideDomain"`
	RFC2136         *RFC2136Input    `json:"rfc2136,omitempty"`
	Cloudflare      *CloudflareInput `json:"cloudflare,omitempty"`
}

// Credential is a row from tls_dns_credentials, with secrets stripped.
type Credential struct {
	ID              uuid.UUID  `json:"id"`
	Provider        string     `json:"provider"`
	Zone            string     `json:"zone"`
	OverrideDomain  string     `json:"overrideDomain"`
	ServerAddr      string     `json:"serverAddr,omitempty"`
	TestedAt        *time.Time `json:"testedAt,omitempty"`
	TestOK          bool       `json:"testOk"`
	CreatedAt       time.Time  `json:"createdAt"`
	UpdatedAt       time.Time  `json:"updatedAt"`
}

// sealedCreds is what we store in the credentials column, JSON-then-sealed.
type sealedRFC2136 struct {
	KeyName   string `json:"keyName"`
	KeySecret string `json:"keySecret"`
	Algorithm string `json:"algorithm"`
}

type sealedCloudflare struct {
	APIToken string `json:"apiToken"`
}

// Deps are what the service uses.
type Deps struct {
	DB     *database.DB
	Sealer *secrets.Sealer
	Audit  *audit.Logger
	Log    *slog.Logger
	Now    func() time.Time
	// Resolve resolves a name; nil means the system resolver.
	Resolve func(ctx context.Context, host string) ([]netip.Addr, error)
}

// Service manages DNS-01 challenge credentials.
type Service struct {
	deps Deps
}

// New builds a service.
func New(deps Deps) *Service {
	if deps.Now == nil {
		deps.Now = time.Now
	}
	if deps.Log == nil {
		deps.Log = slog.Default()
	}
	return &Service{deps: deps}
}

// List returns every credential, secrets stripped.
func (s *Service) List(ctx context.Context) ([]Credential, error) {
	rows, err := s.deps.DB.Pool.Query(ctx,
		`SELECT id, provider, zone, override_domain, server_addr, tested_at, test_ok, created_at, updated_at
		 FROM tls_dns_credentials ORDER BY zone`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Credential
	for rows.Next() {
		var c Credential
		if err := rows.Scan(&c.ID, &c.Provider, &c.Zone, &c.OverrideDomain, &c.ServerAddr, &c.TestedAt, &c.TestOK, &c.CreatedAt, &c.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// Save creates a new DNS credential, tests it, and stores it sealed.
func (s *Service) Save(ctx context.Context, actor audit.Actor, in SaveInput) (*Credential, TestReason, error) {
	zone, creds, serverAddr, err := s.validate(ctx, in)
	if err != nil {
		return nil, "", err
	}
	sealed, err := s.seal(uuid.Nil, creds)
	if err != nil {
		return nil, "", fmt.Errorf("tlsdns: sealing credentials: %w", err)
	}

	id := uuid.New()
	sealedForRow, err := s.seal(id, creds)
	if err != nil {
		return nil, "", fmt.Errorf("tlsdns: sealing credentials: %w", err)
	}
	_ = sealed

	reason := s.test(ctx, in.Provider, zone, in.OverrideDomain, serverAddr, creds)
	now := s.deps.Now()
	testOK := reason == ReasonOK

	var c Credential
	err = s.deps.DB.InTx(ctx, database.System, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`INSERT INTO tls_dns_credentials (id, provider, zone, override_domain, credentials, server_addr, tested_at, test_ok, created_at, updated_at)
			 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $9)
			 RETURNING id, provider, zone, override_domain, server_addr, tested_at, test_ok, created_at, updated_at`,
			id, in.Provider, zone, in.OverrideDomain, sealedForRow, serverAddr, now, testOK, now,
		).Scan(&c.ID, &c.Provider, &c.Zone, &c.OverrideDomain, &c.ServerAddr, &c.TestedAt, &c.TestOK, &c.CreatedAt, &c.UpdatedAt)
	})
	if err != nil {
		if database.IsUniqueViolation(err) {
			return nil, "", ErrDuplicateZone
		}
		return nil, "", err
	}

	_ = s.deps.Audit.Record(ctx, audit.Event{
		Actor: actor, Action: "tls.dns_save", Outcome: audit.Success,
		TargetType: "tls_dns_credential", TargetID: id.String(),
		Details: map[string]any{"provider": in.Provider, "zone": zone, "test_ok": testOK},
	})
	return &c, reason, nil
}

// Replace replaces the credentials on an existing row.
func (s *Service) Replace(ctx context.Context, actor audit.Actor, id uuid.UUID, in SaveInput) (*Credential, TestReason, error) {
	zone, creds, serverAddr, err := s.validate(ctx, in)
	if err != nil {
		return nil, "", err
	}
	sealedForRow, err := s.seal(id, creds)
	if err != nil {
		return nil, "", fmt.Errorf("tlsdns: sealing credentials: %w", err)
	}

	reason := s.test(ctx, in.Provider, zone, in.OverrideDomain, serverAddr, creds)
	now := s.deps.Now()
	testOK := reason == ReasonOK

	var c Credential
	err = s.deps.DB.InTx(ctx, database.System, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx,
			`UPDATE tls_dns_credentials SET provider = $2, zone = $3, override_domain = $4, credentials = $5, server_addr = $6, tested_at = $7, test_ok = $8, updated_at = $7
			 WHERE id = $1`,
			id, in.Provider, zone, in.OverrideDomain, sealedForRow, serverAddr, now, testOK,
		)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return ErrNotFound
		}
		return tx.QueryRow(ctx,
			`SELECT id, provider, zone, override_domain, server_addr, tested_at, test_ok, created_at, updated_at
			 FROM tls_dns_credentials WHERE id = $1`, id,
		).Scan(&c.ID, &c.Provider, &c.Zone, &c.OverrideDomain, &c.ServerAddr, &c.TestedAt, &c.TestOK, &c.CreatedAt, &c.UpdatedAt)
	})
	if err != nil {
		if database.IsUniqueViolation(err) {
			return nil, "", ErrDuplicateZone
		}
		return nil, "", err
	}

	_ = s.deps.Audit.Record(ctx, audit.Event{
		Actor: actor, Action: "tls.dns_replace", Outcome: audit.Success,
		TargetType: "tls_dns_credential", TargetID: id.String(),
		Details: map[string]any{"provider": in.Provider, "zone": zone, "test_ok": testOK},
	})
	return &c, reason, nil
}

// Remove deletes a credential.
func (s *Service) Remove(ctx context.Context, actor audit.Actor, id uuid.UUID) error {
	var zone string
	err := s.deps.DB.InTx(ctx, database.System, func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx, `DELETE FROM tls_dns_credentials WHERE id = $1 RETURNING zone`, id).Scan(&zone)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		return err
	})
	if err != nil {
		return err
	}
	_ = s.deps.Audit.Record(ctx, audit.Event{
		Actor: actor, Action: "tls.dns_remove", Outcome: audit.Success,
		TargetType: "tls_dns_credential", TargetID: id.String(),
		Details: map[string]any{"zone": zone},
	})
	return nil
}

// Retest tests an existing credential again.
func (s *Service) Retest(ctx context.Context, actor audit.Actor, id uuid.UUID) (TestReason, error) {
	var provider, zone, overrideDomain, serverAddr string
	var sealedCreds []byte
	err := s.deps.DB.Pool.QueryRow(ctx,
		`SELECT provider, zone, override_domain, server_addr, credentials FROM tls_dns_credentials WHERE id = $1`, id,
	).Scan(&provider, &zone, &overrideDomain, &serverAddr, &sealedCreds)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrNotFound
	}
	if err != nil {
		return "", err
	}

	creds, err := s.unseal(id, sealedCreds)
	if err != nil {
		return "", fmt.Errorf("tlsdns: unsealing credentials: %w", err)
	}

	reason := s.test(ctx, provider, zone, overrideDomain, serverAddr, creds)
	now := s.deps.Now()
	testOK := reason == ReasonOK
	_, err = s.deps.DB.Pool.Exec(ctx,
		`UPDATE tls_dns_credentials SET tested_at = $2, test_ok = $3, updated_at = $2 WHERE id = $1`,
		id, now, testOK,
	)
	if err != nil {
		return "", err
	}
	_ = s.deps.Audit.Record(ctx, audit.Event{
		Actor: actor, Action: "tls.dns_test", Outcome: audit.Success,
		TargetType: "tls_dns_credential", TargetID: id.String(),
		Details: map[string]any{"provider": provider, "zone": zone, "test_ok": testOK},
	})
	return reason, nil
}

// SolverFor returns a CertMagic DNS-01 solver for the given DNS name, or nil
// if no credentials cover its zone.
func (s *Service) SolverFor(ctx context.Context, name string) (*certmagic.DNS01Solver, error) {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	labels := strings.Split(name, ".")

	for i := range labels {
		candidate := strings.Join(labels[i:], ".")
		var id uuid.UUID
		var provider, zone, overrideDomain, serverAddr string
		var sealedCreds []byte
		var testOK bool
		err := s.deps.DB.Pool.QueryRow(ctx,
			`SELECT id, provider, zone, override_domain, server_addr, credentials, test_ok
			 FROM tls_dns_credentials WHERE zone = $1`, candidate,
		).Scan(&id, &provider, &zone, &overrideDomain, &serverAddr, &sealedCreds, &testOK)
		if errors.Is(err, pgx.ErrNoRows) {
			continue
		}
		if err != nil {
			return nil, err
		}

		creds, err := s.unseal(id, sealedCreds)
		if err != nil {
			return nil, fmt.Errorf("tlsdns: unsealing credentials for zone %s: %w", zone, err)
		}

		prov, resolvers, err := s.provider(provider, zone, serverAddr, creds)
		if err != nil {
			return nil, err
		}

		solver := &certmagic.DNS01Solver{
			DNSManager: certmagic.DNSManager{
				DNSProvider:        prov,
				TTL:                60 * time.Second,
				PropagationTimeout: 5 * time.Minute,
				Resolvers:          resolvers,
			},
		}
		if overrideDomain != "" {
			solver.OverrideDomain = overrideDomain
		}
		return solver, nil
	}
	return nil, nil
}

// validate checks the input and returns the zone, the credentials to seal,
// and the pinned server address (RFC 2136 only).
func (s *Service) validate(ctx context.Context, in SaveInput) (zone string, creds []byte, serverAddr string, err error) {
	switch in.Provider {
	case ProviderRFC2136:
		if in.RFC2136 == nil {
			return "", nil, "", ErrMissingField
		}
		return s.validateRFC2136(ctx, in.RFC2136, in.OverrideDomain)
	case ProviderCloudflare:
		if in.Cloudflare == nil {
			return "", nil, "", ErrMissingField
		}
		return s.validateCloudflare(in.Cloudflare, in.OverrideDomain)
	default:
		return "", nil, "", ErrBadProvider
	}
}

func (s *Service) validateRFC2136(ctx context.Context, in *RFC2136Input, overrideDomain string) (string, []byte, string, error) {
	zone := normalizeZone(in.Zone)
	if zone == "" || !isValidZone(zone) {
		return "", nil, "", ErrBadZone
	}
	if in.KeyName == "" || in.KeySecret == "" || in.Algorithm == "" {
		return "", nil, "", ErrMissingField
	}
	if in.Server == "" {
		return "", nil, "", ErrMissingField
	}

	alg := strings.ToLower(strings.TrimSuffix(in.Algorithm, ".")) + "."
	if !allowedTSIGAlgorithms[alg] {
		return "", nil, "", ErrBadAlgorithm
	}

	addr, err := s.resolveAndPin(ctx, in.Server)
	if err != nil {
		return "", nil, "", err
	}

	creds, _ := json.Marshal(sealedRFC2136{
		KeyName:   in.KeyName,
		KeySecret: in.KeySecret,
		Algorithm: alg,
	})
	return zone, creds, addr, nil
}

func (s *Service) validateCloudflare(in *CloudflareInput, overrideDomain string) (string, []byte, string, error) {
	zone := normalizeZone(in.Zone)
	if zone == "" || !isValidZone(zone) {
		return "", nil, "", ErrBadZone
	}
	if in.APIToken == "" {
		return "", nil, "", ErrMissingField
	}
	creds, _ := json.Marshal(sealedCloudflare{APIToken: in.APIToken})
	return zone, creds, "", nil
}

// resolveAndPin resolves a server name, checks the address, and returns
// ip:53. Cloud metadata addresses are blocked.
func (s *Service) resolveAndPin(ctx context.Context, server string) (string, error) {
	host := server
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}

	if addr, err := netip.ParseAddr(host); err == nil {
		if isCloudMetadata(addr) {
			return "", ErrCloudMetadata
		}
		return netip.AddrPortFrom(addr, 53).String(), nil
	}

	resolve := s.deps.Resolve
	if resolve == nil {
		resolve = func(ctx context.Context, host string) ([]netip.Addr, error) {
			ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
			return ips, err
		}
	}
	addrs, err := resolve(ctx, host)
	if err != nil || len(addrs) == 0 {
		return "", ErrBadServer
	}
	addr := addrs[0].Unmap()
	if isCloudMetadata(addr) {
		return "", ErrCloudMetadata
	}
	return netip.AddrPortFrom(addr, 53).String(), nil
}

// isCloudMetadata returns true for addresses that must never be dialled:
// 169.254.169.254 (AWS/GCP/Azure), fd00:ec2::254 (AWS IMDSv2 IPv6).
func isCloudMetadata(addr netip.Addr) bool {
	a := addr.Unmap()
	if a == netip.MustParseAddr("169.254.169.254") {
		return true
	}
	if a == netip.MustParseAddr("fd00:ec2::254") {
		return true
	}
	return false
}

func normalizeZone(z string) string {
	z = strings.TrimSpace(strings.ToLower(z))
	z = strings.TrimSuffix(z, ".")
	return z
}

func isValidZone(z string) bool {
	if len(z) == 0 || len(z) > 253 {
		return false
	}
	labels := strings.Split(z, ".")
	if len(labels) < 2 {
		return false
	}
	for _, l := range labels {
		if len(l) == 0 || len(l) > 63 {
			return false
		}
	}
	return true
}

// seal encrypts credentials, bound to the row's UUID.
func (s *Service) seal(id uuid.UUID, plaintext []byte) ([]byte, error) {
	sealed, err := s.deps.Sealer.Seal(plaintext, id[:])
	if err != nil {
		return nil, err
	}
	return []byte(sealed), nil
}

// unseal decrypts credentials.
func (s *Service) unseal(id uuid.UUID, sealed []byte) ([]byte, error) {
	return s.deps.Sealer.Open(string(sealed), id[:])
}

// test creates and removes a TXT record to verify the credentials work.
func (s *Service) test(ctx context.Context, provider, zone, overrideDomain, serverAddr string, creds []byte) TestReason {
	prov, _, err := s.provider(provider, zone, serverAddr, creds)
	if err != nil {
		s.deps.Log.Warn("tlsdns: cannot build provider for test", "zone", zone, "error", err)
		return ReasonUnknown
	}

	testZone := zone + "."
	testName := "_acme-challenge-test"
	if overrideDomain != "" {
		testZone = overrideDomain + "."
		testName = "_acme-challenge-test"
	}
	testValue := fmt.Sprintf("easyrmm-test-%d", s.deps.Now().UnixMilli())

	tctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	rec := libdns.RR{
		Type: "TXT",
		Name: testName,
		Data: testValue,
		TTL:  60 * time.Second,
	}

	_, err = prov.AppendRecords(tctx, testZone, []libdns.Record{rec})
	if err != nil {
		return classifyError(err)
	}

	_, err = prov.DeleteRecords(tctx, testZone, []libdns.Record{rec})
	if err != nil {
		s.deps.Log.Warn("tlsdns: test record created but not removed", "zone", zone, "error", err)
	}
	return ReasonOK
}

// provider builds a libdns provider from stored credentials.
func (s *Service) provider(providerName, zone, serverAddr string, creds []byte) (certmagic.DNSProvider, []string, error) {
	switch providerName {
	case ProviderRFC2136:
		var c sealedRFC2136
		if err := json.Unmarshal(creds, &c); err != nil {
			return nil, nil, fmt.Errorf("tlsdns: bad rfc2136 credentials: %w", err)
		}
		addr := serverAddr
		if addr == "" {
			return nil, nil, fmt.Errorf("tlsdns: rfc2136 credentials have no server address")
		}
		p := &rfclib.Provider{
			KeyName: c.KeyName,
			KeyAlg:  c.Algorithm,
			Key:     c.KeySecret,
			Server:  addr,
		}
		return &appendDeleter{a: p, d: p}, []string{addr}, nil
	case ProviderCloudflare:
		var c sealedCloudflare
		if err := json.Unmarshal(creds, &c); err != nil {
			return nil, nil, fmt.Errorf("tlsdns: bad cloudflare credentials: %w", err)
		}
		p := &cflib.Provider{APIToken: c.APIToken}
		return &appendDeleter{a: p, d: p}, nil, nil
	default:
		return nil, nil, fmt.Errorf("tlsdns: unknown provider %q", providerName)
	}
}

// appendDeleter bridges both interfaces into one value.
type appendDeleter struct {
	a libdns.RecordAppender
	d libdns.RecordDeleter
}

func (ad *appendDeleter) AppendRecords(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	return ad.a.AppendRecords(ctx, zone, recs)
}

func (ad *appendDeleter) DeleteRecords(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	return ad.d.DeleteRecords(ctx, zone, recs)
}

// classifyError maps a DNS library error to a fixed reason.
func classifyError(err error) TestReason {
	if err == nil {
		return ReasonOK
	}
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "refused"):
		return ReasonRefused
	case strings.Contains(msg, "timeout") || strings.Contains(msg, "timed out") || strings.Contains(msg, "deadline"):
		return ReasonTimedOut
	case strings.Contains(msg, "not auth") || strings.Contains(msg, "tsig"):
		return ReasonNotAuthorized
	case strings.Contains(msg, "nxdomain") || strings.Contains(msg, "zone not found") || strings.Contains(msg, "notzone"):
		return ReasonZoneNotFound
	default:
		return ReasonUnknown
	}
}
