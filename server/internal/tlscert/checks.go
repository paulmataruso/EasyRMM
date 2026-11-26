package tlscert

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/paulmataruso/easyrmm/server/internal/netguard"
)

// A check's outcome.
const (
	CheckOK   = "ok"
	CheckWarn = "warn"
	CheckFail = "fail"
)

// Check is one result of the checks that run on the Certificates page and in
// `easyrmm-server tls check`: a tick, a warning or a failure, with its fix.
type Check struct {
	ID     string `json:"id"`
	Title  string `json:"title"`
	Status string `json:"status"`
	Detail string `json:"detail"`
	Fix    string `json:"fix,omitempty"`
}

// ErrTooSoon is returned when a name was checked less than 10 seconds ago.
type ErrTooSoon struct{ RetryAfter time.Duration }

func (e *ErrTooSoon) Error() string {
	return fmt.Sprintf("tls: the checks for this name ran a moment ago; wait %d seconds", int(e.RetryAfter.Seconds())+1)
}

const checkInterval = 10 * time.Second

func (s *Service) lookup(ctx context.Context, host string) ([]netip.Addr, error) {
	if s.set.Lookup != nil {
		return s.set.Lookup(ctx, host)
	}
	addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err == nil && len(addrs) == 0 {
		err = errors.New("no addresses")
	}
	return addrs, err
}

func (s *Service) own() []netip.Addr {
	if s.set.Own != nil {
		return s.set.Own()
	}
	return nil
}

// Check runs the checks for a name. They connect out, so they are held to an
// address policy: an address is dialed only if it is one of this server's
// own or public unicast, checked on the address actually dialed, so DNS
// cannot point a check elsewhere between lookup and connection. No redirects
// are followed, the outcome is pass or fail with a fixed reason (never what
// the other side said), each connection times out after 5 seconds, and a
// name is checked at most once every 10 seconds.
func (s *Service) Check(ctx context.Context, name string) ([]Check, error) {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	if !s.Managed(name) {
		return nil, ErrNoName
	}
	s.mu.Lock()
	if s.lastChecked == nil {
		s.lastChecked = map[string]time.Time{}
	}
	if last := s.lastChecked[name]; s.deps.Now().Sub(last) < checkInterval {
		wait := checkInterval - s.deps.Now().Sub(last)
		s.mu.Unlock()
		return nil, &ErrTooSoon{RetryAfter: wait}
	}
	s.lastChecked[name] = s.deps.Now()
	s.mu.Unlock()

	var out []Check
	addrs, err := s.lookup(ctx, name)
	if err != nil {
		out = append(out, Check{ID: "resolves", Title: "The name resolves on this server", Status: CheckWarn,
			Detail: "This server cannot resolve " + name + ".",
			Fix: "Create an A (and AAAA) record for it. A name looked up before its record existed may stay \"not found\" for the zone's negative-caching time (its SOA minimum), here and at the resolvers on the way. " +
				"If this server's resolver cannot see the public answer (split-horizon DNS), use Order anyway."})
	} else {
		out = append(out, Check{ID: "resolves", Title: "The name resolves on this server", Status: CheckOK, Detail: name + " resolves to " + joinAddrs(addrs) + "."})
		out = append(out, s.recordsCheck(addrs))
	}
	out = append(out, s.caaCheck(ctx, name))
	if len(addrs) > 0 {
		out = append(out, s.portsChecks(ctx, name, addrs)...)
	}
	return out, nil
}

func joinAddrs(a []netip.Addr) string {
	var s []string
	for _, x := range a {
		s = append(s, x.String())
	}
	return strings.Join(s, ", ")
}

// recordsCheck compares the name's A and AAAA records with this server's
// addresses: a mismatch is a warning (the operator corrects the list behind
// NAT), except an AAAA record that points elsewhere, which fails, since Let's
// Encrypt tries IPv6 first and retries over IPv4 only after a timeout.
func (s *Service) recordsCheck(addrs []netip.Addr) Check {
	own := s.own()
	c := Check{ID: "records", Title: "Its A and AAAA records point at this server"}
	var badV6, badV4 []netip.Addr
	for _, a := range addrs {
		a = a.Unmap()
		if slices.Contains(own, a) {
			continue
		}
		if a.Is6() {
			badV6 = append(badV6, a)
		} else {
			badV4 = append(badV4, a)
		}
	}
	switch {
	case len(badV6) > 0:
		c.Status = CheckFail
		c.Detail = "An AAAA record points at " + joinAddrs(badV6) + ", which is not an address of this server."
		c.Fix = "Let's Encrypt connects over IPv6 first and falls back to IPv4 only after a timeout, so an AAAA record that points elsewhere fails validation even when the A record is right. Correct or remove the AAAA record."
	case len(badV4) > 0:
		c.Status = CheckWarn
		c.Detail = "An A record points at " + joinAddrs(badV4) + ", which is not among this server's addresses (behind NAT or a proxy that is expected)."
		c.Fix = "If the address is this server's public one behind NAT, correct the list of addresses under IP access."
	default:
		c.Status = CheckOK
		c.Detail = "Every record points at an address of this server."
	}
	return c
}

// dialAllowed is the address policy of the checks.
func (s *Service) dialAllowed(a netip.Addr) bool {
	a = a.Unmap()
	if s.set.AllowDial != nil {
		return s.set.AllowDial(a)
	}
	if slices.Contains(s.own(), a) {
		return netguard.Refused(a) == ""
	}
	if !a.IsGlobalUnicast() || a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast() || a.IsMulticast() || a.IsUnspecified() {
		return false
	}
	for _, p := range reservedRanges {
		if p.Contains(a) {
			return false
		}
	}
	return netguard.Refused(a) == ""
}

var reservedRanges = func() []netip.Prefix {
	var out []netip.Prefix
	for _, s := range []string{"0.0.0.0/8", "100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24", "198.18.0.0/15", "198.51.100.0/24",
		"203.0.113.0/24", "240.0.0.0/4", "2001:db8::/32", "64:ff9b::/96", "2002::/16", "fc00::/7"} {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}()

// portsChecks asks, at each resolved address, for a token this server serves
// under a path of its own: ports 80 and 443 answer (a warning: routers often
// do not loop a host's own address back).
func (s *Service) portsChecks(ctx context.Context, name string, addrs []netip.Addr) []Check {
	raw := make([]byte, 12)
	_, _ = rand.Read(raw)
	token := hex.EncodeToString(raw)
	if err := s.store.Store(ctx, checkKey(name), []byte(token)); err != nil {
		return []Check{{ID: "ports", Title: "Ports 80 and 443 answer", Status: CheckWarn, Detail: "The check could not be prepared.", Fix: "Check the server's log."}}
	}
	defer func() { _ = s.store.Delete(context.WithoutCancel(ctx), checkKey(name)) }()
	var out []Check
	for _, p := range []struct{ id, title, scheme, port string }{
		{"port80", "Port 80 answers at the name's addresses", "http", orDefault(s.set.CheckHTTPPort, "80")},
		{"port443", "Port 443 answers at the name's addresses", "https", orDefault(s.set.CheckHTTPSPort, "443")},
	} {
		if p.scheme == "http" && s.set.HTTPPort == "" {
			out = append(out, Check{ID: p.id, Title: p.title, Status: CheckWarn, Detail: "Port 80 is off (EASYRMM_LISTEN_HTTP is empty): only TLS-ALPN-01 on port 443 can be used.",
				Fix: "Set EASYRMM_LISTEN_HTTP=:80 to allow HTTP-01 as well."})
			continue
		}
		c := Check{ID: p.id, Title: p.title}
		var failed []string
		for _, a := range addrs {
			if !s.dialAllowed(a) {
				failed = append(failed, a.String()+" (not an address the checks may connect to)")
				continue
			}
			if !s.probe(ctx, p.scheme, name, a, p.port, token) {
				failed = append(failed, a.String())
			}
		}
		if len(failed) == 0 {
			c.Status, c.Detail = CheckOK, "The server answered at "+joinAddrs(addrs)+"."
		} else {
			c.Status, c.Detail = CheckWarn, "No answer from this server at "+strings.Join(failed, ", ")+"."
			c.Fix = "Check that the port is forwarded to this server and open in its firewall. Many routers do not loop a host's own public address back; if so this check cannot succeed, and an order from Let's Encrypt may still work."
		}
		out = append(out, c)
	}
	return out
}

func orDefault(v, d string) string {
	if v == "" {
		return d
	}
	return v
}

// probe fetches the token from one address, with the name as Host (and SNI).
func (s *Service) probe(ctx context.Context, scheme, name string, a netip.Addr, port, token string) bool {
	d := &net.Dialer{Timeout: 5 * time.Second, Control: func(_, address string, _ syscall.RawConn) error {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return err
		}
		ap, err := netip.ParseAddr(host)
		if err != nil || !s.dialAllowed(ap) {
			return errors.New("address refused")
		}
		return nil
	}}
	tr := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return d.DialContext(ctx, network, net.JoinHostPort(a.String(), port))
		},
		TLSClientConfig:     &tls.Config{ServerName: name, InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}, //nolint:gosec // only the token is read; the certificate may not exist yet
		TLSHandshakeTimeout: 5 * time.Second,
		DisableKeepAlives:   true,
	}
	cl := &http.Client{Transport: tr, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	u := url.URL{Scheme: scheme, Host: name, Path: "/.well-known/easyrmm-check/" + token}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return false
	}
	resp, err := cl.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 128))
	return resp.StatusCode == http.StatusOK && string(body) == token
}
