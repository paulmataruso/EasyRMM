// Package addrpolicy decides which addresses the server dials for
// destinations people configure: an organization's webhooks now, its syslog
// destinations later (ADR-0053, "The address policy").
//
// The check runs on every address a connection is dialed to, after name
// resolution, and the connection is pinned to the address that passed: the
// dialer resolves the name itself, checks every address the name gives, and
// dials one of those, so a second lookup (DNS rebinding) never decides where
// a connection goes. The dialer's Control function checks the address again
// as the socket is made. Redirects are refused and no proxy is used.
package addrpolicy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/paulmataruso/easyrmm/server/internal/netguard"
)

// Mode is whose destination it is.
type Mode int

const (
	// Organization destinations are the strict policy: private networks and
	// the server's own networks need an approval.
	Organization Mode = iota
	// Platform destinations (platform channels, the mail server, audit
	// forwarding) keep netguard's rule: loopback, private addresses and the
	// server's own are allowed; link-local and cloud metadata are refused.
	Platform
)

// Timeouts: 10 seconds to connect, 30 for the whole request.
const (
	ConnectTimeout = 10 * time.Second
	RequestTimeout = 30 * time.Second
)

// Env is what the policy knows of the server and its network: read again
// every minute by Environment.
type Env struct {
	// Addrs are the server's own addresses (its interfaces', and
	// EASYRMM_IP_ADDRESSES), Nets the networks of its interfaces, Routed the
	// destinations it routes other than by its default route.
	Addrs  []netip.Addr
	Nets   []netip.Prefix
	Routed []netip.Prefix
	// NAT64 are the network's own /96 NAT64 prefixes (RFC 7050); NAT64Other
	// ones of another length, which are refused.
	NAT64      []netip.Prefix
	NAT64Other []netip.Prefix
	// Names are the deployment's names, lower case: refused as a URL's host.
	Names []string
}

// alwaysRefused are the ranges no destination may be in, approved or not.
var alwaysRefused = mustPrefixes(
	"0.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "224.0.0.0/4", "240.0.0.0/4", // includes the broadcast
	"192.0.0.0/24", "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "198.18.0.0/15",
	"::/128", "::1/128", "fe80::/10", "ff00::/8", "2001:db8::/32", "100::/64", "fec0::/10",
	"64:ff9b:1::/48", "2001::/32",
)

// needsApproval are the private ranges: allowed once approved.
var needsApproval = mustPrefixes("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "fc00::/7")

func mustPrefixes(s ...string) []netip.Prefix {
	out := make([]netip.Prefix, len(s))
	for i, p := range s {
		out[i] = netip.MustParsePrefix(p)
	}
	return out
}

func inAny(ps []netip.Prefix, a netip.Addr) bool {
	for _, p := range ps {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// forms lists an address as itself and as each IPv4 address it embeds.
func forms(a netip.Addr, env *Env) []netip.Addr {
	a = a.Unmap()
	var nat []netip.Prefix
	if env != nil {
		nat = env.NAT64
	}
	return append([]netip.Addr{a}, netguard.Embedded(a, nat...)...)
}

// Refuse says why the server does not connect to an address, or "" when it
// does. approved are the prefixes approved for this destination.
func Refuse(env *Env, mode Mode, a netip.Addr, approved []netip.Prefix) string {
	a = a.Unmap().WithZone("")
	if mode == Platform {
		for _, f := range forms(a, env) {
			if why := netguard.Refused(f); why != "" {
				return why
			}
		}
		return ""
	}
	if env == nil {
		env = &Env{}
	}
	if inAny(env.NAT64Other, a) {
		return "a NAT64 prefix of a length EasyRMM cannot read"
	}
	approval := false
	for _, f := range forms(a, env) {
		if why := netguard.Refused(f); why != "" {
			return why
		}
		if inAny(alwaysRefused, f) {
			return "an address no destination may be at (loopback, link-local, multicast, reserved or documentation)"
		}
		for _, s := range env.Addrs {
			if s.Unmap() == f {
				return "the server itself"
			}
		}
		if inAny(needsApproval, f) || inAny(env.Nets, f) || inAny(env.Routed, f) {
			approval = true
		}
	}
	if approval && !inAny(approved, a) {
		return ReasonApproval
	}
	return ""
}

// ReasonApproval is the reason given for a private or local address nobody
// approved: the one refusal an approval cures.
const ReasonApproval = "a private or local address that a super administrator has not approved for this channel"

// NeedsApproval says whether err is the refusal an approval cures.
func NeedsApproval(err error) bool {
	return errors.Is(err, ErrRefused) && strings.Contains(err.Error(), ReasonApproval)
}

// Policy is one destination's rules, fixed when it is made: the closure the
// dialer's Control uses is bound to these approved prefixes and this
// environment snapshot, and nothing is looked up at dial time.
type Policy struct {
	Mode     Mode
	Approved []netip.Prefix
	Env      Env
	// Resolve looks a name up; nil uses the system resolver.
	Resolve func(ctx context.Context, host string) ([]netip.Addr, error)
}

// ErrRefused wraps every refusal, so callers can tell the policy from the
// network. Its message names the host, never a URL's path or query.
var ErrRefused = errors.New("address policy")

func refusal(host, why string) error {
	return fmt.Errorf("%w: EasyRMM does not connect to %s: it is %s", ErrRefused, host, why)
}

// Control is a net.Dialer Control function bound to the policy.
func (p Policy) Control(_, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		host = address
	}
	a, err := netip.ParseAddr(host)
	if err != nil {
		return fmt.Errorf("%w: %q is not an address", ErrRefused, address)
	}
	if why := Refuse(&p.Env, p.Mode, a, p.Approved); why != "" {
		return refusal(a.String(), why)
	}
	return nil
}

func (p Policy) lookup(ctx context.Context, host string) ([]netip.Addr, error) {
	if p.Resolve != nil {
		return p.Resolve(ctx, host)
	}
	return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
}

// DialContext resolves the host, checks every address it gives, and dials
// one of them: the connection goes to the address that was checked.
func (p Policy) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	if p.Mode == Organization {
		for _, n := range p.Env.Names {
			if strings.EqualFold(strings.TrimSuffix(host, "."), n) {
				return nil, refusal(host, "one of this deployment's own names")
			}
		}
	}
	var addrs []netip.Addr
	if ip, perr := netip.ParseAddr(host); perr == nil {
		addrs = []netip.Addr{ip}
	} else if addrs, err = p.lookup(ctx, host); err != nil {
		return nil, fmt.Errorf("the name %s could not be resolved", host)
	}
	if len(addrs) == 0 {
		return nil, fmt.Errorf("the name %s has no address", host)
	}
	// One refused address refuses the name: a name that gives a public and
	// an internal address is no safer for the public one.
	for _, a := range addrs {
		if why := Refuse(&p.Env, p.Mode, a, p.Approved); why != "" {
			return nil, refusal(host, why)
		}
	}
	d := &net.Dialer{Timeout: ConnectTimeout, Control: p.Control}
	var last error
	for _, a := range addrs {
		c, derr := d.DialContext(ctx, network, net.JoinHostPort(a.Unmap().String(), port))
		if derr == nil {
			return c, nil
		}
		last = derr
	}
	return nil, last
}

// NewClient is an HTTPS client for one destination: TLS 1.2 or later, the
// host name verified (ca, PEM, if given is the only trust anchor), no proxy,
// no cookies, no redirects (an answer of 3xx is the caller's failure). An
// organization's client keeps no connection alive, so every request dials,
// and is checked, anew; a platform destination's keeps at most one.
func NewClient(p Policy, ca []byte) (*http.Client, *http.Transport, error) {
	tc := &tls.Config{MinVersion: tls.VersionTLS12}
	if len(ca) > 0 {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(ca) {
			return nil, nil, errors.New("the trusted certificate authority is not a PEM certificate")
		}
		tc.RootCAs = pool
	}
	tr := &http.Transport{
		Proxy:               nil,
		DialContext:         p.DialContext,
		TLSClientConfig:     tc,
		TLSHandshakeTimeout: ConnectTimeout,
		IdleConnTimeout:     90 * time.Second,
		DisableKeepAlives:   p.Mode == Organization,
	}
	if p.Mode == Platform {
		tr.MaxConnsPerHost = 1
	}
	c := &http.Client{
		Transport:     tr,
		Timeout:       RequestTimeout,
		Jar:           nil,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	return c, tr, nil
}

// URLError is a webhook address that is not usable, in a sentence people
// read as a field's message.
type URLError string

func (e URLError) Error() string { return string(e) }

// Destination is a webhook URL taken apart.
type Destination struct {
	Host string
	Port int
}

// ParseURL checks a webhook URL: HTTPS only, a host, no credentials, no
// fragment. It returns the host and port, the only parts ever shown or
// logged.
func ParseURL(raw string) (Destination, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return Destination{}, URLError("Enter a full web address, such as https://hooks.example.com/easyrmm.")
	}
	if u.Scheme != "https" {
		return Destination{}, URLError("The web address must start with https://. EasyRMM does not send to plain http.")
	}
	if u.User != nil {
		return Destination{}, URLError("The web address must not hold a user name or password.")
	}
	if u.Fragment != "" || len(raw) > 2048 {
		return Destination{}, URLError("The web address is too long, or holds a fragment.")
	}
	host := u.Hostname()
	if host == "" || strings.ContainsAny(host, " %") {
		return Destination{}, URLError("The web address has no usable host.")
	}
	port := 443
	if ps := u.Port(); ps != "" {
		if port, err = strconv.Atoi(ps); err != nil || port < 1 || port > 65535 {
			return Destination{}, URLError("The web address's port is not valid.")
		}
	}
	return Destination{Host: strings.ToLower(strings.TrimSuffix(host, ".")), Port: port}, nil
}

// ParsePrefixes reads approved prefixes: CIDRs, or single addresses.
func ParsePrefixes(in []string) ([]netip.Prefix, error) {
	out := make([]netip.Prefix, 0, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		if p, err := netip.ParsePrefix(s); err == nil {
			out = append(out, p.Masked())
			continue
		}
		a, err := netip.ParseAddr(s)
		if err != nil {
			return nil, fmt.Errorf("%q is not an address or a network", s)
		}
		a = a.Unmap()
		out = append(out, netip.PrefixFrom(a, a.BitLen()))
	}
	return out, nil
}

// Environment keeps the Env current: the interfaces, the routes, the NAT64
// prefix and the deployment's names, read again every minute.
type Environment struct {
	names func() []string
	extra []netip.Addr
	mu    sync.RWMutex
	env   Env
	// version increases whenever a reading differs from the one before, so
	// that a transport made under the old one is made anew.
	version uint64
	// Resolve is the resolver NAT64 discovery uses; nil is the system's.
	resolve func(ctx context.Context, host string) ([]netip.Addr, error)
}

// NewEnvironment reads the environment once. names lists the deployment's
// names (EASYRMM_PUBLIC_URL's and EASYRMM_MESH_PUBLIC_URL's hosts and the
// further names), extra the addresses of EASYRMM_IP_ADDRESSES.
func NewEnvironment(names func() []string, extra []netip.Addr) *Environment {
	e := &Environment{names: names, extra: extra}
	e.Refresh(context.Background())
	return e
}

// Snapshot is the environment as last read.
func (e *Environment) Snapshot() Env {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.env
}

// Run reads the environment again every minute, until ctx ends.
func (e *Environment) Run(ctx context.Context) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			e.Refresh(ctx)
		}
	}
}

// Refresh reads the environment now.
func (e *Environment) Refresh(ctx context.Context) {
	env := Env{}
	env.Addrs = append(env.Addrs, e.extra...)
	if ifs, err := net.Interfaces(); err == nil {
		for _, ifc := range ifs {
			as, err := ifc.Addrs()
			if err != nil {
				continue
			}
			for _, a := range as {
				if ipn, ok := a.(*net.IPNet); ok {
					if pfx, ok := netip.AddrFromSlice(ipn.IP); ok {
						pfx = pfx.Unmap()
						ones, _ := ipn.Mask.Size()
						if pfx.Is4() && len(ipn.Mask) == net.IPv6len {
							ones -= 96
						}
						env.Addrs = append(env.Addrs, pfx)
						if p, err := pfx.Prefix(max(ones, 0)); err == nil {
							env.Nets = append(env.Nets, p)
						}
					}
				}
			}
		}
	}
	env.Routed = readRoutes()
	env.NAT64, env.NAT64Other = e.discoverNAT64(ctx)
	if e.names != nil {
		for _, n := range e.names() {
			if n = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(n), ".")); n != "" {
				env.Names = append(env.Names, n)
			}
		}
	}
	e.mu.Lock()
	if !reflect.DeepEqual(e.env, env) {
		e.version++
	}
	e.env = env
	e.mu.Unlock()
}

// Version changes whenever the environment does.
func (e *Environment) Version() uint64 {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.version
}

// discoverNAT64 finds the network's NAT64 prefix the way RFC 7050 gives: the
// resolver's answer for ipv4only.arpa. A /96 prefix is read as embedding
// IPv4; one of another length is refused.
func (e *Environment) discoverNAT64(ctx context.Context) (ok96, other []netip.Prefix) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	look := e.resolve
	if look == nil {
		look = func(ctx context.Context, h string) ([]netip.Addr, error) {
			return net.DefaultResolver.LookupNetIP(ctx, "ip6", h)
		}
	}
	as, err := look(ctx, "ipv4only.arpa")
	if err != nil {
		return nil, nil
	}
	for _, a := range as {
		if !a.Is6() || a.Is4In6() {
			continue
		}
		b := a.As16()
		tail := [4]byte{b[12], b[13], b[14], b[15]}
		if tail == [4]byte{192, 0, 0, 170} || tail == [4]byte{192, 0, 0, 171} {
			if p, err := a.Prefix(96); err == nil {
				ok96 = append(ok96, p)
			}
			continue
		}
		if p, err := a.Prefix(64); err == nil {
			other = append(other, p)
		}
	}
	return ok96, other
}

// readRoutes lists the destinations the server routes other than by its
// default route (a VPN, a static route to another site), on Linux.
func readRoutes() []netip.Prefix {
	var out []netip.Prefix
	if b, err := os.ReadFile("/proc/net/route"); err == nil {
		out = append(out, parseRoutes4(string(b))...)
	}
	if b, err := os.ReadFile("/proc/net/ipv6_route"); err == nil {
		out = append(out, parseRoutes6(string(b))...)
	}
	return out
}

func parseRoutes4(s string) []netip.Prefix {
	var out []netip.Prefix
	for i, line := range strings.Split(s, "\n") {
		f := strings.Fields(line)
		if i == 0 || len(f) < 8 {
			continue
		}
		dst, err1 := strconv.ParseUint(f[1], 16, 32)
		mask, err2 := strconv.ParseUint(f[7], 16, 32)
		if err1 != nil || err2 != nil || mask == 0 {
			continue // the default route
		}
		// /proc prints the words in host (little-endian) order.
		a := netip.AddrFrom4([4]byte{byte(dst), byte(dst >> 8), byte(dst >> 16), byte(dst >> 24)}) //nolint:gosec // parsed with 32 bits
		if p, err := a.Prefix(bitsSet(uint32(mask))); err == nil {
			out = append(out, p)
		}
	}
	return out
}

func bitsSet(m uint32) int {
	n := 0
	for ; m != 0; m >>= 1 {
		n += int(m & 1)
	}
	return n
}

func parseRoutes6(s string) []netip.Prefix {
	var out []netip.Prefix
	for _, line := range strings.Split(s, "\n") {
		f := strings.Fields(line)
		if len(f) < 10 || len(f[0]) != 32 {
			continue
		}
		plen, err := strconv.ParseUint(f[1], 16, 8)
		if err != nil || plen == 0 || plen == 128 {
			continue // the default route, or one address (a local one)
		}
		var b [16]byte
		okHex := true
		for i := range 16 {
			v, err := strconv.ParseUint(f[0][i*2:i*2+2], 16, 8)
			if err != nil {
				okHex = false
				break
			}
			b[i] = byte(v)
		}
		if !okHex {
			continue
		}
		if p, err := netip.AddrFrom16(b).Prefix(int(plen)); err == nil {
			out = append(out, p)
		}
	}
	return out
}
