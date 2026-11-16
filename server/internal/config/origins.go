package config

import (
	"context"
	"net"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Origin is one address the server answers on: a console origin, and the
// MeshCentral origin remote sessions started from it use.
type Origin struct {
	Console *url.URL
	// Mesh is nil when remote access is off.
	Mesh *url.URL
	// Internal origins are served with a certificate from the server's own
	// certificate authority (ADR-0016).
	Internal bool
}

// Origins lists the addresses the server answers on: the public URL first,
// then, with IP access, one per IP address.
func (c *Config) Origins() []Origin {
	if c.PublicURL == nil {
		return nil
	}
	primary := Origin{Console: c.PublicURL, Internal: c.TLSMode == TLSInternal}
	if c.Mesh.Enabled {
		primary.Mesh = c.MeshPublicURL
	}
	out := []Origin{primary}
	if !c.IPAccess {
		return out
	}
	// The operator's certificate for an IP address decides which addresses
	// work; the internal certificate authority serves the rest.
	internal := c.TLSMode == TLSInternal || c.TLSMode == TLSAcme ||
		(c.TLSMode == TLSManual && !isIP(c.PublicURL.Hostname()))
	port := c.PublicURL.Port()
	for _, a := range c.IPAddresses {
		console := &url.URL{Scheme: "https", Host: hostPort(a.String(), port)}
		if slices.ContainsFunc(out, func(o Origin) bool { return Authority(o.Console) == Authority(console) }) {
			continue // the public URL is this address
		}
		// Behind an offloading proxy, the proxy serves the certificate.
		o := Origin{Console: console, Internal: internal}
		if c.Mesh.Enabled {
			o.Mesh = &url.URL{Scheme: "https", Host: net.JoinHostPort(a.String(), strconv.Itoa(c.IPMeshPort))}
		}
		out = append(out, o)
	}
	return out
}

// NeedsInternalCA reports whether any origin uses the internal certificate
// authority.
func (c *Config) NeedsInternalCA() bool {
	return slices.ContainsFunc(c.Origins(), func(o Origin) bool { return o.Internal })
}

// MeshListeners returns the addresses of the extra HTTPS listeners for
// MeshCentral origins on a port of their own (4443 for IP access). Offload
// mode has none: the proxy owns the public ports.
func (c *Config) MeshListeners() []string {
	if c.TLSMode == TLSOffload || c.PublicURL == nil {
		return nil
	}
	host, _, err := net.SplitHostPort(c.ListenHTTPS)
	if err != nil {
		return nil
	}
	public := PortOf(c.PublicURL)
	var out []string
	for _, o := range c.Origins() {
		if o.Mesh == nil || PortOf(o.Mesh) == public {
			continue // served by the main listener
		}
		addr := net.JoinHostPort(host, PortOf(o.Mesh))
		if !slices.Contains(out, addr) {
			out = append(out, addr)
		}
	}
	return out
}

// DetectAddresses fills IPAddresses when IP access is on and none are
// configured. Behind an offloading proxy nothing is detected: the proxy's
// configuration names the addresses.
func (c *Config) DetectAddresses(detect func() []netip.Addr) {
	if !c.IPAccess || c.ipConfigured || c.TLSMode == TLSOffload {
		return
	}
	c.IPAddresses = detect()
}

// PrimaryAddresses returns the addresses this host uses for outbound
// traffic, IPv4 and IPv6: the ones others most likely reach it on. It sends
// nothing; connecting a UDP socket only consults the routing table.
func PrimaryAddresses() []netip.Addr {
	var out []netip.Addr
	// A literal address needs no lookup, and a UDP connect does not wait on
	// the network; the timeout only bounds the unexpected.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	var d net.Dialer
	// Documentation addresses (RFC 5737, RFC 3849): routed by the default
	// route, never answered.
	for _, probe := range []string{"192.0.2.1:9", "[2001:db8::1]:9"} {
		conn, err := d.DialContext(ctx, "udp", probe)
		if err != nil {
			continue
		}
		if a, ok := conn.LocalAddr().(*net.UDPAddr); ok {
			if ip, ok := netip.AddrFromSlice(a.IP); ok {
				ip = ip.Unmap()
				if ip.IsGlobalUnicast() && !slices.Contains(out, ip) {
					out = append(out, ip)
				}
			}
		}
		_ = conn.Close()
	}
	return out
}

func (c *Config) validateIPAccess(add func(string, ...any)) {
	if c.IPMeshPort < 1 || c.IPMeshPort > 65535 {
		add("EASYRMM_IP_MESH_PORT must be between 1 and 65535")
	} else if c.IPAccess && c.Mesh.Enabled && c.PublicURL != nil && strconv.Itoa(c.IPMeshPort) == PortOf(c.PublicURL) {
		add("EASYRMM_IP_MESH_PORT must differ from the console's port (%s)", PortOf(c.PublicURL))
	}
	for _, a := range c.IPAddresses {
		if a.IsUnspecified() || a.IsMulticast() {
			add("EASYRMM_IP_ADDRESSES: %s cannot be served", a)
		}
	}
	if _, main, err := net.SplitHostPort(c.ListenHTTPS); err == nil {
		for _, l := range c.MeshListeners() {
			if _, p, _ := net.SplitHostPort(l); p == main {
				add("the remote-access port %s is the same as EASYRMM_LISTEN_HTTPS; choose another EASYRMM_IP_MESH_PORT or MeshCentral URL port", p)
			}
		}
	}
}

// PortOf returns a URL's port, 443 when it has none.
func PortOf(u *url.URL) string {
	if p := u.Port(); p != "" {
		return p
	}
	return "443"
}

// Authority is a URL's host and port in canonical form (lower case, no
// trailing dot, port 443 when none is given), for comparing origins.
func Authority(u *url.URL) string {
	return net.JoinHostPort(canonicalHost(u.Hostname()), PortOf(u))
}

// HostAuthority is Authority for a request's Host header.
func HostAuthority(hostport string) string {
	host, port, err := net.SplitHostPort(hostport)
	if err != nil {
		host, port = strings.Trim(hostport, "[]"), "443"
	}
	return net.JoinHostPort(canonicalHost(host), port)
}

// canonicalHost is a host name in canonical form.
func canonicalHost(h string) string {
	h = strings.ToLower(strings.TrimSuffix(h, "."))
	if a, err := netip.ParseAddr(h); err == nil {
		return a.Unmap().String()
	}
	return h
}

func hostPort(host, port string) string {
	if port != "" {
		return net.JoinHostPort(host, port)
	}
	if strings.Contains(host, ":") {
		return "[" + host + "]"
	}
	return host
}

func isIP(host string) bool { return net.ParseIP(host) != nil }
