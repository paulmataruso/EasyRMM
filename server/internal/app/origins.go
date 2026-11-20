package app

import (
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strings"

	"github.com/paulmataruso/easyrmm/server/internal/config"
	"github.com/paulmataruso/easyrmm/server/internal/httpapi"
	"github.com/paulmataruso/easyrmm/server/internal/pki"
)

// origins describes the addresses the server answers on (ADR-0016), with
// the key pin of those served by the internal certificate authority.
func origins(cfg *config.Config, ca *pki.Authority, remoteOn bool) []httpapi.Origin {
	var out []httpapi.Origin
	for _, o := range cfg.Origins() {
		h := httpapi.Origin{Console: originString(o.Console)}
		if remoteOn && o.Mesh != nil {
			h.Mesh = originString(o.Mesh)
		}
		if o.Internal && ca != nil {
			h.Pin, h.KeyPin = ca.Pin(), ca.KeyPin()
		}
		out = append(out, h)
	}
	return out
}

// originString is scheme://host[:port], without a path.
func originString(u *url.URL) string {
	return (&url.URL{Scheme: u.Scheme, Host: u.Host}).String()
}

// internalAddresses are the names and IP addresses the internal
// certificate authority's server certificate covers.
func internalAddresses(cfg *config.Config) (names []string, ips []net.IP) {
	add := func(u *url.URL) {
		if u == nil {
			return
		}
		if a, err := netip.ParseAddr(u.Hostname()); err == nil {
			ip := net.IP(a.Unmap().AsSlice())
			if !slices.ContainsFunc(ips, ip.Equal) {
				ips = append(ips, ip)
			}
		} else if !slices.Contains(names, u.Hostname()) {
			names = append(names, u.Hostname())
		}
	}
	for _, o := range cfg.Origins() {
		if o.Internal {
			add(o.Console)
			add(o.Mesh)
		}
	}
	if cfg.TLSMode == config.TLSInternal {
		for _, h := range cfg.ExtraHostnames() {
			add(&url.URL{Host: h})
		}
	}
	return names, ips
}

// hostHandlers serve the names the edge answers besides its origins
// (config.ExtraHostnames), on any port.
type hostHandlers map[string]http.Handler

func (h hostHandlers) match(hostHeader string) (http.Handler, bool) {
	host, _, err := net.SplitHostPort(config.HostAuthority(hostHeader))
	if err != nil {
		return nil, false
	}
	x, ok := h[host]
	return x, ok
}

// route is where a request goes: the console (and agent API) of an origin,
// or the MeshCentral gateway.
type route struct {
	origin httpapi.Origin
	mesh   bool
}

// router maps a request's Host to a route. The host and port decide, since
// on an IP address the console and MeshCentral share the host; a host that
// only one kind of route uses also matches on any port (behind a proxy that
// changes the port, or the development server).
type router struct {
	exact  map[string]route
	byHost map[string][]route
}

func newRouter(all []httpapi.Origin) *router {
	rt := &router{exact: map[string]route{}, byHost: map[string][]route{}}
	add := func(origin string, r route) {
		u, err := url.Parse(origin)
		if err != nil || u.Host == "" {
			return
		}
		a := config.Authority(u)
		if _, dup := rt.exact[a]; dup {
			return
		}
		rt.exact[a] = r
		host, _, _ := net.SplitHostPort(a)
		rt.byHost[host] = append(rt.byHost[host], r)
	}
	for _, o := range all {
		add(o.Console, route{origin: o})
		if o.Mesh != "" {
			add(o.Mesh, route{origin: o, mesh: true})
		}
	}
	return rt
}

func (rt *router) match(hostHeader string) (route, bool) {
	if strings.TrimSpace(hostHeader) == "" {
		return route{}, false
	}
	a := config.HostAuthority(hostHeader)
	if r, ok := rt.exact[a]; ok {
		return r, true
	}
	host, _, err := net.SplitHostPort(a)
	if err != nil {
		return route{}, false
	}
	rs := rt.byHost[host]
	if len(rs) == 0 {
		return route{}, false
	}
	for _, r := range rs[1:] {
		if r.mesh != rs[0].mesh {
			return route{}, false // ambiguous without the right port
		}
	}
	return rs[0], true
}
