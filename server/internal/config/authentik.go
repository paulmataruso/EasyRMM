package config

import (
	"net"
	"strings"
)

// AuthentikClientID is EasyRMM's client ID at the Authentik in its
// deployment: the blueprint (docker/authentik/easyrmm.yaml) creates the
// client with it.
const AuthentikClientID = "easyrmm"

// DefaultAuthentikUpstream is where the authentik-server service listens
// (deploy/docker-compose.yml).
const DefaultAuthentikUpstream = "127.0.0.1:18280"

// Authentik is the sign-in service of this deployment, chosen with setup.sh
// --with-authentik (one-product plan, phase A; ADR-0044). EasyRMM's edge
// serves its sign-in name, EasyRMM signs in through it as a provider the
// deployment manages, and the administrator's account is made from it.
type Authentik struct {
	// Hostname is Authentik's own name, such as auth.example.com; "" when
	// Authentik is not part of the deployment.
	Hostname string
	// AdminEmail is the first super administrator's address. Its domain is
	// the one the provider may sign in.
	AdminEmail string
	// ClientSecret is EasyRMM's client secret at Authentik, which setup.sh
	// generates and the blueprint gives the client.
	ClientSecret string
	// Upstream is Authentik's plain-HTTP listener on loopback, where the
	// edge forwards the sign-in name.
	Upstream string
}

// Enabled reports whether Authentik is part of the deployment.
func (a Authentik) Enabled() bool { return a.Hostname != "" }

// Issuer is the OpenID issuer of EasyRMM's application at Authentik (the
// provider's issuer mode is per provider; the application's slug is
// easyrmm).
func (a Authentik) Issuer() string { return "https://" + a.Hostname + "/application/o/easyrmm/" }

// AdminDomain is the domain of the administrator's address.
func (a Authentik) AdminDomain() string {
	_, domain, _ := strings.Cut(a.AdminEmail, "@")
	return domain
}

func (c *Config) loadAuthentik(l *loader) {
	a := Authentik{
		Hostname:   strings.ToLower(strings.TrimSuffix(l.str("EASYRMM_AUTHENTIK_HOSTNAME", ""), ".")),
		AdminEmail: strings.ToLower(l.str("EASYRMM_AUTHENTIK_ADMIN_EMAIL", "")),
		Upstream:   l.orDefault("EASYRMM_AUTHENTIK_UPSTREAM", DefaultAuthentikUpstream),
	}
	if a.Enabled() {
		a.ClientSecret = l.secret("EASYRMM_AUTHENTIK_CLIENT_SECRET")
		c.Authentik = a
	}
}

// validateAuthentik checks the settings setup.sh --with-authentik writes.
// The sign-in name itself is checked with the other names the edge serves
// (validateExtraHostnames).
func (c *Config) validateAuthentik(add func(string, ...any)) {
	a := c.Authentik
	if !a.Enabled() {
		return
	}
	if c.TLSMode == TLSOffload {
		add("EASYRMM_AUTHENTIK_HOSTNAME needs EasyRMM to own ports 80 and 443 (EASYRMM_TLS_MODE acme, manual or internal): EasyRMM's edge serves Authentik's name and reaches it on loopback")
	}
	if !validEmail(a.AdminEmail) {
		add("EASYRMM_AUTHENTIK_ADMIN_EMAIL must be the administrator's email address, such as admin@example.com, got %q", a.AdminEmail)
	}
	if len(a.ClientSecret) < 32 {
		add("EASYRMM_AUTHENTIK_CLIENT_SECRET must be at least 32 characters; run deploy/scripts/setup.sh --with-authentik to add it")
	}
	host, port, err := net.SplitHostPort(a.Upstream)
	if ip := net.ParseIP(host); err != nil || ip == nil || !ip.IsLoopback() || port == "" {
		add("EASYRMM_AUTHENTIK_UPSTREAM must be a loopback address and port such as %s, got %q", DefaultAuthentikUpstream, a.Upstream)
	}
}

// validEmail accepts the addresses Authentik and EasyRMM both take: one @,
// a local part without spaces, and a DNS name after it.
func validEmail(e string) bool {
	local, domain, ok := strings.Cut(e, "@")
	return ok && local != "" && len(e) <= 254 && !strings.ContainsAny(local, " \t\r\n\"<>,;:@") && validHostname(domain)
}
