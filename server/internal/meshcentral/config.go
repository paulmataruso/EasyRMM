package meshcentral

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
)

// ServiceAccount is the MeshCentral administrator EasyRMM acts as. It is
// created by the container's start script with no usable password; EasyRMM
// authenticates as it with cookies sealed by the shared key.
const ServiceAccount = "easyrmm-service"

// ContainerConfigDir is where the MeshCentral container mounts the directory
// EasyRMM writes its configuration into (deploy/docker-compose.yml).
const ContainerConfigDir = "/easyrmm/config"

// ServerConfig is what EasyRMM decides about its MeshCentral server.
type ServerConfig struct {
	// Hostname is the public MeshCentral hostname (mesh.rmm.example.com) or
	// IP address, which agents connect to.
	Hostname string
	// Listen is the loopback address MeshCentral serves plain HTTP on, behind
	// the EasyRMM edge, e.g. 127.0.0.1:14430.
	Listen string
	// PublicPort is the HTTPS port agents and browsers use (443).
	PublicPort int
	// TrustedProxy is the address the edge connects to MeshCentral from; only
	// its X-Forwarded-For headers are believed.
	TrustedProxy string
	// FramingOrigins are the EasyRMM console origins (the public URL and,
	// with IP access, the server's IP addresses), the only pages allowed to
	// embed MeshCentral.
	FramingOrigins []string
	// MeshOrigins are the MeshCentral origins EasyRMM serves sessions on
	// (the public MeshCentral URL and, with IP access, one per IP address).
	// MeshCentral refuses a session's control connection from a page on
	// any other host. Hostname is always allowed.
	MeshOrigins []string
	// CertURL is where MeshCentral reads the TLS certificate agents see, so it
	// can tell agents which certificate to expect.
	CertURL string
	// LoginKey is the shared loginCookieEncryptionKey (KeySize bytes).
	LoginKey []byte
	// SessionKey encrypts MeshCentral's own web session cookies; keeping it
	// fixed lets sessions survive a restart.
	SessionKey string
	// ConfigMount is where the configuration directory is mounted inside the
	// MeshCentral container (default ContainerConfigDir). MeshCentral serves
	// the session view's script from its web folder (WriteWeb).
	ConfigMount string
}

func (c ServerConfig) configMount() string {
	if c.ConfigMount == "" {
		return ContainerConfigDir
	}
	return c.ConfigMount
}

// Validate checks the configuration.
func (c ServerConfig) Validate() error {
	var errs []error
	if c.Hostname == "" {
		errs = append(errs, errors.New("hostname is required"))
	}
	host, port, err := net.SplitHostPort(c.Listen)
	if err != nil {
		errs = append(errs, fmt.Errorf("listen address: %w", err))
	} else if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
		errs = append(errs, fmt.Errorf("listen address must be loopback, got %q", host))
	} else if p, err := strconv.Atoi(port); err != nil || p < 1 || p > 65535 {
		errs = append(errs, fmt.Errorf("listen port %q is invalid", port))
	}
	if c.PublicPort < 1 || c.PublicPort > 65535 {
		errs = append(errs, errors.New("public port is out of range"))
	}
	if net.ParseIP(c.TrustedProxy) == nil {
		errs = append(errs, fmt.Errorf("trusted proxy must be an IP address, got %q", c.TrustedProxy))
	}
	if len(c.FramingOrigins) == 0 {
		errs = append(errs, errors.New("at least one framing origin is required"))
	}
	for _, o := range c.FramingOrigins {
		if !isOrigin(o) {
			errs = append(errs, fmt.Errorf("framing origin must be an https origin, got %q", o))
		}
	}
	for _, o := range c.MeshOrigins {
		if !isOrigin(o) {
			errs = append(errs, fmt.Errorf("MeshCentral origin must be an https origin, got %q", o))
		}
	}
	if u, err := url.Parse(c.CertURL); err != nil || (u.Scheme != "https" && u.Scheme != "file") {
		errs = append(errs, fmt.Errorf("certificate URL must be https:// or file://, got %q", c.CertURL))
	}
	if len(c.LoginKey) != KeySize {
		errs = append(errs, fmt.Errorf("login key must be %d bytes", KeySize))
	}
	if len(c.SessionKey) < 32 {
		errs = append(errs, errors.New("session key must be at least 32 characters"))
	}
	if m := c.configMount(); !path.IsAbs(m) || path.Clean(m) != m {
		errs = append(errs, fmt.Errorf("config mount must be a clean absolute path, got %q", m))
	}
	return errors.Join(errs...)
}

// isOrigin reports whether o is an https origin: a scheme and host, no path.
func isOrigin(o string) bool {
	u, err := url.Parse(o)
	return err == nil && u.Scheme == "https" && u.Host != "" && u.Path == ""
}

// allowedOrigins returns the hosts whose pages MeshCentral accepts a
// session's control connection from: Hostname and the host of every
// MeshCentral origin, once each.
func (c ServerConfig) allowedOrigins() []string {
	hosts := []string{originHostname(c.Hostname)}
	for _, o := range c.MeshOrigins {
		u, _ := url.Parse(o) // checked by Validate
		if h := originHostname(u.Hostname()); !slices.Contains(hosts, h) {
			hosts = append(hosts, h)
		}
	}
	return hosts
}

// originHostname writes a host the way MeshCentral reads it from a
// browser's Origin header, with Node's URL.hostname, since it compares the
// two as strings: a name in lower case, an IPv6 address compressed and in
// brackets, an IPv4-mapped one in hexadecimal ([::ffff:c000:201]).
func originHostname(host string) string {
	a, err := netip.ParseAddr(host)
	switch {
	case err != nil:
		return strings.ToLower(host)
	case a.Is4():
		return a.String()
	case a.Is4In6():
		b := a.As16()
		return fmt.Sprintf("[::ffff:%x:%x]", uint16(b[12])<<8|uint16(b[13]), uint16(b[14])<<8|uint16(b[15]))
	default:
		return "[" + a.String() + "]"
	}
}

// Render returns MeshCentral's config.json. EasyRMM rewrites it on every
// start, so edits to the file do not survive.
//
// Everything not needed for agents and embedded sessions is switched off:
// account sign-up, Intel AMT, the HTTP redirect and MPS ports, WebRTC, guest
// sharing, login tokens created by users, anonymous agent downloads,
// self-update, plugins and MeshCentral's own backups (the deployment backs
// up its data volume). Its pages are compressed and load EasyRMM's session
// view tuning from the web folder in the configuration directory (WriteWeb,
// ADR-0025). A session's control connection is accepted only from the
// MeshCentral origins EasyRMM serves (allowedOrigin, ADR-0016).
func (c ServerConfig) Render() ([]byte, error) {
	if err := c.Validate(); err != nil {
		return nil, fmt.Errorf("meshcentral config: %w", err)
	}
	host, port, _ := net.SplitHostPort(c.Listen)
	p, _ := strconv.Atoi(port)
	cfg := map[string]any{
		"settings": map[string]any{
			"cert":                     c.Hostname,
			"port":                     p,
			"portBind":                 host,
			"aliasPort":                c.PublicPort,
			"exactPorts":               true,
			"redirPort":                0,
			"mpsPort":                  0,
			"tlsOffload":               c.TrustedProxy,
			"trustedProxy":             c.TrustedProxy,
			"WANonly":                  true,
			"webRTC":                   false,
			"amtManager":               false,
			"allowedFramingOrigins":    c.FramingOrigins,
			"loginCookieEncryptionKey": KeyHex(c.LoginKey),
			"sessionKey":               c.SessionKey,
			"selfUpdate":               false,
			"autoBackup":               false,
			"plugins":                  map[string]any{"enabled": false},
			"agentPong":                300,
			"browserPong":              60,
			// Gzip pages and scripts: a session view loads about 4.6 MB
			// uncompressed, 1.1 MB compressed (ADR-0025). WebSockets and
			// file downloads are not compressed.
			"compression": true,
		},
		"domains": map[string]any{
			"": map[string]any{
				"title":       "EasyRMM remote access",
				"newAccounts": false,
				// MeshCentral closes a session's control connection
				// (control.ashx, "invalidorigin") when the page's Origin
				// host is not listed. Without a list it accepts only
				// `cert`, refusing sessions from every other MeshCentral
				// origin, such as an IP address's (ADR-0016). Never true:
				// that accepts any origin.
				"allowedOrigin": c.allowedOrigins(),
				// Agent installers only for signed-in users; agents updating
				// themselves get a signed link from MeshCentral.
				"lockAgentDownload":  true,
				"certUrl":            c.CertURL,
				"webPublicPath":      path.Join(c.configMount(), webDir),
				"guestDeviceSharing": false,
				"agentInviteCodes":   false,
				"novnc":              false,
				// MeshCentral's web RDP client, for RDP sessions (ADR-0026).
				// The gateway admits its relay only for a device with an
				// RDP grant, by node ID; the stand-alone page stays blocked.
				// Credentials are typed for each session and never stored.
				"mstsc":                        true,
				"allowSavingDeviceCredentials": false,
				"ssh":                          false,
				"geoLocation":                  false,
				"passwordRequirements": map[string]any{
					"loginTokens":       false,
					"otp2factor":        false,
					"backupcode2factor": false,
					"sms2factor":        false,
					"push2factor":       false,
					"email2factor":      false,
					"msg2factor":        false,
					"allowAccountReset": false,
				},
				"myServer": map[string]any{
					"Backup": false, "Restore": false, "Upgrade": false,
					"ErrorLog": false, "Console": false, "Trace": false,
				},
			},
		},
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(cfg); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// WriteConfig writes config.json into dir if its content changed, atomically
// and readable only by its owner (MeshCentral runs as the same user). It
// reports whether the file changed; the MeshCentral container's start
// script restarts MeshCentral when it does.
func WriteConfig(dir string, content []byte) (bool, error) {
	changed, err := writeFile(filepath.Join(dir, "config.json"), content)
	if err != nil {
		return false, fmt.Errorf("writing MeshCentral config: %w", err)
	}
	return changed, nil
}

// writeFile replaces a file with content if it differs, atomically and
// readable only by its owner. It reports whether the file changed.
func writeFile(name string, content []byte) (bool, error) {
	if old, err := os.ReadFile(name); err == nil && bytes.Equal(old, content) { //nolint:gosec // a file in the configured MeshCentral config directory
		return false, nil
	}
	tmp, err := os.CreateTemp(filepath.Dir(name), "."+filepath.Base(name)+"-*")
	if err != nil {
		return false, err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return false, err
	}
	if _, err := tmp.Write(content); err != nil {
		_ = tmp.Close()
		return false, err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return false, err
	}
	if err := tmp.Close(); err != nil {
		return false, err
	}
	if err := os.Rename(tmp.Name(), name); err != nil {
		return false, err
	}
	return true, nil
}
