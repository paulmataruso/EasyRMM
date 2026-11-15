package meshcentral

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
)

// ServiceAccount is the MeshCentral administrator EasyRMM acts as. It is
// created by the container's start script with no usable password; EasyRMM
// authenticates as it with cookies sealed by the shared key.
const ServiceAccount = "easyrmm-service"

// ServerConfig is what EasyRMM decides about its MeshCentral server.
type ServerConfig struct {
	// Hostname is the public MeshCentral hostname (mesh.rmm.example.com).
	Hostname string
	// Listen is the loopback address MeshCentral serves plain HTTP on, behind
	// the EasyRMM edge, e.g. 127.0.0.1:14430.
	Listen string
	// PublicPort is the HTTPS port agents and browsers use (443).
	PublicPort int
	// TrustedProxy is the address the edge connects to MeshCentral from; only
	// its X-Forwarded-For headers are believed.
	TrustedProxy string
	// FramingOrigin is the EasyRMM application origin, the only page allowed
	// to embed MeshCentral.
	FramingOrigin string
	// CertURL is where MeshCentral reads the TLS certificate agents see, so it
	// can tell agents which certificate to expect.
	CertURL string
	// LoginKey is the shared loginCookieEncryptionKey (KeySize bytes).
	LoginKey []byte
	// SessionKey encrypts MeshCentral's own web session cookies; keeping it
	// fixed lets sessions survive a restart.
	SessionKey string
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
	if u, err := url.Parse(c.FramingOrigin); err != nil || u.Scheme != "https" || u.Host == "" || u.Path != "" {
		errs = append(errs, fmt.Errorf("framing origin must be an https origin, got %q", c.FramingOrigin))
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
	return errors.Join(errs...)
}

// Render returns MeshCentral's config.json. EasyRMM rewrites it on every
// start, so edits to the file do not survive.
//
// Everything not needed for agents and embedded sessions is switched off:
// account sign-up, Intel AMT, the HTTP redirect and MPS ports, WebRTC, guest
// sharing, login tokens created by users, anonymous agent downloads,
// self-update, plugins and MeshCentral's own backups (the deployment backs
// up its data volume).
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
			"allowedFramingOrigins":    []string{c.FramingOrigin},
			"loginCookieEncryptionKey": KeyHex(c.LoginKey),
			"sessionKey":               c.SessionKey,
			"selfUpdate":               false,
			"autoBackup":               false,
			"plugins":                  map[string]any{"enabled": false},
			"agentPong":                300,
			"browserPong":              60,
		},
		"domains": map[string]any{
			"": map[string]any{
				"title":       "EasyRMM remote access",
				"newAccounts": false,
				// Agent installers only for signed-in users; agents updating
				// themselves get a signed link from MeshCentral.
				"lockAgentDownload":  true,
				"certUrl":            c.CertURL,
				"guestDeviceSharing": false,
				"agentInviteCodes":   false,
				"novnc":              false,
				"mstsc":              false,
				"ssh":                false,
				"geoLocation":        false,
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
	path := filepath.Join(dir, "config.json")
	if old, err := os.ReadFile(path); err == nil && bytes.Equal(old, content) { //nolint:gosec // the configured MeshCentral config directory
		return false, nil
	}
	tmp, err := os.CreateTemp(dir, ".config-*.json")
	if err != nil {
		return false, fmt.Errorf("writing MeshCentral config: %w", err)
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
	if err := os.Rename(tmp.Name(), path); err != nil {
		return false, fmt.Errorf("writing MeshCentral config: %w", err)
	}
	return true, nil
}
