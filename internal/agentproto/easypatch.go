package agentproto

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/url"
	"path"
	"regexp"
	"strings"
	"time"
)

// Installing the EasyPatch agent (ADR-0031). The server tells an agent in a
// heartbeat answer to install the EasyPatch agent from the EasyPatch server
// EasyRMM is connected to and enroll it with a single-use token. Like an
// update, the instruction is signed with the job key and bound to the device;
// it binds each package's size and SHA-256 as EasyPatch's API reports them.

// EasyPatchInstallVersion is the version of EasyPatchInstallPayload.
const EasyPatchInstallVersion = 1

// MaxEasyPatchPackage bounds the size of an EasyPatch agent package.
const MaxEasyPatchPackage = 512 << 20

// MaxEasyPatchError bounds the error an agent reports for a failed install.
const MaxEasyPatchError = 500

// maxEasyPatchPackages bounds the packages one instruction offers.
const maxEasyPatchPackages = 8

// EasyPatch package formats and architectures, as EasyPatch names them.
const (
	EasyPatchMSI = "msi"
	EasyPatchDeb = "deb"
	EasyPatchRPM = "rpm"
)

// EasyPatchArch is EasyPatch's name for a Go architecture, or "" when
// EasyPatch has no agent for it.
func EasyPatchArch(goarch string) string {
	switch goarch {
	case "amd64":
		return "x64"
	case "arm64":
		return "arm64"
	}
	return ""
}

// EasyPatchPackage is one EasyPatch agent package the agent may install.
type EasyPatchPackage struct {
	FileName string `json:"fileName"`
	// URL is where EasyPatch serves the package (https).
	URL string `json:"url"`
	// Format is msi, deb or rpm.
	Format string `json:"format"`
	// Arch is x64 or arm64.
	Arch    string `json:"arch"`
	Version string `json:"version"`
	Size    int64  `json:"size"`
	SHA256  string `json:"sha256"`
}

// EasyPatchInstallPayload tells one device's agent to install and enroll the
// EasyPatch agent.
type EasyPatchInstallPayload struct {
	V int `json:"v"`
	// ID names this attempt; the agent reports its outcome against it.
	ID       string `json:"id"`
	DeviceID string `json:"deviceId"`
	// ServerURL is EasyPatch's public https address, which the EasyPatch
	// agent enrolls with.
	ServerURL string `json:"serverUrl"`
	// CACert is the PEM certificate of EasyPatch's private certificate
	// authority, empty when its certificate is publicly trusted. The download
	// trusts it besides the system's authorities, and the Windows agent
	// records it for its own connection (SERVERCACERT).
	CACert string `json:"caCert,omitempty"`
	// Packages are those for the device's platform and architecture; the
	// agent picks the one its package manager installs.
	Packages []EasyPatchPackage `json:"packages"`
	// Token is a single-use EasyPatch enrollment token. Agents never put it
	// on a command line or in a log.
	Token     string    `json:"token"`
	IssuedAt  time.Time `json:"issuedAt"`
	ExpiresAt time.Time `json:"expiresAt"`
}

// SignedEasyPatchInstall is an EasyPatchInstallPayload with the server's
// signature.
type SignedEasyPatchInstall struct {
	// Payload is the EasyPatchInstallPayload JSON, base64 (standard, padded).
	Payload string `json:"payload"`
	// Signature is the Ed25519 signature, base64 (standard, padded).
	Signature string `json:"signature"`
}

// EasyPatchInstallStatus is sent with each heartbeat by agents that can
// install the EasyPatch agent; older agents send none, and are sent no
// instructions.
type EasyPatchInstallStatus struct {
	// Busy is the ID of an install still running.
	Busy string `json:"busy,omitempty"`
	// Last is the outcome of the agent's last install, sent until an hour
	// after it ended or until another starts.
	Last *EasyPatchInstallReport `json:"last,omitempty"`
}

// EasyPatchInstallReport is the outcome of one install.
type EasyPatchInstallReport struct {
	ID    string `json:"id"`
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

const easyPatchSigContext = "EASYRMM-EASYPATCH-INSTALL-SIG-V1\n"

// Errors from VerifyEasyPatchInstall.
var (
	ErrEasyPatchSignature = errors.New("agentproto: the EasyPatch install's signature does not verify with the server key this agent trusts")
	ErrEasyPatchMalformed = errors.New("agentproto: the EasyPatch install is malformed")
	ErrEasyPatchDevice    = errors.New("agentproto: the EasyPatch install is for another device")
	ErrEasyPatchExpired   = errors.New("agentproto: the EasyPatch install has expired")
)

var (
	easyPatchFile  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}\.(msi|deb|rpm)$`)
	easyPatchToken = regexp.MustCompile(`^[\x21-\x7e]{8,256}$`)
)

// SignEasyPatchInstall signs an install with the server's job key.
func SignEasyPatchInstall(key ed25519.PrivateKey, p EasyPatchInstallPayload) (SignedEasyPatchInstall, error) {
	b, err := json.Marshal(p)
	if err != nil {
		return SignedEasyPatchInstall{}, err
	}
	sig := ed25519.Sign(key, append([]byte(easyPatchSigContext), b...))
	return SignedEasyPatchInstall{Payload: base64.StdEncoding.EncodeToString(b), Signature: base64.StdEncoding.EncodeToString(sig)}, nil
}

// VerifyEasyPatchInstall checks a signed install with the pinned server key
// and returns its payload. It refuses installs for other devices, expired
// ones, and any whose server, packages, certificate or token are not what
// they should be.
func VerifyEasyPatchInstall[K KeyArg](key K, s SignedEasyPatchInstall, deviceID string, now time.Time) (EasyPatchInstallPayload, error) {
	b, err := base64.StdEncoding.DecodeString(s.Payload)
	if err != nil {
		return EasyPatchInstallPayload{}, ErrEasyPatchMalformed
	}
	sig, err := base64.StdEncoding.DecodeString(s.Signature)
	if err != nil || !keysOf(key).verify(append([]byte(easyPatchSigContext), b...), sig) {
		return EasyPatchInstallPayload{}, ErrEasyPatchSignature
	}
	var p EasyPatchInstallPayload
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return EasyPatchInstallPayload{}, ErrEasyPatchMalformed
	}
	switch {
	case p.V != EasyPatchInstallVersion || p.ID == "" || len(p.ID) > 64 || !httpsURL(p.ServerURL) ||
		!easyPatchToken.MatchString(p.Token) || !validCA(p.CACert) || !validPackages(p.Packages):
		return p, ErrEasyPatchMalformed
	case p.DeviceID != deviceID:
		return p, ErrEasyPatchDevice
	case !now.Before(p.ExpiresAt):
		return p, ErrEasyPatchExpired
	}
	return p, nil
}

func validPackages(pkgs []EasyPatchPackage) bool {
	if len(pkgs) == 0 || len(pkgs) > maxEasyPatchPackages {
		return false
	}
	for _, k := range pkgs {
		m := easyPatchFile.FindStringSubmatch(k.FileName)
		u, err := url.Parse(k.URL)
		if m == nil || m[1] != k.Format || (k.Arch != "x64" && k.Arch != "arm64") || !ValidVersion(k.Version) ||
			k.Size < 1 || k.Size > MaxEasyPatchPackage || !ValidSHA256(k.SHA256) ||
			err != nil || !httpsURL(k.URL) || path.Base(u.Path) != k.FileName {
			return false
		}
	}
	return true
}

// httpsURL reports whether s is an https address without credentials, a
// query or a fragment.
func httpsURL(s string) bool {
	u, err := url.Parse(s)
	return err == nil && u.Scheme == "https" && u.Host != "" && u.User == nil && u.RawQuery == "" && u.Fragment == "" &&
		!strings.ContainsAny(s, " \t\r\n")
}

// validCA reports whether s is empty or one PEM certificate.
func validCA(s string) bool {
	if s == "" {
		return true
	}
	block, rest := pem.Decode([]byte(s))
	if block == nil || block.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
		return false
	}
	_, err := x509.ParseCertificate(block.Bytes)
	return err == nil
}
