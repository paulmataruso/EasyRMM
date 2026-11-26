package agentproto

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"
)

// Agent trust (ADR-0055, slice 5b1). The server asks one device's agent to
// verify the certificate chains a name will be served with, with the trust the
// agent really has on that computer, and, for a move, to widen that trust.
// The instruction is signed with the job key under a context of its own, as an
// update is (ADR-0027); the agent widens its trust only for an instruction
// that verifies with the key it pinned, and only when the target chain
// verifies on the computer itself.

// CapTrust is announced in HeartbeatRequest.Caps by an agent that understands
// trust instructions; the server sends one only to such an agent (ADR-0009).
const CapTrust = "tls.trust.v1"

// TrustPayloadVersion is the version of TrustPayload.
const TrustPayloadVersion = 1

// TrustValid is how long a signed trust instruction stays valid. An agent
// refuses one that claims longer, so that a copy cannot be replayed late.
const TrustValid = 10 * time.Minute

// The purposes of a chain the agent is asked to verify.
const (
	// TrustTarget is the chain a move will serve. The agent widens its trust
	// only when every target chain of the instruction verifies.
	TrustTarget = "target"
	// TrustFallback is the chain the name falls back to (the authority's, or
	// the operator's files'). It never widens anything; a device that fails
	// it is shown as unprotected.
	TrustFallback = "fallback"
	// TrustServed is the chain served now.
	TrustServed = "served"
)

// The scopes of a result: whose trust was checked.
const (
	// TrustScopeAgent is the EasyRMM agent's own trust.
	TrustScopeAgent = "agent"
	// TrustScopeEasyPatch is the EasyPatch agent's, checked by the EasyRMM
	// agent against the system's roots alone (a stand-in on Linux).
	TrustScopeEasyPatch = "easypatch"
)

// Limits shared by both sides.
const (
	// MaxTrustChains bounds the chains of one instruction, for the agent's
	// origin and for the EasyPatch host together.
	MaxTrustChains = 8
	// MaxTrustChainLen bounds one chain's certificates.
	MaxTrustChainLen = 8
	// MaxTrustAddCerts bounds the certificates an instruction adds to the
	// agent's trust.
	MaxTrustAddCerts = 4
	// MaxTrustCertBytes bounds one certificate's DER.
	MaxTrustCertBytes = 8 << 10
	// MaxTrustError bounds the error an agent reports for a chain.
	MaxTrustError = 300
	// MaxTrustResults bounds the results of one report.
	MaxTrustResults = 2 * MaxTrustChains
)

// TrustChain is one chain to verify: the exact chain a source will serve,
// leaf first, each certificate's DER in base64 (standard, padded).
type TrustChain struct {
	// ID names the chain within the instruction; the result echoes it.
	ID      string   `json:"id"`
	Purpose string   `json:"purpose"`
	Chain   []string `json:"chain"`
}

// TrustPayload tells one device's agent to verify chains and, for a target
// chain, to widen its trust.
type TrustPayload struct {
	V int `json:"v"`
	// ID names the request; the agent reports against it. The same ID is
	// sent again until its report arrives.
	ID       string `json:"id"`
	DeviceID string `json:"deviceId"`
	// Origin is the host name the agent's signed requests go to. The agent
	// refuses an instruction for another, and verifies each chain for it.
	Origin string `json:"origin"`
	// AddCerts are certificates (DER, base64) to add to the agent's trust
	// when the target chain verifies: the authority's, when the move needs
	// it. Each must be a certificate authority's.
	AddCerts []string     `json:"addCerts,omitempty"`
	Chains   []TrustChain `json:"chains"`
	// EasyPatchHost is the host the device's EasyPatch agent uses, when it
	// differs from Origin, and EasyPatchChains the chains to verify for it
	// against the system's roots alone.
	EasyPatchHost   string       `json:"easyPatchHost,omitempty"`
	EasyPatchChains []TrustChain `json:"easyPatchChains,omitempty"`
	IssuedAt        time.Time    `json:"issuedAt"`
	ExpiresAt       time.Time    `json:"expiresAt"`
}

// SignedTrust is a TrustPayload with the server's signature.
type SignedTrust struct {
	// Payload is the TrustPayload JSON, base64 (standard, padded).
	Payload string `json:"payload"`
	// Signature is the Ed25519 signature, base64 (standard, padded).
	Signature string `json:"signature"`
}

// TrustReport is what the agent sends in its heartbeat after it handled an
// instruction, until a heartbeat answer no longer carries that instruction.
type TrustReport struct {
	// ID is the instruction's.
	ID string `json:"id"`
	// Refused says why the instruction was not carried out at all: its
	// signature, device, origin or age did not hold. Never set with Results.
	Refused string        `json:"refused,omitempty"`
	Results []TrustResult `json:"results,omitempty"`
	// Widened is true once the agent trusts the system's roots and its CA
	// file together, which this instruction or an earlier one made it do.
	Widened bool `json:"widened,omitempty"`
	// Trusts is what the agent trusts now, for the console: "system",
	// "ca-file" or "system+ca-file". Informational: nothing treats it as
	// proof that a chain verifies.
	Trusts string `json:"trusts,omitempty"`
}

// TrustResult is one chain's outcome.
type TrustResult struct {
	// Chain is TrustChain.ID.
	Chain string `json:"chain"`
	Scope string `json:"scope"`
	OK    bool   `json:"ok"`
	// Error is why the chain did not verify, bounded by MaxTrustError.
	Error string `json:"error,omitempty"`
}

const trustSigContext = "EASYRMM-TRUST-SIG-V1\n"

// Errors from VerifyTrust.
var (
	ErrTrustSignature = errors.New("agentproto: the trust instruction's signature does not verify with the server key this agent trusts")
	ErrTrustMalformed = errors.New("agentproto: the trust instruction is malformed")
	ErrTrustDevice    = errors.New("agentproto: the trust instruction is for another device")
	ErrTrustOrigin    = errors.New("agentproto: the trust instruction is for another origin")
	ErrTrustExpired   = errors.New("agentproto: the trust instruction has expired")
	ErrTrustFuture    = errors.New("agentproto: the trust instruction was issued in the future")
)

// SignTrust signs a trust instruction with the server's job key. It refuses
// a payload the agent would refuse as malformed.
func SignTrust(key ed25519.PrivateKey, p TrustPayload) (SignedTrust, error) {
	if err := p.validate(); err != nil {
		return SignedTrust{}, err
	}
	b, err := json.Marshal(p)
	if err != nil {
		return SignedTrust{}, err
	}
	sig := ed25519.Sign(key, append([]byte(trustSigContext), b...))
	return SignedTrust{Payload: base64.StdEncoding.EncodeToString(b), Signature: base64.StdEncoding.EncodeToString(sig)}, nil
}

// VerifyTrust checks a signed trust instruction with the pinned server key and
// returns its payload. It refuses one for another device or origin, one that
// is expired, issued in the future or valid longer than TrustValid, and one
// with unknown fields. A nil or wrong-sized key never verifies: an agent with
// no pinned key refuses every instruction.
func VerifyTrust(key ed25519.PublicKey, s SignedTrust, deviceID, origin string, now time.Time) (TrustPayload, error) {
	b, err := base64.StdEncoding.DecodeString(s.Payload)
	if err != nil {
		return TrustPayload{}, ErrTrustMalformed
	}
	sig, err := base64.StdEncoding.DecodeString(s.Signature)
	if err != nil || len(key) != ed25519.PublicKeySize || !ed25519.Verify(key, append([]byte(trustSigContext), b...), sig) {
		return TrustPayload{}, ErrTrustSignature
	}
	var p TrustPayload
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil || dec.More() {
		return TrustPayload{}, ErrTrustMalformed
	}
	if err := p.validate(); err != nil {
		return p, err
	}
	switch {
	case p.DeviceID != deviceID:
		return p, ErrTrustDevice
	case !strings.EqualFold(p.Origin, origin):
		return p, ErrTrustOrigin
	case !now.Before(p.ExpiresAt):
		return p, ErrTrustExpired
	case p.IssuedAt.After(now.Add(MaxSkew)):
		return p, ErrTrustFuture
	}
	return p, nil
}

func (p TrustPayload) validate() error {
	bad := func(format string, a ...any) error {
		return fmt.Errorf("%w: %s", ErrTrustMalformed, fmt.Sprintf(format, a...))
	}
	switch {
	case p.V != TrustPayloadVersion:
		return bad("version %d", p.V)
	case p.ID == "" || len(p.ID) > 64:
		return bad("id")
	case p.DeviceID == "" || len(p.DeviceID) > 64:
		return bad("device")
	case !validHost(p.Origin):
		return bad("origin")
	case p.EasyPatchHost != "" && !validHost(p.EasyPatchHost):
		return bad("EasyPatch host")
	case p.EasyPatchHost == "" && len(p.EasyPatchChains) > 0:
		return bad("EasyPatch chains without a host")
	case p.IssuedAt.IsZero() || p.ExpiresAt.IsZero() || !p.ExpiresAt.After(p.IssuedAt) || p.ExpiresAt.Sub(p.IssuedAt) > TrustValid:
		return bad("validity")
	case len(p.Chains)+len(p.EasyPatchChains) > MaxTrustChains:
		return bad("too many chains")
	case len(p.AddCerts) > MaxTrustAddCerts:
		return bad("too many certificates to add")
	}
	for _, c := range p.AddCerts {
		if _, err := DecodeTrustCert(c); err != nil {
			return bad("a certificate to add: %v", err)
		}
	}
	seen := map[string]bool{}
	for _, list := range [][]TrustChain{p.Chains, p.EasyPatchChains} {
		for _, c := range list {
			if c.ID == "" || len(c.ID) > 64 || seen[c.ID] {
				return bad("chain id")
			}
			seen[c.ID] = true
			switch c.Purpose {
			case TrustTarget, TrustFallback, TrustServed:
			default:
				return bad("chain purpose")
			}
			if len(c.Chain) == 0 || len(c.Chain) > MaxTrustChainLen {
				return bad("chain length")
			}
			for _, der := range c.Chain {
				if _, err := DecodeTrustCert(der); err != nil {
					return bad("a chain's certificate: %v", err)
				}
			}
		}
	}
	return nil
}

// validHost is a DNS name as the agent's origin or an EasyPatch host: letters,
// digits, dots and hyphens, lower case, no port. An IP address is not one:
// trust instructions are for names.
func validHost(h string) bool {
	if h == "" || len(h) > 253 || h != strings.ToLower(h) {
		return false
	}
	if _, err := netip.ParseAddr(h); err == nil {
		return false
	}
	for _, r := range h {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '.' && r != '-' {
			return false
		}
	}
	return !strings.HasPrefix(h, ".") && !strings.HasSuffix(h, ".") && !strings.Contains(h, "..")
}

// DecodeTrustCert reads one certificate of an instruction: DER in base64,
// bounded.
func DecodeTrustCert(s string) (*x509.Certificate, error) {
	if len(s) > base64.StdEncoding.EncodedLen(MaxTrustCertBytes) {
		return nil, errors.New("too large")
	}
	der, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, errors.New("not base64")
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, errors.New("not a certificate")
	}
	return c, nil
}

// EncodeTrustChain encodes a chain of DER certificates for TrustChain.Chain.
func EncodeTrustChain(chain [][]byte) []string {
	out := make([]string, len(chain))
	for i, der := range chain {
		out[i] = base64.StdEncoding.EncodeToString(der)
	}
	return out
}

// TrustChainDigest is the hex SHA-256 of a chain's certificates, in order: it
// tells one chain from another.
func TrustChainDigest(chain [][]byte) string {
	h := sha256.New()
	for _, der := range chain {
		s := sha256.Sum256(der)
		h.Write(s[:])
	}
	return hex.EncodeToString(h.Sum(nil))
}
