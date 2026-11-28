package agentproto

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"net/url"
	"strings"
)

// Moving an agent between the addresses a server answers on (ADR-0061,
// slice 1). The agent asks an address whether it is the same server by
// sending it a request signed with its device key; the server answers with a
// confirmation signed with the job key the agent pinned, over the device, the
// request's nonce and the address asked, so that an answer is useless in any
// other exchange and a party that merely holds the name cannot give it. An
// agent that changes address, by hand, by installing again or by falling
// back, reports it on PathMove. Nothing here is an instruction from the
// server: no heartbeat field carries a move yet.

// Paths of the two routes.
const (
	// PathAddress is where an agent asks an address to confirm itself.
	PathAddress = "/api/agent/v1/address"
	// PathMove is where an agent reports that it changed address, or why it
	// could not.
	PathMove = "/api/agent/v1/move"
)

// MaxMoveError bounds the error text of a move report.
const MaxMoveError = 500

// FallbackAfterSeconds is how long every request to its server must have
// failed before an agent tries the address it moved from.
const FallbackAfterSeconds = 3600

// The ways an agent's address changes.
const (
	MoveSetServer = "set-server"
	MoveInstall   = "install"
	MoveFallback  = "fallback"
)

// ValidMoveKind reports whether k is a way an agent changes address.
func ValidMoveKind(k string) bool {
	return k == MoveSetServer || k == MoveInstall || k == MoveFallback
}

// AddressRequest is what an agent sends to PathAddress, at the address it
// asks about. The request is signed with the device key as every one is.
type AddressRequest struct {
	Address string `json:"address"`
}

// AddressAnswer is the server's confirmation of an address.
type AddressAnswer struct {
	Address string `json:"address"`
	// Signature is the Ed25519 signature, base64 (standard, padded).
	Signature string `json:"signature"`
}

// MoveReport is what an agent sends to PathMove, at its current address,
// once it changed address or failed to.
type MoveReport struct {
	// Kind is MoveSetServer, MoveInstall or MoveFallback.
	Kind string `json:"kind"`
	From string `json:"from"`
	To   string `json:"to"`
	// Moved is true once the agent switched; Error says why it did not.
	Moved bool   `json:"moved"`
	Error string `json:"error,omitempty"`
}

const addressSigContext = "EASYRMM-ADDRESS-SIG-V1\n"

// Errors from VerifyAddress.
var (
	ErrAddressUnsigned  = errors.New("agentproto: the server did not confirm its address")
	ErrAddressSignature = errors.New("agentproto: the address's confirmation does not verify with the server key this agent trusts")
	ErrAddressMismatch  = errors.New("agentproto: the confirmation is for another address")
)

func addressMessage(device, nonce, address string) []byte {
	return []byte(addressSigContext + device + "\n" + nonce + "\n" + address)
}

// SignAddress confirms address as the answer to the signed request a, which
// asked about it.
func SignAddress(key ed25519.PrivateKey, a Auth, address string) AddressAnswer {
	return AddressAnswer{
		Address:   address,
		Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(key, addressMessage(a.Device, a.Nonce, address))),
	}
}

// VerifyAddress checks a confirmation with the server keys the agent trusts,
// against the device, the nonce of the request it sent and the address it
// dialed.
func VerifyAddress[K KeyArg](key K, ans AddressAnswer, device, nonce, address string) error {
	if ans.Signature == "" {
		return ErrAddressUnsigned
	}
	if ans.Address != address {
		return ErrAddressMismatch
	}
	sig, err := base64.StdEncoding.DecodeString(ans.Signature)
	if err != nil || !keysOf(key).verify(addressMessage(device, nonce, address), sig) {
		return ErrAddressSignature
	}
	return nil
}

// MoveTarget returns the origin of s for an agent to move to: an https URL
// with a host, no path, query, credentials or fragment. It is stricter than
// the agent's server address: plain http, loopback included, is refused.
func MoveTarget(s string) (string, error) {
	u, err := url.Parse(strings.TrimSuffix(strings.TrimSpace(s), "/"))
	if err != nil || u.Scheme != "https" || u.Host == "" || u.Hostname() == "" || u.User != nil ||
		u.RawQuery != "" || u.Fragment != "" || u.Path != "" || u.Opaque != "" {
		return "", errors.New("an agent moves only to an https address such as https://rmm.example.com")
	}
	return "https://" + strings.TrimSuffix(strings.ToLower(u.Host), ":443"), nil
}
