package agentproto

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
)

// Signed downloads. The agent fetches MeshAgent's binary and its settings
// file from the server and runs MeshAgent as SYSTEM or root (ADR-0015).
// TLS alone does not vouch for them: agents trust the system's roots or the
// internal certificate authority, so a TLS-terminating proxy or an
// inspecting firewall could change them on the way. The server therefore
// signs each such answer with the job key the agent pinned (ADR-0017),
// over the device, the request's target and its single-use nonce, so a
// signature can be neither moved to another download nor replayed. The
// agent uses nothing that does not verify.

// HeaderDownloadSignature carries the server's signature on a download,
// base64 (standard, padded).
const HeaderDownloadSignature = "EasyRMM-Download-Signature"

// MaxMeshAgentBytes bounds a MeshAgent binary: today's are a few MiB.
const MaxMeshAgentBytes = 64 << 20

const downloadSigContext = "EASYRMM-DOWNLOAD-SIG-V1\n"

// Errors from VerifyDownload.
var (
	ErrDownloadUnsigned  = errors.New("agentproto: the server did not sign the download")
	ErrDownloadSignature = errors.New("agentproto: the download's signature does not verify with the server key this agent trusts")
)

func downloadMessage(device, target, nonce string, sum [sha256.Size]byte) []byte {
	return []byte(downloadSigContext + device + "\n" + target + "\n" + nonce + "\n" + hex.EncodeToString(sum[:]))
}

// SignDownload returns the HeaderDownloadSignature value for a download
// whose SHA-256 is sum, answering the request a signed for target.
func SignDownload(key ed25519.PrivateKey, a Auth, target string, sum [sha256.Size]byte) string {
	return base64.StdEncoding.EncodeToString(ed25519.Sign(key, downloadMessage(a.Device, target, a.Nonce, sum)))
}

// VerifyDownload checks the server's signature on a download whose SHA-256
// is sum, fetched by this device with a request for target carrying nonce.
func VerifyDownload[K KeyArg](key K, signature, device, target, nonce string, sum [sha256.Size]byte) error {
	if signature == "" {
		return ErrDownloadUnsigned
	}
	sig, err := base64.StdEncoding.DecodeString(signature)
	if err != nil || !keysOf(key).verify(downloadMessage(device, target, nonce, sum), sig) {
		return ErrDownloadSignature
	}
	return nil
}
