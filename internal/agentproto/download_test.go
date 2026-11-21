package agentproto

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"testing"
	"time"
)

func TestDownloadSignature(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	otherPub, otherPriv, _ := ed25519.GenerateKey(nil)
	_, devKey, _ := ed25519.GenerateKey(nil)
	header, err := Sign(devKey, "dev-1", "GET", PathMeshSettings, nil, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	a, err := Parse(header)
	if err != nil {
		t.Fatal(err)
	}
	body := sha256.Sum256([]byte("MeshID=0x1"))
	sig := SignDownload(priv, a, PathMeshSettings, body)
	if err := VerifyDownload(pub, sig, "dev-1", PathMeshSettings, a.Nonce, body); err != nil {
		t.Fatalf("verify: %v", err)
	}
	other := a
	other.Nonce = base64.RawURLEncoding.EncodeToString(make([]byte, NonceBytes))
	for name, c := range map[string]struct {
		key                  ed25519.PublicKey
		sig, dev, tgt, nonce string
		sum                  [sha256.Size]byte
		want                 error
	}{
		"another server's key": {otherPub, sig, "dev-1", PathMeshSettings, a.Nonce, body, ErrDownloadSignature},
		"signed by another key": {pub, SignDownload(otherPriv, a, PathMeshSettings, body), "dev-1", PathMeshSettings, a.Nonce, body,
			ErrDownloadSignature},
		"another device":        {pub, sig, "dev-2", PathMeshSettings, a.Nonce, body, ErrDownloadSignature},
		"another download":      {pub, sig, "dev-1", PathMeshAgent + "?os=linux&arch=amd64", a.Nonce, body, ErrDownloadSignature},
		"an earlier request":    {pub, SignDownload(priv, other, PathMeshSettings, body), "dev-1", PathMeshSettings, a.Nonce, body, ErrDownloadSignature},
		"changed on the way":    {pub, sig, "dev-1", PathMeshSettings, a.Nonce, sha256.Sum256([]byte("MeshID=0x2")), ErrDownloadSignature},
		"not signed":            {pub, "", "dev-1", PathMeshSettings, a.Nonce, body, ErrDownloadUnsigned},
		"not base64":            {pub, "%%%", "dev-1", PathMeshSettings, a.Nonce, body, ErrDownloadSignature},
		"no key pinned":         {nil, sig, "dev-1", PathMeshSettings, a.Nonce, body, ErrDownloadSignature},
		"a truncated signature": {pub, sig[:20], "dev-1", PathMeshSettings, a.Nonce, body, ErrDownloadSignature},
	} {
		if err := VerifyDownload(c.key, c.sig, c.dev, c.tgt, c.nonce, c.sum); !errors.Is(err, c.want) {
			t.Errorf("%s: %v, want %v", name, err, c.want)
		}
	}
}
