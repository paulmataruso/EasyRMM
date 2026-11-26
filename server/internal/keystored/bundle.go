package keystored

import (
	"bytes"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/paulmataruso/easyrmm/internal/escrowcrypto"
)

// bundleFormat names the recovery bundle's layout; a later one is a new name.
const bundleFormat = "easyrmm-kek-bundle-v1"

// bundle is recovery/kek-v<N>.bundle: the KEK sealed (HPKE) to the recovery
// public key. It opens only with the recovery code; the keystore holds no
// private half, so making one needs no code typed.
type bundle struct {
	Format  string `json:"format"`
	Version int    `json:"version"`
	// CheckValue is the KEK's key check value (base64 in JSON).
	CheckValue []byte `json:"checkValue"`
	Enc        []byte `json:"enc"`
	Ciphertext []byte `json:"ciphertext"`
}

func bundleInfo(version int, cv []byte) []byte {
	return []byte(fmt.Sprintf("%s|%d|%x", bundleFormat, version, cv))
}

func makeBundle(recoveryPub []byte, version int, kek []byte) ([]byte, error) {
	cv := checkValue(kek)
	enc, ct, err := escrowcrypto.SealRaw(recoveryPub, bundleInfo(version, cv), kek)
	if err != nil {
		return nil, err
	}
	return json.MarshalIndent(bundle{Format: bundleFormat, Version: version, CheckValue: cv, Enc: enc, Ciphertext: ct}, "", "  ")
}

// recoveryKey derives the recovery key pair from the typed code and the
// installation's recovery salt. The caller zeroes priv.
func recoveryKey(code, salt []byte) (priv, pub []byte, err error) {
	raw, err := normalizeCode(code)
	if err != nil {
		return nil, nil, err
	}
	defer zero(raw)
	ikm := derive(raw, salt)
	defer zero(ikm)
	return escrowcrypto.DeriveKey(ikm)
}

// openBundle opens a bundle file with the code and returns the KEK and its
// version. A wrong code, a wrong file and a damaged one say the same thing.
func openBundle(path string, code []byte, st *stateFile) (version int, kek []byte, err error) {
	b, err := os.ReadFile(path) //nolint:gosec // an operator-supplied bundle at the host
	if err != nil {
		return 0, nil, fmt.Errorf("keystore: reading the bundle: %w", err)
	}
	var bd bundle
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&bd); err != nil || bd.Format != bundleFormat {
		return 0, nil, errors.New("keystore: that file is not a recovery bundle")
	}
	rec := st.version(bd.Version)
	if rec == nil {
		return 0, nil, fmt.Errorf("keystore: this keystore has no KEK version %d", bd.Version)
	}
	priv, pub, err := recoveryKey(code, st.RecoverySalt)
	if err != nil {
		return 0, nil, err
	}
	defer zero(priv)
	if subtle.ConstantTimeCompare(pub, st.RecoveryPub) != 1 {
		return 0, nil, errors.New("keystore: that recovery code is not this keystore's")
	}
	kek, err = escrowcrypto.OpenRaw(priv, bundleInfo(bd.Version, bd.CheckValue), bd.Enc, bd.Ciphertext)
	if err != nil {
		return 0, nil, errors.New("keystore: the bundle does not open with this code")
	}
	if subtle.ConstantTimeCompare(checkValue(kek), rec.CheckValue) != 1 {
		zero(kek)
		return 0, nil, errors.New("keystore: the bundle's key does not match this keystore's check value")
	}
	return bd.Version, kek, nil
}

func bundlePath(dir string, version int) string {
	return filepath.Join(dir, recoveryDir, versionFile(version)+".bundle")
}
