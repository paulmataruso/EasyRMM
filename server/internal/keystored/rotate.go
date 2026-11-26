package keystored

import (
	"crypto/subtle"

	"github.com/paulmataruso/easyrmm/internal/escrowcrypto"
	"github.com/paulmataruso/easyrmm/server/internal/keystore"
)

// RewrapOrgKey moves an organization key's wrapped private half from the KEK
// version that wraps it to the primary version (ADR-0081 section 10, KEK
// rotation). The keystore unwraps with the old version and wraps with the new
// one; the plaintext of the private key exists only here and is zeroed before
// the function returns. A key already wrapped by the primary version comes
// back unchanged. Nothing older is destroyed: the caller writes the new form
// and the old version stays in the keystore until a person destroys it.
func (k *Keystore) RewrapOrgKey(org, keyID, purpose, wrapped string) (newWrapped string, version int, err error) {
	if org == "" || keyID == "" || (purpose != "escrow" && purpose != "service") || len(org) > 128 || len(keyID) > 128 {
		return "", 0, fail(keystore.CodeBadRequest, "the re-wrap request is not valid")
	}
	oldVer, sealed, err := parseWrapped(wrapped)
	if err != nil {
		return "", 0, fail(keystore.CodeBadRequest, "the wrapped key is not in a known format")
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	newVer, newKEK, err := k.primaryKEK()
	if err != nil {
		return "", 0, err
	}
	if oldVer == newVer {
		return wrapped, newVer, nil
	}
	oldKEK, err := k.kekFor(oldVer)
	if err != nil {
		return "", 0, err
	}
	priv, err := unwrap(oldKEK, sealed, wrapAAD(org, keyID, purpose))
	if err != nil {
		return "", 0, fail(keystore.CodeBadRequest, "the wrapped key does not open for this organization")
	}
	defer zero(priv)
	out, err := wrap(newKEK, newVer, wrapAAD(org, keyID, purpose), priv)
	if err != nil {
		return "", 0, err
	}
	// Prove the new form opens before anything is replaced with it.
	nv, sealedOut, perr := parseWrapped(out)
	if perr != nil || nv != newVer {
		return "", 0, fail(keystore.CodeInternal, "the re-wrapped key is not valid")
	}
	back, err := unwrap(newKEK, sealedOut, wrapAAD(org, keyID, purpose))
	same := err == nil && subtle.ConstantTimeCompare(back, priv) == 1
	zero(back)
	if !same {
		return "", 0, fail(keystore.CodeInternal, "the re-wrapped key does not open")
	}
	return out, newVer, nil
}

// ResealRequest is one record to move from an organization's old escrow key to
// its new one.
type ResealRequest struct {
	RequestID, Record string
	Kind              string
	// OldWrapped is the old key's wrapped private half; Old is the context
	// the record was sealed under and New the same context with the new
	// key's ID.
	OldWrapped      string
	Old, New        escrowcrypto.Context
	NewPublic       []byte
	Enc, Ciphertext []byte
	Fingerprint     []byte
}

// ResealEscrow opens a record under the organization's old key and seals it to
// the new one (ADR-0081 section 10, organization key rotation). Both contexts
// must agree in everything but the key's ID, so a record can neither move to
// another device, volume, protector or organization nor change its meaning.
// The record must be the one the server holds the fingerprint of; nothing that
// does not match is moved. The plaintext stays in this function and is zeroed;
// only ciphertext comes back.
func (k *Keystore) ResealEscrow(r ResealRequest) (enc, ct []byte, err error) {
	o, n := r.Old, r.New
	kind := r.Kind
	if kind == "" {
		kind = escrowcrypto.KindBitLocker
	}
	if !o.Valid() || !n.Valid() || len(r.Fingerprint) != escrowcrypto.FingerprintSize || len(r.NewPublic) != 32 ||
		o.Org != n.Org || o.Device != n.Device || o.Volume != n.Volume || o.Protector != n.Protector || o.OrgKey == n.OrgKey ||
		len(r.RequestID) > 128 || len(r.Record) > 128 {
		return nil, nil, fail(keystore.CodeBadRequest, "the re-seal request is not valid")
	}
	ver, sealed, err := parseWrapped(r.OldWrapped)
	if err != nil {
		return nil, nil, fail(keystore.CodeBadRequest, "the wrapped key is not in a known format")
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	kek, err := k.kekFor(ver)
	if err != nil {
		return nil, nil, err
	}
	priv, err := unwrap(kek, sealed, wrapAAD(o.Org, o.OrgKey, "escrow"))
	if err != nil {
		return nil, nil, fail(keystore.CodeBadRequest, "the wrapped key does not open for this organization")
	}
	defer zero(priv)
	pt, err := escrowcrypto.Open(priv, o, r.Enc, r.Ciphertext)
	if err != nil {
		return nil, nil, fail(keystore.CodeRefused, "the record does not open")
	}
	defer zero(pt)
	norm, err := escrowcrypto.NormalizeBytes(kind, pt)
	if err != nil {
		return nil, nil, fail(keystore.CodeRefused, "the record is not a recovery key")
	}
	fp := escrowcrypto.Fingerprint(o.Protector, norm)
	if subtle.ConstantTimeCompare(fp[:], r.Fingerprint) != 1 {
		return nil, nil, fail(keystore.CodeRefused, "the record is not the verified one")
	}
	enc, ct, err = escrowcrypto.Seal(r.NewPublic, n, norm)
	if err != nil {
		return nil, nil, err
	}
	return enc, ct, nil
}
