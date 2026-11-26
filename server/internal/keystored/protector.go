package keystored

import (
	"errors"
	"fmt"
)

// A protector keeps KEK versions safe on the host (ADR-0081, section 2): it
// turns a KEK into a blob the state directory may hold, and back.
type protector interface {
	// Mode is the mode's name in the state file.
	Mode() string
	// Seal returns the blob that holds the KEK of a version.
	Seal(version int, kek []byte) ([]byte, error)
	// Unseal returns the KEK from a blob; the caller zeroes it.
	Unseal(version int, blob []byte) ([]byte, error)
}

// Errors a protector reports.
var (
	// ErrSealed means the keystore waits for a person to unseal it.
	ErrSealed = errors.New("keystore: sealed: waiting for `easyrmm-keystore unseal` at the host")
	// ErrTPMPolicy means the TPM refused: the PCR policy no longer holds
	// (firmware or Secure Boot change). The recovery bundle is the way back.
	ErrTPMPolicy = errors.New("keystore: the TPM refused to unseal: its policy changed (Secure Boot state or firmware); restore from the recovery bundle")
)

// fileProtector keeps the KEK in the state directory as it is: the opt-in
// stand-in for a host with no TPM where nobody can be present at restarts. A
// copy of the host's disk opens it, and the console says so.
type fileProtector struct{}

func (fileProtector) Mode() string { return "file" }

func (fileProtector) Seal(_ int, kek []byte) ([]byte, error) {
	return append([]byte(nil), kek...), nil
}

func (fileProtector) Unseal(_ int, blob []byte) ([]byte, error) {
	if len(blob) != KEKSize {
		return nil, fmt.Errorf("keystore: the stored key is damaged")
	}
	return append([]byte(nil), blob...), nil
}

// passProtector wraps each KEK under a key from Argon2id of a passphrase and
// the installation's salt. The wrap key is held only after an unseal.
type passProtector struct {
	salt []byte
	key  *Secret
}

func (*passProtector) Mode() string { return "passphrase" }

// Unlock derives the wrap key from the passphrase. A wrong passphrase is
// found when the first KEK fails to open.
func (p *passProtector) Unlock(passphrase []byte) error {
	k := derive(passphrase, p.salt)
	defer zero(k)
	s, err := NewSecret(k)
	if err != nil {
		return err
	}
	p.key.Destroy()
	p.key = s
	return nil
}

// Lock forgets the wrap key.
func (p *passProtector) Lock() {
	p.key.Destroy()
	p.key = nil
}

func passAAD(version int) []byte {
	return []byte(fmt.Sprintf("keystore-kek-passphrase-v1|%d", version))
}

func (p *passProtector) Seal(version int, kek []byte) ([]byte, error) {
	if p.key == nil {
		return nil, ErrSealed
	}
	s, err := wrap(p.key.Bytes(), version, passAAD(version), kek)
	return []byte(s), err
}

func (p *passProtector) Unseal(version int, blob []byte) ([]byte, error) {
	if p.key == nil {
		return nil, ErrSealed
	}
	v, sealed, err := parseWrapped(string(blob))
	if err != nil || v != version {
		return nil, ErrFormat
	}
	kek, err := unwrap(p.key.Bytes(), sealed, passAAD(version))
	if err != nil {
		// Indistinguishable from a wrong passphrase, which is the point.
		return nil, errors.New("keystore: the passphrase does not open the stored key")
	}
	return kek, nil
}
