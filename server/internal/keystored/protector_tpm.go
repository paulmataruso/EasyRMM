package keystored

import (
	"errors"
	"fmt"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

// pcrSecureBoot is the PCR the TPM policy binds to: Secure Boot state.
const pcrSecureBoot = 7

// TPMDevice is the kernel's resource-managed TPM device, never /dev/tpm0.
const TPMDevice = "/dev/tpmrm0"

// tpmProtector seals each KEK to the host's TPM 2.0: a keyed-hash data
// object under the owner hierarchy's ECC storage key, whose authorization is
// a policy over PCR 7. A copy of the state directory opens nothing on
// another machine; PCR 7 changing makes unseal fail until the recovery
// bundle is used.
//
// The sealing command carries the KEK to the TPM through the kernel's device
// in clear (no parameter-encryption session); the kernel is inside this
// design's trust boundary, as root on the host is (ADR-0081, section 8).
type tpmProtector struct {
	open func() (transport.TPMCloser, error)
}

func (tpmProtector) Mode() string { return "tpm" }

func (p tpmProtector) Seal(_ int, kek []byte) (blob []byte, err error) {
	t, err := p.open()
	if err != nil {
		return nil, fmt.Errorf("keystore: opening the TPM: %w", err)
	}
	defer func() { _ = t.Close() }()
	srk, closeSRK, err := loadSRK(t)
	if err != nil {
		return nil, err
	}
	defer closeSRK()
	digest, err := pcrPolicyDigest(t)
	if err != nil {
		return nil, err
	}
	data := tpm2.TPM2BSensitiveData{Buffer: kek}
	created, err := tpm2.Create{
		ParentHandle: tpm2.AuthHandle{Handle: srk.handle, Name: srk.name, Auth: tpm2.PasswordAuth(nil)},
		InSensitive: tpm2.TPM2BSensitiveCreate{Sensitive: &tpm2.TPMSSensitiveCreate{
			Data: tpm2.NewTPMUSensitiveCreate(&data),
		}},
		InPublic: tpm2.New2B(tpm2.TPMTPublic{
			Type:    tpm2.TPMAlgKeyedHash,
			NameAlg: tpm2.TPMAlgSHA256,
			ObjectAttributes: tpm2.TPMAObject{
				FixedTPM: true, FixedParent: true, NoDA: true,
				// UserWithAuth is off: only the PCR policy opens it.
			},
			AuthPolicy: tpm2.TPM2BDigest{Buffer: digest},
			Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgKeyedHash, &tpm2.TPMSKeyedHashParms{
				Scheme: tpm2.TPMTKeyedHashScheme{Scheme: tpm2.TPMAlgNull},
			}),
		}),
	}.Execute(t)
	if err != nil {
		return nil, fmt.Errorf("keystore: sealing to the TPM: %w", err)
	}
	pub, priv := tpm2.Marshal(created.OutPublic), tpm2.Marshal(created.OutPrivate)
	if len(pub) > 0xFFFF || len(priv) > 0xFFFF {
		return nil, errors.New("keystore: the TPM's sealed object is too large")
	}
	blob = append(blob, byte(len(pub)>>8), byte(len(pub))) //nolint:gosec // bounded by the check above
	blob = append(blob, pub...)
	blob = append(blob, priv...)
	return blob, nil
}

func (p tpmProtector) Unseal(_ int, blob []byte) ([]byte, error) {
	if len(blob) < 2 {
		return nil, ErrFormat
	}
	n := int(blob[0])<<8 | int(blob[1])
	if len(blob) < 2+n {
		return nil, ErrFormat
	}
	pub, err := tpm2.Unmarshal[tpm2.TPM2BPublic](blob[2 : 2+n])
	if err != nil {
		return nil, ErrFormat
	}
	priv, err := tpm2.Unmarshal[tpm2.TPM2BPrivate](blob[2+n:])
	if err != nil {
		return nil, ErrFormat
	}
	t, err := p.open()
	if err != nil {
		return nil, fmt.Errorf("keystore: opening the TPM: %w", err)
	}
	defer func() { _ = t.Close() }()
	srk, closeSRK, err := loadSRK(t)
	if err != nil {
		return nil, err
	}
	defer closeSRK()
	loaded, err := tpm2.Load{
		ParentHandle: tpm2.AuthHandle{Handle: srk.handle, Name: srk.name, Auth: tpm2.PasswordAuth(nil)},
		InPrivate:    *priv, InPublic: *pub,
	}.Execute(t)
	if err != nil {
		return nil, fmt.Errorf("keystore: loading the sealed key into the TPM: %w", err)
	}
	defer func() { _, _ = tpm2.FlushContext{FlushHandle: loaded.ObjectHandle}.Execute(t) }()

	sess, closeSess, err := tpm2.PolicySession(t, tpm2.TPMAlgSHA256, 16)
	if err != nil {
		return nil, fmt.Errorf("keystore: starting a TPM policy session: %w", err)
	}
	defer func() { _ = closeSess() }()
	if err := policyPCR(t, sess); err != nil {
		return nil, err
	}
	out, err := tpm2.Unseal{ItemHandle: tpm2.AuthHandle{Handle: loaded.ObjectHandle, Name: loaded.Name, Auth: sess}}.Execute(t)
	if err != nil {
		if errors.Is(err, tpm2.TPMRCPolicyFail) || errors.Is(err, tpm2.TPMRCPolicy) {
			return nil, ErrTPMPolicy
		}
		var rc tpm2.TPMRC
		if errors.As(err, &rc) && (rc&0xFF) == (tpm2.TPMRCPolicyFail&0xFF) {
			return nil, ErrTPMPolicy
		}
		return nil, fmt.Errorf("keystore: unsealing from the TPM: %w", err)
	}
	return out.OutData.Buffer, nil
}

type srkHandle struct {
	handle tpm2.TPMHandle
	name   tpm2.TPM2BName
}

// loadSRK creates the owner hierarchy's ECC storage primary key. The template
// is fixed, so the TPM derives the same key from its owner seed every time:
// nothing persistent is kept in the TPM.
func loadSRK(t transport.TPM) (srkHandle, func(), error) {
	r, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic:      tpm2.New2B(tpm2.ECCSRKTemplate),
	}.Execute(t)
	if err != nil {
		return srkHandle{}, nil, fmt.Errorf("keystore: creating the TPM storage key: %w", err)
	}
	return srkHandle{r.ObjectHandle, r.Name}, func() {
		_, _ = tpm2.FlushContext{FlushHandle: r.ObjectHandle}.Execute(t)
	}, nil
}

func policyPCR(t transport.TPM, sess tpm2.Session) error {
	_, err := tpm2.PolicyPCR{
		PolicySession: sess.Handle(),
		Pcrs: tpm2.TPMLPCRSelection{PCRSelections: []tpm2.TPMSPCRSelection{{
			Hash:      tpm2.TPMAlgSHA256,
			PCRSelect: tpm2.PCClientCompatible.PCRs(pcrSecureBoot),
		}}},
	}.Execute(t)
	if err != nil {
		return fmt.Errorf("keystore: applying the PCR %d policy: %w", pcrSecureBoot, err)
	}
	return nil
}

// pcrPolicyDigest is the digest of "PCR 7 holds what it holds now", made in a
// trial session that authorizes nothing.
func pcrPolicyDigest(t transport.TPM) ([]byte, error) {
	sess, closeSess, err := tpm2.PolicySession(t, tpm2.TPMAlgSHA256, 16, tpm2.Trial())
	if err != nil {
		return nil, fmt.Errorf("keystore: starting a TPM trial session: %w", err)
	}
	defer func() { _ = closeSess() }()
	if err := policyPCR(t, sess); err != nil {
		return nil, err
	}
	d, err := tpm2.PolicyGetDigest{PolicySession: sess.Handle()}.Execute(t)
	if err != nil {
		return nil, fmt.Errorf("keystore: reading the policy digest: %w", err)
	}
	return d.PolicyDigest.Buffer, nil
}

// openHostTPM opens the kernel's resource-managed device.
func openHostTPM() (transport.TPMCloser, error) { return openTPMDevice(TPMDevice) }
