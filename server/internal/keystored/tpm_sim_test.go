//go:build cgo

package keystored

import (
	"errors"
	"testing"

	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpmutil"

	"github.com/paulmataruso/easyrmm/internal/escrowcrypto"
	"github.com/paulmataruso/easyrmm/server/internal/keystore"
)

// simTPM is a connection to the software TPM (the Microsoft reference
// implementation, through go-tpm-tools' simulator). Close does nothing: the
// simulator is one, and the test ends it.
type simTPM struct{ rw *simulator.Simulator }

func (s simTPM) Send(in []byte) ([]byte, error) { return tpmutil.RunCommandRaw(s.rw, in) }
func (simTPM) Close() error                     { return nil }

// startSim starts a simulator whose owner seed is the given one; two
// different seeds are two different machines. Only one runs at a time.
func startSim(t *testing.T, seed int64) (open func() (transport.TPMCloser, error), stop func()) {
	t.Helper()
	sim, err := simulator.GetWithFixedSeedInsecure(seed)
	if err != nil {
		t.Skipf("the software TPM is not available: %v", err)
	}
	return func() (transport.TPMCloser, error) { return simTPM{sim}, nil }, func() { _ = sim.Close() }
}

func openTPMKeystore(t *testing.T, dir string, open func() (transport.TPMCloser, error)) *Keystore {
	t.Helper()
	k, err := Open(Options{Dir: dir, OpenTPM: open, HasTPM: func() bool { return true }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(k.Close)
	return k
}

// One test, so that the simulator's single instance is used in order: a TPM
// round trip, an unattended restart, another machine's TPM, and PCR 7
// changing.
func TestTPMMode(t *testing.T) {
	dir := t.TempDir()
	open, stop := startSim(t, 1)
	k := openTPMKeystore(t, dir, open)
	rc, bf, err := k.Init("", nil)
	if err != nil {
		stop()
		t.Fatal(err)
	}
	if st := k.Status(); st.Mode != keystore.ModeTPM {
		stop()
		t.Fatalf("mode = %s", st.Mode)
	}
	if _, err := k.VerifyRecovery(bf, rc); err != nil {
		stop()
		t.Fatal(err)
	}
	pub, wrapped, _, err := k.CreateOrgKey("org1", "key1", "escrow")
	if err != nil {
		stop()
		t.Fatal(err)
	}
	k.Close()

	// Restart: the TPM unseals with no person present.
	k2 := openTPMKeystore(t, dir, open)
	if st := k2.Status(); st.State != keystore.StateUnsealed || st.Primary != 1 {
		stop()
		t.Fatalf("restart: %+v", st)
	}
	c := ctxOf("org1", "d", "v", "p", "key1")
	enc, ct, _ := escrowcrypto.Seal(pub, c, []byte(blPassword))
	fp := escrowcrypto.Fingerprint("p", []byte(blPassword))
	if r, err := k2.VerifyEscrow(wrapped, c, enc, ct, fp[:], "bitlocker"); err != nil || r != keystore.Match {
		stop()
		t.Fatalf("verify through the TPM-held KEK: %q %v", r, err)
	}
	// The state directory holds no KEK in clear: the blob is the TPM's.
	k2.mu.Lock()
	kek := append([]byte(nil), k2.keks[1].Bytes()...)
	k2.mu.Unlock()
	blob := mustRead(t, k2.blobPath(1))
	if contains(blob, kek) {
		stop()
		t.Fatal("the sealed blob holds the KEK in clear")
	}

	// PCR 7 changes (Secure Boot state): the TPM refuses, the keystore says
	// so and falls back to nothing.
	tp, _ := open()
	if _, err := (tpm2.PCRExtend{
		PCRHandle: tpm2.AuthHandle{Handle: tpm2.TPMHandle(pcrSecureBoot), Auth: tpm2.PasswordAuth(nil)},
		Digests:   tpm2.TPMLDigestValues{Digests: []tpm2.TPMTHA{{HashAlg: tpm2.TPMAlgSHA256, Digest: make([]byte, 32)}}},
	}).Execute(tp); err != nil {
		stop()
		t.Fatal(err)
	}
	k2.Close()
	k3 := openTPMKeystore(t, dir, open)
	st := k3.Status()
	if st.State != keystore.StateSealed || st.Detail != "TPM policy changed: restore from the recovery bundle" {
		stop()
		t.Fatalf("after PCR 7 changed: %+v", st)
	}
	if _, _, _, err := k3.CreateOrgKey("org1", "key2", "escrow"); code(t, err) != keystore.CodeTPMPolicy {
		stop()
		t.Fatalf("wrap after PCR change: %v", err)
	}
	if err := (tpmProtector{open: open}).unsealErr(blob); !errors.Is(err, ErrTPMPolicy) {
		stop()
		t.Fatalf("unseal error = %v", err)
	}
	k3.Close()
	stop()

	// Another machine's TPM (a different owner seed) cannot open the blob.
	open2, stop2 := startSim(t, 2)
	defer stop2()
	if _, err := (tpmProtector{open: open2}).Unseal(1, blob); err == nil {
		t.Fatal("a copy of the state opened on another TPM")
	}
	k4 := openTPMKeystore(t, dir, open2)
	if st := k4.Status(); st.State != keystore.StateSealed {
		t.Fatalf("on another machine: %+v", st)
	}
}
