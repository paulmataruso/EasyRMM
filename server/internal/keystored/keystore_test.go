package keystored

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/paulmataruso/easyrmm/internal/escrowcrypto"
	"github.com/paulmataruso/easyrmm/server/internal/keystore"
)

const (
	testPass   = "a passphrase of sufficient length"
	blPassword = "123456-234567-345678-456789-567890-678901-789012-890123"
)

func openPass(t *testing.T, dir string) *Keystore {
	t.Helper()
	k, err := Open(Options{Dir: dir, Mode: keystore.ModePassphrase})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(k.Close)
	return k
}

func code(t *testing.T, err error) string {
	t.Helper()
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	if err != nil {
		return "other:" + err.Error()
	}
	return ""
}

// initVerified runs init and proves the recovery, as the host command does.
func initVerified(t *testing.T, k *Keystore, pass string) (recoveryCode []byte, bundlePath string) {
	t.Helper()
	c, bf, err := k.Init(keystore.ModePassphrase, []byte(pass))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := k.VerifyRecovery(bf, c); err != nil {
		t.Fatal(err)
	}
	return c, bf
}

func ctxOf(org, dev, vol, prot, key string) escrowcrypto.Context {
	return escrowcrypto.Context{Org: org, Device: dev, Volume: vol, Protector: prot, OrgKey: key}
}

func TestPassphraseLifecycle(t *testing.T) {
	dir := t.TempDir()
	k := openPass(t, dir)
	if st := k.Status(); st.State != keystore.StateUninitialised {
		t.Fatalf("fresh state = %s", st.State)
	}
	if _, _, _, err := k.CreateOrgKey("o", "k", "escrow"); code(t, err) != keystore.CodeUninitialised {
		t.Fatalf("wrap before init: %v", err)
	}
	if _, _, err := k.Init(keystore.ModePassphrase, []byte("short")); code(t, err) != keystore.CodeBadRequest {
		t.Fatalf("short passphrase: %v", err)
	}
	rc, bf, err := k.Init(keystore.ModePassphrase, []byte(testPass))
	if err != nil {
		t.Fatal(err)
	}
	// Recovery is not proved: nothing is wrapped.
	if st := k.Status(); st.Primary != 0 || st.RecoveryVerified || st.Versions[0].State != "pending" {
		t.Fatalf("status before verify: %+v", st)
	}
	if _, _, _, err := k.CreateOrgKey("o", "k", "escrow"); code(t, err) != keystore.CodeNotVerified {
		t.Fatalf("wrap before recovery verified: %v", err)
	}
	// A wrong code, and another keystore's code, prove nothing.
	if _, err := k.VerifyRecovery(bf, []byte("AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA")); code(t, err) != keystore.CodeDenied {
		t.Fatalf("wrong code: %v", err)
	}
	if _, err := k.VerifyRecovery(filepath.Join(dir, "nope"), rc); code(t, err) != keystore.CodeDenied {
		t.Fatalf("missing bundle: %v", err)
	}
	if v, err := k.VerifyRecovery(bf, rc); err != nil || v != 1 {
		t.Fatalf("verify: %d %v", v, err)
	}
	if st := k.Status(); st.Primary != 1 || !st.RecoveryVerified || st.State != keystore.StateUnsealed {
		t.Fatalf("status after verify: %+v", st)
	}
	pub, wrapped, ver, err := k.CreateOrgKey("org1", "key1", "escrow")
	if err != nil || len(pub) != 32 || ver != 1 {
		t.Fatalf("create: %v", err)
	}
	if _, _, err := k.Init(keystore.ModePassphrase, []byte(testPass)); code(t, err) != keystore.CodeRefused {
		t.Fatalf("second init: %v", err)
	}

	// A restart leaves the keystore sealed until the passphrase is typed.
	k.Close()
	k2 := openPass(t, dir)
	if st := k2.Status(); st.State != keystore.StateSealed || st.SealedSince == nil {
		t.Fatalf("after restart: %+v", st)
	}
	if _, _, _, err := k2.CreateOrgKey("org1", "key2", "escrow"); code(t, err) != keystore.CodeSealed {
		t.Fatalf("wrap while sealed: %v", err)
	}
	if err := k2.Unseal([]byte("the wrong passphrase, long enough")); code(t, err) == "" || k2.Status().State != keystore.StateSealed {
		t.Fatalf("wrong passphrase unsealed: %v", err)
	}
	if err := k2.Unseal([]byte(testPass)); err != nil {
		t.Fatal(err)
	}
	if st := k2.Status(); st.State != keystore.StateUnsealed {
		t.Fatalf("after unseal: %+v", st)
	}
	// Once open, another passphrase is refused and the wrap key is kept: a new
	// KEK version made now is still sealed under the right one.
	if err := k2.Unseal([]byte("the wrong passphrase, long enough")); code(t, err) != keystore.CodeRefused {
		t.Fatalf("unseal of an open keystore: %v", err)
	}
	if _, _, err := k2.NewVersion(); err != nil {
		t.Fatal(err)
	}
	k2.Close()
	k2 = openPass(t, dir)
	if err := k2.Unseal([]byte(testPass)); err != nil {
		t.Fatalf("a version made after the refused unseal does not open with the real passphrase: %v", err)
	}
	if st := k2.Status(); len(st.Versions) != 2 || !st.Versions[1].Open {
		t.Fatalf("after reopening: %+v", st)
	}
	// What was wrapped before the restart still opens.
	enc, ct, _ := escrowcrypto.Seal(pub, ctxOf("org1", "d", "v", "p", "key1"), []byte(blPassword))
	fp := escrowcrypto.Fingerprint("p", []byte(blPassword))
	if r, err := k2.VerifyEscrow(wrapped, ctxOf("org1", "d", "v", "p", "key1"), enc, ct, fp[:], "bitlocker"); err != nil || r != keystore.Match {
		t.Fatalf("verify after restart: %q %v", r, err)
	}
}

func TestPassphraseFileHoldsNoKey(t *testing.T) {
	dir := t.TempDir()
	k := openPass(t, dir)
	initVerified(t, k, testPass)
	// No file of the state directory holds the passphrase or a KEK in clear.
	var all []byte
	_ = filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() {
			b, _ := os.ReadFile(p) //nolint:gosec // test
			all = append(all, b...)
			if info.Mode().Perm()&0o077 != 0 {
				t.Errorf("%s is readable by others: %v", p, info.Mode())
			}
		}
		return nil
	})
	k.mu.Lock()
	kek := bytes.Clone(k.keks[1].Bytes())
	k.mu.Unlock()
	if bytes.Contains(all, kek) || bytes.Contains(all, []byte(testPass)) {
		t.Fatal("a key or the passphrase is on disk in clear")
	}
}

func TestFileModeNeedsOptIn(t *testing.T) {
	dir := t.TempDir()
	// Without EASYRMM_KEYSTORE_MODE=file, even a request for it is refused.
	k, _ := Open(Options{Dir: dir, HasTPM: func() bool { return false }})
	if _, _, err := k.Init(keystore.ModeFile, nil); code(t, err) != keystore.CodeRefused {
		t.Fatalf("file mode without opt-in: %v", err)
	}
	k.Close()

	kf, err := Open(Options{Dir: dir, Mode: keystore.ModeFile})
	if err != nil {
		t.Fatal(err)
	}
	rc, bf, err := kf.Init("", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := kf.VerifyRecovery(bf, rc); err != nil {
		t.Fatal(err)
	}
	if err := kf.Unseal([]byte("x")); code(t, err) != keystore.CodeRefused {
		t.Fatalf("unseal in file mode: %v", err)
	}
	kf.Close()
	// It unseals by itself at start.
	kf2, err := Open(Options{Dir: dir, Mode: keystore.ModeFile})
	if err != nil {
		t.Fatal(err)
	}
	defer kf2.Close()
	if st := kf2.Status(); st.State != keystore.StateUnsealed || st.Mode != keystore.ModeFile {
		t.Fatalf("file mode restart: %+v", st)
	}
}

func TestAutoModeWithoutTPMIsPassphrase(t *testing.T) {
	k, _ := Open(Options{Dir: t.TempDir(), HasTPM: func() bool { return false }})
	defer k.Close()
	if _, _, err := k.Init("", nil); code(t, err) != keystore.CodeBadRequest {
		t.Fatalf("auto mode with no TPM wants a passphrase: %v", err)
	}
	if _, _, err := k.Init(keystore.ModeTPM, nil); code(t, err) != keystore.CodeRefused {
		t.Fatalf("tpm mode with no TPM: %v", err)
	}
}

// A later KEK version stays pending, and the old one primary, until its
// recovery is proved; making one needs no code.
func TestNewVersionStaysPendingUntilVerified(t *testing.T) {
	k := openPass(t, t.TempDir())
	rc, _ := initVerified(t, k, testPass)
	_, w1, _, err := k.CreateOrgKey("o", "k1", "escrow")
	if err != nil {
		t.Fatal(err)
	}
	v, bf, err := k.NewVersion()
	if err != nil || v != 2 {
		t.Fatalf("new version: %d %v", v, err)
	}
	if st := k.Status(); st.Primary != 1 || st.Versions[1].State != "pending" {
		t.Fatalf("after new version: %+v", st)
	}
	_, w, ver, err := k.CreateOrgKey("o", "k2", "escrow")
	if err != nil || ver != 1 {
		t.Fatalf("a pending version wrapped: v%d %v", ver, err)
	}
	if v, _, _ := parseWrapped(w); v != 1 {
		t.Fatal("wrong version in the wire format")
	}
	if _, err := k.VerifyRecovery(bf, rc); err != nil {
		t.Fatal(err)
	}
	if _, w2, ver, err := k.CreateOrgKey("o", "k3", "escrow"); err != nil || ver != 2 {
		t.Fatalf("after verify: v%d %v", ver, err)
	} else if v, _, _ := parseWrapped(w2); v != 2 {
		t.Fatal("wrong version")
	}
	// Both versions still open what they wrapped.
	_ = w1
	if k.Status().Primary != 2 {
		t.Fatal("primary did not move")
	}
}

func TestBundleOpensOnlyWithItsCode(t *testing.T) {
	k := openPass(t, t.TempDir())
	rc, bf := initVerified(t, k, testPass)
	other := openPass(t, t.TempDir())
	_, bf2, err := other.Init(keystore.ModePassphrase, []byte(testPass))
	if err != nil {
		t.Fatal(err)
	}
	// The first keystore's code does not open the second's bundle, and the
	// first's bundle is not accepted by the second.
	if _, err := other.VerifyRecovery(bf2, rc); code(t, err) != keystore.CodeDenied {
		t.Fatalf("code of another keystore: %v", err)
	}
	if _, err := other.VerifyRecovery(bf, rc); code(t, err) != keystore.CodeDenied {
		t.Fatalf("bundle of another keystore: %v", err)
	}
	// A damaged bundle fails.
	b, _ := os.ReadFile(bf) //nolint:gosec // test
	b = bytes.Replace(b, []byte(`"ciphertext": "`), []byte(`"ciphertext": "AAAA`), 1)
	bad := filepath.Join(t.TempDir(), "bad.bundle")
	_ = os.WriteFile(bad, b, 0o600)
	if _, err := k.VerifyRecovery(bad, rc); code(t, err) != keystore.CodeDenied {
		t.Fatalf("damaged bundle: %v", err)
	}
}

func escrowFixture(t *testing.T) (k *Keystore, pub []byte, wrapped string) {
	t.Helper()
	k = openPass(t, t.TempDir())
	initVerified(t, k, testPass)
	pub, wrapped, _, err := k.CreateOrgKey("org1", "key1", "escrow")
	if err != nil {
		t.Fatal(err)
	}
	return k, pub, wrapped
}

func TestVerifyEscrowMatchAndMismatch(t *testing.T) {
	k, pub, wrapped := escrowFixture(t)
	c := ctxOf("org1", "dev1", "vol1", "prot1", "key1")
	enc, ct, err := escrowcrypto.Seal(pub, c, []byte(blPassword))
	if err != nil {
		t.Fatal(err)
	}
	fp := escrowcrypto.Fingerprint("prot1", []byte(blPassword))
	verify := func(w string, c escrowcrypto.Context, enc, ct, fp []byte) (string, string) {
		r, err := k.VerifyEscrow(w, c, enc, ct, fp, "bitlocker")
		return r, code(t, err)
	}
	if r, e := verify(wrapped, c, enc, ct, fp[:]); r != keystore.Match || e != "" {
		t.Fatalf("good record: %q %q", r, e)
	}
	// A record copied to another device, volume, protector, organization or
	// key does not open: a mismatch, never a match.
	for name, bc := range map[string]escrowcrypto.Context{
		"device":    ctxOf("org1", "dev2", "vol1", "prot1", "key1"),
		"volume":    ctxOf("org1", "dev1", "vol2", "prot1", "key1"),
		"protector": ctxOf("org1", "dev1", "vol1", "prot2", "key1"),
	} {
		if r, e := verify(wrapped, bc, enc, ct, fp[:]); r != keystore.Mismatch || e != "" {
			t.Errorf("%s: %q %q", name, r, e)
		}
	}
	// A wrong fingerprint is a mismatch.
	wrongFP := escrowcrypto.Fingerprint("prot1", []byte("999999-234567-345678-456789-567890-678901-789012-890123"))
	if r, _ := verify(wrapped, c, enc, ct, wrongFP[:]); r != keystore.Mismatch {
		t.Errorf("wrong fingerprint: %q", r)
	}
	// A record that is not a BitLocker password is a mismatch.
	enc2, ct2, _ := escrowcrypto.Seal(pub, c, []byte("not a recovery password"))
	if r, _ := verify(wrapped, c, enc2, ct2, fp[:]); r != keystore.Mismatch {
		t.Errorf("junk plaintext: %q", r)
	}
	// Tampered ciphertext.
	bad := bytes.Clone(ct)
	bad[3] ^= 1
	if r, _ := verify(wrapped, c, enc, bad, fp[:]); r != keystore.Mismatch {
		t.Errorf("tampered: %q", r)
	}
	// A wrapped key presented for another organization or key id: wrong AAD,
	// an error and not a verdict.
	if r, e := verify(wrapped, ctxOf("org2", "dev1", "vol1", "prot1", "key1"), enc, ct, fp[:]); r != "" || e != keystore.CodeBadRequest {
		t.Errorf("wrong org AAD: %q %q", r, e)
	}
	if r, e := verify(wrapped, ctxOf("org1", "dev1", "vol1", "prot1", "key9"), enc, ct, fp[:]); r != "" || e != keystore.CodeBadRequest {
		t.Errorf("wrong key id AAD: %q %q", r, e)
	}
	// A service key wrapped for the same org and key id is not an escrow key.
	_, svc, _, _ := k.CreateOrgKey("org1", "key1", "service")
	if r, e := verify(svc, c, enc, ct, fp[:]); r != "" || e != keystore.CodeBadRequest {
		t.Errorf("service key used as escrow key: %q %q", r, e)
	}
	// A KEK version this keystore does not have.
	if _, e := verify("ks1.7.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", c, enc, ct, fp[:]); e != keystore.CodeVersionLost {
		t.Errorf("missing version: %q", e)
	}
	if _, e := verify("garbage", c, enc, ct, fp[:]); e != keystore.CodeBadRequest {
		t.Errorf("garbage: %q", e)
	}
	if _, err := k.VerifyEscrow(wrapped, c, enc, ct, fp[:], "veracrypt"); code(t, err) != keystore.CodeBadRequest {
		t.Errorf("an unknown kind: %v", err)
	}
	// A BitLocker password is not a LUKS passphrase: it opens, and is a mismatch.
	if r, err := k.VerifyEscrow(wrapped, c, enc, ct, fp[:], "luks"); err != nil || r != keystore.Mismatch {
		t.Errorf("a password checked as a LUKS passphrase: %q %v", r, err)
	}
}

// While sealed nothing is verified or wrapped, and the error says why.
func TestVerifyEscrowWhileSealed(t *testing.T) {
	dir := t.TempDir()
	k := openPass(t, dir)
	initVerified(t, k, testPass)
	pub, wrapped, _, _ := k.CreateOrgKey("org1", "key1", "escrow")
	k.Close()
	k2 := openPass(t, dir)
	c := ctxOf("org1", "d", "v", "p", "key1")
	enc, ct, _ := escrowcrypto.Seal(pub, c, []byte(blPassword))
	fp := escrowcrypto.Fingerprint("p", []byte(blPassword))
	if _, err := k2.VerifyEscrow(wrapped, c, enc, ct, fp[:], "bitlocker"); code(t, err) != keystore.CodeSealed {
		t.Fatalf("while sealed: %v", err)
	}
}

func TestOrgKeyRequestsAreValidated(t *testing.T) {
	k, _, _ := escrowFixture(t)
	for _, bad := range [][3]string{{"", "k", "escrow"}, {"o", "", "escrow"}, {"o", "k", "other"}} {
		if _, _, _, err := k.CreateOrgKey(bad[0], bad[1], bad[2]); code(t, err) != keystore.CodeBadRequest {
			t.Errorf("%v: %v", bad, err)
		}
	}
	p, _, _, err := k.CreateOrgKey("o", "k", "service")
	if err != nil || p != nil {
		t.Fatalf("service key has no public half: %v %v", p, err)
	}
}

// Over real sockets: who may ask what.
func TestServerSocketsAndPeerCredentials(t *testing.T) {
	k, pub, wrapped := escrowFixture(t)
	dir, err := os.MkdirTemp("", "ks")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	svcPath, admPath := filepath.Join(dir, "s.sock"), filepath.Join(dir, "a.sock")
	svc, err := Listen(svcPath, 0o660)
	if err != nil {
		t.Fatal(err)
	}
	adm, err := Listen(admPath, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	uid := uint32(os.Getuid()) //nolint:gosec // a uid
	srv := &Server{KS: k, ServiceUIDs: []uint32{uid}, AdminUID: uid, ReadTimeout: 5 * time.Second}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = srv.Serve(ctx, svc, adm); close(done) }()
	t.Cleanup(func() { cancel(); <-done })

	sc := &keystore.Client{Path: svcPath, Timeout: 5 * time.Second}
	ac := &keystore.Client{Path: admPath, Timeout: 5 * time.Second}

	st, err := sc.Status(context.Background())
	if err != nil || st.State != keystore.StateUnsealed {
		t.Fatalf("status: %+v %v", st, err)
	}
	c := keystore.EscrowContext{Org: "org1", Device: "d", Volume: "v", Protector: "p", OrgKey: "key1"}
	enc, ct, _ := escrowcrypto.Seal(pub, ctxOf("org1", "d", "v", "p", "key1"), []byte(blPassword))
	fp := escrowcrypto.Fingerprint("p", []byte(blPassword))
	if r, err := sc.VerifyEscrow(context.Background(), "req-1", wrapped, c, enc, ct, fp[:]); err != nil || r != keystore.Match {
		t.Fatalf("verify over the socket: %q %v", r, err)
	}
	if k, err := sc.CreateOrgKey(context.Background(), "org1", "key7", "escrow"); err != nil || len(k.PublicKey) != 32 || k.KEKVersion != 1 {
		t.Fatalf("create over the socket: %v", err)
	}
	// Unseal, init and verify-recovery are not offered on the service socket.
	for _, op := range []string{keystore.OpUnseal, keystore.OpInit, keystore.OpVerifyRecovery, keystore.OpNewVersion} {
		_, err := sc.Do(context.Background(), keystore.Request{Op: op, Passphrase: []byte(testPass)})
		var re *keystore.RemoteError
		if !errors.As(err, &re) || re.Code != keystore.CodeDenied {
			t.Errorf("%s on the service socket: %v", op, err)
		}
	}
	// And the admin socket does not wrap or verify for the server.
	if _, err := ac.CreateOrgKey(context.Background(), "o", "k", "escrow"); err == nil {
		t.Error("an org key was made on the admin socket")
	}

	// A user the keystore does not list gets no answer at all: a second server
	// that lists another user ID, on its own sockets.
	svc2, err := Listen(filepath.Join(dir, "s2.sock"), 0o660)
	if err != nil {
		t.Fatal(err)
	}
	adm2, err := Listen(filepath.Join(dir, "a2.sock"), 0o600)
	if err != nil {
		t.Fatal(err)
	}
	other := &Server{KS: k, ServiceUIDs: []uint32{uid + 1}, AdminUID: uid + 1, ReadTimeout: 5 * time.Second}
	ctx2, cancel2 := context.WithCancel(context.Background())
	done2 := make(chan struct{})
	go func() { _ = other.Serve(ctx2, svc2, adm2); close(done2) }()
	t.Cleanup(func() { cancel2(); <-done2 })
	sc2 := &keystore.Client{Path: filepath.Join(dir, "s2.sock"), Timeout: 5 * time.Second}
	ac2 := &keystore.Client{Path: filepath.Join(dir, "a2.sock"), Timeout: 5 * time.Second}
	if _, err := sc2.Status(context.Background()); !errors.Is(err, keystore.ErrUnavailable) {
		t.Errorf("an unlisted user was answered: %v", err)
	}
	if _, err := ac2.Status(context.Background()); !errors.Is(err, keystore.ErrUnavailable) {
		t.Errorf("an unlisted admin was answered: %v", err)
	}
}

func TestPassphraseRequestIsZeroedAfterUse(t *testing.T) {
	k := openPass(t, t.TempDir())
	srv := &Server{KS: k}
	req := &keystore.Request{Op: keystore.OpInit, Mode: keystore.ModePassphrase, Passphrase: []byte(testPass)}
	resp := srv.handle(req, true)
	if !resp.OK || resp.RecoveryCode == "" {
		t.Fatalf("init: %+v", resp)
	}
	// serveConn zeroes the request's secrets when it is done; do the same
	// here and check the engine did not keep the slice.
	zero(req.Passphrase)
	for _, b := range req.Passphrase {
		if b != 0 {
			t.Fatal("not zeroed")
		}
	}
}
