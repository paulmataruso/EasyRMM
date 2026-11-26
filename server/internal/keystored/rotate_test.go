package keystored

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/paulmataruso/easyrmm/server/internal/keystore"
)

func TestRewrapMovesAKeyToThePrimaryVersionAndKeepsTheOldOne(t *testing.T) {
	k, code := readyKeystoreWithCode(t)
	req, _ := readReq(t, k, "rid-1")
	if _, err := k.ReadEscrow(req); err != nil {
		t.Fatal(err)
	}
	// A new version is pending: nothing moves until its recovery is proved.
	v2, bf, err := k.NewVersion()
	if err != nil || v2 != 2 {
		t.Fatalf("new version: %d %v", v2, err)
	}
	same, ver, err := k.RewrapOrgKey("org1", "key1", "escrow", req.Wrapped)
	if err != nil || ver != 1 || same != req.Wrapped {
		t.Fatalf("a pending version must not take keys: %q %d %v", same, ver, err)
	}
	if _, err := k.VerifyRecovery(bf, code); err != nil {
		t.Fatal(err)
	}
	moved, ver, err := k.RewrapOrgKey("org1", "key1", "escrow", req.Wrapped)
	if err != nil || ver != 2 || moved == req.Wrapped {
		t.Fatalf("rewrap: %q %d %v", moved, ver, err)
	}
	// The moved key reads, and so does the old form: nothing was deleted.
	req2 := req
	req2.RequestID, req2.Wrapped = "rid-2", moved
	if pt, err := k.ReadEscrow(req2); err != nil || string(pt) != blPassword {
		t.Fatalf("read under the new version: %q %v", pt, err)
	}
	req.RequestID = "rid-3"
	if pt, err := k.ReadEscrow(req); err != nil || string(pt) != blPassword {
		t.Fatalf("read under the old version: %q %v", pt, err)
	}
	// Again is a no-op, and another owner's key is refused.
	if again, _, err := k.RewrapOrgKey("org1", "key1", "escrow", moved); err != nil || again != moved {
		t.Fatalf("second rewrap: %v", err)
	}
	if _, _, err := k.RewrapOrgKey("org2", "key1", "escrow", req.Wrapped); err == nil {
		t.Fatal("a key re-wrapped for another organization")
	}
	if _, _, err := k.RewrapOrgKey("org1", "key1", "service", req.Wrapped); err == nil {
		t.Fatal("a key re-wrapped as another purpose")
	}
}

// readyKeystoreWithCode is readyKeystore that keeps the recovery code, which a
// later version's check needs.
func readyKeystoreWithCode(t *testing.T) (*Keystore, []byte) {
	t.Helper()
	k, err := Open(Options{Dir: t.TempDir(), Mode: keystore.ModeFile})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(k.Close)
	c, bf, err := k.Init("", nil)
	if err != nil {
		t.Fatal(err)
	}
	keep := bytes.Clone(c)
	if _, err := k.VerifyRecovery(bf, c); err != nil {
		t.Fatal(err)
	}
	return k, keep
}

func TestResealMovesARecordToTheNewKeyWithoutPlaintext(t *testing.T) {
	k := readyKeystore(t, Options{})
	req, fp := readReq(t, k, "rid-1")
	pub2, wrapped2, _, err := k.CreateOrgKey("org1", "key2", "escrow")
	if err != nil {
		t.Fatal(err)
	}
	newCtx := ctxOf("org1", "dev1", "vol1", "prot1", "key2")
	rr := ResealRequest{RequestID: "rs-1", Record: "rec1", OldWrapped: req.Wrapped, Old: req.Context, New: newCtx,
		NewPublic: pub2, Enc: req.Enc, Ciphertext: req.Ciphertext, Fingerprint: fp}
	enc, ct, err := k.ResealEscrow(rr)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(ct, []byte(blPassword)) || bytes.Equal(ct, req.Ciphertext) {
		t.Fatal("the re-sealed record is not a new ciphertext")
	}
	pt, err := k.ReadEscrow(ReadRequest{RequestID: "rid-2", Record: "rec1", Wrapped: wrapped2, Context: newCtx, Enc: enc, Ciphertext: ct, Fingerprint: fp})
	if err != nil || string(pt) != blPassword {
		t.Fatalf("read of the moved record: %q %v", pt, err)
	}
	// The old key's context no longer opens it.
	if _, err := k.ReadEscrow(ReadRequest{RequestID: "rid-3", Record: "rec1", Wrapped: wrapped2, Context: req.Context, Enc: enc, Ciphertext: ct, Fingerprint: fp}); err == nil {
		t.Fatal("the moved record opens under the old context")
	}

	for name, mut := range map[string]func(*ResealRequest){
		"another device":       func(r *ResealRequest) { r.New.Device = "dev2" },
		"another volume":       func(r *ResealRequest) { r.New.Volume = "vol2" },
		"another protector":    func(r *ResealRequest) { r.New.Protector = "prot2" },
		"another organization": func(r *ResealRequest) { r.New.Org = "org2" },
		"the same key":         func(r *ResealRequest) { r.New.OrgKey = r.Old.OrgKey },
		"a wrong fingerprint":  func(r *ResealRequest) { r.Fingerprint = bytes.Repeat([]byte{1}, 16) },
		"a short public key":   func(r *ResealRequest) { r.NewPublic = r.NewPublic[:5] },
		"a tampered record":    func(r *ResealRequest) { r.Ciphertext = append([]byte{}, r.Ciphertext...); r.Ciphertext[0] ^= 1 },
	} {
		bad := rr
		mut(&bad)
		if _, _, err := k.ResealEscrow(bad); err == nil {
			t.Errorf("%s: the keystore re-sealed it", name)
		}
	}
	raw, _ := os.ReadFile(filepath.Join(k.opts.Dir, logDirName, logFileName))
	if bytes.Contains(raw, []byte("123456-234567")) || bytes.Contains(raw, []byte(blPassword)) {
		t.Fatal("the log holds a key")
	}
	_, entries, _ := k.LogSince(0, 100)
	for _, e := range entries {
		if e.Op == keystore.OpResealEscrow && e.Plaintext {
			t.Fatal("a re-seal is logged as returning a key")
		}
	}
}
