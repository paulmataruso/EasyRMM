package keystored

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/paulmataruso/easyrmm/internal/escrowcrypto"
	"github.com/paulmataruso/easyrmm/server/internal/keystore"
)

func readReq(t *testing.T, k *Keystore, rid string) (ReadRequest, []byte) {
	t.Helper()
	return readReqFor(t, k, "org1", rid)
}

func readReqFor(t *testing.T, k *Keystore, org, rid string) (ReadRequest, []byte) {
	t.Helper()
	pub, wrapped, _, err := k.CreateOrgKey(org, "key1", "escrow")
	if err != nil {
		t.Fatal(err)
	}
	c := ctxOf(org, "dev1", "vol1", "prot1", "key1")
	enc, ct, err := escrowcrypto.Seal(pub, c, []byte(blPassword))
	if err != nil {
		t.Fatal(err)
	}
	fp := escrowcrypto.Fingerprint("prot1", []byte(blPassword))
	return ReadRequest{RequestID: rid, Record: "rec1", Wrapped: wrapped, Context: c, Enc: enc, Ciphertext: ct, Fingerprint: fp[:]}, fp[:]
}

func readyKeystore(t *testing.T, o Options) *Keystore {
	t.Helper()
	o.Mode = keystore.ModeFile
	if o.Dir == "" {
		o.Dir = t.TempDir()
	}
	k, err := Open(o)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(k.Close)
	c, bf, err := k.Init("", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := k.VerifyRecovery(bf, c); err != nil {
		t.Fatal(err)
	}
	return k
}

func TestReadReturnsThePasswordAndLogsBeforeAnswering(t *testing.T) {
	k := readyKeystore(t, Options{})
	req, _ := readReq(t, k, "rid-1")
	pt, err := k.ReadEscrow(req)
	if err != nil || string(pt) != blPassword {
		t.Fatalf("read: %q %v", pt, err)
	}
	_, entries, err := k.LogSince(0, 100)
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, e := range entries {
		if e.Op == keystore.OpReadEscrow && e.Plaintext && e.RequestID == "rid-1" && e.Record == "rec1" && e.Result == "ok" {
			found = true
		}
	}
	if !found {
		t.Fatalf("no plaintext-returning entry for the read: %+v", entries)
	}
	// The log holds the request, never the key.
	raw, _ := os.ReadFile(filepath.Join(k.opts.Dir, logDirName, logFileName))
	if bytes.Contains(raw, []byte("123456-234567")) || bytes.Contains(raw, []byte(blPassword)) {
		t.Fatal("the log holds a key")
	}
}

func TestReadRefusesAWrongFingerprintAndAnythingNotTheRecord(t *testing.T) {
	k := readyKeystore(t, Options{})
	req, _ := readReq(t, k, "rid-1")
	bad := req
	bad.Fingerprint = bytes.Clone(req.Fingerprint)
	bad.Fingerprint[0] ^= 1
	if pt, err := k.ReadEscrow(bad); err == nil || pt != nil || code(t, err) != keystore.CodeRefused {
		t.Fatalf("wrong fingerprint: %q %v", pt, err)
	}
	moved := req
	moved.Context = ctxOf("org1", "dev2", "vol1", "prot1", "key1")
	if pt, err := k.ReadEscrow(moved); err == nil || pt != nil {
		t.Fatalf("a record moved to another device was read: %q", pt)
	}
	noID := req
	noID.RequestID = ""
	if _, err := k.ReadEscrow(noID); code(t, err) != keystore.CodeBadRequest {
		t.Fatalf("no request id: %v", err)
	}
	// None of those left a plaintext-returning entry.
	_, entries, _ := k.LogSince(0, 100)
	for _, e := range entries {
		if e.Plaintext {
			t.Fatalf("a refused read logged a key leaving: %+v", e)
		}
	}
}

func TestReadLimitsHoldInsideTheKeystore(t *testing.T) {
	now := time.Date(2026, 11, 26, 10, 0, 0, 0, time.UTC)
	k := readyKeystore(t, Options{Now: func() time.Time { return now }, Limits: Limits{OrgHour: 2, OrgDay: 3, TotalHour: 4}})
	req, _ := readReq(t, k, "r0")
	read := func(rid string) string {
		r := req
		r.RequestID = rid
		pt, err := k.ReadEscrow(r)
		clear(pt)
		return code(t, err)
	}
	if read("r1") != "" || read("r2") != "" {
		t.Fatal("reads inside the limit refused")
	}
	if c := read("r3"); c != keystore.CodeLimit {
		t.Fatalf("third read in an hour: %q", c)
	}
	// An hour later the day's limit (3) holds.
	now = now.Add(61 * time.Minute)
	if read("r4") != "" {
		t.Fatal("read after the hour refused")
	}
	if c := read("r5"); c != keystore.CodeLimit {
		t.Fatalf("fourth read in a day: %q", c)
	}
	// The total across organizations: 4 an hour. The first org used 1 in this hour.
	r2, _ := readReqFor(t, k, "org2", "x0")
	for i, rid := range []string{"x1", "x2"} {
		r2.RequestID = rid
		pt, err := k.ReadEscrow(r2)
		clear(pt)
		if err != nil {
			t.Fatalf("other organization read %d: %v", i, err)
		}
	}
	r2.RequestID = "x3"
	if pt, err := k.ReadEscrow(r2); code(t, err) != keystore.CodeLimit {
		t.Fatalf("total limit: %q %v", pt, err)
	}
}

func TestLimitsSurviveARestart(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, 11, 26, 10, 0, 0, 0, time.UTC)
	o := Options{Dir: dir, Now: func() time.Time { return now }, Limits: Limits{OrgHour: 1}}
	k := readyKeystore(t, o)
	req, _ := readReq(t, k, "r1")
	pt, err := k.ReadEscrow(req)
	clear(pt)
	if err != nil {
		t.Fatal(err)
	}
	k.Close()
	k2, err := Open(Options{Dir: dir, Mode: keystore.ModeFile, Now: o.Now, Limits: o.Limits})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(k2.Close)
	req.RequestID = "r2"
	if _, err := k2.ReadEscrow(req); code(t, err) != keystore.CodeLimit {
		t.Fatalf("a restart reset the counters: %v", err)
	}
}

func TestLogChainDetectsATamperedLog(t *testing.T) {
	dir := t.TempDir()
	k := readyKeystore(t, Options{Dir: dir})
	req, _ := readReq(t, k, "r1")
	for _, rid := range []string{"r1", "r2", "r3"} {
		req.RequestID = rid
		pt, _ := k.ReadEscrow(req)
		clear(pt)
	}
	_, entries, err := k.LogSince(0, 100)
	if err != nil || len(entries) < 3 {
		t.Fatalf("entries: %d %v", len(entries), err)
	}
	if _, _, err := keystore.VerifyLog("", 0, entries); err != nil {
		t.Fatalf("a fresh log does not verify: %v", err)
	}
	// Removing a plaintext-returning line breaks the chain.
	for i, e := range entries[:2] {
		if e.Plaintext {
			cut := append(append([]keystore.LogEntry{}, entries[:i]...), entries[i+1:]...)
			if _, _, err := keystore.VerifyLog("", 0, cut); err == nil {
				t.Fatal("a removed line was not detected")
			}
		}
	}
	// Editing one is detected too, and a keystore that finds its log damaged
	// at start refuses reads.
	k.Close()
	path := filepath.Join(dir, logDirName, logFileName)
	raw, _ := os.ReadFile(path)
	if err := os.WriteFile(path, []byte(strings.Replace(string(raw), `"result":"ok"`, `"result":"no"`, 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	k2, err := Open(Options{Dir: dir, Mode: keystore.ModeFile})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(k2.Close)
	if pt, err := k2.ReadEscrow(req); err == nil || pt != nil {
		t.Fatalf("a keystore with a damaged log returned a key: %v", err)
	}
}
