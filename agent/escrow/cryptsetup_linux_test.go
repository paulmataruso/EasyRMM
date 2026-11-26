//go:build linux

package escrow_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/paulmataruso/easyrmm/agent/escrow"
	"github.com/paulmataruso/easyrmm/agent/host"
	"github.com/paulmataruso/easyrmm/agent/state"
	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/internal/escrowcrypto"
)

// These tests run the real cryptsetup against real LUKS volumes on file-backed
// loop devices. They need root, cryptsetup, lsblk and loop devices, so they run
// only when EASYRMM_LUKS_TEST=1, inside a privileged throwaway container (see
// scripts/ci/luks-test.sh); everywhere else they are skipped.

type luksLab struct {
	t        *testing.T
	dir      string
	crypttab string
	bin      string
	log      string // the wrapper's record of every call
}

func labFor(t *testing.T) *luksLab {
	t.Helper()
	if os.Getenv("EASYRMM_LUKS_TEST") != "1" {
		t.Skip("set EASYRMM_LUKS_TEST=1 to run against real LUKS volumes (root, cryptsetup, loop devices)")
	}
	l := &luksLab{t: t, dir: t.TempDir()}
	l.crypttab = filepath.Join(l.dir, "crypttab")
	if err := os.WriteFile(l.crypttab, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	// A wrapper that records each call's arguments and environment, then runs the
	// real tool with the same standard input: what the tests check the agent never
	// puts there.
	l.log = filepath.Join(l.dir, "calls.log")
	l.bin = filepath.Join(l.dir, "cryptsetup")
	script := "#!/bin/sh\n{ echo \"ARGS: $*\"; env; } >> " + l.log + "\nexec /usr/sbin/cryptsetup \"$@\"\n"
	if _, err := os.Stat("/usr/sbin/cryptsetup"); err != nil {
		if p, e := exec.LookPath("cryptsetup"); e == nil {
			script = strings.ReplaceAll(script, "/usr/sbin/cryptsetup", p)
		}
	}
	if err := os.WriteFile(l.bin, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	return l
}

func (l *luksLab) sh(stdin []byte, name string, args ...string) string {
	l.t.Helper()
	cmd := exec.Command(name, args...)
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		l.t.Fatalf("%s %v: %v\n%s", name, args, err, out)
	}
	return strings.TrimSpace(string(out))
}

// volume makes a LUKS volume on a loop device and returns its device and UUID.
// version is "luks1" or "luks2"; key is its first key (a passphrase or a key
// file's content), keyfile says whether it is written to a file and listed in
// the crypttab.
func (l *luksLab) volume(version string, key []byte, keyfile bool) (dev, uuid, keypath string) {
	l.t.Helper()
	img := filepath.Join(l.dir, strings.ReplaceAll(l.t.Name(), "/", "_")+version+".img")
	l.sh(nil, "truncate", "-s", "32M", img)
	dev = l.sh(nil, "losetup", "-f", "--show", img)
	l.t.Cleanup(func() { _ = exec.Command("losetup", "-d", dev).Run() })
	args := []string{"luksFormat", "--batch-mode", "--type", version, "--pbkdf", "pbkdf2", "--pbkdf-force-iterations", "1000", "--key-file", "-", dev}
	if keyfile {
		keypath = filepath.Join(l.dir, "keyfile")
		if err := os.WriteFile(keypath, key, 0o400); err != nil {
			l.t.Fatal(err)
		}
	}
	l.sh(key, "cryptsetup", args...)
	uuid = l.sh(nil, "cryptsetup", "luksUUID", dev)
	if keyfile {
		line := "vol UUID=" + uuid + " " + keypath + " luks\n"
		if err := os.WriteFile(l.crypttab, []byte(line), 0o600); err != nil {
			l.t.Fatal(err)
		}
	}
	return dev, uuid, keypath
}

func (l *luksLab) backend() *escrow.Cryptsetup {
	return &escrow.Cryptsetup{Bin: l.bin, Crypttab: l.crypttab}
}

// tokenSlot is the key slot a token of ours names.
func (l *luksLab) tokenSlot(dev, escrowID string) string {
	l.t.Helper()
	var md struct {
		Tokens map[string]struct {
			Keyslots []string `json:"keyslots"`
			EscrowID string   `json:"escrow_id"`
		} `json:"tokens"`
	}
	if err := json.Unmarshal([]byte(l.sh(nil, "cryptsetup", "luksDump", "--dump-json-metadata", dev)), &md); err != nil {
		l.t.Fatal(err)
	}
	for _, t := range md.Tokens {
		if t.EscrowID == escrowID && len(t.Keyslots) == 1 {
			return t.Keyslots[0]
		}
	}
	l.t.Fatalf("no token for %s", escrowID)
	return ""
}

func (l *luksLab) activeSlots(dev string) []string {
	l.t.Helper()
	var md struct {
		Keyslots map[string]json.RawMessage `json:"keyslots"`
	}
	if err := json.Unmarshal([]byte(l.sh(nil, "cryptsetup", "luksDump", "--dump-json-metadata", dev)), &md); err != nil {
		l.t.Fatal(err)
	}
	ids := make([]string, 0, len(md.Keyslots))
	for id := range md.Keyslots {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	return ids
}

func (l *luksLab) opens(dev string, key []byte) bool {
	cmd := exec.Command("cryptsetup", "open", "--test-passphrase", "--key-file", "-", dev)
	cmd.Stdin = bytes.NewReader(key)
	return cmd.Run() == nil
}

func TestRealLUKSReportsWhatTheAgentCanDo(t *testing.T) {
	l := labFor(t)
	ctx := context.Background()

	// A volume with a key file listed in the crypttab: the agent can unlock it.
	_, uuidKF, _ := l.volume("luks2", bytes.Repeat([]byte("k"), 64), true)
	vols, err := l.backend().Volumes(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var got *escrow.LUKSVolume
	for i := range vols {
		if vols[i].UUID == uuidKF {
			got = &vols[i]
		}
	}
	if got == nil || got.State != agentproto.LUKSEscrowable || got.Version != 2 || len(got.Slots) != 0 {
		t.Fatalf("key-file volume: %+v", got)
	}

	// The same kind of volume with no crypttab entry: only a passphrase unlocks it.
	if err := os.WriteFile(l.crypttab, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	dev, uuidPP, _ := l.volume("luks2", []byte("a passphrase only a person knows"), false)
	vols, _ = l.backend().Volumes(ctx)
	for _, v := range vols {
		if v.UUID == uuidPP && (v.State != agentproto.LUKSCannotEscrow || v.Reason == "") {
			t.Fatalf("passphrase-only volume: %+v", v)
		}
	}
	before := l.activeSlots(dev)
	if _, err := l.backend().AddSlot(ctx, uuidPP, mustPass(t)); !errors.Is(err, escrow.ErrCannotUnlock) {
		t.Fatalf("a passphrase-only volume was written to: %v", err)
	}
	if after := l.activeSlots(dev); strings.Join(after, ",") != strings.Join(before, ",") {
		t.Fatalf("header changed: %v -> %v", before, after)
	}

	// LUKS1 has no token to mark the slot: never touched.
	_, uuid1, _ := l.volume("luks1", []byte("whatever, it is luks1"), true)
	vols, _ = l.backend().Volumes(ctx)
	for _, v := range vols {
		if v.UUID == uuid1 && (v.State != agentproto.LUKSCannotEscrow || v.Version != 1) {
			t.Fatalf("LUKS1 volume: %+v", v)
		}
	}

	// A Clevis-managed volume is left alone even with a key file.
	devC, uuidC, _ := l.volume("luks2", bytes.Repeat([]byte("c"), 64), true)
	l.sh([]byte(`{"type":"clevis","keyslots":["0"],"jwe":{}}`), "cryptsetup", "token", "import", devC)
	vols, _ = l.backend().Volumes(ctx)
	for _, v := range vols {
		if v.UUID == uuidC && v.State != agentproto.LUKSManagedElsewhere {
			t.Fatalf("clevis volume: %+v", v)
		}
	}
	if _, err := l.backend().AddSlot(ctx, uuidC, mustPass(t)); err == nil {
		t.Fatal("a Clevis volume was written to")
	}
}

func mustPass(t *testing.T) []byte {
	t.Helper()
	p, err := escrowcrypto.NewLUKSPassphrase()
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestRealLUKSAddsATestedSlotAndNeverPutsTheKeyOnACommandLine(t *testing.T) {
	l := labFor(t)
	ctx := context.Background()
	admin := bytes.Repeat([]byte("a"), 64)
	dev, uuid, _ := l.volume("luks2", admin, true)
	b := l.backend()
	pass := mustPass(t)
	want := string(pass)

	slot, err := b.AddSlot(ctx, uuid, pass)
	if err != nil {
		t.Fatal(err)
	}
	if slot.TokenID == "" || len(slot.Hash) != 64 {
		t.Fatalf("slot: %+v", slot)
	}
	if n := len(l.activeSlots(dev)); n != 2 {
		t.Fatalf("slots after add: %d", n)
	}
	if !l.opens(dev, []byte(want)) || !l.opens(dev, admin) {
		t.Fatal("the new passphrase, or the old key, does not open the volume")
	}
	// The key was on standard input only: not in an argument or the environment of
	// any call, and not in the process list while it ran (the wrapper saw each).
	calls, err := os.ReadFile(l.log)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(calls, []byte(want)) {
		t.Fatal("the passphrase appeared in a command line or an environment")
	}
	if bytes.Contains(calls, admin) {
		t.Fatal("the existing key's content appeared in a command line")
	}

	// The volume reports the slot, with a hash that holds between reads.
	read := func() escrow.LUKSVolume {
		vs, err := b.Volumes(ctx)
		if err != nil {
			t.Fatal(err)
		}
		for _, v := range vs {
			if v.UUID == uuid {
				return v
			}
		}
		t.Fatal("volume missing")
		return escrow.LUKSVolume{}
	}
	v := read()
	if len(v.Slots) != 1 || v.Slots[0] != slot || read().Slots[0].Hash != slot.Hash {
		t.Fatalf("reported slots %+v, want %+v", v.Slots, slot)
	}

	// A slot changed afterwards (its passphrase changed) has another hash.
	newKey := filepath.Join(l.dir, "new")
	if err := os.WriteFile(newKey, bytes.Repeat([]byte("n"), 40), 0o400); err != nil {
		t.Fatal(err)
	}
	l.sh([]byte(want), "cryptsetup", "luksChangeKey", "--batch-mode", "--key-file", "-", "--pbkdf", "pbkdf2", "--pbkdf-force-iterations", "1000", "--key-slot", "1", dev, newKey)
	if read().Slots[0].Hash == slot.Hash {
		t.Fatal("a changed slot kept its hash")
	}
}

func TestRealLUKSRemoveHonoursItsRules(t *testing.T) {
	l := labFor(t)
	ctx := context.Background()
	admin := bytes.Repeat([]byte("a"), 64)
	dev, uuid, _ := l.volume("luks2", admin, true)
	b := l.backend()
	p1, p2 := mustPass(t), mustPass(t)
	s1, err := b.AddSlot(ctx, uuid, slices.Clone(p1))
	if err != nil {
		t.Fatal(err)
	}
	s2, err := b.AddSlot(ctx, uuid, slices.Clone(p2))
	if err != nil {
		t.Fatal(err)
	}
	if n := len(l.activeSlots(dev)); n != 3 {
		t.Fatalf("slots: %d", n)
	}
	// A token that is not ours is never a reason to remove a slot.
	if err := b.RemoveSlot(ctx, uuid, "0a0a0a0a-0000-4000-8000-000000000000"); !errors.Is(err, escrow.ErrNotOurSlot) {
		t.Fatalf("an unknown token: %v", err)
	}
	// A slot another token also names is kept.
	slot2 := l.tokenSlot(dev, s2.TokenID)
	l.sh([]byte(`{"type":"somebody-else","keyslots":["`+slot2+`"]}`), "cryptsetup", "token", "import", dev)
	if err := b.RemoveSlot(ctx, uuid, s2.TokenID); !errors.Is(err, escrow.ErrSharedSlot) {
		t.Fatalf("a shared slot: %v", err)
	}
	if !l.opens(dev, p2) {
		t.Fatal("a refused removal removed the slot")
	}
	// A slot of ours is removed once, and then it is simply not there.
	if err := b.RemoveSlot(ctx, uuid, s1.TokenID); err != nil {
		t.Fatal(err)
	}
	if l.opens(dev, p1) || len(l.activeSlots(dev)) != 2 || !l.opens(dev, admin) {
		t.Fatalf("removing s1: %v", l.activeSlots(dev))
	}
	if err := b.RemoveSlot(ctx, uuid, s1.TokenID); !errors.Is(err, escrow.ErrNotOurSlot) {
		t.Fatalf("removing the same one twice: %v", err)
	}

	// The last slot is never removed: take the key file's slot away (with the
	// administrator's own tools, authenticating with s2's passphrase), leaving only s2's slot.
	l.sh(p2, "cryptsetup", "luksKillSlot", "--batch-mode", "--key-file", "-", dev, "0")
	if got := l.activeSlots(dev); len(got) != 1 || got[0] != slot2 {
		t.Fatalf("setup: %v", got)
	}
	if err := b.RemoveSlot(ctx, uuid, s2.TokenID); !errors.Is(err, escrow.ErrLastSlot) {
		t.Fatalf("the last slot: %v", err)
	}
	if !l.opens(dev, p2) {
		t.Fatal("the last slot was removed")
	}
}

func TestRealLUKSFailedAddLeavesTheHeaderAsItWas(t *testing.T) {
	l := labFor(t)
	ctx := context.Background()
	dev, uuid, keypath := l.volume("luks2", bytes.Repeat([]byte("a"), 64), true)
	before := l.sh(nil, "cryptsetup", "luksDump", "--dump-json-metadata", dev)
	// The crypttab's key file is not the volume's key any more.
	if err := os.Chmod(keypath, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keypath, bytes.Repeat([]byte("z"), 64), 0o400); err != nil {
		t.Fatal(err)
	}
	if _, err := l.backend().AddSlot(ctx, uuid, mustPass(t)); err == nil {
		t.Fatal("a wrong key file added a slot")
	}
	if after := l.sh(nil, "cryptsetup", "luksDump", "--dump-json-metadata", dev); after != before {
		t.Fatal("a failed add changed the header")
	}
}

// The whole flow through the agent, with the real cryptsetup and a recording
// server: report, escrow, and replacement of a stale slot once the new one is
// confirmed.
func TestRealLUKSThroughTheAgent(t *testing.T) {
	l := labFor(t)
	admin := bytes.Repeat([]byte("a"), 64)
	dev, uuid, _ := l.volume("luks2", admin, true)

	store, _, err := state.Open(host.Paths{Root: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(store.Dir(), 0o700); err != nil {
		t.Fatal(err)
	}
	signPub, signKey, _ := ed25519.GenerateKey(rand.Reader)
	orgPriv, orgPub, _ := escrowcrypto.GenerateKey()
	now := time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)
	logs := &bytes.Buffer{}
	srv := &fakeServer{answer: agentproto.EscrowAnswer{State: agentproto.EscrowVerified}, need: []agentproto.EscrowNeed{{VolumeID: uuid}}}
	a := &escrow.Agent{
		DeviceID: device, Key: func() ed25519.PublicKey { return signPub },
		Reader: &stubReader{err: escrow.ErrUnsupported}, LUKS: l.backend(), Server: srv, Store: store,
		Log: slog.New(slog.NewTextHandler(logs, nil)), Now: func() time.Time { return now },
	}
	sign := func() *agentproto.SignedEscrowKey {
		s, err := agentproto.SignEscrowKey(signKey, agentproto.EscrowKeyPayload{
			V: agentproto.EscrowKeyPayloadVersion, DeviceID: device, OrgID: org, KeyID: "key-1", KeyVersion: 1,
			PublicKey: base64.StdEncoding.EncodeToString(orgPub), IssuedAt: now, ExpiresAt: now.Add(agentproto.EscrowKeyValid),
		})
		if err != nil {
			t.Fatal(err)
		}
		return &s
	}
	a.Answered(sign())
	a.Sync(context.Background())
	if len(srv.records) != 1 {
		t.Fatalf("records: %d\n%s", len(srv.records), logs)
	}
	rec := srv.records[0]
	open := func(r agentproto.EscrowRecord) []byte {
		enc, _ := base64.StdEncoding.DecodeString(r.Enc)
		ct, _ := base64.StdEncoding.DecodeString(r.Ciphertext)
		pt, err := escrowcrypto.Open(orgPriv, escrowcrypto.Context{Org: org, Device: device, Volume: uuid, Protector: r.ProtectorID, OrgKey: "key-1"}, enc, ct)
		if err != nil {
			t.Fatal(err)
		}
		return pt
	}
	if !l.opens(dev, open(rec)) {
		t.Fatal("the escrowed passphrase does not open the real volume")
	}
	if strings.Contains(logs.String(), string(open(rec))) {
		t.Fatal("the passphrase is in the agent's log")
	}

	// The server now calls that slot stale and asks for a replacement.
	now = now.Add(time.Hour)
	srv.need = []agentproto.EscrowNeed{{VolumeID: uuid, Replace: []string{rec.ProtectorID}}}
	a.Answered(sign())
	a.Sync(context.Background())
	if len(srv.records) != 2 {
		t.Fatalf("records: %d\n%s", len(srv.records), logs)
	}
	second := srv.records[1]
	if !l.opens(dev, open(second)) {
		t.Fatal("the new passphrase does not open the volume")
	}
	if l.opens(dev, open(rec)) {
		t.Fatal("the replaced slot's passphrase still opens the volume")
	}
	if !l.opens(dev, admin) || len(l.activeSlots(dev)) != 2 {
		t.Fatalf("the administrator's key was disturbed or slots = %d", len(l.activeSlots(dev)))
	}
}
