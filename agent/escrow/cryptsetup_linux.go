//go:build linux

package escrow

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/internal/escrowcrypto"
)

// TokenType is the LUKS2 token type that marks a key slot as EasyRMM's.
const TokenType = "easyrmm-escrow"

// Cryptsetup is the Linux LUKS backend: it runs cryptsetup in the agent's own
// process. A key is only ever written to a command's standard input, never to
// its arguments, its environment or a file, and the existing unlock is a key
// file named in /etc/crypttab or a TPM2 token.
type Cryptsetup struct {
	// Bin, Lsblk and Crypttab are the tools and file used; the defaults are
	// cryptsetup, lsblk and /etc/crypttab.
	Bin, Lsblk, Crypttab string
	// Meminfo is where available memory is read, for the bounded Argon2id cost.
	Meminfo string
}

// SystemLUKS is the LUKS backend of this platform.
func SystemLUKS() LUKS { return &Cryptsetup{} }

func (c *Cryptsetup) bin() string      { return orDefault(c.Bin, "cryptsetup") }
func (c *Cryptsetup) lsblk() string    { return orDefault(c.Lsblk, "lsblk") }
func (c *Cryptsetup) crypttab() string { return orDefault(c.Crypttab, "/etc/crypttab") }
func (c *Cryptsetup) meminfo() string  { return orDefault(c.Meminfo, "/proc/meminfo") }

func orDefault(v, def string) string {
	if v != "" {
		return v
	}
	return def
}

// cmdTimeout bounds one cryptsetup call: Argon2id on a small host takes seconds.
const cmdTimeout = 90 * time.Second

// run executes a tool with stdin, in a clean environment. The error carries the
// command's first line of complaint, which never holds a key: cryptsetup does not
// echo what it reads.
func (c *Cryptsetup) run(ctx context.Context, bin string, stdin []byte, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, cmdTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, args...) //nolint:gosec // fixed tools; arguments are paths and numbers, never a key
	cmd.Env = []string{"LC_ALL=C", "PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &limited{b: &errb, max: 2048}
	if err := cmd.Run(); err != nil {
		if errors.Is(err, exec.ErrNotFound) {
			return nil, ErrUnsupported
		}
		first, _, _ := strings.Cut(strings.TrimSpace(errb.String()), "\n")
		return nil, fmt.Errorf("%s %s: %w: %s", filepath.Base(bin), firstArg(args), err, first)
	}
	return out.Bytes(), nil
}

func firstArg(a []string) string {
	for _, x := range a {
		if !strings.HasPrefix(x, "-") {
			return x
		}
	}
	return ""
}

type limited struct {
	b   *bytes.Buffer
	max int
}

func (l *limited) Write(p []byte) (int, error) {
	if room := l.max - l.b.Len(); room > 0 {
		l.b.Write(p[:min(len(p), room)])
	}
	return len(p), nil
}

// --- discovery ---

type lsblkNode struct {
	Path       string      `json:"path"`
	Type       string      `json:"type"`
	FSType     string      `json:"fstype"`
	UUID       string      `json:"uuid"`
	Mountpoint string      `json:"mountpoint"`
	Children   []lsblkNode `json:"children"`
}

type luksDevice struct{ path, uuid, mount string }

// probeTypes are the device types whose header is read when lsblk names no
// file system.
var probeTypes = map[string]bool{"disk": true, "part": true, "loop": true, "lvm": true, "md": true}

func (c *Cryptsetup) devices(ctx context.Context) ([]luksDevice, error) {
	out, err := c.run(ctx, c.lsblk(), nil, "-J", "-p", "-o", "PATH,TYPE,FSTYPE,UUID,MOUNTPOINT")
	if err != nil {
		return nil, err
	}
	var tree struct {
		Blockdevices []lsblkNode `json:"blockdevices"`
	}
	if err := json.Unmarshal(out, &tree); err != nil {
		return nil, fmt.Errorf("reading lsblk: %w", err)
	}
	var found []luksDevice
	var walk func(n lsblkNode)
	walk = func(n lsblkNode) {
		switch {
		case n.FSType == "crypto_LUKS" && n.UUID != "":
			found = append(found, luksDevice{path: n.Path, uuid: strings.ToLower(n.UUID), mount: firstMount(n.Children)})
		case n.FSType == "" && probeTypes[n.Type]:
			// Without udev (a container) lsblk may not know the file system:
			// read the header.
			if _, err := c.run(ctx, c.bin(), nil, "isLuks", n.Path); err == nil {
				if u, err := c.run(ctx, c.bin(), nil, "luksUUID", n.Path); err == nil {
					found = append(found, luksDevice{path: n.Path, uuid: strings.ToLower(strings.TrimSpace(string(u))), mount: firstMount(n.Children)})
				}
			}
		}
		for _, ch := range n.Children {
			walk(ch)
		}
	}
	for _, n := range tree.Blockdevices {
		walk(n)
	}
	return found, nil
}

// firstMount is the first real mount point below a device.
func firstMount(ns []lsblkNode) string {
	for _, n := range ns {
		if m := n.Mountpoint; m != "" && !strings.HasPrefix(m, "[") {
			return m
		}
		if m := firstMount(n.Children); m != "" {
			return m
		}
	}
	return ""
}

type luksToken struct {
	ID       string // the token's number
	Type     string
	Keyslots []string
	EscrowID string
}

type luksInfo struct {
	dev      luksDevice
	version  int
	slots    map[string]json.RawMessage
	tokens   []luksToken
	state    string
	reason   string
	unlock   []string // the arguments that unlock the volume by itself
	ourSlots []LUKSSlot
}

var escrowIDRe = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

func (c *Cryptsetup) dump(ctx context.Context, dev string) (slots map[string]json.RawMessage, toks []luksToken, err error) {
	out, err := c.run(ctx, c.bin(), nil, "luksDump", "--dump-json-metadata", dev)
	if err != nil {
		return nil, nil, err
	}
	var md struct {
		Keyslots map[string]json.RawMessage `json:"keyslots"`
		Tokens   map[string]json.RawMessage `json:"tokens"`
	}
	if err := json.Unmarshal(out, &md); err != nil {
		return nil, nil, fmt.Errorf("reading the LUKS header: %w", err)
	}
	for id, raw := range md.Tokens {
		var t struct {
			Type     string   `json:"type"`
			Keyslots []string `json:"keyslots"`
			EscrowID string   `json:"escrow_id"`
		}
		if json.Unmarshal(raw, &t) != nil {
			continue
		}
		toks = append(toks, luksToken{ID: id, Type: t.Type, Keyslots: t.Keyslots, EscrowID: t.EscrowID})
	}
	slices.SortFunc(toks, func(a, b luksToken) int { return strings.Compare(a.ID, b.ID) })
	return md.Keyslots, toks, nil
}

// slotHash is the SHA-256 of a key slot's metadata (its key derivation, its
// area and its anti-forensic splitter), re-encoded so that its key order cannot
// differ.
func slotHash(raw json.RawMessage) string {
	var v any
	if json.Unmarshal(raw, &v) != nil {
		return ""
	}
	b, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func (c *Cryptsetup) inspect(ctx context.Context, d luksDevice) (*luksInfo, error) {
	info := &luksInfo{dev: d, version: 2}
	if _, err := c.run(ctx, c.bin(), nil, "isLuks", "--type", "luks2", d.path); err != nil {
		if errors.Is(err, ErrUnsupported) {
			return nil, err
		}
		info.version = 1
		info.state = agentproto.LUKSCannotEscrow
		info.reason = "LUKS1 has no token to mark a key slot as EasyRMM's, so the agent will not add one."
		return info, nil
	}
	slots, toks, err := c.dump(ctx, d.path)
	if err != nil {
		return nil, err
	}
	info.slots, info.tokens = slots, toks
	for _, t := range toks {
		if t.Type == TokenType && escrowIDRe.MatchString(t.EscrowID) && len(t.Keyslots) == 1 {
			if raw, ok := slots[t.Keyslots[0]]; ok {
				info.ourSlots = append(info.ourSlots, LUKSSlot{TokenID: t.EscrowID, Hash: slotHash(raw)})
			}
		}
	}
	has := func(prefix string) bool {
		return slices.ContainsFunc(toks, func(t luksToken) bool { return strings.HasPrefix(t.Type, prefix) })
	}
	switch kf, kfArgs := c.keyfile(d); {
	case has("clevis"):
		info.state = agentproto.LUKSManagedElsewhere
		info.reason = "Clevis manages how this volume unlocks; EasyRMM does not rewrite it."
	case kf != "":
		info.state, info.unlock = agentproto.LUKSEscrowable, kfArgs
	case has("systemd-tpm2"):
		info.state, info.unlock = agentproto.LUKSEscrowable, []string{"--token-only", "--token-type", "systemd-tpm2"}
	default:
		info.state = agentproto.LUKSCannotEscrow
		info.reason = "Only a passphrase unlocks this volume, so the agent cannot add a key slot by itself."
	}
	return info, nil
}

// keyfile finds the key file /etc/crypttab names for the device, and the
// arguments cryptsetup takes for it. Keys read from a device (/dev/urandom, a
// swap's random key) are not unlocks.
func (c *Cryptsetup) keyfile(d luksDevice) (string, []string) {
	f, err := os.Open(c.crypttab())
	if err != nil {
		return "", nil
	}
	defer f.Close() //nolint:errcheck // read only
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fs := strings.Fields(line)
		if len(fs) < 3 || !matchesDevice(fs[1], d) {
			continue
		}
		kf := fs[2]
		if kf == "none" || kf == "-" || !filepath.IsAbs(kf) || strings.HasPrefix(kf, "/dev/") {
			continue
		}
		if st, err := os.Stat(kf); err != nil || !st.Mode().IsRegular() {
			continue
		}
		args := []string{"--key-file", kf}
		if len(fs) > 3 {
			for _, o := range strings.Split(fs[3], ",") {
				if v, ok := strings.CutPrefix(o, "keyfile-offset="); ok && onlyDigits(v) {
					args = append(args, "--keyfile-offset", v)
				}
				if v, ok := strings.CutPrefix(o, "keyfile-size="); ok && onlyDigits(v) {
					args = append(args, "--keyfile-size", v)
				}
			}
		}
		return kf, args
	}
	return "", nil
}

func onlyDigits(s string) bool {
	_, err := strconv.ParseUint(s, 10, 32)
	return err == nil
}

// matchesDevice says whether a crypttab's device column names the device.
func matchesDevice(spec string, d luksDevice) bool {
	switch {
	case strings.HasPrefix(strings.ToUpper(spec), "UUID="):
		return strings.EqualFold(strings.Trim(spec[5:], `"`), d.uuid)
	case strings.HasPrefix(spec, "/dev/disk/by-uuid/"):
		return strings.EqualFold(filepath.Base(spec), d.uuid)
	case strings.HasPrefix(spec, "/"):
		a, e1 := filepath.EvalSymlinks(spec)
		b, e2 := filepath.EvalSymlinks(d.path)
		return e1 == nil && e2 == nil && a == b
	}
	return false
}

// Volumes lists the LUKS volumes and what the agent can do with each.
func (c *Cryptsetup) Volumes(ctx context.Context) ([]LUKSVolume, error) {
	devs, err := c.devices(ctx)
	if err != nil {
		return nil, err
	}
	out := []LUKSVolume{}
	seen := map[string]bool{}
	for _, d := range devs {
		if seen[d.uuid] {
			continue
		}
		seen[d.uuid] = true
		info, err := c.inspect(ctx, d)
		if err != nil {
			if errors.Is(err, ErrUnsupported) {
				return nil, err
			}
			continue // a volume that cannot be read is not reported
		}
		mount := d.mount
		if mount == "" {
			mount = d.path
		}
		if len(mount) > 64 {
			mount = mount[len(mount)-64:]
		}
		out = append(out, LUKSVolume{UUID: d.uuid, Mount: mount, Version: info.version, State: info.state, Reason: info.reason, Slots: info.ourSlots})
	}
	return out, nil
}

func (c *Cryptsetup) find(ctx context.Context, volume string) (*luksInfo, error) {
	devs, err := c.devices(ctx)
	if err != nil {
		return nil, err
	}
	for _, d := range devs {
		if d.uuid == strings.ToLower(volume) {
			return c.inspect(ctx, d)
		}
	}
	return nil, ErrUnknownVolume
}

// argonMemoryKiB is the Argon2id memory cost for a new slot: a quarter of what is
// available, between 64 MiB and 256 MiB, so that a small host is not starved
// and a large one still gets a hard slot.
func (c *Cryptsetup) argonMemoryKiB() int {
	mem := 262144
	if b, err := os.ReadFile(c.meminfo()); err == nil {
		for _, line := range strings.Split(string(b), "\n") {
			if v, ok := strings.CutPrefix(line, "MemAvailable:"); ok {
				if n, err := strconv.Atoi(strings.TrimSuffix(strings.TrimSpace(v), " kB")); err == nil {
					mem = max(65536, min(262144, n/4))
				}
			}
		}
	}
	return mem
}

// AddSlot adds a key slot with the passphrase, marks it with the agent's token
// and tests it. The passphrase goes to cryptsetup on standard input only. If
// anything after the slot exists fails, the slot is removed again with the same
// unlock that added it.
func (c *Cryptsetup) AddSlot(ctx context.Context, volume string, pass []byte) (LUKSSlot, error) {
	if _, err := escrowcrypto.NormalizeLUKSBytes(pass); err != nil {
		return LUKSSlot{}, errors.New("escrow: the passphrase is not one the agent makes")
	}
	info, err := c.find(ctx, volume)
	if err != nil {
		return LUKSSlot{}, err
	}
	if info.state != agentproto.LUKSEscrowable {
		return LUKSSlot{}, ErrCannotUnlock
	}
	before := map[string]bool{}
	for id := range info.slots {
		before[id] = true
	}
	args := []string{"luksAddKey", "--batch-mode", "--pbkdf", "argon2id", "--pbkdf-memory", strconv.Itoa(c.argonMemoryKiB()), "--pbkdf-parallel", "1"}
	args = append(append(args, info.unlock...), info.dev.path, "-")
	if _, err := c.run(ctx, c.bin(), pass, args...); err != nil {
		return LUKSSlot{}, err
	}
	slots, _, err := c.dump(ctx, info.dev.path)
	if err != nil {
		return LUKSSlot{}, err
	}
	var added []string
	for id := range slots {
		if !before[id] {
			added = append(added, id)
		}
	}
	// rollback removes what this call added, with the unlock that added it.
	rollback := func(cause error, token string) (LUKSSlot, error) {
		rctx, stop := context.WithTimeout(context.WithoutCancel(ctx), cmdTimeout)
		defer stop()
		if token != "" {
			_, _ = c.run(rctx, c.bin(), nil, "token", "remove", "--token-id", token, info.dev.path)
		}
		for _, s := range added {
			_, _ = c.run(rctx, c.bin(), nil, append(append([]string{"luksKillSlot", "--batch-mode"}, info.unlock...), info.dev.path, s)...)
		}
		return LUKSSlot{}, cause
	}
	if len(added) != 1 {
		return rollback(errors.New("escrow: cryptsetup did not add exactly one key slot"), "")
	}
	slot := added[0]
	id := uuid.NewString()
	tok, err := json.Marshal(map[string]any{"type": TokenType, "keyslots": []string{slot}, "escrow_id": id})
	if err != nil {
		return rollback(err, "")
	}
	if _, err := c.run(ctx, c.bin(), tok, "token", "import", info.dev.path); err != nil {
		return rollback(err, "")
	}
	// The new token's number, to remove it again if the test fails.
	_, toks, err := c.dump(ctx, info.dev.path)
	if err != nil {
		return rollback(err, "")
	}
	tokenNum := ""
	for _, t := range toks {
		if t.Type == TokenType && t.EscrowID == id {
			tokenNum = t.ID
		}
	}
	if _, err := c.run(ctx, c.bin(), pass, "open", "--test-passphrase", "--key-slot", slot, "--key-file", "-", info.dev.path); err != nil {
		return rollback(fmt.Errorf("escrow: the new passphrase does not open the volume: %w", err), tokenNum)
	}
	slots, _, err = c.dump(ctx, info.dev.path)
	if err != nil || slots[slot] == nil {
		return rollback(errors.New("escrow: the new key slot is not in the header"), tokenNum)
	}
	return LUKSSlot{TokenID: id, Hash: slotHash(slots[slot])}, nil
}

// RemoveSlot removes one of the agent's key slots. Never the last slot, never a
// slot without the agent's token, never a slot another token uses, and only
// with an unlock the agent has by itself.
func (c *Cryptsetup) RemoveSlot(ctx context.Context, volume, tokenID string) error {
	info, err := c.find(ctx, volume)
	if err != nil {
		return err
	}
	var tok *luksToken
	for i := range info.tokens {
		if t := &info.tokens[i]; t.Type == TokenType && t.EscrowID == tokenID {
			tok = t
		}
	}
	if tok == nil || len(tok.Keyslots) != 1 || info.slots[tok.Keyslots[0]] == nil {
		return ErrNotOurSlot
	}
	slot := tok.Keyslots[0]
	if len(info.slots) < 2 {
		return ErrLastSlot
	}
	for _, t := range info.tokens {
		if t.ID != tok.ID && slices.Contains(t.Keyslots, slot) {
			return ErrSharedSlot
		}
	}
	if info.state != agentproto.LUKSEscrowable {
		return ErrCannotUnlock
	}
	args := append(append([]string{"luksKillSlot", "--batch-mode"}, info.unlock...), info.dev.path, slot)
	if _, err := c.run(ctx, c.bin(), nil, args...); err != nil {
		return err
	}
	// The slot is gone; a token that names no slot is only clutter.
	_, _ = c.run(ctx, c.bin(), nil, "token", "remove", "--token-id", tok.ID, info.dev.path)
	return nil
}
