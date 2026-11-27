package main

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/paulmataruso/easyrmm/agent/state"
	"github.com/paulmataruso/easyrmm/agent/trust"
	"github.com/paulmataruso/easyrmm/internal/agentproto"
)

// caFingerprints are the SHA-256 fingerprints, in hex, of the certificates in
// the CA file the agent loads, none when it uses the system's roots
// (ADR-0057: the replacement of EasyRMM's own authority counts them). A file
// that cannot be read reports none, and is bounded.
func caFingerprints(path string) []string {
	if path == "" {
		return nil
	}
	b, err := os.ReadFile(path) //nolint:gosec // the agent's own CA file
	if err != nil {
		return nil
	}
	var out []string
	for len(out) < agentproto.MaxKeyReportAuthorities {
		var blk *pem.Block
		blk, b = pem.Decode(b)
		if blk == nil {
			break
		}
		if blk.Type != "CERTIFICATE" {
			continue
		}
		if _, err := x509.ParseCertificate(blk.Bytes); err != nil {
			continue
		}
		sum := sha256.Sum256(blk.Bytes)
		out = append(out, hex.EncodeToString(sum[:]))
	}
	return out
}

// parseTrustKey reads "<generation>:<key>", the form the console prints.
func parseTrustKey(arg string) (int64, string, error) {
	gen, key, ok := strings.Cut(arg, ":")
	n, err := strconv.ParseInt(gen, 10, 64)
	if !ok || err != nil || n < 1 {
		return 0, "", errors.New("give the key as <generation>:<key>, as the console prints it")
	}
	if _, err := agentproto.DecodeKey(key); err != nil {
		return 0, "", errors.New("the key is not an Ed25519 public key in base64")
	}
	return n, key, nil
}

// trustKey is `easyrmm-agent trust-key <generation>:<key> [--force]`
// (ADR-0057): the keys this agent trusts become the one given, and the
// service restarts. It is run as root or administrator on the computer; the
// key is public, so the command carries no secret. It refuses when the agent
// trusts a key of a higher generation, unless --force, so a command that a
// policy runs again never moves a device back to an older key.
func (e *env) trustKey(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("trust-key", flag.ContinueOnError)
	force := fs.Bool("force", false, "replace a key of a higher generation as well")
	// Flags may follow the key, as the console prints it.
	var rest []string
	for len(args) > 0 {
		if err := fs.Parse(args); err != nil {
			return err
		}
		if fs.NArg() == 0 {
			break
		}
		rest = append(rest, fs.Arg(0))
		args = fs.Args()[1:]
	}
	if len(rest) != 1 {
		return errors.New("usage: easyrmm-agent trust-key <generation>:<key> [--force]")
	}
	gen, key, err := parseTrustKey(rest[0])
	if err != nil {
		return err
	}
	if !e.isRoot() {
		return e.needAdmin("trust-key command")
	}
	if err := e.openStore(); err != nil {
		return err
	}
	cfg, devKey, err := e.store.Load()
	if err != nil {
		return err
	}
	ks := &trust.KeyStore{DeviceID: cfg.DeviceID, Install: agentproto.InstallID(devKey.Public().(ed25519.PublicKey)), Config: cfg, Store: e.store, Log: e.log}
	if err := ks.Replace(gen, key, *force); err != nil {
		return err
	}
	_, _ = fmt.Fprintf(e.stdout, "This agent now trusts only the server key %s (generation %d).\n",
		agentproto.FormatFingerprint(agentproto.Fingerprint(mustKey(key))), gen)
	if supported() && e.hasServices() && e.serviceInstalled(ctx) {
		if err := e.sd.Restart(ctx, e.paths.AgentService().Name); err != nil {
			return fmt.Errorf("the key is saved, but restarting the agent's service failed; restart it by hand: %w", err)
		}
		_, _ = fmt.Fprintln(e.stdout, "The agent's service was restarted.")
	} else {
		_, _ = fmt.Fprintln(e.stdout, "Restart the agent to use it.")
	}
	return nil
}

func mustKey(key string) ed25519.PublicKey {
	pub, _ := agentproto.DecodeKey(key)
	return pub
}

// printKeys lists the keys the agent trusts and its latest logged
// instructions, for `status`.
func (e *env) printKeys(cfg *state.Config) {
	w := e.stdout
	trusted, dropped := trust.View(cfg)
	for _, k := range trusted {
		gen := "unknown"
		if k.Generation > 0 {
			gen = strconv.FormatInt(k.Generation, 10)
		}
		_, _ = fmt.Fprintf(w, "Job key:    %s generation %s\n", agentproto.FormatFingerprint(k.Fingerprint), gen)
	}
	for _, k := range dropped {
		_, _ = fmt.Fprintf(w, "Dropped:    %s (no longer trusted)\n", agentproto.FormatFingerprint(k.Fingerprint))
	}
	if time.Now().Before(cfg.KeyTransitionUntil) {
		_, _ = fmt.Fprintf(w, "Key change: in transition until %s\n", cfg.KeyTransitionUntil.Local().Format(time.RFC1123))
	}
	il := &trust.InstructionLog{Store: e.store}
	for _, en := range il.Latest(5) {
		_, _ = fmt.Fprintf(w, "Accepted:   %s %s signed by %s at %s\n", en.Kind, en.ID, agentproto.FormatFingerprint(en.Signer), en.At.Local().Format(time.RFC1123))
	}
}
